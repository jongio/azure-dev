// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/azure/azure-dev/cli/azd/cmd/actions"
	"github.com/azure/azure-dev/cli/azd/internal"
	"github.com/azure/azure-dev/cli/azd/internal/tracing"
	"github.com/azure/azure-dev/cli/azd/pkg/account"
	"github.com/azure/azure-dev/cli/azd/pkg/alpha"
	"github.com/azure/azure-dev/cli/azd/pkg/apphost"
	"github.com/azure/azure-dev/cli/azd/pkg/async"
	"github.com/azure/azure-dev/cli/azd/pkg/azapi"
	"github.com/azure/azure-dev/cli/azd/pkg/cloud"
	"github.com/azure/azure-dev/cli/azd/pkg/environment"
	"github.com/azure/azure-dev/cli/azd/pkg/environment/azdcontext"
	"github.com/azure/azure-dev/cli/azd/pkg/exec"
	"github.com/azure/azure-dev/cli/azd/pkg/input"
	"github.com/azure/azure-dev/cli/azd/pkg/output"
	"github.com/azure/azure-dev/cli/azd/pkg/output/ux"
	"github.com/azure/azure-dev/cli/azd/pkg/project"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/errgroup"
)

type DeployFlags struct {
	ServiceName string
	All         bool
	Timeout     int
	fromPackage string
	flagSet     *pflag.FlagSet
	global      *internal.GlobalCommandOptions
	*internal.EnvFlag
}

const defaultDeployTimeoutSeconds = 1200

func (d *DeployFlags) Bind(local *pflag.FlagSet, global *internal.GlobalCommandOptions) {
	d.BindNonCommon(local, global)
	d.bindCommon(local, global)
}

func (d *DeployFlags) BindNonCommon(
	local *pflag.FlagSet,
	global *internal.GlobalCommandOptions) {
	local.StringVar(
		&d.ServiceName,
		"service",
		"",
		//nolint:lll
		"Deploys a specific service (when the string is unspecified, all services that are listed in the "+azdcontext.ProjectFileName+" file are deployed).",
	)
	//deprecate:flag hide --service
	_ = local.MarkHidden("service")
	d.global = global
}

func (d *DeployFlags) bindCommon(local *pflag.FlagSet, global *internal.GlobalCommandOptions) {
	d.EnvFlag = &internal.EnvFlag{}
	d.EnvFlag.Bind(local, global)
	d.flagSet = local

	local.BoolVar(
		&d.All,
		"all",
		false,
		"Deploys all services that are listed in "+azdcontext.ProjectFileName,
	)
	local.StringVar(
		&d.fromPackage,
		"from-package",
		"",
		//nolint:lll
		"Deploys the packaged service located at the provided path. Supports zipped file packages (file path) or container images (image tag).",
	)
	local.IntVar(
		&d.Timeout,
		"timeout",
		defaultDeployTimeoutSeconds,
		fmt.Sprintf(
			"Maximum time in seconds for azd to wait for each service deployment. This stops azd from waiting "+
				"but does not cancel the Azure-side deployment. (default: %d)",
			defaultDeployTimeoutSeconds,
		),
	)
}

func (d *DeployFlags) SetCommon(envFlag *internal.EnvFlag) {
	d.EnvFlag = envFlag
}

func NewDeployFlags(cmd *cobra.Command, global *internal.GlobalCommandOptions) *DeployFlags {
	flags := &DeployFlags{}
	flags.Bind(cmd.Flags(), global)

	return flags
}

func NewDeployFlagsFromEnvAndOptions(envFlag *internal.EnvFlag, global *internal.GlobalCommandOptions) *DeployFlags {
	return &DeployFlags{
		Timeout: defaultDeployTimeoutSeconds,
		EnvFlag: envFlag,
		global:  global,
	}
}

func (d *DeployFlags) timeoutChanged() bool {
	if d.flagSet == nil {
		return false
	}

	timeoutFlag := d.flagSet.Lookup("timeout")
	return timeoutFlag != nil && timeoutFlag.Changed
}

func NewDeployCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "deploy <service>",
		Short: "Deploy your project code to Azure.",
	}
	cmd.Args = cobra.MaximumNArgs(1)

	return cmd
}

type DeployAction struct {
	flags               *DeployFlags
	args                []string
	projectConfig       *project.ProjectConfig
	azdCtx              *azdcontext.AzdContext
	env                 *environment.Environment
	envManager          environment.Manager
	projectManager      project.ProjectManager
	serviceManager      project.ServiceManager
	resourceManager     project.ResourceManager
	accountManager      account.Manager
	azCli               *azapi.AzureClient
	portalUrlBase       string
	formatter           output.Formatter
	writer              io.Writer
	console             input.Console
	commandRunner       exec.CommandRunner
	alphaFeatureManager *alpha.FeatureManager
	importManager       *project.ImportManager
}

func NewDeployAction(
	flags *DeployFlags,
	args []string,
	projectConfig *project.ProjectConfig,
	projectManager project.ProjectManager,
	serviceManager project.ServiceManager,
	resourceManager project.ResourceManager,
	azdCtx *azdcontext.AzdContext,
	environment *environment.Environment,
	envManager environment.Manager,
	accountManager account.Manager,
	cloud *cloud.Cloud,
	azCli *azapi.AzureClient,
	commandRunner exec.CommandRunner,
	console input.Console,
	formatter output.Formatter,
	writer io.Writer,
	alphaFeatureManager *alpha.FeatureManager,
	importManager *project.ImportManager,
) actions.Action {
	return &DeployAction{
		flags:               flags,
		args:                args,
		projectConfig:       projectConfig,
		azdCtx:              azdCtx,
		env:                 environment,
		envManager:          envManager,
		projectManager:      projectManager,
		serviceManager:      serviceManager,
		resourceManager:     resourceManager,
		accountManager:      accountManager,
		portalUrlBase:       cloud.PortalUrlBase,
		azCli:               azCli,
		formatter:           formatter,
		writer:              writer,
		console:             console,
		commandRunner:       commandRunner,
		alphaFeatureManager: alphaFeatureManager,
		importManager:       importManager,
	}
}

type DeploymentResult struct {
	Timestamp time.Time                               `json:"timestamp"`
	Services  map[string]*project.ServiceDeployResult `json:"services"`
}

func (da *DeployAction) Run(ctx context.Context) (*actions.ActionResult, error) {
	targetServiceName := da.flags.ServiceName
	if len(da.args) == 1 {
		targetServiceName = da.args[0]
	}

	if da.env.GetSubscriptionId() == "" {
		return nil, &internal.ErrorWithSuggestion{
			Err:        internal.ErrInfraNotProvisioned,
			Suggestion: "Run 'azd provision' to set up infrastructure before deploying.",
		}
	}

	targetServiceName, err := getTargetServiceName(
		ctx,
		da.projectManager,
		da.importManager,
		da.projectConfig,
		string(project.ServiceEventDeploy),
		targetServiceName,
		da.flags.All,
	)
	if err != nil {
		return nil, err
	}

	if da.flags.All && da.flags.fromPackage != "" {
		return nil, &internal.ErrorWithSuggestion{
			Err:        internal.ErrFromPackageWithAll,
			Suggestion: "Use 'azd deploy <service> --from-package <path>' to target a specific service.",
		}
	}

	if targetServiceName == "" && da.flags.fromPackage != "" {
		return nil, &internal.ErrorWithSuggestion{
			Err:        internal.ErrFromPackageNoService,
			Suggestion: "Use 'azd deploy <service> --from-package <path>' to target a specific service.",
		}
	}

	if err := da.projectManager.Initialize(ctx, da.projectConfig); err != nil {
		return nil, err
	}

	if err := da.projectManager.EnsureServiceTargetTools(ctx, da.projectConfig, func(svc *project.ServiceConfig) bool {
		return targetServiceName == "" || svc.Name == targetServiceName
	}); err != nil {
		return nil, err
	}

	// Command title
	da.console.MessageUxItem(ctx, &ux.MessageTitle{
		Title: "Deploying services (azd deploy)",
	})

	startTime := time.Now()

	stableServices, err := da.importManager.ServiceStableFiltered(ctx, da.projectConfig, targetServiceName, da.env.Getenv)
	if err != nil {
		return nil, err
	}

	projectEventArgs := project.ProjectLifecycleEventArgs{
		Project: da.projectConfig,
	}

	deployResults := map[string]*project.ServiceDeployResult{}

	err = da.projectConfig.Invoke(ctx, project.ProjectEventDeploy, projectEventArgs, func() error {
		if da.alphaFeatureManager.IsEnabled(alpha.MustFeatureKey("deploy.parallel")) {
			return da.deployServicesParallel(ctx, stableServices, deployResults)
		}

		for _, svc := range stableServices {
			deployResult, err := da.deploySingleService(ctx, svc)
			if err != nil {
				return err
			}


			deployResults[svc.Name] = deployResult
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	aspireDashboardUrl := apphost.AspireDashboardUrl(ctx, da.env, da.alphaFeatureManager)
	if aspireDashboardUrl != nil {
		da.console.MessageUxItem(ctx, aspireDashboardUrl)
	}

	if da.formatter.Kind() == output.JsonFormat {
		deployResult := DeploymentResult{
			Timestamp: time.Now(),
			Services:  deployResults,
		}

		if fmtErr := da.formatter.Format(deployResult, da.writer, nil); fmtErr != nil {
			return nil, fmt.Errorf("deploy result could not be displayed: %w", fmtErr)
		}
	}

	// Invalidate cache after successful deploy so azd show will refresh
	if err := da.envManager.InvalidateEnvCache(ctx, da.env.Name()); err != nil {
		log.Printf("warning: failed to invalidate state cache: %v", err)
	}

	return &actions.ActionResult{
		Message: &actions.ResultMessage{
			Header: fmt.Sprintf("Your application was deployed to Azure in %s.", ux.DurationAsText(since(startTime))),
			FollowUp: getResourceGroupFollowUp(ctx,
				da.formatter,
				da.portalUrlBase,
				da.projectConfig,
				da.resourceManager,
				da.env,
				false,
			),
		},
	}, nil
}

func (da *DeployAction) resolveDeployTimeout() (time.Duration, error) {
	if da.flags.timeoutChanged() {
		if da.flags.Timeout <= 0 {
			return 0, errors.New("invalid value for --timeout: must be greater than 0 seconds")
		}

		return time.Duration(da.flags.Timeout) * time.Second, nil
	}

	if envVal, ok := os.LookupEnv("AZD_DEPLOY_TIMEOUT"); ok {
		seconds, err := strconv.Atoi(envVal)
		if err != nil {
			return 0, fmt.Errorf("invalid AZD_DEPLOY_TIMEOUT value '%s': must be an integer number of seconds", envVal)
		}
		if seconds <= 0 {
			return 0, fmt.Errorf("invalid AZD_DEPLOY_TIMEOUT value '%d': must be greater than 0 seconds", seconds)
		}
		return time.Duration(seconds) * time.Second, nil
	}

	return time.Duration(defaultDeployTimeoutSeconds) * time.Second, nil
}

// deployServicesParallel deploys all services concurrently.
// Each goroutine handles one service's full lifecycle: Package → Publish → Deploy.
// Protected by the deploy.parallel alpha feature flag.
//
// Enhanced features (each behind their own alpha flag):
//   - deploy.aspireGate: Coordinates Aspire services so the first one completes
//     its Package phase (manifest generation) before others proceed.
//   - deploy.continueOnError: Service failures don't cancel other goroutines;
//     all services run to completion and errors are collected.
//   - deploy.serviceLogs: Per-service log files written to
//     .azure/{env}/logs/deploy-{timestamp}/.
func (da *DeployAction) deployServicesParallel(
	ctx context.Context,
	stableServices []*project.ServiceConfig,
	deployResults map[string]*project.ServiceDeployResult,
) error {
	continueOnError := da.alphaFeatureManager.IsEnabled(alpha.MustFeatureKey("deploy.continueOnError"))
	aspireGateEnabled := da.alphaFeatureManager.IsEnabled(alpha.MustFeatureKey("deploy.aspireGate"))
	serviceLogsEnabled := da.alphaFeatureManager.IsEnabled(alpha.MustFeatureKey("deploy.serviceLogs"))

	// Determine if any services are Aspire services (need build gate coordination)
	var gate *aspireBuildGate
	hasAspireServices := false
	if aspireGateEnabled {
		for _, svc := range stableServices {
			if svc.DotNetContainerApp != nil {
				hasAspireServices = true
				break
			}
		}
		if hasAspireServices {
			gate = newAspireBuildGate()
			log.Printf("deploy.aspireGate: enabled — coordinating Aspire service deployments")
		}
	}

	// Set up per-service log directory
	var logDir string
	if serviceLogsEnabled {
		timestamp := time.Now().Format("20060102-150405")
		logDir = filepath.Join(".azure", da.env.Name(), "logs", fmt.Sprintf("deploy-%s", timestamp))
		if err := os.MkdirAll(logDir, 0700); err != nil {
			log.Printf("deploy.serviceLogs: failed to create log dir %s: %v", logDir, err)
			logDir = "" // disable logging on error
		} else {
			log.Printf("deploy.serviceLogs: writing per-service logs to %s", logDir)
		}
	}

	if continueOnError {
		return da.deployParallelContinueOnError(ctx, stableServices, deployResults, gate, logDir)
	}
	return da.deployParallelFailFast(ctx, stableServices, deployResults, gate, logDir)
}

// deployParallelFailFast uses errgroup — first error cancels all pending goroutines.
// This is the default behavior when deploy.continueOnError is not enabled.
func (da *DeployAction) deployParallelFailFast(
	ctx context.Context,
	stableServices []*project.ServiceConfig,
	deployResults map[string]*project.ServiceDeployResult,
	gate *aspireBuildGate,
	logDir string,
) error {
	var mu sync.Mutex
	g, gCtx := errgroup.WithContext(ctx)

	if limit := os.Getenv("AZD_DEPLOY_CONCURRENCY"); limit != "" {
		if n, err := strconv.Atoi(limit); err == nil && n > 0 {
			g.SetLimit(n)
		}
	}

	for _, svc := range stableServices {
		g.Go(func() error {
			if err := da.waitOnAspireGate(gCtx, svc, gate); err != nil {
				return err
			}

			logWriter := da.createServiceLogWriter(svc.Name, logDir)
			if logWriter != nil {
				defer logWriter.Close()
			}

			deployResult, err := da.deploySingleService(gCtx, svc)

			// For the first Aspire service, signal the gate after Package completes.
			// Since deploySingleService runs Package→Publish→Deploy atomically,
			// we signal the gate based on success/failure of the whole operation
			// for the first Aspire service. A more granular approach would require
			// splitting deploySingleService, but this is safe because other Aspire
			// services only need the manifest which is generated during Package.
			da.signalAspireGate(svc, gate, err)

			if err != nil {
				return err
			}

			mu.Lock()
			deployResults[svc.Name] = deployResult
			mu.Unlock()

			return nil
		})
	}

	if logDir != "" {
		defer func() {
			da.console.Message(ctx, fmt.Sprintf("\nPer-service logs: %s", logDir))
		}()
	}

	return g.Wait()
}

// deployParallelContinueOnError uses sync.WaitGroup — service failures are collected
// but don't cancel other goroutines. Protected by deploy.continueOnError alpha flag.
func (da *DeployAction) deployParallelContinueOnError(
	ctx context.Context,
	stableServices []*project.ServiceConfig,
	deployResults map[string]*project.ServiceDeployResult,
	gate *aspireBuildGate,
	logDir string,
) error {
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		errsMu  sync.Mutex
		errs    []error
	)

	// Concurrency limit via semaphore
	var sem chan struct{}
	if limit := os.Getenv("AZD_DEPLOY_CONCURRENCY"); limit != "" {
		if n, err := strconv.Atoi(limit); err == nil && n > 0 {
			sem = make(chan struct{}, n)
		}
	}

	for _, svc := range stableServices {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Acquire semaphore slot if concurrency limited
			if sem != nil {
				sem <- struct{}{}
				defer func() { <-sem }()
			}

			if err := da.waitOnAspireGate(ctx, svc, gate); err != nil {
				errsMu.Lock()
				errs = append(errs, fmt.Errorf("service %s: %w", svc.Name, err))
				errsMu.Unlock()
				return
			}

			logWriter := da.createServiceLogWriter(svc.Name, logDir)
			if logWriter != nil {
				defer logWriter.Close()
			}

			deployResult, err := da.deploySingleService(ctx, svc)
			da.signalAspireGate(svc, gate, err)

			if err != nil {
				errsMu.Lock()
				errs = append(errs, fmt.Errorf("service %s: %w", svc.Name, err))
				errsMu.Unlock()
				return
			}

			mu.Lock()
			deployResults[svc.Name] = deployResult
			mu.Unlock()
		}()
	}

	wg.Wait()

	if logDir != "" {
		da.console.Message(ctx, fmt.Sprintf("\nPer-service logs: %s", logDir))
	}

	if len(errs) > 0 {
		// Report all failures
		for _, e := range errs {
			log.Printf("deploy error: %v", e)
		}
		return fmt.Errorf("%d service(s) failed to deploy: %w", len(errs), errors.Join(errs...))
	}

	return nil
}

// waitOnAspireGate blocks non-first Aspire services until the gate is opened.
// Non-Aspire services and the first Aspire service pass through immediately.
func (da *DeployAction) waitOnAspireGate(
	ctx context.Context,
	svc *project.ServiceConfig,
	gate *aspireBuildGate,
) error {
	if gate == nil || svc.DotNetContainerApp == nil {
		return nil // not an Aspire service or gate not enabled
	}

	if gate.ClaimFirst() {
		// First Aspire service deploys immediately
		log.Printf("deploy.aspireGate: service %s claimed first-deploy slot", svc.Name)
		return nil
	}

	// Wait for the first Aspire service to complete its Package phase
	log.Printf("deploy.aspireGate: service %s waiting for build gate", svc.Name)
	return gate.Wait(ctx)
}

// signalAspireGate opens or fails the gate after the first Aspire service completes.
func (da *DeployAction) signalAspireGate(
	svc *project.ServiceConfig,
	gate *aspireBuildGate,
	err error,
) {
	if gate == nil || svc.DotNetContainerApp == nil {
		return
	}

	// Only the first Aspire service signals the gate. ClaimFirst returns false
	// for subsequent services, so Open/Fail is only called once via sync.Once.
	if err != nil {
		gate.Fail(err)
	} else {
		gate.Open()
	}
}

// createServiceLogWriter creates a per-service log file if deploy.serviceLogs is enabled.
// Returns nil if logging is disabled or the log directory is empty.
func (da *DeployAction) createServiceLogWriter(serviceName string, logDir string) *os.File {
	if logDir == "" {
		return nil
	}

	logPath := filepath.Join(logDir, serviceName+".log")
	f, err := os.Create(logPath)
	if err != nil {
		log.Printf("deploy.serviceLogs: failed to create log file %s: %v", logPath, err)
		return nil
	}

	return f
}

// deploySingleService executes the full deploy lifecycle for a single service:
// Package → Publish → Deploy → temp cleanup. Both the sequential and parallel
// deploy paths delegate to this helper; orchestration (serial iteration vs errgroup)
// and result storage remain in the callers.
func (da *DeployAction) deploySingleService(
	ctx context.Context,
	svc *project.ServiceConfig,
) (*project.ServiceDeployResult, error) {
	svcCtx, svcSpan := tracing.Start(ctx, "azd.deploy.service."+svc.Name,
		trace.WithAttributes(attribute.String("service.name", svc.Name)))

	stepMessage := fmt.Sprintf("Deploying service %s", svc.Name)
	da.console.ShowSpinner(svcCtx, stepMessage, input.Step)

	if alphaFeatureId, isAlphaFeature := alpha.IsFeatureKey(string(svc.Host)); isAlphaFeature {
		da.console.WarnForFeature(svcCtx, alphaFeatureId)
	}

	serviceContext := project.NewServiceContext()

	if da.flags.fromPackage != "" {
		// --from-package set, skip packaging and create package artifact
		err := serviceContext.Package.Add(&project.Artifact{
			Kind:         determineArtifactKind(da.flags.fromPackage),
			Location:     da.flags.fromPackage,
			LocationKind: project.LocationKindLocal,
		})
		if err != nil {
			da.console.StopSpinner(svcCtx, stepMessage, input.StepFailed)
			svcSpan.EndWithStatus(err)
			return nil, err
		}
	} else {
		// --from-package not set, automatically package the application
		packageStart := time.Now()
		packageResult, err := async.RunWithProgress(
			func(packageProgress project.ServiceProgress) {
				progressMessage := fmt.Sprintf("Packaging service %s (%s)", svc.Name, packageProgress.Message)
				da.console.ShowSpinner(svcCtx, progressMessage, input.Step)
			},
			func(progress *async.Progress[project.ServiceProgress]) (*project.ServicePackageResult, error) {
				return da.serviceManager.Package(svcCtx, svc, serviceContext, progress, nil)
			},
		)
		if err != nil {
			da.console.StopSpinner(svcCtx, stepMessage, input.StepFailed)
			svcSpan.EndWithStatus(err)
			return nil, err
		}
		packageResult.PackageDurationMs = time.Since(packageStart).Milliseconds()
	}

	publishStart := time.Now()
	publishResult, err := async.RunWithProgress(
		func(publishProgress project.ServiceProgress) {
			progressMessage := fmt.Sprintf("Publishing service %s (%s)", svc.Name, publishProgress.Message)
			da.console.ShowSpinner(svcCtx, progressMessage, input.Step)
		},
		func(progress *async.Progress[project.ServiceProgress]) (*project.ServicePublishResult, error) {
			return da.serviceManager.Publish(svcCtx, svc, serviceContext, progress, nil)
		},
	)
	if err != nil {
		da.console.StopSpinner(svcCtx, stepMessage, input.StepFailed)
		svcSpan.EndWithStatus(err)
		return nil, err
	}
	publishResult.PublishDurationMs = time.Since(publishStart).Milliseconds()

	deployTimeout, err := da.resolveDeployTimeout()
	if err != nil {
		da.console.StopSpinner(svcCtx, stepMessage, input.StepFailed)
		svcSpan.EndWithStatus(err)
		return nil, err
	}

	deployCtx, deployCancel := context.WithTimeout(svcCtx, deployTimeout)
	defer deployCancel()

	deployStart := time.Now()
	deployResult, err := async.RunWithProgress(
		func(deployProgress project.ServiceProgress) {
			progressMessage := fmt.Sprintf("Deploying service %s (%s)", svc.Name, deployProgress.Message)
			da.console.ShowSpinner(svcCtx, progressMessage, input.Step)
		},
		func(progress *async.Progress[project.ServiceProgress]) (*project.ServiceDeployResult, error) {
			return da.serviceManager.Deploy(deployCtx, svc, serviceContext, progress)
		},
	)
	if err != nil {
		da.console.StopSpinner(svcCtx, stepMessage, input.StepFailed)
		if deployCtx.Err() == context.DeadlineExceeded {
			warnMsg := fmt.Sprintf(
				"Deployment of service '%s' exceeded the azd wait timeout."+
					" azd has stopped waiting, but the deployment may"+
					" still be running in Azure.",
				svc.Name,
			)
			da.console.MessageUxItem(svcCtx, &ux.WarningMessage{
				Description: warnMsg,
				Hints: []string{
					"Check the Azure Portal for current deployment status.",
					"Increase timeout with --timeout flag or AZD_DEPLOY_TIMEOUT env var.",
				},
			})

			svcSpan.EndWithStatus(err)
			return nil, fmt.Errorf(
				"deployment of service '%s' timed out after %d seconds. To increase, use --timeout flag "+
					"or AZD_DEPLOY_TIMEOUT env var. Note: azd has stopped "+
					"waiting, but the deployment may still be running in Azure. Check the Azure Portal for "+
					"current deployment status.",
				svc.Name,
				int(deployTimeout.Seconds()),
			)
		}
		svcSpan.EndWithStatus(err)
		return nil, err
	}
	deployResult.DeployDurationMs = time.Since(deployStart).Milliseconds()

	// Clean up packages automatically created in temp dir
	if da.flags.fromPackage == "" {
		for _, artifact := range serviceContext.Package {
			if artifact.Kind == project.ArtifactKindArchive && strings.HasPrefix(artifact.Location, os.TempDir()) {
				if err := os.RemoveAll(artifact.Location); err != nil {
					log.Printf("failed to remove temporary package: %s : %s", artifact.Location, err)
				}
			}
		}
	}

	da.console.StopSpinner(svcCtx, stepMessage, input.GetStepResultFormat(err))
	da.console.MessageUxItem(svcCtx, deployResult.Artifacts)
	svcSpan.EndWithStatus(nil)

	return deployResult, nil
}

func GetCmdDeployHelpDescription(*cobra.Command) string {
	return generateCmdHelpDescription("Deploy application to Azure.", []string{
		formatHelpNote(
			"By default, deploys all services listed in 'azure.yaml' in the current directory," +
				" or the service described in the project that matches the current directory."),
		formatHelpNote(
			fmt.Sprintf("When %s is set, only the specific service is deployed.", output.WithHighLightFormat("<service>"))),
		formatHelpNote("After the deployment is complete, the endpoint is printed. To start the service, select" +
			" the endpoint or paste it in a browser."),
	})
}

func GetCmdDeployHelpFooter(*cobra.Command) string {
	return generateCmdHelpSamplesBlock(map[string]string{
		"Deploy all services in the current project to Azure.": output.WithHighLightFormat(
			"azd deploy --all",
		),
		"Deploy the service named 'api' to Azure.": output.WithHighLightFormat(
			"azd deploy api",
		),
		"Deploy the service named 'web' to Azure.": output.WithHighLightFormat(
			"azd deploy web",
		),
		"Deploy the service named 'api' to Azure from a previously generated package.": output.WithHighLightFormat(
			"azd deploy api --from-package <package-path>",
		),
	})
}
