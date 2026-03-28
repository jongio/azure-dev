// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package cmd

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/azure/azure-dev/cli/azd/cmd/actions"
	"github.com/azure/azure-dev/cli/azd/internal"
	"github.com/azure/azure-dev/cli/azd/internal/tracing"
	"github.com/azure/azure-dev/cli/azd/pkg/account"
	"github.com/azure/azure-dev/cli/azd/pkg/alpha"
	"github.com/azure/azure-dev/cli/azd/pkg/azapi"
	"github.com/azure/azure-dev/cli/azd/pkg/azsdk/storage"
	"github.com/azure/azure-dev/cli/azd/pkg/cloud"
	"github.com/azure/azure-dev/cli/azd/pkg/contracts"
	"github.com/azure/azure-dev/cli/azd/pkg/environment"
	"github.com/azure/azure-dev/cli/azd/pkg/infra/provisioning"
	"github.com/azure/azure-dev/cli/azd/pkg/infra/provisioning/bicep"
	"github.com/azure/azure-dev/cli/azd/pkg/input"
	"github.com/azure/azure-dev/cli/azd/pkg/ioc"
	"github.com/azure/azure-dev/cli/azd/pkg/output"
	"github.com/azure/azure-dev/cli/azd/pkg/output/ux"
	"github.com/azure/azure-dev/cli/azd/pkg/project"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/multierr"
	"golang.org/x/sync/errgroup"
)

type ProvisionFlags struct {
	global *internal.GlobalCommandOptions
	*internal.EnvFlag
	subscription          string
	location              string
	noProgress            bool
	preview               bool
	ignoreDeploymentState bool
}

const (
	AINotValid                  = "is not valid according to the validation procedure"
	openAIsubscriptionNoQuotaId = "The subscription does not have QuotaId/Feature required by SKU 'S0' " +
		"from kind 'OpenAI'"
	responsibleAITerms              = "until you agree to Responsible AI terms for this resource"
	specialFeatureOrQuotaIdRequired = "SpecialFeatureOrQuotaIdRequired"
)

func (i *ProvisionFlags) Bind(local *pflag.FlagSet, global *internal.GlobalCommandOptions) {
	i.BindNonCommon(local, global)
	i.bindCommon(local, global)
}

func (i *ProvisionFlags) BindNonCommon(local *pflag.FlagSet, global *internal.GlobalCommandOptions) {
	local.BoolVar(&i.noProgress, "no-progress", false, "Suppresses progress information.")
	//deprecate:Flag hide --no-progress
	_ = local.MarkHidden("no-progress")
	local.StringVar(
		&i.subscription,
		"subscription",
		"",
		"ID of an Azure subscription to use for the new environment",
	)
	local.StringVarP(&i.location, "location", "l", "", "Azure location for the new environment")
	i.global = global
}

// Subscription returns the value of the --subscription flag.
func (i *ProvisionFlags) Subscription() string {
	return i.subscription
}

// Location returns the value of the --location flag.
func (i *ProvisionFlags) Location() string {
	return i.location
}

func (i *ProvisionFlags) bindCommon(local *pflag.FlagSet, global *internal.GlobalCommandOptions) {
	local.BoolVar(&i.preview, "preview", false, "Preview changes to Azure resources.")
	local.BoolVar(
		&i.ignoreDeploymentState,
		"no-state",
		false,
		"(Bicep only) Forces a fresh deployment based on current Bicep template files, "+
			"ignoring any stored deployment state.")

	i.EnvFlag = &internal.EnvFlag{}
	i.EnvFlag.Bind(local, global)
}

func (i *ProvisionFlags) SetCommon(envFlag *internal.EnvFlag) {
	i.EnvFlag = envFlag
}

func NewProvisionFlags(cmd *cobra.Command, global *internal.GlobalCommandOptions) *ProvisionFlags {
	flags := &ProvisionFlags{}
	flags.Bind(cmd.Flags(), global)

	return flags
}

func NewProvisionFlagsFromEnvAndOptions(envFlag *internal.EnvFlag, global *internal.GlobalCommandOptions) *ProvisionFlags {
	flags := &ProvisionFlags{
		EnvFlag: envFlag,
		global:  global,
	}

	return flags
}

func NewProvisionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "provision [<layer>]",
		Short: "Provision Azure resources for your project.",
	}
	cmd.Args = cobra.MaximumNArgs(1)

	return cmd
}

type ProvisionAction struct {
	projectManager  project.ProjectManager
	resourceManager project.ResourceManager
	envManager      environment.Manager
	formatter       output.Formatter
	writer          io.Writer
	console         input.Console
	// Dependencies for creating per-layer provisioning managers in parallel provisioning.
	serviceLocator      ioc.ServiceLocator
	fileShareService    storage.FileShareService
	flags               *ProvisionFlags
	provisionManager    *provisioning.Manager
	env                 *environment.Environment
	projectConfig       *project.ProjectConfig
	subManager          *account.SubscriptionsManager
	importManager       *project.ImportManager
	alphaFeatureManager *alpha.FeatureManager
	defaultProvider     provisioning.DefaultProviderResolver
	cloud               *cloud.Cloud
	portalUrlBase       string
	args                []string
}

func NewProvisionAction(
	args []string,
	flags *ProvisionFlags,
	provisionManager *provisioning.Manager,
	projectManager project.ProjectManager,
	importManager *project.ImportManager,
	resourceManager project.ResourceManager,
	projectConfig *project.ProjectConfig,
	env *environment.Environment,
	envManager environment.Manager,
	console input.Console,
	formatter output.Formatter,
	writer io.Writer,
	subManager *account.SubscriptionsManager,
	alphaFeatureManager *alpha.FeatureManager,
	cloud *cloud.Cloud,
	serviceLocator ioc.ServiceLocator,
	defaultProvider provisioning.DefaultProviderResolver,
	fileShareService storage.FileShareService,
) actions.Action {
	return &ProvisionAction{
		args:                args,
		flags:               flags,
		provisionManager:    provisionManager,
		projectManager:      projectManager,
		resourceManager:     resourceManager,
		env:                 env,
		envManager:          envManager,
		formatter:           formatter,
		projectConfig:       projectConfig,
		writer:              writer,
		console:             console,
		subManager:          subManager,
		importManager:       importManager,
		alphaFeatureManager: alphaFeatureManager,
		portalUrlBase:       cloud.PortalUrlBase,
		serviceLocator:      serviceLocator,
		defaultProvider:     defaultProvider,
		fileShareService:    fileShareService,
		cloud:               cloud,
	}
}

// SetFlags sets the flags for the provision action. Panics if `flags` is nil
func (p *ProvisionAction) SetFlags(flags *ProvisionFlags) {
	if flags == nil {
		panic("flags is nil")
	}

	p.flags = flags
}

// ProvisionResult wraps the provisioning state with timing data for JSON output.
type ProvisionResult struct {
	State      contracts.EnvRefreshResult `json:"state"`
	DurationMs int64                      `json:"durationMs"`
}

func (p *ProvisionAction) Run(ctx context.Context) (_ *actions.ActionResult, runErr error) {
	if p.flags.noProgress {
		fmt.Fprintln(
			p.console.Handles().Stderr,
			//nolint:Lll
			output.WithWarningFormat(
				"WARNING: The '--no-progress' flag is deprecated and will be removed in a future release.",
			),
		)
	}
	previewMode := p.flags.preview

	// Command title
	defaultTitle := "Provisioning Azure resources (azd provision)"
	defaultTitleNote := "Provisioning Azure resources can take some time"
	if previewMode {
		defaultTitle = "Previewing Azure resource changes (azd provision --preview)"
		defaultTitleNote = "This is a preview. No changes will be applied to your Azure resources."
	}

	p.console.MessageUxItem(ctx, &ux.MessageTitle{
		Title:     defaultTitle,
		TitleNote: defaultTitleNote},
	)

	startTime := time.Now()

	ctx, provisionSpan := tracing.Start(ctx, "azd.provision",
		trace.WithAttributes(attribute.String("phase", "provision")))
	defer func() { provisionSpan.EndWithStatus(runErr) }()

	if err := p.projectManager.Initialize(ctx, p.projectConfig); err != nil {
		return nil, err
	}

	if err := p.projectManager.EnsureAllTools(ctx, p.projectConfig, nil); err != nil {
		return nil, err
	}

	// Apply --subscription and --location flags to the environment before provisioning
	envChanged := false
	if p.flags.subscription != "" {
		if existing := p.env.GetSubscriptionId(); existing != "" && existing != p.flags.subscription {
			return nil, &internal.ErrorWithSuggestion{
				Err: fmt.Errorf(
					"environment '%s' (current: %s, requested: %s): %w",
					p.env.Name(), existing, p.flags.subscription, internal.ErrCannotChangeSubscription),
				Suggestion: "Run 'azd env new <name>' to create a new environment with a different subscription.",
			}
		}
		p.env.SetSubscriptionId(p.flags.subscription)
		envChanged = true
	}
	if p.flags.location != "" {
		if existing := p.env.GetLocation(); existing != "" && existing != p.flags.location {
			return nil, &internal.ErrorWithSuggestion{
				Err: fmt.Errorf(
					"environment '%s' (current: %s, requested: %s): %w",
					p.env.Name(), existing, p.flags.location, internal.ErrCannotChangeLocation),
				Suggestion: "Run 'azd env new <name>' to create a new environment with a different location.",
			}
		}
		p.env.SetLocation(p.flags.location)
		envChanged = true
	}
	if envChanged {
		if err := p.envManager.Save(ctx, p.env); err != nil {
			return nil, fmt.Errorf("saving environment: %w", err)
		}
	}

	infra, err := p.importManager.ProjectInfrastructure(ctx, p.projectConfig)
	if err != nil {
		return nil, err
	}
	defer func() { _ = infra.Cleanup() }()

	layer := ""
	if len(p.args) > 0 {
		layer = p.args[0]
	}

	layers := infra.Options.GetLayers()
	if layer != "" {
		layerOption, err := infra.Options.GetLayer(layer)
		if err != nil {
			return nil, err
		}

		layers = []provisioning.Options{layerOption}
	}

	if previewMode && len(layers) > 1 {
		return nil, &internal.ErrorWithSuggestion{
			Err:        internal.ErrPreviewMultipleLayers,
			Suggestion: "Run 'azd provision --preview <layer-name>' targeting a single layer.",
		}
	}

	var allSkipped bool

	// Route to parallel provisioning when the alpha feature is enabled,
	// there are multiple layers, and we're not in preview mode.
	if !previewMode && len(layers) > 1 &&
		p.alphaFeatureManager.IsEnabled(alpha.MustFeatureKey("provision.parallel")) {
		p.console.WarnForFeature(ctx, alpha.MustFeatureKey("provision.parallel"))

		var parallelErr error
		allSkipped, parallelErr = p.provisionLayersParallel(ctx, layers)
		if parallelErr != nil {
			return nil, parallelErr
		}

		// Output JSON with timing data for the parallel path.
		// Uses the shared provisionManager (initialized for layer[0]) for state.
		// NOTE: The parallel path uses ProvisionResult (with durationMs) intentionally —
		// this is new behavior behind the provision.parallel alpha feature flag.
		if p.formatter.Kind() == output.JsonFormat {
			stateResult, err := p.provisionManager.State(ctx, nil)
			if err != nil {
				return nil, fmt.Errorf(
					"deployment succeeded but the deployment result is unavailable: %w", err)
			}

			provisionResult := ProvisionResult{
				State:      provisioning.NewEnvRefreshResultFromState(stateResult.State),
				DurationMs: time.Since(startTime).Milliseconds(),
			}

			if err := p.formatter.Format(provisionResult, p.writer, nil); err != nil {
				return nil, fmt.Errorf(
					"deployment succeeded but the deployment result could not be displayed: %w", err)
			}
		}
	} else {
		// Sequential provisioning path — the original behavior.
		var seqErr error
		allSkipped, seqErr = p.provisionLayersSequential(ctx, layers, startTime, previewMode)
		if seqErr != nil {
			return nil, seqErr
		}
		// In preview mode, provisionLayersSequential already displayed the UX items.
		// Return the preview ActionResult here since the caller owns the final response.
		if previewMode {
			return &actions.ActionResult{
				Message: &actions.ResultMessage{
					Header: fmt.Sprintf(
						"Generated provisioning preview in %s.", ux.DurationAsText(since(startTime))),
					FollowUp: getResourceGroupFollowUp(
						ctx,
						p.formatter,
						p.portalUrlBase,
						p.projectConfig,
						p.resourceManager,
						p.env,
						true,
					),
				},
			}, nil
		}
	}

	if allSkipped {
		return &actions.ActionResult{
			Message: &actions.ResultMessage{
				Header: "There are no changes to provision for your application.",
			},
		}, nil
	}

	// Invalidate cache after successful provisioning so next azd show will refresh
	if err := p.envManager.InvalidateEnvCache(ctx, p.env.Name()); err != nil {
		log.Printf("warning: failed to invalidate state cache: %v", err)
	}

	return &actions.ActionResult{
		Message: &actions.ResultMessage{
			Header: fmt.Sprintf(
				"Your application was provisioned in Azure in %s.", ux.DurationAsText(since(startTime))),
			FollowUp: getResourceGroupFollowUp(
				ctx,
				p.formatter,
				p.portalUrlBase,
				p.projectConfig,
				p.resourceManager,
				p.env,
				false,
			),
		},
	}, nil
}

// syncEnvManager wraps environment.Manager with a mutex around Save and SaveWithOptions
// to serialize .env file writes when multiple provisioning managers run concurrently.
// The LocalFileDataStore.Save uses a read-merge-write cycle that is not safe for concurrent callers.
type syncEnvManager struct {
	environment.Manager
	mu sync.Mutex
}

func (s *syncEnvManager) Save(ctx context.Context, env *environment.Environment) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Manager.Save(ctx, env)
}

func (s *syncEnvManager) SaveWithOptions(
	ctx context.Context, env *environment.Environment, options *environment.SaveOptions,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Manager.SaveWithOptions(ctx, env, options)
}

// syncConsole wraps input.Console with a mutex around all write-path methods
// (Message, MessageUxItem, ShowSpinner, StopSpinner, WarnForFeature, EnsureBlankLine)
// to prevent data races when multiple goroutines write to the console concurrently.
// Read-only and prompt methods delegate to the embedded Console without synchronization.
type syncConsole struct {
	input.Console
	mu sync.Mutex
}

func (s *syncConsole) Message(ctx context.Context, message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Console.Message(ctx, message)
}

func (s *syncConsole) MessageUxItem(ctx context.Context, item ux.UxItem) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Console.MessageUxItem(ctx, item)
}

func (s *syncConsole) ShowSpinner(ctx context.Context, title string, format input.SpinnerUxType) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Console.ShowSpinner(ctx, title, format)
}

func (s *syncConsole) StopSpinner(ctx context.Context, lastMessage string, format input.SpinnerUxType) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Console.StopSpinner(ctx, lastMessage, format)
}

func (s *syncConsole) WarnForFeature(ctx context.Context, id alpha.FeatureId) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Console.WarnForFeature(ctx, id)
}

func (s *syncConsole) EnsureBlankLine(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Console.EnsureBlankLine(ctx)
}

// layerResult holds the outcome of a single layer's provisioning.
type layerResult struct {
	deploy  *provisioning.DeployResult
	layer   provisioning.Options
	skipped bool
}

// provisionLayersParallel provisions multiple infrastructure layers concurrently
// with dependency-aware phased scheduling.
//
// It statically analyzes Bicep templates and parameter files to build a dependency
// graph, then groups layers into phases using topological sort. Layers within a phase
// have no inter-dependencies and run concurrently. After each phase completes,
// deployment outputs are merged into the shared environment so that subsequent phases
// can reference them.
//
// If dependency analysis fails (e.g., unreadable files), it falls back to launching
// all layers in a single phase (the original behavior).
//
// Each layer gets its own provisioning.Manager and a cloned Environment to avoid
// concurrent map writes (environment.Environment is not goroutine-safe).
// The syncEnvManager serializes .env file writes across goroutines.
func (p *ProvisionAction) provisionLayersParallel(
	ctx context.Context,
	layers []provisioning.Options,
) (bool, error) {
	// Initialize the first layer using the shared manager to ensure the environment is ready
	// (subscription/location prompts may fire during initialization).
	layers[0].IgnoreDeploymentState = p.flags.ignoreDeploymentState
	if err := p.provisionManager.Initialize(ctx, p.projectConfig.Path, layers[0]); err != nil {
		return false, fmt.Errorf("initializing provisioning manager: %w", err)
	}

	// Display subscription and location once before parallel provisioning begins.
	p.displaySubscriptionAndLocation(ctx)

	// Analyze layer dependencies to determine execution phases.
	phases, err := bicep.AnalyzeLayerDependencies(layers, p.projectConfig.Path, p.env)
	if err != nil {
		// Dependency analysis is best-effort. If it fails, fall back to running all
		// layers in a single phase (the original parallel behavior).
		log.Printf("layer dependency analysis failed, falling back to single-phase parallel: %v", err)
		allIndices := make([]int, len(layers))
		for i := range layers {
			allIndices[i] = i
		}
		phases = [][]int{allIndices}
	}

	safeEnvManager := &syncEnvManager{Manager: p.envManager}
	safeConsole := &syncConsole{Console: p.console}

	// Resolve stable services once — the set doesn't change between layers.
	servicesStable, err := p.importManager.ServiceStable(ctx, p.projectConfig)
	if err != nil {
		return false, err
	}

	allSkipped := true

	// Execute phases sequentially. Within each phase, layers run concurrently.
	for _, phase := range phases {
		phaseResults := make([]layerResult, len(phase))
		g, gCtx := errgroup.WithContext(ctx)

		// Collect ALL errors from goroutines, not just the first.
		var errsMu sync.Mutex
		var errs []error

		// Optional concurrency limit from env var (mirrors deploy.parallel pattern).
		if limit := os.Getenv("AZD_PROVISION_CONCURRENCY"); limit != "" {
			if n, parseErr := strconv.Atoi(limit); parseErr == nil && n > 0 {
				g.SetLimit(n)
			} else {
				log.Printf("invalid AZD_PROVISION_CONCURRENCY value %q: %v", limit, parseErr)
			}
		}

		for j, layerIdx := range phase {
			layer := layers[layerIdx]
			layer.IgnoreDeploymentState = p.flags.ignoreDeploymentState

			g.Go(func() error {
				result, err := p.provisionSingleLayer(gCtx, layer, safeEnvManager, safeConsole)
				phaseResults[j] = result
				if err != nil {
					errsMu.Lock()
					errs = append(errs, err)
					errsMu.Unlock()
					return err
				}
				return nil
			})
		}

		// Wait preserves errgroup's context cancellation. Then combine all collected errors.
		_ = g.Wait()
		if combined := multierr.Combine(errs...); combined != nil {
			return false, p.wrapProvisionError(combined)
		}

		// Phase complete. Merge deployment outputs into the authoritative environment
		// so that subsequent phases can reference them via readEnvironmentVariable()
		// or ${VAR} substitutions.
		for _, r := range phaseResults {
			if r.skipped {
				continue
			}
			allSkipped = false

			if r.deploy == nil || r.deploy.Deployment == nil {
				continue
			}

			if err := provisioning.UpdateEnvironment(
				ctx, r.deploy.Deployment.Outputs, p.env, p.envManager,
			); err != nil {
				return false, fmt.Errorf("updating environment from layer %q: %w", r.layer.Name, err)
			}

			for _, svc := range servicesStable {
				eventArgs := project.ServiceLifecycleEventArgs{
					Project:        p.projectConfig,
					Service:        svc,
					ServiceContext: project.NewServiceContext(),
					Args: map[string]any{
						"bicepOutput": r.deploy.Deployment.Outputs,
					},
				}

				if err := svc.RaiseEvent(ctx, project.ServiceEventEnvUpdated, eventArgs); err != nil {
					return false, err
				}
			}
		}
	}

	return allSkipped, nil
}

// provisionSingleLayer provisions one infrastructure layer using a dedicated Manager
// and a cloned Environment. The syncEnvManager serializes .env file writes across
// concurrent goroutines. The console parameter should be a syncConsole when called
// from the parallel path. This helper is called from provisionLayersParallel.
func (p *ProvisionAction) provisionSingleLayer(
	ctx context.Context,
	layer provisioning.Options,
	safeEnvManager *syncEnvManager,
	console input.Console,
) (layerResult, error) {
	// Create a per-layer Environment clone so concurrent DotenvSet calls
	// from Manager.Deploy → UpdateEnvironment don't race on the same map.
	layerEnv := environment.NewWithValues(p.env.Name(), p.env.Dotenv())

	// Create a dedicated Manager for this layer. The syncEnvManager serializes
	// .env file writes; each Manager's internal UpdateEnvironment writes to its
	// own cloned env and then calls Save through the serialized wrapper.
	// The console parameter is passed to the Manager so its internal console
	// calls are also synchronized when running in parallel.
	//
	// Thread-safety of serviceLocator: The ioc.NestedContainer is initialized once
	// during application startup. By the time parallel provisioning runs, the container
	// is fully populated and only Resolve() (read path) is called concurrently.
	// The underlying golobby/container uses a read-after-init pattern with map lookups;
	// concurrent reads without writes are safe in Go. No registration (write) occurs here.
	mgr := provisioning.NewManager(
		p.serviceLocator,
		p.defaultProvider,
		safeEnvManager,
		layerEnv,
		console,
		p.alphaFeatureManager,
		p.fileShareService,
		p.cloud,
	)

	if err := mgr.Initialize(ctx, p.projectConfig.Path, layer); err != nil {
		return layerResult{}, fmt.Errorf("initializing provisioning manager for layer %q: %w", layer.Name, err)
	}

	if layer.Name != "" {
		console.Message(ctx, fmt.Sprintf("Layer: %s", output.WithHighLightFormat(layer.Name)))
	}
	console.Message(ctx, "")

	if p.alphaFeatureManager.IsEnabled(azapi.FeatureDeploymentStacks) {
		console.WarnForFeature(ctx, azapi.FeatureDeploymentStacks)
	}

	projectEventArgs := project.ProjectLifecycleEventArgs{
		Project: p.projectConfig,
	}

	var deployResult *provisioning.DeployResult
	err := p.projectConfig.Invoke(ctx, project.ProjectEventProvision, projectEventArgs, func() error {
		var err error
		deployResult, err = mgr.Deploy(ctx)
		return err
	})

	result := layerResult{
		layer:  layer,
		deploy: deployResult,
	}

	if err != nil {
		return result, fmt.Errorf("deployment failed for layer %q: %w", layer.Name, err)
	}

	if deployResult != nil {
		result.skipped = deployResult.SkippedReason == provisioning.DeploymentStateSkipped
	}
	return result, nil
}

// provisionLayersSequential provisions infrastructure layers one at a time.
// This is the original provisioning path used when parallel provisioning is disabled
// or not applicable (single layer, preview mode).
//
// The method preserves the original --output json contract: it emits EnvRefreshResult
// directly (without the ProvisionResult wrapper used by the parallel path) so that
// existing automation consuming the JSON output is not broken.
func (p *ProvisionAction) provisionLayersSequential(
	ctx context.Context,
	layers []provisioning.Options,
	startTime time.Time,
	previewMode bool,
) (bool, error) {
	allSkipped := true

	for i, layer := range layers {
		layer.IgnoreDeploymentState = p.flags.ignoreDeploymentState
		if err := p.provisionManager.Initialize(ctx, p.projectConfig.Path, layer); err != nil {
			return false, fmt.Errorf("initializing provisioning manager: %w", err)
		}

		if i == 0 { // only display once
			// Get Subscription to Display in Command Title Note
			// Subscription and Location are ONLY displayed when they are available (found from env),
			// otherwise, this message is not displayed.
			// This needs to happen after the provisionManager initializes to make sure the env is
			// ready for the provisioning provider
			p.displaySubscriptionAndLocation(ctx)
		} else {
			// separation between each layer
			p.console.Message(ctx, "")
		}

		if layer.Name != "" {
			p.console.Message(ctx, fmt.Sprintf("Layer: %s", output.WithHighLightFormat(layer.Name)))
		}
		p.console.Message(ctx, "")

		var deployResult *provisioning.DeployResult
		var deployPreviewResult *provisioning.DeployPreviewResult
		var err error

		projectEventArgs := project.ProjectLifecycleEventArgs{
			Project: p.projectConfig,
		}

		if p.alphaFeatureManager.IsEnabled(azapi.FeatureDeploymentStacks) {
			p.console.WarnForFeature(ctx, azapi.FeatureDeploymentStacks)
		}

		// Do not raise pre/postprovision events in preview mode
		if previewMode {
			deployPreviewResult, err = p.provisionManager.Preview(ctx)
		} else {
			err = p.projectConfig.Invoke(ctx, project.ProjectEventProvision, projectEventArgs, func() error {
				var err error
				deployResult, err = p.provisionManager.Deploy(ctx)
				return err
			})
		}

		if err != nil {
			// Sequential path: emit EnvRefreshResult directly (preserves backward compat).
			if p.formatter.Kind() == output.JsonFormat {
				stateResult, stateErr := p.provisionManager.State(ctx, nil)
				if stateErr != nil {
					return false, fmt.Errorf(
						"deployment failed and the deployment result is unavailable: %w",
						multierr.Combine(err, stateErr),
					)
				}

				envResult := provisioning.NewEnvRefreshResultFromState(stateResult.State)
				if fmtErr := p.formatter.Format(envResult, p.writer, nil); fmtErr != nil {
					return false, fmt.Errorf(
						"deployment failed and the deployment result could not be displayed: %w",
						multierr.Combine(err, fmtErr),
					)
				}
			}

			return false, p.wrapProvisionError(err)
		}

		if previewMode {
			p.console.MessageUxItem(ctx, deployResultToUx(deployPreviewResult))
			// Return allSkipped=false; the caller handles the preview ActionResult.
			return false, nil
		}

		skipped := deployResult.SkippedReason == provisioning.DeploymentStateSkipped
		allSkipped = allSkipped && skipped
		if skipped {
			// Simply continue here; message is printed in the provider implementation
			continue
		}

		servicesStable, err := p.importManager.ServiceStable(ctx, p.projectConfig)
		if err != nil {
			return false, err
		}

		for _, svc := range servicesStable {
			eventArgs := project.ServiceLifecycleEventArgs{
				Project:        p.projectConfig,
				Service:        svc,
				ServiceContext: project.NewServiceContext(),
				Args: map[string]any{
					"bicepOutput": deployResult.Deployment.Outputs,
				},
			}

			if err := svc.RaiseEvent(ctx, project.ServiceEventEnvUpdated, eventArgs); err != nil {
				return false, err
			}
		}

		// Sequential path: emit EnvRefreshResult directly (preserves backward compat).
		if p.formatter.Kind() == output.JsonFormat {
			stateResult, err := p.provisionManager.State(ctx, nil)
			if err != nil {
				return false, fmt.Errorf(
					"deployment succeeded but the deployment result is unavailable: %w", err)
			}

			envResult := provisioning.NewEnvRefreshResultFromState(stateResult.State)
			if err := p.formatter.Format(envResult, p.writer, nil); err != nil {
				return false, fmt.Errorf(
					"deployment succeeded but the deployment result could not be displayed: %w", err)
			}
		}
	}

	return allSkipped, nil
}

// displaySubscriptionAndLocation shows the Azure subscription and location details.
// This must be called after at least one provisionManager.Initialize to ensure the
// environment has the correct subscription and location values.
func (p *ProvisionAction) displaySubscriptionAndLocation(ctx context.Context) {
	subscription, subErr := p.subManager.GetSubscription(ctx, p.env.GetSubscriptionId())
	if subErr == nil {
		location, err := p.subManager.GetLocation(ctx, p.env.GetSubscriptionId(), p.env.GetLocation())
		var locationDisplay string
		if err != nil {
			log.Printf("failed getting location: %v", err)
		} else {
			locationDisplay = location.DisplayName
		}

		var subscriptionDisplay string
		if v, err := strconv.ParseBool(os.Getenv("AZD_DEMO_MODE")); err == nil && v {
			subscriptionDisplay = subscription.Name
		} else {
			subscriptionDisplay = fmt.Sprintf("%s (%s)", subscription.Name, subscription.Id)
		}

		p.console.MessageUxItem(ctx, &ux.EnvironmentDetails{
			Subscription: subscriptionDisplay,
			Location:     locationDisplay,
		})
	} else {
		log.Printf("failed getting subscriptions. Skip displaying sub and location: %v", subErr)
	}
}

// wrapProvisionError applies the same error-suggestion heuristics used by the sequential path
// (OpenAI quota, Responsible AI terms, etc.) to the given error.
func (p *ProvisionAction) wrapProvisionError(err error) error {
	errorMsg := err.Error()
	if strings.Contains(errorMsg, specialFeatureOrQuotaIdRequired) && strings.Contains(errorMsg, "OpenAI") {
		requestAccessLink := "https://go.microsoft.com/fwlink/?linkid=2259205&clcid=0x409"
		return &internal.ErrorWithSuggestion{
			Err: err,
			Suggestion: "\nSuggested Action: The selected subscription does not have access to" +
				" Azure OpenAI Services. Please visit " + output.WithLinkFormat("%s", requestAccessLink) +
				" to request access.",
		}
	}

	if strings.Contains(errorMsg, AINotValid) &&
		strings.Contains(errorMsg, openAIsubscriptionNoQuotaId) {
		return &internal.ErrorWithSuggestion{
			Suggestion: "\nSuggested Action: The selected " +
				"subscription has not been enabled for use of Azure AI service and does not have quota for " +
				"any pricing tiers. Please visit " + output.WithLinkFormat("%s", p.portalUrlBase) +
				" and select 'Create' on specific services to request access.",
			Err: err,
		}
	}

	if strings.Contains(errorMsg, responsibleAITerms) {
		return &internal.ErrorWithSuggestion{
			Suggestion: "\nSuggested Action: Please visit azure portal in " +
				output.WithLinkFormat("%s", p.portalUrlBase) + ". Create the resource in azure portal " +
				"to go through Responsible AI terms, and then delete it. " +
				"After that, run 'azd provision' again",
			Err: err,
		}
	}

	return fmt.Errorf("deployment failed: %w", err)
}

// deployResultToUx creates the ux element to display from a provision preview
func deployResultToUx(previewResult *provisioning.DeployPreviewResult) ux.UxItem {
	var operations []*ux.Resource
	for _, change := range previewResult.Preview.Properties.Changes {
		// Convert property deltas to UX format
		var propertyDeltas []ux.PropertyDelta
		for _, delta := range change.Delta {
			propertyDeltas = append(propertyDeltas, ux.PropertyDelta{
				Path:       delta.Path,
				ChangeType: string(delta.ChangeType),
				Before:     delta.Before,
				After:      delta.After,
			})
		}

		operations = append(operations, &ux.Resource{
			Operation:      ux.OperationType(change.ChangeType),
			Type:           change.ResourceType,
			Name:           change.Name,
			PropertyDeltas: propertyDeltas,
		})
	}
	return &ux.PreviewProvision{
		Operations: operations,
	}
}

func GetCmdProvisionHelpDescription(c *cobra.Command) string {
	return generateCmdHelpDescription(
		fmt.Sprintf(
			"Provision the Azure resources for an application."+
				" This step may take a while depending on the resources provisioned."+
				" You should run %s any time you update your Bicep or Terraform file."+
				"\n\nThis command prompts you to input the following:",
			output.WithHighLightFormat(c.CommandPath())), []string{
			formatHelpNote("Azure location: The Azure location where your resources will be deployed."),
			formatHelpNote("Azure subscription: The Azure subscription where your resources will be deployed."),
			fmt.Sprintf("\nYou can also set these values in advance to skip the prompts:\n\n"+
				"  %s\n  %s\n\n"+
				"Use %s to configure values in the active environment."+
				" Use %s for structured output suitable for automation.",
				output.WithGrayFormat("azd env set AZURE_SUBSCRIPTION_ID <your-subscription-id>"),
				output.WithGrayFormat("azd env set AZURE_LOCATION <location>"),
				output.WithHighLightFormat("azd env set"),
				output.WithHighLightFormat("--output json"),
			),
			fmt.Sprintf("\nWhen <layer> is specified, only provisions resources for the given layer." +
				" When omitted, provisions resources for all layers defined in the project."),
		})
}
