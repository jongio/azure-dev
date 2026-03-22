// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package apphost

import "github.com/azure/azure-dev/cli/azd/pkg/custommaps"

type genContainerAppEnvironmentServices struct {
	Type string
}

type genKeyVault struct {
	// when true, the bicep definition for tags is not generated
	NoTags bool
	// when provided, the principalId from the user provisioning the key vault gets read access
	ReadAccessPrincipalId bool
}

type genContainerApp struct {
	Volumes    []*Volume
	BindMounts []*BindMount
}

type genContainerAppIngressPort struct {
	External    bool
	TargetPort  int
	ExposedPort int
}

type genContainerAppIngressAdditionalPortMappings struct {
	genContainerAppIngressPort
	ExposedPort int
}

type genContainerAppIngress struct {
	Transport              string
	AdditionalPortMappings []genContainerAppIngressAdditionalPortMappings
	genContainerAppIngressPort
	AllowInsecure    bool
	UsingDefaultPort bool
}

type genContainer struct {
	Env              map[string]string
	Inputs           map[string]Input
	DeploymentParams map[string]any
	Image            string
	DeploymentSource string
	Bindings         custommaps.WithOrder[Binding]
	Volumes          []*Volume
	BindMounts       []*BindMount
	Args             []string
}

type genDockerfile struct {
	Env              map[string]string
	BuildArgs        map[string]string
	DeploymentParams map[string]any
	Path             string
	Context          string
	DeploymentSource string
	Bindings         custommaps.WithOrder[Binding]
	Args             []string
}

type genBuildContainer struct {
	Image             string
	Entrypoint        string
	Args              []string
	Env               map[string]string
	Bindings          custommaps.WithOrder[Binding]
	Volumes           []*Volume
	Build             *genBuildContainerDetails
	DeploymentParams  map[string]any
	DeploymentSource  string
	BindMounts        []*BindMount
	DefaultTargetPort int
}

type genBuildContainerDetails struct {
	Args       map[string]string
	Secrets    map[string]ContainerV1BuildSecrets
	Context    string
	Dockerfile string
	BuildOnly  bool
}

type genProject struct {
	Env              map[string]string
	DeploymentParams map[string]any
	ContainerFiles   map[string]ContainerFile
	Path             string
	DeploymentSource string
	Bindings         custommaps.WithOrder[Binding]
	Args             []string
}

type genDapr struct {
	AppPort                *int
	AppProtocol            *string
	DaprHttpMaxRequestSize *int
	DaprHttpReadBufferSize *int
	EnableApiLogging       *bool
	LogLevel               *string
	AppId                  string
	Application            string
}

type genDaprComponentMetadata struct {
	SecretKeyRef *string
	Value        *string
}

type genDaprComponentSecret struct {
	Value string
}

type genDaprComponent struct {
	Metadata map[string]genDaprComponentMetadata
	Secrets  map[string]genDaprComponentSecret
	Type     string
	Version  string
}

type genOutputParameter struct {
	Type  string
	Value string
}

type genBicepModules struct {
	Path   string
	Params map[string]string
	Scope  string
}

type genBicepTemplateContext struct {
	KeyVaults                       map[string]genKeyVault
	ContainerAppEnvironmentServices map[string]genContainerAppEnvironmentServices
	ContainerApps                   map[string]genContainerApp
	DaprComponents                  map[string]genDaprComponent
	InputParameters                 map[string]Input
	OutputParameters                map[string]genOutputParameter
	OutputSecretParameters          map[string]genOutputParameter
	BicepModules                    map[string]genBicepModules
	// parameters to be passed from main.bicep to resources.bicep
	mappedParameters         []string
	HasContainerRegistry     bool
	HasContainerEnvironment  bool
	HasDaprStore             bool
	HasLogAnalyticsWorkspace bool
	RequiresPrincipalId      bool
	RequiresStorageVolume    bool
	HasBindMounts            bool
}

type genContainerAppManifestTemplateContext struct {
	Ingress         *genContainerAppIngress
	Env             map[string]string
	Secrets         map[string]string
	KeyVaultSecrets map[string]string
	Dapr            *genContainerAppManifestTemplateContextDapr
	DeployParams    map[string]string
	Name            string
	Entrypoint      string
	DeploySource    string
	Args            []string
	Volumes         []*Volume
	BindMounts      []*BindMount
}

type genProjectFileContext struct {
	Services map[string]string
	Name     string
}

type genContainerAppManifestTemplateContextDapr struct {
	AppPort            *int
	AppProtocol        *string
	EnableApiLogging   *bool
	HttpMaxRequestSize *int
	HttpReadBufferSize *int
	LogLevel           *string
	AppId              string
}
