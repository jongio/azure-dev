// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package bicep

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/azure/azure-dev/cli/azd/pkg/environment"
	"github.com/azure/azure-dev/cli/azd/pkg/infra/provisioning"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupLayerDir creates a layer directory with the given bicep and parameter files.
// Returns the provisioning.Options pointing to the created layer.
func setupLayerDir(
	t *testing.T,
	root string,
	name string,
	bicepContent string,
	paramFile string,
	paramContent string,
) provisioning.Options {
	t.Helper()
	dir := filepath.Join(root, name)
	require.NoError(t, os.MkdirAll(dir, 0755))

	if bicepContent != "" {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "main.bicep"), []byte(bicepContent), 0644))
	}
	if paramFile != "" && paramContent != "" {
		require.NoError(t, os.WriteFile(filepath.Join(dir, paramFile), []byte(paramContent), 0644))
	}

	return provisioning.Options{
		Path:   name,
		Module: "main",
		Name:   name,
	}
}

func TestAnalyzeLayerDependencies_SingleLayer(t *testing.T) {
	root := t.TempDir()
	layer := setupLayerDir(t, root, "infra", "output AZURE_COSMOS_CONNECTION_STRING string", "", "")
	env := environment.NewWithValues("test", map[string]string{})

	phases, err := AnalyzeLayerDependencies([]provisioning.Options{layer}, root, env)
	require.NoError(t, err)
	require.Len(t, phases, 1)
	assert.Equal(t, []int{0}, phases[0])
}

func TestAnalyzeLayerDependencies_NoDependencies(t *testing.T) {
	root := t.TempDir()

	layers := []provisioning.Options{
		setupLayerDir(t, root, "network", "output VNET_ID string\noutput SUBNET_ID string", "", ""),
		setupLayerDir(t, root, "storage", "output STORAGE_ACCOUNT_NAME string", "", ""),
		setupLayerDir(t, root, "monitoring", "output LOG_ANALYTICS_ID string", "", ""),
	}
	env := environment.NewWithValues("test", map[string]string{})

	phases, err := AnalyzeLayerDependencies(layers, root, env)
	require.NoError(t, err)
	// All layers are independent — should be a single phase.
	require.Len(t, phases, 1)

	got := make([]int, len(phases[0]))
	copy(got, phases[0])
	sort.Ints(got)
	assert.Equal(t, []int{0, 1, 2}, got)
}

func TestAnalyzeLayerDependencies_LinearChain(t *testing.T) {
	root := t.TempDir()

	// Layer 0 produces CONN_STRING
	// Layer 1 consumes CONN_STRING, produces API_ENDPOINT
	// Layer 2 consumes API_ENDPOINT
	layers := []provisioning.Options{
		setupLayerDir(t, root, "database",
			"output CONN_STRING string",
			"main.parameters.json",
			`{"$schema":"","contentVersion":"1.0.0.0","parameters":{"dbName":{"value":"mydb"}}}`,
		),
		setupLayerDir(t, root, "api",
			"output API_ENDPOINT string",
			"main.parameters.json",
			`{"$schema":"","contentVersion":"1.0.0.0","parameters":{"connStr":{"value":"${CONN_STRING}"}}}`,
		),
		setupLayerDir(t, root, "frontend",
			"output FRONTEND_URL string",
			"main.parameters.json",
			`{"$schema":"","contentVersion":"1.0.0.0","parameters":{"apiUrl":{"value":"${API_ENDPOINT}"}}}`,
		),
	}
	env := environment.NewWithValues("test", map[string]string{})

	phases, err := AnalyzeLayerDependencies(layers, root, env)
	require.NoError(t, err)
	require.Len(t, phases, 3)

	assert.Equal(t, []int{0}, phases[0]) // database first
	assert.Equal(t, []int{1}, phases[1]) // api depends on database
	assert.Equal(t, []int{2}, phases[2]) // frontend depends on api
}

func TestAnalyzeLayerDependencies_Diamond(t *testing.T) {
	root := t.TempDir()

	// Layer 0 (base) produces VNET_ID and SUBNET_ID
	// Layer 1 (compute) consumes VNET_ID, produces VM_IP
	// Layer 2 (storage) consumes SUBNET_ID, produces BLOB_ENDPOINT
	// Layer 3 (app) consumes VM_IP and BLOB_ENDPOINT
	layers := []provisioning.Options{
		setupLayerDir(t, root, "base",
			"output VNET_ID string\noutput SUBNET_ID string",
			"main.parameters.json",
			`{"$schema":"","contentVersion":"1.0.0.0","parameters":{}}`,
		),
		setupLayerDir(t, root, "compute",
			"output VM_IP string",
			"main.parameters.json",
			`{"$schema":"","contentVersion":"1.0.0.0","parameters":{"vnetId":{"value":"${VNET_ID}"}}}`,
		),
		setupLayerDir(t, root, "storage",
			"output BLOB_ENDPOINT string",
			"main.parameters.json",
			`{"$schema":"","contentVersion":"1.0.0.0","parameters":{"subnetId":{"value":"${SUBNET_ID}"}}}`,
		),
		setupLayerDir(t, root, "app",
			"output APP_URL string",
			"main.parameters.json",
			`{"$schema":"","contentVersion":"1.0.0.0","parameters":{"vmIp":{"value":"${VM_IP}"},"blobEndpoint":{"value":"${BLOB_ENDPOINT}"}}}`,
		),
	}
	env := environment.NewWithValues("test", map[string]string{})

	phases, err := AnalyzeLayerDependencies(layers, root, env)
	require.NoError(t, err)
	require.Len(t, phases, 3)

	// Phase 0: base
	assert.Equal(t, []int{0}, phases[0])

	// Phase 1: compute and storage (both depend only on base)
	got := make([]int, len(phases[1]))
	copy(got, phases[1])
	sort.Ints(got)
	assert.Equal(t, []int{1, 2}, got)

	// Phase 2: app (depends on compute and storage)
	assert.Equal(t, []int{3}, phases[2])
}

func TestAnalyzeLayerDependencies_CycleDetected(t *testing.T) {
	root := t.TempDir()

	// Layer 0 consumes OUTPUT_B (from layer 1), produces OUTPUT_A
	// Layer 1 consumes OUTPUT_A (from layer 0), produces OUTPUT_B
	// This is a cycle.
	layers := []provisioning.Options{
		setupLayerDir(t, root, "layerA",
			"output OUTPUT_A string",
			"main.parameters.json",
			`{"$schema":"","contentVersion":"1.0.0.0","parameters":{"b":{"value":"${OUTPUT_B}"}}}`,
		),
		setupLayerDir(t, root, "layerB",
			"output OUTPUT_B string",
			"main.parameters.json",
			`{"$schema":"","contentVersion":"1.0.0.0","parameters":{"a":{"value":"${OUTPUT_A}"}}}`,
		),
	}
	env := environment.NewWithValues("test", map[string]string{})

	_, err := AnalyzeLayerDependencies(layers, root, env)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cycle detected")
}

func TestAnalyzeLayerDependencies_PreExistingEnvVar(t *testing.T) {
	root := t.TempDir()

	// Layer 0 produces CUSTOM_OUTPUT
	// Layer 1 references AZURE_LOCATION (pre-existing) and CUSTOM_OUTPUT
	// Only the CUSTOM_OUTPUT reference should create a dependency.
	layers := []provisioning.Options{
		setupLayerDir(t, root, "base",
			"output CUSTOM_OUTPUT string",
			"main.parameters.json",
			`{"$schema":"","contentVersion":"1.0.0.0","parameters":{}}`,
		),
		setupLayerDir(t, root, "app",
			"output APP_URL string",
			"main.parameters.json",
			`{"$schema":"","contentVersion":"1.0.0.0","parameters":{"loc":{"value":"${AZURE_LOCATION}"},"custom":{"value":"${CUSTOM_OUTPUT}"}}}`,
		),
	}

	// AZURE_LOCATION is pre-existing, CUSTOM_OUTPUT is NOT
	env := environment.NewWithValues("test", map[string]string{
		"AZURE_LOCATION": "eastus2",
	})

	phases, err := AnalyzeLayerDependencies(layers, root, env)
	require.NoError(t, err)
	// base must run before app (dependency on CUSTOM_OUTPUT), but AZURE_LOCATION doesn't count.
	require.Len(t, phases, 2)
	assert.Equal(t, []int{0}, phases[0])
	assert.Equal(t, []int{1}, phases[1])
}

func TestAnalyzeLayerDependencies_PreExistingRemovesDependency(t *testing.T) {
	root := t.TempDir()

	// Layer 0 produces CONN_STRING
	// Layer 1 references CONN_STRING — but it's already in env
	// So there should be NO dependency.
	layers := []provisioning.Options{
		setupLayerDir(t, root, "database",
			"output CONN_STRING string",
			"main.parameters.json",
			`{"$schema":"","contentVersion":"1.0.0.0","parameters":{}}`,
		),
		setupLayerDir(t, root, "api",
			"output API_URL string",
			"main.parameters.json",
			`{"$schema":"","contentVersion":"1.0.0.0","parameters":{"conn":{"value":"${CONN_STRING}"}}}`,
		),
	}
	env := environment.NewWithValues("test", map[string]string{
		"CONN_STRING": "already-set-from-previous-run",
	})

	phases, err := AnalyzeLayerDependencies(layers, root, env)
	require.NoError(t, err)
	// Both layers can run in the same phase since CONN_STRING is pre-existing.
	require.Len(t, phases, 1)
	got := make([]int, len(phases[0]))
	copy(got, phases[0])
	sort.Ints(got)
	assert.Equal(t, []int{0, 1}, got)
}

func TestAnalyzeLayerDependencies_Mixed(t *testing.T) {
	root := t.TempDir()

	// Layer 0 (independent) produces A_OUT
	// Layer 1 (independent) produces B_OUT — no refs to any layer outputs
	// Layer 2 depends on A_OUT
	// Layer 3 is independent
	layers := []provisioning.Options{
		setupLayerDir(t, root, "layerA",
			"output A_OUT string",
			"main.parameters.json",
			`{"$schema":"","contentVersion":"1.0.0.0","parameters":{}}`,
		),
		setupLayerDir(t, root, "layerB",
			"output B_OUT string",
			"main.parameters.json",
			`{"$schema":"","contentVersion":"1.0.0.0","parameters":{}}`,
		),
		setupLayerDir(t, root, "layerC",
			"output C_OUT string",
			"main.parameters.json",
			`{"$schema":"","contentVersion":"1.0.0.0","parameters":{"a":{"value":"${A_OUT}"}}}`,
		),
		setupLayerDir(t, root, "layerD",
			"output D_OUT string",
			"main.parameters.json",
			`{"$schema":"","contentVersion":"1.0.0.0","parameters":{}}`,
		),
	}
	env := environment.NewWithValues("test", map[string]string{})

	phases, err := AnalyzeLayerDependencies(layers, root, env)
	require.NoError(t, err)
	require.Len(t, phases, 2)

	// Phase 0: layers 0, 1, 3 (all independent)
	got0 := make([]int, len(phases[0]))
	copy(got0, phases[0])
	sort.Ints(got0)
	assert.Equal(t, []int{0, 1, 3}, got0)

	// Phase 1: layer 2 (depends on layer 0)
	assert.Equal(t, []int{2}, phases[1])
}

func TestAnalyzeLayerDependencies_BicepparamFormat(t *testing.T) {
	root := t.TempDir()

	// Layer 0 produces DB_HOST
	// Layer 1 uses .bicepparam file format with readEnvironmentVariable()
	layers := []provisioning.Options{
		setupLayerDir(t, root, "database",
			"output DB_HOST string\noutput DB_PORT string",
			"main.parameters.json",
			`{"$schema":"","contentVersion":"1.0.0.0","parameters":{}}`,
		),
		setupLayerDir(t, root, "api",
			"output API_URL string",
			"main.bicepparam",
			`using 'main.bicep'
param dbHost = readEnvironmentVariable('DB_HOST')
param dbPort = readEnvironmentVariable( 'DB_PORT' )
param region = readEnvironmentVariable('AZURE_LOCATION')
`,
		),
	}
	env := environment.NewWithValues("test", map[string]string{
		"AZURE_LOCATION": "westus2",
	})

	phases, err := AnalyzeLayerDependencies(layers, root, env)
	require.NoError(t, err)
	require.Len(t, phases, 2)
	assert.Equal(t, []int{0}, phases[0])
	assert.Equal(t, []int{1}, phases[1])
}

func TestAnalyzeLayerDependencies_NoParamFile(t *testing.T) {
	root := t.TempDir()

	// Layers with no parameter files — should all run in one phase.
	layers := []provisioning.Options{
		setupLayerDir(t, root, "layerA", "output X string", "", ""),
		setupLayerDir(t, root, "layerB", "output Y string", "", ""),
	}
	env := environment.NewWithValues("test", map[string]string{})

	phases, err := AnalyzeLayerDependencies(layers, root, env)
	require.NoError(t, err)
	require.Len(t, phases, 1)
	got := make([]int, len(phases[0]))
	copy(got, phases[0])
	sort.Ints(got)
	assert.Equal(t, []int{0, 1}, got)
}

func TestAnalyzeLayerDependencies_NoBicepFile(t *testing.T) {
	root := t.TempDir()

	// Layer without a .bicep file — should not crash, just has no outputs.
	dir := filepath.Join(root, "ghost")
	require.NoError(t, os.MkdirAll(dir, 0755))
	layers := []provisioning.Options{
		{Path: "ghost", Module: "main", Name: "ghost"},
		setupLayerDir(t, root, "real", "output SOMETHING string", "", ""),
	}
	env := environment.NewWithValues("test", map[string]string{})

	phases, err := AnalyzeLayerDependencies(layers, root, env)
	require.NoError(t, err)
	// Both should be in one phase (no dependency can be established without outputs).
	require.Len(t, phases, 1)
}

// --- Unit tests for extractBicepOutputsFromContent ---

func TestExtractBicepOutputsFromContent(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected []string
	}{
		{
			name:     "SingleOutput",
			content:  "output AZURE_COSMOS_ENDPOINT string = cosmosAccount.properties.documentEndpoint",
			expected: []string{"AZURE_COSMOS_ENDPOINT"},
		},
		{
			name: "MultipleOutputs",
			content: `
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = { name: 'st' }

output STORAGE_ACCOUNT_NAME string = storageAccount.name
output STORAGE_ACCOUNT_KEY string = storageAccount.listKeys().keys[0].value
output STORAGE_BLOB_ENDPOINT string = storageAccount.properties.primaryEndpoints.blob
`,
			expected: []string{"STORAGE_ACCOUNT_NAME", "STORAGE_ACCOUNT_KEY", "STORAGE_BLOB_ENDPOINT"},
		},
		{
			name:     "NoOutputs",
			content:  "resource rg 'Microsoft.Resources/resourceGroups@2021-04-01' = { name: 'rg' }",
			expected: nil,
		},
		{
			name: "OutputWithIndentation",
			content: `
  output MY_VAR string = 'hello'
	output	TABBED_VAR int = 42
`,
			expected: []string{"MY_VAR", "TABBED_VAR"},
		},
		{
			name: "DuplicateOutputNames",
			content: `
output SAME_NAME string = 'a'
output SAME_NAME string = 'b'
`,
			expected: []string{"SAME_NAME"},
		},
		{
			name:     "OutputInComment",
			content:  "// output COMMENTED_OUT string = 'nope'",
			expected: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractBicepOutputsFromContent([]byte(tc.content))
			assert.Equal(t, tc.expected, got)
		})
	}
}

// --- Unit tests for extractParamEnvRefs ---

func TestExtractParamEnvRefs_ParametersJSON(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected []string
	}{
		{
			name: "SingleRef",
			content: `{
				"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
				"contentVersion": "1.0.0.0",
				"parameters": {
					"location": {"value": "${AZURE_LOCATION}"}
				}
			}`,
			expected: []string{"AZURE_LOCATION"},
		},
		{
			name: "MultipleRefs",
			content: `{
				"parameters": {
					"loc": {"value": "${AZURE_LOCATION}"},
					"sub": {"value": "${AZURE_SUBSCRIPTION_ID}"},
					"conn": {"value": "${MY_CONNECTION_STRING}"}
				}
			}`,
			expected: []string{"AZURE_LOCATION", "AZURE_SUBSCRIPTION_ID", "MY_CONNECTION_STRING"},
		},
		{
			name: "DuplicateRef",
			content: `{
				"parameters": {
					"a": {"value": "${SAME_VAR}"},
					"b": {"value": "${SAME_VAR}"}
				}
			}`,
			expected: []string{"SAME_VAR"},
		},
		{
			name:     "NoRefs",
			content:  `{"parameters": {"name": {"value": "hardcoded"}}}`,
			expected: nil,
		},
		{
			name: "MultipleRefsInSingleValue",
			content: `{
				"parameters": {
					"connStr": {"value": "Server=${DB_HOST};Port=${DB_PORT};Database=mydb"}
				}
			}`,
			expected: []string{"DB_HOST", "DB_PORT"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractParamEnvRefs("test.parameters.json", []byte(tc.content))
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestExtractParamEnvRefs_Bicepparam(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected []string
	}{
		{
			name:     "SingleRef",
			content:  `param location = readEnvironmentVariable('AZURE_LOCATION')`,
			expected: []string{"AZURE_LOCATION"},
		},
		{
			name: "MultipleRefs",
			content: `using 'main.bicep'
param location = readEnvironmentVariable('AZURE_LOCATION')
param connStr = readEnvironmentVariable('CONN_STRING')
`,
			expected: []string{"AZURE_LOCATION", "CONN_STRING"},
		},
		{
			name:     "WithSpaces",
			content:  `param x = readEnvironmentVariable(  'MY_VAR'  )`,
			expected: []string{"MY_VAR"},
		},
		{
			name:     "NoRefs",
			content:  "using 'main.bicep'\nparam x = 'hardcoded'",
			expected: nil,
		},
		{
			name: "DuplicateRef",
			content: `
param a = readEnvironmentVariable('DUP')
param b = readEnvironmentVariable('DUP')
`,
			expected: []string{"DUP"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractParamEnvRefs("test.bicepparam", []byte(tc.content))
			assert.Equal(t, tc.expected, got)
		})
	}
}

// --- Unit tests for topoSortPhases ---

func TestTopoSortPhases(t *testing.T) {
	tests := []struct {
		name        string
		graph       *layerDependencyGraph
		expected    [][]int
		expectError bool
	}{
		{
			name: "NoEdges",
			graph: &layerDependencyGraph{
				layerCount:      3,
				edges:           map[int][]int{},
				outputProviders: map[string]int{},
			},
			expected: [][]int{{0, 1, 2}},
		},
		{
			name: "LinearChain",
			graph: &layerDependencyGraph{
				layerCount: 3,
				edges: map[int][]int{
					1: {0},
					2: {1},
				},
				outputProviders: map[string]int{},
			},
			expected: [][]int{{0}, {1}, {2}},
		},
		{
			name: "DiamondShape",
			graph: &layerDependencyGraph{
				layerCount: 4,
				edges: map[int][]int{
					1: {0},
					2: {0},
					3: {1, 2},
				},
				outputProviders: map[string]int{},
			},
			expected: [][]int{{0}, {1, 2}, {3}},
		},
		{
			name: "Cycle",
			graph: &layerDependencyGraph{
				layerCount: 2,
				edges: map[int][]int{
					0: {1},
					1: {0},
				},
				outputProviders: map[string]int{},
			},
			expectError: true,
		},
		{
			name: "SingleNode",
			graph: &layerDependencyGraph{
				layerCount:      1,
				edges:           map[int][]int{},
				outputProviders: map[string]int{},
			},
			expected: [][]int{{0}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			phases, err := topoSortPhases(tc.graph)
			if tc.expectError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, phases, len(tc.expected))

			for i := range tc.expected {
				got := make([]int, len(phases[i]))
				copy(got, phases[i])
				sort.Ints(got)

				exp := make([]int, len(tc.expected[i]))
				copy(exp, tc.expected[i])
				sort.Ints(exp)

				assert.Equal(t, exp, got, "phase %d mismatch", i)
			}
		})
	}
}

// TestExtractBicepOutputsFromContent_OutputInComment verifies that lines starting with
// a comment marker (//) are not treated as real output declarations. The regex does
// NOT skip comments (it cannot reliably in all cases), so this test documents the
// current behavior: lines with "// output" at the start of the line are skipped by
// the ^\s* anchor only when there's no leading whitespace before //.
// In practice, commented-out outputs starting a line with // are not matched because
// the regex expects the line to start with optional whitespace followed by "output".
func TestExtractBicepOutputsFromContent_CommentedOutput(t *testing.T) {
	// "// output X string" — the // is not whitespace, so ^\s*output doesn't match.
	got := extractBicepOutputsFromContent([]byte("// output FAKE string = 'nope'"))
	assert.Empty(t, got)

	// But "  output X string" still matches (leading whitespace is fine).
	got = extractBicepOutputsFromContent([]byte("  output REAL string = 'yes'"))
	assert.Equal(t, []string{"REAL"}, got)
}
