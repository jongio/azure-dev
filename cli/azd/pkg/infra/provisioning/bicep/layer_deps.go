// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package bicep

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/azure/azure-dev/cli/azd/pkg/environment"
	"github.com/azure/azure-dev/cli/azd/pkg/infra/provisioning"
)

// layerDependencyGraph represents dependencies between provisioning layers.
type layerDependencyGraph struct {
	layerCount int
	// edges[i] contains indices of layers that layer i depends on (i.e., must run before i).
	edges map[int][]int
	// outputProviders maps an output variable name → layer index that produces it.
	outputProviders map[string]int
}

// AnalyzeLayerDependencies performs static analysis on Bicep templates and parameter
// files to determine execution order for parallel provisioning layers.
//
// For each layer it:
//  1. Parses the .bicep source file for `output` declarations to learn what each layer produces.
//  2. Parses the parameter file (.parameters.json or .bicepparam) for environment variable
//     references (${VAR} or readEnvironmentVariable('VAR')) to learn what each layer consumes.
//  3. Builds a directed dependency graph: if layer B references variable X and layer A declares
//     output X, then A→B (B depends on A). Variables already present in the environment are not
//     treated as dependencies.
//  4. Topologically sorts the graph into phases — groups of layers that can safely run in parallel.
//
// Returns [][]int where each inner slice is a phase of layer indices that can run concurrently.
// Returns an error if a cycle is detected or file I/O fails unexpectedly.
func AnalyzeLayerDependencies(
	layers []provisioning.Options,
	projectPath string,
	env *environment.Environment,
) ([][]int, error) {
	if len(layers) <= 1 {
		indices := make([]int, len(layers))
		for i := range layers {
			indices[i] = i
		}
		return [][]int{indices}, nil
	}

	g := &layerDependencyGraph{
		layerCount:      len(layers),
		edges:           make(map[int][]int),
		outputProviders: make(map[string]int),
	}

	// Phase 1: Discover outputs from each layer's .bicep source file.
	for i, layer := range layers {
		opts, err := layer.GetWithDefaults()
		if err != nil {
			return nil, fmt.Errorf("resolving defaults for layer %d: %w", i, err)
		}

		bicepPath := resolveBicepPath(opts, projectPath)
		outputs, err := extractBicepOutputs(bicepPath)
		if err != nil {
			// If we can't read the bicep file, skip this layer's outputs.
			// The layer may still work if it produces no outputs, or the file
			// is generated at deploy time. Don't fail the whole analysis.
			continue
		}

		for _, name := range outputs {
			// azd's UpdateEnvironment stores outputs using the ARM template key
			// directly as the env var name (no case conversion). Bicep output
			// names are used as-is for both the ARM key and the env var.
			g.outputProviders[name] = i
		}
	}

	// Phase 2: Discover env var references from each layer's parameter file.
	for i, layer := range layers {
		opts, err := layer.GetWithDefaults()
		if err != nil {
			return nil, fmt.Errorf("resolving defaults for layer %d: %w", i, err)
		}

		refs := discoverParamEnvRefs(opts, projectPath)
		for _, ref := range refs {
			// Skip variables that are already set in the environment — they
			// don't create inter-layer dependencies.
			if _, exists := env.LookupEnv(ref); exists {
				continue
			}

			if providerIdx, ok := g.outputProviders[ref]; ok && providerIdx != i {
				g.edges[i] = append(g.edges[i], providerIdx)
			}
		}
	}

	return topoSortPhases(g)
}

// resolveBicepPath resolves the absolute path to the .bicep source file for a layer.
func resolveBicepPath(opts provisioning.Options, projectPath string) string {
	infraPath := opts.Path
	if !filepath.IsAbs(infraPath) {
		infraPath = filepath.Join(projectPath, infraPath)
	}
	return filepath.Join(infraPath, opts.Module+".bicep")
}

// resolveParamPaths returns the candidate parameter file paths for a layer,
// in priority order: .bicepparam first, then .parameters.json.
func resolveParamPaths(opts provisioning.Options, projectPath string) (bicepparam string, parametersJSON string) {
	infraPath := opts.Path
	if !filepath.IsAbs(infraPath) {
		infraPath = filepath.Join(projectPath, infraPath)
	}
	bicepparam = filepath.Join(infraPath, opts.Module+".bicepparam")
	parametersJSON = filepath.Join(infraPath, opts.Module+".parameters.json")
	return bicepparam, parametersJSON
}

// Regular expressions for static analysis. Compiled once, reused for every layer.
var (
	// Matches Bicep output declarations: `output myVar string = ...`
	// Captures the output name (first submatch).
	reBicepOutput = regexp.MustCompile(`(?m)^\s*output\s+(\w+)\s+`)

	// Matches ${VAR_NAME} references in .parameters.json string values.
	reParamEnvRef = regexp.MustCompile(`\$\{([^}]+)\}`)

	// Matches readEnvironmentVariable('VAR_NAME') calls in .bicepparam files.
	reBicepparamEnvRef = regexp.MustCompile(`readEnvironmentVariable\(\s*'([^']+)'`)
)

// extractBicepOutputs parses a .bicep source file and returns the declared output names.
func extractBicepOutputs(bicepFilePath string) ([]string, error) {
	content, err := os.ReadFile(bicepFilePath)
	if err != nil {
		return nil, err
	}
	return extractBicepOutputsFromContent(content), nil
}

// extractBicepOutputsFromContent extracts output names from Bicep source content.
func extractBicepOutputsFromContent(content []byte) []string {
	matches := reBicepOutput.FindAllSubmatch(content, -1)
	seen := make(map[string]struct{}, len(matches))
	var names []string
	for _, m := range matches {
		name := string(m[1])
		if _, dup := seen[name]; !dup {
			seen[name] = struct{}{}
			names = append(names, name)
		}
	}
	return names
}

// extractParamEnvRefs extracts environment variable references from a parameter file.
// For .parameters.json files it looks for ${VAR_NAME} patterns.
// For .bicepparam files it looks for readEnvironmentVariable('VAR_NAME') patterns.
func extractParamEnvRefs(paramFilePath string, content []byte) []string {
	ext := strings.ToLower(filepath.Ext(paramFilePath))

	var re *regexp.Regexp
	switch {
	case ext == ".bicepparam":
		re = reBicepparamEnvRef
	default:
		// .parameters.json or any other extension
		re = reParamEnvRef
	}

	matches := re.FindAllSubmatch(content, -1)
	seen := make(map[string]struct{}, len(matches))
	var refs []string
	for _, m := range matches {
		ref := string(m[1])
		if _, dup := seen[ref]; !dup {
			seen[ref] = struct{}{}
			refs = append(refs, ref)
		}
	}
	return refs
}

// discoverParamEnvRefs finds environment variable references for a layer by checking
// all candidate parameter files (.bicepparam and .parameters.json).
func discoverParamEnvRefs(opts provisioning.Options, projectPath string) []string {
	bicepparam, parametersJSON := resolveParamPaths(opts, projectPath)

	// Prefer .bicepparam if it exists.
	if content, err := os.ReadFile(bicepparam); err == nil {
		return extractParamEnvRefs(bicepparam, content)
	}

	// Fall back to .parameters.json.
	if content, err := os.ReadFile(parametersJSON); err == nil {
		return extractParamEnvRefs(parametersJSON, content)
	}

	return nil
}

// topoSortPhases performs a topological sort using Kahn's algorithm and groups
// nodes into execution phases. Each phase contains layers whose dependencies
// are fully satisfied by prior phases. Layers within a phase can run in parallel.
//
// Returns an error if the graph contains a cycle.
func topoSortPhases(g *layerDependencyGraph) ([][]int, error) {
	// Compute in-degree for each node.
	inDegree := make([]int, g.layerCount)
	for node, deps := range g.edges {
		inDegree[node] = len(deps)
	}

	// Seed the first frontier with all zero in-degree nodes.
	var frontier []int
	for i := 0; i < g.layerCount; i++ {
		if inDegree[i] == 0 {
			frontier = append(frontier, i)
		}
	}

	var phases [][]int
	processed := 0

	for len(frontier) > 0 {
		// The current frontier is one phase — all members have no pending dependencies.
		phases = append(phases, frontier)
		processed += len(frontier)

		var nextFrontier []int
		for _, completed := range frontier {
			// For every node that depends on 'completed', decrement its in-degree.
			for node, deps := range g.edges {
				for _, dep := range deps {
					if dep == completed {
						inDegree[node]--
						if inDegree[node] == 0 {
							nextFrontier = append(nextFrontier, node)
						}
					}
				}
			}
		}
		frontier = nextFrontier
	}

	if processed != g.layerCount {
		return nil, fmt.Errorf("cycle detected in layer dependencies: %d of %d layers could not be scheduled",
			g.layerCount-processed, g.layerCount)
	}

	return phases, nil
}
