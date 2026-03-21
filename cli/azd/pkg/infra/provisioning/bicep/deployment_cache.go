// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package bicep

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/azure/azure-dev/cli/azd/pkg/alpha"
	"github.com/azure/azure-dev/cli/azd/pkg/infra/provisioning"
)

var localCacheFeatureKey = alpha.MustFeatureKey("provision.localCache")

// deploymentCacheOutput stores a single output parameter from a deployment.
type deploymentCacheOutput struct {
	Type  string `json:"type"`
	Value any    `json:"value"`
}

// deploymentCacheEntry stores the cached state for a single deployment layer.
type deploymentCacheEntry struct {
	TemplateHash    string                           `json:"templateHash"`
	ParameterHash   string                           `json:"parameterHash"`
	TemplateModTime time.Time                        `json:"templateModTime"`
	LastDeployedAt  time.Time                        `json:"lastDeployedAt"`
	Outputs         map[string]deploymentCacheOutput `json:"outputs"`
}

// deploymentCache is the top-level structure persisted to deployment-cache-{layer}.json.
type deploymentCache struct {
	Layers map[string]*deploymentCacheEntry `json:"layers"`
}

// deploymentCachePath returns the path to the deployment cache file for the current environment and layer.
// Each layer writes to its own file (deployment-cache-{layer}.json) so that parallel provisioning
// goroutines never race on a shared file.
func (p *BicepProvider) deploymentCachePath() string {
	filename := fmt.Sprintf("deployment-cache-%s.json", p.layerCacheKey())
	return filepath.Join(p.projectPath, ".azure", p.env.Name(), filename)
}

// layerCacheKey returns the cache key for the current layer.
func (p *BicepProvider) layerCacheKey() string {
	if p.layer == "" {
		return "main"
	}
	return p.layer
}

// loadDeploymentCache reads the cache file from disk. Returns a new empty cache if the file does not exist
// or is malformed.
func loadDeploymentCache(cachePath string) (*deploymentCache, error) {
	data, err := os.ReadFile(cachePath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &deploymentCache{Layers: make(map[string]*deploymentCacheEntry)}, nil
		}
		return nil, err
	}

	var cache deploymentCache
	if err := json.Unmarshal(data, &cache); err != nil {
		// Treat corrupt cache as empty – fall through to Azure API.
		return &deploymentCache{Layers: make(map[string]*deploymentCacheEntry)}, nil
	}

	if cache.Layers == nil {
		cache.Layers = make(map[string]*deploymentCacheEntry)
	}
	return &cache, nil
}

// saveDeploymentCache writes the cache to disk, creating intermediate directories if needed.
func saveDeploymentCache(cachePath string, cache *deploymentCache) error {
	if err := os.MkdirAll(filepath.Dir(cachePath), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return err
	}
	//nolint:gosec // cache file contains no secrets – output values are the same as .env
	return os.WriteFile(cachePath, data, 0600)
}

// computeTemplateContentHash computes a local SHA-256 hash of raw ARM template JSON.
func computeTemplateContentHash(rawTemplate []byte) string {
	h := sha256.Sum256(rawTemplate)
	return fmt.Sprintf("%x", h[:])
}

// checkLocalDeploymentCache checks the local cache and returns a DeployResult if the cache is
// valid, or nil when the caller should fall through to the Azure API check.
func (p *BicepProvider) checkLocalDeploymentCache(
	ctx context.Context,
	planned *compileBicepResult,
	currentParamsHash string,
	result *provisioning.Deployment,
) (*provisioning.DeployResult, error) {
	cachePath := p.deploymentCachePath()
	cache, err := loadDeploymentCache(cachePath)
	if err != nil {
		return nil, fmt.Errorf("loading local cache: %w", err)
	}

	entry, ok := cache.Layers[p.layerCacheKey()]
	if !ok {
		logDS("local cache: no entry for layer %q", p.layerCacheKey())
		return nil, nil
	}

	// 1. Quick check: source file modification time.
	info, err := os.Stat(p.path)
	if err != nil {
		return nil, fmt.Errorf("local cache: stat source file: %w", err)
	}
	if !info.ModTime().Equal(entry.TemplateModTime) {
		logDS("local cache: source file mod time changed")
		return nil, nil
	}

	// 2. Template content hash (local SHA-256 of compiled ARM JSON).
	templateHash := computeTemplateContentHash(planned.RawArmTemplate)
	if templateHash != entry.TemplateHash {
		logDS("local cache: template hash changed")
		return nil, nil
	}

	// 3. Parameter hash.
	if currentParamsHash != entry.ParameterHash {
		logDS("local cache: parameter hash changed")
		return nil, nil
	}

	// All checks passed – reconstruct outputs from cache.
	outputs := make(map[string]provisioning.OutputParameter, len(entry.Outputs))
	for k, v := range entry.Outputs {
		outputs[k] = provisioning.OutputParameter{
			Type:  provisioning.ParameterType(v.Type),
			Value: v.Value,
		}
	}

	logDS("local cache: hit – skipping Azure API call (layer %q)", p.layerCacheKey())
	result.Outputs = outputs

	return &provisioning.DeployResult{
		Deployment:    result,
		SkippedReason: provisioning.DeploymentStateSkipped,
	}, nil
}

// updateLocalDeploymentCache writes the current hashes and outputs to the local cache file.
func (p *BicepProvider) updateLocalDeploymentCache(
	planned *compileBicepResult,
	currentParamsHash string,
	outputs map[string]provisioning.OutputParameter,
) {
	cachePath := p.deploymentCachePath()
	cache, err := loadDeploymentCache(cachePath)
	if err != nil {
		logDS("local cache: failed to load for update: %s", err.Error())
		return
	}

	// Source file mod time.
	var modTime time.Time
	if info, err := os.Stat(p.path); err == nil {
		modTime = info.ModTime()
	}

	// Convert outputs to cache format.
	cachedOutputs := make(map[string]deploymentCacheOutput, len(outputs))
	for k, v := range outputs {
		cachedOutputs[k] = deploymentCacheOutput{
			Type:  string(v.Type),
			Value: v.Value,
		}
	}

	cache.Layers[p.layerCacheKey()] = &deploymentCacheEntry{
		TemplateHash:    computeTemplateContentHash(planned.RawArmTemplate),
		ParameterHash:   currentParamsHash,
		TemplateModTime: modTime,
		LastDeployedAt:  time.Now().UTC(),
		Outputs:         cachedOutputs,
	}

	if err := saveDeploymentCache(cachePath, cache); err != nil {
		logDS("local cache: failed to save: %s", err.Error())
	}
}
