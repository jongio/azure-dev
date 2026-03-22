// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package bicep

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// newRealisticCache builds a deploymentCache with the given number of layers,
// each containing 10 outputs, suitable for benchmark data.
func newRealisticCache(layerCount int) *deploymentCache {
	cache := &deploymentCache{Layers: make(map[string]*deploymentCacheEntry, layerCount)}
	for i := 0; i < layerCount; i++ {
		outputs := make(map[string]deploymentCacheOutput, 10)
		for j := 0; j < 10; j++ {
			outputs[fmt.Sprintf("output_%d_%d", i, j)] = deploymentCacheOutput{
				Type:  "string",
				Value: fmt.Sprintf("https://svc%d-%d.azurewebsites.net", i, j),
			}
		}
		cache.Layers[fmt.Sprintf("layer-%d", i)] = &deploymentCacheEntry{
			TemplateHash:    fmt.Sprintf("abc123%d", i),
			ParameterHash:   fmt.Sprintf("def456%d", i),
			TemplateModTime: time.Now().UTC().Add(-time.Duration(i) * time.Hour),
			LastDeployedAt:  time.Now().UTC(),
			Outputs:         outputs,
		}
	}
	return cache
}

// writeCacheFile writes a deploymentCache to a temp file and returns the path.
func writeCacheFile(b *testing.B, cache *deploymentCache) string {
	b.Helper()
	tmpDir := b.TempDir()
	cachePath := filepath.Join(tmpDir, "deployment-cache-main.json")
	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(cachePath, data, 0600); err != nil {
		b.Fatal(err)
	}
	return cachePath
}

// BenchmarkCacheHit measures loading a cache file and finding a matching entry (template hash matches).
func BenchmarkCacheHit(b *testing.B) {
	b.ReportAllocs()

	cache := newRealisticCache(5)
	// Ensure the "main" layer matches what we'll look up.
	cache.Layers["main"] = &deploymentCacheEntry{
		TemplateHash:    "match-hash",
		ParameterHash:   "match-params",
		TemplateModTime: time.Now().UTC(),
		LastDeployedAt:  time.Now().UTC(),
		Outputs: map[string]deploymentCacheOutput{
			"endpoint": {Type: "string", Value: "https://app.azurewebsites.net"},
		},
	}
	cachePath := writeCacheFile(b, cache)

	b.ResetTimer()
	for range b.N {
		c, err := loadDeploymentCache(cachePath)
		if err != nil {
			b.Fatal(err)
		}
		entry, ok := c.Layers["main"]
		if !ok || entry.TemplateHash != "match-hash" {
			b.Fatal("expected cache hit")
		}
	}
}

// BenchmarkCacheMiss measures loading a cache file when the looked-up layer key doesn't exist.
func BenchmarkCacheMiss(b *testing.B) {
	b.ReportAllocs()

	cache := newRealisticCache(5)
	cachePath := writeCacheFile(b, cache)

	b.ResetTimer()
	for range b.N {
		c, err := loadDeploymentCache(cachePath)
		if err != nil {
			b.Fatal(err)
		}
		if _, ok := c.Layers["nonexistent-layer"]; ok {
			b.Fatal("unexpected cache hit")
		}
	}
}

// BenchmarkCacheWrite measures writing a realistic cache with 5 layers (10 outputs each) to disk.
func BenchmarkCacheWrite(b *testing.B) {
	b.ReportAllocs()

	cache := newRealisticCache(5)
	tmpDir := b.TempDir()
	cachePath := filepath.Join(tmpDir, "deployment-cache-main.json")

	b.ResetTimer()
	for range b.N {
		if err := saveDeploymentCache(cachePath, cache); err != nil {
			b.Fatal(err)
		}
	}
}
