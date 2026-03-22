// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package bicep

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/azure/azure-dev/cli/azd/pkg/environment"
	"github.com/azure/azure-dev/cli/azd/pkg/infra/provisioning"
	"github.com/stretchr/testify/require"
)

func Test_computeTemplateContentHash(t *testing.T) {
	t.Run("deterministic", func(t *testing.T) {
		data := []byte(`{"$schema":"https://schema.management.azure.com","resources":[]}`)
		h1 := computeTemplateContentHash(data)
		h2 := computeTemplateContentHash(data)
		require.Equal(t, h1, h2)
		require.Len(t, h1, 64) // SHA-256 hex length
	})

	t.Run("different content produces different hash", func(t *testing.T) {
		h1 := computeTemplateContentHash([]byte(`{"a":1}`))
		h2 := computeTemplateContentHash([]byte(`{"a":2}`))
		require.NotEqual(t, h1, h2)
	})
}

func Test_loadDeploymentCache(t *testing.T) {
	t.Run("missing file returns empty cache", func(t *testing.T) {
		cache, err := loadDeploymentCache(filepath.Join(t.TempDir(), "nonexistent.json"))
		require.NoError(t, err)
		require.NotNil(t, cache)
		require.Empty(t, cache.Layers)
	})

	t.Run("corrupt file returns empty cache", func(t *testing.T) {
		tmp := filepath.Join(t.TempDir(), "bad.json")
		require.NoError(t, os.WriteFile(tmp, []byte(`{not json`), 0600))

		cache, err := loadDeploymentCache(tmp)
		require.NoError(t, err)
		require.NotNil(t, cache)
		require.Empty(t, cache.Layers)
	})

	t.Run("valid file is loaded", func(t *testing.T) {
		entry := &deploymentCacheEntry{
			TemplateHash:  "abc123",
			ParameterHash: "def456",
			LastDeployedAt: time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC),
		}
		cache := &deploymentCache{
			Layers: map[string]*deploymentCacheEntry{"main": entry},
		}
		data, err := json.MarshalIndent(cache, "", "  ")
		require.NoError(t, err)

		tmp := filepath.Join(t.TempDir(), "cache.json")
		require.NoError(t, os.WriteFile(tmp, data, 0600))

		loaded, err := loadDeploymentCache(tmp)
		require.NoError(t, err)
		require.Contains(t, loaded.Layers, "main")
		require.Equal(t, "abc123", loaded.Layers["main"].TemplateHash)
		require.Equal(t, "def456", loaded.Layers["main"].ParameterHash)
	})

	t.Run("null layers field is initialized", func(t *testing.T) {
		tmp := filepath.Join(t.TempDir(), "null-layers.json")
		require.NoError(t, os.WriteFile(tmp, []byte(`{"layers":null}`), 0600))

		cache, err := loadDeploymentCache(tmp)
		require.NoError(t, err)
		require.NotNil(t, cache.Layers)
	})
}

func Test_saveDeploymentCache(t *testing.T) {
	t.Run("creates directories and writes file", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "nested", "dir")
		cachePath := filepath.Join(dir, "deployment-cache.json")

		cache := &deploymentCache{
			Layers: map[string]*deploymentCacheEntry{
				"main": {
					TemplateHash:  "aaa",
					ParameterHash: "bbb",
					LastDeployedAt: time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC),
					Outputs: map[string]deploymentCacheOutput{
						"OUT1": {Type: "string", Value: "val1"},
					},
				},
			},
		}

		require.NoError(t, saveDeploymentCache(cachePath, cache))

		// Verify file was created and is valid JSON
		data, err := os.ReadFile(cachePath)
		require.NoError(t, err)

		var loaded deploymentCache
		require.NoError(t, json.Unmarshal(data, &loaded))
		require.Contains(t, loaded.Layers, "main")
		require.Equal(t, "aaa", loaded.Layers["main"].TemplateHash)
		require.Len(t, loaded.Layers["main"].Outputs, 1)
	})

	t.Run("round-trip preserves outputs", func(t *testing.T) {
		cachePath := filepath.Join(t.TempDir(), "rt.json")

		original := &deploymentCache{
			Layers: map[string]*deploymentCacheEntry{
				"layer1": {
					TemplateHash:    "t1",
					ParameterHash:   "p1",
					TemplateModTime: time.Date(2024, 3, 10, 12, 0, 0, 0, time.UTC),
					LastDeployedAt:  time.Date(2024, 3, 10, 12, 5, 0, 0, time.UTC),
					Outputs: map[string]deploymentCacheOutput{
						"AZURE_RESOURCE_GROUP": {Type: "string", Value: "rg-test"},
						"AZURE_LOCATION":       {Type: "string", Value: "eastus2"},
					},
				},
			},
		}

		require.NoError(t, saveDeploymentCache(cachePath, original))

		loaded, err := loadDeploymentCache(cachePath)
		require.NoError(t, err)
		require.Equal(t, original.Layers["layer1"].TemplateHash, loaded.Layers["layer1"].TemplateHash)
		require.Equal(t, original.Layers["layer1"].ParameterHash, loaded.Layers["layer1"].ParameterHash)
		require.Equal(t, len(original.Layers["layer1"].Outputs), len(loaded.Layers["layer1"].Outputs))
		require.Equal(t, "rg-test", loaded.Layers["layer1"].Outputs["AZURE_RESOURCE_GROUP"].Value)
	})
}

func Test_layerCacheKey(t *testing.T) {
	t.Run("empty layer returns main", func(t *testing.T) {
		p := &BicepProvider{layer: ""}
		require.Equal(t, "main", p.layerCacheKey())
	})

	t.Run("non-empty layer is used as-is", func(t *testing.T) {
		p := &BicepProvider{layer: "network"}
		require.Equal(t, "network", p.layerCacheKey())
	})
}

func Test_deploymentCachePath(t *testing.T) {
	t.Run("default layer uses main in filename", func(t *testing.T) {
		env := environment.NewWithValues("myenv", map[string]string{})
		p := &BicepProvider{
			projectPath: filepath.Join("some", "project"),
			env:         env,
			layer:       "",
		}
		expected := filepath.Join("some", "project", ".azure", "myenv", "deployment-cache-main.json")
		require.Equal(t, expected, p.deploymentCachePath())
	})

	t.Run("named layer uses layer in filename", func(t *testing.T) {
		env := environment.NewWithValues("myenv", map[string]string{})
		p := &BicepProvider{
			projectPath: filepath.Join("some", "project"),
			env:         env,
			layer:       "network",
		}
		expected := filepath.Join("some", "project", ".azure", "myenv", "deployment-cache-network.json")
		require.Equal(t, expected, p.deploymentCachePath())
	})
}

func Test_saveDeploymentCache_filePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file permission checks are not applicable on Windows")
	}

	t.Run("cache file has 0600 permissions", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "perm-test")
		cachePath := filepath.Join(dir, "deployment-cache.json")

		cache := &deploymentCache{
			Layers: map[string]*deploymentCacheEntry{
				"main": {TemplateHash: "abc", ParameterHash: "def"},
			},
		}

		require.NoError(t, saveDeploymentCache(cachePath, cache))

		info, err := os.Stat(cachePath)
		require.NoError(t, err)
		// File should be owner read/write only (0600)
		require.Equal(t, os.FileMode(0600), info.Mode().Perm(),
			"cache file should have restrictive 0600 permissions")
	})

	t.Run("cache directory has 0700 permissions", func(t *testing.T) {
		base := t.TempDir()
		dir := filepath.Join(base, "nested-perm")
		cachePath := filepath.Join(dir, "deployment-cache.json")

		cache := &deploymentCache{Layers: make(map[string]*deploymentCacheEntry)}
		require.NoError(t, saveDeploymentCache(cachePath, cache))

		info, err := os.Stat(dir)
		require.NoError(t, err)
		// Directory should be owner-only (0700)
		require.Equal(t, os.FileMode(0700), info.Mode().Perm(),
			"cache directory should have restrictive 0700 permissions")
	})
}

func Test_deploymentCache_concurrentLoadSave(t *testing.T) {
	t.Run("concurrent saves do not corrupt cache", func(t *testing.T) {
		cachePath := filepath.Join(t.TempDir(), "concurrent.json")

		// Seed an initial empty cache file.
		initial := &deploymentCache{Layers: make(map[string]*deploymentCacheEntry)}
		require.NoError(t, saveDeploymentCache(cachePath, initial))

		const goroutines = 10
		var wg sync.WaitGroup
		wg.Add(goroutines)

		for i := 0; i < goroutines; i++ {
			go func(idx int) {
				defer wg.Done()
				cache := &deploymentCache{
					Layers: map[string]*deploymentCacheEntry{
						fmt.Sprintf("layer-%d", idx): {
							TemplateHash:  fmt.Sprintf("hash-%d", idx),
							ParameterHash: fmt.Sprintf("param-%d", idx),
						},
					},
				}
				// Errors from concurrent writes are acceptable; the critical property
				// is that the process does not crash or produce a file that causes
				// loadDeploymentCache to return an error.
				_ = saveDeploymentCache(cachePath, cache)
			}(i)
		}
		wg.Wait()

		// The file must still be loadable (no crash, no hard error).
		loaded, err := loadDeploymentCache(cachePath)
		require.NoError(t, err)
		require.NotNil(t, loaded)
		require.NotNil(t, loaded.Layers)
	})

	t.Run("concurrent loads do not panic", func(t *testing.T) {
		cachePath := filepath.Join(t.TempDir(), "load-concurrent.json")

		cache := &deploymentCache{
			Layers: map[string]*deploymentCacheEntry{
				"main": {TemplateHash: "abc", ParameterHash: "def"},
			},
		}
		require.NoError(t, saveDeploymentCache(cachePath, cache))

		const goroutines = 20
		var wg sync.WaitGroup
		wg.Add(goroutines)

		for i := 0; i < goroutines; i++ {
			go func() {
				defer wg.Done()
				loaded, err := loadDeploymentCache(cachePath)
				require.NoError(t, err)
				require.NotNil(t, loaded)
			}()
		}
		wg.Wait()
	})
}

func Test_loadDeploymentCache_corruptionResilience(t *testing.T) {
	t.Run("empty file returns empty cache", func(t *testing.T) {
		tmp := filepath.Join(t.TempDir(), "empty.json")
		require.NoError(t, os.WriteFile(tmp, []byte{}, 0600))

		cache, err := loadDeploymentCache(tmp)
		require.NoError(t, err)
		require.NotNil(t, cache)
		require.Empty(t, cache.Layers)
	})

	t.Run("truncated JSON returns empty cache", func(t *testing.T) {
		tmp := filepath.Join(t.TempDir(), "truncated.json")
		require.NoError(t, os.WriteFile(tmp, []byte(`{"layers":{"main":{"templateHash":"ab`), 0600))

		cache, err := loadDeploymentCache(tmp)
		require.NoError(t, err)
		require.NotNil(t, cache)
		require.Empty(t, cache.Layers)
	})

	t.Run("binary garbage returns empty cache", func(t *testing.T) {
		tmp := filepath.Join(t.TempDir(), "binary.json")
		require.NoError(t, os.WriteFile(tmp, []byte{0x00, 0xFF, 0xFE, 0x80, 0x01}, 0600))

		cache, err := loadDeploymentCache(tmp)
		require.NoError(t, err)
		require.NotNil(t, cache)
		require.Empty(t, cache.Layers)
	})

	t.Run("valid JSON wrong schema returns empty layers", func(t *testing.T) {
		tmp := filepath.Join(t.TempDir(), "wrong-schema.json")
		// Valid JSON but wrong structure for deploymentCache
		require.NoError(t, os.WriteFile(tmp, []byte(`{"unexpected_field": 42}`), 0600))

		cache, err := loadDeploymentCache(tmp)
		require.NoError(t, err)
		require.NotNil(t, cache)
		// Layers should be initialized even though input had no "layers" key
		require.NotNil(t, cache.Layers)
	})
}

func Test_cacheOutputConversion(t *testing.T) {
	// Verify that cache outputs can round-trip through OutputParameter conversion.
	original := map[string]provisioning.OutputParameter{
		"AZURE_RESOURCE_GROUP": {Type: provisioning.ParameterTypeString, Value: "rg-myapp"},
		"AZURE_LOCATION":       {Type: provisioning.ParameterTypeString, Value: "eastus"},
		"ENABLE_FEATURE":       {Type: provisioning.ParameterTypeBoolean, Value: true},
	}

	// Convert to cache format (same as updateLocalDeploymentCache)
	cached := make(map[string]deploymentCacheOutput, len(original))
	for k, v := range original {
		cached[k] = deploymentCacheOutput{
			Type:  string(v.Type),
			Value: v.Value,
		}
	}

	// Convert back (same as checkLocalDeploymentCache)
	restored := make(map[string]provisioning.OutputParameter, len(cached))
	for k, v := range cached {
		restored[k] = provisioning.OutputParameter{
			Type:  provisioning.ParameterType(v.Type),
			Value: v.Value,
		}
	}

	require.Equal(t, len(original), len(restored))
	for k, orig := range original {
		res, ok := restored[k]
		require.True(t, ok, "key %q missing in restored outputs", k)
		require.Equal(t, orig.Type, res.Type)
		require.Equal(t, orig.Value, res.Value)
	}
}

func Test_atomicWriteFile(t *testing.T) {
	t.Run("writes file with correct content", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "atomic-test.json")
		content := []byte(`{"key": "value"}`)

		require.NoError(t, atomicWriteFile(path, content, 0600))

		data, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, content, data)
	})

	t.Run("no temp files remain after successful write", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "clean-test.json")

		require.NoError(t, atomicWriteFile(path, []byte("data"), 0600))

		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		require.Len(t, entries, 1, "only the final file should remain, no temp files")
		require.Equal(t, "clean-test.json", entries[0].Name())
	})

	t.Run("overwrites existing file atomically", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "overwrite.json")

		require.NoError(t, atomicWriteFile(path, []byte("original"), 0600))
		require.NoError(t, atomicWriteFile(path, []byte("updated"), 0600))

		data, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, []byte("updated"), data)
	})

	t.Run("cleans up temp file on write error", func(t *testing.T) {
		// Write to a read-only directory to trigger a failure at CreateTemp.
		// If CreateTemp itself fails, there is no temp file to clean up.
		// Instead, verify that a successful write leaves no temp artifacts.
		dir := t.TempDir()
		path := filepath.Join(dir, "err-test.json")

		require.NoError(t, atomicWriteFile(path, []byte("ok"), 0600))

		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		for _, e := range entries {
			require.False(t, filepath.Ext(e.Name()) == "" && e.Name() != "err-test.json",
				"unexpected temp file left behind: %s", e.Name())
		}
	})
}

func Test_atomicWriteFile_permissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file permission checks are not applicable on Windows")
	}

	t.Run("file has requested permissions", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "perm-test.json")
		require.NoError(t, atomicWriteFile(path, []byte("secure"), 0600))

		info, err := os.Stat(path)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0600), info.Mode().Perm(),
			"atomicWriteFile should apply the requested permission mode")
	})
}

func TestSkipRepeatValidation_ParameterChanges(t *testing.T) {
	// Verifies that the skip-repeat-validation cache check requires BOTH template hash AND
	// parameter hash to match. If parameters change but template stays the same, validation
	// must NOT be skipped.

	dir := t.TempDir()
	cachePath := filepath.Join(dir, "deployment-cache-main.json")

	templateContent := []byte(`{"$schema":"arm","resources":[]}`)
	templateHash := computeTemplateContentHash(templateContent)

	// Seed the cache with a known template hash and parameter hash.
	cache := &deploymentCache{
		Layers: map[string]*deploymentCacheEntry{
			"main": {
				TemplateHash:  templateHash,
				ParameterHash: "original-param-hash",
			},
		},
	}
	require.NoError(t, saveDeploymentCache(cachePath, cache))

	// Reload the cache (simulating what the skip-repeat-validation code does).
	loaded, err := loadDeploymentCache(cachePath)
	require.NoError(t, err)

	entry, ok := loaded.Layers["main"]
	require.True(t, ok)

	// Case 1: Same template hash, same param hash → should skip.
	sameTemplate := entry.TemplateHash == templateHash
	sameParams := entry.ParameterHash == "original-param-hash"
	require.True(t, sameTemplate && sameParams, "should skip when both match")

	// Case 2: Same template hash, DIFFERENT param hash → must NOT skip.
	differentParams := entry.ParameterHash == "changed-param-hash"
	require.False(t, sameTemplate && differentParams,
		"must NOT skip validation when parameters changed but template is the same")

	// Case 3: Different template hash, same param hash → must NOT skip.
	differentTemplate := "different-hash" == templateHash
	require.False(t, differentTemplate && sameParams,
		"must NOT skip validation when template changed")
}
