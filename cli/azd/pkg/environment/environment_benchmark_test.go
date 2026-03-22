// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package environment

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/azure/azure-dev/cli/azd/pkg/config"
	"github.com/azure/azure-dev/cli/azd/pkg/environment/azdcontext"
	"github.com/joho/godotenv"
)

// BenchmarkDotenvSet measures the cost of setting 100 environment variables on an Environment.
func BenchmarkDotenvSet(b *testing.B) {
	b.ReportAllocs()

	keys := make([]string, 100)
	vals := make([]string, 100)
	for i := range keys {
		keys[i] = fmt.Sprintf("SERVICE_%d_ENDPOINT", i)
		vals[i] = fmt.Sprintf("https://svc%d.azurewebsites.net", i)
	}

	b.ResetTimer()
	for range b.N {
		env := New("bench-env")
		for i := 0; i < 100; i++ {
			env.DotenvSet(keys[i], vals[i])
		}
	}
}

// BenchmarkDotenvGet measures lookup performance on a populated Environment with 100 variables.
func BenchmarkDotenvGet(b *testing.B) {
	b.ReportAllocs()

	values := make(map[string]string, 100)
	keys := make([]string, 100)
	for i := range keys {
		keys[i] = fmt.Sprintf("SERVICE_%d_ENDPOINT", i)
		values[keys[i]] = fmt.Sprintf("https://svc%d.azurewebsites.net", i)
	}
	env := NewWithValues("bench-env", values)

	b.ResetTimer()
	for range b.N {
		for _, k := range keys {
			_ = env.Getenv(k)
		}
	}
}

// BenchmarkEnvironmentReload measures the cost of reloading an Environment from a .env file on disk.
func BenchmarkEnvironmentReload(b *testing.B) {
	b.ReportAllocs()

	// Build a realistic .env file with 100 entries.
	values := make(map[string]string, 100)
	for i := 0; i < 100; i++ {
		values[fmt.Sprintf("SERVICE_%d_ENDPOINT", i)] = fmt.Sprintf("https://svc%d.azurewebsites.net", i)
	}
	values[EnvNameEnvVarName] = "bench-env"

	dotenvContent, err := godotenv.Marshal(values)
	if err != nil {
		b.Fatal(err)
	}

	// Write to a temp directory matching the LocalFileDataStore layout: <root>/.azure/<name>/.env
	tmpDir := b.TempDir()
	azdCtx := azdcontext.NewAzdContextWithDirectory(tmpDir)
	envDir := azdCtx.EnvironmentRoot("bench-env")
	if err := os.MkdirAll(envDir, 0700); err != nil {
		b.Fatal(err)
	}
	envPath := filepath.Join(envDir, DotEnvFileName)
	if err := os.WriteFile(envPath, []byte(dotenvContent), 0600); err != nil {
		b.Fatal(err)
	}

	cfgMgr := config.NewFileConfigManager(config.NewManager())
	ds := NewLocalFileDataStore(azdCtx, cfgMgr)

	env := New("bench-env")

	b.ResetTimer()
	for range b.N {
		if err := ds.Reload(context.Background(), env); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkNewWithValues measures creating a new Environment from a pre-built map of 50 key/value pairs.
func BenchmarkNewWithValues(b *testing.B) {
	b.ReportAllocs()

	values := make(map[string]string, 50)
	for i := 0; i < 50; i++ {
		values[fmt.Sprintf("KEY_%d", i)] = fmt.Sprintf("value-%d", i)
	}

	b.ResetTimer()
	for range b.N {
		_ = NewWithValues("bench-env", values)
	}
}
