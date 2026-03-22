// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package bicep

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/azure/azure-dev/cli/azd/pkg/alpha"
	"github.com/azure/azure-dev/cli/azd/pkg/config"
	"github.com/azure/azure-dev/cli/azd/pkg/exec"
	"github.com/azure/azure-dev/cli/azd/test/mocks"
	"github.com/stretchr/testify/require"
)

// newCacheTestCli creates a Cli with a mocked command runner and the bicep cache alpha feature
// enabled. The returned mock context can be used to set up command expectations.
func newCacheTestCli(t *testing.T) (*Cli, *mocks.MockContext) {
	t.Helper()

	mockContext := mocks.NewMockContext(context.Background())

	// Enable the provision.bicepCache feature via default enablement.
	alpha.SetDefaultEnablement("provision.bicepCache", true)
	t.Cleanup(func() { alpha.ResetDefaultEnablement("provision.bicepCache") })

	alphaManager := alpha.NewFeaturesManagerWithConfig(config.NewEmptyConfig())

	cli := newCliWithTransporter(
		mockContext.Console, mockContext.CommandRunner, mockContext.HttpClient, alphaManager,
	)

	// Pre-initialise the install check so tests never attempt to find or download a real
	// bicep binary. After this call, ensureInstalledOnce is a no-op that returns nil.
	_ = cli.installInit.Do(func() error {
		cli.path = "bicep"
		return nil
	})

	return cli, mockContext
}

func TestBuildCache_HitReturnsCachedResult(t *testing.T) {
	// Not parallel — newCacheTestCli mutates global defaultEnablement.

	dir := t.TempDir()
	bicepFile := filepath.Join(dir, "main.bicep")
	require.NoError(t, os.WriteFile(bicepFile, []byte("param location string"), 0600))

	cli, mockContext := newCacheTestCli(t)

	// Set up the command runner to return a compiled template.
	mockContext.CommandRunner.When(func(args exec.RunArgs, command string) bool {
		return len(args.Args) >= 2 && args.Args[0] == "build" && args.Args[2] == "--stdout"
	}).Respond(exec.NewRunResult(0, `{"$schema":"arm-template"}`, ""))

	ctx := *mockContext.Context

	// First call: cache miss — should invoke bicep build.
	result1, err := cli.Build(ctx, bicepFile)
	require.NoError(t, err)
	require.Equal(t, `{"$schema":"arm-template"}`, result1.Compiled)

	// Second call with same file content: cache hit — should NOT invoke bicep build again.
	// Override the command runner to fail, proving the cache is used.
	mockContext.CommandRunner.When(func(args exec.RunArgs, command string) bool {
		return len(args.Args) >= 2 && args.Args[0] == "build"
	}).Respond(exec.NewRunResult(1, "", "should not be called"))

	result2, err := cli.Build(ctx, bicepFile)
	require.NoError(t, err)
	require.Equal(t, result1.Compiled, result2.Compiled)
	require.Equal(t, result1.LintErr, result2.LintErr)
}

func TestBuildCache_MissTriggersBuild(t *testing.T) {
	// Not parallel — newCacheTestCli mutates global defaultEnablement.

	dir := t.TempDir()
	bicepFile := filepath.Join(dir, "main.bicep")
	require.NoError(t, os.WriteFile(bicepFile, []byte("param name string"), 0600))

	cli, mockContext := newCacheTestCli(t)

	buildCalled := false
	mockContext.CommandRunner.When(func(args exec.RunArgs, command string) bool {
		return len(args.Args) >= 2 && args.Args[0] == "build"
	}).RespondFn(func(args exec.RunArgs) (exec.RunResult, error) {
		buildCalled = true
		return exec.NewRunResult(0, `{"compiled":true}`, ""), nil
	})

	result, err := cli.Build(*mockContext.Context, bicepFile)
	require.NoError(t, err)
	require.True(t, buildCalled, "expected bicep build to be invoked on cache miss")
	require.Equal(t, `{"compiled":true}`, result.Compiled)
}

func TestBuildCache_DifferentContentGetsDifferentKey(t *testing.T) {
	// Not parallel — newCacheTestCli mutates global defaultEnablement.

	dir := t.TempDir()
	bicepFileA := filepath.Join(dir, "a.bicep")
	bicepFileB := filepath.Join(dir, "b.bicep")
	require.NoError(t, os.WriteFile(bicepFileA, []byte("param a string"), 0600))
	require.NoError(t, os.WriteFile(bicepFileB, []byte("param b string"), 0600))

	cli, _ := newCacheTestCli(t)

	keyA, err := cli.buildCacheKey(bicepFileA)
	require.NoError(t, err)

	keyB, err := cli.buildCacheKey(bicepFileB)
	require.NoError(t, err)

	require.NotEqual(t, keyA, keyB, "different file content must produce different cache keys")
}

func TestBuildCache_InvalidationOnFileChange(t *testing.T) {
	// Not parallel — newCacheTestCli mutates global defaultEnablement.

	dir := t.TempDir()
	bicepFile := filepath.Join(dir, "main.bicep")
	require.NoError(t, os.WriteFile(bicepFile, []byte("param v1 string"), 0600))

	cli, mockContext := newCacheTestCli(t)

	callCount := 0
	mockContext.CommandRunner.When(func(args exec.RunArgs, command string) bool {
		return len(args.Args) >= 2 && args.Args[0] == "build"
	}).RespondFn(func(args exec.RunArgs) (exec.RunResult, error) {
		callCount++
		return exec.NewRunResult(0, `{"version":`+string(rune('0'+callCount))+`}`, ""), nil
	})

	ctx := *mockContext.Context

	// First build with v1 content.
	result1, err := cli.Build(ctx, bicepFile)
	require.NoError(t, err)
	require.Equal(t, 1, callCount)

	// Mutate the file content.
	require.NoError(t, os.WriteFile(bicepFile, []byte("param v2 string"), 0600))

	// Second build with v2 content — cache key changes, so bicep build must be invoked again.
	result2, err := cli.Build(ctx, bicepFile)
	require.NoError(t, err)
	require.Equal(t, 2, callCount, "expected second bicep build invocation after file change")
	require.NotEqual(t, result1.Compiled, result2.Compiled)
}

func TestBuildCache_DisabledWithoutAlphaFlag(t *testing.T) {
	// Not parallel — other cache tests mutate global defaultEnablement.

	dir := t.TempDir()
	bicepFile := filepath.Join(dir, "main.bicep")
	require.NoError(t, os.WriteFile(bicepFile, []byte("param loc string"), 0600))

	mockContext := mocks.NewMockContext(context.Background())

	// Create CLI without alpha feature manager — cache should be disabled.
	cli := newCliWithTransporter(
		mockContext.Console, mockContext.CommandRunner, mockContext.HttpClient, nil,
	)
	// Pre-initialise install so real bicep is never looked up.
	_ = cli.installInit.Do(func() error {
		cli.path = "bicep"
		return nil
	})

	callCount := 0
	mockContext.CommandRunner.When(func(args exec.RunArgs, command string) bool {
		return len(args.Args) >= 2 && args.Args[0] == "build"
	}).RespondFn(func(args exec.RunArgs) (exec.RunResult, error) {
		callCount++
		return exec.NewRunResult(0, `{"ok":true}`, ""), nil
	})

	ctx := *mockContext.Context

	_, err := cli.Build(ctx, bicepFile)
	require.NoError(t, err)
	_, err = cli.Build(ctx, bicepFile)
	require.NoError(t, err)

	require.Equal(t, 2, callCount, "without alpha flag, every Build call should invoke bicep")
}

func TestBuildCacheKey_IncludesBicepparamContent(t *testing.T) {
	// Not parallel — newCacheTestCli mutates global defaultEnablement.

	dir := t.TempDir()
	bicepFile := filepath.Join(dir, "main.bicep")
	paramFile := filepath.Join(dir, "main.bicepparam")

	require.NoError(t, os.WriteFile(bicepFile, []byte("param loc string"), 0600))

	cli, _ := newCacheTestCli(t)

	// Key without .bicepparam
	keyWithout, err := cli.buildCacheKey(bicepFile)
	require.NoError(t, err)

	// Add a .bicepparam file
	require.NoError(t, os.WriteFile(paramFile, []byte("using './main.bicep'\nparam loc = 'eastus'"), 0600))

	// Key with .bicepparam — must differ
	keyWith, err := cli.buildCacheKey(bicepFile)
	require.NoError(t, err)

	require.NotEqual(t, keyWithout, keyWith, "adding a .bicepparam file must change the cache key")
}
