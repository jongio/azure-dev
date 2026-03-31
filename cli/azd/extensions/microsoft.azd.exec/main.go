// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package main

import (
	"errors"
	"os"

	"microsoft.azd.exec/internal/cmd"
	"microsoft.azd.exec/internal/executor"

	"github.com/azure/azure-dev/cli/azd/pkg/azdext"
	"github.com/fatih/color"
)

func init() {
	forceColorVal, has := os.LookupEnv("FORCE_COLOR")
	if has && forceColorVal == "1" {
		color.NoColor = false
	}
}

func main() {
	ctx := azdext.NewContext()
	ctx = azdext.WithAccessToken(ctx)
	rootCmd := cmd.NewRootCommand()

	if err := rootCmd.ExecuteContext(ctx); err != nil {
		// Report all errors to azd for telemetry before exiting.
		_ = azdext.ReportError(ctx, err)

		// Propagate the child process exit code so callers (CI/CD, scripts)
		// observe the same code the executed script returned.
		if execErr, ok := errors.AsType[*executor.ExecutionError](err); ok {
			os.Exit(execErr.ExitCode)
		}

		color.Red("Error: %v", err)
		os.Exit(1)
	}
}
