// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package workflow

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/azure/azure-dev/cli/azd/internal"
	"github.com/azure/azure-dev/cli/azd/pkg/input"
	"golang.org/x/sync/errgroup"
)

// AzdCommandRunner abstracts the execution of an azd command given a set of arguments and context.
type AzdCommandRunner interface {
	ExecuteContext(ctx context.Context, args []string) error
}

// ConcurrentExecutor is an optional interface that AzdCommandRunner implementations
// can implement to support concurrent command execution. Unlike the standard
// SetArgs + ExecuteContext pattern (which shares mutable state on a single cobra.Command),
// FindAndExecute locates and invokes the target command directly, making it safe
// to call from multiple goroutines simultaneously.
type ConcurrentExecutor interface {
	// FindAndExecute finds the target sub-command for the given args and executes
	// it directly. Each call operates on an independent cobra.Command object,
	// so concurrent calls with different args are safe.
	FindAndExecute(ctx context.Context, args []string) error
}

// Runner is responsible for executing a workflow
type Runner struct {
	azdRunner AzdCommandRunner
	console   input.Console
}

// NewRunner creates a new instance of the Runner.
func NewRunner(azdRunner AzdCommandRunner, console input.Console) *Runner {
	return &Runner{
		azdRunner: azdRunner,
		console:   console,
	}
}

// Run executes the specified workflow against the root cobra command
func (r *Runner) Run(ctx context.Context, workflow *Workflow) error {
	for _, step := range workflow.Steps {
		// Create a child context for this step to enable automatic handler cleanup
		stepCtx, cancel := context.WithCancel(ctx)

		// Execute the step with the step-scoped context and command args
		err := r.azdRunner.ExecuteContext(stepCtx, step.AzdCommand.Args)

		// Cancel the step context to trigger automatic cleanup of any handlers
		// registered during this step execution
		cancel()

		if err != nil {
			// User intentionally aborted — stop the workflow without wrapping the error.
			// Returning the original error preserves errors.Is checks upstream.
			if errors.Is(err, internal.ErrAbortedByUser) {
				return err
			}
			return fmt.Errorf("error executing step command '%s': %w", strings.Join(step.AzdCommand.Args, " "), err)
		}
	}

	return nil
}

// RunConcurrentSteps executes the provided workflow steps concurrently using errgroup.
// It requires the underlying AzdCommandRunner to implement ConcurrentExecutor.
// If the runner does not support concurrent execution, it falls back to sequential execution.
//
// This method is safe for concurrent use because it bypasses the shared cobra.Command.args
// field. Instead of SetArgs + ExecuteContext (which mutate shared state), each goroutine
// finds its target sub-command via cobra.Command.Find (read-only tree traversal) and
// invokes the sub-command's RunE directly. Since each sub-command is a distinct
// cobra.Command object with its own flag set and context, concurrent execution is safe.
//
// SAFETY: Each step must target a distinct top-level subcommand (e.g. "package" and "provision").
// Concurrent execution of the same subcommand is a data race because cobra.Command.Find
// returns the same pointer, and ParseFlags/SetContext mutate that shared instance.
func (r *Runner) RunConcurrentSteps(ctx context.Context, steps []*Step) error {
	ce, ok := r.azdRunner.(ConcurrentExecutor)
	if !ok {
		// Fall back to sequential execution
		return r.Run(ctx, &Workflow{Steps: steps})
	}

	// Validate that no two steps target the same top-level subcommand.
	// cobra.Command.Find returns the same pointer for the same path, so concurrent
	// calls with identical first args would race on ParseFlags and SetContext.
	seen := make(map[string]bool, len(steps))
	for _, step := range steps {
		if len(step.AzdCommand.Args) == 0 {
			continue
		}
		key := step.AzdCommand.Args[0]
		if seen[key] {
			return fmt.Errorf(
				"concurrent execution of duplicate subcommand %q is not supported: "+
					"each step must target a distinct subcommand", key)
		}
		seen[key] = true
	}

	g, gCtx := errgroup.WithContext(ctx)

	for _, step := range steps {
		if len(step.AzdCommand.Args) == 0 {
			continue
		}

		g.Go(func() error {
			stepCtx, cancel := context.WithCancel(gCtx)
			defer cancel()

			if err := ce.FindAndExecute(stepCtx, step.AzdCommand.Args); err != nil {
				return fmt.Errorf(
					"error executing step command '%s': %w", strings.Join(step.AzdCommand.Args, " "), err,
				)
			}

			return nil
		})
	}

	return g.Wait()
}
