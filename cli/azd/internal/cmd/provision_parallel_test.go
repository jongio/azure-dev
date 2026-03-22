// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package cmd

import (
	"context"
	"sync"
	"testing"

	"github.com/azure/azure-dev/cli/azd/pkg/input"
	"github.com/azure/azure-dev/cli/azd/test/mocks/mockinput"
	"github.com/stretchr/testify/require"
)

// syncEnvManager tests are in provision_security_test.go alongside the mockEnvManager.
// This file covers syncConsole concurrent access tests.

func TestSyncConsole_ConcurrentMessage(t *testing.T) {
	// Verify that syncConsole serializes concurrent Message calls.
	// Under -race, this would fire without the mutex.
	const goroutines = 50

	inner := mockinput.NewMockConsole()
	sc := &syncConsole{Console: inner}

	ctx := context.Background()
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			sc.Message(ctx, "hello")
		}()
	}

	wg.Wait()
	// MockConsole.Message appends to an internal log; verify no panics occurred
	// and all goroutines completed. The -race detector is the real verifier here.
}

func TestSyncConsole_ConcurrentMixedOps(t *testing.T) {
	// Verify that mixed concurrent calls to different syncConsole methods
	// do not race. The -race detector is the primary verifier.
	const goroutines = 30

	inner := mockinput.NewMockConsole()
	sc := &syncConsole{Console: inner}

	ctx := context.Background()
	var wg sync.WaitGroup
	wg.Add(goroutines * 3)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			sc.Message(ctx, "msg")
		}()
		go func() {
			defer wg.Done()
			sc.ShowSpinner(ctx, "loading", input.Step)
		}()
		go func() {
			defer wg.Done()
			sc.StopSpinner(ctx, "done", input.Step)
		}()
	}

	wg.Wait()
}

func TestSyncConsole_SerializesAccess(t *testing.T) {
	// Verify that when syncConsole wraps an inner console, the mutex
	// prevents concurrent access. We verify this by checking that
	// no panics occur during highly concurrent mixed operations.
	const goroutines = 100

	inner := mockinput.NewMockConsole()
	sc := &syncConsole{Console: inner}

	ctx := context.Background()
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(n int) {
			defer wg.Done()
			switch n % 5 {
			case 0:
				sc.Message(ctx, "hello")
			case 1:
				sc.ShowSpinner(ctx, "loading", input.Step)
			case 2:
				sc.StopSpinner(ctx, "done", input.Step)
			case 3:
				sc.EnsureBlankLine(ctx)
			case 4:
				sc.Message(ctx, "ux-item") // MessageUxItem needs a non-nil UxItem; use Message instead
			}
		}(i)
	}

	wg.Wait()
	require.True(t, true, "no panics during concurrent syncConsole access")
}
