// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package cmd

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAspireBuildGate_ClaimFirst(t *testing.T) {
	gate := newAspireBuildGate()

	// First caller claims the slot
	assert.True(t, gate.ClaimFirst(), "first caller should claim the slot")
	// Subsequent callers get false
	assert.False(t, gate.ClaimFirst(), "second caller should not claim")
	assert.False(t, gate.ClaimFirst(), "third caller should not claim")
}

func TestAspireBuildGate_ClaimFirst_Concurrent(t *testing.T) {
	gate := newAspireBuildGate()

	const goroutines = 50
	results := make([]bool, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			results[idx] = gate.ClaimFirst()
		}(i)
	}
	wg.Wait()

	claimedCount := 0
	for _, r := range results {
		if r {
			claimedCount++
		}
	}
	assert.Equal(t, 1, claimedCount, "exactly one goroutine should claim first")
}

func TestAspireBuildGate_OpenUnblocksWaiters(t *testing.T) {
	gate := newAspireBuildGate()
	ctx := context.Background()

	const waiters = 5
	var wg sync.WaitGroup
	errs := make([]error, waiters)

	// Start waiters before opening
	wg.Add(waiters)
	for i := 0; i < waiters; i++ {
		go func(idx int) {
			defer wg.Done()
			errs[idx] = gate.Wait(ctx)
		}(i)
	}

	// Give waiters time to block
	time.Sleep(50 * time.Millisecond)

	// Open the gate
	gate.Open()
	wg.Wait()

	for i, err := range errs {
		assert.NoError(t, err, "waiter %d should not have error", i)
	}
}

func TestAspireBuildGate_FailUnblocksWaiters(t *testing.T) {
	gate := newAspireBuildGate()
	ctx := context.Background()

	const waiters = 3
	var wg sync.WaitGroup
	errs := make([]error, waiters)

	wg.Add(waiters)
	for i := 0; i < waiters; i++ {
		go func(idx int) {
			defer wg.Done()
			errs[idx] = gate.Wait(ctx)
		}(i)
	}

	time.Sleep(50 * time.Millisecond)

	// Fail the gate
	gate.Fail(errors.New("manifest generation failed"))
	wg.Wait()

	for i, err := range errs {
		require.Error(t, err, "waiter %d should have error", i)
		assert.Contains(t, err.Error(), "aspire build gate failed")
		assert.Contains(t, err.Error(), "manifest generation failed")
	}
}

func TestAspireBuildGate_ContextCancellation(t *testing.T) {
	gate := newAspireBuildGate()
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- gate.Wait(ctx)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	err := <-done
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestAspireBuildGate_OpenIdempotent(t *testing.T) {
	gate := newAspireBuildGate()

	// Calling Open multiple times should not panic
	gate.Open()
	gate.Open()
	gate.Open()

	err := gate.Wait(context.Background())
	assert.NoError(t, err)
}

func TestAspireBuildGate_FailIdempotent(t *testing.T) {
	gate := newAspireBuildGate()

	// Only the first Fail error is stored
	gate.Fail(errors.New("first error"))
	gate.Fail(errors.New("second error"))

	err := gate.Wait(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "first error")
}

func TestAspireBuildGate_OpenBeforeWait(t *testing.T) {
	gate := newAspireBuildGate()

	// Open gate before anyone waits
	gate.Open()

	// Wait should return immediately
	done := make(chan error, 1)
	go func() {
		done <- gate.Wait(context.Background())
	}()

	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(1 * time.Second):
		t.Fatal("Wait should have returned immediately for pre-opened gate")
	}
}

func TestAspireBuildGate_FailBeforeWait(t *testing.T) {
	gate := newAspireBuildGate()

	// Fail gate before anyone waits
	gate.Fail(errors.New("pre-failed"))

	done := make(chan error, 1)
	go func() {
		done <- gate.Wait(context.Background())
	}()

	select {
	case err := <-done:
		require.Error(t, err)
		assert.Contains(t, err.Error(), "pre-failed")
	case <-time.After(1 * time.Second):
		t.Fatal("Wait should have returned immediately for pre-failed gate")
	}
}

func TestAspireBuildGate_FailWithNilError(t *testing.T) {
	gate := newAspireBuildGate()

	gate.Fail(nil)

	err := gate.Wait(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "aspire build gate failed")
}
