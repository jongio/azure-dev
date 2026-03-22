// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package bicep

import (
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/stretchr/testify/require"
)

func TestNewAdaptivePoller(t *testing.T) {
	poller := newAdaptivePoller()
	require.Equal(t, 1*time.Second, poller.minInterval)
	require.Equal(t, 10*time.Second, poller.maxInterval)
	require.Equal(t, 1*time.Second, poller.currentInterval)
	require.Equal(t, 2.0, poller.backoffFactor)
	require.Equal(t, -1, poller.lastResourceCount)
}

func TestAdaptivePollerBacksOffWhenStateUnchanged(t *testing.T) {
	poller := newAdaptivePoller()

	// First call with 0 resources — state changes from -1 to 0, should reset to min
	interval := poller.nextInterval(0)
	require.Equal(t, 1*time.Second, interval)

	// Same state (0 resources) — should back off
	interval = poller.nextInterval(0)
	require.Equal(t, 2*time.Second, interval)

	interval = poller.nextInterval(0)
	require.Equal(t, 4*time.Second, interval)

	interval = poller.nextInterval(0)
	require.Equal(t, 8*time.Second, interval)

	// Should cap at maxInterval (10s)
	interval = poller.nextInterval(0)
	require.Equal(t, 10*time.Second, interval)

	// Should stay at cap
	interval = poller.nextInterval(0)
	require.Equal(t, 10*time.Second, interval)
}

func TestAdaptivePollerResetsOnStateChange(t *testing.T) {
	poller := newAdaptivePoller()

	// Initial state change from -1 to 0
	poller.nextInterval(0)
	// Back off a few times
	poller.nextInterval(0) // 2s
	poller.nextInterval(0) // 4s
	interval := poller.nextInterval(0)
	require.Equal(t, 8*time.Second, interval)

	// New resource completed — state changes, should reset to min
	interval = poller.nextInterval(1)
	require.Equal(t, 1*time.Second, interval)

	// Back off again from the new state
	interval = poller.nextInterval(1)
	require.Equal(t, 2*time.Second, interval)

	// Another resource completes — reset again
	interval = poller.nextInterval(2)
	require.Equal(t, 1*time.Second, interval)
}

func TestAdaptivePollerNeverExceedsMax(t *testing.T) {
	poller := newAdaptivePoller()

	// Pump through many iterations — should never exceed maxInterval
	poller.nextInterval(0) // 1s (state change from -1 to 0)
	for i := 0; i < 20; i++ {
		interval := poller.nextInterval(0)
		require.LessOrEqual(t, interval, 10*time.Second, "interval should never exceed maxInterval")
	}
}

func TestAdaptivePollerExponentialSequence(t *testing.T) {
	poller := newAdaptivePoller()

	// Trigger initial state change
	first := poller.nextInterval(5)
	require.Equal(t, 1*time.Second, first)

	// Verify exact exponential sequence: 2s, 4s, 8s, 10s (capped)
	expected := []time.Duration{
		2 * time.Second,
		4 * time.Second,
		8 * time.Second,
		10 * time.Second,
	}

	for i, exp := range expected {
		got := poller.nextInterval(5)
		require.Equal(t, exp, got, "iteration %d", i)
	}
}

func TestRgExistsCacheConcurrency(t *testing.T) {
	t.Parallel()
	// Exercises sync.Map under concurrent access — runs clean with -race.
	var cache sync.Map

	const goroutines = 50
	const opsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < opsPerGoroutine; i++ {
				key := fmt.Sprintf("/subscriptions/sub/resourceGroups/rg-%d", (id+i)%20)
				cache.Store(key, true)
				if _, ok := cache.Load(key); !ok {
					t.Errorf("expected key %s to be present after Store", key)
				}
			}
		}(g)
	}

	wg.Wait()
}

func TestAdaptivePolling_ThrottleDetection(t *testing.T) {
	t.Run("recordThrottle forces max interval", func(t *testing.T) {
		poller := newAdaptivePoller()
		// Start with a normal interval.
		poller.nextInterval(0)
		require.Equal(t, 1*time.Second, poller.currentInterval)

		// Record a throttle — interval should jump to max.
		poller.recordThrottle()
		require.Equal(t, poller.maxInterval, poller.currentInterval)
	})

	t.Run("warning emitted at threshold", func(t *testing.T) {
		poller := newAdaptivePoller()
		for i := 1; i < throttleThreshold; i++ {
			shouldWarn := poller.recordThrottle()
			require.False(t, shouldWarn, "should not warn before threshold (throttle %d)", i)
		}
		shouldWarn := poller.recordThrottle()
		require.True(t, shouldWarn, "should warn at threshold")

		// Beyond threshold — no repeat warning.
		shouldWarn = poller.recordThrottle()
		require.False(t, shouldWarn, "should not warn again after threshold")
	})

	t.Run("clearThrottle resets counter", func(t *testing.T) {
		poller := newAdaptivePoller()
		for i := 0; i < throttleThreshold-1; i++ {
			poller.recordThrottle()
		}
		poller.clearThrottle()
		require.Equal(t, 0, poller.consecutiveThrottles)

		// After clear, it takes another full threshold to warn.
		for i := 1; i < throttleThreshold; i++ {
			require.False(t, poller.recordThrottle())
		}
		require.True(t, poller.recordThrottle(), "should warn again after clear + threshold")
	})

	t.Run("isThrottleError detects 429", func(t *testing.T) {
		throttleErr := &azcore.ResponseError{StatusCode: http.StatusTooManyRequests}
		require.True(t, isThrottleError(throttleErr))

		otherErr := &azcore.ResponseError{StatusCode: http.StatusInternalServerError}
		require.False(t, isThrottleError(otherErr))

		plainErr := fmt.Errorf("some other error")
		require.False(t, isThrottleError(plainErr))
	})
}
