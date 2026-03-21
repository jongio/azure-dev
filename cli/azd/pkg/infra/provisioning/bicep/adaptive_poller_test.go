// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package bicep

import (
	"testing"
	"time"

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
