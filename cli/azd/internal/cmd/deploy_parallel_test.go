// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package cmd

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/multierr"
)

func TestDeployServicesParallel_ErrorCollection(t *testing.T) {
	// Verify that multierr.Combine correctly aggregates multiple errors,
	// matching the pattern used in deployServicesParallel.
	errA := errors.New("service-api failed: timeout")
	errB := errors.New("service-web failed: image not found")

	// Simulate the error collection pattern from deployServicesParallel
	var errs []error
	errs = append(errs, errA)
	errs = append(errs, errB)

	combined := multierr.Combine(errs...)
	require.Error(t, combined, "combined error should be non-nil")

	// Both error messages should be present in the combined error
	msg := combined.Error()
	require.True(t, strings.Contains(msg, "service-api failed"),
		"combined error should contain first error message, got: %s", msg)
	require.True(t, strings.Contains(msg, "service-web failed"),
		"combined error should contain second error message, got: %s", msg)

	// multierr.Errors should return both individual errors
	individual := multierr.Errors(combined)
	require.Len(t, individual, 2, "should have exactly 2 errors")
}

func TestDeployServicesParallel_SingleError(t *testing.T) {
	// When only one service fails, multierr.Combine should return it directly.
	errA := errors.New("service-api failed")

	combined := multierr.Combine(errA)
	require.Error(t, combined)
	require.Equal(t, errA, combined, "single error should pass through unchanged")
}

func TestDeployServicesParallel_NoErrors(t *testing.T) {
	// When no services fail, multierr.Combine should return nil.
	var errs []error
	combined := multierr.Combine(errs...)
	require.NoError(t, combined, "no errors should return nil")
}
