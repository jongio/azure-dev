// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package azapi

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_isBuildFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		err    error
		expect bool
	}{
		{"nil error", nil, false},
		{"unrelated error", errors.New("connection refused"), false},
		{"transient build failure", errors.New("the build process failed"), true},
		{"transient build failure wrapped", errors.New("deploy error: the build process failed with exit code 1"), true},
		{"real build failure with logs", errors.New("the build process failed, check logs for more info"), false},
		{"genuine build failure from status API",
			errors.New("Deployment failed because the build process failed\n"), false},
		{"partial match", errors.New("build process"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expect, isBuildFailure(tt.err))
		})
	}
}

// mockScmChecker is a mock implementation of scmReadyChecker for testing.
type mockScmChecker struct {
	calls atomic.Int32
	fn    func(ctx context.Context, call int) (bool, error)
}

func (m *mockScmChecker) IsScmReady(ctx context.Context) (bool, error) {
	call := int(m.calls.Add(1))
	return m.fn(ctx, call)
}

func Test_waitForScmReady_ImmediateSuccess(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	mock := &mockScmChecker{fn: func(_ context.Context, _ int) (bool, error) {
		return true, nil
	}}

	var logs []string
	err := waitForScmReady(ctx, mock, func(msg string) { logs = append(logs, msg) })

	require.NoError(t, err)
	require.Equal(t, int32(1), mock.calls.Load())
	require.Contains(t, logs, "SCM site is ready")
}

func Test_waitForScmReady_ContextCanceled(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())

	mock := &mockScmChecker{fn: func(_ context.Context, _ int) (bool, error) {
		return false, context.Canceled
	}}

	cancel() // cancel before calling
	err := waitForScmReady(ctx, mock, func(string) {})

	require.Error(t, err)
	require.ErrorIs(t, err, context.Canceled)
}

func Test_waitForScmReady_TransientErrorsThenSuccess(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	mock := &mockScmChecker{fn: func(_ context.Context, call int) (bool, error) {
		if call < 3 {
			return false, errors.New("transient error")
		}
		return true, nil
	}}

	err := waitForScmReady(ctx, mock, func(string) {})

	require.NoError(t, err)
	require.GreaterOrEqual(t, int(mock.calls.Load()), 3)
}

func Test_waitForScmReady_ContextDeadlineExceeded(t *testing.T) {
	t.Parallel()

	mock := &mockScmChecker{fn: func(_ context.Context, _ int) (bool, error) {
		return false, context.DeadlineExceeded
	}}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := waitForScmReady(ctx, mock, func(string) {})

	require.Error(t, err)
}
