// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package cmd

import (
	"context"
	"fmt"
	"sync"
)

// aspireBuildGate coordinates parallel deployment of Aspire services. In an Aspire project,
// the first service to deploy must complete its Package phase (which generates the AppHost
// manifest) before other Aspire services can proceed. Without this gate, parallel Aspire
// service deployments race on manifest generation and fail.
//
// Ported from the concurx extension's buildGate pattern (concurrent_deployer.go:226-294).
type aspireBuildGate struct {
	claimed   bool
	claimedMu sync.Mutex
	openOnce  sync.Once
	failOnce  sync.Once
	readyCh   chan struct{}
	failCh    chan struct{}
	errMu     sync.Mutex
	err       error
}

func newAspireBuildGate() *aspireBuildGate {
	return &aspireBuildGate{
		readyCh: make(chan struct{}),
		failCh:  make(chan struct{}),
	}
}

// ClaimFirst attempts to claim the first-to-deploy slot. Only the first caller gets true;
// that service deploys immediately while others wait on the gate.
func (g *aspireBuildGate) ClaimFirst() bool {
	g.claimedMu.Lock()
	defer g.claimedMu.Unlock()

	if !g.claimed {
		g.claimed = true
		return true
	}
	return false
}

// Open releases all waiting services. Called after the first Aspire service's Package phase
// completes successfully, meaning the manifest is available.
func (g *aspireBuildGate) Open() {
	g.openOnce.Do(func() {
		close(g.readyCh)
	})
}

// Fail marks the gate as failed and unblocks all waiters with the given error.
// Called when the first Aspire service's Package phase fails.
func (g *aspireBuildGate) Fail(err error) {
	g.failOnce.Do(func() {
		g.errMu.Lock()
		g.err = err
		g.errMu.Unlock()
		close(g.failCh)
	})
}

// Wait blocks until the gate opens (success), fails, or the context is canceled.
func (g *aspireBuildGate) Wait(ctx context.Context) error {
	select {
	case <-g.readyCh:
		return nil
	case <-g.failCh:
		g.errMu.Lock()
		defer g.errMu.Unlock()
		if g.err != nil {
			return fmt.Errorf("aspire build gate failed: %w", g.err)
		}
		return fmt.Errorf("aspire build gate failed")
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Note: Aspire services are detected in deploy.go by checking
// svc.DotNetContainerApp != nil on *project.ServiceConfig.
