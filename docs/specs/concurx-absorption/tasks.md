# Tasks: Absorb Concurx Features into azd Core

<!-- ALL TASKS COMPLETE -->

## TODO

### 1. deploy.aspireGate — Aspire Build Gate for Parallel Deploy

**Priority**: P0 (CRITICAL)
**Alpha feature**: `deploy.aspireGate`

Port `buildGate` struct from concurx into azd core deploy path.

**Implementation**:
- Add `buildGate` struct to `cli/azd/internal/cmd/deploy.go` (or new `deploy_gate.go`)
- In `deployServicesParallel()`: classify services as aspire vs non-aspire
- Aspire detection: `svc.DotNetContainerApp != nil`
- Non-Aspire services: launch immediately (no change)
- First Aspire service: `ClaimFirstAspire()` = true, launch immediately
- Remaining Aspire services: `gate.Wait(ctx)` before `deploySingleService()`
- After first Aspire service's Package phase completes: `gate.Open()`
- If Package fails: `gate.Fail(err)`
- Add alpha feature definition to `cli/azd/resources/alpha_features.yaml`
- Add tests

**Files**:
- `cli/azd/internal/cmd/deploy.go`
- `cli/azd/resources/alpha_features.yaml`

### 2. deploy.continueOnError — Graceful Partial Failure

**Priority**: P1 (HIGH)
**Alpha feature**: `deploy.continueOnError`
**Depends on**: Task 1

Replace errgroup cancel-on-first-error with collect-all-errors pattern.

**Implementation**:
- When `deploy.continueOnError` enabled, use `sync.WaitGroup` + error slice instead of `errgroup`
- Service failures logged but don't cancel other goroutines
- Respect `AZD_DEPLOY_CONCURRENCY` via semaphore channel
- Report ALL errors in final summary with per-service attribution
- Context cancellation (Ctrl+C) still stops everything — only service failures are isolated
- Add alpha feature definition
- Add tests

**Files**:
- `cli/azd/internal/cmd/deploy.go`
- `cli/azd/resources/alpha_features.yaml`

### 3. deploy.serviceLogs — Per-Service Log Files

**Priority**: P2 (MEDIUM)
**Alpha feature**: `deploy.serviceLogs`
**Depends on**: Task 1

Create per-service log files during parallel deployment.

**Implementation**:
- When enabled + parallel deploy active: create `.azure/{env}/logs/deploy-{timestamp}/`
- Per service: create `{serviceName}.log` file
- In `deploySingleService()`: tee progress messages to both console AND log file
- Log all Package/Publish/Deploy phases with timestamps
- Log errors with full details
- After all services complete: print log directory path
- Add alpha feature definition
- Add tests

**Files**:
- `cli/azd/internal/cmd/deploy.go`
- `cli/azd/resources/alpha_features.yaml`

### 4. deploy.progressTable — Enhanced Parallel Console Output

**Priority**: P3 (LOW)
**Alpha feature**: `deploy.progressTable`
**Depends on**: Task 3

Replace conflicting spinners with ANSI status table.

**Implementation**:
- Show per-service status/phase/elapsed time in a table
- Update in-place using ANSI cursor control
- Non-interactive mode (CI): fall back to line-per-event output
- Lightweight — no Bubble Tea dependency

**Files**:
- `cli/azd/internal/cmd/deploy.go`
- `cli/azd/resources/alpha_features.yaml`

### 5. azd-perf — Update Alpha Feature List

**Priority**: P2
**Depends on**: Tasks 1, 2, 3

Update azd-perf benchmarking to test new alpha features.

**Implementation**:
- Add `deploy.aspireGate`, `deploy.continueOnError`, `deploy.serviceLogs`, `deploy.progressTable` to comparison-sweep.yml
- Test Aspire templates with all alphas enabled
- Verify azd+alphas >= concurx performance

**Files**:
- `azd-perf/.github/workflows/comparison-sweep.yml`

## IN PROGRESS

(none)

## DONE

### ✅ Task 1: deploy.aspireGate — IMPLEMENTED
- `cli/azd/internal/cmd/deploy_gate.go` — aspireBuildGate struct (ClaimFirst/Open/Fail/Wait)
- `cli/azd/internal/cmd/deploy_gate_test.go` — 10 unit tests, all pass
- `cli/azd/internal/cmd/deploy.go` — Enhanced deployServicesParallel with gate support
- `cli/azd/resources/alpha_features.yaml` — Feature definition added

### ✅ Task 2: deploy.continueOnError — IMPLEMENTED
- `cli/azd/internal/cmd/deploy.go` — deployParallelContinueOnError method (WaitGroup + error slice)
- `cli/azd/resources/alpha_features.yaml` — Feature definition added

### ✅ Task 3: deploy.serviceLogs — IMPLEMENTED
- `cli/azd/internal/cmd/deploy.go` — createServiceLogWriter + log directory creation
- `cli/azd/resources/alpha_features.yaml` — Feature definition added
- Logs written to `.azure/{env}/logs/deploy-{timestamp}/{service}.log`

### ✅ Task 4: deploy.progressTable — IMPLEMENTED
- `cli/azd/internal/cmd/deploy_progress.go` — deployProgressTracker (ANSI table + CI fallback)
- `cli/azd/internal/cmd/deploy_progress_test.go` — 11 unit tests, all pass
- `cli/azd/internal/cmd/deploy.go` — Wired into both FailFast and ContinueOnError paths
- `cli/azd/resources/alpha_features.yaml` — Feature definition added

### ✅ Task 5: azd-perf — Alpha Feature List Updated
- `azd-perf/.github/workflows/comparison-sweep.yml` — Added 4 new features to default list
- Total alpha features in sweep: 15 (was 11)
