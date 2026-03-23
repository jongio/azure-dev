# Tasks: Absorb Concurx Features into azd Core

<!-- NEXT: 1 -->

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
- Add `deploy.aspireGate`, `deploy.continueOnError`, `deploy.serviceLogs` to comparison-sweep.yml
- Test Aspire templates with all alphas enabled
- Verify azd+alphas >= concurx performance

**Files**:
- `azd-perf/.github/workflows/comparison-sweep.yml`

### 6. Deprecate Concurx Extension

**Priority**: P3
**Depends on**: Task 5

Mark concurx as deprecated, document migration to alpha features.

**Implementation**:
- Add deprecation notice to concurx README
- Log deprecation warning on invocation
- Document migration path: which alpha features replace each concurx capability

## IN PROGRESS

(none)

## DONE

(none)
