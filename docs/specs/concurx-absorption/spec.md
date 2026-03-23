# Spec: Absorb Concurx Features into azd Core

## Goal

Merge ALL unique concurx extension capabilities into azd's native parallel-provisioning-and-deployment feature set so that the concurx extension can be retired. Users get a single `azd up` with all optimizations built-in.

## Background

The `concurx` extension (`azd concurx up`) provides parallel deployment with Aspire build coordination, per-service logging, process isolation, and a real-time TUI. azd core already has 11 alpha features for parallelism (`deploy.parallel`, `up.concurrent`, `provision.parallel`, etc.). Both overlap significantly but each has gaps the other fills.

## Gap Analysis

### GAP 1: Aspire Build Gate Coordination (CRITICAL)

**Concurx**: `buildGate` struct (concurrent_deployer.go:226-294) — first Aspire service claims the gate via `ClaimFirstAspire()`, runs its deploy (which builds the AppHost manifest), then calls `Open()` to release a channel that other Aspire services `Wait()` on. If the first service fails, `Fail()` propagates the error. Uses `sync.Once` + channels for thread-safe coordination.

**azd core**: `deployServicesParallel()` (deploy.go:361-392) fires ALL services simultaneously via `errgroup.Go()`. No Aspire awareness. If two Aspire services both try to build the AppHost manifest concurrently, they race and one may fail.

**Why this matters**: Every .NET Aspire project with 2+ services needs this. Without it, parallel deploy of Aspire projects is broken.

### GAP 2: Graceful Partial Failure (HIGH)

**Concurx**: Each service runs as a separate goroutine with independent error handling. If service A fails, services B/C/D continue to completion. Errors collected in `errChan` and reported in final summary.

**azd core**: Uses `errgroup.WithContext()` — first error cancels ALL pending goroutines via `gCtx`. If service A fails, B/C/D are aborted even if they were 90% done.

**Why this matters**: In a 10-service project, one flaky service shouldn't kill the other 9 deployments.

### GAP 3: Per-Service Isolated Log Files (MEDIUM)

**Concurx**: Creates `.azure/logs/deploy/{timestamp}/deploy-{serviceName}.log` per service plus `provision.log` for provisioning.

**azd core**: All output goes through `input.Console` to a single stdout/stderr stream. No per-service log files. In parallel deploy, outputs from different services are interleaved.

**Why this matters**: When parallel deploy fails, users can't tell which service produced which error.

### GAP 4: Real-Time Deployment Progress TUI (LOW / NICE-TO-HAVE)

**Concurx**: Full Bubble Tea TUI (deployment_model.go, 748 lines) with per-service status grid, tab-based log viewer, keyboard navigation, and modal prompt overlay.

**azd core**: Sequential spinners via `console.ShowSpinner()`. In parallel mode, multiple spinners conflict.

**Recommendation**: Defer full TUI. Focus on correctness (gaps 1-3) first. A lightweight ANSI progress table is sufficient.

### NOT Being Absorbed

| Feature | Reason |
|---|---|
| Full Bubble Tea TUI (748 lines) | Overkill; lightweight table sufficient |
| HTTP Prompt Server (488 lines) | Artifact of subprocess model; not needed in-process |
| Prompt Model UI (506 lines) | Same — subprocess artifact |
| Subprocess architecture | Goroutine model is faster + lower overhead |

## Features Already Covered by azd Core

| Concurx Feature | azd Equivalent | Status |
|---|---|---|
| Parallel service deploy | `deploy.parallel` | Exists |
| Concurrent provision + package | `up.concurrent` | Exists |
| Parallel infra layers | `provision.parallel` | Exists |
| Parallel Docker builds | `deploy.parallelBuild` | Exists |
| Parallel service init | `deploy.parallelInit` | Exists |
| Concurrency limit | `AZD_DEPLOY_CONCURRENCY` env var | Exists |

## azd Core Advantages Over Concurx

| Aspect | azd Core | Concurx |
|---|---|---|
| Overhead | Goroutines (KB) | OS processes (MB each, full binary reload) |
| Auth sharing | Single auth token, shared | N separate auth flows |
| Config parsing | Parsed once | Parsed N times (once per subprocess) |
| Build parallelism | `deploy.parallelBuild` — CPU-core limited errgroup | None |
| Provision parallelism | `provision.parallel` — dependency-aware phasing | Sequential subprocess |
| Caching | localCache + bicepCache + skipRepeatValidation | None |
| Smart deploy | `deploy.smartApi` (direct revision API) | None |
| Run from package | `deploy.runFromPackage` for App Service | None |
| Package + Provision overlap | `up.concurrent` runs both in parallel | Sequential |

## New Alpha Features

| Feature | Alpha Key | Priority |
|---|---|---|
| Aspire build gate | `deploy.aspireGate` | CRITICAL |
| Continue on error | `deploy.continueOnError` | HIGH |
| Per-service log files | `deploy.serviceLogs` | MEDIUM |
| Progress table | `deploy.progressTable` | LOW |

## Architecture: Before vs After

### Current (deploy.parallel):
```
azd deploy --all
  errgroup.WithContext(ctx)
    goroutine: deploySingleService(svcA) -> Package -> Publish -> Deploy
    goroutine: deploySingleService(svcB) -> Package -> Publish -> Deploy
    goroutine: deploySingleService(svcC) -> Package -> Publish -> Deploy
  First error -> gCtx.Cancel() -> ALL stop
```

### Proposed (with all new features):
```
azd deploy --all [deploy.parallel + deploy.aspireGate + deploy.continueOnError]
  WaitGroup + buildGate
    non-aspire: goroutine: deploySingleService(svcA) -> Package -> Publish -> Deploy
    aspire[0]:  goroutine: deploySingleService(svcB) -> Package -> gate.Open() -> Publish -> Deploy
    aspire[1]:  goroutine: gate.Wait() -> deploySingleService(svcC) -> ...
    aspire[2]:  goroutine: gate.Wait() -> deploySingleService(svcD) -> ...
  Service failure -> log error, continue others -> report all at end
  Per-service logs in .azure/{env}/logs/deploy-{timestamp}/
```
