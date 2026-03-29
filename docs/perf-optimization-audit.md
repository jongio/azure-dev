# Performance Optimization: Alpha Features Audit & Opportunities

> **Date**: 2026-03-29
> **Branch**: `perf/parallel-provisioning-and-deployment`
> **Context**: The `azd-perf` profile runs the `perf-canonical-full` template (2 Container Apps,
> Cosmos DB, Key Vault, Storage, ACR, monitoring) with 15 alpha features enabled.
> Current delta vs `azd-stable` is only **~40-60s** (~554s → ~514s).
> This document audits each feature and identifies the highest-impact opportunities.

---

## Benchmark Data (recent canonical runs)

| Profile | Total | Provision | Deploy | Cleanup | Notes |
|---|---|---|---|---|---|
| **azd-stable** | ~554-609s | ~449-521s | 0* | ~21-34s | Baseline |
| **azd-perf** | ~514-550s | ~477-559s | 0* | ~7s | All 15 alpha features |

\*Deploy shows as 0 because `azd up` is measured as a single operation — deploy time is folded
into provision. The runner sets `ProvisionMs = totalUpMs` and `DeployMs = 0`.

**Key observation**: Provision is actually **slower** in azd-perf (~490s vs ~449s). The net
savings come almost entirely from faster cleanup via deployment stacks (~15-25s).

---

## Alpha Feature Audit

### ✅ Working & Effective

| Feature | Location | What It Does | Impact |
|---|---|---|---|
| `deployment.stacks` | `resources/alpha_features.yaml`, `cmd/container.go:724-756`, `pkg/azapi/stack_deployments.go` | Uses ARM deployment stacks instead of standard deployments. Stack delete is faster than void-state + RG delete. | **~15-25s saved** on cleanup |
| `deploy.parallel` | `internal/cmd/deploy.go:278-424` | Runs each service's deploy lifecycle (package → publish → deploy) in parallel via errgroup. | Helps with 2+ services |
| `up.concurrent` | `cmd/up.go:172-225` | Overlaps `package --all` and `provision` concurrently, then runs `deploy --all` after both complete. | Saves package time (~few seconds) |
| `deploy.smartApi` | `pkg/project/service_target_containerapp.go:281-520` | For container app services, if infra template hash is unchanged, skips full ARM deployment and uses direct revision API (`AddRevision`/`UpdateContainerAppJobImage`). | **Big win for repeat deploys** |
| `provision.bicepCache` | `pkg/tools/bicep/bicep.go:296-408` | In-memory Bicep compilation cache keyed by file content + referenced modules. Skips repeat `bicep build` within the same process. | Saves ~1-3s per compile |
| `provision.localCache` | `pkg/infra/provisioning/bicep/deployment_cache.go:20-232` | On-disk cache under `.azure/{env}/deployment-cache-{layer}.json`. If template hash + parameter hash match, skips Azure API state lookup entirely. | **Significant for repeat runs** |
| `provision.skipRepeatValidation` | `pkg/infra/provisioning/bicep/bicep_provider.go:822-839` | Skips ARM preflight validation when template + parameter hashes match the last successful deployment. | Saves ~5-15s on repeat runs |
| `provision.adaptivePolling` | `pkg/infra/provisioning/bicep/bicep_provider.go:128-184, 889-933` | Changes progress UI polling from fixed 3s to adaptive (1s → 2s → 4s → 8s → 10s cap, resets on state change). Backs off on 429 throttling. | **UI responsiveness only** — does not affect ARM LRO poll frequency |
| `deploy.parallelInit` | `pkg/project/project_manager.go:101-140` | Initializes service framework/target components in parallel via errgroup. | Small (~1-2s) |
| `provision.parallel` | `internal/cmd/provision.go:314-347, 479-609` | Parallelizes independent Bicep layers using `bicep.AnalyzeLayerDependencies`. Runs independent layers concurrently, merges outputs between phases. | **Only helps with multiple layers** — single-layer templates get no benefit |

### ⚠️ Dead Code / Not Wired

| Feature | Location | Issue |
|---|---|---|
| `deploy.parallelBuild` | `pkg/project/service_manager.go:819-871` | `PackageAll()` is implemented with `runtime.NumCPU()` concurrency cap, but **no production call site exists**. `deploy.go` calls `deploySingleService()` per service which packages sequentially inside each goroutine. Container builds are **not** actually parallelized. |

### ❌ Not Implemented

| Feature | Evidence |
|---|---|
| `provision.smartApi` | No code references found. No feature gate, no implementation. |
| `deploy.caching` | No code references found. Related always-on caching exists (service operation cache, Bicep compile cache, deployment cache) but not under this flag. |
| `provision.caching` | No code references found. Same as above. |
| `azd.strategy` | Not feature-gated. The underlying deployment strategy logic (`pkg/infra/deployment_manager.go:80-150`) is always-on, matching deployments by tags/names. Not an alpha feature. |

---

## Canonical Template Dependency Graph

The `perf-canonical-full` template (`templates/canonical/azd/v1`) provisions:

```
                    ┌─────────────┐
                    │  monitoring  │
                    └──────┬──────┘
                           │
                  ┌────────▼─────────┐
                  │ containerAppsStack│  (ACR + CA Environment)
                  └────────┬─────────┘
                           │
            ┌──────────────┴──────────────┐
            │                             │
     ┌──────▼──────┐              ┌───────▼───────┐
     │ webIdentity │              │  apiIdentity  │
     └──────┬──────┘              └───┬───┬───┬───┘
            │                        │   │   │
            │                   ┌────┘   │   └────┐
            │                   │        │        │
            │            ┌──────▼──┐ ┌───▼────┐ ┌─▼────────────┐
            │            │keyVault │ │ cosmos │ │storageAccount│
            │            └──────┬──┘ └───┬────┘ └─┬────────────┘
            │                   │        │        │
     ┌──────▼──────┐     ┌─────▼────────▼────────▼┐
     │     web     │     │          api            │  ← most constrained
     └─────────────┘     └─────────────────────────┘
```

**Critical path**: `monitoring` → `containerAppsStack` → `apiIdentity` → `cosmos`/`keyVault`/`storage` → `api`

The `web` service can start much earlier than `api`. This asymmetry is an optimization target.

---

## Optimization Opportunities (Ranked by Impact)

### 1. True Provision + Deploy Overlap (~60-120s potential)

**Problem**: `up.concurrent` only overlaps package + provision. Deploy waits until ALL
provision completes. But `web`'s infra is ready long before `api`'s infra finishes (cosmos
and storage are slow).

**Opportunity**: Start deploying (remote build + revision update) for services whose infra
is ready, while other services' infra is still provisioning.

**Implementation sketch**:
- In `up.go`, after provision emits per-resource completion events, trigger deploy for
  services whose dependencies are satisfied.
- Or: in `provision.go`, expose a channel/callback per service when its resources are ready.
- Deploy `web` as soon as `containerAppsStack` + `webIdentity` complete (~60% through provision).

**Files**: `cmd/up.go`, `internal/cmd/provision.go`, `internal/cmd/deploy.go`

### 2. Wire Up Parallel Container Builds (~30-60s potential)

**Problem**: `deploy.parallelBuild` is implemented in `PackageAll()` but never called.
Both `web` and `api` use `remoteBuild: true` — their ACR builds currently happen
sequentially inside `deploySingleService()`.

**Opportunity**: Call `PackageAll()` from the parallel deploy path, or restructure
`deploySingleService()` to separate packaging from publishing.

**Implementation sketch**:
- In `deploy.go`'s parallel deploy orchestration, run `PackageAll()` first (parallel), then
  run `deploySingleService()` with `--from-package` (skipping the package step).
- Or: refactor `deploySingleService()` to accept pre-packaged artifacts.

**Files**: `internal/cmd/deploy.go`, `pkg/project/service_manager.go`

### 3. Early Remote Build Start (~30-60s potential)

**Problem**: Remote container builds don't start until after provision completes. ACR builds
take ~30-60s and could overlap with the tail end of provisioning.

**Opportunity**: Since `up.concurrent` already overlaps package + provision, extend it to
start remote builds (upload context + trigger ACR build) during provision.

**Implementation sketch**:
- `up.concurrent` currently does: `package || provision` → `deploy`
- Change to: `(package → start remote builds) || provision` → `deploy (just update revisions)`
- This requires separating "build image" from "deploy revision" in the container app target.

**Files**: `cmd/up.go`, `pkg/project/container_helper.go`, `pkg/project/service_target_containerapp.go`

### 4. Implement `provision.smartApi` (~30-60s potential)

**Problem**: Feature is listed but has no code. Every `azd up` runs a full ARM deployment
even when only container images changed.

**Opportunity**: Detect when Bicep template + parameters are unchanged from the last
successful deployment, and skip the entire ARM deployment. Use cached outputs instead.

**Implementation sketch**:
- In `BicepProvider.Deploy()`, after computing template/parameter hashes:
  - If hashes match AND `provision.smartApi` is enabled, return cached outputs immediately.
  - This is an extension of `provision.localCache` but skips the deployment entirely
    (localCache still calls Azure to check deployment state).

**Files**: `pkg/infra/provisioning/bicep/bicep_provider.go`, `pkg/infra/provisioning/bicep/deployment_cache.go`

### 5. Reduce Template Serial Dependencies (~20-40s potential)

**Problem**: The `api` container app depends on cosmos, keyVault, storage, identities, AND
containerAppsStack. This creates a long serial chain.

**Opportunity**: Move non-critical connection info (cosmos connection string, storage keys)
to post-deploy configuration (e.g., Dapr components, app settings update) instead of Bicep
parameters. This lets the `api` container app deploy with a placeholder and get configured
after.

**Implementation**: Template-level change in `templates/canonical/azd/v1/infra/resources.bicep`.

### 6. ARM LRO Poll Tuning (small, ~5-10s)

**Problem**: ARM deployment long-running operation polling is fixed at 2s intervals.

**Opportunity**: Use adaptive polling for the ARM LRO itself (not just the progress UI).
Start at 1s, back off to 5-10s as the deployment progresses.

**Files**: `pkg/azapi/standard_deployments.go`, `pkg/azapi/stack_deployments.go`

---

## Quick Wins (Low Effort, Moderate Impact)

1. **Wire `deploy.parallelBuild`**: Add a call to `PackageAll()` in the deploy path (~2h effort)
2. **Fix timing instrumentation**: Split `azd up` measurement into provision + deploy in the
   perf runner so we can see where time actually goes (~1h effort)
3. **Remove dead feature flags**: Clean up `provision.smartApi`, `deploy.caching`,
   `provision.caching`, `azd.strategy` from the entrypoint alpha list — they add config noise
   with zero benefit (~30min effort)

---

## Summary

The ~40-60s improvement from 15 alpha features is disappointing because:
- **3 features have no implementation** (provision.smartApi, deploy.caching, provision.caching)
- **1 feature is dead code** (deploy.parallelBuild)
- **Several features only help on repeat runs** (localCache, skipRepeatValidation, smartApi)
- **Provision is slower**, suggesting parallel orchestration overhead without enough parallelizable work
- **The real bottleneck is ARM provisioning** (~490s), which no local optimization can reduce

The biggest opportunity is **architectural**: overlap provision and deploy so container builds
and service deployments start as soon as their individual infra dependencies are ready, rather
than waiting for the entire provision to complete.
