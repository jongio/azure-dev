# Security Audit: perf/parallel-provisioning-and-deployment

**Date**: 2025-07-25
**Branch**: `perf/parallel-provisioning-and-deployment` vs `upstream/main`
**Scope**: 252 files changed, +7801/-1307 lines
**Auditor**: SecOps Agent (adversarial review)
**Go Version**: 1.26 (loop variable capture NOT a bug)

---

## Executive Summary

The branch adds parallel provisioning/deployment, local deployment caching, Bicep
compilation caching, pprof profiling, HTTP transport tuning, and adaptive ARM polling.
All new features are gated behind alpha feature flags (opt-in only).

**No CRITICAL or HIGH findings.** The code demonstrates strong security awareness:
file permissions set to 0600, atomic writes for cache files, mutex-guarded concurrent
access, hidden profile flags, and existing security tests for concurrency invariants.

6 findings total: 0 CRITICAL, 0 HIGH, 2 MEDIUM, 4 LOW.

---

## STRIDE Threat Model

| Component | S | T | I | R | E | D | Notes |
|-----------|---|---|---|---|---|---|-------|
| Deployment Cache | - | LOW | LOW | - | - | - | Plaintext secrets at rest; path from azure.yaml |
| Bicep Build Cache | - | - | - | - | - | LOW | Unbounded in-memory cache |
| Parallel Provisioning | - | - | - | - | - | - | syncEnvManager + env cloning verified safe |
| Parallel Deployment | - | - | - | - | - | - | Mutex-guarded result map, errgroup cancellation |
| pprof Profiling | - | LOW | - | - | - | - | User-supplied file path, hidden flag |
| CI bench.yml | - | MED | - | - | - | - | Mutable action tags, unpinned tooling |
| HTTP Transport Tuning | - | - | - | - | - | - | Standard Go stdlib tuning, no security impact |
| Adaptive Polling | - | - | - | - | - | - | Backoff logic only, no auth/data changes |
| Concurrent Workflow | - | - | - | - | - | - | De-dup guard on executingCommands prevents races |

**Legend**: S=Spoofing, T=Tampering, I=Info Disclosure, R=Repudiation, E=Elevation, D=DoS

---

## OWASP Top 10 (2021) Coverage Matrix

| # | Category | Status | Finding |
|---|----------|--------|---------|
| A01 | Broken Access Control | PASS | Profile flags are hidden; cache in user-owned dir |
| A02 | Cryptographic Failures | PASS (with note) | F03: cache outputs in plaintext |
| A03 | Injection | PASS (with note) | F04: layer name unsanitized in path |
| A04 | Insecure Design | PASS | Alpha-gated, atomic writes, mutex guards |
| A05 | Security Misconfiguration | PASS (with note) | F05: unbounded cache |
| A06 | Vulnerable Components | PASS (with note) | F01/F02: CI action pinning |
| A07 | Auth Failures | PASS | No auth changes in diff |
| A08 | Software/Data Integrity | PASS (with note) | F01/F02: supply chain |
| A09 | Logging/Monitoring | PASS | logDS calls for cache hits/misses |
| A10 | SSRF | N/A | No outbound URL construction from user input |

---

## Findings

### F01 [MEDIUM] CI Workflow Actions Pinned to Mutable Tags

- **CWE**: CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
- **CVSS**: 6.5
- **STRIDE**: Tampering
- **OWASP**: A08:2021 Software and Data Integrity Failures
- **Classification**: [INFORM]
- **File**: `.github/workflows/bench.yml` lines 29, 31, 40, 88

**Description**: Four GitHub Actions are pinned to mutable version tags (`@v4`, `@v6`,
`@v7`) instead of immutable SHA hashes:

```yaml
- uses: actions/checkout@v4          # TODO(security): pin to SHA
- uses: actions/setup-go@v6          # TODO(security): pin to SHA
- uses: actions/cache@v4             # TODO(security): pin to SHA
- uses: actions/github-script@v7     # TODO(security): pin to SHA
```

The TODO comments indicate awareness. A compromised or force-pushed tag would execute
arbitrary code in the CI environment with `pull-requests: write` permission.

**Remediation**: Pin all actions to full commit SHAs. Example:
```yaml
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
```

---

### F02 [MEDIUM] benchstat Installed at @latest Without Hash Pinning

- **CWE**: CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
- **CVSS**: 5.3
- **STRIDE**: Tampering
- **OWASP**: A08:2021 Software and Data Integrity Failures
- **Classification**: [INFORM]
- **File**: `.github/workflows/bench.yml` line 36

**Description**: `go install golang.org/x/perf/cmd/benchstat@latest` fetches the
latest module version at workflow runtime. A compromised module or supply chain attack
on golang.org/x/perf could inject arbitrary code into CI.

**Remediation**: Pin to a specific version with hash verification:
```yaml
run: go install golang.org/x/perf/cmd/benchstat@v0.0.0-20250603012028-06a1d2a45d01
```

---

### F03 [LOW] Deployment Cache Stores ARM Outputs in Plaintext JSON

- **CWE**: CWE-312 (Cleartext Storage of Sensitive Information)
- **CVSS**: 3.9
- **STRIDE**: Information Disclosure
- **OWASP**: A02:2021 Cryptographic Failures
- **Classification**: [PROPOSE]
- **File**: `cli/azd/pkg/infra/provisioning/bicep/deployment_cache.go`

**Description**: ARM deployment outputs (which may include connection strings, storage
account keys, and other secrets) are cached in plaintext JSON files at
`{project}/.azure/{env}/deployment-cache-{layer}.json`.

**Mitigating factors** (the code already handles this responsibly):
1. Files written with `0600` permissions (owner read/write only)
2. Directory created with `0700` permissions
3. Atomic write pattern (temp file + rename) prevents partial reads
4. Feature is alpha-gated (`provision.localCache`)
5. Cache stored in `.azure/` which is typically `.gitignore`d
6. SecurityNote comments document the risk explicitly (lines 39-42, 87-89)
7. Existing tests verify `0600` file permissions and `0700` directory permissions

**Residual risk**: On shared workstations or if `.azure/` is accidentally committed,
secrets are exposed in plaintext. The code's own SecurityNote acknowledges this and
recommends encryption in a future release.

**Recommendation**: Before GA, encrypt sensitive output values at rest (e.g., DPAPI on
Windows, keychain on macOS, or a user-scoped symmetric key). For alpha, the current
approach with `0600` permissions and explicit documentation is acceptable.

---

### F04 [LOW] Layer Name from azure.yaml Not Sanitized Before Filesystem Path

- **CWE**: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)
- **CVSS**: 2.5
- **STRIDE**: Tampering
- **OWASP**: A03:2021 Injection
- **Classification**: [INFORM]
- **File**: `cli/azd/pkg/infra/provisioning/bicep/deployment_cache.go` lines 50-53

**Description**: The `layerCacheKey()` returns `p.layer` (set from
`infraOptions.Name`, which is the `name:` field in `azure.yaml`) directly into a
`filepath.Join` path component:

```go
func (p *BicepProvider) deploymentCachePath() string {
    filename := fmt.Sprintf("deployment-cache-%s.json", p.layerCacheKey())
    return filepath.Join(p.projectPath, ".azure", p.env.Name(), filename)
}
```

**Mitigating factors**:
1. `filepath.Join` normalizes path separators and removes `..` path elements when
   they're in the middle of a path, but does NOT prevent traversal in a filename
   component like `../../etc/cron.d/evil`
2. However, the layer name comes from `azure.yaml` which is a developer-controlled
   local file -- the attacker and the victim are the same person
3. Environment names are validated by `EnvironmentNameRegexp` (`^[a-zA-Z0-9-\(\)_\.]{1,64}$`)
   but layer names have no equivalent validation

**Recommendation**: Add a `filepath.Base()` call or regex validation on `p.layer`
before use in the filename. This is defense-in-depth since the input is from
developer-controlled YAML:

```go
func (p *BicepProvider) layerCacheKey() string {
    if p.layer == "" {
        return "main"
    }
    return filepath.Base(p.layer)
}
```

---

### F05 [LOW] Bicep Build Cache (sync.Map) Has No Size Bound

- **CWE**: CWE-400 (Uncontrolled Resource Consumption)
- **CVSS**: 2.0
- **STRIDE**: Denial of Service
- **OWASP**: A05:2021 Security Misconfiguration
- **Classification**: [INFORM]
- **File**: `cli/azd/pkg/tools/bicep/bicep.go` line 56

**Description**: The `buildCache sync.Map` stores compiled ARM template results
(potentially large JSON blobs) keyed by content hash. There is no eviction policy
or size limit.

**Mitigating factors**:
1. The cache is per-process and lives only for the duration of a single `azd` run
2. Behind the `provision.bicepCache` alpha feature flag
3. In practice, a project has a small number of Bicep files (typically 1-10)
4. Each entry is the compiled ARM JSON which is already in memory anyway

**Recommendation**: Acceptable for alpha. Before GA, consider an LRU cache with a
configurable max entry count or total byte limit.

---

### F06 [LOW] pprof Profile Flags Accept User-Supplied Path

- **CWE**: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)
- **CVSS**: 2.0
- **STRIDE**: Tampering
- **OWASP**: A01:2021 Broken Access Control
- **Classification**: [INFORM]
- **File**: `cli/azd/cmd/root.go` lines 152-155, 177-180

**Description**: The `--cpu-profile` and `--mem-profile` flags accept arbitrary file
paths and create/overwrite them with `os.OpenFile(..., os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)`.
A user could point these to overwrite arbitrary files they have write access to.

**Mitigating factors**:
1. Both flags are **hidden** (`MarkHidden` in `auto_install.go` lines 638, 641)
2. Test coverage verifies hidden status (`auto_install_test.go` lines 569-575)
3. Files are created with `0600` permissions
4. This is a developer-only diagnostic feature -- the user is running their own CLI
5. The "attacker" must be the local user who is already running `azd`
6. This matches the standard pattern used by `go test -cpuprofile` and `go tool pprof`

**Recommendation**: Acceptable as-is. The threat model for a CLI diagnostic flag is
that the user controls their own machine.

---

## Verified Safe Areas

### Concurrency (sync.Map, mutex, errgroup)

**PASS**: The concurrency model is well-designed:

1. **syncEnvManager**: Wraps `environment.Manager` with a `sync.Mutex` around `Save` and
   `SaveWithOptions`. Tests in `provision_security_test.go` verify serialization with
   50 concurrent goroutines and assert `maxConcur == 1`.

2. **syncConsole**: Wraps `input.Console` write-path methods with a mutex. All output
   methods (Message, MessageUxItem, ShowSpinner, StopSpinner, WarnForFeature, EnsureBlankLine)
   are synchronized.

3. **Environment cloning**: `environment.NewWithValues(p.env.Name(), p.env.Dotenv())` is safe
   because `Dotenv()` returns `maps.Clone(e.dotenv)`. Tests verify clone independence and
   concurrent writes to clones do not race.

4. **errgroup cancellation**: Both parallel provisioning and deployment use `errgroup.WithContext`
   which propagates cancellation from the first error.

5. **Result map**: `deployResults` map writes protected by `sync.Mutex` (parallel deploy) or
   pre-allocated slice indexed by goroutine index (parallel provision).

6. **rgExistsCache**: Uses `sync.Map` for concurrent resource group existence caching.

7. **FindAndExecute**: Guards against concurrent execution of the same cobra subcommand
   via `executingCommands sync.Map` with `LoadOrStore` + deferred `Delete`.

### File Permissions

**PASS**: All new file creation uses restrictive permissions:
- Cache files: `0600` (owner read/write only)
- Cache directories: `0700` (owner only)
- Profile files: `0600` (owner read/write only)
- Atomic write pattern prevents race between write and permission set

### Input Validation

**PASS**: Environment names validated by `EnvironmentNameRegexp` (`^[a-zA-Z0-9-\(\)_\.]{1,64}$`).
Profile flags are hidden. Concurrency limit env vars (`AZD_DEPLOY_CONCURRENCY`,
`AZD_PROVISION_CONCURRENCY`) are parsed with `strconv.Atoi` with explicit `> 0` checks.

### Credential Handling

**PASS**: No changes to Azure credential flows, token handling, or auth logic in the diff.
The `auth/` package changes are struct field reordering only (alignment optimization).

### HTTP Transport Tuning

**PASS**: `TunedTransport()` clones `http.DefaultTransport` and only adjusts connection
pooling parameters. No TLS configuration changes, no certificate pinning modifications,
no proxy bypass.

### Alpha Feature Gating

**PASS**: All new features are behind alpha feature keys registered in `alpha_features.yaml`:
- `deploy.parallel`, `provision.parallel`, `up.concurrent`
- `provision.localCache`, `provision.bicepCache`
- `provision.adaptivePolling`, `provision.skipRepeatValidation`
- `deploy.smartApi`, `deploy.runFromPackage`, `deploy.parallelBuild`, `deploy.parallelInit`

---

## Supply Chain

| Check | Status |
|-------|--------|
| go.mod: no new dependencies added | PASS (only `go 1.26` version bump) |
| Lockfile integrity | N/A (Go modules use go.sum) |
| CI actions pinned to SHA | FAIL (F01) |
| CI tools pinned to version | FAIL (F02) |
| No install scripts in deps | PASS |
| License compatibility | PASS (all existing deps) |

---

## Compliance Notes

- **GDPR**: No PII handling changes
- **SOC 2**: Cache file permissions (0600) and atomic writes support CC6.1
- **Secrets management**: Cache plaintext (F03) is documented risk; alpha-only

---

## Remediation Roadmap

| Priority | Finding | Action | Effort |
|----------|---------|--------|--------|
| Before merge | F01 | Pin CI actions to SHA hashes | 15 min |
| Before merge | F02 | Pin benchstat to specific version | 5 min |
| Before GA | F03 | Encrypt sensitive cache outputs at rest | 2-4 hours |
| Low priority | F04 | Add `filepath.Base()` to layer cache key | 5 min |
| Before GA | F05 | Add LRU/max-size to Bicep build cache | 1 hour |
| No action | F06 | Acceptable for dev-only hidden flag | - |
