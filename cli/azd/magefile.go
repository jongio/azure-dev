// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

//go:build mage

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/magefile/mage/mg"
)

// Dev contains developer tooling commands for building and installing azd from source.
type Dev mg.Namespace

// Install builds azd from source as 'azd-dev' and installs it to ~/.azd/bin.
// The binary is named azd-dev to avoid conflicting with a production azd install.
// Automatically adds ~/.azd/bin to PATH if not already present.
//
// Usage: mage dev:install
func (Dev) Install() error {
	repoRoot, err := findRepoRoot()
	if err != nil {
		return err
	}

	azdDir := filepath.Join(repoRoot, "cli", "azd")
	installDir, err := installDir()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(installDir, 0o755); err != nil {
		return fmt.Errorf("creating install dir: %w", err)
	}

	binaryName := "azd-dev"
	if runtime.GOOS == "windows" {
		binaryName = "azd-dev.exe"
	}
	outputPath := filepath.Join(installDir, binaryName)

	version, commit := devVersion(repoRoot)
	ldflags := fmt.Sprintf(
		"-X 'github.com/azure/azure-dev/cli/azd/internal.Version=%s (commit %s)'",
		version, commit,
	)

	fmt.Printf("Building azd (%s/%s)...\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("  version: %s\n", version)
	fmt.Printf("  commit:  %s\n", commit)

	cmd := exec.Command("go", "build", "-ldflags", ldflags, "-o", outputPath, ".")
	cmd.Dir = azdDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("go build failed: %w", err)
	}

	fmt.Printf("\nInstalled: %s\n", outputPath)

	if !dirOnPath(installDir) {
		if err := addToPath(installDir); err != nil {
			return err
		}
	} else {
		fmt.Println("✓ Install directory is already on PATH.")
	}

	return nil
}

// Uninstall removes the azd-dev binary from ~/.azd/bin.
// The PATH entry is left intact.
//
// Usage: mage dev:uninstall
func (Dev) Uninstall() error {
	dir, err := installDir()
	if err != nil {
		return err
	}

	binaryName := "azd-dev"
	if runtime.GOOS == "windows" {
		binaryName = "azd-dev.exe"
	}
	path := filepath.Join(dir, binaryName)

	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			fmt.Println("azd-dev is not installed.")
			return nil
		}
		return fmt.Errorf("removing %s: %w", path, err)
	}

	fmt.Printf("Removed %s\n", path)
	return nil
}

// Preflight runs all pre-commit quality checks: formatting, copyright headers, linting,
// spell checking, compilation, and unit tests. Reports a summary of all results at the end.
//
// Usage: mage preflight
func Preflight() error {
	// Disable Go workspace mode so preflight mirrors CI, which has no go.work file.
	// Without this, a local go.work can silently resolve different module versions
	// than go.mod alone, masking build failures that only appear in CI.
	origGowork, hadGowork := os.LookupEnv("GOWORK")
	os.Setenv("GOWORK", "off")
	defer func() {
		if hadGowork {
			os.Setenv("GOWORK", origGowork)
		} else {
			os.Unsetenv("GOWORK")
		}
	}()

	repoRoot, err := findRepoRoot()
	if err != nil {
		return err
	}
	azdDir := filepath.Join(repoRoot, "cli", "azd")

	type result struct {
		name   string
		status string // "pass" or "fail"
		detail string
	}
	var results []result
	failed := false

	record := func(name, status, detail string) {
		results = append(results, result{name, status, detail})
		if status == "fail" {
			failed = true
		}
	}

	// Check required tools are installed before running anything.
	if err := requireTool("golangci-lint",
		"go install github.com/golangci/golangci-lint/cmd/golangci-lint@v2.10.1"); err != nil {
		return err
	}
	if err := requireTool("cspell", "npm install -g cspell@8.13.1"); err != nil {
		return err
	}
	shell := "sh"
	if runtime.GOOS == "windows" {
		if p, err := exec.LookPath("bash"); err == nil {
			shell = p
		} else if p, err := exec.LookPath("sh"); err == nil {
			shell = p
		} else {
			return fmt.Errorf("bash/sh not found — install Git for Windows: https://git-scm.com/downloads/win")
		}
	}

	// 1. gofmt — check for unformatted files
	fmt.Println("══ Formatting (gofmt) ══")
	if out, err := runCapture(azdDir, "gofmt", "-s", "-l", "."); err != nil {
		record("gofmt", "fail", err.Error())
	} else if len(strings.TrimSpace(out)) > 0 {
		record("gofmt", "fail", "unformatted files:\n"+out)
		fmt.Print(out)
	} else {
		record("gofmt", "pass", "")
	}

	// 2. go fix — check for code modernization opportunities
	fmt.Println("══ Code modernization (go fix) ══")
	if out, err := runCapture(azdDir, "go", "fix", "-diff", "./..."); err != nil {
		record("go fix", "fail", err.Error())
	} else if len(strings.TrimSpace(out)) > 0 {
		record("go fix", "fail", "code should be modernized — run 'go fix ./...' to apply:\n"+out)
		fmt.Print(out)
	} else {
		record("go fix", "pass", "")
	}

	// 3. Copyright headers
	fmt.Println("══ Copyright headers ══")
	script := filepath.Join(repoRoot, "eng", "scripts", "copyright-check.sh")
	if _, err := os.Stat(script); err != nil {
		record("copyright", "fail", "script not found: "+script)
	} else if err := runShellScript(azdDir, shell, script, "."); err != nil {
		record("copyright", "fail", err.Error())
	} else {
		record("copyright", "pass", "")
	}

	// 4. golangci-lint
	fmt.Println("══ Lint (golangci-lint) ══")
	if err := runStreaming(azdDir, "golangci-lint", "run", "./..."); err != nil {
		record("lint", "fail", err.Error())
	} else {
		record("lint", "pass", "")
	}

	// 5. Spell check (cspell)
	fmt.Println("══ Spell check (cspell) ══")
	if err := runStreaming(azdDir, "cspell", "lint", "**/*.go",
		"--relative", "--config", "./.vscode/cspell.yaml", "--no-progress"); err != nil {
		record("cspell", "fail", err.Error())
	} else {
		record("cspell", "pass", "")
	}

	// 6. Compile check
	fmt.Println("══ Build (go build) ══")
	if err := runStreaming(azdDir, "go", "build", "./..."); err != nil {
		record("build", "fail", err.Error())
	} else {
		record("build", "pass", "")
	}

	// 7. Unit tests (with -cover to match CI and catch os.Args leaks)
	fmt.Println("══ Unit tests (go test -short -cover) ══")
	if err := runStreaming(azdDir, "go", "test", "./...", "-short", "-cover", "-count=1"); err != nil {
		record("test", "fail", err.Error())
	} else {
		record("test", "pass", "")
	}

	// Summary
	fmt.Println("\n══════════════════════════")
	fmt.Println("  Preflight Summary")
	fmt.Println("══════════════════════════")
	for _, r := range results {
		icon := "✓"
		if r.status == "fail" {
			icon = "✗"
		}
		fmt.Printf("  %s %s\n", icon, r.name)
	}
	fmt.Println("══════════════════════════")

	if failed {
		return fmt.Errorf("preflight failed")
	}
	fmt.Println("All checks passed!")
	return nil
}

// BenchBaseline runs benchmarks and saves the output as baseline for future comparison.
// Results are saved to perf/baselines/{GOOS}/main.txt
//
// Usage: mage benchbaseline
func BenchBaseline() error {
	repoRoot, err := findRepoRoot()
	if err != nil {
		return err
	}
	azdDir := filepath.Join(repoRoot, "cli", "azd")

	dir := filepath.Join(azdDir, "perf", "baselines", runtime.GOOS)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating baseline dir: %w", err)
	}

	outPath := filepath.Join(dir, "main.txt")

	fmt.Println("Running benchmarks (this may take several minutes)...")
	out, err := runCapture(azdDir, "go", "test", "-bench=.", "-benchmem", "-count=6", "-timeout=10m", "./...")
	if err != nil {
		return fmt.Errorf("benchmarks failed: %w\n%s", err, out)
	}

	if err := os.WriteFile(outPath, []byte(out), 0o644); err != nil {
		return fmt.Errorf("writing baseline: %w", err)
	}

	fmt.Printf("Baseline saved to %s\n", outPath)
	return nil
}

// BenchCompare runs benchmarks and compares against the saved baseline using benchstat.
// Requires benchstat: go install golang.org/x/perf/cmd/benchstat@latest
//
// Usage: mage benchcompare
func BenchCompare() error {
	repoRoot, err := findRepoRoot()
	if err != nil {
		return err
	}
	azdDir := filepath.Join(repoRoot, "cli", "azd")

	baseline := filepath.Join(azdDir, "perf", "baselines", runtime.GOOS, "main.txt")
	if _, err := os.Stat(baseline); err != nil {
		return fmt.Errorf("baseline not found at %s — run 'mage benchbaseline' first", baseline)
	}

	if err := requireTool("benchstat",
		"go install golang.org/x/perf/cmd/benchstat@latest"); err != nil {
		return err
	}

	tmp, err := os.CreateTemp("", "bench-new-*.txt")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	defer os.Remove(tmp.Name())
	tmp.Close()

	fmt.Println("Running benchmarks (this may take several minutes)...")
	out, err := runCapture(azdDir, "go", "test", "-bench=.", "-benchmem", "-count=6", "-timeout=10m", "./...")
	if err != nil {
		return fmt.Errorf("benchmarks failed: %w\n%s", err, out)
	}

	if err := os.WriteFile(tmp.Name(), []byte(out), 0o644); err != nil {
		return fmt.Errorf("writing temp results: %w", err)
	}

	stat, err := runCapture(azdDir, "benchstat", "old="+baseline, "new="+tmp.Name())
	if err != nil {
		// benchstat exits non-zero only on usage errors; partial output is still useful.
		fmt.Fprintf(os.Stderr, "benchstat warning: %v\n", err)
	}

	fmt.Println(stat)
	return nil
}

// BenchRegress runs benchmarks and fails if any regression exceeds thresholds.
// Thresholds: >15% timing regression or >10% memory regression (p<0.05).
//
// Usage: mage benchregress
func BenchRegress() error {
	repoRoot, err := findRepoRoot()
	if err != nil {
		return err
	}
	azdDir := filepath.Join(repoRoot, "cli", "azd")

	baseline := filepath.Join(azdDir, "perf", "baselines", runtime.GOOS, "main.txt")
	if _, err := os.Stat(baseline); err != nil {
		return fmt.Errorf("baseline not found at %s — run 'mage benchbaseline' first", baseline)
	}

	if err := requireTool("benchstat",
		"go install golang.org/x/perf/cmd/benchstat@latest"); err != nil {
		return err
	}

	tmp, err := os.CreateTemp("", "bench-regress-*.txt")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	defer os.Remove(tmp.Name())
	tmp.Close()

	fmt.Println("Running benchmarks (this may take several minutes)...")
	out, err := runCapture(azdDir, "go", "test", "-bench=.", "-benchmem", "-count=6", "-timeout=10m", "./...")
	if err != nil {
		return fmt.Errorf("benchmarks failed: %w\n%s", err, out)
	}

	if err := os.WriteFile(tmp.Name(), []byte(out), 0o644); err != nil {
		return fmt.Errorf("writing temp results: %w", err)
	}

	stat, err := runCapture(azdDir, "benchstat", "old="+baseline, "new="+tmp.Name())
	if err != nil {
		fmt.Fprintf(os.Stderr, "benchstat warning: %v\n", err)
	}

	regressions := parseBenchRegressions(stat)
	if len(regressions) > 0 {
		fmt.Println(stat)
		return fmt.Errorf("performance regressions detected:\n%s", strings.Join(regressions, "\n"))
	}

	fmt.Println("No significant regressions detected.")
	return nil
}

// parseBenchRegressions scans benchstat output for significant regressions.
// Returns a list of human-readable regression descriptions.
// Thresholds: >15% for sec/op (timing), >10% for B/op (memory).
func parseBenchRegressions(output string) []string {
	re := regexp.MustCompile(`(Benchmark\S*)\s+.*\+(\d+(?:\.\d+)?)%\s+\(p=(\d+(?:\.\d+)?)`)

	var regressions []string
	var metric string

	for _, line := range strings.Split(output, "\n") {
		switch {
		case strings.Contains(line, "sec/op"):
			metric = "sec/op"
		case strings.Contains(line, "B/op"):
			metric = "B/op"
		case strings.Contains(line, "allocs/op"):
			metric = "allocs/op"
		}

		m := re.FindStringSubmatch(line)
		if m == nil {
			continue
		}

		name := m[1]
		pct, _ := strconv.ParseFloat(m[2], 64)
		pVal, _ := strconv.ParseFloat(m[3], 64)

		if pVal >= 0.05 {
			continue // not statistically significant
		}

		threshold := 15.0
		if metric == "B/op" || metric == "allocs/op" {
			threshold = 10.0
		}

		if pct > threshold {
			regressions = append(regressions,
				fmt.Sprintf("  %s: +%.2f%% %s (p=%.3f)", name, pct, metric, pVal))
		}
	}

	return regressions
}

// runCapture runs a command and returns its combined stdout/stderr.
func runCapture(dir string, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

// runStreaming runs a command with stdout/stderr connected to the terminal.
func runStreaming(dir string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// runShellScript runs a shell script using the given shell binary.
// On Windows, converts the script path to the form expected by the detected shell (WSL or Git-for-Windows bash)
// and handles CRLF line endings that WSL bash cannot process.
func runShellScript(dir string, shell string, script string, args ...string) error {
	if runtime.GOOS == "windows" {
		shellScript := toShellPath(shell, script)

		// Build: cd '<dir>' && tr -d '\r' < '<script>' | bash -s -- '<arg1>' ...
		// This strips CRLF line endings that WSL bash chokes on.
		shellDir := toShellPath(shell, dir)
		quotedArgs := make([]string, len(args))
		for i, a := range args {
			quotedArgs[i] = shellQuote(a)
		}
		inner := fmt.Sprintf(`cd %s && tr -d '\r' < %s | bash -s -- %s`,
			shellQuote(shellDir), shellQuote(shellScript), strings.Join(quotedArgs, " "))
		cmd := exec.Command(shell, "-c", inner)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}

	cmdArgs := append([]string{script}, args...)
	cmd := exec.Command(shell, cmdArgs...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// shellKind caches the result of detecting whether the shell is WSL or Git-for-Windows bash.
var shellKind struct {
	once  sync.Once
	isWSL bool
}

// toShellPath converts a Windows path to a unix-style path for the given shell.
// WSL bash expects /mnt/c/..., Git-for-Windows bash expects /c/...
func toShellPath(shell, winPath string) string {
	p := filepath.ToSlash(winPath)
	if len(p) >= 2 && p[1] == ':' {
		drive := strings.ToLower(string(p[0]))
		rest := p[2:]

		// Cache WSL detection so we only shell out once.
		shellKind.once.Do(func() {
			out, err := exec.Command(shell, "-c", "test -d /mnt/c && echo wsl").Output()
			shellKind.isWSL = err == nil && strings.TrimSpace(string(out)) == "wsl"
		})
		if shellKind.isWSL {
			return "/mnt/" + drive + rest
		}
		return "/" + drive + rest
	}
	return p
}

// requireTool checks that a CLI tool is on PATH, returning a helpful install message if not.
func requireTool(name, installCmd string) error {
	if _, err := exec.LookPath(name); err != nil {
		return fmt.Errorf("%s is required but not installed.\n  Install: %s", name, installCmd)
	}
	return nil
}

// shellQuote wraps s in single quotes and escapes embedded single quotes for POSIX shells.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func installDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("getting home directory: %w", err)
	}
	return filepath.Join(home, ".azd", "bin"), nil
}

func devVersion(repoRoot string) (string, string) {
	version := "0.0.0-dev.0"

	if data, err := os.ReadFile(filepath.Join(repoRoot, "cli", "version.txt")); err == nil {
		if v := strings.TrimSpace(string(data)); v != "" {
			version = v + "-dev"
		}
	}

	commit := strings.Repeat("0", 40)
	if out, err := exec.Command("git", "-C", repoRoot, "rev-parse", "HEAD").Output(); err == nil {
		if h := strings.TrimSpace(string(out)); len(h) == 40 {
			commit = h
		}
	}

	return version, commit
}

func findRepoRoot() (string, error) {
	if out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output(); err == nil {
		return filepath.FromSlash(strings.TrimSpace(string(out))), nil
	}

	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "cli", "azd", "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("could not find azure-dev repository root (looking for cli/azd/go.mod)")
		}
		dir = parent
	}
}

func dirOnPath(dir string) bool {
	for _, entry := range filepath.SplitList(os.Getenv("PATH")) {
		if strings.EqualFold(filepath.Clean(entry), filepath.Clean(dir)) {
			return true
		}
	}
	return false
}

// addToPath persistently adds dir to the user's PATH.
//   - Windows: updates the User environment variable via PowerShell.
//   - Unix: appends an export line to the user's shell rc file.
//
// The current process PATH is also updated so subsequent steps see the change.
func addToPath(dir string) error {
	switch runtime.GOOS {
	case "windows":
		return addToPathWindows(dir)
	default:
		return addToPathUnix(dir)
	}
}

func addToPathWindows(dir string) error {
	// Read the persisted user PATH to check for duplicates (process PATH may be stale).
	out, err := exec.Command(
		"powershell", "-NoProfile", "-Command",
		"[Environment]::GetEnvironmentVariable('PATH', 'User')",
	).Output()
	if err == nil {
		for _, entry := range filepath.SplitList(strings.TrimSpace(string(out))) {
			if strings.EqualFold(filepath.Clean(entry), filepath.Clean(dir)) {
				fmt.Printf("✓ User PATH already contains %s.\n", dir)
				os.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
				return nil
			}
		}
	}

	// Persistently prepend to user-level PATH via PowerShell.
	// Pass dir as a parameter to avoid shell-injection from special characters in the path.
	cmd := exec.Command(
		"powershell", "-NoProfile", "-Command",
		"param([string]$dir) "+
			"$current = [Environment]::GetEnvironmentVariable('PATH', 'User'); "+
			`[Environment]::SetEnvironmentVariable('PATH', "$dir;" + $current, 'User')`,
		dir,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to update user PATH: %w", err)
	}

	// Update current process so the caller sees it immediately.
	os.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	fmt.Printf("✓ Added %s to user PATH (persistent). Restart your terminal for other sessions.\n", dir)
	return nil
}

func addToPathUnix(dir string) error {
	shell := filepath.Base(os.Getenv("SHELL"))
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("getting home directory: %w", err)
	}

	var rcFile string
	var exportLine string

	switch shell {
	case "zsh":
		rcFile = filepath.Join(home, ".zshrc")
		exportLine = fmt.Sprintf(`export PATH=%s:$PATH`, shellQuote(dir))
	case "fish":
		rcFile = filepath.Join(home, ".config", "fish", "config.fish")
		exportLine = fmt.Sprintf("fish_add_path %s", shellQuote(dir))
	default: // bash and others
		rcFile = filepath.Join(home, ".bashrc")
		exportLine = fmt.Sprintf(`export PATH=%s:$PATH`, shellQuote(dir))
	}

	// Check if already present in rc file to avoid duplicates on re-runs.
	if data, err := os.ReadFile(rcFile); err == nil {
		if strings.Contains(string(data), exportLine) {
			fmt.Printf("✓ %s already references %s.\n", rcFile, dir)
			os.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			return nil
		}
	}

	// Ensure parent dir exists (for fish config path).
	if err := os.MkdirAll(filepath.Dir(rcFile), 0o755); err != nil {
		return fmt.Errorf("creating config dir: %w", err)
	}

	f, err := os.OpenFile(rcFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("opening %s: %w", rcFile, err)
	}
	defer f.Close()

	if _, err := fmt.Fprintf(f, "\n# Added by azd dev:install\n%s\n", exportLine); err != nil {
		return fmt.Errorf("writing to %s: %w", rcFile, err)
	}

	os.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	fmt.Printf("✓ Added %s to %s. Restart your terminal or run: source %s\n", dir, rcFile, rcFile)
	return nil
}

// ---------------------------------------------------------------------------
// Perf namespace — performance validation comparing perf branch vs released azd
// ---------------------------------------------------------------------------

// Perf contains commands for performance validation comparing the perf branch against released azd.
type Perf mg.Namespace

// Build compiles the perf branch binary and downloads the released azd binary.
// Both are placed in cli/azd/perf/bin/ for side-by-side comparison.
//
// The released version defaults to 1.23.11 and can be overridden with AZD_PERF_RELEASED_VERSION.
//
// Usage: mage perf:build
func (Perf) Build() error {
	repoRoot, err := findRepoRoot()
	if err != nil {
		return err
	}

	azdDir := filepath.Join(repoRoot, "cli", "azd")
	perfBinDir := filepath.Join(azdDir, "perf", "bin")
	if err := os.MkdirAll(perfBinDir, 0o755); err != nil {
		return fmt.Errorf("creating perf/bin dir: %w", err)
	}

	// --- Build perf binary from current branch ---
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	perfBinary := filepath.Join(perfBinDir, "azd-perf"+ext)

	version, commit := devVersion(repoRoot)
	ldflags := fmt.Sprintf(
		"-X 'github.com/azure/azure-dev/cli/azd/internal.Version=%s (commit %s)'",
		version, commit,
	)

	fmt.Printf("Building perf binary (%s/%s)...\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("  version: %s\n", version)
	fmt.Printf("  commit:  %s\n", commit)

	cmd := exec.Command("go", "build", "-ldflags", ldflags, "-o", perfBinary, ".")
	cmd.Dir = azdDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("building perf binary: %w", err)
	}

	// --- Download released azd binary ---
	releasedVersion := os.Getenv("AZD_PERF_RELEASED_VERSION")
	if releasedVersion == "" {
		releasedVersion = "1.23.11"
	}

	osName := runtime.GOOS   // "windows", "linux", "darwin"
	archName := runtime.GOARCH // "amd64", "arm64"
	downloadURL := fmt.Sprintf(
		"https://azure-dev.azureedge.net/azd/standalone/release/%s/azd-%s-%s%s",
		releasedVersion, osName, archName, ext,
	)

	releasedBinary := filepath.Join(perfBinDir, "azd-released"+ext)
	fmt.Printf("\nDownloading released azd %s (%s/%s)...\n", releasedVersion, osName, archName)
	fmt.Printf("  URL: %s\n", downloadURL)

	if err := downloadFile(downloadURL, releasedBinary); err != nil {
		return err
	}

	if runtime.GOOS != "windows" {
		if err := os.Chmod(releasedBinary, 0o755); err != nil {
			return fmt.Errorf("setting executable permission: %w", err)
		}
	}

	// --- Verify both binaries ---
	fmt.Println("\nVerifying binaries...")

	fmt.Println("  Perf binary:")
	if out, err := runCapture("", perfBinary, "version"); err != nil {
		fmt.Fprintf(os.Stderr, "    warning: verification failed: %v\n", err)
	} else {
		fmt.Printf("    %s\n", strings.TrimSpace(out))
	}

	fmt.Println("  Released binary:")
	if out, err := runCapture("", releasedBinary, "version"); err != nil {
		fmt.Fprintf(os.Stderr, "    warning: verification failed: %v\n", err)
	} else {
		fmt.Printf("    %s\n", strings.TrimSpace(out))
	}

	fmt.Println("\n══════════════════════════")
	fmt.Println("  Perf Build Summary")
	fmt.Println("══════════════════════════")
	fmt.Printf("  Perf binary:     %s\n", perfBinary)
	fmt.Printf("  Released binary: %s\n", releasedBinary)
	fmt.Println("══════════════════════════")

	return nil
}

// BenchGo runs Go micro-benchmarks on upstream/main and the perf branch, then compares
// the results using benchstat. Results are saved to cli/azd/perf/results/.
// Requires benchstat: go install golang.org/x/perf/cmd/benchstat@latest
//
// Usage: mage perf:benchgo
func (Perf) BenchGo() error {
	repoRoot, err := findRepoRoot()
	if err != nil {
		return err
	}
	azdDir := filepath.Join(repoRoot, "cli", "azd")

	if err := requireTool("benchstat",
		"go install golang.org/x/perf/cmd/benchstat@latest"); err != nil {
		return err
	}

	resultsDir := filepath.Join(azdDir, "perf", "results")
	if err := os.MkdirAll(resultsDir, 0o755); err != nil {
		return fmt.Errorf("creating perf/results dir: %w", err)
	}

	benchPkgs := []string{
		"./internal/cmd/...",
		"./pkg/containerapps/...",
		"./pkg/environment/...",
		"./pkg/infra/provisioning/bicep/...",
		"./pkg/project/...",
	}

	benchArgs := append([]string{
		"test", "-bench=.", "-benchmem", "-count=6", "-timeout=10m", "-run=^$",
	}, benchPkgs...)

	goworkEnv := []string{"GOWORK=off"}

	// --- Run benchmarks on upstream/main ---
	fmt.Println("══ Benchmarks on upstream/main ══")
	worktreeDir, err := perfCreateWorktree(repoRoot, "upstream/main")
	if err != nil {
		return err
	}

	worktreeAzdDir := filepath.Join(worktreeDir, "cli", "azd")
	mainOut, err := runCaptureWithEnv(worktreeAzdDir, goworkEnv, "go", benchArgs...)
	perfRemoveWorktree(repoRoot, worktreeDir)
	if err != nil {
		return fmt.Errorf("benchmarks on upstream/main failed: %w\n%s", err, mainOut)
	}

	mainPath := filepath.Join(resultsDir, "bench-main.txt")
	if err := os.WriteFile(mainPath, []byte(mainOut), 0o644); err != nil {
		return fmt.Errorf("writing bench-main.txt: %w", err)
	}
	fmt.Printf("  Saved to %s\n", mainPath)

	// --- Run benchmarks on perf branch ---
	fmt.Println("\n══ Benchmarks on perf branch ══")
	perfOut, err := runCaptureWithEnv(azdDir, goworkEnv, "go", benchArgs...)
	if err != nil {
		return fmt.Errorf("benchmarks on perf branch failed: %w\n%s", err, perfOut)
	}

	perfPath := filepath.Join(resultsDir, "bench-perf.txt")
	if err := os.WriteFile(perfPath, []byte(perfOut), 0o644); err != nil {
		return fmt.Errorf("writing bench-perf.txt: %w", err)
	}
	fmt.Printf("  Saved to %s\n", perfPath)

	// --- Compare with benchstat ---
	fmt.Println("\n══ Benchmark Comparison ══")
	comparison, err := runCapture(azdDir, "benchstat", "old="+mainPath, "new="+perfPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "benchstat warning: %v\n", err)
	}

	compPath := filepath.Join(resultsDir, "bench-comparison.txt")
	if err := os.WriteFile(compPath, []byte(comparison), 0o644); err != nil {
		return fmt.Errorf("writing bench-comparison.txt: %w", err)
	}
	fmt.Println(comparison)

	// --- Generate changelog (best effort) ---
	changelogPath := filepath.Join(resultsDir, "bench-changelog.md")
	changelogOut, err := runCapture(azdDir, "go", "run", "./tools/bench-changelog", mainPath, perfPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "note: bench-changelog skipped (tool not found or failed): %v\n", err)
	} else {
		if writeErr := os.WriteFile(changelogPath, []byte(changelogOut), 0o644); writeErr != nil {
			fmt.Fprintf(os.Stderr, "warning: writing bench-changelog.md: %v\n", writeErr)
		} else {
			fmt.Printf("Changelog saved to %s\n", changelogPath)
		}
	}

	// --- Upload to azd-perf API if URL is configured ---
	apiURL := os.Getenv("AZD_PERF_API_URL")
	if err := perfUploadBenchmarks(mainPath, perfPath, apiURL); err != nil {
		fmt.Fprintf(os.Stderr, "  Warning: upload failed: %v\n", err)
		// Non-fatal — don't fail the benchmark run for upload issues
	}

	return nil
}

// TestParity runs tests on upstream/main and the perf branch, then compares results
// to identify regressions and new tests. Results are saved to cli/azd/perf/results/.
//
// Usage: mage perf:testparity
func (Perf) TestParity() error {
	repoRoot, err := findRepoRoot()
	if err != nil {
		return err
	}
	azdDir := filepath.Join(repoRoot, "cli", "azd")

	resultsDir := filepath.Join(azdDir, "perf", "results")
	if err := os.MkdirAll(resultsDir, 0o755); err != nil {
		return fmt.Errorf("creating perf/results dir: %w", err)
	}

	goworkEnv := []string{"GOWORK=off"}
	testArgs := []string{"test", "./...", "-short", "-json", "-timeout=10m"}

	// --- Run tests on upstream/main ---
	fmt.Println("══ Tests on upstream/main ══")
	worktreeDir, err := perfCreateWorktree(repoRoot, "upstream/main")
	if err != nil {
		return err
	}

	worktreeAzdDir := filepath.Join(worktreeDir, "cli", "azd")
	mainOut, err := runCaptureWithEnv(worktreeAzdDir, goworkEnv, "go", testArgs...)
	perfRemoveWorktree(repoRoot, worktreeDir)
	// go test -json exits non-zero if any test fails, but we still want the output.
	if mainOut == "" && err != nil {
		return fmt.Errorf("tests on upstream/main failed with no output: %w", err)
	}

	mainPath := filepath.Join(resultsDir, "tests-main.json")
	if err := os.WriteFile(mainPath, []byte(mainOut), 0o644); err != nil {
		return fmt.Errorf("writing tests-main.json: %w", err)
	}
	fmt.Printf("  Saved to %s\n", mainPath)

	// --- Run tests on perf branch ---
	fmt.Println("\n══ Tests on perf branch ══")
	perfOut, err := runCaptureWithEnv(azdDir, goworkEnv, "go", testArgs...)
	if perfOut == "" && err != nil {
		return fmt.Errorf("tests on perf branch failed with no output: %w", err)
	}

	perfPath := filepath.Join(resultsDir, "tests-perf.json")
	if err := os.WriteFile(perfPath, []byte(perfOut), 0o644); err != nil {
		return fmt.Errorf("writing tests-perf.json: %w", err)
	}
	fmt.Printf("  Saved to %s\n", perfPath)

	// --- Compare results ---
	fmt.Println("\n══ Test Parity Analysis ══")
	mainSummary := parseTestJSON([]byte(mainOut))
	perfSummary := parseTestJSON([]byte(perfOut))

	// Identify regressions: pass on main → fail on perf
	var regressions []string
	for key, mainAction := range mainSummary.tests {
		if perfAction, ok := perfSummary.tests[key]; ok && mainAction == "pass" && perfAction == "fail" {
			regressions = append(regressions, key)
		}
	}
	sort.Strings(regressions)

	// Identify new tests on perf branch
	var newTests []string
	for key := range perfSummary.tests {
		if _, ok := mainSummary.tests[key]; !ok {
			newTests = append(newTests, key)
		}
	}
	sort.Strings(newTests)

	// Print summary table
	fmt.Println()
	fmt.Printf("  %-12s  %-16s  %-16s\n", "", "upstream/main", "perf branch")
	fmt.Printf("  %-12s  %-16d  %-16d\n", "Total", mainSummary.total, perfSummary.total)
	fmt.Printf("  %-12s  %-16d  %-16d\n", "Passed", mainSummary.passed, perfSummary.passed)
	fmt.Printf("  %-12s  %-16d  %-16d\n", "Failed", mainSummary.failed, perfSummary.failed)
	fmt.Printf("  %-12s  %-16d  %-16d\n", "Skipped", mainSummary.skipped, perfSummary.skipped)

	if len(regressions) > 0 {
		fmt.Printf("\n  Regressions (%d): tests that PASS on main but FAIL on perf:\n", len(regressions))
		for _, r := range regressions {
			fmt.Printf("    ✗ %s\n", r)
		}
	} else {
		fmt.Println("\n  No regressions detected.")
	}

	if len(newTests) > 0 {
		fmt.Printf("\n  New tests (%d): tests on perf branch not present on main:\n", len(newTests))
		for _, t := range newTests {
			fmt.Printf("    + %s\n", t)
		}
	}

	// Write markdown report
	var report strings.Builder
	report.WriteString("# Test Parity Report\n\n")
	report.WriteString("## Summary\n\n")
	report.WriteString("| Metric | upstream/main | perf branch |\n")
	report.WriteString("|--------|--------------|-------------|\n")
	report.WriteString(fmt.Sprintf("| Total | %d | %d |\n", mainSummary.total, perfSummary.total))
	report.WriteString(fmt.Sprintf("| Passed | %d | %d |\n", mainSummary.passed, perfSummary.passed))
	report.WriteString(fmt.Sprintf("| Failed | %d | %d |\n", mainSummary.failed, perfSummary.failed))
	report.WriteString(fmt.Sprintf("| Skipped | %d | %d |\n", mainSummary.skipped, perfSummary.skipped))

	if len(regressions) > 0 {
		report.WriteString(fmt.Sprintf("\n## Regressions (%d)\n\n", len(regressions)))
		report.WriteString("Tests that PASS on upstream/main but FAIL on perf branch:\n\n")
		for _, r := range regressions {
			report.WriteString(fmt.Sprintf("- `%s`\n", r))
		}
	}

	if len(newTests) > 0 {
		report.WriteString(fmt.Sprintf("\n## New Tests (%d)\n\n", len(newTests)))
		report.WriteString("Tests present on perf branch but not on upstream/main:\n\n")
		for _, t := range newTests {
			report.WriteString(fmt.Sprintf("- `%s`\n", t))
		}
	}

	parityPath := filepath.Join(resultsDir, "test-parity.md")
	if err := os.WriteFile(parityPath, []byte(report.String()), 0o644); err != nil {
		return fmt.Errorf("writing test-parity.md: %w", err)
	}
	fmt.Printf("\n  Report saved to %s\n", parityPath)

	return nil
}

// Validate runs the full performance validation pipeline: Build → BenchGo → TestParity.
//
// Usage: mage perf:validate
func (p Perf) Validate() error {
	if err := p.Build(); err != nil {
		return fmt.Errorf("perf:build failed: %w", err)
	}
	if err := p.BenchGo(); err != nil {
		return fmt.Errorf("perf:benchgo failed: %w", err)
	}
	if err := p.TestParity(); err != nil {
		return fmt.Errorf("perf:testparity failed: %w", err)
	}

	fmt.Println("\n══════════════════════════════")
	fmt.Println("  Perf Validation Complete ✓")
	fmt.Println("══════════════════════════════")
	return nil
}

// Demo runs BenchGo and TestParity without rebuilding binaries.
// Use this for quick demonstrations when binaries are already built.
//
// Usage: mage perf:demo
func (p Perf) Demo() error {
	if err := p.BenchGo(); err != nil {
		return fmt.Errorf("perf:benchgo failed: %w", err)
	}
	if err := p.TestParity(); err != nil {
		return fmt.Errorf("perf:testparity failed: %w", err)
	}

	fmt.Println("\n══════════════════════════")
	fmt.Println("  Perf Demo Complete ✓")
	fmt.Println("══════════════════════════")
	return nil
}

// ---------------------------------------------------------------------------
// Perf helper types and functions
// ---------------------------------------------------------------------------

// perfTestEvent represents a single event from go test -json output.
type perfTestEvent struct {
	Action  string `json:"Action"`
	Package string `json:"Package"`
	Test    string `json:"Test"`
}

// perfTestSummary holds aggregated test results parsed from go test -json output.
type perfTestSummary struct {
	total   int
	passed  int
	failed  int
	skipped int
	tests   map[string]string // "package/TestName" → final action
}

// parseTestJSON parses line-delimited go test -json output into a summary.
// Each line is a JSON object with Action, Package, Test fields.
// Only test-level events (non-empty Test field) are tracked.
func parseTestJSON(data []byte) perfTestSummary {
	summary := perfTestSummary{tests: make(map[string]string)}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var ev perfTestEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue // skip non-JSON lines (e.g., build output)
		}

		// Skip package-level events (no Test field).
		if ev.Test == "" {
			continue
		}

		key := ev.Package + "/" + ev.Test
		switch ev.Action {
		case "pass", "fail", "skip":
			summary.tests[key] = ev.Action
		}
	}

	for _, action := range summary.tests {
		summary.total++
		switch action {
		case "pass":
			summary.passed++
		case "fail":
			summary.failed++
		case "skip":
			summary.skipped++
		}
	}

	return summary
}

// downloadFile downloads a file from url and saves it to destPath.
// Uses a 5-minute timeout. Partial downloads are cleaned up on error.
func downloadFile(url, destPath string) error {
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url) //nolint:noctx // Simple download; context not needed for mage CLI tool.
	if err != nil {
		return fmt.Errorf("downloading %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("downloading %s: HTTP %d", url, resp.StatusCode)
	}

	f, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("creating %s: %w", destPath, err)
	}

	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(destPath)
		return fmt.Errorf("writing %s: %w", destPath, err)
	}

	return f.Close()
}

// perfCreateWorktree creates a git worktree for the given ref in a temp directory.
// Returns the worktree path. Caller must call perfRemoveWorktree to clean up.
func perfCreateWorktree(repoRoot, ref string) (string, error) {
	tmpDir, err := os.MkdirTemp("", "azd-perf-*")
	if err != nil {
		return "", fmt.Errorf("creating temp dir for worktree: %w", err)
	}
	// git worktree add requires the target directory to not exist.
	if err := os.Remove(tmpDir); err != nil {
		return "", fmt.Errorf("preparing worktree path: %w", err)
	}

	fmt.Printf("  Creating worktree for %s...\n", ref)
	cmd := exec.Command("git", "worktree", "add", tmpDir, ref)
	cmd.Dir = repoRoot
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("creating worktree for %s: %w", ref, err)
	}

	return tmpDir, nil
}

// perfRemoveWorktree removes a git worktree, falling back to manual cleanup on failure.
func perfRemoveWorktree(repoRoot, path string) {
	fmt.Printf("  Removing worktree at %s...\n", path)
	cmd := exec.Command("git", "worktree", "remove", path, "--force")
	cmd.Dir = repoRoot
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "  warning: git worktree remove failed: %v — cleaning up manually\n", err)
		os.RemoveAll(path)
		pruneCmd := exec.Command("git", "worktree", "prune")
		pruneCmd.Dir = repoRoot
		_ = pruneCmd.Run()
	}
}

// runCaptureWithEnv runs a command with additional environment variables and returns its combined output.
func runCaptureWithEnv(dir string, env []string, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

// benchEntry represents a single parsed Go benchmark result.
type benchEntry struct {
	Name     string
	NsOp     float64
	BytesOp  float64
	AllocsOp float64
}

// parseBenchOutput reads Go benchmark output and extracts benchmark entries.
// Expected format: BenchmarkXxx-N    12345    98.5 ns/op    64 B/op    2 allocs/op
func parseBenchOutput(path string) ([]benchEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var entries []benchEntry
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Benchmark") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		e := benchEntry{Name: fields[0]}

		// Parse ns/op, B/op, allocs/op from fields
		for i, f := range fields {
			if i+1 < len(fields) {
				switch fields[i+1] {
				case "ns/op":
					fmt.Sscanf(f, "%f", &e.NsOp)
				case "B/op":
					fmt.Sscanf(f, "%f", &e.BytesOp)
				case "allocs/op":
					fmt.Sscanf(f, "%f", &e.AllocsOp)
				}
			}
		}

		if e.NsOp > 0 { // only include entries with valid timing
			entries = append(entries, e)
		}
	}

	return entries, nil
}

// perfUploadBenchmarks parses benchstat output files and uploads results to the azd-perf API.
// If apiURL is empty, the upload is skipped with a log message.
func perfUploadBenchmarks(mainFile, perfFile, apiURL string) error {
	if apiURL == "" {
		fmt.Println("  Skipping upload: AZD_PERF_API_URL not set")
		return nil
	}

	// Parse the perf benchmark file for individual results
	entries, err := parseBenchOutput(perfFile)
	if err != nil {
		return fmt.Errorf("parsing benchmark output: %w", err)
	}

	// Parse the main benchmark file for baseline values
	baselineEntries, err := parseBenchOutput(mainFile)
	if err != nil {
		// Non-fatal: we can still upload without baseline
		fmt.Printf("  Warning: could not parse baseline benchmarks: %v\n", err)
		baselineEntries = nil
	}

	// Build baseline lookup map
	baselineMap := make(map[string]benchEntry)
	for _, e := range baselineEntries {
		baselineMap[e.Name] = e
	}

	// Build the MicrobenchmarkRun payload
	var benchmarks []map[string]any
	improved, regressed, unchanged := 0, 0, 0
	for _, e := range entries {
		entry := map[string]any{
			"name":         e.Name,
			"newNsOp":      e.NsOp,
			"newBytesOp":   e.BytesOp,
			"newAllocsOp":  e.AllocsOp,
			"oldNsOp":      0.0,
			"oldBytesOp":   0.0,
			"oldAllocsOp":  0.0,
			"deltaPercent": 0.0,
			"significant":  false,
		}

		if base, ok := baselineMap[e.Name]; ok {
			entry["oldNsOp"] = base.NsOp
			entry["oldBytesOp"] = base.BytesOp
			entry["oldAllocsOp"] = base.AllocsOp
			if base.NsOp > 0 {
				delta := (e.NsOp - base.NsOp) / base.NsOp * 100
				entry["deltaPercent"] = delta
				entry["significant"] = delta > 5 || delta < -5
				if delta < -5 {
					improved++
				} else if delta > 5 {
					regressed++
				} else {
					unchanged++
				}
			}
		}

		benchmarks = append(benchmarks, entry)
	}

	// Get git info
	commitCmd := exec.Command("git", "rev-parse", "--short", "HEAD")
	commitOut, _ := commitCmd.Output()
	commit := strings.TrimSpace(string(commitOut))

	branchCmd := exec.Command("git", "rev-parse", "--abbrev-ref", "HEAD")
	branchOut, _ := branchCmd.Output()
	branch := strings.TrimSpace(string(branchOut))

	goVerCmd := exec.Command("go", "version")
	goVerOut, _ := goVerCmd.Output()
	goVer := strings.TrimSpace(string(goVerOut))

	payload := map[string]any{
		"id":              fmt.Sprintf("microbench-%s-%d", commit, time.Now().Unix()),
		"azdVersion":      fmt.Sprintf("perf-%s", commit),
		"baselineVersion": "upstream/main",
		"commit":          commit,
		"branch":          branch,
		"os":              runtime.GOOS,
		"arch":            runtime.GOARCH,
		"goVersion":       goVer,
		"timestamp":       time.Now().UTC().Format(time.RFC3339),
		"benchmarks":      benchmarks,
		"summary": map[string]any{
			"totalBenchmarks":    len(benchmarks),
			"improved":           improved,
			"regressed":          regressed,
			"unchanged":          unchanged,
			"significantChanges": improved + regressed,
		},
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling payload: %w", err)
	}

	// POST to API
	fmt.Printf("  Uploading %d benchmarks to %s/api/microbenchmarks\n", len(benchmarks), apiURL)

	url := strings.TrimRight(apiURL, "/") + "/api/microbenchmarks"
	resp, err := http.Post(url, "application/json", bytes.NewReader(jsonData)) //nolint:gosec
	if err != nil {
		return fmt.Errorf("uploading benchmarks: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("upload failed with status %d: %s", resp.StatusCode, string(body))
	}

	fmt.Println("  Upload successful")
	return nil
}
