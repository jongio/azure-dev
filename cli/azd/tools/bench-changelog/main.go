// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// bench-changelog reads two Go benchmark result files (old and new),
// runs benchstat to compute deltas, and emits a Markdown "Performance"
// section suitable for inclusion in a CHANGELOG.
//
// Usage:
//
//	go run ./tools/bench-changelog <old.txt> <new.txt>
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <old-baseline.txt> <new-baseline.txt>\n", os.Args[0])
		os.Exit(2)
	}

	oldFile := os.Args[1]
	newFile := os.Args[2]

	for _, f := range []string{oldFile, newFile} {
		if _, err := os.Stat(f); err != nil {
			fmt.Fprintf(os.Stderr, "error: cannot read %s: %v\n", f, err)
			os.Exit(1)
		}
	}

	diff, err := runBenchstat(oldFile, newFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error running benchstat: %v\n", err)
		os.Exit(1)
	}

	rows := parseBenchstatTable(diff)
	if len(rows) == 0 {
		fmt.Fprintln(os.Stderr, "no significant benchmark changes detected")
		os.Exit(0)
	}

	printMarkdown(rows)
}

// benchRow holds one parsed benchstat result row.
type benchRow struct {
	Name   string
	Before string
	After  string
	Change string
}

// runBenchstat invokes benchstat and returns its combined stdout/stderr.
func runBenchstat(oldFile, newFile string) (string, error) {
	cmd := exec.Command("benchstat", fmt.Sprintf("old=%s", oldFile), fmt.Sprintf("new=%s", newFile))
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%w: %s", err, out.String())
	}
	return out.String(), nil
}

// changeRe matches a benchstat percentage change like "-15.0%" or "+3.2%"
// while also matching "~" (no significant change) so we can skip those.
var changeRe = regexp.MustCompile(`([+-]\d+\.\d+%|~)`)

// parseBenchstatTable extracts sec/op rows from benchstat's table output.
// It only keeps rows where the change is statistically significant (has a +/-
// percentage, not "~").
//
// benchstat v2 output looks like:
//
//	            │  old.txt   │              new.txt               │
//	            │  sec/op    │   sec/op     vs base               │
//	DotenvSet     16.72µ ± 1%   14.22µ ± 2%  -15.00% (p=0.002 n=6)
func parseBenchstatTable(output string) []benchRow {
	var rows []benchRow

	scanner := bufio.NewScanner(strings.NewReader(output))
	// Track whether we are in a sec/op section (not B/op or allocs/op).
	inSecOp := false

	for scanner.Scan() {
		line := scanner.Text()

		// Detect section headers to know which metric we are reading.
		lower := strings.ToLower(line)
		if strings.Contains(lower, "sec/op") && strings.Contains(lower, "│") {
			inSecOp = true
			continue
		}
		if (strings.Contains(lower, "b/op") || strings.Contains(lower, "allocs/op")) &&
			strings.Contains(lower, "│") {
			inSecOp = false
			continue
		}

		if !inSecOp {
			continue
		}

		// Data rows are pipe-delimited: Name │ old │ new + vs base
		parts := strings.Split(line, "│")
		if len(parts) < 3 {
			continue
		}

		name := strings.TrimSpace(parts[0])
		if name == "" || strings.HasPrefix(name, "geomean") {
			continue
		}

		oldVal := strings.TrimSpace(parts[1])
		newPart := strings.TrimSpace(parts[2])

		// Extract the actual value and the percentage change from newPart.
		// Example: "14.22µ ± 2%  -15.00% (p=0.002 n=6)"
		changeLoc := changeRe.FindStringIndex(newPart)
		if changeLoc == nil {
			continue
		}
		changeStr := newPart[changeLoc[0]:changeLoc[1]]

		// Skip rows where benchstat reports "~" (no significant change).
		if changeStr == "~" {
			continue
		}

		// The new value is everything before the change percentage, trimmed.
		newVal := strings.TrimSpace(newPart[:changeLoc[0]])

		// Strip the "± X%" noise from values for a cleaner table.
		oldVal = stripUncertainty(oldVal)
		newVal = stripUncertainty(newVal)

		rows = append(rows, benchRow{
			Name:   name,
			Before: oldVal,
			After:  newVal,
			Change: changeStr,
		})
	}

	return rows
}

// stripUncertainty removes trailing "± N%" from a value string.
func stripUncertainty(s string) string {
	if idx := strings.Index(s, "±"); idx > 0 {
		return strings.TrimSpace(s[:idx])
	}
	return s
}

// printMarkdown writes the Performance section to stdout.
func printMarkdown(rows []benchRow) {
	fmt.Println("### ⚡ Performance")
	fmt.Println()
	fmt.Println("| Benchmark | Before | After | Change |")
	fmt.Println("|-----------|--------|-------|--------|")
	for _, r := range rows {
		fmt.Printf("| %s | %s | %s | %s |\n", r.Name, r.Before, r.After, r.Change)
	}
	fmt.Println()
	fmt.Println("*Measured with `go test -bench -count=6` on linux/amd64*")
}
