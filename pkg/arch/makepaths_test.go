// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package arch

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// MissingMakePathError reports one Makefile recipe that names a directory
// which does not exist in the tree: a `./<path>/...` package pattern, or the
// `cd <dir>` a `go test` invocation runs from.
type MissingMakePathError struct {
	// Line is the 1-based Makefile line the path appears on.
	Line int

	// Target is the rule whose recipe contains the path, or "(top level)"
	// when the path is not inside a recipe.
	Target string

	// Path is the repo-relative directory that does not exist.
	Path string
}

// Error renders the finding as a clickable `Makefile:<line>` reference.
func (e MissingMakePathError) Error() string {
	return fmt.Sprintf("Makefile:%d: target %s: %s does not exist", e.Line, e.Target, e.Path)
}

var (
	// makeRuleRe matches a rule header (`name: deps`) but not a variable
	// assignment (`NAME := value`, `NAME ?= value`, `NAME += value`).
	makeRuleRe = regexp.MustCompile(`^([A-Za-z0-9_./%-]+)\s*:([^=]|$)`)

	// makeDotPathRe matches a `./<path>/...` Go package pattern.
	makeDotPathRe = regexp.MustCompile(`\./([A-Za-z0-9_][A-Za-z0-9_./-]*)/\.\.\.`)

	// makeCdRe matches `cd <dir>` at the start of a shell command.
	makeCdRe = regexp.MustCompile(`(?:^|[\s;&|(])cd\s+([^\s;&|)]+)`)

	// makeWorkdirRe matches docker's `-w /workspace[/<dir>]`, which is how
	// the devcontainer recipes set the directory `go test` runs from.
	makeWorkdirRe = regexp.MustCompile(`-w\s+/workspace(?:/([^\s\\]*))?`)

	// makeGoTestRe detects a `go test` invocation on a logical line.
	makeGoTestRe = regexp.MustCompile(`\bgo\s+test\b`)
)

// makeLogicalLine is one Makefile line with its backslash continuations
// joined. Text keeps the embedded newlines so a match offset maps back to
// the physical line it came from.
type makeLogicalLine struct {
	Start  int
	Target string
	Text   string
}

// splitMakeLogicalLines joins continuation lines and tags each logical line
// with the rule whose recipe it belongs to.
func splitMakeLogicalLines(makefile string) []makeLogicalLine {
	physical := strings.Split(makefile, "\n")
	var out []makeLogicalLine
	target := "(top level)"
	for i := 0; i < len(physical); i++ {
		line := physical[i]
		if !strings.HasPrefix(line, "\t") {
			trimmed := strings.TrimSpace(line)
			if m := makeRuleRe.FindStringSubmatch(trimmed); len(m) > 1 && !strings.HasPrefix(m[1], ".") {
				target = m[1]
			}
		}
		start := i
		text := line
		for strings.HasSuffix(strings.TrimRight(text, " "), "\\") && i+1 < len(physical) {
			i++
			text += "\n" + physical[i]
		}
		out = append(out, makeLogicalLine{Start: start + 1, Target: target, Text: text})
	}
	return out
}

// makeBaseDirAt returns the directory a command at byte offset `at` runs
// from: the last `cd <dir>` or `-w /workspace/<dir>` before that offset, or
// "" for the repo root. Directories built from make variables are opaque and
// yield ok=false.
func makeBaseDirAt(text string, at int) (base string, ok bool) {
	prefix := text[:at]
	best := -1
	for _, m := range makeCdRe.FindAllStringSubmatchIndex(prefix, -1) {
		if m[2] > best {
			best = m[2]
			base = prefix[m[2]:m[3]]
		}
	}
	for _, m := range makeWorkdirRe.FindAllStringSubmatchIndex(prefix, -1) {
		if m[0] > best {
			best = m[0]
			base = ""
			if m[2] >= 0 {
				base = prefix[m[2]:m[3]]
			}
		}
	}
	if strings.Contains(base, "$") || strings.HasPrefix(base, "/") {
		return "", false
	}
	return strings.Trim(base, "/"), true
}

// physicalLine maps a byte offset within a logical line back to its
// 1-based physical Makefile line.
func (l makeLogicalLine) physicalLine(at int) int {
	return l.Start + strings.Count(l.Text[:at], "\n")
}

// scanMakefilePaths walks every logical line of a Makefile and reports each
// `./<path>/...` pattern, and each `cd <dir>` that a `go test` runs from,
// whose directory `exists` rejects. Paths are resolved relative to the
// enclosing `cd` / `-w /workspace` so `cd sdk/go && go test ./services/...`
// is checked as sdk/go/services.
func scanMakefilePaths(makefile string, exists func(rel string) bool) []MissingMakePathError {
	var findings []MissingMakePathError
	seen := map[string]bool{}
	report := func(line int, target, rel string) {
		key := fmt.Sprintf("%d:%s", line, rel)
		if seen[key] {
			return
		}
		seen[key] = true
		findings = append(findings, MissingMakePathError{Line: line, Target: target, Path: rel})
	}

	for _, l := range splitMakeLogicalLines(makefile) {
		if strings.HasPrefix(strings.TrimSpace(l.Text), "#") {
			continue
		}
		for _, m := range makeDotPathRe.FindAllStringSubmatchIndex(l.Text, -1) {
			rel := l.Text[m[2]:m[3]]
			if strings.Contains(rel, "$") {
				continue
			}
			base, ok := makeBaseDirAt(l.Text, m[0])
			if !ok {
				continue
			}
			full := path.Join(base, rel)
			if !exists(full) {
				report(l.physicalLine(m[0]), l.Target, full)
			}
		}
		if !makeGoTestRe.MatchString(l.Text) {
			continue
		}
		for _, m := range makeCdRe.FindAllStringSubmatchIndex(l.Text, -1) {
			dir := l.Text[m[2]:m[3]]
			if strings.Contains(dir, "$") || strings.HasPrefix(dir, "/") {
				continue
			}
			if !exists(dir) {
				report(l.physicalLine(m[2]), l.Target, dir)
			}
		}
	}
	return findings
}

// TestMakefileTestPathsExist asserts that every `./<path>/...` pattern in the
// Makefile, and every directory a `go test` recipe `cd`s into, names a
// directory that exists.
//
// A recipe pointing at a missing directory fails loudly (`[setup failed]`,
// make exit 2) but only when someone runs it — `make -n` exits 0 — so
// thirteen targets across eight directories that had never existed in this
// repository sat red unnoticed because no workflow referenced them (#397).
// This is the check that would have caught them the day they were written.
//
// SCOPE — what this guard does NOT check: build paths. A `cd <dir>` on a
// line that runs `go build` (not `go test`) is ignored, so the dead
// `build-api` family (`cd cmd/platform-api`, with `build-all`, `run-api` and
// `integration-test-api` behind it) is invisible here on purpose: what
// `make build-all` should build is an owner decision, tracked as #411.
// Extend makeGoTestRe there once that is decided; do not assume a green run
// means every path in the Makefile resolves.
func TestMakefileTestPathsExist(t *testing.T) {
	root := repoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "Makefile"))
	require.NoError(t, err)

	exists := func(rel string) bool {
		info, statErr := os.Stat(filepath.Join(root, filepath.FromSlash(rel)))
		return statErr == nil && info.IsDir()
	}

	var lines []string
	for _, f := range scanMakefilePaths(string(data), exists) {
		lines = append(lines, f.Error())
	}
	require.Empty(t, lines,
		"these Makefile recipes name directories that do not exist. Repoint the "+
			"target at where the code lives now, or delete the target if the "+
			"capability left this repository:\n%s", strings.Join(lines, "\n"))
}

// makepathsFixture is a Makefile excerpt whose recipes exercise every
// resolution rule: a plain pattern, a docker `-w` base spanning
// continuations, a `cd` base, a `cd` into a missing directory, a make
// variable that must be ignored, a comment, and a top-level assignment.
const makepathsFixture = `# a comment naming ./pkg/commented/... must be ignored
TEST_PKGS := ./pkg/present/...

.PHONY: test-gone
test-gone:
	go test -v -count=1 ./pkg/gone/...

integration-test-stress: build-devcontainer
	@docker run --rm \
		-v $(PWD):/workspace \
		-w /workspace/test/integration/sdn \
		$(DEVCONTAINER_IMAGE) \
		go test -v ./stress/...

test-ntp-sdk:
	cd sdk/go && go test -count=1 ./services/ntp/... && \
		go test -count=1 ./transport/...

test-tpm-cli:
	rm -rf pkg/cmd/tpm/trusted-data
	cd pkg/cmd/tpm && go test -v -run ^Test_EK$$

test-var:
	go test ./$(PKG)/...
	cd $(DIR) && go test ./...

build-api:
	cd cmd/platform-api; \
	go build -o ../../platform-api
`

// makepathsFixtureTree is the set of directories the fixture may reference
// that exist; everything else is missing.
var makepathsFixtureTree = map[string]bool{
	"pkg/present":                 true,
	"test/integration/sdn/stress": true,
	"sdk/go":                      true,
	"sdk/go/services/ntp":         true,
	"sdk/go/transport":            true,
}

// TestScanMakefilePathsFindsMissing is the positive control: the scanner must
// report a missing `./<path>/...` and a missing `go test` cd, at the right
// physical line and target, and nothing else.
func TestScanMakefilePathsFindsMissing(t *testing.T) {
	exists := func(rel string) bool { return makepathsFixtureTree[rel] }
	findings := scanMakefilePaths(makepathsFixture, exists)

	require.Equal(t, []MissingMakePathError{
		{Line: 6, Target: "test-gone", Path: "pkg/gone"},
		{Line: 21, Target: "test-tpm-cli", Path: "pkg/cmd/tpm"},
	}, findings)
	require.Equal(t, "Makefile:6: target test-gone: pkg/gone does not exist", findings[0].Error())
}

// TestScanMakefilePathsResolvesBases is the negative control: when every
// directory exists, the `-w /workspace/<dir>` base across continuations, the
// `cd <dir> &&` base, and the second command after a continuation all
// resolve without a finding, and variables, comments and non-test `cd`s are
// ignored.
func TestScanMakefilePathsResolvesBases(t *testing.T) {
	var asked []string
	exists := func(rel string) bool {
		asked = append(asked, rel)
		return true
	}
	findings := scanMakefilePaths(makepathsFixture, exists)
	require.Empty(t, findings)
	require.ElementsMatch(t, []string{
		"pkg/present",
		"pkg/gone",
		"test/integration/sdn/stress",
		"sdk/go/services/ntp",
		"sdk/go/transport",
		"sdk/go",
		"pkg/cmd/tpm",
	}, asked)
}

// TestScanMakefilePathsRejectsInvalidInput covers the degenerate inputs: an
// empty Makefile, a Makefile with no recipes, and a `cd` that is not followed
// by `go test` produce no findings.
func TestScanMakefilePathsRejectsInvalidInput(t *testing.T) {
	never := func(string) bool { return false }
	require.Empty(t, scanMakefilePaths("", never))
	require.Empty(t, scanMakefilePaths("VAR := 1\n# only ./pkg/x/... in a comment\n", never))
	require.Empty(t, scanMakefilePaths("build:\n\tcd cmd/gone && go build ./...\n", never),
		"a build cd is not a test path")
}
