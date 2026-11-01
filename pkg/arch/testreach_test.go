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
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// deliberatelyUnreached names every package that contains _test.go files and
// whose OWN tests run in NO stage of any workflow and under NO path the
// integration runner executes, with the reason it is kept out.
//
// This is the terminal list. Nothing here is "covered elsewhere": the
// integration runner exercises subsystems end-to-end from test/integration/
// and never compiles these packages' _test.go files, and no workflow invokes
// it anyway (#359). A reason that names a destination is rejected by
// TestDeliberatelyUnreachedHasNoStaleEntries, because a destination that does
// not exist is what let this gap survive five rediscoveries.
//
// THIS LIST MAY ONLY SHRINK. A package added here needs a reason that survives
// review; a package that becomes reachable — a stage runs it, or TEST_UNIT_PKGS
// re-adds it — comes off it, and the ratchet fails until it does.
var deliberatelyUnreached = map[string]string{
	"pkg/api/grpc":                    "gRPC server harness; unrouted, see #34",
	"pkg/cli":                         "needs a running platformd",
	"pkg/cli/commands":                "needs a running platformd; the SUBpackages are reached (#319)",
	"pkg/compute":                     "needs an OCI runtime",
	"pkg/compute/podman":              "needs an OCI runtime",
	"pkg/dns/dao":                     "datastore harness; unrouted, see #34",
	"pkg/initrd":                      "static initramfs build; needs a TPM, LUKS and block devices",
	"pkg/installer":                   "needs root and real block devices",
	"pkg/installer/alpine":            "needs root and real block devices",
	"pkg/ipxe":                        "needs a bound TFTP/HTTP listener",
	"pkg/iso":                         "needs cpio/zstd/grub",
	"pkg/platform/system":             "needs root",
	"pkg/qemu":                        "needs QEMU",
	"pkg/sdn/gateway/commands":        "needs a running gatewayd",
	"pkg/sdn/netlink":                 "needs CAP_NET_ADMIN",
	"pkg/store/datastore":             "datastore harness; unrouted, see #34",
	"pkg/storage/luks":                "needs cryptsetup",
	"pkg/testenv":                     "test scaffolding, not a unit under test",
	"pkg/uefi/firmware":               "needs a TPM",
	"pkg/uki":                         "needs sbsign/objcopy",
	"pkg/webservice":                  "needs a running platformd",
	"pkg/webservice/v1/rest/platform": "needs a running platformd",
	"pkg/webservice/v1/test":          "test scaffolding, not a unit under test",
	"pkg/webservice/v1/webauthn":      "needs a running platformd",
	"pkg/boot/commands":               "needs root",
}

// UnreachedPackageError reports one defect in the repository's test-execution
// record: a test-bearing package no stage runs that the list does not
// acknowledge, or a list entry that has gone stale.
type UnreachedPackageError struct {
	// File is the repo-relative file the finding points at.
	File string

	// Line is the 1-based line in File, or 0 when unknown.
	Line int

	// Package is the repo-relative package directory.
	Package string

	// Reason says what is wrong and what fixes it.
	Reason string
}

// Error renders the finding as a clickable file:line reference.
func (e UnreachedPackageError) Error() string {
	return fmt.Sprintf("%s:%d: %s: %s", e.File, e.Line, e.Package, e.Reason)
}

// TestReachLoadError reports a repository file the reachability measurement
// could not read or parse.
type TestReachLoadError struct {
	// File is the repo-relative file.
	File string

	// Line is the 1-based line, or 0 when the whole file is at fault.
	Line int

	// Detail says what was wrong.
	Detail string

	// Err is the underlying error, if any.
	Err error
}

// Error renders the load failure as a file:line reference.
func (e TestReachLoadError) Error() string {
	msg := fmt.Sprintf("%s:%d: %s", e.File, e.Line, e.Detail)
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

// Unwrap exposes the underlying error.
func (e TestReachLoadError) Unwrap() error { return e.Err }

const (
	makefilePath  = "Makefile"
	workflowsDir  = ".github/workflows"
	runnerPath    = "build/docker/devcontainer/run-integration-tests.sh"
	reachListFile = "pkg/arch/testreach_test.go"
)

var (
	// workflowRunRe matches a `run:` step and captures its inline command, or
	// a block-scalar indicator (`|`, `>`) when the commands follow.
	workflowRunRe = regexp.MustCompile(`^(\s*)(?:- )?run:\s*(.*)$`)

	// makeInvocationRe captures the words after a `make` command up to the
	// next shell separator.
	makeInvocationRe = regexp.MustCompile(`(?:^|[\s;&|(])make\s+([^\n;&|)]+)`)

	// goTestInvocationRe captures the arguments of a direct `go test`.
	goTestInvocationRe = regexp.MustCompile(`(?:^|[\s;&|(])go\s+test\s+([^\n;&|)]+)`)

	// dotPkgPathRe matches a `./pkg/...`-style path argument.
	dotPkgPathRe = regexp.MustCompile(`\./((?:pkg|cmd)(?:/[A-Za-z0-9_-][A-Za-z0-9_.-]*)*)/?(\.\.\.)?`)

	// shellCommentRe matches a whole-line shell comment.
	shellCommentRe = regexp.MustCompile(`(?m)^\s*#.*$`)

	// destinationClaimRe rejects a list reason that claims the package's tests
	// run somewhere. The list records packages whose tests run NOWHERE.
	//
	// Why this exists (#359): for months the Makefile and ci.yml said the
	// excluded packages were "tested via integration tests" / "covered by
	// make integration-test". Measured, the runner executes zero ./pkg paths
	// and no workflow invokes it. A destination that does not exist is what
	// let the gap survive five rediscoveries — an exclusion with a stated
	// destination reads as routed. Do not relax this regex to admit one; add
	// the stage that actually runs the package and delete the entry instead.
	destinationClaimRe = regexp.MustCompile(`(?i)\b(covered|integration|tested via|run by|runs? in|re-added)\b`)
)

// testReach is the measured test-execution surface of one repository tree:
// which package directories some stage of some workflow, or some path in the
// integration runner, actually runs the tests of.
type testReach struct {
	root        string
	excludeLine int
	excludeRe   *regexp.Regexp
	unitPkgs    map[string]bool

	// runsMakeTest is true when at least one workflow step invokes `make
	// test` or `make test-race`, the only stages that discover packages.
	runsMakeTest bool

	// stages describes every workflow step and runner path that runs tests,
	// for the failure message.
	stages []string

	// explicitDirs are package directories named directly by a workflow
	// (`make test-pkg PKG=./pkg/x/`, `go test ./pkg/x`) or by the runner.
	explicitDirs map[string]bool

	// explicitTrees are directories named with a `/...` suffix; every
	// package beneath one is reached.
	explicitTrees []string
}

// repoRoot walks up from this package to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for i := 0; i < 8; i++ {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not locate the module root")
	return ""
}

// makeVarAt extracts a simple `NAME := value` assignment from Makefile text
// and returns the value with its 1-based line, or ok=false when absent.
func makeVarAt(makefile, name string) (value string, line int, ok bool) {
	re := regexp.MustCompile(`(?m)^` + name + `\s*:=\s*(.*)$`)
	loc := re.FindStringSubmatchIndex(makefile)
	if loc == nil {
		return "", 0, false
	}
	// Recipes escape `$` as `$$`; the shell sees a single `$`.
	value = strings.ReplaceAll(makefile[loc[2]:loc[3]], "$$", "$")
	return value, 1 + strings.Count(makefile[:loc[0]], "\n"), true
}

// workflowCommands returns the shell text of every `run:` step in every
// workflow file under root, each prefixed for the stage description.
func workflowCommands(root string) (map[string]string, error) {
	files, err := filepath.Glob(filepath.Join(root, workflowsDir, "*.yml"))
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, f := range files {
		data, readErr := os.ReadFile(f)
		if readErr != nil {
			return nil, readErr
		}
		lines := strings.Split(string(data), "\n")
		var b strings.Builder
		for i := 0; i < len(lines); i++ {
			m := workflowRunRe.FindStringSubmatch(lines[i])
			if m == nil {
				continue
			}
			rest := strings.TrimSpace(m[2])
			if rest != "|" && rest != ">" && !strings.HasPrefix(rest, "|") && !strings.HasPrefix(rest, ">") {
				b.WriteString(rest + "\n")
				continue
			}
			indent := len(m[1])
			for i+1 < len(lines) {
				next := lines[i+1]
				if strings.TrimSpace(next) != "" && len(next)-len(strings.TrimLeft(next, " ")) <= indent {
					break
				}
				i++
				b.WriteString(strings.TrimSpace(next) + "\n")
			}
		}
		out[filepath.Base(f)] = b.String()
	}
	return out, nil
}

// addPath records one `./pkg/...`-style argument as an explicit destination.
func (r *testReach) addPath(arg string) {
	m := dotPkgPathRe.FindStringSubmatch(arg)
	if m == nil {
		return
	}
	dir := strings.TrimSuffix(m[1], "/")
	if m[2] != "" {
		r.explicitTrees = append(r.explicitTrees, dir)
		return
	}
	r.explicitDirs[dir] = true
}

// absorbCommands reads make and go test invocations out of shell text.
func (r *testReach) absorbCommands(source, text string) {
	for _, m := range makeInvocationRe.FindAllStringSubmatch(text, -1) {
		words := strings.Fields(m[1])
		var target string
		for _, w := range words {
			if strings.HasPrefix(w, "PKG=") {
				r.addPath(strings.TrimPrefix(w, "PKG="))
				continue
			}
			if !strings.Contains(w, "=") && !strings.HasPrefix(w, "-") && target == "" {
				target = w
			}
		}
		switch target {
		case "test", "test-race":
			r.runsMakeTest = true
			r.stages = append(r.stages, source+": make "+target)
		case "test-pkg":
			r.stages = append(r.stages, source+": make "+m[1])
		}
	}
	for _, m := range goTestInvocationRe.FindAllStringSubmatch(text, -1) {
		for _, w := range strings.Fields(m[1]) {
			r.addPath(w)
		}
		r.stages = append(r.stages, source+": go test "+m[1])
	}
}

// loadTestReach measures the tree under root.
func loadTestReach(root string) (*testReach, error) {
	data, err := os.ReadFile(filepath.Join(root, makefilePath))
	if err != nil {
		return nil, TestReachLoadError{File: makefilePath, Detail: "unreadable", Err: err}
	}
	excludeVal, excludeLine, ok := makeVarAt(string(data), "TEST_EXCLUDE")
	if !ok {
		return nil, TestReachLoadError{File: makefilePath, Detail: "TEST_EXCLUDE not found"}
	}
	excludeRe, err := regexp.Compile(excludeVal)
	if err != nil {
		return nil, TestReachLoadError{File: makefilePath, Line: excludeLine, Detail: "TEST_EXCLUDE is not a valid regexp", Err: err}
	}
	r := &testReach{
		root:         root,
		excludeLine:  excludeLine,
		excludeRe:    excludeRe,
		unitPkgs:     map[string]bool{},
		explicitDirs: map[string]bool{},
	}
	if unitVal, _, found := makeVarAt(string(data), "TEST_UNIT_PKGS"); found {
		for _, p := range strings.Fields(unitVal) {
			r.unitPkgs[strings.Trim(p, "./")] = true
		}
	}

	cmds, err := workflowCommands(root)
	if err != nil {
		return nil, TestReachLoadError{File: workflowsDir, Detail: "unreadable", Err: err}
	}
	for name, text := range cmds {
		r.absorbCommands(filepath.Join(workflowsDir, name), shellCommentRe.ReplaceAllString(text, ""))
	}

	runner, err := os.ReadFile(filepath.Join(root, runnerPath))
	if err != nil {
		return nil, TestReachLoadError{File: runnerPath, Detail: "unreadable", Err: err}
	}
	for _, m := range dotPkgPathRe.FindAllString(shellCommentRe.ReplaceAllString(string(runner), ""), -1) {
		r.addPath(m)
		r.stages = append(r.stages, runnerPath+": "+m)
	}
	return r, nil
}

// reaches reports whether some stage runs the tests of the package at rel,
// and which one.
func (r *testReach) reaches(rel string) (bool, string) {
	if r.explicitDirs[rel] {
		return true, "named by a workflow step or the runner"
	}
	for _, tree := range r.explicitTrees {
		if rel == tree || strings.HasPrefix(rel, tree+"/") {
			return true, "under ./" + tree + "/... in a workflow step or the runner"
		}
	}
	if !r.runsMakeTest {
		return false, ""
	}
	if r.unitPkgs[rel] {
		return true, "TEST_UNIT_PKGS, via make test"
	}
	if !r.excludeRe.MatchString(rel) {
		return true, "make test discovery"
	}
	return false, ""
}

// testBearingPackages lists every pkg/ and cmd/ directory under root that
// contains at least one _test.go file.
func testBearingPackages(root string) ([]string, error) {
	var pkgs []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return err
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		if rel != "pkg" && rel != "cmd" && !strings.HasPrefix(rel, "pkg/") && !strings.HasPrefix(rel, "cmd/") {
			if rel != "." {
				return filepath.SkipDir
			}
			return nil
		}
		matches, _ := filepath.Glob(filepath.Join(path, "*_test.go"))
		if len(matches) > 0 {
			pkgs = append(pkgs, rel)
		}
		return nil
	})
	sort.Strings(pkgs)
	return pkgs, err
}

// listEntryLine finds the 1-based line of a `"pkg":` entry in the list source,
// or 0 when the source is unavailable.
func listEntryLine(root, pkg string) int {
	data, err := os.ReadFile(filepath.Join(root, reachListFile))
	if err != nil {
		return 0
	}
	needle := `"` + pkg + `":`
	for i, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, needle) {
			return i + 1
		}
	}
	return 0
}

// unreachedFindings is the check. It returns one finding per test-bearing
// package that no stage runs and the list does not acknowledge, and one per
// list entry that is stale: reachable, gone, without tests, or claiming a
// destination.
func unreachedFindings(root string, list map[string]string) ([]UnreachedPackageError, error) {
	r, err := loadTestReach(root)
	if err != nil {
		return nil, err
	}
	pkgs, err := testBearingPackages(root)
	if err != nil {
		return nil, TestReachLoadError{File: "pkg/", Detail: "walk failed", Err: err}
	}
	hasTests := map[string]bool{}
	for _, p := range pkgs {
		hasTests[p] = true
	}

	stages := "no stage"
	if len(r.stages) > 0 {
		stages = strings.Join(r.stages, ", ")
	}

	var findings []UnreachedPackageError
	for _, p := range pkgs {
		if reached, _ := r.reaches(p); reached {
			continue
		}
		if _, listed := list[p]; listed {
			continue
		}
		findings = append(findings, UnreachedPackageError{
			File:    makefilePath,
			Line:    r.excludeLine,
			Package: p,
			Reason: "excluded from make test and run by no stage of any workflow " +
				"and no path in the integration runner (stages: " + stages + "). " +
				"Anchor the TEST_EXCLUDE entry that swallowed it (check for a " +
				"missing `$$`), route it, or add it to deliberatelyUnreached in " +
				reachListFile + " with the prerequisite that keeps it out",
		})
	}

	entries := make([]string, 0, len(list))
	for p := range list {
		entries = append(entries, p)
	}
	sort.Strings(entries)
	for _, p := range entries {
		reason := list[p]
		line := listEntryLine(root, p)
		switch {
		case strings.TrimSpace(reason) == "":
			findings = append(findings, UnreachedPackageError{File: reachListFile, Line: line, Package: p,
				Reason: "list entry needs a reason"})
		case destinationClaimRe.MatchString(reason):
			findings = append(findings, UnreachedPackageError{File: reachListFile, Line: line, Package: p,
				Reason: fmt.Sprintf("list entry claims a destination (%q); this list records packages whose tests run NOWHERE — name the prerequisite instead", reason)})
		}
		if _, statErr := os.Stat(filepath.Join(root, filepath.FromSlash(p))); statErr != nil {
			findings = append(findings, UnreachedPackageError{File: reachListFile, Line: line, Package: p,
				Reason: "package no longer exists — delete the entry"})
			continue
		}
		if !hasTests[p] {
			findings = append(findings, UnreachedPackageError{File: reachListFile, Line: line, Package: p,
				Reason: "package has no _test.go files, so there is nothing to reach — delete the entry"})
			continue
		}
		if reached, how := r.reaches(p); reached {
			findings = append(findings, UnreachedPackageError{File: reachListFile, Line: line, Package: p,
				Reason: "now reached by " + how + " — delete the entry"})
		}
	}
	return findings, nil
}

// TestEveryTestBearingPackageIsReached asserts that a package containing
// _test.go files is either run by some stage of some workflow (directly, or
// through `make test` discovery and TEST_UNIT_PKGS), or run by a path the
// integration runner executes, or named in deliberatelyUnreached with the
// prerequisite that keeps it out.
//
// Reachability is measured from .github/workflows/*.yml and the runner
// script, not assumed from the Makefile: ci.yml once asserted that every
// excluded package was "covered by make integration-test", which no workflow
// invoked and which runs zero ./pkg/... paths (#359). A comment cannot be
// checked; this can. If no workflow runs `make test`, every package is
// unreached and this test fails on all of them — fail-closed by design.
//
// TEST_EXCLUDE is a grep -E alternation, so an entry missing its `$` anchor is
// a SUBSTRING match that silently drops every subpackage beneath it (#319).
func TestEveryTestBearingPackageIsReached(t *testing.T) {
	findings, err := unreachedFindings(repoRoot(t), deliberatelyUnreached)
	require.NoError(t, err)

	var lines []string
	for _, f := range findings {
		if f.File == makefilePath {
			lines = append(lines, f.Error())
		}
	}
	require.Empty(t, lines, "these packages contain tests that NO stage runs:\n%s", strings.Join(lines, "\n"))
}

// TestDeliberatelyUnreachedHasNoStaleEntries is the ratchet: once a package
// becomes reachable, loses its tests, or disappears, its entry must go, and a
// reason may never claim a destination — so the list cannot quietly stop
// shrinking or start lying.
func TestDeliberatelyUnreachedHasNoStaleEntries(t *testing.T) {
	findings, err := unreachedFindings(repoRoot(t), deliberatelyUnreached)
	require.NoError(t, err)

	var lines []string
	for _, f := range findings {
		if f.File == reachListFile {
			lines = append(lines, f.Error())
		}
	}
	require.Empty(t, lines, "stale deliberatelyUnreached entries:\n%s", strings.Join(lines, "\n"))
}

// TestWorkflowsRunTheUnitSuite pins the premise the reachability model rests
// on: at least one workflow step runs `make test`, and the measured stages
// are reported so a reader of a failure can see what was counted.
func TestWorkflowsRunTheUnitSuite(t *testing.T) {
	r, err := loadTestReach(repoRoot(t))
	require.NoError(t, err)
	require.True(t, r.runsMakeTest, "no workflow step runs `make test` or `make test-race`; stages seen: %v", r.stages)
	require.NotEmpty(t, r.stages)
}

// reachFixture writes a minimal repository tree for the positive and negative
// controls: three test-bearing packages, a Makefile excluding two of them, a
// workflow, and a runner script.
func reachFixture(t *testing.T, workflow, runner string) string {
	t.Helper()
	root := t.TempDir()
	for _, p := range []string{"pkg/a", "pkg/b", "pkg/c", "pkg/notests"} {
		require.NoError(t, os.MkdirAll(filepath.Join(root, p), 0o755))
	}
	for _, p := range []string{"pkg/a", "pkg/b", "pkg/c"} {
		require.NoError(t, os.WriteFile(filepath.Join(root, p, "x_test.go"), []byte("package x\n"), 0o644))
	}
	require.NoError(t, os.WriteFile(filepath.Join(root, "go.mod"), []byte("module fixture\n"), 0o644))
	makefile := "TEST_EXCLUDE := pkg/b$$|pkg/c$$\nTEST_UNIT_PKGS := \n\ntest:\n\tgo test $$(go list ./pkg/... | grep -v -E \"$(TEST_EXCLUDE)\")\n"
	require.NoError(t, os.WriteFile(filepath.Join(root, makefilePath), []byte(makefile), 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(root, workflowsDir), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, workflowsDir, "ci.yml"), []byte(workflow), 0o644))
	require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(root, runnerPath)), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, runnerPath), []byte(runner), 0o755))
	return root
}

const (
	fixtureWorkflowMakeTest = "jobs:\n  test:\n    steps:\n      - name: Unit tests\n        run: make test\n"
	fixtureRunnerNoPkg      = "run_test ./test/integration/ca/...\n"
)

// TestUnreachedFindingsFailOnKnownUncoveredPackage is the positive control:
// with `make test` the only stage and the runner touching no ./pkg path, the
// two excluded packages are reported at the Makefile's TEST_EXCLUDE line, and
// nothing else is.
func TestUnreachedFindingsFailOnKnownUncoveredPackage(t *testing.T) {
	root := reachFixture(t, fixtureWorkflowMakeTest, fixtureRunnerNoPkg)
	findings, err := unreachedFindings(root, map[string]string{})
	require.NoError(t, err)
	require.Len(t, findings, 2)
	require.Equal(t, "pkg/b", findings[0].Package)
	require.Equal(t, "pkg/c", findings[1].Package)
	for _, f := range findings {
		require.Equal(t, makefilePath, f.File)
		require.Equal(t, 1, f.Line, "TEST_EXCLUDE is on line 1 of the fixture Makefile")
		require.Contains(t, f.Error(), "Makefile:1: "+f.Package+": excluded from make test")
	}

	// Acknowledging one leaves the other.
	findings, err = unreachedFindings(root, map[string]string{"pkg/b": "needs a TPM"})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	require.Equal(t, "pkg/c", findings[0].Package)
}

// TestUnreachedFindingsHonourEveryRoute is the negative control: each way a
// package can be reached — make test discovery, TEST_UNIT_PKGS, a `make
// test-pkg PKG=` step, a direct `go test` step in a block scalar, and a
// runner path — clears the finding for exactly that package.
func TestUnreachedFindingsHonourEveryRoute(t *testing.T) {
	cases := map[string]struct {
		workflow string
		runner   string
		want     []string
	}{
		"make test-pkg step": {
			workflow: fixtureWorkflowMakeTest + "      - run: make test-pkg PKG=./pkg/b/\n",
			runner:   fixtureRunnerNoPkg,
			want:     []string{"pkg/c"},
		},
		"go test in a block scalar": {
			workflow: fixtureWorkflowMakeTest + "      - run: |\n          echo hi\n          go test -count=1 ./pkg/c/...\n",
			runner:   fixtureRunnerNoPkg,
			want:     []string{"pkg/b"},
		},
		"runner path": {
			workflow: fixtureWorkflowMakeTest,
			runner:   fixtureRunnerNoPkg + "run_test ./pkg/b/...\n",
			want:     []string{"pkg/c"},
		},
		"runner tree covers subpackages": {
			workflow: fixtureWorkflowMakeTest,
			runner:   "run_test ./pkg/...\n",
			want:     nil,
		},
		"race job counts as the unit suite": {
			workflow: "steps:\n  - run: make test-race\n",
			runner:   fixtureRunnerNoPkg,
			want:     []string{"pkg/b", "pkg/c"},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			root := reachFixture(t, tc.workflow, tc.runner)
			findings, err := unreachedFindings(root, map[string]string{})
			require.NoError(t, err)
			var got []string
			for _, f := range findings {
				got = append(got, f.Package)
			}
			require.Equal(t, tc.want, got)
		})
	}
}

// TestUnreachedFindingsFailClosedWithoutAUnitStage asserts that when no
// workflow runs `make test`, discovery reaches nothing and every test-bearing
// package is reported — a deleted Unit-tests step turns the guard red rather
// than silently shrinking the count to zero.
func TestUnreachedFindingsFailClosedWithoutAUnitStage(t *testing.T) {
	root := reachFixture(t, "steps:\n  - run: make lint\n  - run: make build\n", fixtureRunnerNoPkg)
	findings, err := unreachedFindings(root, map[string]string{})
	require.NoError(t, err)
	var got []string
	for _, f := range findings {
		got = append(got, f.Package)
	}
	require.Equal(t, []string{"pkg/a", "pkg/b", "pkg/c"}, got)
}

// TestUnreachedFindingsRejectStaleListEntries covers every way an entry goes
// stale: reachable, gone, without tests, empty reason, destination claim.
func TestUnreachedFindingsRejectStaleListEntries(t *testing.T) {
	root := reachFixture(t, fixtureWorkflowMakeTest, fixtureRunnerNoPkg)
	findings, err := unreachedFindings(root, map[string]string{
		"pkg/a":       "needs a TPM",
		"pkg/b":       "",
		"pkg/c":       "covered by make integration-test",
		"pkg/gone":    "needs root",
		"pkg/notests": "needs swtpm",
	})
	require.NoError(t, err)

	reasons := map[string][]string{}
	for _, f := range findings {
		require.Equal(t, reachListFile, f.File)
		reasons[f.Package] = append(reasons[f.Package], f.Reason)
	}
	require.Len(t, reasons["pkg/a"], 1)
	require.Contains(t, reasons["pkg/a"][0], "now reached by make test discovery")
	require.Len(t, reasons["pkg/b"], 1)
	require.Contains(t, reasons["pkg/b"][0], "needs a reason")
	require.Len(t, reasons["pkg/c"], 1)
	require.Contains(t, reasons["pkg/c"][0], "claims a destination")
	require.Len(t, reasons["pkg/gone"], 1)
	require.Contains(t, reasons["pkg/gone"][0], "no longer exists")
	require.Len(t, reasons["pkg/notests"], 1)
	require.Contains(t, reasons["pkg/notests"][0], "no _test.go files")
}

// TestUnreachedFindingsRejectInvalidInput covers the degenerate trees: a
// Makefile without TEST_EXCLUDE, an unparseable TEST_EXCLUDE, and a missing
// runner script are errors, not empty results.
func TestUnreachedFindingsRejectInvalidInput(t *testing.T) {
	root := reachFixture(t, fixtureWorkflowMakeTest, fixtureRunnerNoPkg)

	require.NoError(t, os.WriteFile(filepath.Join(root, makefilePath), []byte("test:\n\tgo test ./...\n"), 0o644))
	_, err := unreachedFindings(root, nil)
	require.ErrorContains(t, err, "TEST_EXCLUDE not found")

	require.NoError(t, os.WriteFile(filepath.Join(root, makefilePath), []byte("TEST_EXCLUDE := pkg/(b$$\n"), 0o644))
	_, err = unreachedFindings(root, nil)
	require.ErrorContains(t, err, "Makefile:1: TEST_EXCLUDE is not a valid regexp")

	require.NoError(t, os.WriteFile(filepath.Join(root, makefilePath), []byte("TEST_EXCLUDE := pkg/b$$\n"), 0o644))
	require.NoError(t, os.Remove(filepath.Join(root, runnerPath)))
	_, err = unreachedFindings(root, nil)
	require.Error(t, err)
}
