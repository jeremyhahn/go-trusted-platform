package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const module = "github.com/jeremyhahn/go-trusted-platform/"

// testBaseline lists two iam leaves and one kms leaf.
const testBaseline = "# kind\tpackage\tname\tupstream\tclosing_release\n" +
	"test\ttest/integration/iam\tTestIAMCLI/CreateRole\tgo-quicbaas#1778\tfirst go-quicbaas tag closing #1778\n" +
	"test\ttest/integration/iam\tTestIAMCLI/GetRole\tgo-quicbaas#1778\tfirst go-quicbaas tag closing #1778\n" +
	"\n" +
	"test\ttest/integration/kms\tTestKMS/gRPC/HMAC\tgo-quicbaas#1777+go-xkms#1667\tfirst go-quicbaas tag closing #1777\n"

// target renders one runner section: the go test -v lines between the
// runner's "--- Testing" and "--- PASS/FAIL" lines, and a summary row.
type target struct {
	name, pkg string
	body      []string
	failed    bool
}

// failedTarget is a target whose test binary ran to the end and failed with
// the given --- FAIL lines.
func failedTarget(name, pkg string, failLines ...string) target {
	body := []string{"=== RUN   TestX"}
	body = append(body, failLines...)
	body = append(body, "FAIL", "exit status 1", "FAIL\t"+module+pkg+"\t12.345s")
	return target{name: name, pkg: pkg, body: body, failed: true}
}

// suiteOutput renders the runner's output for the targets, closing summary
// included.
func suiteOutput(targets ...target) string {
	var b strings.Builder
	anyFailed := false
	for _, t := range targets {
		b.WriteString("\n--- Testing ./" + t.pkg + " (" + t.name + ") ---\n")
		for _, line := range t.body {
			b.WriteString(line + "\n")
		}
		outcome := "PASS"
		if t.failed {
			outcome = "FAIL"
			anyFailed = true
		}
		b.WriteString("--- " + outcome + ": ./" + t.pkg + " ---\n")
	}
	b.WriteString("=== end platformd diagnostics ===\n\n")
	b.WriteString(summaryOpen + "\n")
	for _, t := range targets {
		outcome := "PASS"
		if t.failed {
			outcome = "FAIL"
		}
		b.WriteString("  " + outcome + "  " + t.name + "\n")
	}
	b.WriteString(summaryClose + "\n")
	if anyFailed {
		b.WriteString(summaryFailed + "\n")
	} else {
		b.WriteString(summaryPassed + "\n")
	}
	b.WriteString(summaryOpen + "\n")
	return b.String()
}

// check parses the baseline and the log and decides.
func check(t *testing.T, baselineText, logText string) *verdict {
	t.Helper()
	b, err := parseBaseline("foreign-failures.tsv", strings.NewReader(baselineText))
	require.NoError(t, err)
	log, err := parseSuiteLog("suite.log", strings.NewReader(logText))
	require.NoError(t, err)
	return decide(log, b)
}

func TestEveryFailureListedPasses(t *testing.T) {
	v := check(t, testBaseline, suiteOutput(
		failedTarget("iam", "test/integration/iam",
			"    --- FAIL: TestIAMCLI/CreateRole (0.01s)",
			"    --- FAIL: TestIAMCLI/GetRole (0.02s)",
			"--- FAIL: TestIAMCLI (0.03s)"),
		target{name: "dns", pkg: "test/integration/dns", body: []string{"PASS", "ok  \t" + module + "test/integration/dns\t1.0s"}},
	))
	assert.False(t, v.gating(), "unlisted %v, unattributable %v", v.Unlisted, v.Unattributable)
	assert.Len(t, v.Hits, 2)
	assert.Equal(t, []string{"go-quicbaas#1778: 2"}, v.hitsByUpstream())
}

func TestAnUnlistedFailureGatesAndIsNamed(t *testing.T) {
	v := check(t, testBaseline, suiteOutput(
		failedTarget("iam", "test/integration/iam",
			"    --- FAIL: TestIAMCLI/CreateRole (0.01s)",
			"    --- FAIL: TestIAMCLI/DeleteRole (0.01s)",
			"--- FAIL: TestIAMCLI (0.03s)"),
	))
	assert.True(t, v.gating())
	assert.Equal(t, []failure{{Package: "test/integration/iam", Name: "TestIAMCLI/DeleteRole"}}, v.Unlisted)
}

func TestAListedNameInAnotherPackageGates(t *testing.T) {
	v := check(t, testBaseline, suiteOutput(
		failedTarget("kms", "test/integration/kms", "--- FAIL: TestIAMCLI/CreateRole (0.01s)"),
	))
	assert.Equal(t, []failure{{Package: "test/integration/kms", Name: "TestIAMCLI/CreateRole"}}, v.Unlisted)
}

func TestAParentFailingOnlyThroughListedChildrenPasses(t *testing.T) {
	v := check(t, testBaseline, suiteOutput(
		failedTarget("kms", "test/integration/kms",
			"        --- FAIL: TestKMS/gRPC/HMAC (0.01s)",
			"    --- FAIL: TestKMS/gRPC (0.01s)",
			"--- FAIL: TestKMS (0.02s)"),
	))
	assert.False(t, v.gating(), "unlisted %v, unattributable %v", v.Unlisted, v.Unattributable)
}

func TestAPackageFailureWithNoFailingTestGates(t *testing.T) {
	v := check(t, testBaseline, suiteOutput(failedTarget("iam", "test/integration/iam")))
	assert.True(t, v.gating())
	require.Len(t, v.Unattributable, 1)
	assert.Contains(t, v.Unattributable[0], "iam: the package failed with no failing test")
}

func TestATimeoutPanicGatesEvenWithListedFailures(t *testing.T) {
	v := check(t, testBaseline, suiteOutput(
		failedTarget("iam", "test/integration/iam",
			"    --- FAIL: TestIAMCLI/CreateRole (0.01s)",
			"panic: test timed out after 10m0s"),
	))
	assert.True(t, v.gating())
	require.Len(t, v.Unattributable, 1)
	assert.Contains(t, v.Unattributable[0], "panic: test timed out after 10m0s")
}

func TestABuildFailureGates(t *testing.T) {
	broken := target{name: "iam", pkg: "test/integration/iam", failed: true, body: []string{
		"test/integration/iam/iam_test.go:12:2: undefined: foo",
		"FAIL\t" + module + "test/integration/iam [build failed]",
	}}
	v := check(t, testBaseline, suiteOutput(broken))
	assert.True(t, v.gating())
	assert.Contains(t, v.Unattributable[0], "[build failed]")
}

func TestATestBinaryThatDidNotFinishGates(t *testing.T) {
	// os.Exit mid-run: go test prints the package FAIL line, but the
	// binary never printed its own closing FAIL.
	exited := target{name: "iam", pkg: "test/integration/iam", failed: true, body: []string{
		"    --- FAIL: TestIAMCLI/CreateRole (0.01s)",
		"FAIL\t" + module + "test/integration/iam\t1.0s",
	}}
	v := check(t, testBaseline, suiteOutput(exited))
	assert.True(t, v.gating())
	assert.Contains(t, v.Unattributable[0], "did not run to the end")
}

func TestATargetFailingOutsideGoTestGates(t *testing.T) {
	logText := suiteOutput(target{name: "dns", pkg: "test/integration/dns", body: []string{"PASS"}})
	logText = strings.Replace(logText, "  PASS  dns\n", "  PASS  dns\n  FAIL  compute\n", 1)
	v := check(t, testBaseline, logText)
	assert.True(t, v.gating())
	assert.Contains(t, v.Unattributable[0], "compute: failed outside go test")
}

func TestAJobEntryCoversItsTarget(t *testing.T) {
	baselineText := testBaseline + "job\ttest/integration/compute\tcompute\tgo-quicbaas#1\tgo-quicbaas v9\n"
	logText := suiteOutput(target{name: "dns", pkg: "test/integration/dns", body: []string{"PASS"}})
	logText = strings.Replace(logText, "  PASS  dns\n", "  PASS  dns\n  FAIL  compute\n", 1)
	v := check(t, baselineText, logText)
	assert.False(t, v.gating(), "unattributable %v", v.Unattributable)
}

func TestALogWithoutTheSummaryGates(t *testing.T) {
	logText := suiteOutput(failedTarget("iam", "test/integration/iam", "--- FAIL: TestIAMCLI/CreateRole (0.01s)"))
	logText = logText[:strings.Index(logText, summaryOpen)]
	v := check(t, testBaseline, logText)
	assert.True(t, v.gating())
	assert.Contains(t, v.Unattributable[0], "summary is missing")
}

func TestASummaryWithNoFailedTargetGates(t *testing.T) {
	v := check(t, testBaseline, suiteOutput(target{name: "dns", pkg: "test/integration/dns", body: []string{"PASS"}}))
	assert.True(t, v.gating())
	assert.Contains(t, v.Unattributable[0], "lists no failed target")
}

func TestASectionCutOffGates(t *testing.T) {
	logText := "--- Testing ./test/integration/iam (iam) ---\n--- FAIL: TestIAMCLI/CreateRole (0.01s)\n"
	v := check(t, testBaseline, logText)
	assert.True(t, v.gating())
	log, err := parseSuiteLog("suite.log", strings.NewReader(logText))
	require.NoError(t, err)
	assert.Equal(t, []string{"the log ended inside the section"}, log.sections["iam"].Problems)
}

func TestEmptyLogIsRefused(t *testing.T) {
	_, err := parseSuiteLog("suite.log", strings.NewReader(""))
	require.ErrorIs(t, err, ErrEmptyLog)
}

func TestStaleEntriesAreReportedNotFailed(t *testing.T) {
	v := check(t, testBaseline, suiteOutput(
		failedTarget("iam", "test/integration/iam", "    --- FAIL: TestIAMCLI/CreateRole (0.01s)"),
	))
	assert.False(t, v.gating())
	require.Len(t, v.Stale, 2)
	assert.Equal(t, "TestIAMCLI/GetRole", v.Stale[0].Name)
	assert.Equal(t, "TestKMS/gRPC/HMAC", v.Stale[1].Name)

	var stdout, stderr bytes.Buffer
	assert.Equal(t, exitOK, report(v, &stdout, &stderr))
	assert.Contains(t, stdout.String(), "notice: 2 baseline entries did not fail in this run")
	assert.Empty(t, stderr.String())
}

func TestLeaves(t *testing.T) {
	got := leaves([]string{"A/B/C", "A/B", "A", "A/BC", "D"})
	assert.Equal(t, []string{"A/B/C", "A/BC", "D"}, got)
	assert.Empty(t, leaves(nil))
}

func TestParseBaselineRejectsMalformedRows(t *testing.T) {
	cases := map[string]string{
		"too few columns": "test\ttest/integration/iam\tTestA\tgo-quicbaas#1\n",
		"unknown kind":    "suite\ttest/integration/iam\tTestA\tgo-quicbaas#1\tv1\n",
		"wildcard pkg":    "test\ttest/integration/*\tTestA\tgo-quicbaas#1\tv1\n",
		"spaced name":     "test\ttest/integration/iam\tTestA B\tgo-quicbaas#1\tv1\n",
		"no issue":        "test\ttest/integration/iam\tTestA\tgo-quicbaas pin class\tv1\n",
		"no release":      "test\ttest/integration/iam\tTestA\tgo-quicbaas#1\t \n",
		"duplicate test":  "test\ttest/integration/iam\tTestA\tgo-quicbaas#1\tv1\ntest\ttest/integration/iam\tTestA\tgo-quicbaas#2\tv2\n",
		"duplicate job":   "job\ttest/integration/compute\tcompute\tgo-quicbaas#1\tv1\njob\ttest/integration/compute\tcompute\tgo-quicbaas#1\tv1\n",
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := parseBaseline("foreign-failures.tsv", strings.NewReader("# header\n"+text))
			var be *BaselineError
			require.ErrorAs(t, err, &be)
			assert.GreaterOrEqual(t, be.Line, 2)
			assert.Contains(t, err.Error(), "foreign-failures.tsv:")
		})
	}
}

// TestRepositoryBaselineParses holds the committed baseline to ruling 125:
// every row parses, names an upstream issue and carries a closing release.
func TestRepositoryBaselineParses(t *testing.T) {
	b, err := loadBaseline(filepath.Join("..", "..", ".github", "foreign-failures.tsv"))
	require.NoError(t, err)
	require.NotEmpty(t, b.entries)
	for _, e := range b.entries {
		assert.Regexp(t, upstreamRe, e.Upstream, "line %d", e.Line)
		assert.NotEmpty(t, e.ClosingRelease, "line %d", e.Line)
	}
}

func TestRun(t *testing.T) {
	dir := t.TempDir()
	baselinePath := filepath.Join(dir, "foreign-failures.tsv")
	require.NoError(t, os.WriteFile(baselinePath, []byte(testBaseline), 0o600))
	write := func(name, text string) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, []byte(text), 0o600))
		return path
	}
	listed := write("listed.log", suiteOutput(failedTarget("iam", "test/integration/iam", "--- FAIL: TestIAMCLI/CreateRole (0.01s)")))
	unlisted := write("unlisted.log", suiteOutput(failedTarget("iam", "test/integration/iam", "--- FAIL: TestIAMCLI/Other (0.01s)")))
	empty := write("empty.log", "")
	badBaseline := write("bad.tsv", "test\tonly-two\n")

	cases := []struct {
		name   string
		args   []string
		code   int
		stdout string
		stderr string
	}{
		{"listed", []string{"-baseline", baselinePath, listed}, exitOK, "go-quicbaas#1778: 1", ""},
		{"unlisted", []string{"-baseline", baselinePath, unlisted}, exitGating, "", "FAIL not in the baseline: test/integration/iam TestIAMCLI/Other"},
		{"empty log", []string{"-baseline", baselinePath, empty}, exitUsage, "", "log is empty"},
		{"missing log", []string{"-baseline", baselinePath, filepath.Join(dir, "absent.log")}, exitUsage, "", "reading"},
		{"malformed baseline", []string{"-baseline", badBaseline, listed}, exitUsage, "", "bad.tsv:1"},
		{"missing baseline", []string{"-baseline", filepath.Join(dir, "absent.tsv"), listed}, exitUsage, "", "reading"},
		{"no log argument", []string{"-baseline", baselinePath}, exitUsage, "", "usage"},
		{"unknown flag", []string{"-nope"}, exitUsage, "", "flag provided but not defined"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			assert.Equal(t, tc.code, run(tc.args, &stdout, &stderr), "stderr: %s", stderr.String())
			assert.Contains(t, stdout.String(), tc.stdout)
			assert.Contains(t, stderr.String(), tc.stderr)
		})
	}
}
