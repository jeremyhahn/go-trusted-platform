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
	log, err := parseSuiteLog("suite.log", defaultModule, strings.NewReader(logText))
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

func TestAMultiPackageTargetAttributesEachPackage(t *testing.T) {
	// A ./test/integration/<dir>/... target runs several packages; each
	// failure belongs to the package whose result line follows it.
	multi := target{name: "kms", pkg: "test/integration/kms/...", failed: true, body: []string{
		"?   \t" + module + "test/integration/kms/helpers\t[no test files]",
		"=== RUN   TestOK",
		"--- PASS: TestOK (0.00s)",
		"PASS",
		"ok  \t" + module + "test/integration/kms/ok\t0.5s",
		"        --- FAIL: TestKMS/gRPC/HMAC (0.01s)",
		"    --- FAIL: TestKMS/gRPC (0.01s)",
		"--- FAIL: TestKMS (0.02s)",
		"FAIL",
		"FAIL\t" + module + "test/integration/kms\t1.0s",
		"    --- FAIL: TestIAMCLI/CreateRole (0.01s)",
		"FAIL",
		"FAIL\t" + module + "test/integration/kms/sub\t1.0s",
	}}
	v := check(t, testBaseline, suiteOutput(multi))
	assert.True(t, v.gating())
	assert.Empty(t, v.Unattributable)
	assert.Equal(t, []failure{{Package: "test/integration/kms/sub", Name: "TestIAMCLI/CreateRole"}}, v.Unlisted)
	require.Len(t, v.Hits, 1)
	assert.Equal(t, "TestKMS/gRPC/HMAC", v.Hits[0].Name)
}

// The sdn target's two package patterns and its section lines, as run_test
// printed them in CI job 280944 (#973, bebfac996).
const (
	sdnPatterns     = "test/integration/sdn/ ./test/integration/sdn/mock_bgp/..."
	sdnStartLine    = "--- Testing ./test/integration/sdn/ ./test/integration/sdn/mock_bgp/... (sdn) ---"
	sdnEndLine      = "--- FAIL: ./test/integration/sdn/ ./test/integration/sdn/mock_bgp/... ---"
	sdnStressLine   = "--- Testing ./test/integration/sdn/stress/... (sdn-stress) ---"
	sdnTestBaseline = "# kind\tpackage\tname\tupstream\tclosing_release\n" +
		"test\ttest/integration/sdn\tTestSDNFlows/OVS/Install\tgo-quicbaas#1\tfirst go-quicbaas tag closing #1\n" +
		"test\ttest/integration/sdn/mock_bgp\tTestMockBGP/Peer\tgo-quicbaas#2\tfirst go-quicbaas tag closing #2\n"
)

// sdnTarget is the sdn target failing in both of its packages: bgpFailLines
// are the failed tests of test/integration/sdn/mock_bgp.
func sdnTarget(bgpFailLines ...string) target {
	body := []string{
		"    --- FAIL: TestSDNFlows/OVS/Install (0.01s)",
		"--- FAIL: TestSDNFlows (0.02s)",
		"FAIL",
		"FAIL\t" + module + "test/integration/sdn\t3.0s",
	}
	body = append(body, bgpFailLines...)
	body = append(body, "FAIL", "FAIL\t"+module+"test/integration/sdn/mock_bgp\t1.0s", "FAIL")
	return target{name: "sdn", pkg: sdnPatterns, body: body, failed: true}
}

func TestAMultiPathTargetWithOnlyListedFailuresPasses(t *testing.T) {
	stress := target{name: "sdn-stress", pkg: "test/integration/sdn/stress/..."}
	logText := suiteOutput(sdnTarget("    --- FAIL: TestMockBGP/Peer (0.01s)", "--- FAIL: TestMockBGP (0.01s)"), stress)
	require.Contains(t, logText, "\n"+sdnStartLine+"\n")
	require.Contains(t, logText, "\n"+sdnEndLine+"\n")
	require.Contains(t, logText, "\n"+sdnStressLine+"\n")

	v := check(t, sdnTestBaseline, logText)
	assert.False(t, v.gating())
	assert.Empty(t, v.Unattributable)
	assert.Empty(t, v.Unlisted)
	require.Len(t, v.Hits, 2)
	assert.Equal(t, "test/integration/sdn", v.Hits[0].Package)
	assert.Equal(t, "TestSDNFlows/OVS/Install", v.Hits[0].Name)
	assert.Equal(t, "test/integration/sdn/mock_bgp", v.Hits[1].Package)
	assert.Equal(t, "TestMockBGP/Peer", v.Hits[1].Name)
}

func TestAMultiPathTargetWithAnUnlistedLeafGatesAndNamesIt(t *testing.T) {
	logText := suiteOutput(sdnTarget(
		"    --- FAIL: TestMockBGP/Peer (0.01s)",
		"    --- FAIL: TestMockBGP/Withdraw (0.01s)",
		"--- FAIL: TestMockBGP (0.02s)",
	))
	v := check(t, sdnTestBaseline, logText)
	assert.True(t, v.gating())
	assert.Empty(t, v.Unattributable)
	assert.Equal(t, []failure{{Package: "test/integration/sdn/mock_bgp", Name: "TestMockBGP/Withdraw"}}, v.Unlisted)
	require.Len(t, v.Hits, 2)
}

func TestAMultiPathSectionWithNoClosingLineGates(t *testing.T) {
	logText := sdnStartLine + "\n" +
		"    --- FAIL: TestSDNFlows/OVS/Install (0.01s)\n" +
		"--- FAIL: TestSDNFlows (0.02s)\n" +
		"FAIL\n" +
		"FAIL\t" + module + "test/integration/sdn\t3.0s\n" +
		sdnStressLine + "\n"
	v := check(t, sdnTestBaseline, logText)
	assert.True(t, v.gating())
	log, err := parseSuiteLog("suite.log", defaultModule, strings.NewReader(logText))
	require.NoError(t, err)
	require.Contains(t, log.sections, "sdn")
	assert.Equal(t, "test/integration/sdn/ test/integration/sdn/mock_bgp/...", log.sections["sdn"].Pattern)
	assert.False(t, log.sections["sdn"].Ended)
	assert.Contains(t, log.sections["sdn"].Problems, "the section ended without the runner's PASS/FAIL line")
}

func TestPackagePatterns(t *testing.T) {
	assert.Equal(t, "test/integration/iam", packagePatterns("./test/integration/iam"))
	assert.Equal(t, "test/integration/sdn/ test/integration/sdn/mock_bgp/...",
		packagePatterns("./test/integration/sdn/ ./test/integration/sdn/mock_bgp/..."))
	assert.Equal(t, packagePatterns(sdnPatterns), packagePatterns("./"+sdnPatterns))
}

func TestPackagePatternsBlankOrDifferentInput(t *testing.T) {
	assert.Equal(t, "", packagePatterns(""))
	assert.Equal(t, "", packagePatterns("   "))
	// A pattern missing from the end line never closes the section.
	assert.NotEqual(t, packagePatterns("./test/integration/sdn/ ./test/integration/sdn/mock_bgp/..."),
		packagePatterns("./test/integration/sdn/"))
}

func TestFailuresBeforeAPassingPackageGate(t *testing.T) {
	odd := target{name: "kms", pkg: "test/integration/kms/...", failed: true, body: []string{
		"        --- FAIL: TestKMS/gRPC/HMAC (0.01s)",
		"ok  \t" + module + "test/integration/kms\t1.0s",
		"    --- FAIL: TestIAMCLI/CreateRole (0.01s)",
		"FAIL",
		"FAIL\t" + module + "test/integration/iam\t1.0s",
	}}
	v := check(t, testBaseline, suiteOutput(odd))
	assert.True(t, v.gating())
	assert.Contains(t, v.Unattributable[0], "before a passing package's result")
}

func TestFailuresWithNoPackageResultGate(t *testing.T) {
	cut := target{name: "iam", pkg: "test/integration/iam", failed: true, body: []string{
		"    --- FAIL: TestIAMCLI/CreateRole (0.01s)",
		"FAIL",
	}}
	v := check(t, testBaseline, suiteOutput(cut))
	assert.True(t, v.gating())
	assert.Contains(t, v.Unattributable[0], "no package FAIL line")
}

// ffdemoBaseline lists the two failing leaves of testdata/failing-package.log.
const ffdemoBaseline = "# kind\tpackage\tname\tupstream\tclosing_release\n" +
	"test\ttest/integration/ffdemo\tTestCLI/Create\tgo-quicbaas#1\tgo-quicbaas v9\n" +
	"test\ttest/integration/ffdemo\tTestCLI/Get\tgo-quicbaas#1\tgo-quicbaas v9\n"

// readFixture returns a testdata log: real go test -v output inside the
// runner's framing, ending with the binary's FAIL, go test's package line
// and the go test command's own trailing FAIL.
func readFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	return string(data)
}

func TestARealFailingPackageWithEveryLeafListedPasses(t *testing.T) {
	v := check(t, ffdemoBaseline, readFixture(t, "failing-package.log"))
	assert.False(t, v.gating(), "unlisted %v, unattributable %v", v.Unlisted, v.Unattributable)
	assert.Len(t, v.Hits, 2)
}

func TestARealFailingPackageWithALeafUnlistedNamesOnlyThatLeaf(t *testing.T) {
	baselineText := strings.Replace(ffdemoBaseline, "test\ttest/integration/ffdemo\tTestCLI/Get\tgo-quicbaas#1\tgo-quicbaas v9\n", "", 1)
	v := check(t, baselineText, readFixture(t, "failing-package.log"))
	assert.True(t, v.gating())
	assert.Empty(t, v.Unattributable)
	assert.Equal(t, []failure{{Package: "test/integration/ffdemo", Name: "TestCLI/Get"}}, v.Unlisted)
}

// sectionProblems parses one runner section around body and returns it.
func sectionProblems(t *testing.T, pkg string, body ...string) *section {
	t.Helper()
	log, err := parseSuiteLog("suite.log", defaultModule, strings.NewReader(suiteOutput(target{name: "t", pkg: pkg, failed: true, body: body})))
	require.NoError(t, err)
	require.Contains(t, log.sections, "t")
	return log.sections["t"]
}

// The go test command closes with its own FAIL after the last package's
// result line, whichever kind that line is (real go test -v bytes).
func TestTheCommandsTrailingFAILAfterAResultLineIsNotABinaryResult(t *testing.T) {
	cases := map[string][]string{
		"after a passing package": {
			"=== RUN   TestOK", "--- PASS: TestOK (0.00s)", "PASS",
			"ok  \t" + module + "test/integration/ffdemo/passes\t0.001s",
			"FAIL",
		},
		"after a package with no test files": {
			"--- FAIL: TestCLI (0.00s)", "    --- FAIL: TestCLI/Create (0.00s)", "FAIL",
			"FAIL\t" + module + "test/integration/ffdemo/fails\t0.002s",
			"=== RUN   TestOK", "--- PASS: TestOK (0.00s)", "PASS",
			"ok  \t" + module + "test/integration/ffdemo/passes\t0.001s",
			"?   \t" + module + "test/integration/ffdemo/notests\t[no test files]",
			"FAIL",
		},
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			s := sectionProblems(t, "test/integration/ffdemo/...", body...)
			assert.Empty(t, s.Problems)
			for _, p := range s.Failed {
				assert.True(t, p.BinaryFailed, p.Package)
			}
		})
	}
}

// Real go test -v framings that must stay problems, each followed by the
// command's trailing FAIL, which must add no problem of its own.
func TestRealBrokenPackagesStayProblems(t *testing.T) {
	pkg := module + "test/integration/ffdemo/"
	cases := map[string]struct {
		body     []string
		problems []string
	}{
		"build failed": {
			body: []string{
				"# " + pkg + "build [" + pkg + "build.test]",
				"test/integration/ffdemo/build/a_test.go:3:28: undefined: undefinedThing",
				"FAIL\t" + pkg + "build [build failed]",
				"FAIL",
			},
			problems: []string{"FAIL\t" + pkg + "build [build failed]"},
		},
		"setup failed": {
			body: []string{
				"# " + pkg + "setup",
				"test/integration/ffdemo/setup/a_test.go:4:2: no required module provides package " + module + "nope; to add it:",
				"\tgo get " + module + "nope",
				"FAIL\t" + pkg + "setup [setup failed]",
				"FAIL",
			},
			problems: []string{"FAIL\t" + pkg + "setup [setup failed]"},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s := sectionProblems(t, "test/integration/ffdemo/...", tc.body...)
			assert.Equal(t, tc.problems, s.Problems)
		})
	}
}

// A test calling os.Exit: go test prints the package line but the binary
// never printed its own FAIL. The command's trailing FAIL must not stand
// in for it.
func TestARealExitedBinaryStaysUnfinished(t *testing.T) {
	baselineText := ffdemoBaseline + "test\ttest/integration/ffdemo/exits\tTestE/Sub\tgo-quicbaas#1\tgo-quicbaas v9\n"
	exited := target{name: "ffdemo", pkg: "test/integration/ffdemo/...", failed: true, body: []string{
		"=== RUN   TestE",
		"=== RUN   TestE/Sub",
		"    a_test.go:6: x",
		"FAIL\t" + module + "test/integration/ffdemo/exits\t0.001s",
		"FAIL",
	}}
	v := check(t, baselineText, suiteOutput(exited))
	assert.True(t, v.gating())
	assert.Equal(t, []string{"ffdemo: test/integration/ffdemo/exits: the test binary did not run to the end"}, v.Unattributable)
}

// Fail-closed after a result line: a later package's failing leaves and its
// binary's FAIL, with no package line, are still a binary that died.
func TestFailuresAfterAResultLineWithNoPackageLineGate(t *testing.T) {
	s := sectionProblems(t, "test/integration/ffdemo/...",
		"ok  \t"+module+"test/integration/ffdemo/passes\t0.001s",
		"    --- FAIL: TestCLI/Create (0.00s)",
		"FAIL",
	)
	assert.Equal(t, []string{"failed tests with no package FAIL line: the test binary did not run to the end"}, s.Problems)
}

func TestAPackageOutsideTheModuleGates(t *testing.T) {
	foreign := target{name: "iam", pkg: "test/integration/iam", failed: true, body: []string{
		"    --- FAIL: TestIAMCLI/CreateRole (0.01s)",
		"FAIL",
		"FAIL\texample.com/other/test/integration/iam\t1.0s",
	}}
	v := check(t, testBaseline, suiteOutput(foreign))
	assert.True(t, v.gating())
	assert.Contains(t, v.Unattributable[0], "outside module")
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
	logText, _, found := strings.Cut(logText, summaryOpen)
	require.True(t, found)
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
	log, err := parseSuiteLog("suite.log", defaultModule, strings.NewReader(logText))
	require.NoError(t, err)
	assert.Contains(t, log.sections["iam"].Problems, "the log ended inside the section")
}

func TestEmptyLogIsRefused(t *testing.T) {
	_, err := parseSuiteLog("suite.log", defaultModule, strings.NewReader(""))
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
