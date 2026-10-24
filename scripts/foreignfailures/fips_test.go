package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	vpnAgent  = defaultModule + "/pkg/vpn/agent"
	app       = defaultModule + "/pkg/app"
	vpnPanic  = "TestXKMSTPM_IDevIDSignerSignsWithTheTPMKey"
	appPanic  = "TestDeviceActivation_IDevIDOverMTLS"
	fipsPanic = "crypto/hmac: use of keys shorter than 112 bits is not allowed in FIPS 140-only mode"
)

// errExit stands for a go command that exited non-zero.
var errExit = errors.New("exit status 1")

// fakeGo answers the checker's `go test -list` and `go test -run` calls.
type fakeGo struct {
	// lists are the -list output per import path.
	lists map[string]string
	// rounds are the outputs of successive reruns per import path, taken
	// first; past them, runs apply.
	rounds map[string][]fakeRound
	// runs override the rerun output per import path; unset, every
	// requested name passes.
	runs    map[string]string
	listErr error
	runErr  error
	calls   [][]string
}

// fakeRound is one rerun's output and exit error.
type fakeRound struct {
	out string
	err error
}

func (f *fakeGo) command(_ context.Context, args ...string) ([]byte, error) {
	f.calls = append(f.calls, args)
	importPath := args[len(args)-1]
	if args[3] == "-list" {
		return []byte(f.lists[importPath]), f.listErr
	}
	if rounds := f.rounds[importPath]; len(rounds) > 0 {
		f.rounds[importPath] = rounds[1:]
		return []byte(rounds[0].out), rounds[0].err
	}
	if out, ok := f.runs[importPath]; ok {
		return []byte(out), f.runErr
	}
	return []byte(passingRun(importPath, args[len(args)-2])), f.runErr
}

// runArgs are the -run patterns the checker passed, by import path.
func (f *fakeGo) runArgs() map[string]string {
	runs := map[string]string{}
	for _, args := range f.calls {
		if args[3] != "-list" {
			runs[args[len(args)-1]] = args[len(args)-2]
		}
	}
	return runs
}

// passingRun is `go test -v -run run` output in which every name passes.
func passingRun(importPath, run string) string {
	var b strings.Builder
	for _, name := range strings.Split(strings.TrimSuffix(strings.TrimPrefix(run, "^("), ")$"), "|") {
		b.WriteString("=== RUN   " + name + "\n--- PASS: " + name + " (0.00s)\n")
	}
	b.WriteString("PASS\nok  \t" + importPath + "\t0.104s\n")
	return b.String()
}

func listing(importPath string, names ...string) string {
	return strings.Join(names, "\n") + "\nok  \t" + importPath + "\t0.012s\n"
}

func newFakeGo() *fakeGo {
	return &fakeGo{lists: map[string]string{
		vpnAgent: listing(vpnAgent, "TestTPMDevice_QuoteFailure", vpnPanic, "TestXKMSTPM_OpensTheTPM",
			"TestDroppedByMakeTestSkip", "ExampleNewTPMDevice", "FuzzParseQuote", "BenchmarkSign"),
		app: listing(app, "TestApp_GetInstallerConfig_CarriesPlan", appPanic, "TestAppServices_EmbeddedSDK"),
	}}
}

func fipsEnv(f *fakeGo) environment {
	vars := map[string]string{"GOFIPS140": "latest", "GODEBUG": "x509sha1=0,fips140=only"}
	return environment{
		getenv: func(key string) string { return vars[key] },
		goCmd:  func(string) goCommand { return f.command },
	}
}

func repositoryFIPSBaseline(t *testing.T) *baseline {
	t.Helper()
	b, err := loadFIPSBaseline(filepath.Join("..", "..", ".github", "foreign-failures-fips.tsv"))
	require.NoError(t, err)
	return b
}

func fipsLog(t *testing.T, text string) *goTestLog {
	t.Helper()
	log, err := parseGoTestLog("fips.log", defaultModule, strings.NewReader(text))
	require.NoError(t, err)
	return log
}

// decideFIPSText decides text against the repository's FIPS baseline.
func decideFIPSText(t *testing.T, text string) (*verdict, []rerun) {
	t.Helper()
	return decideFIPS(fipsLog(t, text), repositoryFIPSBaseline(t))
}

// requireGates asserts v gates and one of its reasons contains want.
func requireGates(t *testing.T, v *verdict, want string) {
	t.Helper()
	require.True(t, v.gating(), "verdict: %+v", v)
	var reasons []string
	reasons = append(reasons, v.Unattributable...)
	for _, f := range v.Unlisted {
		reasons = append(reasons, f.Package+" "+f.Name)
	}
	assert.Contains(t, strings.Join(reasons, "\n"), want)
}

func TestTheTwoListedFIPSPanicsAttributeAndRerunTheirPackages(t *testing.T) {
	v, reruns := decideFIPSText(t, readFixture(t, "fips-panics.log"))
	assert.False(t, v.gating(), "verdict: %+v", v)
	assert.Len(t, v.Hits, 2)
	assert.Empty(t, v.Stale)
	assert.Equal(t, []rerun{{Package: "pkg/vpn/agent", Exclude: vpnPanic}, {Package: "pkg/app", Exclude: appPanic}}, reruns)
}

func TestTheFIPSJobPassesOnlyAfterGreenReruns(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "fips.log")
	require.NoError(t, os.WriteFile(logPath, []byte(readFixture(t, "fips-panics.log")), 0o600))
	f := newFakeGo()
	var stdout, stderr bytes.Buffer
	code := runIn(fipsEnv(f), []string{"-job", "fips", "-baseline", filepath.Join("..", "..", ".github", "foreign-failures-fips.tsv"),
		"-tags", "fips codec_cbor", "-skip-tests", "^TestDroppedByMakeTestSkip$", logPath}, &stdout, &stderr)
	require.Equal(t, exitOK, code, "stderr: %s", stderr.String())
	assert.Equal(t, map[string]string{
		vpnAgent: "^(TestTPMDevice_QuoteFailure|TestXKMSTPM_OpensTheTPM|ExampleNewTPMDevice|FuzzParseQuote)$",
		app:      "^(TestApp_GetInstallerConfig_CarriesPlan|TestAppServices_EmbeddedSDK)$",
	}, f.runArgs())
	for _, args := range f.calls {
		assert.Equal(t, []string{"test", "-tags", "fips codec_cbor"}, args[:3], "every call carries the run's tags")
		assert.NotContains(t, args, "-skip")
		assert.NotContains(t, args, "-short")
	}
	assert.Contains(t, stdout.String(), "go-quicbaas#1389+go-trusted-platform#937: 2")
	assert.Contains(t, stdout.String(), "rerun: pkg/vpn/agent: 4 other tests passed under fips140=only (all but "+vpnPanic+")")
	assert.Contains(t, stdout.String(), "rerun: pkg/app: 2 other tests passed under fips140=only (all but "+appPanic+")")
	assert.Contains(t, stdout.String(), "every FIPS failure is in the FIPS foreign-failure baseline")
	assert.Empty(t, stderr.String())
}

func TestTheSamePanicInAnUnlistedTestGates(t *testing.T) {
	text := strings.ReplaceAll(readFixture(t, "fips-panics.log"), vpnPanic, "TestXKMSTPM_Unlisted")
	v, _ := decideFIPSText(t, text)
	requireGates(t, v, "pkg/vpn/agent TestXKMSTPM_Unlisted: panicked and is not in the FIPS baseline: "+fipsPanic)
}

func TestAListedPanicInAnotherPackageGates(t *testing.T) {
	text := strings.ReplaceAll(readFixture(t, "fips-panics.log"), "go-trusted-platform/pkg/app", "go-trusted-platform/pkg/other")
	v, _ := decideFIPSText(t, text)
	requireGates(t, v, "pkg/other "+appPanic+": panicked and is not in the FIPS baseline")
}

func TestAListedPanicWithTheWrongMessageOrStackGates(t *testing.T) {
	fixture := readFixture(t, "fips-panics.log")
	cases := map[string]struct{ text, want string }{
		"another message": {
			strings.Replace(fixture, "keys shorter than 112 bits", "keys shorter than 64 bits", 1),
			`panic "crypto/hmac: use of keys shorter than 64 bits`,
		},
		"a second, nested panic": {
			strings.Replace(fixture, "\ngoroutine 620", "\tpanic: close of closed channel\n\ngoroutine 620", 1),
			`panic "close of closed channel" is not the row's`,
		},
		"no Authorize frame": {
			strings.Replace(fixture, "tpm2.(*policySession).Authorize(0x2d1facbfca80", "tpm2.(*hmacSession).Authorize(0x2d1facbfca80", 1),
			"does not pass through github.com/google/go-tpm/tpm2.(*policySession).Authorize",
		},
		"the frame only in another goroutine": {
			strings.Replace(
				strings.Replace(fixture, "tpm2.(*policySession).Authorize(0x2d1facbfca80", "tpm2.(*hmacSession).Authorize(0x2d1facbfca80", 1),
				"\tpkg/vpn/agent/tpm_host_simulator_test.go:132 +0x27\n", "\tpkg/vpn/agent/tpm_host_simulator_test.go:132 +0x27\n\ngoroutine 9 [chan receive]:\ngithub.com/google/go-tpm/tpm2.(*policySession).Authorize(0x0)\n", 1),
			"does not pass through github.com/google/go-tpm/tpm2.(*policySession).Authorize",
		},
		"not the listed test's goroutine": {
			strings.Replace(fixture, "pkg/vpn/agent."+vpnPanic+"(0x2d1fad90f208)", "pkg/vpn/agent.startBackground.func1()", 1),
			"does not pass through " + vpnAgent + "." + vpnPanic + ": the panic is not the listed test's",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			v, _ := decideFIPSText(t, tc.text)
			requireGates(t, v, tc.want)
		})
	}
}

func TestAListedTestFailingWithoutAPanicGates(t *testing.T) {
	text := "=== RUN   " + appPanic + "\n" +
		"    idevid_activation_test.go:210: activation refused\n" +
		"--- FAIL: " + appPanic + " (0.09s)\nFAIL\nFAIL\t" + app + "\t0.416s\nFAIL\n"
	v, reruns := decideFIPSText(t, text)
	requireGates(t, v, "pkg/app "+appPanic+": listed as a panic but failed without one")
	assert.Empty(t, reruns)
}

func TestAListedPanicBesideAnyOtherFailureGates(t *testing.T) {
	fixture := readFixture(t, "fips-panics.log")
	tail := "?   \tgithub.com/jeremyhahn/go-trusted-platform/pkg/version\t[no test files]\n"
	cases := map[string]struct{ extra, want string }{
		"another failing test": {
			"=== RUN   TestOther\n--- FAIL: TestOther (0.00s)\nFAIL\nFAIL\t" + defaultModule + "/pkg/dns\t0.020s\n",
			"pkg/dns TestOther",
		},
		"a build failure": {
			"FAIL\t" + defaultModule + "/pkg/dns [build failed]\n",
			"pkg/dns [build failed]",
		},
		"a timeout": {
			"=== RUN   TestSlow\npanic: test timed out after 10m0s\n\trunning tests:\n\t\tTestSlow (10m0s)\n\ngoroutine 30 [running]:\ntesting.(*M).startAlarm.func1()\n\t/usr/local/go/src/testing/testing.go:2682 +0x345\n\nFAIL\t" + defaultModule + "/pkg/dns\t600.017s\n",
			"pkg/dns: a panic with 0 failing tests",
		},
		"a killed binary": {
			"=== RUN   TestBig\n*** Test killed: ran too long (11m0s).\nFAIL\t" + defaultModule + "/pkg/dns\t660.001s\n",
			"*** Test killed",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			v, _ := decideFIPSText(t, strings.Replace(fixture, tail, tail+tc.extra, 1))
			requireGates(t, v, tc.want)
			assert.Len(t, v.Hits, 2, "the listed panics still count as hits")
		})
	}
}

func TestASecondFailingTestInAPanickedPackageGates(t *testing.T) {
	fixture := readFixture(t, "fips-panics.log")
	text := strings.Replace(fixture, "--- PASS: TestTPMDevice_QuoteFailure (0.00s)", "--- FAIL: TestTPMDevice_QuoteFailure (0.00s)", 1)
	v, _ := decideFIPSText(t, text)
	requireGates(t, v, "pkg/vpn/agent: a panic with 2 failing tests")
}

func TestAFIPSRunThatDidNotFinishGates(t *testing.T) {
	fixture := readFixture(t, "fips-panics.log")
	insidePackage, _, found := strings.Cut(fixture, "FAIL\t"+app)
	if !found {
		t.Fatalf("fixture has no %q line to cut the log before", "FAIL\t"+app)
	}
	cases := map[string]struct{ text, want string }{
		"no closing FAIL": {
			strings.TrimSuffix(fixture, "FAIL\nmake: *** [Makefile:1363: test] Error 1\n"),
			"did not finish",
		},
		"cut off inside a package": {
			insidePackage,
			"the log ends inside a package",
		},
		"nothing failed": {
			"ok  \t" + app + "\t0.416s\n",
			"no package failed",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			v, _ := decideFIPSText(t, tc.text)
			requireGates(t, v, tc.want)
		})
	}
}

func TestTheRecoveredPanicInAPassingPackageIsIgnored(t *testing.T) {
	fixture := readFixture(t, "fips-panics.log")
	log := fipsLog(t, fixture)
	assert.Contains(t, log.Passed, "pkg/api/daemon")
	for _, p := range log.Failed {
		assert.NotEqual(t, "pkg/api/daemon", p.Package)
	}

	// The same recovered panic printed raw, as the runtime prints one.
	raw := strings.Replace(fixture, "--- PASS: TestQUICHandler_RecoverGuard_PanicInHandler",
		"panic: deliberate panic in ListNetworkZones to test recover() guard\n\ngoroutine 23437 [running]:\nruntime/debug.Stack()\n\t/usr/local/go/src/runtime/debug/stack.go:26 +0x5e\n\n--- PASS: TestQUICHandler_RecoverGuard_PanicInHandler", 1)
	v, reruns := decideFIPSText(t, raw)
	assert.False(t, v.gating(), "verdict: %+v", v)
	assert.Len(t, reruns, 2)
}

func TestAFailingRerunGates(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "fips.log")
	require.NoError(t, os.WriteFile(logPath, []byte(readFixture(t, "fips-panics.log")), 0o600))
	cases := map[string]struct {
		setup func(*fakeGo)
		want  string
	}{
		"a rerun test fails": {func(f *fakeGo) {
			f.runs = map[string]string{app: "=== RUN   TestApp_GetInstallerConfig_CarriesPlan\n--- FAIL: TestApp_GetInstallerConfig_CarriesPlan (0.00s)\n=== RUN   TestAppServices_EmbeddedSDK\n--- PASS: TestAppServices_EmbeddedSDK (0.00s)\nFAIL\nFAIL\t" + app + "\t0.104s\nFAIL\n"}
			f.runErr = errExit
		}, "pkg/app: the rerun of its other tests under fips140=only failed (exit status 1)"},
		"a rerun panics again": {func(f *fakeGo) {
			f.runs = map[string]string{app: "=== RUN   TestApp_GetInstallerConfig_CarriesPlan\n--- FAIL: TestApp_GetInstallerConfig_CarriesPlan (0.00s)\npanic: " + fipsPanic + " [recovered, repanicked]\n\ngoroutine 7 [running]:\n\nFAIL\t" + app + "\t0.104s\nFAIL\n"}
			f.runErr = errExit
		}, "pkg/app: the rerun of its other tests under fips140=only failed"},
		"a rerun leaves a name out": {func(f *fakeGo) {
			f.runs = map[string]string{app: "=== RUN   TestApp_GetInstallerConfig_CarriesPlan\n--- PASS: TestApp_GetInstallerConfig_CarriesPlan (0.00s)\nPASS\nok  \t" + app + "\t0.104s\n"}
		}, "pkg/app: the rerun of its other tests under fips140=only did not run TestAppServices_EmbeddedSDK"},
		"a rerun exits 0 without a result": {func(f *fakeGo) {
			f.runs = map[string]string{app: "=== RUN   TestApp_GetInstallerConfig_CarriesPlan\n"}
		}, "did not end in one passing package result"},
		"a rerun prints nothing": {func(f *fakeGo) {
			f.runs = map[string]string{app: ""}
		}, "pkg/app: the rerun of its other tests under fips140=only printed nothing"},
		"the listing fails": {func(f *fakeGo) {
			f.listErr = errExit
		}, "could not list the package's tests (exit status 1)"},
		"the listing has no result": {func(f *fakeGo) {
			f.lists[app] = "TestA\n" + appPanic + "\n"
		}, "go test -list printed no ok line"},
		"the listing lacks the panicked test": {func(f *fakeGo) {
			f.lists[app] = listing(app, "TestA")
		}, "could not exclude " + appPanic + ": go test -list does not name it"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFakeGo()
			tc.setup(f)
			var stdout, stderr bytes.Buffer
			code := runIn(fipsEnv(f), []string{"-job", "fips", "-baseline", filepath.Join("..", "..", ".github", "foreign-failures-fips.tsv"), logPath}, &stdout, &stderr)
			assert.Equal(t, exitGating, code, "stdout: %s", stdout.String())
			assert.Contains(t, stderr.String(), tc.want)
			assert.Contains(t, stderr.String(), "the FIPS unit tests failed outside the FIPS foreign-failure baseline")
		})
	}
}

func TestARerunOfAPackageWithNoOtherTestsRunsNothing(t *testing.T) {
	f := newFakeGo()
	f.lists[app] = listing(app, appPanic, "BenchmarkActivation")
	rr := &rerunner{goCmd: f.command, module: defaultModule, stdout: &bytes.Buffer{}}
	names, hidden, err := rr.round(context.Background(), rerun{Package: "pkg/app", Exclude: appPanic})
	require.NoError(t, err)
	assert.Empty(t, names)
	assert.Nil(t, hidden)
	assert.Len(t, f.calls, 1, "only the listing ran")
}

func TestAFIPSRowNeverExcusesAnIntegrationFailureNorTheReverse(t *testing.T) {
	fipsFile := filepath.Join("..", "..", ".github", "foreign-failures-fips.tsv")
	integrationFile := filepath.Join("..", "..", ".github", "foreign-failures.tsv")

	_, err := loadBaseline(fipsFile)
	var be *BaselineError
	require.ErrorAs(t, err, &be, "the Integration reader refuses the FIPS file")

	_, err = loadFIPSBaseline(integrationFile)
	require.ErrorAs(t, err, &be, "the FIPS reader refuses the Integration file")

	dir := t.TempDir()
	write := func(name, text string) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, []byte(text), 0o600))
		return path
	}
	integrationLog := write("integration.log", suiteOutput(failedTarget("app", "test/integration/app", "--- FAIL: "+appPanic+" (0.01s)")))
	fipsLogPath := write("fips.log", readFixture(t, "fips-panics.log"))
	integrationBaseline := write("foreign-failures.tsv", "test\tpkg/app\t"+appPanic+"\tgo-quicbaas#1389\tv0.16.0-alpha\n")

	var stdout, stderr bytes.Buffer
	assert.Equal(t, exitUsage, run([]string{"-baseline", fipsFile, integrationLog}, &stdout, &stderr))
	assert.Contains(t, stderr.String(), "foreign-failures-fips.tsv:")

	stderr.Reset()
	assert.Equal(t, exitUsage, runIn(fipsEnv(newFakeGo()), []string{"-job", "fips", "-baseline", integrationBaseline, fipsLogPath}, &stdout, &stderr))
	assert.Contains(t, stderr.String(), "foreign-failures.tsv:1: want 7 tab-separated columns")
}

func TestTheFIPSJobRefusesBadInvocations(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "fips.log")
	require.NoError(t, os.WriteFile(logPath, []byte(readFixture(t, "fips-panics.log")), 0o600))
	notFIPS := environment{getenv: func(string) string { return "" }, goCmd: func(string) goCommand { return newFakeGo().command }}
	cases := map[string]struct {
		env  environment
		args []string
		want string
	}{
		"outside fips140=only": {notFIPS, []string{"-job", "fips", logPath}, ErrNotFIPSMode.Error()},
		"an unknown job":       {fipsEnv(newFakeGo()), []string{"-job", "nightly", logPath}, `"nightly"`},
		"a bad -skip-tests":    {fipsEnv(newFakeGo()), []string{"-job", "fips", "-skip-tests", "Test(", logPath}, "Test("},
		"a missing log":        {fipsEnv(newFakeGo()), []string{"-job", "fips", logPath + ".absent"}, "reading"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			tc.args = append([]string{"-baseline", filepath.Join("..", "..", ".github", "foreign-failures-fips.tsv")}, tc.args...)
			assert.Equal(t, exitUsage, runIn(tc.env, tc.args, &stdout, &stderr))
			assert.Contains(t, stderr.String(), tc.want)
		})
	}
}

func TestFIPSOnly(t *testing.T) {
	cases := []struct {
		gofips, godebug string
		want            bool
	}{
		{"latest", "fips140=only", true},
		{"v1.0.0", "x509sha1=1, fips140=only", true},
		{"", "fips140=only", false},
		{"latest", "fips140=on", false},
		{"latest", "fips140=onlyish", false},
		{"latest", "", false},
	}
	for _, tc := range cases {
		vars := map[string]string{"GOFIPS140": tc.gofips, "GODEBUG": tc.godebug}
		assert.Equal(t, tc.want, fipsOnly(func(key string) string { return vars[key] }), "GOFIPS140=%q GODEBUG=%q", tc.gofips, tc.godebug)
	}
}

func TestExecGo(t *testing.T) {
	out, err := execGo("go")(context.Background(), "env", "GOOS")
	require.NoError(t, err)
	assert.NotEmpty(t, strings.TrimSpace(string(out)))

	_, err = execGo(filepath.Join(t.TempDir(), "no-such-go"))(context.Background(), "version")
	assert.Error(t, err)
}

func TestParseFIPSBaselineRejectsMalformedRows(t *testing.T) {
	row := func(fields ...string) string { return strings.Join(fields, "\t") + "\n" }
	good := []string{"panic", "pkg/app", appPanic, "go-quicbaas#1389", "v0.16.0-alpha", "github.com/google/go-tpm/tpm2.(*policySession).Authorize", fipsPanic}
	with := func(i int, value string) string {
		fields := append([]string(nil), good...)
		fields[i] = value
		return row(fields...)
	}
	cases := map[string]string{
		"an Integration row":  row("test", "pkg/app", appPanic, "go-quicbaas#1389", "v0.16.0-alpha"),
		"a job row":           with(0, "job"),
		"a test row":          with(0, "test"),
		"a wildcard package":  with(1, "pkg/*"),
		"a subtest":           with(2, appPanic+"/sub"),
		"a wildcard name":     with(2, "TestDevice.*"),
		"no issue":            with(3, "go-quicbaas pin class"),
		"no release":          with(4, " "),
		"a frame with args":   with(5, "github.com/google/go-tpm/tpm2.(*policySession).Authorize(0x0)"),
		"a frame with spaces": with(5, "go tpm"),
		"no message":          with(6, " "),
		"a duplicate row":     row(good...) + row(good...),
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := parseFIPSBaseline("foreign-failures-fips.tsv", strings.NewReader("# header\n"+text))
			var be *BaselineError
			require.ErrorAs(t, err, &be)
			assert.GreaterOrEqual(t, be.Line, 2)
			assert.Contains(t, err.Error(), "foreign-failures-fips.tsv:")
		})
	}
	b, err := parseFIPSBaseline("foreign-failures-fips.tsv", strings.NewReader("# header\n"+row(good...)))
	require.NoError(t, err)
	assert.Equal(t, fipsPanic, b.tests[testKey{Package: "pkg/app", Name: appPanic}].Message)
}

func TestRepositoryFIPSBaselineParses(t *testing.T) {
	b := repositoryFIPSBaseline(t)
	require.Len(t, b.entries, 5)
	for _, e := range b.entries {
		assert.Equal(t, kindPanic, e.Kind)
		assert.Equal(t, fipsPanic, e.Message)
		assert.Equal(t, "github.com/google/go-tpm/tpm2.(*policySession).Authorize", e.Frame)
		assert.Contains(t, e.Upstream, "go-quicbaas#1389")
		assert.Contains(t, e.ClosingRelease, "go-quicbaas v0.16.0-alpha")
	}
	assert.Contains(t, b.tests, testKey{Package: "pkg/vpn/agent", Name: vpnPanic})
	assert.Contains(t, b.tests, testKey{Package: "pkg/app", Name: appPanic})
	assert.Contains(t, b.tests, testKey{Package: "pkg/app", Name: appHiddenPanic})
	assert.Contains(t, b.tests, testKey{Package: "pkg/app", Name: "TestIDevIDSigner_NilPublicKey"})
	assert.Contains(t, b.tests, testKey{Package: "pkg/app", Name: "TestTPMSigner_IDevIDSignsTLS13ClientCertificateVerify"})
	assert.Equal(t, 4, b.rowsIn("pkg/app"), "the bound on a pkg/app rerun")
	assert.Equal(t, 0, b.rowsIn("pkg/dns"))
}

func TestTheSkipPatternOnlyDropsWhatItMatches(t *testing.T) {
	rr := &rerunner{module: defaultModule, skip: regexp.MustCompile(`^TestDroppedByMakeTestSkip$`)}
	names, err := rr.others(rerun{Package: "pkg/vpn/agent", Exclude: vpnPanic}, vpnAgent, []byte(newFakeGo().lists[vpnAgent]))
	require.NoError(t, err)
	assert.Equal(t, []string{"TestTPMDevice_QuoteFailure", "TestXKMSTPM_OpensTheTPM", "ExampleNewTPMDevice", "FuzzParseQuote"}, names)
}
