package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// appHiddenPanic is pkg/app's second listed panic: it runs after appPanic,
// so only a rerun reaches it.
const appHiddenPanic = "TestFetchProfileAndActivate_IDevIDOverMTLS"

// The pkg/app tests the hidden-panic fakes list: appPanic first, as in the
// run, then two that pass, appHiddenPanic, and one its panic hides.
const (
	appPasses = "TestApp_GetInstallerConfig_CarriesPlan"
	appSDK    = "TestAppServices_EmbeddedSDK"
	appLast   = "TestAppZ_RunsAfterTheHiddenPanic"
)

// hiddenPanicGo is a fake go command whose pkg/app lists appHiddenPanic
// and whose reruns return rounds in order.
func hiddenPanicGo(rounds ...fakeRound) *fakeGo {
	f := newFakeGo()
	f.lists[app] = listing(app, appPasses, appPanic, appSDK, appHiddenPanic, appLast)
	f.rounds = map[string][]fakeRound{app: rounds}
	return f
}

// appPanicRound is a rerun round of pkg/app in which passed pass and then
// panicked panics with the fixture's FIPS HMAC panic and stack.
func appPanicRound(t *testing.T, panicked string, passed ...string) fakeRound {
	t.Helper()
	fixture := readFixture(t, "fips-panics.log")
	start := strings.Index(fixture, "--- FAIL: "+appPanic)
	end := strings.Index(fixture, "FAIL\t"+app+"\t")
	require.True(t, start >= 0 && end > start, "the fixture carries the pkg/app panic")
	var b strings.Builder
	for _, name := range passed {
		b.WriteString("=== RUN   " + name + "\n--- PASS: " + name + " (0.00s)\n")
	}
	b.WriteString("=== RUN   " + panicked + "\n")
	b.WriteString(strings.ReplaceAll(fixture[start:end], appPanic, panicked))
	b.WriteString("FAIL\t" + app + "\t0.391s\nFAIL\n")
	return fakeRound{out: b.String(), err: errExit}
}

// hiddenPanicBaseline writes a FIPS baseline with the fixture's two rows
// and appHiddenPanic's, so these tests do not move with the repository's
// rows, which grow as reruns surface more panics.
func hiddenPanicBaseline(t *testing.T) string {
	t.Helper()
	row := func(pkg, name string) string {
		return strings.Join([]string{"panic", pkg, name, "go-quicbaas#1389+go-trusted-platform#937", "go-quicbaas v0.16.0-alpha",
			"github.com/google/go-tpm/tpm2.(*policySession).Authorize", fipsPanic}, "\t") + "\n"
	}
	path := filepath.Join(t.TempDir(), "foreign-failures-fips.tsv")
	text := row("pkg/vpn/agent", vpnPanic) + row("pkg/app", appPanic) + row("pkg/app", appHiddenPanic)
	require.NoError(t, os.WriteFile(path, []byte(text), 0o600))
	return path
}

// hiddenPanicRows loads hiddenPanicBaseline.
func hiddenPanicRows(t *testing.T) *baseline {
	t.Helper()
	b, err := loadFIPSBaseline(hiddenPanicBaseline(t))
	require.NoError(t, err)
	return b
}

// runHiddenPanic runs the FIPS job on the fixture log with f.
func runHiddenPanic(t *testing.T, f *fakeGo) (int, string, string) {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), "fips.log")
	require.NoError(t, os.WriteFile(logPath, []byte(readFixture(t, "fips-panics.log")), 0o600))
	var stdout, stderr bytes.Buffer
	code := runIn(fipsEnv(f), []string{"-job", "fips", "-baseline", hiddenPanicBaseline(t),
		"-tags", "fips codec_cbor", logPath}, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// runPatterns are the -run patterns of every rerun of importPath, in order.
func (f *fakeGo) runPatterns(importPath string) []string {
	var patterns []string
	for _, args := range f.calls {
		if args[3] != "-list" && args[len(args)-1] == importPath {
			patterns = append(patterns, args[len(args)-2])
		}
	}
	return patterns
}

func TestTwoListedPanicsInOnePackageSettleInSuccessiveRounds(t *testing.T) {
	f := hiddenPanicGo(appPanicRound(t, appHiddenPanic, appPasses, appSDK))
	code, stdout, stderr := runHiddenPanic(t, f)
	require.Equal(t, exitOK, code, "stderr: %s", stderr)
	assert.Equal(t, []string{
		"^(" + appPasses + "|" + appSDK + "|" + appHiddenPanic + "|" + appLast + ")$",
		"^(" + appPasses + "|" + appSDK + "|" + appLast + ")$",
	}, f.runPatterns(app), "round 2 runs every name but the two listed panics")
	for _, args := range f.calls {
		assert.Equal(t, []string{"test", "-tags", "fips codec_cbor"}, args[:3], "every round carries the run's tags")
		assert.NotContains(t, args, "-skip")
		assert.NotContains(t, args, "-short")
	}
	assert.Contains(t, stdout, "rerun: pkg/app: round 1 of at most 2 ran 4 tests (all but "+appPanic+"): listed "+appHiddenPanic+" panicked as its row")
	assert.Contains(t, stdout, "rerun: pkg/app: 3 other tests passed under fips140=only (all but "+appPanic+", "+appHiddenPanic+"), round 2 of at most 2")
	assert.Contains(t, stdout, "rerun: pkg/vpn/agent: 5 other tests passed under fips140=only (all but "+vpnPanic+"), round 1 of at most 1")
	assert.Contains(t, stdout, "go-quicbaas#1389+go-trusted-platform#937: 3", "the hidden row counts as a hit")
	assert.NotContains(t, stdout, "did not fail in this run")
	assert.Empty(t, stderr)
}

func TestARerunThatNeverReachesTheHiddenRowReportsItStale(t *testing.T) {
	code, stdout, stderr := runHiddenPanic(t, newFakeGo())
	require.Equal(t, exitOK, code, "stderr: %s", stderr)
	assert.Contains(t, stdout, "go-quicbaas#1389+go-trusted-platform#937: 2")
	assert.Contains(t, stdout, "notice: 1 baseline entries did not fail in this run")
	assert.Contains(t, stdout, "panic\tpkg/app\t"+appHiddenPanic+"\t")
}

func TestASecondRoundPanicGatesUnlessItIsAListedRowsAlone(t *testing.T) {
	cases := map[string]struct {
		round fakeRound
		want  string
	}{
		"an unlisted test": {
			appPanicRound(t, appLast, appPasses, appSDK),
			"pkg/app " + appLast + ": panicked and is not in the FIPS baseline: " + fipsPanic,
		},
		"another message": {
			func() fakeRound {
				r := appPanicRound(t, appHiddenPanic, appPasses)
				r.out = strings.Replace(r.out, "keys shorter than 112 bits", "keys shorter than 64 bits", 1)
				return r
			}(),
			`panic "crypto/hmac: use of keys shorter than 64 bits`,
		},
		"no Authorize frame": {
			func() fakeRound {
				r := appPanicRound(t, appHiddenPanic, appPasses)
				r.out = strings.Replace(r.out, "tpm2.(*policySession).Authorize(", "tpm2.(*hmacSession).Authorize(", 1)
				return r
			}(),
			"does not pass through github.com/google/go-tpm/tpm2.(*policySession).Authorize",
		},
		"beside another failure": {
			func() fakeRound {
				r := appPanicRound(t, appHiddenPanic, appPasses, appSDK)
				r.out = strings.Replace(r.out, "--- PASS: "+appSDK, "--- FAIL: "+appSDK, 1)
				return r
			}(),
			"pkg/app: a panic with 2 failing tests",
		},
		"beside a killed binary": {
			func() fakeRound {
				r := appPanicRound(t, appHiddenPanic, appPasses)
				r.out = strings.Replace(r.out, "=== RUN   "+appHiddenPanic, "*** Test killed: ran too long (11m0s).\n=== RUN   "+appHiddenPanic, 1)
				return r
			}(),
			"pkg/app: a panic beside *** Test killed",
		},
		"a round with no closing FAIL": {
			func() fakeRound {
				r := appPanicRound(t, appHiddenPanic, appPasses)
				r.out = strings.TrimSuffix(r.out, "FAIL\n")
				return r
			}(),
			"a panic in a round that did not finish",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := hiddenPanicGo(tc.round)
			code, stdout, stderr := runHiddenPanic(t, f)
			assert.Equal(t, exitGating, code, "stdout: %s", stdout)
			assert.Contains(t, stderr, "pkg/app: the rerun of its other tests under fips140=only failed (exit status 1): ")
			assert.Contains(t, stderr, tc.want)
			assert.Len(t, f.runPatterns(app), 1, "a gating round ends the rerun")
		})
	}
}

func TestARerunPastItsBoundGatesWithATypedError(t *testing.T) {
	// A listed panic in every round: the second repeats a test the round
	// excluded, as a misbehaving -run would. The bound stops the loop.
	f := hiddenPanicGo(appPanicRound(t, appHiddenPanic, appPasses), appPanicRound(t, appHiddenPanic, appPasses), appPanicRound(t, appHiddenPanic))
	rr := &rerunner{goCmd: f.command, module: defaultModule, baseline: hiddenPanicRows(t), stdout: &bytes.Buffer{}}
	lines, hidden, err := rr.settle(context.Background(), rerun{Package: "pkg/app", Exclude: appPanic})
	var be *RerunBoundError
	require.ErrorAs(t, err, &be)
	assert.Equal(t, &RerunBoundError{Package: "pkg/app", Bound: 2}, be)
	assert.Len(t, lines, 2, "both rounds are reported")
	assert.Len(t, hidden, 2)
	assert.Len(t, f.runPatterns(app), 2, "no round past the bound")

	code, _, stderr := runHiddenPanic(t, hiddenPanicGo(appPanicRound(t, appHiddenPanic, appPasses), appPanicRound(t, appHiddenPanic, appPasses)))
	assert.Equal(t, exitGating, code)
	assert.Contains(t, stderr, "pkg/app: the rerun of its other tests under fips140=only still panicked in a listed test after 2 rounds")
}

func TestASecondRoundExcludesOnlyNamesTheListingCarries(t *testing.T) {
	f := hiddenPanicGo(appPanicRound(t, appHiddenPanic, appPasses))
	rr := &rerunner{goCmd: f.command, module: defaultModule, baseline: hiddenPanicRows(t), stdout: &bytes.Buffer{}}
	names, err := rr.others(rerun{Package: "pkg/app", Exclude: appPanic, Hidden: []string{appHiddenPanic}}, app, []byte(f.lists[app]))
	require.NoError(t, err)
	assert.Equal(t, []string{appPasses, appSDK, appLast}, names)

	_, err = rr.others(rerun{Package: "pkg/app", Exclude: appPanic, Hidden: []string{"TestGone"}}, app, []byte(f.lists[app]))
	var re *RerunError
	require.ErrorAs(t, err, &re)
	assert.Contains(t, err.Error(), "could not exclude TestGone: go test -list does not name it")
}
