package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const firstParty = "github.com/jeremyhahn/"

// fixtureSource answers from testdata: a fixed GOPROXY, and the dir's
// list.json in place of `go list -m -u -versions -json` output.
type fixtureSource struct {
	goproxy string
}

func (s fixtureSource) GoProxy(string) (string, error) { return s.goproxy, nil }

func (s fixtureSource) List(dir string, _ []string) (map[string]listedModule, error) {
	f, err := os.Open(filepath.Join(dir, "list.json"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return decodeList(dir, f)
}

// testNow is the fixed clock release ages are measured against.
var testNow = time.Date(2026, time.October, 20, 0, 0, 0, 0, time.UTC)

func runFixture(t *testing.T, src moduleSource, dirs ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(dirs, src, testNow, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestParseGoMod(t *testing.T) {
	data, err := os.ReadFile("testdata/parse/go.mod")
	require.NoError(t, err)

	got, err := parseGoMod("go.mod", data)
	require.NoError(t, err)

	want := []directive{
		{Kind: kindReplace, Line: 6, Path: "example.com/held", NewPath: "example.com/held", NewVersion: "v1.2.0", Comment: "held: v2 drops the streaming API"},
		{Kind: kindReplace, Line: 8, Path: "example.com/local", NewPath: "./local"},
		{Kind: kindRequire, Line: 13, Path: "example.com/direct", Version: "v1.0.0"},
		{Kind: kindRequire, Line: 14, Path: "example.com/trailing", Version: "v1.1.0", Comment: "v1.2 breaks the wire format"},
		{Kind: kindRequire, Line: 16, Path: "example.com/above", Version: "v0.3.0", Comment: "a comment line directly above the line"},
		{Kind: kindRequire, Line: 17, Path: "example.com/dep", Version: "v1.0.0", Indirect: true},
		{Kind: kindRequire, Line: 18, Path: "example.com/why", Version: "v2.0.0", Indirect: true, Comment: "pinned by the parent"},
		{Kind: kindRequire, Line: 19, Path: "example.com/quoted", Version: "v0.1.0"},
		{Kind: kindRequire, Line: 22, Path: "example.com/single", Version: "v0.9.0"},
		{Kind: kindReplace, Line: 24, Path: "example.com/one", Version: "v1.0.0", NewPath: "example.com/one", NewVersion: "v1.0.1"},
	}
	assert.Equal(t, want, got)
}

func TestParseGoModErrors(t *testing.T) {
	cases := map[string]struct {
		data string
		line int
	}{
		"require without a version":   {"module m\n\nrequire example.com/a\n", 3},
		"block require extra field":   {"require (\n\texample.com/a v1.0.0 v2\n)\n", 2},
		"replace without an arrow":    {"replace example.com/a v1.0.0 example.com/b v1.0.0\n", 1},
		"replace with nothing after":  {"replace example.com/a =>\n", 1},
		"unterminated quoted path":    {"require \"example.com/a v1.0.0\n", 1},
		"block that is never closed":  {"module m\nrequire (\n\texample.com/a v1.0.0\n", 2},
		"replace with three on right": {"replace a => b v1 extra\n", 1},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := parseGoMod("go.mod", []byte(tc.data))
			var parseErr *ParseError
			require.ErrorAs(t, err, &parseErr)
			assert.Equal(t, tc.line, parseErr.Line)
		})
	}
}

func TestDependencies(t *testing.T) {
	data, err := os.ReadFile("testdata/parse/go.mod")
	require.NoError(t, err)
	directives, err := parseGoMod("go.mod", data)
	require.NoError(t, err)

	var got []string
	for _, d := range dependencies("go.mod", directives) {
		got = append(got, d.Kind+" "+d.Module+" "+d.Path+"@"+d.Version)
	}

	// Indirect requires and the local-directory replace are not compared;
	// version replaces are, as the version they put in effect.
	assert.Equal(t, []string{
		"replace example.com/held example.com/held@v1.2.0",
		"replace example.com/one example.com/one@v1.0.1",
		"require example.com/direct example.com/direct@v1.0.0",
		"require example.com/trailing example.com/trailing@v1.1.0",
		"require example.com/above example.com/above@v0.3.0",
		"require example.com/quoted example.com/quoted@v0.1.0",
		"require example.com/single example.com/single@v0.9.0",
	}, got)
}

func TestDependenciesSkipsReplacedRequires(t *testing.T) {
	directives := []directive{
		{Kind: kindReplace, Path: "example.com/all", NewPath: "example.com/all", NewVersion: "v1.1.0"},
		{Kind: kindReplace, Path: "example.com/one", Version: "v1.0.0", NewPath: "./one"},
		{Kind: kindRequire, Path: "example.com/all", Version: "v1.0.0"},
		{Kind: kindRequire, Path: "example.com/one", Version: "v1.0.0"},
		{Kind: kindRequire, Path: "example.com/other", Version: "v2.0.0"},
	}

	deps := dependencies("go.mod", directives)

	// A replace scoped to v1.0.0 leaves a require of another version alone.
	directives[3].Version = "v1.5.0"
	again := dependencies("go.mod", directives)

	require.Len(t, deps, 2)
	assert.Equal(t, kindReplace, deps[0].Kind)
	assert.Equal(t, "example.com/other", deps[1].Path)
	require.Len(t, again, 3)
	assert.Equal(t, "example.com/one", again[1].Path)
}

// TestParsesThisRepository parses the two go.mod files `make deps-check`
// reads, so a form the parser rejects fails here, not in the CI stage.
func TestParsesThisRepository(t *testing.T) {
	for _, file := range []string{"../../go.mod", "../../sdk/go/go.mod"} {
		t.Run(file, func(t *testing.T) {
			data, err := os.ReadFile(file)
			require.NoError(t, err)

			directives, err := parseGoMod(file, data)
			require.NoError(t, err)

			deps := dependencies(file, directives)
			require.NotEmpty(t, deps)
			for _, d := range deps {
				assert.NotEqual(t, "github.com/jeremyhahn/go-trusted-platform/sdk/go", d.Module, "the local sdk/go replace has no published version to compare")
			}
		})
	}
}

func TestDecodeList(t *testing.T) {
	f, err := os.Open("testdata/fail/list.json")
	require.NoError(t, err)
	defer f.Close()

	got, err := decodeList("testdata/fail", f)
	require.NoError(t, err)

	require.Contains(t, got, "example.com/behind")
	assert.Equal(t, []string{"v1.1.0", "v1.2.0", "v1.3.0"}, got["example.com/behind"].Versions)
	require.NotNil(t, got["example.com/behind"].Update)
	assert.Equal(t, "v1.3.0", got["example.com/behind"].Update.Version)
	assert.True(t, time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC).Equal(got["example.com/behind"].Update.Time))
	require.NotNil(t, got["example.com/documented"].Update)
	assert.True(t, got["example.com/documented"].Update.Time.IsZero(), "no Time in the listing decodes as zero")
	assert.Empty(t, got["example.com/gone"].Version)
}

func TestDecodeListRejectsGarbage(t *testing.T) {
	_, err := decodeList("dir", strings.NewReader(`{"Path": "a"} not json`))

	var listErr *ListOutputError
	require.ErrorAs(t, err, &listErr)
	assert.Equal(t, "dir", listErr.Dir)
}

func TestProxyDisabled(t *testing.T) {
	cases := map[string]bool{
		"off":                             true,
		"off|https://proxy.golang.org":    true,
		"off,https://proxy.golang.org":    true,
		"https://proxy.golang.org,direct": false,
		"https://proxy.golang.org,off":    false,
		"direct":                          false,
		"":                                false,
	}
	for goproxy, want := range cases {
		assert.Equal(t, want, proxyDisabled(goproxy), "GOPROXY=%q", goproxy)
	}
}

func TestAssess(t *testing.T) {
	require3 := dependency{Kind: kindRequire, Module: "example.com/a", Path: "example.com/a", Version: "v1.2.0"}
	first := dependency{Kind: kindRequire, Module: "github.com/jeremyhahn/go-a", Path: "github.com/jeremyhahn/go-a", Version: "v0.3.0-alpha"}
	replace := dependency{Kind: kindReplace, Module: "example.com/a", Path: "example.com/a", Version: "v1.2.0"}
	update := func(v string) *moduleUpdate { return &moduleUpdate{Version: v} }

	cases := map[string]struct {
		dep    dependency
		mod    listedModule
		latest string
		behind bool
	}{
		"third-party require at latest": {
			dep: require3, mod: listedModule{Version: "v1.2.0", Versions: []string{"v1.2.0", "v1.3.0-rc.1"}},
			latest: "v1.2.0",
		},
		"third-party require behind the go command's update": {
			dep: require3, mod: listedModule{Version: "v1.2.0", Versions: []string{"v1.2.0", "v1.3.0"}, Update: update("v1.3.0")},
			latest: "v1.3.0", behind: true,
		},
		"third-party pseudo-version behind a newer commit": {
			dep:    dependency{Kind: kindRequire, Module: "example.com/a", Path: "example.com/a", Version: "v0.0.0-20250101000000-abcdefabcdef"},
			mod:    listedModule{Version: "v0.0.0-20250101000000-abcdefabcdef", Update: update("v0.0.0-20260101000000-123456123456")},
			latest: "v0.0.0-20260101000000-123456123456", behind: true,
		},
		"first-party behind a newer alpha the placeholder hides": {
			dep: first, mod: listedModule{Version: "v0.3.0-alpha", Versions: []string{"v0.0.0", "v0.3.0-alpha", "v0.4.0-alpha"}},
			latest: "v0.4.0-alpha", behind: true,
		},
		"first-party at its highest tag": {
			dep: first, mod: listedModule{Version: "v0.3.0-alpha", Versions: []string{"v0.0.0", "v0.2.0-alpha", "v0.3.0-alpha"}},
			latest: "v0.3.0-alpha",
		},
		"first-party at an untagged commit": {
			dep:    dependency{Kind: kindRequire, Module: "github.com/jeremyhahn/go-a", Path: "github.com/jeremyhahn/go-a", Version: "v0.3.1-0.20260101000000-abcdefabcdef"},
			mod:    listedModule{Version: "v0.3.1-0.20260101000000-abcdefabcdef", Versions: []string{"v0.3.0-alpha"}},
			latest: "v0.3.0-alpha", behind: true,
		},
		"replace behind the highest release, prerelease ignored": {
			dep: replace, mod: listedModule{Version: "v1.0.0", Versions: []string{"v1.2.0", "v1.3.0", "v1.4.0-rc.1"}},
			latest: "v1.3.0", behind: true,
		},
		"replace at the highest release": {
			dep: replace, mod: listedModule{Version: "v1.0.0", Versions: []string{"v1.1.0", "v1.2.0", "v1.3.0-rc.1"}},
			latest: "v1.2.0",
		},
		"replace onto a fork": {
			dep:    dependency{Kind: kindReplace, Module: "example.com/a", Path: "example.com/fork", Version: "v1.0.0"},
			mod:    listedModule{Version: "v1.0.0", Versions: []string{"v1.0.0"}},
			latest: forkLatest, behind: true,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := assess(tc.dep, tc.mod, true, firstParty, testNow)
			require.Nil(t, f.Lookup)
			assert.False(t, f.Unused)
			assert.Equal(t, tc.latest, f.Latest)
			assert.Equal(t, tc.behind, f.Behind)
		})
	}
}

func TestAssessFailures(t *testing.T) {
	require3 := dependency{Kind: kindRequire, Module: "example.com/a", Path: "example.com/a", Version: "v1.2.0"}
	replace := dependency{Kind: kindReplace, Module: "example.com/a", Path: "example.com/a", Version: "v1.2.0"}

	missing := assess(require3, listedModule{}, false, firstParty, testNow)
	failed := assess(require3, listedModule{Version: "v1.2.0", Error: &struct{ Err string }{Err: "lookup failed"}}, true, firstParty, testNow)
	unknown := assess(require3, listedModule{Path: "example.com/a"}, true, firstParty, testNow)
	unused := assess(replace, listedModule{Path: "example.com/a"}, true, firstParty, testNow)

	require.NotNil(t, missing.Lookup)
	require.NotNil(t, failed.Lookup)
	assert.Equal(t, "lookup failed", failed.Lookup.Reason)
	require.NotNil(t, unknown.Lookup)
	assert.Equal(t, "not a known dependency", unknown.Lookup.Reason)
	assert.True(t, unused.Unused)
	assert.Nil(t, unused.Lookup)
	assert.False(t, unused.Behind)
}

func TestRunFailsOnUndocumentedLag(t *testing.T) {
	code, stdout, stderr := runFixture(t, fixtureSource{goproxy: "https://proxy.golang.org,direct"}, "testdata/fail")

	assert.Equal(t, exitUndocumented, code)
	file := filepath.Join("testdata", "fail", "go.mod")
	assert.Contains(t, stderr, file+":14: example.com/behind v1.2.0 is behind latest v1.3.0 and its require line carries no reason comment")
	assert.Contains(t, stderr, "example.com/pseudo v0.0.0-20250101000000-abcdefabcdef is behind latest v0.0.0-20260101000000-123456123456")
	assert.Contains(t, stderr, "github.com/jeremyhahn/go-lib v0.3.0-alpha is behind latest v0.4.0-alpha")
	assert.Contains(t, stderr, "deps-check: FAILED: 3 module(s) behind latest without a go.mod reason comment")
	assert.NotContains(t, stderr, "example.com/current")
	assert.NotContains(t, stdout, "fresh:", "a release older than 7 days still fails")
	assert.NotContains(t, stderr, "go-latest")
	assert.Contains(t, stdout, "held: example.com/documented v1.2.0, latest v1.3.0: v1.3 removes the Foo API")
	assert.Contains(t, stdout, "held: example.com/fork v1.0.0, latest "+forkLatest+": forked to drop cgo")
	assert.Contains(t, stdout, "note: replace of example.com/gone applies to no module in the build list")
}

func TestRunPassesWhenEveryLagIsDocumented(t *testing.T) {
	code, stdout, stderr := runFixture(t, fixtureSource{goproxy: "direct"}, "testdata/pass")

	assert.Equal(t, exitOK, code)
	assert.Empty(t, stderr)
	assert.Contains(t, stdout, "held: example.com/documented v1.2.0")
	file := filepath.Join("testdata", "pass", "go.mod")
	assert.Contains(t, stdout, file+":11: fresh: example.com/fresh v1.0.0, latest v1.1.0 released 2026-10-14, under 7 days: reported, not failed")
	assert.Contains(t, stdout, "deps-check: every dependency is at its latest version or documents why it is held")
}

func TestRunFailsWhenALookupFails(t *testing.T) {
	code, _, stderr := runFixture(t, fixtureSource{goproxy: "direct"}, "testdata/pass", "testdata/lookup")

	assert.Equal(t, exitLookup, code)
	assert.Contains(t, stderr, "cannot look up the latest version of github.com/jeremyhahn/go-private: git ls-remote -q origin: exit status 128")
	assert.Contains(t, stderr, "deps-check: FAILED: the latest version of 1 module(s) could not be looked up")
}

// TestRunFailsLoudlyOffline drives the real go command: with GOPROXY=off
// the check must stop with the reason before reading any go.mod.
func TestRunFailsLoudlyOffline(t *testing.T) {
	t.Setenv("GOPROXY", "off")

	code, stdout, stderr := runFixture(t, goCommand{}, "testdata/pass")

	assert.Equal(t, exitLookup, code)
	assert.Empty(t, stdout)
	assert.Contains(t, stderr, ErrLookupDisabled.Error())
}

func TestRunErrors(t *testing.T) {
	t.Run("no module directory", func(t *testing.T) {
		code, _, stderr := runFixture(t, fixtureSource{goproxy: "direct"})
		assert.Equal(t, exitLookup, code)
		assert.Contains(t, stderr, ErrUsage.Error())
	})
	t.Run("unknown flag", func(t *testing.T) {
		code, _, _ := runFixture(t, fixtureSource{goproxy: "direct"}, "-bogus", "testdata/pass")
		assert.Equal(t, exitLookup, code)
	})
	t.Run("no go.mod", func(t *testing.T) {
		code, _, stderr := runFixture(t, fixtureSource{goproxy: "direct"}, t.TempDir())
		assert.Equal(t, exitLookup, code)
		assert.Contains(t, stderr, "go.mod")
	})
	t.Run("go command missing", func(t *testing.T) {
		code, _, stderr := runFixture(t, goCommand{}, "-go", filepath.Join(t.TempDir(), "no-such-go"), "testdata/pass")
		assert.Equal(t, exitLookup, code)
		assert.Contains(t, stderr, "depscheck: go env GOPROXY")
	})
}

// failingWriter refuses every write, as a closed pipe does.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write refused") }

func TestRunFailsWhenTheReportCannotBeWritten(t *testing.T) {
	src := fixtureSource{goproxy: "direct"}
	t.Run("stdout of a passing report", func(t *testing.T) {
		var stderr bytes.Buffer
		code := run([]string{"testdata/pass"}, src, testNow, failingWriter{}, &stderr)
		assert.Equal(t, exitOutput, code)
	})
	t.Run("stderr of a failing report", func(t *testing.T) {
		var stdout bytes.Buffer
		code := run([]string{"testdata/fail"}, fixtureSource{goproxy: "https://proxy.golang.org,direct"}, testNow, &stdout, failingWriter{})
		assert.Equal(t, exitOutput, code)
	})
	t.Run("stderr of the usage error", func(t *testing.T) {
		var stdout bytes.Buffer
		code := run(nil, src, testNow, &stdout, failingWriter{})
		assert.Equal(t, exitOutput, code)
	})
	t.Run("stderr of a module error", func(t *testing.T) {
		var stdout bytes.Buffer
		code := run([]string{t.TempDir()}, src, testNow, &stdout, failingWriter{})
		assert.Equal(t, exitOutput, code)
	})
}

func TestGoCommandError(t *testing.T) {
	_, err := goCommand{path: filepath.Join(t.TempDir(), "no-such-go")}.GoProxy(".")

	var cmdErr *GoCommandError
	require.ErrorAs(t, err, &cmdErr)
	assert.Equal(t, []string{"env", "GOPROXY"}, cmdErr.Args)
	assert.Error(t, cmdErr.Unwrap())
}

func TestIsPrerelease(t *testing.T) {
	assert.True(t, isPrerelease("v1.0.0-rc.1"))
	assert.True(t, isPrerelease("v0.3.0-alpha"))
	assert.True(t, isPrerelease("v0.0.0-20250101000000-abcdefabcdef"))
	assert.False(t, isPrerelease("v1.2.3"))
	assert.False(t, isPrerelease("v2.0.0+incompatible"))
}

func TestIsFresh(t *testing.T) {
	cases := map[string]struct {
		released time.Time
		fresh    bool
	}{
		"released 6 days ago":                     {released: testNow.Add(-6 * 24 * time.Hour), fresh: true},
		"released one second short of 7 days ago": {released: testNow.Add(-freshWindow + time.Second), fresh: true},
		"released exactly 7 days ago":             {released: testNow.Add(-freshWindow)},
		"released 30 days ago":                    {released: testNow.Add(-30 * 24 * time.Hour)},
		"no release time":                         {},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.fresh, isFresh(tc.released, testNow))
		})
	}
}

func TestAssessReleaseAge(t *testing.T) {
	behind := dependency{Kind: kindRequire, Module: "example.com/a", Path: "example.com/a", Version: "v1.2.0"}
	first := dependency{Kind: kindRequire, Module: "github.com/jeremyhahn/go-a", Path: "github.com/jeremyhahn/go-a", Version: "v0.3.0-alpha"}
	sixDays := testNow.Add(-6 * 24 * time.Hour)
	listed := func(released time.Time) listedModule {
		return listedModule{Version: "v1.2.0", Versions: []string{"v1.2.0", "v1.3.0"}, Update: &moduleUpdate{Version: "v1.3.0", Time: released}}
	}

	cases := map[string]struct {
		dep      dependency
		mod      listedModule
		fresh    bool
		released time.Time
	}{
		"update released 6 days ago is fresh": {dep: behind, mod: listed(sixDays), fresh: true, released: sixDays},
		"update released 7 days ago is old":   {dep: behind, mod: listed(testNow.Add(-freshWindow)), released: testNow.Add(-freshWindow)},
		"update with no release time is old":  {dep: behind, mod: listed(time.Time{})},
		"at latest is never fresh": {
			dep: dependency{Kind: kindRequire, Module: "example.com/a", Path: "example.com/a", Version: "v1.3.0"},
			mod: listedModule{Version: "v1.3.0", Versions: []string{"v1.2.0", "v1.3.0"}},
		},
		"first-party latest not the update carries no release time": {
			dep: first,
			mod: listedModule{Version: "v0.3.0-alpha", Versions: []string{"v0.3.0-alpha", "v0.4.0-alpha"}, Update: &moduleUpdate{Version: "v0.3.1", Time: sixDays}},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := assess(tc.dep, tc.mod, true, firstParty, testNow)
			require.Nil(t, f.Lookup)
			assert.Equal(t, tc.fresh, f.Fresh)
			assert.True(t, tc.released.Equal(f.Released), "released %v, want %v", f.Released, tc.released)
		})
	}
}

func TestReportFreshRelease(t *testing.T) {
	sixDays := testNow.Add(-6 * 24 * time.Hour)
	dep := dependency{Kind: kindRequire, File: "go.mod", Line: 7, Module: "example.com/a", Path: "example.com/a", Version: "v1.2.0"}
	held := dep
	held.Reason = "v1.3 breaks Foo"

	cases := map[string]struct {
		finding finding
		code    int
		stdout  string
		stderr  string
	}{
		"fresh with no reason is reported": {
			finding: finding{Dep: dep, Latest: "v1.3.0", Behind: true, Fresh: true, Released: sixDays},
			code:    exitOK,
			stdout:  "go.mod:7: fresh: example.com/a v1.2.0, latest v1.3.0 released 2026-10-14, under 7 days: reported, not failed",
		},
		"old with no reason fails": {
			finding: finding{Dep: dep, Latest: "v1.3.0", Behind: true, Released: testNow.Add(-freshWindow)},
			code:    exitUndocumented,
			stderr:  "go.mod:7: example.com/a v1.2.0 is behind latest v1.3.0 and its require line carries no reason comment",
		},
		"fresh with a reason stays held": {
			finding: finding{Dep: held, Latest: "v1.3.0", Behind: true, Fresh: true, Released: sixDays},
			code:    exitOK,
			stdout:  "go.mod:7: held: example.com/a v1.2.0, latest v1.3.0: v1.3 breaks Foo",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			assert.Equal(t, tc.code, report([]finding{tc.finding}, &stdout, &stderr))
			if tc.stdout != "" {
				assert.Contains(t, stdout.String(), tc.stdout)
			}
			if tc.stderr != "" {
				assert.Contains(t, stderr.String(), tc.stderr)
				assert.NotContains(t, stdout.String(), "fresh:")
			}
		})
	}
}
