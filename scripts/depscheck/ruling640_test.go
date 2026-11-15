package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The tests below cover -base, -vuln and -bump (ruling 640): fake git,
// govulncheck and go get seams over the testdata fixtures.

// fakeBase answers GoModAt from memory.
type fakeBase struct {
	data  string
	found bool
	err   error
	asked []string
}

func (f *fakeBase) GoModAt(dir, commit string) ([]byte, bool, error) {
	f.asked = append(f.asked, dir+"@"+commit)
	return []byte(f.data), f.found, f.err
}

// merge returns the union of scans.
func merge(scans ...map[string][]advisory) map[string][]advisory {
	out := make(map[string][]advisory)
	for _, m := range scans {
		for k, v := range m {
			out[k] = append(out[k], v...)
		}
	}
	return out
}

// fakeVuln answers Scan from memory.
type fakeVuln struct {
	hits map[string][]advisory
	err  error
}

func (f fakeVuln) Scan(string) (map[string][]advisory, error) { return f.hits, f.err }

// fakeEditor records go get and go mod tidy calls.
type fakeEditor struct {
	gets  []string
	tidy  int
	err   error
	after int // fail on this get (1-based); 0 never
}

func (f *fakeEditor) Get(dir, pathAtVersion string) error {
	f.gets = append(f.gets, dir+" "+pathAtVersion)
	if f.after > 0 && len(f.gets) == f.after {
		return f.err
	}
	return nil
}

func (f *fakeEditor) Tidy(string) error {
	f.tidy++
	if f.after == 0 {
		return f.err
	}
	return nil
}

var proxied = fixtureSource{goproxy: "https://proxy.golang.org,direct"}

func runTools(t *testing.T, tools toolset, args ...string) (int, string, string) {
	t.Helper()
	if tools.src == nil {
		tools.src = proxied
	}
	if tools.base == nil {
		tools.base = &fakeBase{err: errors.New("base must not be read")}
	}
	if tools.vuln == nil {
		tools.vuln = fakeVuln{err: errors.New("scan must not run")}
	}
	if tools.edit == nil {
		tools.edit = &fakeEditor{err: errors.New("edit must not run")}
	}
	var stdout, stderr bytes.Buffer
	code := runWith(args, tools, testNow, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func failGoMod(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("testdata/fail/go.mod")
	require.NoError(t, err)
	return string(data)
}

func TestBaseFailsOnlyWhatTheChangeTouches(t *testing.T) {
	file := filepath.Join("testdata", "fail", "go.mod")
	gomod := failGoMod(t)
	cases := []struct {
		name     string
		base     *fakeBase
		code     int
		failed   []string
		reported []string
	}{
		{
			name: "every lag was already there",
			base: &fakeBase{data: gomod, found: true},
			code: exitOK,
			reported: []string{
				file + ":14: behind, untouched by this change: example.com/behind v1.2.0, latest v1.3.0: reported, not failed (ruling 640)",
				"behind, untouched by this change: example.com/pseudo v0.0.0-20250101000000-abcdefabcdef",
				"behind, untouched by this change: github.com/jeremyhahn/go-lib v0.3.0-alpha",
				"or the change did not touch it",
			},
		},
		{
			name:     "the change bumps a lag but not to latest",
			base:     &fakeBase{data: strings.Replace(gomod, "example.com/behind v1.2.0", "example.com/behind v1.1.0", 1), found: true},
			code:     exitUndocumented,
			failed:   []string{file + ":14: example.com/behind v1.2.0 is behind latest v1.3.0", "FAILED: 1 module(s) behind latest"},
			reported: []string{"untouched by this change: example.com/pseudo", "untouched by this change: github.com/jeremyhahn/go-lib"},
		},
		{
			name:     "the change adds a lagging require",
			base:     &fakeBase{data: strings.Replace(gomod, "\texample.com/behind v1.2.0\n", "", 1), found: true},
			code:     exitUndocumented,
			failed:   []string{"example.com/behind v1.2.0 is behind latest v1.3.0", "FAILED: 1 module(s)"},
			reported: []string{"untouched by this change: example.com/pseudo"},
		},
		{
			name:   "the change adds the module",
			base:   &fakeBase{found: false},
			code:   exitUndocumented,
			failed: []string{"FAILED: 3 module(s) behind latest"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := runTools(t, toolset{base: tc.base}, "-base", "abc123", "testdata/fail")
			assert.Equal(t, tc.code, code, stderr)
			assert.Equal(t, []string{"testdata/fail@abc123"}, tc.base.asked)
			for _, want := range tc.failed {
				assert.Contains(t, stderr, want)
			}
			for _, want := range tc.reported {
				assert.Contains(t, stdout, want)
			}
			assert.Contains(t, stdout, "held: example.com/documented v1.2.0", "a documented hold is still listed")
		})
	}
}

func TestBaseErrors(t *testing.T) {
	t.Run("git fails", func(t *testing.T) {
		code, _, stderr := runTools(t, toolset{base: &fakeBase{err: &BaseError{Dir: "testdata/fail", Commit: "abc123", Err: errors.New("exit status 128"), Stderr: "bad object"}}}, "-base", "abc123", "testdata/fail")
		assert.Equal(t, exitLookup, code)
		assert.Contains(t, stderr, "depscheck: reading testdata/fail/go.mod at abc123: exit status 128: bad object")
	})
	t.Run("base go.mod does not parse", func(t *testing.T) {
		code, _, stderr := runTools(t, toolset{base: &fakeBase{data: "require (\n", found: true}}, "-base", "abc123", "testdata/fail")
		assert.Equal(t, exitLookup, code)
		assert.Contains(t, stderr, "go.mod@abc123")
	})
}

func TestTouched(t *testing.T) {
	dep := dependency{Kind: kindRequire, Module: "example.com/a", Path: "example.com/a", Version: "v1.0.0"}
	cases := []struct {
		name string
		base map[string]string
		want bool
	}{
		{"new module", nil, true},
		{"same line", map[string]string{"require example.com/a": "example.com/a@v1.0.0"}, false},
		{"version changed", map[string]string{"require example.com/a": "example.com/a@v0.9.0"}, true},
		{"added", map[string]string{"require example.com/b": "example.com/b@v1.0.0"}, true},
		{"was a replace only", map[string]string{"replace example.com/a": "example.com/a@v1.0.0"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, touched(dep, tc.base))
		})
	}
}

func TestGitBase(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("no git")
	}
	repo := t.TempDir()
	gitRun := func(dir string, args ...string) string {
		t.Helper()
		cmd := exec.Command(git, append([]string{"-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", "-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))
		return strings.TrimSpace(string(out))
	}
	gitRun(repo, "init", "-q")
	require.NoError(t, os.WriteFile(filepath.Join(repo, "go.mod"), []byte("module example.com/app\n"), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(repo, "sdk"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(repo, "sdk", "keep"), nil, 0o600))
	gitRun(repo, "add", ".")
	gitRun(repo, "commit", "-q", "-m", "base")
	head := gitRun(repo, "rev-parse", "HEAD")
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")

	g := gitBase{path: git}
	data, found, err := g.GoModAt(repo, head)
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, "module example.com/app\n", string(data))

	_, found, err = g.GoModAt(filepath.Join(repo, "sdk"), head)
	require.NoError(t, err)
	assert.False(t, found, "a module added after base has no go.mod there")

	_, _, err = g.GoModAt(repo, "0123456789abcdef0123456789abcdef01234567")
	var baseErr *BaseError
	require.ErrorAs(t, err, &baseErr)
	assert.Equal(t, "0123456789abcdef0123456789abcdef01234567", baseErr.Commit)
}

func TestVuln(t *testing.T) {
	hit := map[string][]advisory{"example.com/current@v1.4.0": {{ID: "GO-2026-0001", Fixed: "v1.4.1"}}}
	stdlibHit := map[string][]advisory{"stdlib@v1.27.0": {{ID: "GO-2026-0100", Fixed: "v1.27.1"}}}
	indirectHit := map[string][]advisory{"golang.org/x/net@v0.29.0": {{ID: "GO-2026-0002", Fixed: "v0.30.0"}}}
	gomod := failGoMod(t)
	cases := []struct {
		name   string
		dir    string
		args   []string
		tools  toolset
		code   int
		stderr []string
		stdout string
	}{
		{name: "clean", dir: "testdata/pass", tools: toolset{src: fixtureSource{goproxy: "direct"}, vuln: fakeVuln{}}, code: exitOK, stdout: "deps-check: every dependency"},
		{
			name:   "a current version that is vulnerable still fails",
			dir:    "testdata/pass",
			tools:  toolset{src: fixtureSource{goproxy: "direct"}, vuln: fakeVuln{hits: hit}},
			code:   exitVulnerable,
			stderr: []string{"testdata/pass: vulnerable: example.com/current v1.4.0: GO-2026-0001 (fixed in v1.4.1)", "FAILED: 1 required module version(s) govulncheck reports vulnerable"},
		},
		{
			name:   "an untouched vulnerable version fails",
			dir:    "testdata/fail",
			args:   []string{"-base", "abc123"},
			tools:  toolset{base: &fakeBase{data: gomod, found: true}, vuln: fakeVuln{hits: hit}},
			code:   exitVulnerable,
			stderr: []string{"vulnerable: example.com/current v1.4.0", "FAILED: 1 required module version(s) govulncheck reports vulnerable"},
		},
		{
			name:   "a vulnerability outranks an undocumented lag",
			dir:    "testdata/fail",
			tools:  toolset{vuln: fakeVuln{hits: hit}},
			code:   exitVulnerable,
			stderr: []string{"vulnerable: example.com/current v1.4.0", "FAILED: 1 required module version(s) govulncheck reports vulnerable"},
		},
		{
			name:   "stdlib only is reported, not failed",
			dir:    "testdata/pass",
			tools:  toolset{src: fixtureSource{goproxy: "direct"}, vuln: fakeVuln{hits: stdlibHit}},
			code:   exitOK,
			stdout: "testdata/pass: reported, not failed: stdlib go1.27.0: GO-2026-0100 (fixed in v1.27.1), the portfolio-wide toolchain pass carries it (CLAUDE.md Go toolchain rule); the security job gates reachable stdlib findings",
		},
		{
			name:   "toolchain is reported, not failed",
			dir:    "testdata/pass",
			tools:  toolset{src: fixtureSource{goproxy: "direct"}, vuln: fakeVuln{hits: map[string][]advisory{"toolchain@v1.27.0": {{ID: "GO-2026-0101"}}}}},
			code:   exitOK,
			stdout: "reported, not failed: toolchain go1.27.0: GO-2026-0101, the portfolio-wide toolchain pass carries it",
		},
		{
			name:   "an indirect-only module not in go.mod is reported, not failed",
			dir:    "testdata/pass",
			tools:  toolset{src: fixtureSource{goproxy: "direct"}, vuln: fakeVuln{hits: indirectHit}},
			code:   exitOK,
			stdout: "testdata/pass: reported, not failed: golang.org/x/net v0.29.0: GO-2026-0002 (fixed in v0.30.0), no require line in go.mod",
		},
		{
			name:   "stdlib and indirect-only beside a required hit: only the requirement fails",
			dir:    "testdata/pass",
			tools:  toolset{src: fixtureSource{goproxy: "direct"}, vuln: fakeVuln{hits: merge(hit, stdlibHit, indirectHit)}},
			code:   exitVulnerable,
			stderr: []string{"vulnerable: example.com/current v1.4.0", "FAILED: 1 required module version(s) govulncheck reports vulnerable"},
			stdout: "reported, not failed: stdlib go1.27.0",
		},
		{
			name:   "a // indirect require line in go.mod is a requirement and fails",
			dir:    "testdata/fail",
			args:   []string{"-base", "abc123"},
			tools:  toolset{base: &fakeBase{data: gomod, found: true}, vuln: fakeVuln{hits: map[string][]advisory{"example.com/dep@v1.0.0": {{ID: "GO-2026-0003"}}}}},
			code:   exitVulnerable,
			stderr: []string{"vulnerable: example.com/dep v1.0.0: GO-2026-0003", "FAILED: 1 required module version(s)"},
		},
		{
			name:   "scanner fails",
			dir:    "testdata/pass",
			tools:  toolset{src: fixtureSource{goproxy: "direct"}, vuln: fakeVuln{err: &VulnError{Dir: "testdata/pass", Err: errors.New("exit status 1"), Stderr: "no go.sum"}}},
			code:   exitLookup,
			stderr: []string{"depscheck: govulncheck in testdata/pass: exit status 1: no go.sum"},
		},
		{
			name:   "scanner missing",
			dir:    "testdata/pass",
			args:   []string{"-govulncheck", "/nonexistent/govulncheck"},
			tools:  toolset{src: fixtureSource{goproxy: "direct"}, vuln: govulncheck{}},
			code:   exitLookup,
			stderr: []string{"depscheck: govulncheck in testdata/pass"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := append(append([]string{"-vuln"}, tc.args...), tc.dir)
			code, stdout, stderr := runTools(t, tc.tools, args...)
			assert.Equal(t, tc.code, code, stderr)
			for _, want := range tc.stderr {
				assert.Contains(t, stderr, want)
			}
			assert.Contains(t, stdout, tc.stdout)
		})
	}
}

func TestDecodeVulns(t *testing.T) {
	stream := `{"config":{"protocol_version":"v1.0.0","scan_level":"module"}}
{"progress":{"message":"Scanning your code"}}
{"osv":{"id":"GO-2026-0002"}}
{"finding":{"osv":"GO-2026-0002","fixed_version":"v0.30.0","trace":[{"module":"golang.org/x/net","version":"v0.29.0"}]}}
{"finding":{"osv":"GO-2026-0002","fixed_version":"v0.30.0","trace":[{"module":"golang.org/x/net","version":"v0.29.0","package":"golang.org/x/net/html"}]}}
{"finding":{"osv":"GO-2026-0001","fixed_version":"v0.30.0","trace":[{"module":"golang.org/x/net","version":"v0.29.0"}]}}
{"finding":{"osv":"GO-2026-0003","fixed_version":"v1.27.5","trace":[{"module":"stdlib","version":"v1.27.4"}]}}
`
	got, err := decodeVulns("d", strings.NewReader(stream))
	require.NoError(t, err)
	assert.Equal(t, map[string][]advisory{
		"golang.org/x/net@v0.29.0": {{ID: "GO-2026-0001", Fixed: "v0.30.0"}, {ID: "GO-2026-0002", Fixed: "v0.30.0"}},
		"stdlib@v1.27.4":           {{ID: "GO-2026-0003", Fixed: "v1.27.5"}},
	}, got)

	empty, err := decodeVulns("d", strings.NewReader(`{"config":{"scan_level":"module"}}`))
	require.NoError(t, err)
	assert.Empty(t, empty)

	for name, in := range map[string]string{"garbage": "not json", "no config": `{"finding":{}}`, "nothing": ""} {
		t.Run(name, func(t *testing.T) {
			_, err := decodeVulns("d", strings.NewReader(in))
			var vulnErr *VulnError
			require.ErrorAs(t, err, &vulnErr)
		})
	}
}

func TestBump(t *testing.T) {
	t.Run("moves every failing lag and tidies", func(t *testing.T) {
		edit := &fakeEditor{}
		code, stdout, stderr := runTools(t, toolset{edit: edit}, "-bump", "testdata/fail")
		assert.Equal(t, exitOK, code, stderr)
		assert.Equal(t, []string{
			"testdata/fail example.com/behind@v1.3.0",
			"testdata/fail example.com/pseudo@v0.0.0-20260101000000-123456123456",
			"testdata/fail github.com/jeremyhahn/go-lib@v0.4.0-alpha",
		}, edit.gets, "documented, forked, fresh and current lines stay")
		assert.Equal(t, 1, edit.tidy)
		assert.Contains(t, stdout, "bumped example.com/behind v1.2.0 -> v1.3.0")
		assert.Contains(t, stdout, "deps-bump: done; re-run deps-check to verify (depscheck v1.0.0)")
	})
	t.Run("nothing to move", func(t *testing.T) {
		edit := &fakeEditor{}
		code, stdout, _ := runTools(t, toolset{src: fixtureSource{goproxy: "direct"}, edit: edit}, "-bump", "testdata/pass")
		assert.Equal(t, exitOK, code)
		assert.Empty(t, edit.gets, "a fresh release waits out its 7 days")
		assert.Equal(t, 0, edit.tidy)
		assert.NotContains(t, stdout, "bumped")
	})
	t.Run("go get fails", func(t *testing.T) {
		edit := &fakeEditor{err: &GoCommandError{Dir: "testdata/fail", Args: []string{"get"}, Err: errors.New("exit status 1")}, after: 2}
		code, _, stderr := runTools(t, toolset{edit: edit}, "-bump", "testdata/fail")
		assert.Equal(t, exitLookup, code)
		assert.Len(t, edit.gets, 2)
		assert.Contains(t, stderr, "exit status 1")
	})
	t.Run("go mod tidy fails", func(t *testing.T) {
		edit := &fakeEditor{err: errors.New("tidy refused")}
		code, _, stderr := runTools(t, toolset{edit: edit}, "-bump", "testdata/fail")
		assert.Equal(t, exitLookup, code)
		assert.Contains(t, stderr, "tidy refused")
	})
	t.Run("a lookup failure stops the bump", func(t *testing.T) {
		code, _, _ := runTools(t, toolset{src: fixtureSource{goproxy: "off"}}, "-bump", "testdata/fail")
		assert.Equal(t, exitLookup, code)
	})
	for _, extra := range [][]string{{"-base", "abc"}, {"-vuln"}} {
		t.Run("-bump with "+extra[0], func(t *testing.T) {
			code, _, stderr := runTools(t, toolset{}, append(append([]string{"-bump"}, extra...), "testdata/fail")...)
			assert.Equal(t, exitLookup, code)
			assert.Contains(t, stderr, ErrUsage.Error())
		})
	}
}

func TestBumpable(t *testing.T) {
	dep := dependency{Kind: kindRequire, Module: "m", Path: "m", Version: "v1"}
	cases := []struct {
		name string
		f    finding
		want bool
	}{
		{"behind", finding{Dep: dep, Behind: true, Latest: "v2"}, true},
		{"current", finding{Dep: dep, Latest: "v1"}, false},
		{"fresh", finding{Dep: dep, Behind: true, Fresh: true, Latest: "v2"}, false},
		{"documented", finding{Dep: dependency{Kind: kindRequire, Module: "m", Path: "m", Version: "v1", Reason: "held"}, Behind: true, Latest: "v2"}, false},
		{"lookup", finding{Dep: dep, Lookup: &LookupError{Module: "m"}}, false},
		{"fork", finding{Dep: dependency{Kind: kindReplace, Module: "m", Path: "f", Version: "v1"}, Behind: true, Latest: forkLatest}, false},
		{"unused", finding{Dep: dep, Unused: true}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, bumpable(tc.f))
		})
	}
}

func TestReportUntouchedVersusFresh(t *testing.T) {
	dep := dependency{File: "go.mod", Line: 3, Kind: kindRequire, Module: "m", Path: "m", Version: "v1.0.0"}
	var stdout, stderr bytes.Buffer
	code := report([]finding{{Dep: dep, Behind: true, Latest: "v1.1.0", Untouched: true}}, nil, &stdout, &stderr)
	assert.Equal(t, exitOK, code)
	assert.Equal(t, "go.mod:3: behind, untouched by this change: m v1.0.0, latest v1.1.0: reported, not failed (ruling 640)\n", strings.SplitAfter(stdout.String(), "\n")[0])
	assert.Empty(t, stderr.String())
}

func TestRequiredModules(t *testing.T) {
	got, err := requiredModules("testdata/fail")
	require.NoError(t, err)
	assert.True(t, got["example.com/current"])
	assert.True(t, got["example.com/dep"], "a // indirect require line is a requirement")
	assert.False(t, got["example.com/gone"], "a replace with no require line is not")
	assert.False(t, got["stdlib"])

	_, err = requiredModules("testdata/missing")
	assert.Error(t, err)
}

// TestScanDir: a module scan runs in a package directory of the module,
// because govulncheck -scan module takes no pattern and fails with "no Go
// files" in a root that has none.
func TestScanDir(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go command")
	}
	write := func(t *testing.T, root string, files map[string]string) {
		t.Helper()
		for f, body := range files {
			p := filepath.Join(root, f)
			require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
			require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
		}
	}
	const mod = "module example.com/x\n\ngo 1.21\n"
	const pkg = "package x\n"
	const tagged = "//go:build never\n\npackage x\n"
	cases := []struct {
		name  string
		files map[string]string
		tags  string
		want  string
	}{
		{"root package", map[string]string{"go.mod": mod, "x.go": pkg}, "", "."},
		{"empty root", map[string]string{"go.mod": mod, "doc_test.go": pkg, "pkg/b/b.go": pkg, "pkg/c/c.go": pkg}, "", "pkg/b"},
		{"every file tagged", map[string]string{"go.mod": mod, "a/t.go": tagged}, "never", "a"},
		{"skips build-tagged, nested module and ignored dirs", map[string]string{
			"go.mod": mod, "a/t.go": tagged, "b/go.mod": "module example.com/b\n\ngo 1.21\n", "b/b.go": pkg,
			"_x/x.go": pkg, "testdata/t.go": pkg, "z/z.go": pkg,
		}, "", "z"},
		{"no package", map[string]string{"go.mod": mod, "x_test.go": pkg}, "", "."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			write(t, root, tc.files)
			t.Setenv("GOFLAGS", "-mod=mod")
			t.Setenv("GOWORK", "off")
			got, err := scanDir("go", tc.tags, root)
			require.NoError(t, err)
			want, err := filepath.EvalSymlinks(filepath.Join(root, tc.want))
			require.NoError(t, err)
			gotReal, err := filepath.EvalSymlinks(got)
			require.NoError(t, err)
			assert.Equal(t, want, gotReal)
		})
	}

	_, err := scanDir("go", "", filepath.Join(t.TempDir(), "missing"))
	assert.Error(t, err)
}
