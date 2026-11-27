package arch

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// touchedRunner is a stub of the suite runner: the scripts read only its
// TARGET_PACKAGES table, so the rest of it is a comment and an unrelated map.
const touchedRunner = `#!/usr/bin/env bash
# stub suite runner
declare -A OTHER=(
    [alpha]="not the table"
)

declare -A TARGET_PACKAGES=(
    [all]=""
    [alpha]="./test/integration/alpha/..."
    [beta]="./test/integration/beta/..."
    [helpers]="./test/integration/helpers/..."
    [root]="./test/integration"
)

# beta runs through its own make target only.
ALL_TARGETS=(
    alpha # the first suite
    helpers
    root
)

declare -A LATER=(
    [gamma]="./test/integration/gamma/..."
)
`

// touchedBase is the throwaway repository each touched-script test starts
// from: a module, the stub runner, a Makefile, docs, three integration
// packages and two unit packages where pkg/b imports pkg/a.
var touchedBase = map[string]string{
	"go.mod": "module example.com/m\n\ngo 1.21\n",
	"build/docker/devcontainer/run-integration-tests.sh": touchedRunner,
	"Makefile":                                  "print-build-tags:\n\t@echo\n",
	"README.md":                                 "# m\n",
	"docs/guide.txt":                            "guide\n",
	".github/workflows/ci.yml":                  "name: ci\n",
	"test/integration/root_test.go":             "package integration\n\nimport \"testing\"\n\nfunc TestRoot(t *testing.T) {}\n",
	"test/integration/alpha/alpha.go":           "package alpha\n\nfunc A() int { return 1 }\n",
	"test/integration/alpha/alpha_test.go":      "package alpha\n\nimport \"testing\"\n\nfunc TestA(t *testing.T) { _ = A() }\n",
	"test/integration/beta/beta.go":             "package beta\n\nfunc B() int { return 1 }\n",
	"test/integration/beta/beta_test.go":        "package beta\n\nimport \"testing\"\n\nfunc TestB(t *testing.T) { _ = B() }\n",
	"test/integration/beta/beta_extra.go":       "package beta\n\nfunc C() int { return 1 }\n",
	"test/integration/helpers/h.go":             "package helpers\n\nfunc H() int { return 1 }\n",
	"test/integration/helpers/freeport/main.go": "package main\n\nfunc main() {}\n",
	"pkg/a/a.go":                                "package a\n\nfunc A() int { return 1 }\n",
	"pkg/a/extra.go":                            "package a\n\nfunc X() int { return 1 }\n",
	"pkg/b/b.go":                                "package b\n\nimport \"example.com/m/pkg/a\"\n\nfunc B() int { return a.A() }\n",
	"pkg/a/testdata/in.txt":                     "in\n",
	"pkg/c/c.go":                                "package c\n\nimport _ \"embed\"\n\n//go:embed policies/p.rego\nvar P string\n",
	"pkg/c/policies/p.rego":                     "package p\n",
	"web/src/app.ts":                            "export {}\n",
}

type touchedCase struct {
	name   string
	files  map[string]string
	remove []string // paths deleted in the same commit
	base   string   // the <base> argument; empty means HEAD^
	want   []string
}

// touchedRepo builds the base repository in a temporary directory and
// returns it with a function that commits one case's files on top of HEAD.
func touchedRepo(t *testing.T) (string, func(map[string]string, []string)) {
	t.Helper()
	for _, tool := range []string{"git", "go", "make"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not on PATH", tool)
		}
	}
	dir := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		full := append([]string{"-c", "user.name=t", "-c", "user.email=t@example.invalid",
			"-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null"}, args...)
		cmd := exec.Command("git", full...) // #nosec G204 -- fixed git arguments
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	commit := func(files map[string]string, remove []string) {
		t.Helper()
		for _, name := range remove {
			if err := os.Remove(filepath.Join(dir, filepath.FromSlash(name))); err != nil {
				t.Fatal(err)
			}
		}
		for name, body := range files {
			path := filepath.Join(dir, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		git("add", "-A")
		git("commit", "-q", "-m", "case")
	}
	git("init", "-q")
	commit(touchedBase, nil)
	return dir, commit
}

// runTouched runs a touched script on HEAD^..HEAD of dir and returns its
// stdout lines.
func runTouched(t *testing.T, dir, name, base string) []string {
	t.Helper()
	script, err := filepath.Abs("../../scripts/" + name)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", script, base, "HEAD") // #nosec G204 -- the repository's own script
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOTOOLCHAIN=local", "GOFLAGS=-mod=mod")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s failed: %v\nstdout:\n%s\nstderr:\n%s", name, err, stdout.String(), stderr.String())
	}
	var lines []string
	for _, line := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func runTouchedCases(t *testing.T, script string, cases []touchedCase) {
	dir, commit := touchedRepo(t)
	for _, c := range cases {
		commit(c.files, c.remove)
		base := c.base
		if base == "" {
			base = "HEAD^"
		}
		if got := runTouched(t, dir, script, base); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %s printed %q, want %q", c.name, script, got, c.want)
		}
	}
}

// TestTouchedFeatures: handbook testing-guidelines.md section 4, ruling 1171.
// The script names the features of the one table a range touches: nothing
// for docs, ALL for a shared change or a test directory in no feature.
func TestTouchedFeatures(t *testing.T) {
	runTouchedCases(t, "touched-features.sh", []touchedCase{
		{name: "docs only", files: map[string]string{"README.md": "# m2\n", "docs/guide.txt": "guide 2\n"}},
		{name: "alpha only", files: map[string]string{"test/integration/alpha/alpha.go": "package alpha\n\nfunc A() int { return 2 }\n"}, want: []string{"alpha"}},
		{name: "the root package starts importing alpha", files: map[string]string{
			"test/integration/root_test.go": "package integration\n\nimport (\n\t\"testing\"\n\n\t\"example.com/m/test/integration/alpha\"\n)\n\nfunc TestRoot(t *testing.T) { _ = alpha.A() }\n",
		}, want: []string{"root"}},
		{name: "alpha imported by the root package", files: map[string]string{"test/integration/alpha/alpha.go": "package alpha\n\nfunc A() int { return 3 }\n"}, want: []string{"alpha", "root"}},
		{name: "beta only", files: map[string]string{"test/integration/beta/beta.go": "package beta\n\nfunc B() int { return 2 }\n"}, want: []string{"beta"}},
		{name: "a Makefile change", files: map[string]string{"Makefile": "print-build-tags:\n\t@echo\n\n# changed\n"}, want: []string{"ALL", "beta"}},
		{name: "a package outside test/integration", files: map[string]string{"pkg/a/a.go": "package a\n\nfunc A() int { return 2 }\n"}, want: []string{"ALL", "beta"}},
		{name: "a workflow change", files: map[string]string{".github/workflows/ci.yml": "name: ci2\n"}, want: []string{"ALL", "beta"}},
		{name: "a test directory in no feature", files: map[string]string{"test/integration/gamma/gamma_test.go": "package gamma\n\nimport \"testing\"\n\nfunc TestG(t *testing.T) {}\n"}, want: []string{"ALL", "beta"}},
		{name: "every feature touched", files: map[string]string{
			"test/integration/alpha/alpha.go": "package alpha\n\nfunc A() int { return 4 }\n",
			"test/integration/beta/beta.go":   "package beta\n\nfunc B() int { return 3 }\n",
			"test/integration/helpers/h.go":   "package helpers\n\nfunc H() int { return 2 }\n",
		}, want: []string{"ALL", "beta"}},
		{name: "a helpers change", files: map[string]string{"test/integration/helpers/h.go": "package helpers\n\nfunc H() int { return 3 }\n"}, want: []string{"helpers"}},
		{name: "the runner's freeport command", files: map[string]string{"test/integration/helpers/freeport/main.go": "package main\n\nfunc main() { _ = 1 }\n"}, want: []string{"ALL", "beta"}},
		{name: "a suite file moved to docs", files: map[string]string{"docs/beta_extra.go": "package beta\n\nfunc C() int { return 1 }\n"}, remove: []string{"test/integration/beta/beta_extra.go"}, want: []string{"beta"}},
		{name: "a docs change against an unknown base", files: map[string]string{"README.md": "# m3\n"}, base: "no-such-rev", want: []string{"ALL", "beta"}},
		// #2445: go list -e reports a package error in its output and exits
		// 0, so the importers it lists are incomplete; that is a failure to
		// list the packages, which fails closed. Last: the broken file stays.
		{name: "an integration package go list reports an error for", files: map[string]string{
			"test/integration/alpha/alpha.go": "package alpha\n\nfunc A( int { return 1 }\n",
		}, want: []string{"ALL", "beta"}},
	})
}

// touchedNAT64Setup turns the base repository into one with the project's
// real feature table and the two halves of the NAT64 suite (#601): the
// host harness test/integration/nat64, which boots the VM, and its guest
// suite, test/integration/sdn built with the nat64vm tag (Makefile
// nat64-vm-suite, test/integration/nat64/vm_test.go).
func touchedNAT64Setup(t *testing.T) map[string]string {
	t.Helper()
	runner, err := os.ReadFile(filepath.Join(repoRoot(t), filepath.FromSlash(featureTableRunner)))
	if err != nil {
		t.Fatal(err)
	}
	return map[string]string{
		featureTableRunner:                        string(runner),
		"test/integration/nat64/vm_test.go":       "//go:build integration\n\npackage nat64\n\nimport \"testing\"\n\nfunc TestNAT64VM(t *testing.T) {}\n",
		"test/integration/sdn/helpers.go":         "//go:build integration\n\npackage sdn\n\nfunc S() int { return 1 }\n",
		"test/integration/sdn/nat64_jool_test.go": "//go:build integration && nat64vm\n\npackage sdn\n\nimport \"testing\"\n\nfunc TestJoolDriver(t *testing.T) { _ = S() }\n",
	}
}

// TestTouchedFeaturesSelectsNAT64GuestSuite: #2445. Under the project's
// real feature table, a change to the NAT64 guest suite -- a nat64vm guest
// test, or a file of the package the guest binary is built from -- selects
// the nat64 feature, whose make target builds and boots that guest suite.
// Today the table's nat64 row covers only the host harness, so the script
// prints lb and sdn and the NAT64 guest tests never run.
func TestTouchedFeaturesSelectsNAT64GuestSuite(t *testing.T) {
	dir, commit := touchedRepo(t)
	commit(touchedNAT64Setup(t), nil)
	for _, c := range []touchedCase{
		{name: "a nat64vm guest test", files: map[string]string{
			"test/integration/sdn/nat64_jool_test.go": "//go:build integration && nat64vm\n\npackage sdn\n\nimport \"testing\"\n\nfunc TestJoolDriver(t *testing.T) { _ = S() + 1 }\n",
		}},
		{name: "a new nat64vm guest test file", files: map[string]string{
			"test/integration/sdn/nat64_datapath_test.go": "//go:build integration && nat64vm\n\npackage sdn\n\nimport \"testing\"\n\nfunc TestNAT64Datapath(t *testing.T) { _ = S() }\n",
		}},
		{name: "a file the guest binary compiles", files: map[string]string{
			"test/integration/sdn/helpers.go": "//go:build integration\n\npackage sdn\n\nfunc S() int { return 2 }\n",
		}},
	} {
		commit(c.files, c.remove)
		got := runTouched(t, dir, "touched-features.sh", "HEAD^")
		if !slices.Contains(got, "nat64") || slices.Contains(got, "ALL") {
			t.Errorf("%s: touched-features.sh printed %q, want the nat64 feature (and no ALL)", c.name, got)
		}
	}
}

// TestTouchedPackages: the script names the changed packages and their
// direct importers in the module, one ./dir per line for make test-pkg.
func TestTouchedPackages(t *testing.T) {
	runTouchedCases(t, "touched-packages.sh", []touchedCase{
		{name: "pkg/a and its importer", files: map[string]string{"pkg/a/a.go": "package a\n\nfunc A() int { return 2 }\n"}, want: []string{"./pkg/a", "./pkg/b"}},
		{name: "pkg/b alone", files: map[string]string{"pkg/b/b.go": "package b\n\nimport \"example.com/m/pkg/a\"\n\nfunc B() int { return a.A() + 1 }\n"}, want: []string{"./pkg/b"}},
		{name: "docs only", files: map[string]string{"README.md": "# m2\n", "docs/guide.txt": "guide 2\n"}},
		{name: "an embedded policy", files: map[string]string{"pkg/c/policies/p.rego": "package p2\n"}, want: []string{"./pkg/c"}},
		{name: "testdata of pkg/a", files: map[string]string{"pkg/a/testdata/in.txt": "in 2\n"}, want: []string{"./pkg/a", "./pkg/b"}},
		{name: "a Makefile change", files: map[string]string{"Makefile": "print-build-tags:\n\t@echo\n\n# changed\n"}, want: []string{"./..."}},
		{name: "a file in no package", files: map[string]string{"web/src/app.ts": "export const x = 1\n"}, want: []string{"./..."}},
		{name: "a docs change against an unknown base", files: map[string]string{"README.md": "# m3\n"}, base: "no-such-rev", want: []string{"./..."}},
		{name: "a go.mod change", files: map[string]string{"go.mod": "module example.com/m\n\ngo 1.21\n\n// changed\n"}, want: []string{"./..."}},
		{name: "a file moved across packages", files: map[string]string{"pkg/d/extra.go": "package d\n\nfunc X() int { return 1 }\n"}, remove: []string{"pkg/a/extra.go"}, want: []string{"./pkg/a", "./pkg/b", "./pkg/d"}},
		// #2445: go list -e reports a package error in its output and exits
		// 0, so the packages and importers it lists are incomplete; that is a
		// failure to list the packages, which fails closed to ./... .
		// Last: the broken file stays in the repository.
		{name: "a package go list reports an error for", files: map[string]string{"pkg/e/e.go": "package e\n\nfunc E( int { return 1 }\n"}, want: []string{"./..."}},
	})
}
