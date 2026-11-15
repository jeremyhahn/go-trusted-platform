// Command depscheck is `make deps-check`, the CI standard's latest-version
// stage (handbook ci-standard.md §1, devops.md §9), and `make deps-bump`,
// the bump the daily deps-bump workflow lands (ruling 640).
//
// Usage:
//
//	depscheck [-go <go command>] [-first-party <prefix>] [-base <commit>]
//	          [-vuln [-govulncheck <command>] [-vuln-tags <tags>]] [-bump] <module dir>...
//
// Without -base the full gate applies: a direct dependency behind its
// latest version, with no go.mod reason comment and a latest release older
// than 7 days, fails. With -base <commit> (CI passes the merge base on a
// pull request and the previous tip on a push) that lag fails only for a
// line the change adds or whose version it changes; a lag the change did
// not touch is reported, not failed. -vuln also runs govulncheck at module
// level and fails any version it reports vulnerable of a module go.mod
// requires, touched or not; a finding on the standard library, the
// toolchain or a module with no require line is reported, not failed. -bump moves every failing lag to latest with `go get`, runs
// `go mod tidy`, prints what moved and exits 0; the caller then re-runs
// the check.
//
// Exit status: 0 pass, 1 an undocumented lag, 2 a lookup, git or
// govulncheck failure (GOPROXY=off among them: an offline check never
// passes silently), 3 the report could not be written, 4 a vulnerable
// version of a required module.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// version is the shared tool's version (handbook templates/deps/depscheck).
const version = "depscheck v1.0.0"

const (
	exitOK           = 0
	exitUndocumented = 1
	exitLookup       = 2
	// exitOutput is returned when the report could not be written: a check
	// whose output was lost does not pass.
	exitOutput     = 3
	exitVulnerable = 4
)

// reportWriter writes report lines to one stream and keeps the first write
// error; later lines are skipped once a write has failed.
type reportWriter struct {
	w   io.Writer
	err error
}

func (r *reportWriter) printf(format string, args ...any) {
	if r.err != nil {
		return
	}
	_, r.err = fmt.Fprintf(r.w, format, args...)
}

// toolset is every outside command depscheck uses, so tests can fake each.
type toolset struct {
	src  moduleSource
	base baseReader
	vuln vulnScanner
	edit moduleEditor
}

func main() {
	os.Exit(runWith(os.Args[1:], toolset{src: goCommand{}, base: gitBase{}, vuln: govulncheck{}, edit: goCommand{}}, time.Now(), os.Stdout, os.Stderr))
}

// run checks every module directory given with the real git and govulncheck.
func run(args []string, src moduleSource, now time.Time, stdout, stderr io.Writer) int {
	return runWith(args, toolset{src: src, base: gitBase{}, vuln: govulncheck{}, edit: goCommand{}}, now, stdout, stderr)
}

// runWith is run with every tool supplied. A goCommand, govulncheck or
// gitBase with no path takes its path from the flags.
func runWith(args []string, tools toolset, now time.Time, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("depscheck", flag.ContinueOnError)
	flags.SetOutput(stderr)
	goPath := flags.String("go", "go", "the go command")
	firstParty := flags.String("first-party", "github.com/jeremyhahn/", "module path prefix of first-party modules")
	base := flags.String("base", "", "fail a lag only when the change adds or bumps it versus this commit (ruling 640)")
	vuln := flags.Bool("vuln", false, "fail any version govulncheck reports vulnerable of a module go.mod requires")
	vulnPath := flags.String("govulncheck", "govulncheck", "the govulncheck command")
	vulnTags := flags.String("vuln-tags", "", "comma-separated build tags for the govulncheck module scan, for a module whose every file is behind a tag")
	bump := flags.Bool("bump", false, "go get every failing lag to latest, go mod tidy, and exit 0")
	if err := flags.Parse(args); err != nil {
		return exitLookup
	}
	fail := func(err error) int {
		if _, werr := fmt.Fprintf(stderr, "%s\n", err); werr != nil {
			return exitOutput
		}
		return exitLookup
	}
	if flags.NArg() == 0 || (*bump && (*base != "" || *vuln)) {
		return fail(ErrUsage)
	}
	if g, ok := tools.src.(goCommand); ok && g.path == "" {
		tools.src = goCommand{path: *goPath}
	}
	if g, ok := tools.edit.(goCommand); ok && g.path == "" {
		tools.edit = goCommand{path: *goPath}
	}
	if g, ok := tools.vuln.(govulncheck); ok && g.path == "" {
		tools.vuln = govulncheck{path: *vulnPath, goPath: *goPath, tags: *vulnTags}
	}
	var findings []finding
	var vulns []vulnFinding
	for _, dir := range flags.Args() {
		found, err := checkModule(tools.src, dir, *firstParty, now)
		if err != nil {
			return fail(err)
		}
		if *base != "" {
			if err := markUntouched(tools.base, dir, *base, found); err != nil {
				return fail(err)
			}
		}
		if *bump {
			if err := bumpModule(tools.edit, dir, found, stdout); err != nil {
				return fail(err)
			}
			continue
		}
		findings = append(findings, found...)
		if *vuln {
			hits, err := tools.vuln.Scan(dir)
			if err != nil {
				return fail(err)
			}
			required, err := requiredModules(dir)
			if err != nil {
				return fail(err)
			}
			vulns = append(vulns, vulnFindings(dir, hits, required)...)
		}
	}
	if *bump {
		if _, err := fmt.Fprintf(stdout, "deps-bump: done; re-run deps-check to verify (%s)\n", version); err != nil {
			return exitOutput
		}
		return exitOK
	}
	return report(findings, vulns, stdout, stderr)
}

// markUntouched sets Untouched on each finding whose go.mod line has the
// same path and version at base. A module with no go.mod at base is new:
// every line in it is touched.
func markUntouched(base baseReader, dir, commit string, findings []finding) error {
	data, found, err := base.GoModAt(dir, commit)
	if err != nil {
		return err
	}
	var was map[string]string
	if found {
		if was, err = baseVersions(filepath.Join(dir, "go.mod")+"@"+commit, data); err != nil {
			return err
		}
	}
	for i := range findings {
		findings[i].Untouched = !touched(findings[i].Dep, was)
	}
	return nil
}

// checkModule assesses the dependencies of the go.mod in dir.
func checkModule(src moduleSource, dir, firstParty string, now time.Time) ([]finding, error) {
	goproxy, err := src.GoProxy(dir)
	if err != nil {
		return nil, err
	}
	if proxyDisabled(goproxy) {
		return nil, ErrLookupDisabled
	}
	file := filepath.Join(dir, "go.mod")
	data, err := os.ReadFile(file) //#nosec G304 -- the go.mod of a module directory the Makefile names
	if err != nil {
		return nil, err
	}
	directives, err := parseGoMod(file, data)
	if err != nil {
		return nil, err
	}
	deps := dependencies(file, directives)
	if len(deps) == 0 {
		return nil, nil
	}
	modules := make([]string, 0, len(deps))
	for _, dep := range deps {
		modules = append(modules, dep.Module)
	}
	listing, err := src.List(dir, modules)
	if err != nil {
		return nil, err
	}
	findings := make([]finding, 0, len(deps))
	for _, dep := range deps {
		mod, listed := listing[dep.Module]
		findings = append(findings, assess(dep, mod, listed, firstParty, now))
	}
	return findings, nil
}

// report prints each lagging dependency, each vulnerable version and the
// verdict, and returns the exit status. Held and untouched lags are listed
// on stdout so they stay visible; failures go to stderr.
func report(findings []finding, vulns []vulnFinding, stdout, stderr io.Writer) int {
	out, errOut := &reportWriter{w: stdout}, &reportWriter{w: stderr}
	code := writeReport(findings, vulns, out, errOut)
	if out.err != nil || errOut.err != nil {
		return exitOutput
	}
	return code
}

// writeReport writes one line per finding and the verdict, and returns the
// verdict's exit code: a lookup failure first, then a vulnerability, then
// an undocumented lag.
func writeReport(findings []finding, vulns []vulnFinding, out, errOut *reportWriter) int {
	lookups, undocumented := 0, 0
	for _, f := range findings {
		d := f.Dep
		switch {
		case f.Lookup != nil:
			errOut.printf("%s:%d: %v\n", d.File, d.Line, f.Lookup)
			lookups++
		case f.Unused:
			out.printf("%s:%d: note: replace of %s applies to no module in the build list\n", d.File, d.Line, d.Module)
		case !f.Behind:
		case d.Reason == "" && f.Fresh:
			out.printf("%s:%d: fresh: %s %s, latest %s released %s, under 7 days: reported, not failed\n", d.File, d.Line, d.Path, d.Version, f.Latest, f.Released.UTC().Format(time.DateOnly))
		case d.Reason == "" && f.Untouched:
			out.printf("%s:%d: behind, untouched by this change: %s %s, latest %s: reported, not failed (ruling 640)\n", d.File, d.Line, d.Path, d.Version, f.Latest)
		case d.Reason == "":
			errOut.printf("%s:%d: %s %s is behind latest %s and its %s line carries no reason comment\n", d.File, d.Line, d.Path, d.Version, f.Latest, d.Kind)
			undocumented++
		default:
			out.printf("%s:%d: held: %s %s, latest %s: %s\n", d.File, d.Line, d.Path, d.Version, f.Latest, d.Reason)
		}
	}
	vulnerable := 0
	for _, v := range vulns {
		if !v.Required {
			out.printf("%s\n", v.note())
			continue
		}
		errOut.printf("%s: vulnerable: %s %s: %s\n", v.Dir, v.Module, v.Version, v.describe())
		vulnerable++
	}
	switch {
	case lookups > 0:
		errOut.printf("deps-check: FAILED: the latest version of %d module(s) could not be looked up\n", lookups)
		return exitLookup
	case vulnerable > 0:
		errOut.printf("deps-check: FAILED: %d required module version(s) govulncheck reports vulnerable (ruling 640)\n", vulnerable)
		return exitVulnerable
	case undocumented > 0:
		errOut.printf("deps-check: FAILED: %d module(s) behind latest without a go.mod reason comment (devops.md §9)\n", undocumented)
		return exitUndocumented
	}
	out.printf("%s\n", "deps-check: every dependency is at its latest version or documents why it is held, or the change did not touch it")
	return exitOK
}
