// Command depscheck is `make deps-check`, the CI standard's latest-version
// stage (handbook ci-standard.md §1, devops.md §4). It fails when a direct
// dependency, first-party or third-party, is behind its latest version and
// its go.mod line carries no comment naming the reason (devops.md §9,
// dependency-resolution.md §3).
//
// Usage:
//
//	depscheck [-go <go command>] [-first-party <module path prefix>] <module dir>...
//
// Exit status: 0 when every dependency is current or documented, 1 when one
// is behind without a reason, 2 when a latest version cannot be looked up —
// GOPROXY=off among them, since an offline check must never pass silently.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const (
	exitOK           = 0
	exitUndocumented = 1
	exitLookup       = 2
)

func main() {
	os.Exit(run(os.Args[1:], goCommand{}, time.Now(), os.Stdout, os.Stderr))
}

// run checks every module directory given. A goCommand with no path takes
// its path from the -go flag.
func run(args []string, src moduleSource, now time.Time, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("depscheck", flag.ContinueOnError)
	flags.SetOutput(stderr)
	goPath := flags.String("go", "go", "the go command")
	firstParty := flags.String("first-party", "github.com/jeremyhahn/", "module path prefix of first-party modules")
	if err := flags.Parse(args); err != nil {
		return exitLookup
	}
	if flags.NArg() == 0 {
		fmt.Fprintf(stderr, "%s\n", ErrUsage)
		return exitLookup
	}
	if g, ok := src.(goCommand); ok && g.path == "" {
		src = goCommand{path: *goPath}
	}
	var findings []finding
	for _, dir := range flags.Args() {
		found, err := checkModule(src, dir, *firstParty, now)
		if err != nil {
			fmt.Fprintf(stderr, "%s\n", err)
			return exitLookup
		}
		findings = append(findings, found...)
	}
	return report(findings, stdout, stderr)
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

// report prints each lagging dependency and the verdict, and returns the
// exit status. Held dependencies with a reason are listed on stdout so the
// pins stay visible; failures go to stderr.
func report(findings []finding, stdout, stderr io.Writer) int {
	lookups, undocumented := 0, 0
	for _, f := range findings {
		d := f.Dep
		switch {
		case f.Lookup != nil:
			fmt.Fprintf(stderr, "%s:%d: %v\n", d.File, d.Line, f.Lookup)
			lookups++
		case f.Unused:
			fmt.Fprintf(stdout, "%s:%d: note: replace of %s applies to no module in the build list\n", d.File, d.Line, d.Module)
		case !f.Behind:
		case d.Reason == "" && f.Fresh:
			fmt.Fprintf(stdout, "%s:%d: fresh: %s %s, latest %s released %s, under 7 days: reported, not failed\n", d.File, d.Line, d.Path, d.Version, f.Latest, f.Released.UTC().Format(time.DateOnly))
		case d.Reason == "":
			fmt.Fprintf(stderr, "%s:%d: %s %s is behind latest %s and its %s line carries no reason comment\n", d.File, d.Line, d.Path, d.Version, f.Latest, d.Kind)
			undocumented++
		default:
			fmt.Fprintf(stdout, "%s:%d: held: %s %s, latest %s: %s\n", d.File, d.Line, d.Path, d.Version, f.Latest, d.Reason)
		}
	}
	switch {
	case lookups > 0:
		fmt.Fprintf(stderr, "deps-check: FAILED: the latest version of %d module(s) could not be looked up\n", lookups)
		return exitLookup
	case undocumented > 0:
		fmt.Fprintf(stderr, "deps-check: FAILED: %d module(s) behind latest without a go.mod reason comment (devops.md §9)\n", undocumented)
		return exitUndocumented
	}
	fmt.Fprintf(stdout, "%s\n", "deps-check: every dependency is at its latest version or documents why it is held")
	return exitOK
}
