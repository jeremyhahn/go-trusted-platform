package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strings"
)

// listedNameRe is a name `go test -list` prints that `go test -run` runs:
// tests, examples and fuzz targets' seed corpora. Benchmarks are left out,
// as `make test` passes no -bench.
var listedNameRe = regexp.MustCompile(`^(Test|Example|Fuzz)[A-Za-z0-9_]*$`)

// goCommand runs the go command with args and returns its combined output.
type goCommand func(ctx context.Context, args ...string) ([]byte, error)

// execGo returns a goCommand running the go binary goBin in the current
// directory and environment, so a rerun inherits GOFIPS140 and GODEBUG.
func execGo(goBin string) goCommand {
	return func(ctx context.Context, args ...string) ([]byte, error) {
		return exec.CommandContext(ctx, goBin, args...).CombinedOutput()
	}
}

// rerunner runs a panicked package's other tests with the run's build tags.
type rerunner struct {
	goCmd  goCommand
	module string
	tags   string
	// skip is the run's -skip pattern (`make test`'s TEST_SKIP); a
	// top-level name it matches did not run in the run either. May be nil.
	skip   *regexp.Regexp
	stdout io.Writer
}

// rest runs every top-level test of r.Package but r.Exclude, by explicit
// name, and returns the names it ran. Any failure is a *RerunError.
func (rr *rerunner) rest(ctx context.Context, r rerun) ([]string, error) {
	importPath := rr.module + "/" + r.Package
	out, err := rr.goCmd(ctx, "test", "-tags", rr.tags, "-list", ".", importPath)
	if err != nil {
		return nil, &RerunError{Package: r.Package, Reason: fmt.Sprintf("could not list the package's tests (%v):\n%s", err, out)}
	}
	names, err := rr.others(r, importPath, out)
	if err != nil || len(names) == 0 {
		return nil, err
	}
	run := "^(" + strings.Join(names, "|") + ")$"
	out, err = rr.goCmd(ctx, "test", "-tags", rr.tags, "-count=1", "-v", "-run", run, importPath)
	fmt.Fprintf(rr.stdout, "rerun of %s under fips140=only, -run %s:\n%s", r.Package, run, out)
	if err != nil {
		return nil, &RerunError{Package: r.Package, Reason: fmt.Sprintf("failed (%v)", err)}
	}
	if err := checkRerun(r, importPath, names, out); err != nil {
		return nil, err
	}
	return names, nil
}

// others reads `go test -list` output and returns every listed name but
// the excluded test and the names the run's -skip pattern dropped.
func (rr *rerunner) others(r rerun, importPath string, list []byte) ([]string, error) {
	var names []string
	excluded, ended := false, false
	for _, line := range strings.Split(string(list), "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case line == r.Exclude:
			excluded = true
		case strings.HasPrefix(line, "ok  \t"+importPath+"\t"):
			ended = true
		case !listedNameRe.MatchString(line):
		case rr.skip != nil && rr.skip.MatchString(line):
		default:
			names = append(names, line)
		}
	}
	switch {
	case !ended:
		return nil, &RerunError{Package: r.Package, Reason: "could not list the package's tests: go test -list printed no ok line"}
	case !excluded:
		return nil, &RerunError{Package: r.Package, Reason: fmt.Sprintf("could not exclude %s: go test -list does not name it", r.Exclude)}
	}
	return names, nil
}

// checkRerun confirms a rerun passed and ran every name it was given.
func checkRerun(r rerun, importPath string, names []string, out []byte) error {
	log, err := parseGoTestLog(importPath, "", bytes.NewReader(out))
	if err != nil {
		return &RerunError{Package: r.Package, Reason: "printed nothing"}
	}
	if len(log.Failed) > 0 || len(log.Problems) > 0 || len(log.Passed) != 1 || log.Passed[0] != importPath {
		return &RerunError{Package: r.Package, Reason: "did not end in one passing package result"}
	}
	ran := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		if name, ok := strings.CutPrefix(strings.TrimRight(line, "\r"), "=== RUN   "); ok {
			ran[name] = true
		}
	}
	for _, name := range names {
		if !ran[name] {
			return &RerunError{Package: r.Package, Reason: fmt.Sprintf("did not run %s", name)}
		}
	}
	return nil
}
