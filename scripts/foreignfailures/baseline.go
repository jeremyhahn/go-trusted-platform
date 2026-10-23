package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

// Entry kinds. A test entry names one leaf test of one package; a job entry
// names one runner target (ALL_TARGETS in run-integration-tests.sh) whose
// failure happens outside go test, such as a daemon that does not start.
const (
	kindTest = "test"
	kindJob  = "job"
	// kindPanic is the FIPS baseline's one kind: a top-level test whose
	// panic, message and frame are all the row's.
	kindPanic = "panic"
)

// baselineColumns is the number of tab-separated columns in a row: kind,
// package, name, upstream, closing_release.
const baselineColumns = 5

// fipsBaselineColumns is a FIPS row: the Integration columns plus the stack
// frame the panic must pass through and the panic's exact message.
const fipsBaselineColumns = 7

var (
	// packageRe is a package path relative to the module root.
	packageRe = regexp.MustCompile(`^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$`)
	// upstreamRe is one or more upstream issues, repo#number, joined by "+".
	upstreamRe = regexp.MustCompile(`^[A-Za-z0-9._-]+#[1-9][0-9]*(\+[A-Za-z0-9._-]+#[1-9][0-9]*)*$`)
	// topLevelTestRe is a FIPS row's name: one top-level test, because the
	// rerun replaces the whole binary the panic killed, test by test.
	topLevelTestRe = regexp.MustCompile(`^Test[A-Za-z0-9_]*$`)
	// frameRe is a Go function as a stack trace prints it, without its
	// argument list: path/pkg.Func or path/pkg.(*Type).Method.
	frameRe = regexp.MustCompile(`^[A-Za-z0-9._/-]+\.(\(\*?[A-Za-z0-9_]+\)\.)?[A-Za-z0-9_]+$`)
)

// entry is one baseline row.
type entry struct {
	Kind           string
	Package        string
	Name           string
	Upstream       string
	ClosingRelease string
	// Frame and Message are set on kind panic rows only.
	Frame   string
	Message string
	Line    int
}

// testKey identifies one leaf test.
type testKey struct {
	Package string
	Name    string
}

// baseline is the parsed foreign-failure baseline, indexed for exact lookup:
// no row is a pattern, so a new failure can never hide under an entry.
type baseline struct {
	entries []*entry
	tests   map[testKey]*entry
	jobs    map[string]*entry
}

// loadBaseline reads and parses the baseline file at path.
func loadBaseline(path string) (*baseline, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, &ReadError{Path: path, Err: err}
	}
	defer f.Close()
	return parseBaseline(path, f)
}

// parseBaseline parses baseline rows; blank lines and # comments are skipped.
func parseBaseline(name string, r io.Reader) (*baseline, error) {
	return parseRows(name, r, parseRow)
}

// rowParser turns one non-comment line of a baseline file into an entry.
type rowParser func(name string, lineNo int, line string) (*entry, error)

// parseRows reads a baseline file whose rows parse is the only row format
// it accepts, so a row of one job's file never loads as the other's.
func parseRows(name string, r io.Reader, parse rowParser) (*baseline, error) {
	b := &baseline{tests: map[testKey]*entry{}, jobs: map[string]*entry{}}
	scanner := bufio.NewScanner(r)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimRight(scanner.Text(), "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		e, err := parse(name, lineNo, line)
		if err != nil {
			return nil, err
		}
		if err := b.add(name, e); err != nil {
			return nil, err
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, &ReadError{Path: name, Err: err}
	}
	return b, nil
}

// loadFIPSBaseline reads and validates the FIPS job's baseline file.
func loadFIPSBaseline(path string) (*baseline, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, &ReadError{Path: path, Err: err}
	}
	defer f.Close()
	return parseFIPSBaseline(path, f)
}

// parseFIPSBaseline reads FIPS baseline rows: kind panic only.
func parseFIPSBaseline(name string, r io.Reader) (*baseline, error) {
	return parseRows(name, r, parseFIPSRow)
}

// parseFIPSRow parses one FIPS row: kind, package, name, upstream,
// closing_release, frame, message. message is last because it holds spaces.
func parseFIPSRow(name string, lineNo int, line string) (*entry, error) {
	fields := strings.Split(line, "\t")
	if len(fields) != fipsBaselineColumns {
		return nil, &BaselineError{File: name, Line: lineNo,
			Reason: fmt.Sprintf("want %d tab-separated columns (kind, package, name, upstream, closing_release, frame, message), got %d", fipsBaselineColumns, len(fields))}
	}
	e := &entry{
		Kind:           fields[0],
		Package:        fields[1],
		Name:           fields[2],
		Upstream:       fields[3],
		ClosingRelease: strings.TrimSpace(fields[4]),
		Frame:          fields[5],
		Message:        strings.TrimSpace(fields[6]),
		Line:           lineNo,
	}
	switch {
	case e.Kind != kindPanic:
		return nil, &BaselineError{File: name, Line: lineNo, Reason: fmt.Sprintf("kind %q is not %q: the FIPS baseline lists panics only", e.Kind, kindPanic)}
	case !packageRe.MatchString(e.Package):
		return nil, &BaselineError{File: name, Line: lineNo, Reason: fmt.Sprintf("package %q is not a module-relative package path", e.Package)}
	case !topLevelTestRe.MatchString(e.Name):
		return nil, &BaselineError{File: name, Line: lineNo, Reason: fmt.Sprintf("name %q is not one top-level test", e.Name)}
	case !upstreamRe.MatchString(e.Upstream):
		return nil, &BaselineError{File: name, Line: lineNo, Reason: fmt.Sprintf("upstream %q does not name an issue as repo#number", e.Upstream)}
	case e.ClosingRelease == "":
		return nil, &BaselineError{File: name, Line: lineNo, Reason: "closing_release is empty"}
	case !frameRe.MatchString(e.Frame):
		return nil, &BaselineError{File: name, Line: lineNo, Reason: fmt.Sprintf("frame %q is not a Go function as a stack trace names it", e.Frame)}
	case e.Message == "":
		return nil, &BaselineError{File: name, Line: lineNo, Reason: "message is empty"}
	}
	return e, nil
}

// parseRow validates one row.
func parseRow(name string, lineNo int, line string) (*entry, error) {
	fields := strings.Split(line, "\t")
	if len(fields) != baselineColumns {
		return nil, &BaselineError{File: name, Line: lineNo,
			Reason: fmt.Sprintf("want %d tab-separated columns (kind, package, name, upstream, closing_release), got %d", baselineColumns, len(fields))}
	}
	e := &entry{
		Kind:           fields[0],
		Package:        fields[1],
		Name:           fields[2],
		Upstream:       fields[3],
		ClosingRelease: strings.TrimSpace(fields[4]),
		Line:           lineNo,
	}
	switch {
	case e.Kind != kindTest && e.Kind != kindJob:
		return nil, &BaselineError{File: name, Line: lineNo, Reason: fmt.Sprintf("kind %q is neither %q nor %q", e.Kind, kindTest, kindJob)}
	case !packageRe.MatchString(e.Package):
		return nil, &BaselineError{File: name, Line: lineNo, Reason: fmt.Sprintf("package %q is not a module-relative package path", e.Package)}
	case e.Name == "" || strings.ContainsAny(e.Name, " \t"):
		return nil, &BaselineError{File: name, Line: lineNo, Reason: fmt.Sprintf("name %q is empty or holds whitespace", e.Name)}
	case !upstreamRe.MatchString(e.Upstream):
		return nil, &BaselineError{File: name, Line: lineNo, Reason: fmt.Sprintf("upstream %q does not name an issue as repo#number", e.Upstream)}
	case e.ClosingRelease == "":
		return nil, &BaselineError{File: name, Line: lineNo, Reason: "closing_release is empty"}
	}
	return e, nil
}

// add indexes e, refusing a second row for the same test or target.
func (b *baseline) add(name string, e *entry) error {
	if e.Kind == kindJob {
		if prev, ok := b.jobs[e.Name]; ok {
			return &BaselineError{File: name, Line: e.Line, Reason: fmt.Sprintf("job %s is already listed on line %d", e.Name, prev.Line)}
		}
		b.jobs[e.Name] = e
	} else {
		key := testKey{Package: e.Package, Name: e.Name}
		if prev, ok := b.tests[key]; ok {
			return &BaselineError{File: name, Line: e.Line, Reason: fmt.Sprintf("test %s %s is already listed on line %d", e.Package, e.Name, prev.Line)}
		}
		b.tests[key] = e
	}
	b.entries = append(b.entries, e)
	return nil
}
