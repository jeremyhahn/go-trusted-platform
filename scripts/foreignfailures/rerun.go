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
	skip *regexp.Regexp
	// baseline attributes a round's panic, exactly as in the run.
	baseline *baseline
	stdout   io.Writer
}

// settle reruns r's package until a round passes. A panic kills the test
// binary, so a second listed test's panic surfaces only in a rerun: when a
// round fails only by a listed test's panic that attributePanic attributes
// exactly as in the run, the next round excludes that test as well. Any
// other failure gates. The rounds are bounded by the package's baseline
// rows, so the loop cannot spin. settle returns one line per round and
// the rows the rounds' panics hit.
func (rr *rerunner) settle(ctx context.Context, r rerun) ([]string, []*entry, error) {
	bound := rr.baseline.rowsIn(r.Package)
	var lines []string
	var hidden []*entry
	for round := 1; ; round++ {
		names, e, err := rr.round(ctx, r)
		if err != nil {
			return lines, hidden, err
		}
		excluded := strings.Join(r.excluded(), ", ")
		if e == nil {
			line := fmt.Sprintf("%s: %d other tests passed under fips140=only (all but %s), round %d of at most %d",
				r.Package, len(names), excluded, round, bound)
			return append(lines, line), hidden, nil
		}
		hidden = append(hidden, e)
		lines = append(lines, fmt.Sprintf("%s: round %d of at most %d ran %d tests (all but %s): listed %s panicked as its row (%s), so the next round excludes it too",
			r.Package, round, bound, len(names), excluded, e.Name, e.Upstream))
		if round >= bound {
			return lines, hidden, &RerunBoundError{Package: r.Package, Bound: bound}
		}
		r.Hidden = append(r.Hidden, e.Name)
	}
}

// round runs every top-level test of r.Package but the excluded ones, by
// explicit name, and returns the names it ran. When the round failed only
// by a listed test's attributable panic it returns that test's row too.
// Any other failure is a *RerunError.
func (rr *rerunner) round(ctx context.Context, r rerun) ([]string, *entry, error) {
	importPath := rr.module + "/" + r.Package
	out, err := rr.goCmd(ctx, "test", "-tags", rr.tags, "-list", ".", importPath)
	if err != nil {
		return nil, nil, &RerunError{Package: r.Package, Reason: fmt.Sprintf("could not list the package's tests (%v):\n%s", err, out)}
	}
	names, err := rr.others(r, importPath, out)
	if err != nil || len(names) == 0 {
		return nil, nil, err
	}
	for _, batch := range runBatches(names, maxRunPatternBytes) {
		run := runPattern(batch)
		out, err = rr.goCmd(ctx, "test", "-tags", rr.tags, "-count=1", "-v", "-run", run, importPath)
		fmt.Fprintf(rr.stdout, "rerun of %s under fips140=only, -run %s:\n%s", r.Package, run, out)
		if err != nil {
			e, reason := rr.attribute(r, out)
			if e == nil {
				return nil, nil, &RerunError{Package: r.Package, Reason: fmt.Sprintf("failed (%v)%s", err, reason)}
			}
			return names, e, nil
		}
		if err := checkRerun(r, importPath, batch, out); err != nil {
			return nil, nil, err
		}
	}
	return names, nil, nil
}

// maxRunPatternBytes bounds one rerun's -run pattern. Linux refuses a
// single exec argument past MAX_ARG_STRLEN (128 KiB) with "argument list
// too long", and pkg/api/daemon alone lists more than that in test names.
const maxRunPatternBytes = 64 << 10

// runPattern is the -run pattern that runs exactly names.
func runPattern(names []string) string {
	return "^(" + strings.Join(names, "|") + ")$"
}

// runBatches splits names, in order, into batches whose runPattern stays
// within limit bytes. A name too long for limit on its own gets a batch
// to itself, so every name is run exactly once.
func runBatches(names []string, limit int) [][]string {
	var batches [][]string
	var batch []string
	size := len(runPattern(nil))
	for _, name := range names {
		grown := size + len(name)
		if len(batch) > 0 {
			grown++ // the "|" before it
		}
		if len(batch) > 0 && grown > limit {
			batches = append(batches, batch)
			batch, grown = nil, len(runPattern(nil))+len(name)
		}
		batch = append(batch, name)
		size = grown
	}
	if len(batch) > 0 {
		batches = append(batches, batch)
	}
	return batches
}

// attribute decides a failed round by the run's own rules: the row of the
// listed test whose panic was the round's only failure, or why the round
// gates as ": <reason>" ("" when the round printed no panic).
func (rr *rerunner) attribute(r rerun, out []byte) (*entry, string) {
	log, err := parseGoTestLog(r.Package, rr.module, bytes.NewReader(out))
	if err != nil {
		return nil, ""
	}
	var p *packageRun
	for _, failed := range log.Failed {
		if failed.Panic != nil {
			p = failed
		}
	}
	switch {
	case p == nil:
		return nil, ""
	case len(log.Failed) != 1 || p.Package != r.Package || len(log.Passed) > 0:
		return nil, ": a panic beside another package result"
	case !log.Finished || len(log.Problems) > 0:
		return nil, ": a panic in a round that did not finish or printed output no test carries"
	}
	e, reason := attributePanic(rr.module, p, rr.baseline)
	if e == nil {
		return nil, ": " + reason
	}
	return e, ""
}

// others reads `go test -list` output and returns every listed name but
// the excluded tests and the names the run's -skip pattern dropped.
func (rr *rerunner) others(r rerun, importPath string, list []byte) ([]string, error) {
	var names []string
	excluded := map[string]bool{}
	for _, name := range r.excluded() {
		excluded[name] = false
	}
	ended := false
	for _, line := range strings.Split(string(list), "\n") {
		line = strings.TrimRight(line, "\r")
		_, exclude := excluded[line]
		switch {
		case exclude:
			excluded[line] = true
		case strings.HasPrefix(line, "ok  \t"+importPath+"\t"):
			ended = true
		case !listedNameRe.MatchString(line):
		case rr.skip != nil && rr.skip.MatchString(line):
		default:
			names = append(names, line)
		}
	}
	if !ended {
		return nil, &RerunError{Package: r.Package, Reason: "could not list the package's tests: go test -list printed no ok line"}
	}
	for _, name := range r.excluded() {
		if !excluded[name] {
			return nil, &RerunError{Package: r.Package, Reason: fmt.Sprintf("could not exclude %s: go test -list does not name it", name)}
		}
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
