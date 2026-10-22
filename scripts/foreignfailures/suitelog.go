package main

import (
	"bufio"
	"io"
	"regexp"
	"strings"
)

// The lines of the integration suite's output the checker reads. The section
// and summary lines are printed by build/docker/devcontainer/
// run-integration-tests.sh; the rest by go test -v.
var (
	// sectionStartRe opens one target's section (run_test). The package is
	// the target's pattern, often ./test/integration/<dir>/...
	sectionStartRe = regexp.MustCompile(`^--- Testing (\S+) \((\S+)\) ---$`)
	// sectionEndRe closes it with the target's go test outcome (run_test).
	sectionEndRe = regexp.MustCompile(`^--- (PASS|FAIL): (\S+) ---$`)
	// testFailRe is one failed test or subtest, at any depth.
	testFailRe = regexp.MustCompile(`^\s*--- FAIL: (\S+) \(\d+(\.\d+)?s\)$`)
	// packageFailRe is go test's result line for a package whose test binary
	// exited non-zero. It follows that package's output.
	packageFailRe = regexp.MustCompile(`^FAIL\t(\S+)\t\d+(\.\d+)?s$`)
	// packageOKRe is go test's result line for a package that passed.
	packageOKRe = regexp.MustCompile(`^ok  \t\S+`)
	// packageNoTestsRe is go test's result line for a package with no test
	// files.
	packageNoTestsRe = regexp.MustCompile(`^\?   \t\S+\t\[no test files\]$`)
	// packageBrokenRe is go test's result line for a package that did not
	// build or set up, so no test ran.
	packageBrokenRe = regexp.MustCompile(`^FAIL\t\S+ \[[^]]+\]$`)
	// compileErrorRe is the runner's compile_check refusal.
	compileErrorRe = regexp.MustCompile(`^ERROR: \S+ \(\S+\) does not compile`)
	// summaryResultRe is one target's row in the runner's closing summary.
	summaryResultRe = regexp.MustCompile(`^  (PASS|FAIL)  (\S+)$`)
)

// The runner's closing summary is fenced by these rules and ends with one of
// the verdict lines.
const (
	summaryOpen   = "============================================="
	summaryClose  = "---------------------------------------------"
	summaryFailed = "  SOME INTEGRATION TESTS FAILED"
	summaryPassed = "  ALL INTEGRATION TESTS PASSED"
)

// packageResult is one Go package go test reported FAIL inside a section.
type packageResult struct {
	Package string // module-relative import path
	// BinaryFailed is the test binary's own closing "FAIL" line: without it
	// the binary did not run to the end (an os.Exit, a crash).
	BinaryFailed bool
	FailedTests  []string
}

// section is one target's output, from the runner's "--- Testing" line to its
// "--- PASS/FAIL" line. One target may cover several Go packages.
type section struct {
	Target  string
	Pattern string // the target's package pattern, without the leading "./"
	Ended   bool
	// Failed are the packages go test reported FAIL, in output order.
	Failed []*packageResult
	// Problems are lines that show a failure no test name carries: a panic,
	// a timeout, a build or compile failure, failed tests with no result line.
	Problems []string

	// pending gathers the current package's output until its result line.
	pending packageResult
	// afterResult is set while the last line read was a package result
	// line. A bare "FAIL" then is the go test command's own closing line,
	// not a test binary's.
	afterResult bool
	module      string
}

// suiteLog is what the checker reads from one run of the suite.
type suiteLog struct {
	sections map[string]*section
	// summary maps each target in the runner's closing summary to PASS or
	// FAIL; summarySeen is set once the summary's verdict line is read.
	summary     map[string]string
	summaryRows []string
	summarySeen bool
}

// parseSuiteLog reads the suite's combined output. module is the module path
// go test prints in front of each module-relative package.
func parseSuiteLog(name, module string, r io.Reader) (*suiteLog, error) {
	log := &suiteLog{sections: map[string]*section{}}
	var open *section
	inSummary := false
	lines := 0
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		lines++
		line := strings.TrimRight(scanner.Text(), "\r")

		if m := sectionStartRe.FindStringSubmatch(line); m != nil {
			if open != nil {
				open.close("the section ended without the runner's PASS/FAIL line")
			}
			open = &section{Target: m[2], Pattern: strings.TrimPrefix(m[1], "./"), module: module}
			log.sections[open.Target] = open
			continue
		}
		if open != nil {
			if m := sectionEndRe.FindStringSubmatch(line); len(m) == 3 && strings.TrimPrefix(m[2], "./") == open.Pattern {
				open.Ended = true
				open.close("")
				open = nil
				continue
			}
			open.read(line)
			continue
		}

		switch {
		case line == summaryOpen && log.summarySeen:
			// The rule that closes the summary after its verdict line.
		case line == summaryOpen:
			inSummary = true
			log.summary = map[string]string{}
			log.summaryRows = nil
		case inSummary && line == summaryClose:
			inSummary = false
		case inSummary:
			if m := summaryResultRe.FindStringSubmatch(line); m != nil {
				log.summary[m[2]] = m[1]
				log.summaryRows = append(log.summaryRows, m[2])
			}
		case log.summary != nil && (line == summaryFailed || line == summaryPassed):
			log.summarySeen = true
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, &ReadError{Path: name, Err: err}
	}
	if lines == 0 {
		return nil, ErrEmptyLog
	}
	if open != nil {
		open.close("the log ended inside the section")
	}
	return log, nil
}

// read records one line of a target's go test output.
func (s *section) read(line string) {
	if line == "FAIL" && s.afterResult {
		// The go test command's overall result after its last package.
		return
	}
	s.afterResult = false
	if m := testFailRe.FindStringSubmatch(line); m != nil {
		s.pending.FailedTests = append(s.pending.FailedTests, m[1])
		return
	}
	if m := packageFailRe.FindStringSubmatch(line); m != nil {
		rel, ok := strings.CutPrefix(m[1], s.module+"/")
		if !ok {
			s.Problems = append(s.Problems, "a package outside module "+s.module+" failed: "+line)
		}
		result := s.pending
		result.Package = rel
		s.Failed = append(s.Failed, &result)
		s.pending = packageResult{}
		s.afterResult = true
		return
	}
	switch {
	case line == "FAIL":
		s.pending.BinaryFailed = true
	case packageOKRe.MatchString(line), packageNoTestsRe.MatchString(line):
		if s.pending.failed() {
			s.Problems = append(s.Problems, "failed tests were printed before a passing package's result: "+line)
		}
		s.pending = packageResult{}
		s.afterResult = true
	case packageBrokenRe.MatchString(line):
		s.Problems = append(s.Problems, line)
		s.afterResult = true
	case compileErrorRe.MatchString(line),
		strings.HasPrefix(line, "panic: "),
		strings.HasPrefix(line, "*** Test killed"):
		s.Problems = append(s.Problems, line)
	}
}

// close ends the section; problem, when set, says why it ended early.
func (s *section) close(problem string) {
	if problem != "" {
		s.Problems = append(s.Problems, problem)
	}
	if s.pending.failed() {
		s.Problems = append(s.Problems, "failed tests with no package FAIL line: the test binary did not run to the end")
	}
	s.pending = packageResult{}
}

// failed reports whether the package output read so far shows a failure.
func (p *packageResult) failed() bool {
	return p.BinaryFailed || len(p.FailedTests) > 0
}

// leaves returns the failed tests that have no failed subtest. A parent test
// fails because its child did, so only the leaves carry a cause.
func leaves(failed []string) []string {
	var out []string
	for _, name := range failed {
		leaf := true
		for _, other := range failed {
			if strings.HasPrefix(other, name+"/") {
				leaf = false
				break
			}
		}
		if leaf {
			out = append(out, name)
		}
	}
	return out
}
