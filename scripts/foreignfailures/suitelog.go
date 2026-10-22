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
	// sectionStartRe opens one target's section (run_test).
	sectionStartRe = regexp.MustCompile(`^--- Testing (\S+) \((\S+)\) ---$`)
	// sectionEndRe closes it with the target's go test outcome (run_test).
	sectionEndRe = regexp.MustCompile(`^--- (PASS|FAIL): (\S+) ---$`)
	// testFailRe is one failed test or subtest, at any depth.
	testFailRe = regexp.MustCompile(`^\s*--- FAIL: (\S+) \(\d+(\.\d+)?s\)$`)
	// packageFailRe is go test's line for a package whose test binary ran to
	// the end and failed.
	packageFailRe = regexp.MustCompile(`^FAIL\t(\S+)\t\d+(\.\d+)?s$`)
	// packageBrokenRe is go test's line for a package that did not build or
	// set up, so no test ran.
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

// section is one target's output, from the runner's "--- Testing" line to its
// "--- PASS/FAIL" line.
type section struct {
	Target  string
	Package string // module-relative, without the leading "./"
	Ended   bool
	// BinaryFailed is the test binary's own closing "FAIL" line and
	// PackageFailed go test's "FAIL\t<package>\t<duration>" line: both
	// present means the binary ran to the end.
	BinaryFailed  bool
	PackageFailed bool
	FailedTests   []string
	// Problems are lines that show a failure no test name carries: a panic,
	// a timeout, a build or compile failure.
	Problems []string
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

// parseSuiteLog reads the suite's combined output.
func parseSuiteLog(name string, r io.Reader) (*suiteLog, error) {
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
				open.Problems = append(open.Problems, "the section ended without the runner's PASS/FAIL line")
			}
			open = &section{Target: m[2], Package: strings.TrimPrefix(m[1], "./")}
			log.sections[open.Target] = open
			continue
		}
		if open != nil {
			if m := sectionEndRe.FindStringSubmatch(line); m != nil && strings.TrimPrefix(m[2], "./") == open.Package {
				open.Ended = true
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
			log.summarySeen = false
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
		open.Problems = append(open.Problems, "the log ended inside the section")
	}
	return log, nil
}

// read records one line of a target's go test output.
func (s *section) read(line string) {
	if m := testFailRe.FindStringSubmatch(line); m != nil {
		s.FailedTests = append(s.FailedTests, m[1])
		return
	}
	switch {
	case line == "FAIL":
		s.BinaryFailed = true
	case packageFailRe.MatchString(line):
		path := packageFailRe.FindStringSubmatch(line)[1]
		if path == s.Package || strings.HasSuffix(path, "/"+s.Package) {
			s.PackageFailed = true
		}
	case packageBrokenRe.MatchString(line),
		compileErrorRe.MatchString(line),
		strings.HasPrefix(line, "panic: "),
		strings.HasPrefix(line, "*** Test killed"):
		s.Problems = append(s.Problems, line)
	}
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
