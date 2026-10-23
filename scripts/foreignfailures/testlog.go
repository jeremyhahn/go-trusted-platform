package main

import (
	"bufio"
	"io"
	"os"
	"strings"
)

// panicPrefix starts the runtime's report of an unrecovered panic. A nested
// panic is printed indented by a tab, so both forms are read.
const panicPrefix = "panic: "

// panicRun is an unrecovered panic that killed a test binary.
type panicRun struct {
	// Messages are every "panic: " line's message, the runtime's
	// " [recovered...]" note removed, in output order.
	Messages []string
	// Frames are the function lines of the first goroutine the runtime
	// printed: the panicking one, as GOTRACEBACK's default prints only it.
	Frames []string
}

// packageRun is one package `go test -v` reported FAIL.
type packageRun struct {
	Package string // module-relative import path
	// BinaryFailed is the test binary's own closing "FAIL" line. A binary
	// a panic killed prints none.
	BinaryFailed bool
	FailedTests  []string
	Panic        *panicRun
	// Problems are lines inside the package's output that no test carries.
	Problems []string
}

// goTestLog is the output of one multi-package `go test -v` run, as
// `make test` prints it: package after package, no runner sections.
type goTestLog struct {
	module string
	// Failed are the packages go test reported FAIL, in output order.
	Failed []*packageRun
	// Passed are the packages go test reported ok, module-relative.
	Passed []string
	// Problems are failures no package carries: a build or setup failure,
	// failed tests printed before a passing package's result.
	Problems []string
	// Finished is the go test command's closing "FAIL" after its last
	// package result: without it the run did not reach its end.
	Finished bool

	pending     packageRun
	inStack     bool
	afterResult bool
}

// readGoTestLog reads a `go test -v` log from path.
func readGoTestLog(path, module string) (*goTestLog, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, &ReadError{Path: path, Err: err}
	}
	defer f.Close()
	return parseGoTestLog(path, module, f)
}

// parseGoTestLog reads `go test -v` output for packages under module.
func parseGoTestLog(name, module string, r io.Reader) (*goTestLog, error) {
	log := &goTestLog{module: module}
	lines := 0
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		lines++
		log.read(strings.TrimRight(scanner.Text(), "\r"))
	}
	if err := scanner.Err(); err != nil {
		return nil, &ReadError{Path: name, Err: err}
	}
	if lines == 0 {
		return nil, ErrEmptyLog
	}
	if log.pending.failed() || log.pending.Panic != nil {
		log.Problems = append(log.Problems, "failed tests or a panic with no package result line: the log ends inside a package")
	}
	return log, nil
}

// read takes one line of the log.
func (l *goTestLog) read(line string) {
	if line == "FAIL" && l.afterResult {
		l.Finished = true
		return
	}
	l.afterResult = false
	// Result lines first: the runtime prints no blank line between a
	// panic's stack and go test's FAIL line for the package.
	if m := packageFailRe.FindStringSubmatch(line); m != nil {
		l.closePackage(m[1], true)
		return
	}
	if packageOKRe.MatchString(line) || packageNoTestsRe.MatchString(line) {
		l.closePackage(packageField(line), false)
		return
	}
	if m := testFailRe.FindStringSubmatch(line); m != nil {
		l.pending.FailedTests = append(l.pending.FailedTests, m[1])
		return
	}
	if l.readStack(line) {
		return
	}
	trimmed := strings.TrimLeft(line, "\t")
	switch {
	case line == "FAIL":
		l.pending.BinaryFailed = true
	case strings.HasPrefix(trimmed, panicPrefix):
		if l.pending.Panic == nil {
			l.pending.Panic = &panicRun{}
		}
		message := strings.TrimPrefix(trimmed, panicPrefix)
		if i := strings.Index(message, " [recovered"); i >= 0 {
			message = message[:i]
		}
		l.pending.Panic.Messages = append(l.pending.Panic.Messages, message)
	case packageBrokenRe.MatchString(line):
		l.Problems = append(l.Problems, line)
		l.afterResult = true
	case strings.HasPrefix(line, "*** Test killed"):
		l.pending.Problems = append(l.pending.Problems, line)
	}
}

// readStack collects the first goroutine's frames after a panic, and
// reports whether line belonged to that stack.
func (l *goTestLog) readStack(line string) bool {
	p := l.pending.Panic
	if p == nil {
		return false
	}
	if !l.inStack {
		if len(p.Frames) == 0 && strings.HasPrefix(line, "goroutine ") {
			l.inStack = true
			return true
		}
		return false
	}
	switch {
	case line == "":
		// The blank line that ends the goroutine's stack.
		l.inStack = false
	case !strings.HasPrefix(line, "\t"):
		p.Frames = append(p.Frames, line)
	}
	return true
}

// closePackage ends the pending package at its result line.
func (l *goTestLog) closePackage(importPath string, failed bool) {
	l.inStack = false
	l.afterResult = true
	l.Finished = false
	result := l.pending
	l.pending = packageRun{}
	rel, inModule := strings.CutPrefix(importPath, l.module+"/")
	if !failed {
		// A passing binary's output is not a failure, whatever it logged:
		// a test may recover a panic on purpose and print its stack.
		if len(result.FailedTests) > 0 {
			l.Problems = append(l.Problems, "failed tests were printed before a passing package's result: "+importPath)
		}
		l.Passed = append(l.Passed, rel)
		return
	}
	if !inModule {
		l.Problems = append(l.Problems, "a package outside module "+l.module+" failed: "+importPath)
		return
	}
	result.Package = rel
	l.Failed = append(l.Failed, &result)
}

// packageField is the import path on an "ok" or "?" result line.
func packageField(line string) string {
	fields := strings.Split(line, "\t")
	if len(fields) < 2 {
		return ""
	}
	return fields[1]
}

// failed reports whether the package printed a failure of its own.
func (p *packageRun) failed() bool {
	return p.BinaryFailed || len(p.FailedTests) > 0
}
