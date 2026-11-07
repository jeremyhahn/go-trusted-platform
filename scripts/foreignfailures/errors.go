package main

import (
	"errors"
	"fmt"
)

// ErrUsage is returned when the command line does not name one suite log.
var ErrUsage = errors.New("foreignfailures: usage: foreignfailures [-job integration|fips] [-baseline <file>] [-tags <tags>] [-skip-tests <regexp>] <suite log>")

// ErrNotFIPSMode is returned when the fips job would rerun tests outside
// fips140=only: the rerun must run under the same environment as the run.
var ErrNotFIPSMode = errors.New("foreignfailures: -job fips reruns tests and needs GODEBUG=fips140=only and GOFIPS140 in its environment")

// JobError names a -job value no job is registered under.
type JobError struct {
	Job string
}

func (e *JobError) Error() string {
	return fmt.Sprintf("foreignfailures: unknown -job %q (want integration or fips)", e.Job)
}

// SkipPatternError is a -skip-tests value that is not a regular expression.
type SkipPatternError struct {
	Pattern string
	Err     error
}

func (e *SkipPatternError) Error() string {
	return fmt.Sprintf("foreignfailures: -skip-tests %q: %v", e.Pattern, e.Err)
}

func (e *SkipPatternError) Unwrap() error { return e.Err }

// RerunError is a rerun of a panicked package's other tests that could not
// run, or did not pass, under fips140=only.
type RerunError struct {
	Package string
	Reason  string
}

func (e *RerunError) Error() string {
	return fmt.Sprintf("%s: the rerun of its other tests under fips140=only %s", e.Package, e.Reason)
}

// RerunBoundError is a FIPS rerun whose every round, up to one per
// baseline row for its package, ended in a listed test's panic: each round
// excludes one more listed test, so a further round cannot be a new row's.
type RerunBoundError struct {
	Package string
	Bound   int
}

func (e *RerunBoundError) Error() string {
	return fmt.Sprintf("%s: the rerun of its other tests under fips140=only still panicked in a listed test after %d rounds, its bound (one per baseline row for the package)", e.Package, e.Bound)
}

// ErrEmptyLog is returned for a suite log with no lines: nothing in it can be
// attributed to a test, so the suite's failure stands.
var ErrEmptyLog = errors.New("foreignfailures: the integration suite log is empty")

// BaselineError is a baseline row the checker refuses.
type BaselineError struct {
	File   string
	Line   int
	Reason string
}

func (e *BaselineError) Error() string {
	return fmt.Sprintf("foreignfailures: %s:%d: %s", e.File, e.Line, e.Reason)
}

// ReadError is a failure to read one of the checker's input files.
type ReadError struct {
	Path string
	Err  error
}

func (e *ReadError) Error() string {
	return fmt.Sprintf("foreignfailures: reading %s: %v", e.Path, e.Err)
}

func (e *ReadError) Unwrap() error { return e.Err }

// WriteError is a failure to write the checker's output: a verdict whose
// output was lost does not pass.
type WriteError struct {
	Err error
}

func (e *WriteError) Error() string {
	return fmt.Sprintf("foreignfailures: writing output: %v", e.Err)
}

func (e *WriteError) Unwrap() error { return e.Err }
