package main

import (
	"errors"
	"fmt"
)

// ErrUsage is returned when the command line does not name one suite log.
var ErrUsage = errors.New("foreignfailures: usage: foreignfailures [-baseline <file>] <integration suite log>")

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
