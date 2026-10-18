package main

import (
	"errors"
	"fmt"
	"strings"
)

// ErrLookupDisabled is returned when GOPROXY=off: without the proxy and the
// dev Gitea no latest version can be known, and a check that cannot look
// anything up must not report that everything is current.
var ErrLookupDisabled = errors.New("depscheck: GOPROXY=off disables module version lookup, so the latest release of each dependency cannot be known; run make deps-check with access to the module proxy and the dev Gitea")

// ErrUsage is returned when no module directory is given.
var ErrUsage = errors.New("depscheck: usage: depscheck [-go <go command>] [-first-party <module path prefix>] <module dir>...")

// ParseError reports a go.mod line the parser does not understand.
type ParseError struct {
	File string
	Line int
	Text string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("depscheck: %s:%d: cannot parse %q", e.File, e.Line, e.Text)
}

// GoCommandError reports a go command that failed to run.
type GoCommandError struct {
	Dir    string
	Args   []string
	Stderr string
	Err    error
}

func (e *GoCommandError) Error() string {
	return fmt.Sprintf("depscheck: go %s in %s: %v: %s", strings.Join(e.Args, " "), e.Dir, e.Err, strings.TrimSpace(e.Stderr))
}

func (e *GoCommandError) Unwrap() error { return e.Err }

// ListOutputError reports `go list -json` output that does not decode.
type ListOutputError struct {
	Dir string
	Err error
}

func (e *ListOutputError) Error() string {
	return fmt.Sprintf("depscheck: decoding go list output in %s: %v", e.Dir, e.Err)
}

func (e *ListOutputError) Unwrap() error { return e.Err }

// LookupError reports a module whose latest version could not be looked up.
type LookupError struct {
	Module string
	Reason string
}

func (e *LookupError) Error() string {
	return fmt.Sprintf("depscheck: cannot look up the latest version of %s: %s", e.Module, e.Reason)
}
