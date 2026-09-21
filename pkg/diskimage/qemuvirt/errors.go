package qemuvirt

import "errors"

// StageError reports a failure staging the built kernel onto the media.
type StageError struct {
	Step string
	Err  error
}

func (e *StageError) Error() string { return "qemuvirt: " + e.Step + ": " + e.Err.Error() }
func (e *StageError) Unwrap() error { return e.Err }

// errNoKernel is the cause when StageKernel is given no artifacts.
var errNoKernel = errors.New("no kernel artifacts to stage")
