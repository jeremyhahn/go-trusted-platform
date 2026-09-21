// Package runner is the one seam through which the disk image builder runs
// external commands (docker, losetup, mtools). Production code uses Exec;
// tests inject a Runner that records the argv and answers from a table, so
// no unit test ever touches a container runtime or a loop device.
package runner

import (
	"context"
	"os/exec"
)

// Runner runs name with args and returns its combined output.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// Exec is the production Runner: os/exec with combined stdout and stderr.
func Exec(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return out, &CommandError{Name: name, Args: args, Output: string(out), Err: err}
	}
	return out, nil
}

// CommandError reports a command that exited unsuccessfully, with its output.
type CommandError struct {
	Name   string
	Args   []string
	Output string
	Err    error
}

// Error implements error.
func (e *CommandError) Error() string {
	msg := "runner: " + e.Name + " failed: " + e.Err.Error()
	if e.Output != "" {
		msg += ": " + e.Output
	}
	return msg
}

// Unwrap returns the underlying exec error.
func (e *CommandError) Unwrap() error { return e.Err }
