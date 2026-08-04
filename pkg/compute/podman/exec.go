// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package podman

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
)

// ErrExecCommandRequired is returned when an exec request carries no command.
var ErrExecCommandRequired = errors.New("exec command is required")

// ErrExecNotSupported is returned when the backend cannot execute commands
// inside containers.
var ErrExecNotSupported = errors.New("container exec not supported by backend")

// ExecOptions configures a command executed inside a running container via the
// OCI runtime's `exec` verb. It complements the pre-existing ExecConfig by
// carrying the OCI-oriented environment list and TTY flag the runtime needs.
type ExecOptions struct {
	// Command is the argv executed inside the container (argv[0] is the binary).
	Command []string

	// Env is a list of KEY=VALUE strings added to the exec environment.
	Env []string

	// WorkingDir is the working directory for the executed process.
	WorkingDir string

	// TTY allocates a pseudo-terminal for the process. When set on a buffered
	// Exec the combined output is returned on the result's Stdout.
	TTY bool
}

// Executor is the capability of running a command inside a running container.
// The embedded podmanManager satisfies it; callers type-assert against it so
// the base PodmanManager interface stays minimal. The buffered result reuses
// the package's ExecResult type.
type Executor interface {
	ExecContainer(ctx context.Context, id string, opts ExecOptions) (*ExecResult, error)
}

// runOCIExec is the seam used to invoke the OCI runtime for a buffered exec.
// It is a package-level variable so tests can fake the runtime invocation
// without a real container or host mutation.
var runOCIExec = defaultRunOCIExec

// execArgs builds the OCI-runtime `exec` argument vector for the given
// container and options. The pseudo-terminal (when requested) is supplied by
// the caller through the process stdio, so the runtime's own `--tty` flag is
// intentionally not added here.
func execArgs(containerID string, opts ExecOptions) []string {
	args := make([]string, 0, 4+len(opts.Env)*2+len(opts.Command))
	args = append(args, "exec")
	for _, env := range opts.Env {
		args = append(args, "--env", env)
	}
	if opts.WorkingDir != "" {
		args = append(args, "--cwd", opts.WorkingDir)
	}
	args = append(args, containerID)
	args = append(args, opts.Command...)
	return args
}

// Exec runs a command inside a running container and returns its buffered
// output and exit code. It mirrors the runc-invocation pattern used by
// StartContainer: `<runtime> exec [--env ...] [--cwd ...] <id> <cmd...>`.
func (r *Runtime) Exec(ctx context.Context, id string, opts ExecOptions) (*ExecResult, error) {
	state, err := r.lookupContainer(id)
	if err != nil {
		return nil, err
	}

	if len(opts.Command) == 0 {
		return nil, NewContainerError(id, "exec", ErrExecCommandRequired)
	}

	r.logger.Debug("executing command in container",
		"id", id,
		"name", state.Name,
		"command", opts.Command,
		"tty", opts.TTY,
	)

	args := execArgs(state.ID, opts)
	result, err := runOCIExec(ctx, r.config.OCIRuntime, args, opts.TTY)
	if err != nil {
		return nil, NewContainerError(id, "exec", err)
	}
	return result, nil
}

// defaultRunOCIExec is the production implementation of the exec seam. For a
// non-TTY exec it captures stdout and stderr independently; for a TTY exec it
// allocates a pseudo-terminal, runs the process attached to it, and returns
// the combined terminal output on Stdout.
func defaultRunOCIExec(ctx context.Context, runtime string, args []string, tty bool) (*ExecResult, error) {
	if tty {
		return runOCIExecTTY(ctx, runtime, args)
	}

	cmd := exec.CommandContext(ctx, runtime, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	exitCode, execErr := exitCodeFromRunErr(err)
	if execErr != nil {
		return nil, execErr
	}

	return &ExecResult{
		ExitCode: exitCode,
		Stdout:   stdout.Bytes(),
		Stderr:   stderr.Bytes(),
	}, nil
}

// runOCIExecTTY runs a buffered exec attached to a pseudo-terminal and returns
// the combined output. It is the buffered counterpart of the attach broker.
func runOCIExecTTY(ctx context.Context, runtime string, args []string) (*ExecResult, error) {
	session, err := startPTYExec(ctx, runtime, args)
	if err != nil {
		return nil, err
	}
	defer session.Close()

	var out bytes.Buffer
	for chunk := range session.Output() {
		out.Write(chunk.Data)
	}

	exitCode, waitErr := session.Wait()
	if waitErr != nil {
		return nil, waitErr
	}

	return &ExecResult{
		ExitCode: exitCode,
		Stdout:   out.Bytes(),
	}, nil
}

// exitCodeFromRunErr extracts the process exit code from an *exec.ExitError,
// treating a clean exit as code 0. A non-exit error (e.g. runtime not found)
// is returned as the second value.
func exitCodeFromRunErr(err error) (int, error) {
	if err == nil {
		return 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), nil
	}
	return -1, err
}
