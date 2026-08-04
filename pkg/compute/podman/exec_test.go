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
	"context"
	"errors"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestRuntime builds a Runtime rooted at a temporary directory with an OCI
// runtime name that resolves in PATH ("sh") so NewRuntime succeeds. The real
// runtime is never invoked because the exec/attach seams are faked.
func newTestRuntime(t *testing.T) *Runtime {
	t.Helper()

	dir := t.TempDir()
	config := &RuntimeConfig{
		Root:            dir + "/root",
		RunRoot:         dir + "/run",
		TmpDir:          dir + "/tmp",
		GraphDriverName: "vfs",
		StaticDir:       dir + "/static",
		VolumePath:      dir + "/volumes",
		OCIRuntime:      "sh",
		ImageStorePath:  dir + "/images",
	}

	rt, err := NewRuntime(context.Background(), config)
	require.NoError(t, err)
	require.NotNil(t, rt)
	return rt
}

// createTestContainer registers a container in the runtime state and returns
// its ID.
func createTestContainer(t *testing.T, rt *Runtime, name string) string {
	t.Helper()

	state, err := rt.CreateContainer(context.Background(), &ContainerConfig{
		Name:  name,
		Image: "alpine:latest",
	})
	require.NoError(t, err)
	require.NotNil(t, state)
	return state.ID
}

func TestRuntimeExec_Success(t *testing.T) {
	rt := newTestRuntime(t)
	id := createTestContainer(t, rt, "exec-ok")

	var gotArgs []string
	var gotTTY bool
	restore := runOCIExec
	runOCIExec = func(ctx context.Context, runtime string, args []string, tty bool) (*ExecResult, error) {
		gotArgs = args
		gotTTY = tty
		return &ExecResult{ExitCode: 0, Stdout: []byte("hello\n")}, nil
	}
	t.Cleanup(func() { runOCIExec = restore })

	result, err := rt.Exec(context.Background(), id, ExecOptions{
		Command:    []string{"echo", "hello"},
		Env:        []string{"FOO=bar"},
		WorkingDir: "/work",
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, 0, result.ExitCode)
	assert.Equal(t, "hello\n", string(result.Stdout))
	assert.False(t, gotTTY)

	// Verify the OCI exec argument vector is well-formed.
	assert.Equal(t, "exec", gotArgs[0])
	assert.Contains(t, gotArgs, "--env")
	assert.Contains(t, gotArgs, "FOO=bar")
	assert.Contains(t, gotArgs, "--cwd")
	assert.Contains(t, gotArgs, "/work")
	assert.Contains(t, gotArgs, "echo")
	assert.Contains(t, gotArgs, "hello")
}

func TestRuntimeExec_NonZeroExit(t *testing.T) {
	rt := newTestRuntime(t)
	id := createTestContainer(t, rt, "exec-nonzero")

	restore := runOCIExec
	runOCIExec = func(ctx context.Context, runtime string, args []string, tty bool) (*ExecResult, error) {
		return &ExecResult{ExitCode: 7, Stderr: []byte("boom")}, nil
	}
	t.Cleanup(func() { runOCIExec = restore })

	result, err := rt.Exec(context.Background(), id, ExecOptions{Command: []string{"false"}})
	require.NoError(t, err)
	assert.Equal(t, 7, result.ExitCode)
	assert.Equal(t, "boom", string(result.Stderr))
}

func TestRuntimeExec_MissingContainer(t *testing.T) {
	rt := newTestRuntime(t)

	_, err := rt.Exec(context.Background(), "does-not-exist", ExecOptions{Command: []string{"ls"}})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrContainerNotFound)
}

func TestRuntimeExec_EmptyCommand(t *testing.T) {
	rt := newTestRuntime(t)
	id := createTestContainer(t, rt, "exec-empty")

	_, err := rt.Exec(context.Background(), id, ExecOptions{})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrExecCommandRequired)
}

func TestRuntimeExec_RuntimeFailure(t *testing.T) {
	rt := newTestRuntime(t)
	id := createTestContainer(t, rt, "exec-fail")

	sentinel := errors.New("runtime blew up")
	restore := runOCIExec
	runOCIExec = func(ctx context.Context, runtime string, args []string, tty bool) (*ExecResult, error) {
		return nil, sentinel
	}
	t.Cleanup(func() { runOCIExec = restore })

	_, err := rt.Exec(context.Background(), id, ExecOptions{Command: []string{"ls"}})
	require.Error(t, err)
	assert.ErrorIs(t, err, sentinel)
}

func TestExitCodeFromRunErr(t *testing.T) {
	// Clean exit.
	code, err := exitCodeFromRunErr(nil)
	require.NoError(t, err)
	assert.Equal(t, 0, code)

	// A real non-zero process exit is surfaced as an exit code, not an error.
	runErr := exec.Command("sh", "-c", "exit 5").Run()
	code, err = exitCodeFromRunErr(runErr)
	require.NoError(t, err)
	assert.Equal(t, 5, code)

	// A non-exit error is propagated.
	sentinel := errors.New("not an exit error")
	code, err = exitCodeFromRunErr(sentinel)
	require.ErrorIs(t, err, sentinel)
	assert.Equal(t, -1, code)
}

func TestExecArgs(t *testing.T) {
	args := execArgs("cid", ExecOptions{
		Command:    []string{"ps", "-ef"},
		Env:        []string{"A=1", "B=2"},
		WorkingDir: "/root",
	})

	assert.Equal(t, []string{
		"exec",
		"--env", "A=1",
		"--env", "B=2",
		"--cwd", "/root",
		"cid",
		"ps", "-ef",
	}, args)
}

func TestManagerExec_Delegates(t *testing.T) {
	rt := newTestRuntime(t)
	id := createTestContainer(t, rt, "mgr-exec")

	restore := runOCIExec
	runOCIExec = func(ctx context.Context, runtime string, args []string, tty bool) (*ExecResult, error) {
		return &ExecResult{ExitCode: 0, Stdout: []byte("ok")}, nil
	}
	t.Cleanup(func() { runOCIExec = restore })

	m := &podmanManager{config: DefaultManagerConfig(), logger: rt.logger, runtime: rt}
	m.initialized.Store(true)

	result, err := m.ExecContainer(context.Background(), id, ExecOptions{Command: []string{"echo", "ok"}})
	require.NoError(t, err)
	assert.Equal(t, "ok", string(result.Stdout))
}

func TestManagerExec_NotInitialized(t *testing.T) {
	m := &podmanManager{config: DefaultManagerConfig(), logger: newTestRuntime(t).logger}
	_, err := m.ExecContainer(context.Background(), "cid", ExecOptions{Command: []string{"ls"}})
	require.ErrorIs(t, err, ErrClientNotConnected)
}
