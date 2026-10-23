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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeAttachSession is an in-memory AttachSession for exercising the attach
// broker without a real pseudo-terminal.
type fakeAttachSession struct {
	out      chan AttachChunk
	exitCode int
	waitErr  error
	closed   bool
}

func newFakeAttachSession(chunks []AttachChunk, exitCode int) *fakeAttachSession {
	out := make(chan AttachChunk, len(chunks))
	for _, c := range chunks {
		out <- c
	}
	close(out)
	return &fakeAttachSession{out: out, exitCode: exitCode}
}

func (f *fakeAttachSession) Output() <-chan AttachChunk { return f.out }
func (f *fakeAttachSession) Wait() (int, error)         { return f.exitCode, f.waitErr }
func (f *fakeAttachSession) Close() error               { f.closed = true; return nil }

func TestRuntimeAttach_Success(t *testing.T) {
	rt := newTestRuntime(t)
	id := createTestContainer(t, rt, "attach-ok")

	var gotArgs []string
	restore := startPTYExec
	startPTYExec = func(ctx context.Context, runtime string, args []string) (AttachSession, error) {
		gotArgs = args
		return newFakeAttachSession([]AttachChunk{
			{Stream: "console", Data: []byte("line1\n")},
			{Stream: "console", Data: []byte("line2\n")},
		}, 0), nil
	}
	t.Cleanup(func() { startPTYExec = restore })

	session, err := rt.Attach(context.Background(), id, ExecOptions{})
	require.NoError(t, err)
	require.NotNil(t, session)

	var output []byte
	for chunk := range session.Output() {
		output = append(output, chunk.Data...)
	}
	assert.Equal(t, "line1\nline2\n", string(output))

	code, err := session.Wait()
	require.NoError(t, err)
	assert.Equal(t, 0, code)

	// The default command is a shell.
	assert.Contains(t, gotArgs, "/bin/sh")
	assert.Equal(t, "exec", gotArgs[0])
}

func TestRuntimeAttach_CustomCommand(t *testing.T) {
	rt := newTestRuntime(t)
	id := createTestContainer(t, rt, "attach-cmd")

	var gotArgs []string
	restore := startPTYExec
	startPTYExec = func(ctx context.Context, runtime string, args []string) (AttachSession, error) {
		gotArgs = args
		return newFakeAttachSession(nil, 0), nil
	}
	t.Cleanup(func() { startPTYExec = restore })

	_, err := rt.Attach(context.Background(), id, ExecOptions{Command: []string{"/bin/bash", "-l"}})
	require.NoError(t, err)
	assert.Contains(t, gotArgs, "/bin/bash")
	assert.Contains(t, gotArgs, "-l")
}

func TestRuntimeAttach_MissingContainer(t *testing.T) {
	rt := newTestRuntime(t)
	_, err := rt.Attach(context.Background(), "ghost", ExecOptions{})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrContainerNotFound)
}

func TestRuntimeAttach_StartFailure(t *testing.T) {
	rt := newTestRuntime(t)
	id := createTestContainer(t, rt, "attach-fail")

	sentinel := errors.New("pty allocation failed")
	restore := startPTYExec
	startPTYExec = func(ctx context.Context, runtime string, args []string) (AttachSession, error) {
		return nil, sentinel
	}
	t.Cleanup(func() { startPTYExec = restore })

	_, err := rt.Attach(context.Background(), id, ExecOptions{})
	require.Error(t, err)
	assert.ErrorIs(t, err, sentinel)
}

func TestManagerAttach_Delegates(t *testing.T) {
	rt := newTestRuntime(t)
	id := createTestContainer(t, rt, "mgr-attach")

	restore := startPTYExec
	startPTYExec = func(ctx context.Context, runtime string, args []string) (AttachSession, error) {
		return newFakeAttachSession([]AttachChunk{{Stream: "console", Data: []byte("hi")}}, 0), nil
	}
	t.Cleanup(func() { startPTYExec = restore })

	m := &podmanManager{config: DefaultManagerConfig(), logger: rt.logger, runtime: rt}
	m.initialized.Store(true)

	session, err := m.AttachContainer(context.Background(), id, ExecOptions{})
	require.NoError(t, err)
	require.NotNil(t, session)
	chunk := <-session.Output()
	assert.Equal(t, "hi", string(chunk.Data))
}

func TestManagerAttach_NotInitialized(t *testing.T) {
	m := &podmanManager{config: DefaultManagerConfig(), logger: newTestRuntime(t).logger}
	_, err := m.AttachContainer(context.Background(), "cid", ExecOptions{})
	require.ErrorIs(t, err, ErrClientNotConnected)
}

func TestRunOCIExecTTY_ViaSeam(t *testing.T) {
	// The buffered TTY exec path drains the attach session's output into the
	// result Stdout and reports the exit code.
	session := newFakeAttachSession([]AttachChunk{
		{Stream: "console", Data: []byte("tty-")},
		{Stream: "console", Data: []byte("out")},
	}, 3)
	restore := startPTYExec
	startPTYExec = func(ctx context.Context, runtime string, args []string) (AttachSession, error) {
		return session, nil
	}
	t.Cleanup(func() { startPTYExec = restore })

	result, err := runOCIExecTTY(context.Background(), "sh", []string{"exec", "cid", "sh"})
	require.NoError(t, err)
	assert.Equal(t, "tty-out", string(result.Stdout))
	assert.Equal(t, 3, result.ExitCode)
	assert.True(t, session.closed, "the buffered exec owns its session and must release the PTY")
}
