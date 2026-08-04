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
	"os"
	"os/exec"
	"sync"
)

// AttachChunk is one framed slice of container console output produced by an
// attach session.
type AttachChunk struct {
	// Stream identifies the origin of the data: "console" for a TTY session,
	// or "stdout"/"stderr" for a demultiplexed session.
	Stream string

	// Data is the raw output bytes.
	Data []byte
}

// AttachSession is an interactive attach broker over a pseudo-terminal. Output
// delivers console chunks until the session ends and the channel is closed;
// Wait blocks for the process exit code; Close tears the session down and
// reaps the process. It is safe to call Wait and Close from different
// goroutines.
type AttachSession interface {
	// Output returns the channel of console output chunks. The channel is
	// closed when the underlying process exits or the session is closed.
	Output() <-chan AttachChunk

	// Wait blocks until the attached process exits and returns its exit code.
	Wait() (int, error)

	// Close terminates the session, releases the pseudo-terminal, and reaps
	// the process. It is idempotent.
	Close() error
}

// Attacher is the capability of attaching an interactive session to a running
// container. The embedded podmanManager satisfies it.
type Attacher interface {
	AttachContainer(ctx context.Context, id string, opts ExecOptions) (AttachSession, error)
}

// startPTYExec is the seam used to launch a pseudo-terminal exec session. It
// is a package-level variable so tests can fake the OCI invocation.
var startPTYExec = defaultStartPTYExec

// Attach starts an interactive attach session against a running container by
// running an OCI-runtime exec attached to a freshly allocated pseudo-terminal.
// When no command is supplied it defaults to a shell. The session's console
// output is delivered on the returned channel and fanned out by the transport
// layer (e.g. the gRPC AttachContainer server stream).
func (r *Runtime) Attach(ctx context.Context, id string, opts ExecOptions) (AttachSession, error) {
	state, err := r.lookupContainer(id)
	if err != nil {
		return nil, err
	}

	if len(opts.Command) == 0 {
		opts.Command = []string{"/bin/sh"}
	}
	opts.TTY = true

	r.logger.Debug("attaching to container",
		"id", id,
		"name", state.Name,
		"command", opts.Command,
	)

	args := execArgs(state.ID, opts)
	session, err := startPTYExec(ctx, r.config.OCIRuntime, args)
	if err != nil {
		return nil, NewContainerError(id, "attach", err)
	}
	return session, nil
}

// ptySession is the concrete AttachSession backed by a pseudo-terminal master
// and the OCI-runtime child process.
type ptySession struct {
	cmd    *exec.Cmd
	master *os.File
	output chan AttachChunk
	done   chan struct{}

	waitOnce  sync.Once
	exitCode  int
	waitErr   error
	closeOnce sync.Once
}

// defaultStartPTYExec launches the OCI runtime with its stdio bound to a
// pseudo-terminal slave and starts a reader goroutine that fans the master
// output onto the session channel.
func defaultStartPTYExec(ctx context.Context, runtime string, args []string) (AttachSession, error) {
	master, slave, err := openPTY()
	if err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, runtime, args...)
	cmd.Stdin = slave
	cmd.Stdout = slave
	cmd.Stderr = slave
	cmd.SysProcAttr = ptySysProcAttr()

	if err := cmd.Start(); err != nil {
		_ = master.Close()
		_ = slave.Close()
		return nil, err
	}

	// The child owns the slave now; the parent only reads/writes the master.
	_ = slave.Close()

	s := &ptySession{
		cmd:    cmd,
		master: master,
		output: make(chan AttachChunk, 16),
		done:   make(chan struct{}),
	}
	go s.readLoop()
	return s, nil
}

// readLoop copies pseudo-terminal master output onto the session channel until
// the master returns an error (EOF/EIO on child exit) or the session is
// closed, then closes the channel.
func (s *ptySession) readLoop() {
	defer close(s.output)
	buf := make([]byte, 4096)
	for {
		n, err := s.master.Read(buf)
		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])
			select {
			case s.output <- AttachChunk{Stream: "console", Data: data}:
			case <-s.done:
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// Output returns the session's console output channel.
func (s *ptySession) Output() <-chan AttachChunk {
	return s.output
}

// Wait blocks until the attached process exits and returns its exit code.
func (s *ptySession) Wait() (int, error) {
	s.waitOnce.Do(func() {
		err := s.cmd.Wait()
		s.exitCode, s.waitErr = exitCodeFromRunErr(err)
	})
	return s.exitCode, s.waitErr
}

// Close terminates the session, closes the pseudo-terminal master, kills the
// process if it is still running, and reaps it. It is idempotent.
func (s *ptySession) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
		_ = s.master.Close()
		if s.cmd.Process != nil {
			_ = s.cmd.Process.Kill()
		}
		s.waitOnce.Do(func() {
			err := s.cmd.Wait()
			s.exitCode, s.waitErr = exitCodeFromRunErr(err)
		})
	})
	return nil
}
