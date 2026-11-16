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

package quicagent

import "fmt"

// ErrInvalidTLSConfig is returned by NewClient and NewServer when the TLS
// configuration cannot give a mutually authenticated session.
type ErrInvalidTLSConfig struct {
	Reason string
}

func (e ErrInvalidTLSConfig) Error() string {
	return "quicagent: invalid TLS configuration: " + e.Reason
}

// ErrConnect is returned when the client cannot reach or authenticate to
// the agent.
type ErrConnect struct {
	Addr  string
	Cause error
}

func (e ErrConnect) Error() string {
	return fmt.Sprintf("quicagent: connect to %s: %v", e.Addr, e.Cause)
}

func (e ErrConnect) Unwrap() error { return e.Cause }

// ErrLoadTLS is a certificate, key or CA bundle file that could not be
// read or parsed.
type ErrLoadTLS struct {
	What  string
	Path  string
	Cause error
}

func (e ErrLoadTLS) Error() string {
	return fmt.Sprintf("quicagent: load %s from %q: %v", e.What, e.Path, e.Cause)
}

func (e ErrLoadTLS) Unwrap() error { return e.Cause }

// ErrNotConnected is returned by an operation on a client that has not
// connected, or whose connection has closed.
type ErrNotConnected struct {
	Addr string
}

func (e ErrNotConnected) Error() string {
	return fmt.Sprintf("quicagent: not connected to %s", e.Addr)
}

// ErrStream is returned when an operation's stream fails before the agent
// answers: the connection dropped, the context ended or the peer reset it.
type ErrStream struct {
	Op    string
	Cause error
}

func (e ErrStream) Error() string {
	return fmt.Sprintf("quicagent: %s stream: %v", e.Op, e.Cause)
}

func (e ErrStream) Unwrap() error { return e.Cause }

// ErrRemote carries a failure the agent reported for an operation.
type ErrRemote struct {
	Op      string
	Message string
}

func (e ErrRemote) Error() string {
	return fmt.Sprintf("quicagent: agent %s failed: %s", e.Op, e.Message)
}

// ErrCommand is returned by Run when the command exits non-zero or the
// agent cannot start it (ExitCode -1, Cause set).
type ErrCommand struct {
	Command  string
	Output   string
	ExitCode int
	Cause    error
}

func (e ErrCommand) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("quicagent: command %q: %v", e.Command, e.Cause)
	}
	return fmt.Sprintf("quicagent: command %q exited with status %d: %s", e.Command, e.ExitCode, e.Output)
}

func (e ErrCommand) Unwrap() error { return e.Cause }

// ErrDigestMismatch is returned by CopyFileStream when the sha256 the agent
// computed over the bytes it wrote differs from the sender's.
type ErrDigestMismatch struct {
	Path   string
	Local  string
	Remote string
}

func (e ErrDigestMismatch) Error() string {
	return fmt.Sprintf("quicagent: sha256 mismatch for %s: sent %s, agent wrote %s", e.Path, e.Local, e.Remote)
}

// ErrFrameTooLarge is returned when a frame header announces more than
// maxFrameSize bytes.
type ErrFrameTooLarge struct {
	Size uint32
}

func (e ErrFrameTooLarge) Error() string {
	return fmt.Sprintf("quicagent: frame of %d bytes exceeds the %d byte limit", e.Size, maxFrameSize)
}

// ErrSourceChanged reports a local file that ended before the size
// announced to the agent: it shrank during the upload.
type ErrSourceChanged struct {
	Path      string
	Announced int64
	Sent      int64
}

func (e ErrSourceChanged) Error() string {
	return fmt.Sprintf("quicagent: %s ended after %d of the %d bytes announced", e.Path, e.Sent, e.Announced)
}

// ErrOutputTooLarge reports a command whose combined stdout and stderr
// passed the agent's output budget; the agent killed it.
type ErrOutputTooLarge struct {
	Limit int
}

func (e ErrOutputTooLarge) Error() string {
	return fmt.Sprintf("quicagent: command output passed the %d byte limit; the command was killed", e.Limit)
}
