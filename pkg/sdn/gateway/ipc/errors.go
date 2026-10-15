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

package ipc

import (
	"errors"
	"fmt"
)

// ErrEmptySocketPath is the cause of an ErrSocketPath for a Dial with no
// path: gRPC would otherwise accept the target and fail on the first RPC.
var ErrEmptySocketPath = errors.New("socket path is empty")

// ErrPeerDenied reports a Unix socket caller whose kernel-verified uid is
// not admitted to the service it called.
type ErrPeerDenied struct {
	Service string
	UID     uint32
	PID     int32
}

func (e *ErrPeerDenied) Error() string {
	return fmt.Sprintf("gatewayd ipc: uid %d (pid %d) is not admitted to %s", e.UID, e.PID, e.Service)
}

// ErrUnknownService reports an RPC whose service is not part of the
// contract; the policy fails closed on it.
type ErrUnknownService struct {
	Method string
}

func (e *ErrUnknownService) Error() string {
	return fmt.Sprintf("gatewayd ipc: no peer policy for method %q", e.Method)
}

// ErrSocketPath reports a control socket the server could not bind or
// secure.
type ErrSocketPath struct {
	Path  string
	Op    string
	Cause error
}

func (e *ErrSocketPath) Error() string {
	return fmt.Sprintf("gatewayd ipc: %s %q: %v", e.Op, e.Path, e.Cause)
}

func (e *ErrSocketPath) Unwrap() error {
	return e.Cause
}

// ErrSocketGroup reports a control socket that did not get the group its
// peers reach it through. The supervisor's setgid control-socket directory
// gives every socket bound in it that group; a socket bound elsewhere needs a
// chown, which the datapath child — holding no CAP_CHOWN and not in the
// group — cannot make.
type ErrSocketGroup struct {
	Path  string
	Want  int
	Got   int
	Cause error
}

func (e *ErrSocketGroup) Error() string {
	return fmt.Sprintf("gatewayd ipc: socket %q has group %d, not %d, and cannot be given it (the control-socket directory must be setgid and owned by that group): %v",
		e.Path, e.Got, e.Want, e.Cause)
}

func (e *ErrSocketGroup) Unwrap() error {
	return e.Cause
}

// ErrDocument reports a gwstate document that did not encode or decode
// across the socket.
type ErrDocument struct {
	Document string
	Cause    error
}

func (e *ErrDocument) Error() string {
	return fmt.Sprintf("gatewayd ipc: %s document: %v", e.Document, e.Cause)
}

func (e *ErrDocument) Unwrap() error {
	return e.Cause
}

// ErrRemoteApply carries the datapath child's Gateway.Apply error text to
// the supervisor. The reconciliation state travels beside it.
type ErrRemoteApply struct {
	Message string
}

func (e *ErrRemoteApply) Error() string {
	return "gatewayd ipc: datapath apply failed: " + e.Message
}

// ErrServerNotListening reports Serve before Listen.
type ErrServerNotListening struct{}

func (e *ErrServerNotListening) Error() string {
	return "gatewayd ipc: server has no listener; call Listen first"
}
