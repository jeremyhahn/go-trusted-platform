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

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
)

// ErrEmptySocketPath is the cause of an ErrSocketPath for a Dial with no
// path: gRPC would otherwise accept the target and fail on the first RPC.
var ErrEmptySocketPath = errors.New("socket path is empty")

// ErrPeerDenied reports a Unix socket caller whose kernel-verified uid is
// not admitted to the method it called.
type ErrPeerDenied struct {
	Method string
	UID    uint32
	PID    int32
}

func (e *ErrPeerDenied) Error() string {
	return fmt.Sprintf("gatewayd ipc: uid %d (pid %d) is not admitted to %s", e.UID, e.PID, e.Method)
}

// ErrUnknownService reports an RPC whose method has no entry in the
// policy's authorization table; the policy fails closed on it.
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

// ErrRemoteService is a service error the datapath child reported over
// GatewayServicesService, carried as its text. Sentinel is the service
// package's sentinel the refusal class named, nil for an untyped failure,
// so errors.Is matches as it would in-process.
type ErrRemoteService struct {
	Message  string
	Sentinel error
}

func (e *ErrRemoteService) Error() string {
	if e.Message == "" && e.Sentinel != nil {
		return e.Sentinel.Error()
	}
	return e.Message
}

func (e *ErrRemoteService) Unwrap() error {
	return e.Sentinel
}

// ErrServiceUnreachable reports a GatewayServicesService call the datapath
// child did not answer: nothing listens on the socket, the peer policy
// refused the caller, or the call failed in transit. It matches
// *gateway.ErrServiceNotActive for Service, so every API transport reports
// it as the service being unavailable.
type ErrServiceUnreachable struct {
	Socket  string
	Service string
	Cause   error
}

func (e *ErrServiceUnreachable) Error() string {
	return fmt.Sprintf("gatewayd ipc: %s unreachable on %q: %v", e.Service, e.Socket, e.Cause)
}

func (e *ErrServiceUnreachable) Unwrap() []error {
	return []error{&gateway.ErrServiceNotActive{Service: e.Service}, e.Cause}
}

// ErrConntrackZone reports a conntrack zone outside the wire's int32.
type ErrConntrackZone struct {
	Zone int
}

func (e *ErrConntrackZone) Error() string {
	return fmt.Sprintf("gatewayd ipc: conntrack zone %d is out of range", e.Zone)
}

// ErrVIPKey reports a VIP key whose address is not an "address:port".
type ErrVIPKey struct {
	Address string
	Cause   error
}

func (e *ErrVIPKey) Error() string {
	return fmt.Sprintf("gatewayd ipc: VIP address %q: %v", e.Address, e.Cause)
}

func (e *ErrVIPKey) Unwrap() error {
	return e.Cause
}
