// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package ipsec

import (
	"errors"
	"net/netip"
)

var (
	// ErrMissingDependency is returned when a constructor or Attach is
	// handed a nil collaborator.
	ErrMissingDependency = errors.New("ipsec: missing dependency")
	// ErrNotEvicted is returned when Readmit names a peer that is not
	// evicted.
	ErrNotEvicted = errors.New("ipsec: peer is not evicted")
	// ErrNotSocket is returned when the VICI socket path is not a socket.
	ErrNotSocket = errors.New("ipsec: not a socket")
	// ErrSocketMode is returned when the VICI socket is not mode 0600.
	ErrSocketMode = errors.New("ipsec: socket mode is not 0600")
	// ErrSocketOwner is returned when the VICI socket is not owned by
	// platformd's user.
	ErrSocketOwner = errors.New("ipsec: socket is not owned by the platform user")
	// ErrSocketPeer is returned when the process serving the VICI socket
	// did not listen as charon's uid.
	ErrSocketPeer = errors.New("ipsec: socket is not served by charon")
	// ErrInvalidMessage is returned when a request lacks what charon needs:
	// a certificate without data, a token key without an ID.
	ErrInvalidMessage = errors.New("ipsec: incomplete request")
	// ErrCommandRefused is returned when charon answers a VICI command with
	// success=no: it understood the request and refused it.
	ErrCommandRefused = errors.New("ipsec: charon refused the command")
	// ErrCharonGone is returned when a connection to charon ended.
	ErrCharonGone = errors.New("ipsec: charon connection ended")
	// ErrNoCertificate is returned when a tunnel identity has no
	// certificate.
	ErrNoCertificate = errors.New("ipsec: tunnel identity has no certificate")
	// ErrCertificateAddress is returned when the tunnel certificate does
	// not carry the local address as an IP subject alternative name.
	ErrCertificateAddress = errors.New("ipsec: tunnel certificate does not name the local address")
	// ErrNoKeyID is returned when a tunnel identity names no key.
	ErrNoKeyID = errors.New("ipsec: tunnel identity names no token key")
	// ErrNoRoot is returned when a tunnel identity's chain does not end in
	// a self-signed root CA.
	ErrNoRoot = errors.New("ipsec: tunnel identity chain does not end in a root CA")
	// ErrChainBroken is returned when a certificate of a tunnel identity's
	// chain is not signed by the certificate after it.
	ErrChainBroken = errors.New("ipsec: tunnel identity chain is not signed in order")
	// ErrNotAnchored is returned when a tunnel identity's root is not a
	// certificate of the platform anchor.
	ErrNotAnchored = errors.New("ipsec: tunnel identity does not chain to the platform anchor")
	// ErrCRLQueueFull is returned when a CRL cannot be verified yet and the
	// queue of such CRLs already holds as many issuers as it takes.
	ErrCRLQueueFull = errors.New("ipsec: too many CRLs await a tunnel identity")
	// ErrCRLStale is returned when a pushed CRL has no NextUpdate, or one
	// that has passed.
	ErrCRLStale = errors.New("ipsec: CRL is past its next update")
	// ErrCRLUntrusted is returned when a pushed CRL is not signed by a CA
	// of the tunnel identity.
	ErrCRLUntrusted = errors.New("ipsec: CRL is not signed by a tunnel CA")
	// ErrLinkWatchEnded is returned when the kernel ends the link
	// subscription the forward block follows the fabric interface by.
	ErrLinkWatchEnded = errors.New("ipsec: fabric link subscription ended")
	// ErrNoVTEPAdmission is returned when a route names a VTEP on a node
	// that has no VTEP admitter: its peers are the static peers alone.
	ErrNoVTEPAdmission = errors.New("ipsec: no VTEP admitter; only static peers are admitted")
)

// FloorError reports a fail-closed floor that could not be installed. The
// node must not send on the fabric without it.
type FloorError struct {
	// Err is the layer's failure: an OpError of nftables apply or xfrm
	// install.
	Err error
}

// Error implements the error interface.
func (e *FloorError) Error() string {
	return "ipsec: fail-closed floor not installed: " + e.Err.Error()
}

// Unwrap implements errors.Unwrap.
func (e *FloorError) Unwrap() error { return e.Err }

// CommandError reports a VICI command that failed: charon refused it, or
// the connection failed under it.
type CommandError struct {
	// Command is the VICI command.
	Command string
	// Reason is charon's errmsg when Err is ErrCommandRefused.
	Reason string
	// Err is the cause.
	Err error
}

// Error implements the error interface.
func (e *CommandError) Error() string {
	msg := "vici " + e.Command + ": " + e.Err.Error()
	if e.Reason != "" {
		msg += ": " + e.Reason
	}
	return msg
}

// Unwrap implements errors.Unwrap.
func (e *CommandError) Unwrap() error { return e.Err }

// SocketError reports a VICI socket that was refused or could not be
// opened.
type SocketError struct {
	// Path is the socket path.
	Path string
	// Err is the cause: ErrNotSocket, ErrSocketMode, ErrSocketOwner,
	// ErrSocketPeer, or the failure to open, stat, dial or read the peer's
	// credentials.
	Err error
}

// Error implements the error interface.
func (e *SocketError) Error() string { return "ipsec: vici socket " + e.Path + ": " + e.Err.Error() }

// Unwrap implements errors.Unwrap.
func (e *SocketError) Unwrap() error { return e.Err }

// CloseError reports a close that failed after another failure.
type CloseError struct {
	// Cause is the failure that led to the close.
	Cause error
	// Err is the close's own failure.
	Err error
}

// Error implements the error interface.
func (e *CloseError) Error() string { return e.Cause.Error() + " (close: " + e.Err.Error() + ")" }

// Unwrap implements errors.Unwrap: both errors match.
func (e *CloseError) Unwrap() []error { return []error{e.Cause, e.Err} }

// PeerError reports an operation on one peer that failed.
type PeerError struct {
	// Peer is the VTEP address.
	Peer netip.Addr
	// Op is the step: "admit", "load-conn", "unload-conn", "drop", ...
	Op string
	// Err is the cause.
	Err error
}

// Error implements the error interface.
func (e *PeerError) Error() string {
	return "ipsec: " + e.Op + " " + e.Peer.String() + ": " + e.Err.Error()
}

// Unwrap implements errors.Unwrap.
func (e *PeerError) Unwrap() error { return e.Err }

// OpError reports a charon operation, not tied to one peer, that failed.
type OpError struct {
	// Op is the VICI command.
	Op string
	// Err is the cause.
	Err error
}

// Error implements the error interface.
func (e *OpError) Error() string { return "ipsec: " + e.Op + ": " + e.Err.Error() }

// Unwrap implements errors.Unwrap.
func (e *OpError) Unwrap() error { return e.Err }

// IdentityMismatchError reports an IKE_SA whose peer authenticated as an
// identity other than the address the connection runs to. The SA is
// terminated.
type IdentityMismatchError struct {
	// Conn is the connection name.
	Conn string
	// RemoteHost is the address the SA runs to.
	RemoteHost string
	// RemoteID is the identity the peer authenticated as.
	RemoteID string
}

// Error implements the error interface.
func (e *IdentityMismatchError) Error() string {
	return "ipsec: " + e.Conn + ": peer at " + e.RemoteHost + " authenticated as " + e.RemoteID
}
