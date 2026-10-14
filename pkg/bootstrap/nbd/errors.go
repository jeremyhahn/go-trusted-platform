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

package nbd

import "fmt"

// ErrInvalidConfig is returned by NewServer for a configuration it cannot
// serve.
type ErrInvalidConfig struct {
	Field  string
	Reason string
}

func (e ErrInvalidConfig) Error() string {
	return fmt.Sprintf("nbd: invalid config %s: %s", e.Field, e.Reason)
}

// ErrCmdline refuses a kernel command line whose NBD parameter is missing,
// repeated or malformed.
type ErrCmdline struct {
	Param  string
	Reason string
}

func (e ErrCmdline) Error() string {
	return fmt.Sprintf("nbd: kernel command line %s: %s", e.Param, e.Reason)
}

// ErrServeFailed is returned by Serve when the listener fails for a reason
// other than shutdown.
type ErrServeFailed struct {
	Cause error
}

func (e ErrServeFailed) Error() string {
	return fmt.Sprintf("nbd: serve failed: %v", e.Cause)
}

func (e ErrServeFailed) Unwrap() error {
	return e.Cause
}

// ErrUnsupportedClientFlags ends a handshake whose client flags lack
// NBD_FLAG_C_FIXED_NEWSTYLE or carry a bit this server does not know.
type ErrUnsupportedClientFlags struct {
	Flags uint32
}

func (e ErrUnsupportedClientFlags) Error() string {
	return fmt.Sprintf("nbd: unsupported client flags %#x (fixed newstyle required)", e.Flags)
}

// ErrTLSRequired ends a session that tried to negotiate before
// NBD_OPT_STARTTLS. Option is the last option the client sent.
type ErrTLSRequired struct {
	Option uint32
}

func (e ErrTLSRequired) Error() string {
	return fmt.Sprintf("nbd: option %d refused before STARTTLS: TLS is required", e.Option)
}

// ErrTLSHandshake wraps a TLS handshake failure that has no more specific
// typed error.
type ErrTLSHandshake struct {
	Cause error
}

func (e ErrTLSHandshake) Error() string {
	return fmt.Sprintf("nbd: TLS handshake failed: %v", e.Cause)
}

func (e ErrTLSHandshake) Unwrap() error {
	return e.Cause
}

// ErrClientCertificateRequired refuses a client that presented no
// certificate.
type ErrClientCertificateRequired struct{}

func (ErrClientCertificateRequired) Error() string {
	return "nbd: client certificate required"
}

// ErrClientCertificateUntrusted refuses a client certificate whose chain
// does not verify against the platform anchor for client authentication.
type ErrClientCertificateUntrusted struct {
	Subject string
	Cause   error
}

func (e ErrClientCertificateUntrusted) Error() string {
	return fmt.Sprintf("nbd: client certificate %q not trusted by the platform anchor: %v", e.Subject, e.Cause)
}

func (e ErrClientCertificateUntrusted) Unwrap() error {
	return e.Cause
}

// ErrTrustAnchor refuses a handshake because the platform anchor could not
// be read (trust.ErrAnchorUnavailable, trust.ErrAnchorEmpty).
type ErrTrustAnchor struct {
	Cause error
}

func (e ErrTrustAnchor) Error() string {
	return fmt.Sprintf("nbd: platform anchor unavailable: %v", e.Cause)
}

func (e ErrTrustAnchor) Unwrap() error {
	return e.Cause
}

// ErrUnknownIdentity refuses a verified client whose identity is not a
// diskless-nbd node this server exports a volume for.
type ErrUnknownIdentity struct {
	Identity string
}

func (e ErrUnknownIdentity) Error() string {
	return fmt.Sprintf("nbd: identity %q is not a diskless-nbd node", e.Identity)
}

// ErrExportNotPermitted refuses a request for an export other than the
// client's own.
type ErrExportNotPermitted struct {
	Identity string
	Export   string
}

func (e ErrExportNotPermitted) Error() string {
	return fmt.Sprintf("nbd: identity %q may not open export %q", e.Identity, e.Export)
}

// ErrVolume reports a volume that could not be created, opened or used.
type ErrVolume struct {
	Identity string
	Op       string
	Cause    error
}

func (e ErrVolume) Error() string {
	return fmt.Sprintf("nbd: volume %q: %s: %v", e.Identity, e.Op, e.Cause)
}

func (e ErrVolume) Unwrap() error {
	return e.Cause
}

// ErrNotInstalled is returned for a volume that holds no installed node: it
// does not exist yet, or it is blank, with no partition table. Installing
// onto it destroys nothing.
type ErrNotInstalled struct {
	Identity string
}

func (e ErrNotInstalled) Error() string {
	return fmt.Sprintf("nbd: volume %q holds no installed node", e.Identity)
}

// ErrMetadataArea is returned for a partitioned volume whose metadata area
// cannot be read, or does not hold the file asked for. The volume may hold a
// node's root, so it is never taken for a blank one.
type ErrMetadataArea struct {
	Identity string
	Reason   string
	Cause    error
}

func (e ErrMetadataArea) Error() string {
	if e.Cause == nil {
		return fmt.Sprintf("nbd: volume %q: metadata area: %s", e.Identity, e.Reason)
	}
	return fmt.Sprintf("nbd: volume %q: metadata area: %s: %v", e.Identity, e.Reason, e.Cause)
}

func (e ErrMetadataArea) Unwrap() error {
	return e.Cause
}

// ErrProtocol ends a session that broke the NBD protocol.
type ErrProtocol struct {
	Reason string
	Cause  error
}

func (e ErrProtocol) Error() string {
	if e.Cause == nil {
		return fmt.Sprintf("nbd: protocol error: %s", e.Reason)
	}
	return fmt.Sprintf("nbd: protocol error: %s: %v", e.Reason, e.Cause)
}

func (e ErrProtocol) Unwrap() error {
	return e.Cause
}

// ErrServerRefused is a node's attach the boot server refused with an NBD
// error reply. A refusal is final: the node neither retries nor asks for
// another export.
type ErrServerRefused struct {
	Option uint32
	Reply  uint32
}

func (e ErrServerRefused) Error() string {
	return fmt.Sprintf("nbd: server refused %s: %s", optionName(e.Option), replyName(e.Reply))
}
