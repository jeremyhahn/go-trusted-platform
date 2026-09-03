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

package admin

import "fmt"

// ErrBundleUnreadable is returned when a file the ceremony needs — the
// admin certificate, its key, or a CA bundle — cannot be read or parsed.
type ErrBundleUnreadable struct {
	Path  string
	Cause error
}

func (e ErrBundleUnreadable) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("admin: cannot read %q: %v", e.Path, e.Cause)
	}
	return fmt.Sprintf("admin: %q is not usable credential material", e.Path)
}

func (e ErrBundleUnreadable) Unwrap() error { return e.Cause }

// ErrProtectedMemoryUnavailable is returned when the encoded private key
// cannot be held in protected memory — typically a host whose
// RLIMIT_MEMLOCK is too low to mlock the region, or a key file above
// memguard.MaxFileSize. It is reported distinctly from a read failure
// because the fix is a host limit or a wrong file, not a path or a
// permission.
type ErrProtectedMemoryUnavailable struct {
	Cause error
}

func (e ErrProtectedMemoryUnavailable) Error() string {
	return fmt.Sprintf(
		"admin: cannot hold the admin key in protected memory (check RLIMIT_MEMLOCK): %v",
		e.Cause)
}

func (e ErrProtectedMemoryUnavailable) Unwrap() error { return e.Cause }

// ErrDaemonUnreachable is returned when the claim endpoints cannot be
// reached.
type ErrDaemonUnreachable struct {
	Endpoint string
	Cause    error
}

func (e ErrDaemonUnreachable) Error() string {
	return fmt.Sprintf("admin: cannot reach the platform API at %s: %v", e.Endpoint, e.Cause)
}

func (e ErrDaemonUnreachable) Unwrap() error { return e.Cause }

// ErrClaimRefused is returned when the daemon rejects a step of the
// ceremony.
type ErrClaimRefused struct {
	Status int
	Reason string
}

func (e ErrClaimRefused) Error() string {
	return fmt.Sprintf("admin: the platform refused the claim (HTTP %d): %s", e.Status, e.Reason)
}

// ErrAlreadyClaimed is returned when the node's admin identity already
// carries an operator-enrolled authenticator.
type ErrAlreadyClaimed struct {
	Username string
}

func (e ErrAlreadyClaimed) Error() string {
	return fmt.Sprintf(
		"admin: %q has already been claimed; to re-run the ceremony (for example after losing the enrolled authenticator) remove its remaining auth factor through an authenticated admin session first",
		e.Username)
}

// ErrContextNotREST is returned when the active platformctl context names a
// server the claim ceremony cannot dial. The ceremony is REST-only — its
// routes run before any session exists — and remote contexts default to
// gRPC, so a context's server is frequently a transport-specific address.
//
// It is an error rather than a guess deliberately. Bolting a scheme and an
// assumed port onto such an address could reach a different service on that
// host, and the ceremony hands a claim token to whatever answers; the same
// reasoning is why this command has no --insecure option.
type ErrContextNotREST struct {
	Server string
}

func (e ErrContextNotREST) Error() string {
	return fmt.Sprintf(
		"admin: the active context's server %q is not an http:// or https:// endpoint, "+
			"and the claim ceremony is REST-only; pass --api with the node's REST endpoint",
		e.Server)
}
