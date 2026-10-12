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

// Package surface is the one place an integration suite decides that an
// operation is "not implemented" on a transport and may be skipped.
//
// A skip needs a typed declaration: an adapter returns ErrNoSurface for an
// operation its transport has no endpoint for, or the server answers a gRPC
// call with codes.Unimplemented. Error text is never matched, so a 404, an
// unknown CLI flag, a timeout or a failed handshake fails the subtest
// instead of reading as "not built yet" (#487).
//
// A deployment gap the server declares with a sentinel (for example
// "fido2: backend not configured") is recognised by IsDeclaredRefusal from
// the sentinel value itself, never from a hand-written phrase list.
//
// The package carries no build tag so its unit tests run in `make test`.
package surface

import (
	"errors"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrNoSurface declares that a transport has no endpoint for an operation.
//
// Its text deliberately avoids the phrase "not implemented": the
// declaration is matched by type, and a reader of a skip message should
// see which surface is missing and where that gap is recorded.
type ErrNoSurface struct {
	// Transport names the transport, e.g. "QUIC" or "MCP".
	Transport string
	// Operation names the adapter operation that has no endpoint.
	Operation string
	// Reason optionally says where the gap is recorded, e.g. a doc section.
	Reason string
}

// Error implements error.
func (e ErrNoSurface) Error() string {
	msg := e.Transport + " has no surface for " + e.Operation
	if e.Reason != "" {
		msg += ": " + e.Reason
	}
	return msg
}

// IsNotImplemented reports whether err declares a missing surface: an
// ErrNoSurface anywhere in its chain, or a gRPC status (possibly wrapped)
// with code Unimplemented. Every other error, whatever its text, is not a
// declaration.
func IsNotImplemented(err error) bool {
	if err == nil {
		return false
	}
	var noSurface ErrNoSurface
	if errors.As(err, &noSurface) {
		return true
	}
	return status.Code(err) == codes.Unimplemented
}

// IsDeclaredRefusal reports whether err is one of the given server
// sentinels: in its chain (embedded transport), or carried across the wire
// as the sentinel's exact text (REST body, gRPC status message, QUIC or MCP
// error payload). The match is derived from the sentinel values themselves,
// so a renamed or retired sentinel breaks the build instead of silently
// widening the skip. A nil sentinel is ignored.
func IsDeclaredRefusal(err error, refusals ...error) bool {
	if err == nil {
		return false
	}
	text := err.Error()
	for _, refusal := range refusals {
		if refusal == nil {
			continue
		}
		if errors.Is(err, refusal) || strings.Contains(text, refusal.Error()) {
			return true
		}
	}
	return false
}

// Skipper is the part of testing.TB that SkipIfNotImplemented needs.
type Skipper interface {
	Helper()
	Skipf(format string, args ...any)
}

// SkipIfNotImplemented skips the test when err declares a missing surface
// (see IsNotImplemented). Any other error is left to the caller, which
// fails the test with its text or asserts it as an expected refusal.
func SkipIfNotImplemented(t Skipper, err error) {
	t.Helper()
	if IsNotImplemented(err) {
		t.Skipf("Declared gap: %v", err)
	}
}
