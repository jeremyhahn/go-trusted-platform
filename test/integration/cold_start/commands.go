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

//go:build integration

package cold_start

import (
	"context"
	"fmt"
)

// HealthSnapshot captures the /healthz response shape used by every
// adapter to confirm the daemon's view of the world.
type HealthSnapshot struct {
	State string
	Ready bool
}

// FactorRecord captures the canonical "auth factor list" entry shape
// shared by all adapters. Detailed metadata is intentionally omitted —
// the cold-start suite only needs to count the factors after add/remove.
type FactorRecord struct {
	ID     string
	Method string
	Label  string
}

// LoginSnapshot captures the result of an "auth login" call. The token
// field is intentionally a string because each adapter strips its
// transport-specific envelope before returning.
type LoginSnapshot struct {
	Token   string
	Subject string
}

// ColdStartCommands is the transport-agnostic surface every adapter
// implements. The 11-step lifecycle scenario consumes this interface so
// the same body runs against CLI, REST, gRPC, QUIC, MCP and Unix.
//
// All adapters share the same harness; Setup is responsible for
// connection bring-up and Teardown for clean shutdown. Implementations
// MUST be safe to call after Teardown — they must surface a clear error
// rather than panic.
type ColdStartCommands interface {
	Name() string
	Setup(ctx context.Context, h *Harness) error
	Teardown() error

	// Health returns the daemon's current state via the protocol's own
	// "health" surface. CLI uses platformctl; transports use their
	// canonical health endpoint.
	Health(ctx context.Context) (*HealthSnapshot, error)

	// AddMTLSFactor enrolls an mTLS client cert as a factor against the
	// configured user. bundlePath is the path to the cert+key PEM.
	AddMTLSFactor(ctx context.Context, username, bundlePath, label string) error

	// ListFactors returns the factors currently enrolled for the user.
	ListFactors(ctx context.Context, username string) ([]FactorRecord, error)

	// LoginMTLS exchanges the enrolled mTLS cert for an auth token.
	LoginMTLS(ctx context.Context, username, bundlePath string) (*LoginSnapshot, error)

	// RotateMTLSFactor swaps the existing mTLS cert for a new bundle.
	// Returns the new factor ID.
	RotateMTLSFactor(ctx context.Context, username, factorID, newBundlePath string) (string, error)

	// RemoveFactor removes the factor identified by factorID. Returns a
	// non-nil error matching ErrLastFactor if the daemon refuses the
	// removal because it would leave the user without authentication.
	RemoveFactor(ctx context.Context, username, factorID string) error
}

// ErrLastFactor is the canonical sentinel surfaced by every adapter when
// the daemon refuses to remove the last remaining factor. Each protocol
// returns a slightly different transport-level error which the adapters
// normalize into ErrLastFactor before returning to the test body.
type ErrLastFactor struct {
	Username string
	Reason   string
}

// Error returns a human-readable description.
func (e *ErrLastFactor) Error() string {
	return fmt.Sprintf("cold_start: cannot remove last factor for %q: %s", e.Username, e.Reason)
}

// ErrAdapterNotReady indicates the adapter's Setup was not called, or
// the underlying connection was already closed.
type ErrAdapterNotReady struct {
	Adapter string
}

// Error returns a human-readable description.
func (e *ErrAdapterNotReady) Error() string {
	return "cold_start: adapter not ready: " + e.Adapter
}
