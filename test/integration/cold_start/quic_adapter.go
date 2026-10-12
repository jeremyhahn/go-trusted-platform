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
	"crypto/tls"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	quicgo "github.com/quic-go/quic-go"
)

// QUICAdapter drives cold-start auth operations via QUIC. The auth
// sub-opcode space is being defined in #143-b/c follow-ups; this adapter
// dials the cold-start QUIC port so connectivity is validated, but
// every mutating method returns surface.ErrNoSurface.
type QUICAdapter struct {
	endpoint  string
	tlsConfig *tls.Config

	mu     sync.Mutex
	conn   *quicgo.Conn
	closed bool
}

// NewQUICAdapter returns a fresh QUIC adapter.
func NewQUICAdapter() *QUICAdapter {
	return &QUICAdapter{tlsConfig: helpers.QUICTLSConfig()}
}

// Name returns "QUIC".
func (q *QUICAdapter) Name() string { return "QUIC" }

// Setup dials the cold-start QUIC port.
func (q *QUICAdapter) Setup(ctx context.Context, h *Harness) error {
	q.endpoint = GetServiceEndpoints(h.Config()).QUIC

	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, err := quicgo.DialAddr(dialCtx, q.endpoint, q.tlsConfig, &quicgo.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 10 * time.Second,
	})
	if err != nil {
		return err
	}
	q.mu.Lock()
	q.conn = conn
	q.mu.Unlock()
	return nil
}

// Teardown closes the QUIC connection.
func (q *QUICAdapter) Teardown() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed || q.conn == nil {
		return nil
	}
	q.closed = true
	return q.conn.CloseWithError(0, "adapter teardown")
}

// Health surfaces a snapshot derived from the QUIC connection state.
func (q *QUICAdapter) Health(ctx context.Context) (*HealthSnapshot, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed || q.conn == nil {
		return nil, &ErrAdapterNotReady{Adapter: "QUIC"}
	}
	return &HealthSnapshot{State: "unsealed", Ready: true}, nil
}

// AddMTLSFactor invokes the auth sub-opcode. Stubbed.
func (q *QUICAdapter) AddMTLSFactor(ctx context.Context, username, bundlePath, label string) error {
	return notWired("QUIC", "auth factor add")
}

// ListFactors lists factors. Stubbed.
func (q *QUICAdapter) ListFactors(ctx context.Context, username string) ([]FactorRecord, error) {
	return nil, notWired("QUIC", "auth factor list")
}

// LoginMTLS performs an mTLS login. Stubbed.
func (q *QUICAdapter) LoginMTLS(ctx context.Context, username, bundlePath string) (*LoginSnapshot, error) {
	return nil, notWired("QUIC", "auth login")
}

// RotateMTLSFactor rotates a factor. Stubbed.
func (q *QUICAdapter) RotateMTLSFactor(ctx context.Context, username, factorID, newBundlePath string) (string, error) {
	return "", notWired("QUIC", "auth factor rotate")
}

// RemoveFactor removes a factor. Stubbed.
func (q *QUICAdapter) RemoveFactor(ctx context.Context, username, factorID string) error {
	return notWired("QUIC", "auth factor remove")
}

var _ ColdStartCommands = (*QUICAdapter)(nil)
