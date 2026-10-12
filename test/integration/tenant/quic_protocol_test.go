//go:build integration

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

package tenant

import (
	"context"
	"errors"
	"testing"
	"time"
)

// This adapter's request framing was already correct and had never once
// executed. It offered ALPN "tenant-quic" while the daemon advertises only
// quicwire.ALPNProtocol, so the TLS handshake failed with no_application_protocol
// BEFORE a stream was opened -- the framing code below the handshake was
// unreachable, and every call returned an error that looked like a refusal.
//
// The assertion that separates a working adapter from that one is NOT "the
// call returned an error", because a broken adapter errors too -- that is
// precisely how this hid. It is that the DAEMON ANSWERED: a response frame
// came back carrying a status byte. Only an adapter speaking the server's
// framing can produce ErrQUICStatus.

const quicNegativeTimeout = 30 * time.Second

// requireDaemonAnswered fails unless err is a status the daemon sent back.
// A transport-level failure -- no ALPN, wrong framing, no connection --
// surfaces as ErrQUICRequestFailed or QUICAdapterError, which is exactly what
// this must refuse to accept.
func requireDaemonAnswered(t *testing.T, op string, err error) ErrQUICStatus {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected the daemon to refuse, got success", op)
	}
	var status ErrQUICStatus
	if !errors.As(err, &status) {
		t.Fatalf("%s: no response frame came back, so the adapter reached no handler: %v", op, err)
	}
	return status
}

// TestQUICAdapter_DaemonAnswers proves the handshake completes and the
// server's framing is spoken, by asking for a tenant that cannot exist and
// requiring a status byte back rather than a transport failure.
func TestQUICAdapter_DaemonAnswers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), quicNegativeTimeout)
	defer cancel()

	a := NewQUICAdapter()
	if err := a.Setup(ctx); err != nil {
		t.Fatalf("QUIC setup failed; an ALPN mismatch surfaces here, before any framing: %v", err)
	}
	defer func() { _ = a.Teardown(ctx) }()

	_, err := a.GetTenant(ctx, GetTenantOptions{TenantID: "no-such-tenant-486"})
	status := requireDaemonAnswered(t, "GetTenant", err)
	t.Logf("daemon answered GetTenant with status 0x%02X: %s", status.Status, status.Message)
}
