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

package attestation

import (
	"context"
	"errors"
	"testing"
	"time"
)

// This adapter had both defects: it offered ALPN "attestation-quic" while the
// daemon advertises only quicwire.ALPNProtocol, and it wrote a JSON
// {method, path, body} envelope past a server that reads opcode framing. The
// handshake failed before a stream was opened, so the framing never ran, and
// every call failed in a way that looked exactly like a refusal.
//
// The assertion that separates a working adapter from that one is NOT "the
// call returned an error" -- a broken adapter errors too, which is how this
// hid. It is that the DAEMON ANSWERED: a response frame came back carrying a
// status byte. Only an adapter speaking the server's framing produces
// ErrQUICStatus.
//
// Note what a PASS here means today. The four operations that name an opcode
// all reach handleAttestationOperation's default branch, which delegates to an
// AttestationHandler that no production code constructs, so the daemon answers
// StatusUnavailable. The other eleven have no opcode at all. That is a served-but-unwired surface,
// and this test proves the adapter now reaches it -- turning a failure that
// the suite laundered into an accepted gap into a true one.

const quicNegativeTimeout = 30 * time.Second

// requireDaemonAnswered fails unless err is a status the daemon sent back.
// A transport-level failure -- no ALPN, wrong framing, no connection --
// surfaces as *QUICAdapterError, which is exactly what this must not accept.
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
// server's framing is spoken. BuildManifest carries a real opcode
// (OpAttestBuildManifest, 0x7C) in a dispatched range, so whatever the daemon
// decides about it comes back as a status byte rather than a transport error.
func TestQUICAdapter_DaemonAnswers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), quicNegativeTimeout)
	defer cancel()

	a := NewQUICAdapter()
	if err := a.Setup(ctx); err != nil {
		t.Fatalf("QUIC setup failed; an ALPN mismatch surfaces here, before any framing: %v", err)
	}
	defer func() { _ = a.Teardown(ctx) }()

	_, err := a.BuildManifest(ctx, BuildManifestOptions{HostID: "no-such-host-486"})
	status := requireDaemonAnswered(t, "BuildManifest", err)
	t.Logf("daemon answered BuildManifest with status 0x%02X: %s", status.Status, status.Message)
}

// TestQUICAdapter_OperationsWithoutAnOpcodeSaySo asserts the gap is reported
// rather than skipped. PushAttestation has no opcode in any dispatched range,
// so it must surface ErrQUICNoSurface -- a named absence, not a timeout and
// not a phrase a skip guard would swallow.
func TestQUICAdapter_OperationsWithoutAnOpcodeSaySo(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), quicNegativeTimeout)
	defer cancel()

	a := NewQUICAdapter()
	if err := a.Setup(ctx); err != nil {
		t.Fatalf("QUIC setup failed: %v", err)
	}
	defer func() { _ = a.Teardown(ctx) }()

	_, err := a.PushAttestation(ctx, PushAttestationOptions{})
	var noSurface ErrQUICNoSurface
	if !errors.As(err, &noSurface) {
		t.Fatalf("PushAttestation: expected a named absent surface, got %v", err)
	}
}

// TestQUICAdapter_EveryOperationIsClassified walks every operation and
// requires each to be in exactly one of two states: it names a dispatched
// opcode, or it declares it has no wire surface. A third state -- silently
// resolving to nothing -- is what this PR's first attempt shipped.
//
// That attempt derived the opcode from the caller's path string through a
// static map. A key that matched nothing looked identical to a key that
// matched something, and a caller building its path with a format verb could
// never match any literal key, so eleven of fifteen operations returned a
// no-surface error for capabilities that are dispatched. Neither failure was
// visible at a call site, and no per-operation test revealed anything about
// the other fifteen. Hence a check over the whole set.
//
// The discriminator needs no daemon: a no-surface operation returns before it
// touches the connection, while one that names an opcode gets as far as the
// nil connection and reports that instead.
func TestQUICAdapter_EveryOperationIsClassified(t *testing.T) {
	ctx := context.Background()
	// Constructed directly rather than via NewQUICAdapter: that constructor
	// builds a TLS config and panics without the mTLS environment, which this
	// classification does not need. A zero-value adapter has no connection, so
	// an operation naming an opcode reports exactly that.
	a := &QUICAdapter{}

	type probe struct {
		name string
		call func() error
	}
	probes := []probe{
		{"GenerateVMQuote", func() error { _, e := a.GenerateVMQuote(ctx, GenerateVMQuoteOptions{}); return e }},
		{"GetVMIdentity", func() error { _, e := a.GetVMIdentity(ctx, GetVMIdentityOptions{}); return e }},
		{"GetVMAttestation", func() error { _, e := a.GetVMAttestation(ctx, GetVMAttestationOptions{}); return e }},
		{"VerifyVMAttestation", func() error { _, e := a.VerifyVMAttestation(ctx, VerifyVMAttestationOptions{}); return e }},
		{"BuildManifest", func() error { _, e := a.BuildManifest(ctx, BuildManifestOptions{}); return e }},
		{"SignManifest", func() error { _, e := a.SignManifest(ctx, SignManifestOptions{}); return e }},
		{"VerifyManifest", func() error { _, e := a.VerifyManifest(ctx, VerifyManifestOptions{}); return e }},
		{"GetManifest", func() error { _, e := a.GetManifest(ctx, GetManifestOptions{}); return e }},
		{"PushAttestation", func() error { _, e := a.PushAttestation(ctx, PushAttestationOptions{}); return e }},
		{"PushAttestationBatch", func() error { _, e := a.PushAttestationBatch(ctx, PushAttestationBatchOptions{}); return e }},
		{"GetPushStatus", func() error { _, e := a.GetPushStatus(ctx, GetPushStatusOptions{}); return e }},
		{"ExtendWorkloadChain", func() error { _, e := a.ExtendWorkloadChain(ctx, ExtendWorkloadChainOptions{}); return e }},
		{"GetWorkloadChainHistory", func() error { _, e := a.GetWorkloadChainHistory(ctx, GetWorkloadChainHistoryOptions{}); return e }},
		{"VerifyWorkloadChain", func() error { _, e := a.VerifyWorkloadChain(ctx, VerifyWorkloadChainOptions{}); return e }},
		{"GetWorkloadChainStats", func() error { _, e := a.GetWorkloadChainStats(ctx, GetWorkloadChainStatsOptions{}); return e }},
	}

	var withOpcode, withoutSurface []string
	for _, p := range probes {
		err := p.call()
		if err == nil {
			t.Errorf("%s: returned success with no connection; it reached neither an opcode nor a declaration", p.name)
			continue
		}
		var noSurface ErrQUICNoSurface
		if errors.As(err, &noSurface) {
			withoutSurface = append(withoutSurface, p.name)
			continue
		}
		withOpcode = append(withOpcode, p.name)
	}

	t.Logf("operations naming a dispatched opcode: %d %v", len(withOpcode), withOpcode)
	t.Logf("operations declaring no wire surface : %d %v", len(withoutSurface), withoutSurface)

	if len(withOpcode)+len(withoutSurface) != len(probes) {
		t.Fatalf("%d operations classified, %d exist -- something is still being derived rather than named",
			len(withOpcode)+len(withoutSurface), len(probes))
	}
	if len(withOpcode) == 0 {
		t.Fatal("no operation names an opcode; the adapter reaches the daemon for nothing")
	}
}
