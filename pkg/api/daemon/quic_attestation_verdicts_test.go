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

package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict/feed"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// pollVerdictsOverQUIC sends one OpAttestPollVerdicts request through the
// daemon's attestation router, as the SDK QUIC adapter does.
func pollVerdictsOverQUIC(t *testing.T, h *QUICServiceHandler, ctx context.Context, req *platformv1.PollDeviceVerdictsRequest) (*platformv1.PollDeviceVerdictsResponse, byte) {
	t.Helper()
	payload, err := quicwire.EncodePayload(req)
	if err != nil {
		t.Fatalf("EncodePayload: %v", err)
	}
	resp := h.handleAttestationOperation(ctx, &quicwire.Request{Opcode: quicwire.OpAttestPollVerdicts, Payload: payload})
	if resp.Status != quicwire.StatusOK {
		return nil, resp.Status
	}
	var out platformv1.PollDeviceVerdictsResponse
	if err := quicwire.DecodePayload(resp.Payload, &out); err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	return &out, resp.Status
}

func quicTokenCtx(tenantID string, scopes ...string) context.Context {
	return quic.ContextWithAuthorizedContext(context.Background(),
		&platformtoken.AuthorizedContext{Subject: "s", TenantID: tenantID, Scopes: scopes})
}

// TestQUICPollDeviceVerdicts follows verdicts over QUIC: the token's tenant
// filters what it sees, and the verdict crosses the msgpack wire intact.
func TestQUICPollDeviceVerdicts(t *testing.T) {
	server, attestation, _, _ := verdictFeedServer(t)
	h := newTestQUICServiceHandler(logging.DefaultLogger())
	h.SetAttestationGRPCService(server)
	ctx := quicTokenCtx("tenant-a", "attestation:read")

	head, st := pollVerdictsOverQUIC(t, h, ctx, &platformv1.PollDeviceVerdictsRequest{})
	if st != quicwire.StatusOK || head.GetCursor() == "" {
		t.Fatalf("the first poll returns the head cursor: status %#x, %+v", st, head)
	}
	attestation.record(verdict.DeviceVerdict{DeviceID: 1, TenantID: "tenant-b", Reason: "pcr mismatch"}, "ev-b")
	attestation.record(verdict.DeviceVerdict{DeviceID: 2, TenantID: "tenant-a", HostID: "node-2", Serial: "SN2",
		Cryptographic: true, Reason: "signature invalid"}, "ev-a")

	page, st := pollVerdictsOverQUIC(t, h, ctx, &platformv1.PollDeviceVerdictsRequest{Cursor: head.GetCursor(), WaitMs: 1000})
	if st != quicwire.StatusOK {
		t.Fatalf("status %#x", st)
	}
	if len(page.GetVerdicts()) != 1 {
		t.Fatalf("tenant-a must see only its own device's verdict: %+v", page.GetVerdicts())
	}
	got := page.GetVerdicts()[0]
	if got.GetEventId() != "ev-a" || got.GetDeviceId() != 2 || got.GetHostId() != "node-2" || got.GetSerial() != "SN2" ||
		!got.GetCryptographic() || got.GetReason() != "signature invalid" ||
		!got.GetRecordedAt().AsTime().Equal(time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("the verdict must cross the wire intact: %+v", got)
	}
}

func TestQUICPollDeviceVerdictsRefusals(t *testing.T) {
	server, attestation, _, _ := verdictFeedServer(t, feed.WithCapacity(1))
	h := newTestQUICServiceHandler(logging.DefaultLogger())
	h.SetAttestationGRPCService(server)
	reader := quicTokenCtx("tenant-a", "attestation:read")

	head, st := pollVerdictsOverQUIC(t, h, reader, &platformv1.PollDeviceVerdictsRequest{})
	if st != quicwire.StatusOK {
		t.Fatalf("status %#x", st)
	}
	attestation.record(verdict.DeviceVerdict{DeviceID: 1, TenantID: "tenant-a"}, "ev-1")
	attestation.record(verdict.DeviceVerdict{DeviceID: 2, TenantID: "tenant-a"}, "ev-2")

	tests := []struct {
		name string
		ctx  context.Context
		req  *platformv1.PollDeviceVerdictsRequest
		want byte
	}{
		{name: "no token", ctx: context.Background(), req: &platformv1.PollDeviceVerdictsRequest{}, want: quicwire.StatusPermissionDenied},
		{name: "token without the scope", ctx: quicTokenCtx("tenant-a", "device:read"), req: &platformv1.PollDeviceVerdictsRequest{}, want: quicwire.StatusPermissionDenied},
		{name: "token without a tenant", ctx: quicTokenCtx("", "attestation:read"), req: &platformv1.PollDeviceVerdictsRequest{}, want: quicwire.StatusPermissionDenied},
		{name: "missed verdicts", ctx: reader, req: &platformv1.PollDeviceVerdictsRequest{Cursor: head.GetCursor()}, want: quicwire.StatusResourceExhausted},
		{name: "malformed cursor", ctx: reader, req: &platformv1.PollDeviceVerdictsRequest{Cursor: "garbage"}, want: quicwire.StatusInvalidArgument},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, st := pollVerdictsOverQUIC(t, h, tt.ctx, tt.req); st != tt.want {
				t.Fatalf("status %#x, want %#x", st, tt.want)
			}
		})
	}

	t.Run("undecodable payload", func(t *testing.T) {
		resp := h.handleAttestationOperation(reader, &quicwire.Request{Opcode: quicwire.OpAttestPollVerdicts, Payload: []byte{0xc1}})
		if resp.Status != quicwire.StatusInvalidRequest {
			t.Fatalf("status %#x, want %#x", resp.Status, quicwire.StatusInvalidRequest)
		}
	})
	t.Run("no attestation service", func(t *testing.T) {
		bare := newTestQUICServiceHandler(logging.DefaultLogger())
		if _, st := pollVerdictsOverQUIC(t, bare, reader, &platformv1.PollDeviceVerdictsRequest{}); st != quicwire.StatusUnavailable {
			t.Fatalf("status %#x, want %#x", st, quicwire.StatusUnavailable)
		}
	})
}

// TestQUICAttestWireCompatPollVerdicts round-trips the poll messages, whose
// verdicts carry a Timestamp, through the msgpack payload codec.
func TestQUICAttestWireCompatPollVerdicts(t *testing.T) {
	roundTripPBWire(t,
		&platformv1.PollDeviceVerdictsRequest{Cursor: "18f.3", WaitMs: 20000},
		&platformv1.PollDeviceVerdictsRequest{})
	roundTripPBWire(t,
		&platformv1.PollDeviceVerdictsResponse{
			Cursor:   "18f.4",
			Verdicts: []*platformv1.DeviceVerdictEvent{{EventId: "ev-1", DeviceId: 7, TenantId: "t1", Passed: true}},
		},
		&platformv1.PollDeviceVerdictsResponse{})
}
