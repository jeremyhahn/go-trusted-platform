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

package quic

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// TestDNSUpdateZone_FramesUnderTheDNSCategory proves the UpdateZone client
// call travels as OpDNSCategory (0x61) with sub-opcode 0x30 in payload[0]
// and the UpdateZoneRequest in payload[1:], and decodes the reply.
func TestDNSUpdateZone_FramesUnderTheDNSCategory(t *testing.T) {
	want := &platformv1.UpdateZoneResponse{
		Zone: &platformv1.Zone{Name: "example.com.", Ttl: 7200, Description: "updated"},
	}
	encoded, err := quicwire.EncodePayload(want)
	if err != nil {
		t.Fatalf("encode reply: %v", err)
	}
	sender := &recordingSender{respPayload: encoded}
	conn := newConnWithSender(t, sender)

	req := &platformv1.UpdateZoneRequest{Name: "example.com.", Ttl: 7200, Description: "updated"}
	got := &platformv1.UpdateZoneResponse{}
	if err := conn.Invoke(context.Background(), platformv1.DNSService_UpdateZone_FullMethodName, req, got); err != nil {
		t.Fatalf("Invoke() unexpected error: %v", err)
	}

	if sender.rawOpcode != quicwire.OpDNSCategory {
		t.Fatalf("opcode = 0x%02X, want OpDNSCategory 0x%02X", sender.rawOpcode, quicwire.OpDNSCategory)
	}
	if len(sender.rawPayload) == 0 || sender.rawPayload[0] != quicwire.OpDNSUpdateZone {
		t.Fatalf("payload[0] = %v, want sub-opcode 0x%02X", sender.rawPayload, quicwire.OpDNSUpdateZone)
	}
	var sent platformv1.UpdateZoneRequest
	if err := quicwire.DecodePayload(sender.rawPayload[1:], &sent); err != nil {
		t.Fatalf("decode sent request: %v", err)
	}
	if !proto.Equal(&sent, req) {
		t.Fatalf("sent request = %v, want %v", &sent, req)
	}
	if !proto.Equal(got.GetZone(), want.GetZone()) {
		t.Fatalf("decoded zone = %v, want %v", got.GetZone(), want.GetZone())
	}
}

// TestDNSUpdateZone_NotFoundMapsToGRPCNotFound proves a daemon NotFound
// reply (unknown zone) surfaces as codes.NotFound, as gRPC UpdateZone does.
func TestDNSUpdateZone_NotFoundMapsToGRPCNotFound(t *testing.T) {
	sender := &recordingSender{
		sendRequestErr: &quicwire.ErrProtocol{Status: quicwire.StatusNotFound, Message: "zone not found"},
	}
	conn := newConnWithSender(t, sender)

	err := conn.Invoke(context.Background(), platformv1.DNSService_UpdateZone_FullMethodName,
		&platformv1.UpdateZoneRequest{Name: "missing.com."}, &platformv1.UpdateZoneResponse{})

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T: %v", err, err)
	}
	if st.Code() != codes.NotFound {
		t.Fatalf("code = %v, want %v", st.Code(), codes.NotFound)
	}
}
