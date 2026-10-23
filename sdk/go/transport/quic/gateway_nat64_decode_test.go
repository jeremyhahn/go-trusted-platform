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

//go:build codec_msgpack

package quic

import (
	"context"
	"errors"
	"testing"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// TestInvoke_NAT64Status_DecodesAConvergedTranslator drives GetNAT64Status
// through the QUIC adapter with the server's own wire struct
// (pkg/api/quic.GatewayNAT64StatusResponse). A translator that has
// reconciled carries last_reconcile as Unix seconds, which the default
// decode could not put into the reply's Timestamp: every status read after
// the first reconcile failed with an Internal error (#661 review).
func TestInvoke_NAT64Status_DecodesAConvergedTranslator(t *testing.T) {
	reconciled := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	encoded, err := quicwire.EncodePayload(&quicwire.GatewayNAT64StatusResponse{
		Status: &quicwire.NAT64StatusInfo{
			Active:          true,
			InstancePresent: true,
			Prefix:          "64:ff9b::/96",
			Instance:        "tp-nat64",
			Sessions:        12,
			Pool4Used:       7,
			ModuleVersion:   "4.1.14",
			FlowCount:       5,
			LastReconcile:   reconciled.Unix(),
			LastError:       "pool4 display: busy",
		},
		Timestamp: reconciled.Unix() + 5,
	})
	if err != nil {
		t.Fatalf("EncodePayload setup failed: %v", err)
	}
	conn := newConnWithSender(t, &recordingSender{respPayload: encoded})

	reply := &platformv1.GetNAT64StatusResponse{}
	if err := conn.Invoke(context.Background(), platformv1.GatewayService_GetNAT64Status_FullMethodName,
		&platformv1.GetNAT64StatusRequest{}, reply); err != nil {
		t.Fatalf("Invoke() = %v", err)
	}
	s := reply.GetStatus()
	if s == nil {
		t.Fatal("GetNAT64Status over QUIC returned no status")
	}
	if !s.GetActive() || !s.GetInstancePresent() || s.GetPrefix() != "64:ff9b::/96" || s.GetInstance() != "tp-nat64" ||
		s.GetSessions() != 12 || s.GetPool4Used() != 7 || s.GetModuleVersion() != "4.1.14" || s.GetFlowCount() != 5 {
		t.Fatalf("status = %+v, want the served values", s)
	}
	if s.GetLastError() != "pool4 display: busy" {
		t.Fatalf("last_error = %q, want the served failure", s.GetLastError())
	}
	if !s.GetLastReconcile().AsTime().Equal(reconciled) {
		t.Fatalf("last_reconcile = %v, want %v", s.GetLastReconcile().AsTime(), reconciled)
	}
}

func TestInvoke_NAT64Status_LeavesANeverConvergedServiceUnset(t *testing.T) {
	encoded, err := quicwire.EncodePayload(&quicwire.GatewayNAT64StatusResponse{
		Status: &quicwire.NAT64StatusInfo{Active: false, Prefix: "64:ff9b::/96"},
	})
	if err != nil {
		t.Fatalf("EncodePayload setup failed: %v", err)
	}
	reply := &platformv1.GetNAT64StatusResponse{}
	if err := newConnWithSender(t, &recordingSender{respPayload: encoded}).Invoke(context.Background(),
		platformv1.GatewayService_GetNAT64Status_FullMethodName, &platformv1.GetNAT64StatusRequest{}, reply); err != nil {
		t.Fatalf("Invoke() = %v", err)
	}
	if reply.GetStatus().GetLastReconcile() != nil {
		t.Fatalf("last_reconcile = %v, want unset", reply.GetStatus().GetLastReconcile())
	}
}

func TestDecodeGatewayNAT64StatusReply_Refusals(t *testing.T) {
	var wrongType ErrInvalidReplyType
	if err := decodeGatewayNAT64StatusReply(nil, &platformv1.GetLBStatusResponse{}); !errors.As(err, &wrongType) {
		t.Fatalf("decode into the wrong reply = %v, want ErrInvalidReplyType", err)
	}
	var undecodable ErrDecodingFailed
	if err := decodeGatewayNAT64StatusReply([]byte{0xc1}, &platformv1.GetNAT64StatusResponse{}); !errors.As(err, &undecodable) {
		t.Fatalf("decode of garbage = %v, want ErrDecodingFailed", err)
	}
}
