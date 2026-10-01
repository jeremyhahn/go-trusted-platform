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

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestNAT64Status_DecodesTheToolResult drives GetNAT64Status through the
// MCP adapter against what gateway_nat64_status returns: the bare status
// object, not the gRPC
// reply that wraps it. The generic decode dropped every field (#661
// review).
func TestNAT64Status_DecodesTheToolResult(t *testing.T) {
	// The wire is pinned to the server's type on the server side
	// (pkg/api/rest: TestNAT64StatusResponse_DecodesThroughTheSDK).
	const served = `{"active":true,"instance_present":false,"prefix":"64:ff9b::/96","instance":"tp-nat64","sessions":3,"pool4_used":2,"flow_count":5,"last_reconcile":"2026-10-01T12:00:00Z","last_error":"instance vanished"}`
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(served), &result); err != nil {
		t.Fatal(err)
	}

	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{"gateway_nat64_status": result}, &calls)
	resp := &platformv1.GetNAT64StatusResponse{}
	if err := a.Connection().Invoke(context.Background(), "/platform.v1.GatewayService/GetNAT64Status",
		&platformv1.GetNAT64StatusRequest{}, resp); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if len(calls) != 1 || calls[0].Name != "gateway_nat64_status" {
		t.Fatalf("calls = %+v, want one gateway_nat64_status", calls)
	}
	s := resp.GetStatus()
	if s == nil {
		t.Fatal("GetNAT64Status over MCP returned no status")
	}
	if !s.GetActive() || s.GetInstancePresent() || s.GetPrefix() != "64:ff9b::/96" || s.GetSessions() != 3 ||
		s.GetPool4Used() != 2 || s.GetFlowCount() != 5 || s.GetLastError() != "instance vanished" {
		t.Fatalf("status = %+v, want the tool's values", s)
	}
}

func TestNAT64Status_RefusesAToolReplyOfAnotherType(t *testing.T) {
	err := decodeGatewayNAT64StatusResult(map[string]interface{}{"active": true}, &platformv1.GetLBStatusResponse{})
	var typed ErrUnexpectedReplyType
	if !errors.As(err, &typed) {
		t.Fatalf("decode into the wrong reply = %v, want ErrUnexpectedReplyType", err)
	}
}
