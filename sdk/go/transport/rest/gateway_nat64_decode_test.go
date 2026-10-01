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

package rest

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestNAT64Status_DecodesTheServedPayload drives GetNAT64Status through the
// REST adapter against the payload the platformd handler writes: the bare
// status object, not the gRPC reply that wraps it. Before the
// decoder the generic decode matched no field of the reply and every value
// was dropped, so the CLI over REST printed an empty status (#661 review).
func TestNAT64Status_DecodesTheServedPayload(t *testing.T) {
	// The wire is pinned to the server's type on the server side
	// (pkg/api/rest: TestNAT64StatusResponse_DecodesThroughTheSDK).
	const served = `{"active":true,"instance_present":true,"prefix":"64:ff9b::/96","instance":"tp-nat64","sessions":12,"pool4_used":7,"module_version":"4.1.14","flow_count":5,"last_reconcile":"2026-10-01T12:00:00Z","timestamp":"2026-10-01T12:00:05Z"}`
	wantReconcile := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(served))
	})

	resp := &platformv1.GetNAT64StatusResponse{}
	if err := a.Connection().Invoke(context.Background(), "/platform.v1.GatewayService/GetNAT64Status",
		&platformv1.GetNAT64StatusRequest{}, resp); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	s := resp.GetStatus()
	if s == nil {
		t.Fatal("GetNAT64Status over REST returned no status")
	}
	if !s.GetActive() || !s.GetInstancePresent() || s.GetPrefix() != "64:ff9b::/96" || s.GetSessions() != 12 ||
		s.GetPool4Used() != 7 || s.GetFlowCount() != 5 || s.GetModuleVersion() != "4.1.14" {
		t.Fatalf("status = %+v, want the served values", s)
	}
	if !s.GetLastReconcile().AsTime().Equal(wantReconcile) {
		t.Fatalf("last_reconcile = %v, want %v", s.GetLastReconcile().AsTime(), wantReconcile)
	}
}

func TestNAT64Status_RefusesAReplyOfAnotherType(t *testing.T) {
	err := decodeGatewayNAT64Status([]byte(`{"active":true}`), &platformv1.GetLBStatusResponse{})
	var typed ErrUnexpectedReplyType
	if !errors.As(err, &typed) {
		t.Fatalf("decode into the wrong reply = %v, want ErrUnexpectedReplyType", err)
	}
}
