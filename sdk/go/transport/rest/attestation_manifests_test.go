// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.
package rest

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// manifestCalls records each request the manifest routes receive and
// answers it with the canned body for its method.
type manifestCalls struct {
	mu    sync.Mutex
	seen  []string
	query []string
	body  string
}

func (m *manifestCalls) serve(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/health") {
		w.WriteHeader(http.StatusOK)
		return
	}
	m.mu.Lock()
	m.seen = append(m.seen, r.Method+" "+r.URL.Path)
	m.query = append(m.query, r.URL.RawQuery)
	m.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(m.body))
}

func TestAttestationManifests_List_RouteAndDecode(t *testing.T) {
	calls := &manifestCalls{body: `{"manifests":[{"id":"m-11","host_id":"h1"}],"total":30}`}
	a, _ := adapterAgainst(t, calls.serve)

	resp := &platformv1.ListManifestsResponse{}
	err := a.Connection().Invoke(context.Background(), platformv1.AttestationService_ListManifests_FullMethodName,
		&platformv1.ListManifestsRequest{HostId: "h1", Limit: 10, Offset: 10}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if len(calls.seen) != 1 || calls.seen[0] != "GET /api/v1/attestation/manifests" {
		t.Fatalf("requests = %q, want GET /api/v1/attestation/manifests", calls.seen)
	}
	if calls.query[0] != "host_id=h1&limit=10&offset=10" {
		t.Fatalf("query = %q, want host_id, limit and offset", calls.query[0])
	}
	if resp.GetTotal() != 30 || len(resp.GetManifests()) != 1 || resp.GetManifests()[0].GetId() != "m-11" {
		t.Fatalf("resp = %+v", resp)
	}
}

func TestAttestationManifests_Get_RouteAndDecode(t *testing.T) {
	calls := &manifestCalls{body: `{"manifest":{"id":"m-1","host_id":"h1","nonce":"AQI="}}`}
	a, _ := adapterAgainst(t, calls.serve)

	resp := &platformv1.GetManifestResponse{}
	err := a.Connection().Invoke(context.Background(), platformv1.AttestationService_GetManifest_FullMethodName,
		&platformv1.GetManifestRequest{Id: "m-1"}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if len(calls.seen) != 1 || calls.seen[0] != "GET /api/v1/attestation/manifests/m-1" {
		t.Fatalf("requests = %q, want GET /api/v1/attestation/manifests/m-1", calls.seen)
	}
	if resp.GetManifest().GetId() != "m-1" || string(resp.GetManifest().GetNonce()) != "\x01\x02" {
		t.Fatalf("resp = %+v", resp)
	}
}

func TestAttestationManifests_Delete_Route(t *testing.T) {
	calls := &manifestCalls{body: `{}`}
	a, _ := adapterAgainst(t, calls.serve)

	resp := &platformv1.DeleteManifestResponse{}
	err := a.Connection().Invoke(context.Background(), platformv1.AttestationService_DeleteManifest_FullMethodName,
		&platformv1.DeleteManifestRequest{Id: "m-1"}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if len(calls.seen) != 1 || calls.seen[0] != "DELETE /api/v1/attestation/manifests/m-1" {
		t.Fatalf("requests = %q, want DELETE /api/v1/attestation/manifests/m-1", calls.seen)
	}
}
