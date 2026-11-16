// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// manifestReadsAdapter connects an Adapter to a server that records every
// API request it receives and answers each with body inside the envelope.
func manifestReadsAdapter(t *testing.T, body string, seen *[]capturedRequest) *Adapter {
	t.Helper()
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health/live" {
			w.WriteHeader(http.StatusOK)
			return
		}
		*seen = append(*seen, capturedRequest{method: r.Method, path: r.URL.Path})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(envelope(body)))
	})
	return a
}

func TestAttestationManifestReads_ResolveToTheServedRoutes(t *testing.T) {
	ctx := context.Background()

	t.Run("GetManifest", func(t *testing.T) {
		var seen []capturedRequest
		a := manifestReadsAdapter(t, `{"manifest":{"id":"m1"}}`, &seen)
		resp := &platformv1.GetManifestResponse{}
		if err := a.Connection().Invoke(ctx, platformv1.AttestationService_GetManifest_FullMethodName,
			&platformv1.GetManifestRequest{Id: "m1"}, resp); err != nil {
			t.Fatalf("Invoke: %v", err)
		}
		if len(seen) != 1 || seen[0].method != http.MethodGet || seen[0].path != "/api/v1/attestation/manifests/m1" {
			t.Errorf("requests = %+v, want GET /api/v1/attestation/manifests/m1", seen)
		}
		if resp.GetManifest().GetId() != "m1" {
			t.Errorf("manifest id = %q, want m1", resp.GetManifest().GetId())
		}
	})

	t.Run("ListManifests", func(t *testing.T) {
		var seen []capturedRequest
		a := manifestReadsAdapter(t, `{"manifests":[{"id":"m-a"},{"id":"m-b"}],"total":2}`, &seen)
		resp := &platformv1.ListManifestsResponse{}
		if err := a.Connection().Invoke(ctx, platformv1.AttestationService_ListManifests_FullMethodName,
			&platformv1.ListManifestsRequest{}, resp); err != nil {
			t.Fatalf("Invoke: %v", err)
		}
		if len(seen) != 1 || seen[0].method != http.MethodGet || seen[0].path != "/api/v1/attestation/manifests" {
			t.Errorf("requests = %+v, want GET /api/v1/attestation/manifests", seen)
		}
		if len(resp.GetManifests()) != 2 || resp.GetManifests()[1].GetId() != "m-b" || resp.GetTotal() != 2 {
			t.Errorf("reply = %+v, want manifests m-a, m-b and total 2", resp)
		}
	})

	t.Run("DeleteManifest", func(t *testing.T) {
		var seen []capturedRequest
		a := manifestReadsAdapter(t, `{"status":{"success":true}}`, &seen)
		resp := &platformv1.DeleteManifestResponse{}
		if err := a.Connection().Invoke(ctx, platformv1.AttestationService_DeleteManifest_FullMethodName,
			&platformv1.DeleteManifestRequest{Id: "m1"}, resp); err != nil {
			t.Fatalf("Invoke: %v", err)
		}
		if len(seen) != 1 || seen[0].method != http.MethodDelete || seen[0].path != "/api/v1/attestation/manifests/m1" {
			t.Errorf("requests = %+v, want DELETE /api/v1/attestation/manifests/m1", seen)
		}
	})
}

func TestAttestationManifestReads_EmptyIDNeverReachesTheWire(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name   string
		method string
		req    any
		resp   any
	}{
		{"GetManifest", platformv1.AttestationService_GetManifest_FullMethodName,
			&platformv1.GetManifestRequest{}, &platformv1.GetManifestResponse{}},
		{"DeleteManifest", platformv1.AttestationService_DeleteManifest_FullMethodName,
			&platformv1.DeleteManifestRequest{}, &platformv1.DeleteManifestResponse{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var seen []capturedRequest
			a := manifestReadsAdapter(t, `{}`, &seen)
			err := a.Connection().Invoke(ctx, tc.method, tc.req, tc.resp)
			if status.Code(err) != codes.InvalidArgument {
				t.Errorf("code = %v (%v), want InvalidArgument", status.Code(err), err)
			}
			if len(seen) != 0 {
				t.Errorf("requests = %+v, want none", seen)
			}
		})
	}
}
