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
	"io"
	"net/http"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// manifestBuildCapture records the request the adapter sent.
type manifestBuildCapture struct {
	method string
	path   string
	body   []byte
}

// manifestBuildAdapter answers every API request with statusCode and body
// and records the request into captured.
func manifestBuildAdapter(t *testing.T, statusCode int, body string, captured *manifestBuildCapture) *Adapter {
	t.Helper()
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health/live" {
			w.WriteHeader(http.StatusOK)
			return
		}
		captured.method = r.Method
		captured.path = r.URL.Path
		captured.body, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		_, _ = w.Write([]byte(body))
	})
	return a
}

func TestAttestationManifestBuild_ResolveToTheServedRoutes(t *testing.T) {
	cases := []struct {
		name     string
		method   string
		status   int
		reply    string
		req      proto.Message
		resp     proto.Message
		wantPath string
	}{
		{
			name:     "build",
			method:   platformv1.AttestationService_BuildManifest_FullMethodName,
			status:   http.StatusCreated,
			reply:    envelope(`{"manifest":{"id":"m-built"}}`),
			req:      &platformv1.BuildManifestRequest{Nonce: []byte("n")},
			resp:     &platformv1.BuildManifestResponse{},
			wantPath: "/api/v1/attestation/manifests/build",
		},
		{
			name:     "verify",
			method:   platformv1.AttestationService_VerifyManifest_FullMethodName,
			status:   http.StatusOK,
			reply:    envelope(`{"result":{"status":"MANIFEST_VERIFICATION_STATUS_VERIFIED"}}`),
			req:      &platformv1.VerifyManifestRequest{Manifest: &platformv1.HostManifest{Id: "m-1"}},
			resp:     &platformv1.VerifyManifestResponse{},
			wantPath: "/api/v1/attestation/manifests/verify",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var captured manifestBuildCapture
			a := manifestBuildAdapter(t, tc.status, tc.reply, &captured)
			if err := a.Connection().Invoke(context.Background(), tc.method, tc.req, tc.resp); err != nil {
				t.Fatalf("Invoke: %v", err)
			}
			if captured.method != http.MethodPost || captured.path != tc.wantPath {
				t.Errorf("request = %s %s, want POST %s", captured.method, captured.path, tc.wantPath)
			}
		})
	}
}

func TestAttestationManifestBuild_VerifyBodyIsProtoJSON(t *testing.T) {
	var captured manifestBuildCapture
	a := manifestBuildAdapter(t, http.StatusOK,
		envelope(`{"result":{"status":"MANIFEST_VERIFICATION_STATUS_VERIFIED"}}`), &captured)

	sent := &platformv1.VerifyManifestRequest{
		Manifest: &platformv1.HostManifest{
			Id:        "m-1",
			Nonce:     []byte("nonce"),
			Timestamp: &timestamppb.Timestamp{Seconds: 1767225600, Nanos: 500},
		},
		ExpectedNonce: []byte("nonce"),
		PublicKeyPem:  []byte("-----BEGIN PUBLIC KEY-----"),
		ExpectedPcrs:  map[uint32][]byte{7: {0xaa}},
	}
	resp := &platformv1.VerifyManifestResponse{}
	if err := a.Connection().Invoke(context.Background(),
		platformv1.AttestationService_VerifyManifest_FullMethodName, sent, resp); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	got := &platformv1.VerifyManifestRequest{}
	if err := protojson.Unmarshal(captured.body, got); err != nil {
		t.Fatalf("body %s is not protojson: %v", captured.body, err)
	}
	if !proto.Equal(got, sent) {
		t.Errorf("decoded body = %v, want %v", got, sent)
	}
	if resp.GetResult().GetStatus() != platformv1.ManifestVerificationStatus_MANIFEST_VERIFICATION_STATUS_VERIFIED {
		t.Errorf("result = %v, want VERIFIED", resp.GetResult())
	}
}
