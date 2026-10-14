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
	"encoding/json"
	"net/http"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// caItemOperations are the CAService rows #452 repairs. Revoke and renew used
// to send a collection path (POST /api/v1/ca/certificates/revoke, .../renew)
// with the serial in the body; the web service serves them as item operations
// on /api/v1/ca/certificates/{serial} (pkg/webservice/v1/rest/ca/router.go).
var caItemOperations = []struct {
	name       string
	grpcMethod string
	req        proto.Message
	resp       proto.Message
	wantMethod string
	wantPath   string
	kept       string // a non-identifier proto JSON field that must stay in the body
	zero       proto.Message
}{
	{
		name:       "RevokeCertificate",
		grpcMethod: "/platform.v1.CAService/RevokeCertificate",
		req:        &platformv1.RevokeCertificateRequest{Serial: "5a17e5", DeleteKeys: true},
		resp:       &platformv1.RevokeCertificateResponse{},
		wantMethod: http.MethodDelete,
		wantPath:   "/api/v1/ca/certificates/5a17e5",
		kept:       "delete_keys",
		zero:       &platformv1.RevokeCertificateRequest{DeleteKeys: true},
	},
	{
		name:       "RenewCertificate",
		grpcMethod: "/platform.v1.CAService/RenewCertificate",
		req:        &platformv1.RenewCertificateRequest{Serial: "5a17e5", ValidDays: 30},
		resp:       &platformv1.RenewCertificateResponse{},
		wantMethod: http.MethodPost,
		wantPath:   "/api/v1/ca/certificates/5a17e5/renew",
		kept:       "valid_days",
		zero:       &platformv1.RenewCertificateRequest{ValidDays: 30},
	},
}

// TestCAItemOperations_SerialTravelsInThePath asserts, per row, the method and
// item path the server registers, that the serial left the body for the path,
// and that the remaining fields still travel in the body.
func TestCAItemOperations_SerialTravelsInThePath(t *testing.T) {
	for _, tc := range caItemOperations {
		t.Run(tc.name, func(t *testing.T) {
			var captured struct {
				method string
				path   string
				body   map[string]interface{}
			}
			a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
				captured.method = r.Method
				captured.path = r.URL.Path
				_ = json.NewDecoder(r.Body).Decode(&captured.body)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"success":true,"payload":{}}`))
			})

			if err := a.Connection().Invoke(context.Background(), tc.grpcMethod, tc.req, tc.resp); err != nil {
				t.Fatalf("Invoke: %v", err)
			}
			if captured.method != tc.wantMethod {
				t.Errorf("method = %q, want %q", captured.method, tc.wantMethod)
			}
			if captured.path != tc.wantPath {
				t.Errorf("path = %q, want %q", captured.path, tc.wantPath)
			}
			if _, has := captured.body["serial"]; has {
				t.Errorf("serial travels in the body as well as the path: %v", captured.body)
			}
			if _, has := captured.body[tc.kept]; !has {
				t.Errorf("%q was dropped from the body: %v", tc.kept, captured.body)
			}
		})
	}
}

// TestCAItemOperations_MissingSerialRejectedBeforeTheWire: with the serial
// empty the request must not leave the client. An unfilled placeholder would
// otherwise produce DELETE /api/v1/ca/certificates/ — a different route.
func TestCAItemOperations_MissingSerialRejectedBeforeTheWire(t *testing.T) {
	for _, tc := range caItemOperations {
		t.Run(tc.name, func(t *testing.T) {
			var apiHits int
			a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/health" {
					apiHits++
				}
				w.WriteHeader(http.StatusOK)
			})

			err := a.Connection().Invoke(context.Background(), tc.grpcMethod, tc.zero, tc.resp)
			if err == nil {
				t.Fatal("expected an error for the missing serial, got nil")
			}
			if st, _ := status.FromError(err); st == nil || st.Code() != codes.InvalidArgument {
				t.Errorf("status = %v, want InvalidArgument", st)
			}
			if apiHits != 0 {
				t.Errorf("server saw %d API hits; want 0 -- the request must not leave the client", apiHits)
			}
		})
	}
}
