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
	"net/http"
	"testing"

	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// The CA lifecycle RPCs are served on fixed REST routes (the daemon's
// SetCALifecycle); the SDK must reach those routes rather than the generic
// lower-cased fallback, which the daemon answers with 404.
func TestCALifecycleRoutes_MatchTheServedRoutes(t *testing.T) {
	cases := []struct {
		grpcMethod string
		req        proto.Message
		resp       proto.Message
		wantMethod string
		wantPath   string
	}{
		{
			grpcMethod: "/platform.v1.CAService/InitCA",
			req:        &platformv1.InitCARequest{},
			resp:       &platformv1.InitCAResponse{},
			wantMethod: http.MethodPost,
			wantPath:   "/api/v1/ca/init",
		},
		{
			grpcMethod: "/platform.v1.CAService/InstallCACertificates",
			req:        &platformv1.InstallCACertificatesRequest{},
			resp:       &platformv1.InstallCACertificatesResponse{},
			wantMethod: http.MethodPost,
			wantPath:   "/api/v1/ca/trust/install",
		},
		{
			grpcMethod: "/platform.v1.CAService/UninstallCACertificates",
			req:        &platformv1.UninstallCACertificatesRequest{},
			resp:       &platformv1.UninstallCACertificatesResponse{},
			wantMethod: http.MethodPost,
			wantPath:   "/api/v1/ca/trust/uninstall",
		},
	}
	for _, tc := range cases {
		t.Run(tc.grpcMethod, func(t *testing.T) {
			var captured struct {
				method string
				path   string
			}
			a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/health/live" {
					captured.method = r.Method
					captured.path = r.URL.Path
				}
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
		})
	}
}
