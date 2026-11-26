// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: AGPL-3.0-only

package ceremony

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-qrdb/pkg/auth"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// tlsRecordingServer records the TLS state each handler finds in its
// context, which the embedded SDK reads to authenticate share claims.
type tlsRecordingServer struct {
	recordingServer
	seen map[string]*tls.ConnectionState
}

func (s *tlsRecordingServer) record(name string, ctx context.Context) {
	if s.seen == nil {
		s.seen = map[string]*tls.ConnectionState{}
	}
	s.seen[name] = auth.TLSStateFromContext(ctx)
}

func (s *tlsRecordingServer) ClaimShareBegin(ctx context.Context, req *platformv1.CeremonyClaimShareBeginRequest) (*platformv1.CeremonyClaimShareBeginResponse, error) {
	s.record("claim share begin", ctx)
	return s.recordingServer.ClaimShareBegin(ctx, req)
}

func (s *tlsRecordingServer) ClaimShareComplete(ctx context.Context, req *platformv1.CeremonyClaimShareCompleteRequest) (*platformv1.CeremonyClaimShareCompleteResponse, error) {
	s.record("claim share complete", ctx)
	return s.recordingServer.ClaimShareComplete(ctx, req)
}

func (s *tlsRecordingServer) Status(ctx context.Context, req *platformv1.CeremonyStatusRequest) (*platformv1.CeremonyStatusResponse, error) {
	s.record("status", ctx)
	return s.recordingServer.Status(ctx, req)
}

func TestCeremonyRouterPassesTLSStateToTheService(t *testing.T) {
	routes := []struct{ name, verb, path, body string }{
		{"claim share begin", http.MethodPost, "/api/v1/ceremony/claim-share/begin", `{"username":"alice"}`},
		{"claim share complete", http.MethodPost, "/api/v1/ceremony/claim-share/complete", `{"username":"alice","nonce":"n2","signature":"c2ln"}`},
		{"status", http.MethodGet, "/api/v1/ceremony/status", ""},
	}
	for _, withTLS := range []bool{true, false} {
		server := &tlsRecordingServer{}
		router := mountRouter(server)
		for _, route := range routes {
			req := httptest.NewRequest(route.verb, route.path, strings.NewReader(route.body))
			var state *tls.ConnectionState
			if withTLS {
				state = &tls.ConnectionState{HandshakeComplete: true, ServerName: "ca.example"}
			}
			req.TLS = state
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s (tls=%v): status %d, body %s", route.name, withTLS, rec.Code, rec.Body.String())
			}
			got, ok := server.seen[route.name]
			if !ok {
				t.Fatalf("%s (tls=%v): the service was not called", route.name, withTLS)
			}
			if got != state {
				t.Errorf("%s (tls=%v): the service saw TLS state %p, want %p", route.name, withTLS, got, state)
			}
		}
	}
}
