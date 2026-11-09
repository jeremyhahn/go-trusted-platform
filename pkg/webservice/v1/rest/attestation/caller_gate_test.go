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

package attestation

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/calleradmission"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

type stubPolicy struct {
	decision calleradmission.Decision
	peers    []*calleradmission.Peer
	desc     calleradmission.Description
}

func (p *stubPolicy) Evaluate(_ context.Context, peer *calleradmission.Peer) calleradmission.Decision {
	p.peers = append(p.peers, peer)
	return p.decision
}

func (p *stubPolicy) Describe() calleradmission.Description { return p.desc }

func (p *stubPolicy) Anchors() []*x509.Certificate { return nil }

func testWriter() response.HttpWriter {
	return response.NewResponseWriter(logging.NewLogger(slog.LevelError, io.Discard), nil)
}

func testLoggerFor() *logging.Logger {
	return logging.NewLogger(slog.LevelError, io.Discard)
}

func decodeEnvelope(t *testing.T, body *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var env map[string]any
	require.NoError(t, json.Unmarshal(body.Body.Bytes(), &env), body.Body.String())
	return env
}

func mountCallers(rep *Reporting) *mux.Router {
	root := mux.NewRouter()
	NewCallersRouter(rep, testWriter()).RegisterRoutes(root.PathPrefix("/api/v1").Subrouter())
	return root
}

func TestCallersRouter_NoPolicyAdmitsNobody(t *testing.T) {
	for _, rep := range []*Reporting{nil, {}} {
		router := mountCallers(rep)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/attestation/callers", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		payload := decodeEnvelope(t, w)["payload"].(map[string]any)
		assert.Equal(t, true, payload["admits_nobody"])
	}
}

func TestCallersRouter_ReportsTheEffectivePolicy(t *testing.T) {
	policy := &stubPolicy{desc: calleradmission.Description{
		Strategy: calleradmission.StrategyAllowlist, Identities: []string{"cp.example.internal"}, ListValid: true, AnchorsConfigured: true,
	}}
	router := mountCallers(&Reporting{Policy: policy})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/attestation/callers", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	payload := decodeEnvelope(t, w)["payload"].(map[string]any)
	assert.Equal(t, "allowlist", payload["strategy"])
	assert.Equal(t, []any{"cp.example.internal"}, payload["identities"])
	assert.Equal(t, false, payload["admits_nobody"])
}

// --- caller gate ---

func withClientCert(req *http.Request) *http.Request {
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: "cp.example.internal"}}}}
	req.RemoteAddr = "198.51.100.140:41000"
	return req
}

func gateHarness(policy CallerPolicy) (http.Handler, *int, *int) {
	nextHits, operatorHits := 0, 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextHits++
		if id, ok := AdmittedCaller(r.Context()); ok {
			w.Header().Set("X-Admitted", id)
		}
		w.WriteHeader(http.StatusOK)
	})
	operator := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			operatorHits++
			if r.Header.Get("Authorization") == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			h.ServeHTTP(w, r)
		})
	}
	return NewCallerGate(testLoggerFor(), policy, testWriter()).Wrap(next, operator), &nextHits, &operatorHits
}

func TestCallerGate_NoCertificateGoesToTheOperatorChain(t *testing.T) {
	policy := &stubPolicy{}
	h, next, operator := gateHarness(policy)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/attestation/host", nil))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, 1, *operator)
	assert.Equal(t, 0, *next)
	assert.Empty(t, policy.peers, "the policy is not consulted without a certificate")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/attestation/host", nil)
	req.Header.Set("Authorization", "Bearer operator")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 1, *next)
	assert.Empty(t, w.Header().Get("X-Admitted"))
}

func TestCallerGate_AdmittedMachineCallerSkipsTheOperatorChain(t *testing.T) {
	policy := &stubPolicy{decision: calleradmission.Decision{Admitted: true, Identity: "cp.example.internal", Reason: calleradmission.ReasonAdmitted}}
	h, next, operator := gateHarness(policy)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, withClientCert(httptest.NewRequest(http.MethodPost, "/api/v1/attestation/host", nil)))
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 1, *next)
	assert.Equal(t, 0, *operator)
	assert.Equal(t, "cp.example.internal", w.Header().Get("X-Admitted"))
	require.Len(t, policy.peers, 1)
	assert.Equal(t, "198.51.100.140:41000", policy.peers[0].RemoteAddr)
}

func TestCallerGate_RefusedMachineCallerGetsNoSecondChance(t *testing.T) {
	cases := []struct {
		reason calleradmission.Reason
		status int
	}{
		{calleradmission.ReasonNotListed, http.StatusForbidden},
		{calleradmission.ReasonNotAttested, http.StatusForbidden},
		{calleradmission.ReasonListEmpty, http.StatusForbidden},
		{calleradmission.ReasonNoAnchors, http.StatusForbidden},
		{calleradmission.ReasonUntrustedIssuer, http.StatusUnauthorized},
		{calleradmission.ReasonNoIdentity, http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(string(tc.reason), func(t *testing.T) {
			policy := &stubPolicy{decision: calleradmission.Decision{Admitted: false, Identity: "x", Reason: tc.reason}}
			h, next, operator := gateHarness(policy)
			req := withClientCert(httptest.NewRequest(http.MethodPost, "/api/v1/attestation/host", nil))
			// Even a valid operator credential does not rescue a refused
			// machine identity on the same request.
			req.Header.Set("Authorization", "Bearer operator")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			assert.Equal(t, tc.status, w.Code)
			assert.Equal(t, 0, *next)
			assert.Equal(t, 0, *operator)
			assert.Contains(t, w.Body.String(), string(tc.reason))
		})
	}
}

func TestCallerGate_NilPolicyIsOperatorOnly(t *testing.T) {
	var gate *CallerGate
	hits := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ })
	h := gate.Wrap(next, nil)
	h.ServeHTTP(httptest.NewRecorder(), withClientCert(httptest.NewRequest(http.MethodPost, "/", nil)))
	assert.Equal(t, 1, hits)

	h = NewCallerGate(testLoggerFor(), nil, testWriter()).Wrap(next, func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) })
	})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, withClientCert(httptest.NewRequest(http.MethodPost, "/", nil)))
	assert.Equal(t, http.StatusTeapot, w.Code, "with no policy a certificate is ignored and the operator chain decides")
	assert.Equal(t, 1, hits)
}

func TestAdmittedCaller_AbsentByDefault(t *testing.T) {
	_, ok := AdmittedCaller(context.Background())
	assert.False(t, ok)
	_, ok = AdmittedCaller(context.WithValue(context.Background(), callerContextKey{}, ""))
	assert.False(t, ok)
}

func TestErrCallerRefused(t *testing.T) {
	assert.Contains(t, ErrCallerRefused{Reason: calleradmission.ReasonNotListed}.Error(), "not-listed")
	assert.Contains(t, ErrCallerRefused{Identity: "a", Reason: calleradmission.ReasonNotListed}.Error(), "a refused")
}

func TestQuoteRoutes_RegisteredThroughTheGate(t *testing.T) {
	r, _ := newServerRouter()
	root := mux.NewRouter()
	policy := &stubPolicy{decision: calleradmission.Decision{Admitted: true, Identity: "cp", Reason: calleradmission.ReasonAdmitted}}
	gate := NewCallerGate(testLoggerFor(), policy, testWriter())
	operatorCalls := 0
	r.RegisterQuoteRoutes(root.PathPrefix("/api/v1").Subrouter(), gate, func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { operatorCalls++; h.ServeHTTP(w, req) })
	})
	for _, path := range []string{"/api/v1/attestation/host", "/api/v1/attestation/quote"} {
		w := httptest.NewRecorder()
		root.ServeHTTP(w, withClientCert(httptest.NewRequest(http.MethodPost, path, nil)))
		// The server is nil in this harness, so an admitted caller reaches
		// the handler and gets its 503; an unadmitted one would get 403.
		assert.Equal(t, http.StatusServiceUnavailable, w.Code, path)
	}
	assert.Equal(t, 0, operatorCalls)
	assert.Len(t, policy.peers, 2)
}
