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

package daemon

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	restgateway "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/gateway"
)

// gatewayTelemetryRequest is a gateway's POST /api/v1/gateway/telemetry for
// gatewayID, sent over a TLS connection whose verified client certificate
// names certCN.
func gatewayTelemetryRequest(t *testing.T, gatewayID, certCN string) *http.Request {
	t.Helper()
	body, err := json.Marshal(&gwstate.Snapshot{GatewayID: gatewayID, Hostname: "gw.example.com"})
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/telemetry", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	leaf := &x509.Certificate{Subject: pkix.Name{CommonName: certCN}}
	req.TLS = &tls.ConnectionState{
		HandshakeComplete: true,
		PeerCertificates:  []*x509.Certificate{leaf},
		VerifiedChains:    [][]*x509.Certificate{{leaf}},
	}
	return req
}

func newGatewayControlPlane(t *testing.T) (*restgateway.ControlPlane, gwstate.Store) {
	t.Helper()
	store, err := gwstate.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	return restgateway.NewControlPlane(logger, store, nil, response.NewResponseWriter(logger, nil)), store
}

// TestRESTServer_SetGatewayControlPlane_StoresGatewayTelemetry proves a
// daemon-only control plane takes its gateways' reports: the telemetry route
// is mounted under /api/v1 and stores the snapshot of the gateway the client
// certificate names.
func TestRESTServer_SetGatewayControlPlane_StoresGatewayTelemetry(t *testing.T) {
	s := newTestRESTServerForPhase35(t)
	cp, store := newGatewayControlPlane(t)
	s.SetGatewayControlPlane(cp)

	rec := httptest.NewRecorder()
	s.Router().ServeHTTP(rec, gatewayTelemetryRequest(t, "gw-01", "gw-01"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body %s)", rec.Code, http.StatusOK, rec.Body.String())
	}
	snap, err := store.Get("gw-01")
	if err != nil {
		t.Fatalf("store.Get(gw-01): %v", err)
	}
	if snap.GatewayID != "gw-01" {
		t.Fatalf("stored gateway_id = %q, want gw-01", snap.GatewayID)
	}
}

// TestRESTServer_SetGatewayControlPlane_RefusesAnotherGatewaysReport keeps the
// gateway binding on the daemon REST server: a certificate for one gateway
// cannot report for another.
func TestRESTServer_SetGatewayControlPlane_RefusesAnotherGatewaysReport(t *testing.T) {
	s := newTestRESTServerForPhase35(t)
	cp, store := newGatewayControlPlane(t)
	s.SetGatewayControlPlane(cp)

	rec := httptest.NewRecorder()
	s.Router().ServeHTTP(rec, gatewayTelemetryRequest(t, "gw-02", "gw-01"))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d (body %s)", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	if _, err := store.Get("gw-02"); err == nil {
		t.Fatal("a report for gw-02 under gw-01's certificate was stored")
	}
}

// TestRESTServer_SetGatewayControlPlane_NilLeavesRoutesUnmounted pins the nil
// case: no control plane, no gateway routes.
func TestRESTServer_SetGatewayControlPlane_NilLeavesRoutesUnmounted(t *testing.T) {
	s := newTestRESTServerForPhase35(t)
	s.SetGatewayControlPlane(nil)

	rec := httptest.NewRecorder()
	s.Router().ServeHTTP(rec, gatewayTelemetryRequest(t, "gw-01", "gw-01"))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}
