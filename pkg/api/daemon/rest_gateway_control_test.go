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
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
)

// gatewayControlRESTServer builds a daemon REST server with the gateway
// control plane mounted over a store in a temporary directory.
func gatewayControlRESTServer(t *testing.T) *RESTServer {
	t.Helper()
	cfg := DefaultConfig()
	cfg.RESTListenAddr = "127.0.0.1:0"
	svc, err := NewService(cfg)
	require.NoError(t, err)
	s, err := NewRESTServer(cfg, svc, slog.Default())
	require.NoError(t, err)
	store, err := gwstate.NewFileStore(t.TempDir())
	require.NoError(t, err)
	s.SetGatewayControlPlane(store, nil, nil, nil)
	return s
}

// gatewayRequest builds a request whose TLS state carries a verified client
// certificate with Common Name cn, or no TLS state when cn is empty.
func gatewayRequest(method, path, body, cn string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if cn != "" {
		leaf := &x509.Certificate{Subject: pkix.Name{CommonName: cn}}
		req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf}}}
	}
	return req
}

func TestSetGatewayControlPlane_TelemetryFromTheCertifiedGatewayIsStored(t *testing.T) {
	s := gatewayControlRESTServer(t)

	rec := httptest.NewRecorder()
	s.Router().ServeHTTP(rec, gatewayRequest(http.MethodPost, "/api/v1/gateway/telemetry", `{"gateway_id":"gw-01"}`, "gw-01"))

	require.Less(t, rec.Code, http.StatusMultipleChoices, "telemetry from gw-01 over its own certificate: %s", rec.Body.String())
}

func TestSetGatewayControlPlane_TelemetryWithoutACertificateIsUnauthenticated(t *testing.T) {
	s := gatewayControlRESTServer(t)

	rec := httptest.NewRecorder()
	s.Router().ServeHTTP(rec, gatewayRequest(http.MethodPost, "/api/v1/gateway/telemetry", `{"gateway_id":"gw-01"}`, ""))

	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestSetGatewayControlPlane_TelemetryForAnotherGatewayIsForbidden(t *testing.T) {
	s := gatewayControlRESTServer(t)

	rec := httptest.NewRecorder()
	s.Router().ServeHTTP(rec, gatewayRequest(http.MethodPost, "/api/v1/gateway/telemetry", `{"gateway_id":"gw-02"}`, "gw-01"))

	require.Equal(t, http.StatusForbidden, rec.Code)
}

func TestSetGatewayControlPlane_StateSurfaceRequiresTheGuard(t *testing.T) {
	s := gatewayControlRESTServer(t)

	// A nil guard denies every request: the operator half is never served
	// on the gateway's certificate alone.
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		path := "/api/v1/gateway/state"
		if method == http.MethodDelete {
			path += "/gw-01"
		}
		rec := httptest.NewRecorder()
		s.Router().ServeHTTP(rec, gatewayRequest(method, path, "", "gw-01"))
		require.Equal(t, http.StatusForbidden, rec.Code, method+" "+path)
	}
}

func TestSetGatewayControlPlane_NothingMountedWithoutABackend(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RESTListenAddr = "127.0.0.1:0"
	svc, err := NewService(cfg)
	require.NoError(t, err)
	s, err := NewRESTServer(cfg, svc, slog.Default())
	require.NoError(t, err)

	s.SetGatewayControlPlane(nil, nil, nil, nil)

	rec := httptest.NewRecorder()
	s.Router().ServeHTTP(rec, gatewayRequest(http.MethodPost, "/api/v1/gateway/telemetry", `{"gateway_id":"gw-01"}`, "gw-01"))
	require.Equal(t, http.StatusNotFound, rec.Code)
}

func TestGatewayStateReadScope_IsTheSnapshotRPCScope(t *testing.T) {
	require.Equal(t, grpcapi.ScopeForMethod("/platform.v1.GatewayService/GetGatewaySnapshot"), gatewayStateReadScope)
}
