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

package v1

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/jwt"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	restgateway "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/gateway"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// fakeSDNGatewayRegistry satisfies RestHandlerRegistry for the SDN and
// gateway accessors only; the embedded nil interface panics on any
// other accessor, which would indicate the routes under test reached
// beyond their declared dependencies.
type fakeSDNGatewayRegistry struct {
	RestHandlerRegistry
	sdn     platformv1.SDNServiceServer
	gateway platformv1.GatewayServiceServer
	writer  response.HttpWriter
}

func (f *fakeSDNGatewayRegistry) ResponseWriter() response.HttpWriter {
	return f.writer
}

func (f *fakeSDNGatewayRegistry) SDNService() platformv1.SDNServiceServer {
	return f.sdn
}

func (f *fakeSDNGatewayRegistry) GatewayServiceServer() platformv1.GatewayServiceServer {
	return f.gateway
}

func (f *fakeSDNGatewayRegistry) GatewayControlPlane() (restgateway.GatewayStateStore, restgateway.DesiredConfigSource) {
	return nil, nil
}

func (f *fakeSDNGatewayRegistry) GatewayVPNLeases() restgateway.VPNLeaseSink { return nil }

// JSONWebTokenHandler and PlatformTokenMiddleware are declared because
// gating /sdn and /sdn/gateway gave those routes a real dependency on the
// inbound authentication seam: v1Router.gated() resolves it at
// registration time. That is a genuine dependency of the routes under
// test, not an accessor they reached beyond their declared set for, so it
// is declared here rather than worked around.
//
// It publishes an admin session rather than denying, so these tests assert
// what they are actually about — that the request reaches the zone and
// IPAM handlers instead of a 404 or the sdn 503 stub. A denying seam would
// turn every case into a 401 and prove nothing about routing.
func (f *fakeSDNGatewayRegistry) JSONWebTokenHandler() jwt.TokenHandler {
	return &sessionAuth{roles: []string{common.ROLE_ADMIN}, tenantID: "system"}
}

func (f *fakeSDNGatewayRegistry) PlatformTokenMiddleware() middleware.AuthMiddleware {
	return nil
}

// newSDNGatewayTestRouter registers the gateway + sdn routes in the
// production order (gateway first, then sdn) so the ordering contract
// between /sdn/gateway/ipam and the sdn 503 stub is under test.
func newSDNGatewayTestRouter(t *testing.T, sdn platformv1.SDNServiceServer, gateway platformv1.GatewayServiceServer) *mux.Router {
	t.Helper()
	logger := testLogger()
	writer := response.NewResponseWriter(logger, nil)
	mr := mux.NewRouter()
	v1Router := &Router{
		logger:         logger,
		responseWriter: writer,
		router:         mr,
		restHandlerRegistry: &fakeSDNGatewayRegistry{
			sdn:     sdn,
			gateway: gateway,
			writer:  writer,
		},
		serviceRegistry: NewServiceRegistry(logger, writer),
	}
	v1Router.gatewayRoutes()
	v1Router.sdnRoutes()
	return mr
}

func TestSDNGatewayIPAM_NotShadowedBySDNStub(t *testing.T) {
	// SDN unconfigured (503 stub on /sdn), gateway configured: the
	// /sdn/gateway/ipam surface registers first and must stay live.
	mr := newSDNGatewayTestRouter(t, nil, &platformv1.UnimplementedGatewayServiceServer{})

	rec := httptest.NewRecorder()
	mr.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sdn/gateway/ipam/pools", nil))
	if rec.Code == http.StatusNotFound {
		t.Fatalf("/sdn/gateway/ipam/pools: 404 — route not registered")
	}
	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if svc, _ := body["service"].(string); svc == "sdn" {
		t.Fatalf("/sdn/gateway/ipam/pools was shadowed by the sdn 503 stub: %s", rec.Body.String())
	}
}

func TestSDNZoneRoutes_RegisteredWithSDNService(t *testing.T) {
	// A configured SDN service registers the zone routes; the
	// UnimplementedSDNServiceServer answers Unimplemented (501), which
	// proves the route dispatched to the real handler rather than 404.
	mr := newSDNGatewayTestRouter(t, &platformv1.UnimplementedSDNServiceServer{}, nil)

	rec := httptest.NewRecorder()
	mr.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sdn/zones", nil))
	if rec.Code == http.StatusNotFound {
		t.Fatalf("/sdn/zones: 404 — zone routes not registered on the sdn router")
	}
}

func TestSDNUnconfigured_ZonesAnswer503(t *testing.T) {
	mr := newSDNGatewayTestRouter(t, nil, nil)

	rec := httptest.NewRecorder()
	mr.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sdn/zones", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/sdn/zones with no sdn service: status = %d, want 503", rec.Code)
	}
	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode 503 body: %v", err)
	}
	if svc, _ := body["service"].(string); svc != "sdn" {
		t.Fatalf("service in body = %q, want sdn", svc)
	}
}
