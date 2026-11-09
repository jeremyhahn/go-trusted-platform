package daemon

import (
	"context"
	"log/slog"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/calleradmission"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// attestationRESTCallers are the callers the attestation REST tests
// authenticate as.
var attestationRESTCallers = iamRESTTokens{
	"attestation-reader":  {Subject: "attestation-reader", TenantID: iamRESTTenantA, Scopes: []string{"attestation:read"}},
	"attestation-writer":  {Subject: "attestation-writer", TenantID: iamRESTTenantA, Scopes: []string{"attestation:write"}},
	"attestation-deleter": {Subject: "attestation-deleter", TenantID: iamRESTTenantA, Scopes: []string{"attestation:delete"}},
}

// recordingAttestationServer counts the manifest rpcs that reach it and
// answers each with an empty response; every other rpc is Unimplemented.
type recordingAttestationServer struct {
	platformv1.UnimplementedAttestationServiceServer
	builds, verifies, deletes atomic.Int32
}

func (s *recordingAttestationServer) BuildManifest(context.Context, *platformv1.BuildManifestRequest) (*platformv1.BuildManifestResponse, error) {
	s.builds.Add(1)
	return &platformv1.BuildManifestResponse{}, nil
}

func (s *recordingAttestationServer) VerifyManifest(context.Context, *platformv1.VerifyManifestRequest) (*platformv1.VerifyManifestResponse, error) {
	s.verifies.Add(1)
	return &platformv1.VerifyManifestResponse{}, nil
}

func (s *recordingAttestationServer) DeleteManifest(context.Context, *platformv1.DeleteManifestRequest) (*platformv1.DeleteManifestResponse, error) {
	s.deletes.Add(1)
	return &platformv1.DeleteManifestResponse{}, nil
}

// attestationRESTServer is a RESTServer serving the attestation routers over
// server, with no report cache.
func attestationRESTServer(t *testing.T, server platformv1.AttestationServiceServer) *RESTServer {
	t.Helper()
	s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
	guard := restapi.NewScopeGuard(attestationRESTCallers, nil, nil)
	require.NoError(t, s.SetAttestationRouterHandlers(logging.DefaultLogger(), server, ReportingHandles{}, guard))
	return s
}

func TestSetAttestationRouterHandlers_RefusesAMissingDependency(t *testing.T) {
	guard := restapi.NewScopeGuard(attestationRESTCallers, nil, nil)
	cases := []struct {
		name   string
		logger *logging.Logger
		guard  *restapi.ScopeGuard
		reason string
	}{
		{"no logger", nil, guard, "no logger"},
		{"no guard", logging.DefaultLogger(), nil, "no REST scope guard"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
			err := s.SetAttestationRouterHandlers(tc.logger, &recordingAttestationServer{}, ReportingHandles{}, tc.guard)
			var unavailable ErrAttestationRESTUnavailable
			require.ErrorAs(t, err, &unavailable)
			assert.Equal(t, tc.reason, unavailable.Reason)
			assert.NotContains(t, restRouteTemplates(t, s, "/api/v1/attestation"), "/api/v1/attestation/manifests",
				"a refused mount serves no attestation route")
		})
	}
}

// A node without an attestation service serves no attestation route.
func TestSetAttestationRouterHandlers_MountsNothingWithoutAServer(t *testing.T) {
	s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
	guard := restapi.NewScopeGuard(attestationRESTCallers, nil, nil)
	require.NoError(t, s.SetAttestationRouterHandlers(logging.DefaultLogger(), nil, ReportingHandles{}, guard))
	assert.Empty(t, restRouteTemplates(t, s, "/api/v1/attestation"))
}

// The report and caller routes are mounted only with a report cache.
// Without a report cache the reporting routes still mount and fail closed:
// the caller policy admits nobody and the report list answers 503.
func TestSetAttestationRouterHandlers_MountsFailClosedReportingWithoutACache(t *testing.T) {
	s := attestationRESTServer(t, &recordingAttestationServer{})
	assert.Contains(t, restRouteTemplates(t, s, "/api/v1/attestation"), "/api/v1/attestation/reports")
	assert.Contains(t, restRouteTemplates(t, s, "/api/v1/attestation"), "/api/v1/attestation/callers")
	callers := serveIAM(s, http.MethodGet, "/api/v1/attestation/callers", "attestation-reader")
	assert.Equal(t, http.StatusOK, callers.Code, callers.Body.String())
	reports := serveIAM(s, http.MethodGet, "/api/v1/attestation/reports", "attestation-reader")
	assert.Equal(t, http.StatusServiceUnavailable, reports.Code, reports.Body.String())
}

// A node without a collector still has a caller policy: the callers route
// describes it, while the reports routes stay 503.
func TestSetAttestationRouterHandlers_DescribesThePolicyWithoutACache(t *testing.T) {
	with := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
	guard := restapi.NewScopeGuard(attestationRESTCallers, nil, nil)
	policy := stubDescriber{d: calleradmission.Description{
		Strategy: calleradmission.StrategyAllowlist, Identities: []string{"a"}, ListValid: true, AnchorsConfigured: true, AnchorSource: "x",
	}}
	require.NoError(t, with.SetAttestationRouterHandlers(logging.DefaultLogger(), &recordingAttestationServer{},
		ReportingHandles{Policy: policy}, guard))
	callers := serveIAM(with, http.MethodGet, "/api/v1/attestation/callers", "attestation-reader")
	require.Equal(t, http.StatusOK, callers.Code, callers.Body.String())
	assert.Contains(t, callers.Body.String(), `"allowlist"`)
	assert.NotContains(t, callers.Body.String(), `"admits_nobody":true`)
	reports := serveIAM(with, http.MethodGet, "/api/v1/attestation/reports", "attestation-reader")
	assert.Equal(t, http.StatusServiceUnavailable, reports.Code, reports.Body.String())
}

func TestSetAttestationRouterHandlers_MountsReportsWithACache(t *testing.T) {
	with := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
	guard := restapi.NewScopeGuard(attestationRESTCallers, nil, nil)
	require.NoError(t, with.SetAttestationRouterHandlers(logging.DefaultLogger(), &recordingAttestationServer{},
		ReportingHandles{Reports: routeTableAttestationCache{}}, guard))
	assert.Contains(t, restRouteTemplates(t, with, "/api/v1/attestation"), "/api/v1/attestation/reports/{device_id}/refresh")
	assert.Contains(t, restRouteTemplates(t, with, "/api/v1/attestation"), "/api/v1/attestation/callers")
	recorder := serveIAM(with, http.MethodGet, "/api/v1/attestation/callers", "attestation-reader")
	assert.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	assert.Equal(t, http.StatusForbidden, serveIAM(with, http.MethodPost, "/api/v1/attestation/reports/d1/refresh", "attestation-reader").Code)
}

// Each manifest route needs the scope the gRPC catalog gives its rpc, and a
// refused request never reaches the server.
func TestAttestationREST_ScopePerRoute(t *testing.T) {
	server := &recordingAttestationServer{}
	s := attestationRESTServer(t, server)

	recorder := serveIAM(s, http.MethodPost, "/api/v1/attestation/manifests/build", "attestation-reader")
	assert.Equal(t, http.StatusForbidden, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "scope attestation:write required")
	assert.Zero(t, server.builds.Load())

	recorder = serveIAM(s, http.MethodPost, "/api/v1/attestation/manifests/verify", "attestation-reader")
	assert.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	assert.Equal(t, int32(1), server.verifies.Load(), "a read caller verifies a manifest")

	recorder = serveIAM(s, http.MethodDelete, "/api/v1/attestation/manifests/m1", "attestation-reader")
	assert.Equal(t, http.StatusForbidden, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "scope attestation:delete required")
	assert.Zero(t, server.deletes.Load())

	recorder = serveIAM(s, http.MethodPost, "/api/v1/attestation/manifests/build", "attestation-writer")
	assert.Equal(t, http.StatusCreated, recorder.Code, recorder.Body.String())
	assert.Equal(t, int32(1), server.builds.Load())

	recorder = serveIAM(s, http.MethodDelete, "/api/v1/attestation/manifests/m1", "attestation-deleter")
	assert.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	assert.Equal(t, int32(1), server.deletes.Load())

	assert.Equal(t, http.StatusUnauthorized, serveIAM(s, http.MethodGet, "/api/v1/attestation/manifests", "").Code)
}

func TestAttestationRouteScope(t *testing.T) {
	cases := []struct{ method, route, scope string }{
		{http.MethodGet, "/api/v1/attestation/manifests", "attestation:read"},
		{http.MethodPost, "/api/v1/attestation/manifests/verify", "attestation:read"},
		{http.MethodPost, "/api/v1/attestation/quote/verify", "attestation:read"},
		{http.MethodPost, "/api/v1/attestation/manifests/build", "attestation:write"},
		{http.MethodPost, "/api/v1/attestation/vm/{id}", "attestation:write"},
		{http.MethodDelete, "/api/v1/attestation/manifests/{id}", "attestation:delete"},
	}
	for _, tc := range cases {
		scope, err := attestationRouteScope(tc.method, tc.route)
		require.NoError(t, err, "%s %s", tc.method, tc.route)
		assert.Equal(t, tc.scope, scope, "%s %s", tc.method, tc.route)
	}
	_, err := attestationRouteScope(http.MethodOptions, "/api/v1/attestation/manifests")
	var forbidden restapi.ErrRouteForbidden
	require.ErrorAs(t, err, &forbidden)
	assert.Equal(t, "attestation:*", forbidden.Scope)
}
