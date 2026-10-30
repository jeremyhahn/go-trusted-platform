package daemon

import (
	"context"
	"log/slog"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
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
	listed                    *platformv1.ListManifestsRequest
}

func (s *recordingAttestationServer) ListManifests(_ context.Context, req *platformv1.ListManifestsRequest) (*platformv1.ListManifestsResponse, error) {
	s.listed = req
	return &platformv1.ListManifestsResponse{}, nil
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
func TestSetAttestationRouterHandlers_MountsReportsWithACache(t *testing.T) {
	without := attestationRESTServer(t, &recordingAttestationServer{})
	assert.NotContains(t, restRouteTemplates(t, without, "/api/v1/attestation"), "/api/v1/attestation/reports")
	assert.NotContains(t, restRouteTemplates(t, without, "/api/v1/attestation"), "/api/v1/attestation/callers")

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

// Codex review 8545: the daemon mount hands the manifest list filters to the
// service, and a malformed filter never reaches it.
func TestAttestationREST_ListManifestsFilters(t *testing.T) {
	tests := []struct {
		name   string
		query  string
		status int
		want   *platformv1.ListManifestsRequest
	}{
		{
			name:   "filters reach the service",
			query:  "?host_id=node-a&limit=10&offset=5&start_time=2026-10-01T00:00:00Z&end_time=2026-10-02T00:00:00Z",
			status: http.StatusOK,
			want: &platformv1.ListManifestsRequest{
				HostId:    "node-a",
				StartTime: timestamppb.New(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)),
				EndTime:   timestamppb.New(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)),
				Limit:     10,
				Offset:    5,
			},
		},
		{name: "no filters", query: "", status: http.StatusOK, want: &platformv1.ListManifestsRequest{}},
		{name: "malformed limit", query: "?limit=ten", status: http.StatusBadRequest},
		{name: "start after end", query: "?start_time=2026-10-02T00:00:00Z&end_time=2026-10-01T00:00:00Z", status: http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := &recordingAttestationServer{}
			s := attestationRESTServer(t, server)
			recorder := serveIAM(s, http.MethodGet, "/api/v1/attestation/manifests"+tt.query, "attestation-reader")
			require.Equal(t, tt.status, recorder.Code, recorder.Body.String())
			if tt.want == nil {
				assert.Nil(t, server.listed, "a rejected filter does not reach the service")
				return
			}
			assert.True(t, proto.Equal(tt.want, server.listed), "want %v, got %v", tt.want, server.listed)
		})
	}
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
