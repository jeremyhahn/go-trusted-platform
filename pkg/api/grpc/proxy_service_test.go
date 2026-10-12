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

package grpc

import (
	"context"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/proxy"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeProxyService is a configurable ProxyService test double.
type fakeProxyService struct {
	route      proxy.RouteConfig
	pool       proxy.BackendPoolConfig
	routes     []proxy.RouteConfig
	pools      []proxy.BackendPoolConfig
	version    uint64
	statusInfo *ProxyStatusInfo
	matrix     *ProxyZoneMatrixInfo
	err        error

	lastRoute proxy.RouteConfig
	lastPool  proxy.BackendPoolConfig
	lastID    string
}

func (f *fakeProxyService) CreateRoute(ctx context.Context, route proxy.RouteConfig) (proxy.RouteConfig, uint64, error) {
	f.lastRoute = route
	return f.route, f.version, f.err
}

func (f *fakeProxyService) Route(ctx context.Context, id string) (proxy.RouteConfig, error) {
	f.lastID = id
	return f.route, f.err
}

func (f *fakeProxyService) UpdateRoute(ctx context.Context, route proxy.RouteConfig) (proxy.RouteConfig, uint64, error) {
	f.lastRoute = route
	return f.route, f.version, f.err
}

func (f *fakeProxyService) DeleteRoute(ctx context.Context, id string) (uint64, error) {
	f.lastID = id
	return f.version, f.err
}

func (f *fakeProxyService) Routes(ctx context.Context) ([]proxy.RouteConfig, uint64, error) {
	return f.routes, f.version, f.err
}

func (f *fakeProxyService) CreatePool(ctx context.Context, pool proxy.BackendPoolConfig) (proxy.BackendPoolConfig, uint64, error) {
	f.lastPool = pool
	return f.pool, f.version, f.err
}

func (f *fakeProxyService) Pool(ctx context.Context, id string) (proxy.BackendPoolConfig, error) {
	f.lastID = id
	return f.pool, f.err
}

func (f *fakeProxyService) UpdatePool(ctx context.Context, pool proxy.BackendPoolConfig) (proxy.BackendPoolConfig, uint64, error) {
	f.lastPool = pool
	return f.pool, f.version, f.err
}

func (f *fakeProxyService) DeletePool(ctx context.Context, id string) (uint64, error) {
	f.lastID = id
	return f.version, f.err
}

func (f *fakeProxyService) Pools(ctx context.Context) ([]proxy.BackendPoolConfig, uint64, error) {
	return f.pools, f.version, f.err
}

func (f *fakeProxyService) Snapshot(ctx context.Context) ([]proxy.RouteConfig, []proxy.BackendPoolConfig, uint64, error) {
	return f.routes, f.pools, f.version, f.err
}

func (f *fakeProxyService) Status(ctx context.Context) (*ProxyStatusInfo, error) {
	return f.statusInfo, f.err
}

func (f *fakeProxyService) Reload(ctx context.Context) (uint64, error) {
	return f.version, f.err
}

func (f *fakeProxyService) ZoneMatrix(ctx context.Context) (*ProxyZoneMatrixInfo, error) {
	return f.matrix, f.err
}

// newProxyTestService returns a ProxyGRPCService over a preconfigured fake.
func newProxyTestService(fake *fakeProxyService) *ProxyGRPCService {
	return NewProxyGRPCService(nil, fake)
}

// pbTestRoute returns a fully populated protobuf route.
func pbTestRoute(id string) *platformv1.ProxyRoute {
	return &platformv1.ProxyRoute{
		Id:         id,
		Hosts:      []string{"example.com"},
		PathPrefix: "/api",
		PoolId:     "pool-1",
		Auth: &platformv1.ProxyAuthRequirements{
			Mode:                   proxy.AuthModeMTLS,
			RequireIdevid:          true,
			AllowedZones:           []string{"control-plane"},
			BackendZone:            "internal",
			RequireAttestation:     true,
			AttestationMaxAgeNanos: int64(5 * time.Minute),
			RequiredRoles:          []string{"admin"},
			RequiredScopes:         []string{"proxy:read"},
			OpaPolicy:              "policies/proxy.rego",
			TokenZone:              "edge",
		},
		StripPrefix:  true,
		PreserveHost: true,
	}
}

// pbTestPool returns a fully populated protobuf pool.
func pbTestPool(id string) *platformv1.ProxyPool {
	return &platformv1.ProxyPool{
		Id: id,
		Backends: []*platformv1.ProxyBackend{
			{Url: "https://10.0.0.10:8443", Weight: 2},
		},
		Balancer: "round-robin",
		Tls: &platformv1.ProxyBackendTLS{
			TrustClass:     "internal",
			MtlsClientCert: true,
		},
		MaxIdleConnsPerHost:  16,
		IdleConnTimeoutNanos: int64(90 * time.Second),
	}
}

// requireCode fails the test unless err is a gRPC status with the given code.
func requireCode(t *testing.T, err error, want codes.Code) {
	t.Helper()
	if status.Code(err) != want {
		t.Fatalf("status code = %v (%v), want %v", status.Code(err), err, want)
	}
}

func TestProxyGRPCService_NilService(t *testing.T) {
	s := NewProxyGRPCService(nil, nil)
	ctx := context.Background()

	if _, err := s.CreateRoute(ctx, &platformv1.CreateProxyRouteRequest{}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("CreateRoute code = %v, want FailedPrecondition", status.Code(err))
	}
	if _, err := s.GetRoute(ctx, &platformv1.GetProxyRouteRequest{}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("GetRoute code = %v, want FailedPrecondition", status.Code(err))
	}
	if _, err := s.UpdateRoute(ctx, &platformv1.UpdateProxyRouteRequest{}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("UpdateRoute code = %v, want FailedPrecondition", status.Code(err))
	}
	if _, err := s.DeleteRoute(ctx, &platformv1.DeleteProxyRouteRequest{}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("DeleteRoute code = %v, want FailedPrecondition", status.Code(err))
	}
	if _, err := s.ListRoutes(ctx, &platformv1.ListProxyRoutesRequest{}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("ListRoutes code = %v, want FailedPrecondition", status.Code(err))
	}
	if _, err := s.CreatePool(ctx, &platformv1.CreateProxyPoolRequest{}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("CreatePool code = %v, want FailedPrecondition", status.Code(err))
	}
	if _, err := s.GetPool(ctx, &platformv1.GetProxyPoolRequest{}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("GetPool code = %v, want FailedPrecondition", status.Code(err))
	}
	if _, err := s.UpdatePool(ctx, &platformv1.UpdateProxyPoolRequest{}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("UpdatePool code = %v, want FailedPrecondition", status.Code(err))
	}
	if _, err := s.DeletePool(ctx, &platformv1.DeleteProxyPoolRequest{}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("DeletePool code = %v, want FailedPrecondition", status.Code(err))
	}
	if _, err := s.ListPools(ctx, &platformv1.ListProxyPoolsRequest{}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("ListPools code = %v, want FailedPrecondition", status.Code(err))
	}
	if _, err := s.GetProxyConfig(ctx, &platformv1.GetProxyConfigRequest{}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("GetProxyConfig code = %v, want FailedPrecondition", status.Code(err))
	}
	if _, err := s.GetProxyStatus(ctx, &platformv1.GetProxyStatusRequest{}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("GetProxyStatus code = %v, want FailedPrecondition", status.Code(err))
	}
	if _, err := s.ReloadProxyConfig(ctx, &platformv1.ReloadProxyConfigRequest{}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("ReloadProxyConfig code = %v, want FailedPrecondition", status.Code(err))
	}
	if _, err := s.GetZoneMatrix(ctx, &platformv1.GetProxyZoneMatrixRequest{}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("GetZoneMatrix code = %v, want FailedPrecondition", status.Code(err))
	}
}

func TestProxyGRPCService_CreateRoute(t *testing.T) {
	fake := &fakeProxyService{
		route:   proxy.RouteFromProto(pbTestRoute("web")),
		version: 7,
	}
	s := newProxyTestService(fake)

	resp, err := s.CreateRoute(context.Background(), &platformv1.CreateProxyRouteRequest{Route: pbTestRoute("web")})
	if err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}
	if resp.GetVersion() != 7 {
		t.Errorf("version = %d, want 7", resp.GetVersion())
	}
	if resp.GetRoute().GetId() != "web" {
		t.Errorf("route id = %q, want web", resp.GetRoute().GetId())
	}
	// Full round-trip fidelity through the converters.
	if got := resp.GetRoute().GetAuth().GetAttestationMaxAgeNanos(); got != int64(5*time.Minute) {
		t.Errorf("attestation max age = %d, want %d", got, int64(5*time.Minute))
	}
	if !fake.lastRoute.Auth.RequireIDevID || fake.lastRoute.Auth.OPAPolicy != "policies/proxy.rego" ||
		fake.lastRoute.Auth.TokenZone != "edge" {
		t.Errorf("domain conversion dropped auth fields: %+v", fake.lastRoute.Auth)
	}
}

func TestProxyGRPCService_CreateRoute_Invalid(t *testing.T) {
	s := newProxyTestService(&fakeProxyService{})
	ctx := context.Background()

	_, err := s.CreateRoute(ctx, &platformv1.CreateProxyRouteRequest{})
	requireCode(t, err, codes.InvalidArgument)

	_, err = s.CreateRoute(ctx, &platformv1.CreateProxyRouteRequest{Route: &platformv1.ProxyRoute{}})
	requireCode(t, err, codes.InvalidArgument)
}

func TestProxyGRPCService_GetRoute(t *testing.T) {
	fake := &fakeProxyService{route: proxy.RouteFromProto(pbTestRoute("web"))}
	s := newProxyTestService(fake)

	resp, err := s.GetRoute(context.Background(), &platformv1.GetProxyRouteRequest{Id: "web"})
	if err != nil {
		t.Fatalf("GetRoute: %v", err)
	}
	if resp.GetRoute().GetPoolId() != "pool-1" {
		t.Errorf("pool id = %q, want pool-1", resp.GetRoute().GetPoolId())
	}
	if fake.lastID != "web" {
		t.Errorf("service received id %q, want web", fake.lastID)
	}
}

func TestProxyGRPCService_GetRoute_Errors(t *testing.T) {
	s := newProxyTestService(&fakeProxyService{err: ErrProxyRouteNotFound{ID: "ghost"}})
	ctx := context.Background()

	_, err := s.GetRoute(ctx, &platformv1.GetProxyRouteRequest{})
	requireCode(t, err, codes.InvalidArgument)

	_, err = s.GetRoute(ctx, &platformv1.GetProxyRouteRequest{Id: "ghost"})
	requireCode(t, err, codes.NotFound)
}

func TestProxyGRPCService_UpdateRoute_IDResolution(t *testing.T) {
	fake := &fakeProxyService{route: proxy.RouteFromProto(pbTestRoute("web")), version: 3}
	s := newProxyTestService(fake)
	ctx := context.Background()

	// Body without ID takes the request ID.
	body := pbTestRoute("")
	if _, err := s.UpdateRoute(ctx, &platformv1.UpdateProxyRouteRequest{Id: "web", Route: body}); err != nil {
		t.Fatalf("UpdateRoute: %v", err)
	}
	if fake.lastRoute.ID != "web" {
		t.Errorf("service route id = %q, want web (from request id)", fake.lastRoute.ID)
	}

	// Mismatched IDs are rejected.
	_, err := s.UpdateRoute(ctx, &platformv1.UpdateProxyRouteRequest{Id: "a", Route: pbTestRoute("b")})
	requireCode(t, err, codes.InvalidArgument)

	// Missing both IDs is rejected.
	_, err = s.UpdateRoute(ctx, &platformv1.UpdateProxyRouteRequest{Route: pbTestRoute("")})
	requireCode(t, err, codes.InvalidArgument)

	// Missing route body is rejected.
	_, err = s.UpdateRoute(ctx, &platformv1.UpdateProxyRouteRequest{Id: "web"})
	requireCode(t, err, codes.InvalidArgument)
}

func TestProxyGRPCService_DeleteRoute(t *testing.T) {
	fake := &fakeProxyService{version: 9}
	s := newProxyTestService(fake)

	resp, err := s.DeleteRoute(context.Background(), &platformv1.DeleteProxyRouteRequest{Id: "web"})
	if err != nil {
		t.Fatalf("DeleteRoute: %v", err)
	}
	if resp.GetVersion() != 9 {
		t.Errorf("version = %d, want 9", resp.GetVersion())
	}
}

func TestProxyGRPCService_DeleteRoute_Errors(t *testing.T) {
	s := newProxyTestService(&fakeProxyService{err: ErrProxyRouteNotFound{ID: "ghost"}})
	ctx := context.Background()

	_, err := s.DeleteRoute(ctx, &platformv1.DeleteProxyRouteRequest{})
	requireCode(t, err, codes.InvalidArgument)

	_, err = s.DeleteRoute(ctx, &platformv1.DeleteProxyRouteRequest{Id: "ghost"})
	requireCode(t, err, codes.NotFound)
}

func TestProxyGRPCService_ListRoutes(t *testing.T) {
	fake := &fakeProxyService{
		routes:  []proxy.RouteConfig{proxy.RouteFromProto(pbTestRoute("a")), proxy.RouteFromProto(pbTestRoute("b"))},
		version: 4,
	}
	s := newProxyTestService(fake)

	resp, err := s.ListRoutes(context.Background(), &platformv1.ListProxyRoutesRequest{})
	if err != nil {
		t.Fatalf("ListRoutes: %v", err)
	}
	if len(resp.GetRoutes()) != 2 || resp.GetVersion() != 4 {
		t.Errorf("list = (%d routes, v%d), want (2, v4)", len(resp.GetRoutes()), resp.GetVersion())
	}
}

func TestProxyGRPCService_ListRoutes_Error(t *testing.T) {
	s := newProxyTestService(&fakeProxyService{err: context.DeadlineExceeded})
	_, err := s.ListRoutes(context.Background(), &platformv1.ListProxyRoutesRequest{})
	requireCode(t, err, codes.Internal)
}

func TestProxyGRPCService_CreatePool(t *testing.T) {
	fake := &fakeProxyService{pool: proxy.PoolFromProto(pbTestPool("pool-1")), version: 2}
	s := newProxyTestService(fake)

	resp, err := s.CreatePool(context.Background(), &platformv1.CreateProxyPoolRequest{Pool: pbTestPool("pool-1")})
	if err != nil {
		t.Fatalf("CreatePool: %v", err)
	}
	if resp.GetPool().GetTls().GetTrustClass() != "internal" {
		t.Errorf("trust class = %q, want internal", resp.GetPool().GetTls().GetTrustClass())
	}
	if resp.GetPool().GetIdleConnTimeoutNanos() != int64(90*time.Second) {
		t.Errorf("idle conn timeout = %d, want %d", resp.GetPool().GetIdleConnTimeoutNanos(), int64(90*time.Second))
	}
	if fake.lastPool.TLS.TrustClass != "internal" || !fake.lastPool.TLS.MTLSClientCert {
		t.Errorf("domain conversion dropped TLS fields: %+v", fake.lastPool.TLS)
	}
}

func TestProxyGRPCService_CreatePool_Invalid(t *testing.T) {
	s := newProxyTestService(&fakeProxyService{})
	ctx := context.Background()

	_, err := s.CreatePool(ctx, &platformv1.CreateProxyPoolRequest{})
	requireCode(t, err, codes.InvalidArgument)

	_, err = s.CreatePool(ctx, &platformv1.CreateProxyPoolRequest{Pool: &platformv1.ProxyPool{}})
	requireCode(t, err, codes.InvalidArgument)
}

func TestProxyGRPCService_GetPool_Errors(t *testing.T) {
	s := newProxyTestService(&fakeProxyService{err: ErrProxyPoolNotFound{ID: "ghost"}})
	ctx := context.Background()

	_, err := s.GetPool(ctx, &platformv1.GetProxyPoolRequest{})
	requireCode(t, err, codes.InvalidArgument)

	_, err = s.GetPool(ctx, &platformv1.GetProxyPoolRequest{Id: "ghost"})
	requireCode(t, err, codes.NotFound)
}

func TestProxyGRPCService_UpdatePool_IDResolution(t *testing.T) {
	fake := &fakeProxyService{pool: proxy.PoolFromProto(pbTestPool("pool-1")), version: 5}
	s := newProxyTestService(fake)
	ctx := context.Background()

	body := pbTestPool("")
	if _, err := s.UpdatePool(ctx, &platformv1.UpdateProxyPoolRequest{Id: "pool-1", Pool: body}); err != nil {
		t.Fatalf("UpdatePool: %v", err)
	}
	if fake.lastPool.ID != "pool-1" {
		t.Errorf("service pool id = %q, want pool-1 (from request id)", fake.lastPool.ID)
	}

	_, err := s.UpdatePool(ctx, &platformv1.UpdateProxyPoolRequest{Id: "a", Pool: pbTestPool("b")})
	requireCode(t, err, codes.InvalidArgument)

	_, err = s.UpdatePool(ctx, &platformv1.UpdateProxyPoolRequest{Pool: pbTestPool("")})
	requireCode(t, err, codes.InvalidArgument)

	_, err = s.UpdatePool(ctx, &platformv1.UpdateProxyPoolRequest{Id: "pool-1"})
	requireCode(t, err, codes.InvalidArgument)
}

func TestProxyGRPCService_DeletePool_Errors(t *testing.T) {
	ctx := context.Background()

	s := newProxyTestService(&fakeProxyService{err: ErrProxyPoolInUse{ID: "pool-1", Routes: []string{"web"}}})
	_, err := s.DeletePool(ctx, &platformv1.DeleteProxyPoolRequest{Id: "pool-1"})
	requireCode(t, err, codes.FailedPrecondition)

	s = newProxyTestService(&fakeProxyService{err: ErrProxyPoolExists{ID: "pool-1"}})
	_, err = s.CreatePool(ctx, &platformv1.CreateProxyPoolRequest{Pool: pbTestPool("pool-1")})
	requireCode(t, err, codes.AlreadyExists)

	s = newProxyTestService(&fakeProxyService{err: ErrProxyRouteExists{ID: "web"}})
	_, err = s.CreateRoute(ctx, &platformv1.CreateProxyRouteRequest{Route: pbTestRoute("web")})
	requireCode(t, err, codes.AlreadyExists)
}

func TestProxyGRPCService_ListPools(t *testing.T) {
	fake := &fakeProxyService{
		pools:   []proxy.BackendPoolConfig{proxy.PoolFromProto(pbTestPool("a"))},
		version: 6,
	}
	s := newProxyTestService(fake)

	resp, err := s.ListPools(context.Background(), &platformv1.ListProxyPoolsRequest{})
	if err != nil {
		t.Fatalf("ListPools: %v", err)
	}
	if len(resp.GetPools()) != 1 || resp.GetVersion() != 6 {
		t.Errorf("list = (%d pools, v%d), want (1, v6)", len(resp.GetPools()), resp.GetVersion())
	}
}

func TestProxyGRPCService_ListPools_Error(t *testing.T) {
	s := newProxyTestService(&fakeProxyService{err: context.Canceled})
	_, err := s.ListPools(context.Background(), &platformv1.ListProxyPoolsRequest{})
	requireCode(t, err, codes.Internal)
}

func TestProxyGRPCService_GetProxyConfig(t *testing.T) {
	fake := &fakeProxyService{
		routes:  []proxy.RouteConfig{proxy.RouteFromProto(pbTestRoute("web"))},
		pools:   []proxy.BackendPoolConfig{proxy.PoolFromProto(pbTestPool("pool-1"))},
		version: 11,
	}
	s := newProxyTestService(fake)

	resp, err := s.GetProxyConfig(context.Background(), &platformv1.GetProxyConfigRequest{})
	if err != nil {
		t.Fatalf("GetProxyConfig: %v", err)
	}
	if len(resp.GetRoutes()) != 1 || len(resp.GetPools()) != 1 || resp.GetVersion() != 11 {
		t.Errorf("config = (%d routes, %d pools, v%d), want (1, 1, v11)",
			len(resp.GetRoutes()), len(resp.GetPools()), resp.GetVersion())
	}
}

func TestProxyGRPCService_GetProxyConfig_Error(t *testing.T) {
	s := newProxyTestService(&fakeProxyService{err: context.Canceled})
	_, err := s.GetProxyConfig(context.Background(), &platformv1.GetProxyConfigRequest{})
	requireCode(t, err, codes.Internal)
}

func TestProxyGRPCService_GetProxyStatus(t *testing.T) {
	now := time.Now()
	fake := &fakeProxyService{statusInfo: &ProxyStatusInfo{
		Version:    3,
		RouteCount: 2,
		PoolCount:  1,
		UpdatedAt:  now,
	}}
	s := newProxyTestService(fake)

	resp, err := s.GetProxyStatus(context.Background(), &platformv1.GetProxyStatusRequest{})
	if err != nil {
		t.Fatalf("GetProxyStatus: %v", err)
	}
	if resp.GetVersion() != 3 || resp.GetRouteCount() != 2 || resp.GetPoolCount() != 1 {
		t.Errorf("status = %+v, want v3 / 2 routes / 1 pool", resp)
	}
	if resp.GetUpdatedAt() != now.Unix() {
		t.Errorf("updated at = %d, want %d", resp.GetUpdatedAt(), now.Unix())
	}
}

func TestProxyGRPCService_GetProxyStatus_ZeroTime(t *testing.T) {
	s := newProxyTestService(&fakeProxyService{statusInfo: &ProxyStatusInfo{}})
	resp, err := s.GetProxyStatus(context.Background(), &platformv1.GetProxyStatusRequest{})
	if err != nil {
		t.Fatalf("GetProxyStatus: %v", err)
	}
	if resp.GetUpdatedAt() != 0 {
		t.Errorf("updated at = %d, want 0 for zero time", resp.GetUpdatedAt())
	}
}

func TestProxyGRPCService_ReloadProxyConfig(t *testing.T) {
	s := newProxyTestService(&fakeProxyService{version: 12})
	resp, err := s.ReloadProxyConfig(context.Background(), &platformv1.ReloadProxyConfigRequest{})
	if err != nil {
		t.Fatalf("ReloadProxyConfig: %v", err)
	}
	if resp.GetVersion() != 12 {
		t.Errorf("version = %d, want 12", resp.GetVersion())
	}
}

func TestProxyGRPCService_ReloadProxyConfig_Error(t *testing.T) {
	s := newProxyTestService(&fakeProxyService{err: context.Canceled})
	_, err := s.ReloadProxyConfig(context.Background(), &platformv1.ReloadProxyConfigRequest{})
	requireCode(t, err, codes.Internal)
}

func TestProxyGRPCService_GetZoneMatrix(t *testing.T) {
	fake := &fakeProxyService{matrix: &ProxyZoneMatrixInfo{
		Zones: []string{"provisioning", "control-plane"},
		Pairs: []ProxyZonePairInfo{
			{From: "provisioning", To: "control-plane", Services: []string{"dns"}},
		},
	}}
	s := newProxyTestService(fake)

	resp, err := s.GetZoneMatrix(context.Background(), &platformv1.GetProxyZoneMatrixRequest{})
	if err != nil {
		t.Fatalf("GetZoneMatrix: %v", err)
	}
	if len(resp.GetZones()) != 2 || len(resp.GetPairs()) != 1 {
		t.Fatalf("matrix = (%d zones, %d pairs), want (2, 1)", len(resp.GetZones()), len(resp.GetPairs()))
	}
	pair := resp.GetPairs()[0]
	if pair.GetFrom() != "provisioning" || pair.GetTo() != "control-plane" || len(pair.GetServices()) != 1 {
		t.Errorf("pair = %+v, want provisioning->control-plane [dns]", pair)
	}
}

func TestProxyGRPCService_GetZoneMatrix_Unavailable(t *testing.T) {
	s := newProxyTestService(&fakeProxyService{err: ErrProxyZoneMatrixUnavailable{}})
	_, err := s.GetZoneMatrix(context.Background(), &platformv1.GetProxyZoneMatrixRequest{})
	requireCode(t, err, codes.Unavailable)
}

func TestProxyGRPCService_ValidationErrorMapsInvalidArgument(t *testing.T) {
	s := newProxyTestService(&fakeProxyService{err: &proxy.ConfigError{
		Kind: "route", ID: "web", Err: proxy.ErrInvalidPathPrefix,
	}})
	_, err := s.CreateRoute(context.Background(), &platformv1.CreateProxyRouteRequest{Route: pbTestRoute("web")})
	requireCode(t, err, codes.InvalidArgument)
}
