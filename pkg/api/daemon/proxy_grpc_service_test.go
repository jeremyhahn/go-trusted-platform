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
	"context"
	"errors"
	"testing"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/proxy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// newTestZoneService returns a zone service seeded with the built-in zones.
func newTestZoneService(t *testing.T) gateway.ZoneService {
	t.Helper()
	zs, err := gateway.NewZoneService(nil, nil)
	if err != nil {
		t.Fatalf("NewZoneService: %v", err)
	}
	return zs
}

func TestProxyStoreService_ErrorMapping(t *testing.T) {
	ctx := context.Background()
	svc := newProxyStoreService(NewProxyStore(), nil)

	// Route not found maps to the grpc-package typed error.
	_, err := svc.Route(ctx, "ghost")
	var routeNotFound grpcapi.ErrProxyRouteNotFound
	if !errors.As(err, &routeNotFound) || routeNotFound.ID != "ghost" {
		t.Fatalf("err = %v, want grpcapi.ErrProxyRouteNotFound{ghost}", err)
	}

	// Pool not found maps likewise.
	_, err = svc.Pool(ctx, "ghost")
	var poolNotFound grpcapi.ErrProxyPoolNotFound
	if !errors.As(err, &poolNotFound) {
		t.Fatalf("err = %v, want grpcapi.ErrProxyPoolNotFound", err)
	}

	// Duplicate pool maps to exists.
	if _, _, err := svc.CreatePool(ctx, testPool("p1")); err != nil {
		t.Fatalf("CreatePool: %v", err)
	}
	_, _, err = svc.CreatePool(ctx, testPool("p1"))
	var poolExists grpcapi.ErrProxyPoolExists
	if !errors.As(err, &poolExists) {
		t.Fatalf("err = %v, want grpcapi.ErrProxyPoolExists", err)
	}

	// Duplicate route maps to exists.
	if _, _, err := svc.CreateRoute(ctx, testRoute("r1", "p1")); err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}
	_, _, err = svc.CreateRoute(ctx, testRoute("r1", "p1"))
	var routeExists grpcapi.ErrProxyRouteExists
	if !errors.As(err, &routeExists) {
		t.Fatalf("err = %v, want grpcapi.ErrProxyRouteExists", err)
	}

	// In-use pool delete maps to in-use with route references.
	_, err = svc.DeletePool(ctx, "p1")
	var inUse grpcapi.ErrProxyPoolInUse
	if !errors.As(err, &inUse) || len(inUse.Routes) != 1 {
		t.Fatalf("err = %v, want grpcapi.ErrProxyPoolInUse with one route", err)
	}

	// Update of missing route / pool map to not found.
	if _, _, err := svc.UpdateRoute(ctx, testRoute("ghost", "p1")); !errors.As(err, &routeNotFound) {
		t.Fatalf("UpdateRoute err = %v, want grpcapi.ErrProxyRouteNotFound", err)
	}
	if _, _, err := svc.UpdatePool(ctx, testPool("ghost")); !errors.As(err, &poolNotFound) {
		t.Fatalf("UpdatePool err = %v, want grpcapi.ErrProxyPoolNotFound", err)
	}
	if _, err := svc.DeleteRoute(ctx, "ghost"); !errors.As(err, &routeNotFound) {
		t.Fatalf("DeleteRoute err = %v, want grpcapi.ErrProxyRouteNotFound", err)
	}

	// Validation errors pass through unchanged.
	_, _, err = svc.CreateRoute(ctx, testRoute("r2", "missing-pool"))
	if !errors.Is(err, proxy.ErrUnknownPoolID) {
		t.Fatalf("err = %v, want wrapped proxy.ErrUnknownPoolID", err)
	}
}

func TestProxyStoreService_PassThroughOperations(t *testing.T) {
	ctx := context.Background()
	svc := newProxyStoreService(NewProxyStore(), nil)

	if _, _, err := svc.CreatePool(ctx, testPool("p1")); err != nil {
		t.Fatalf("CreatePool: %v", err)
	}
	if _, _, err := svc.CreateRoute(ctx, testRoute("r1", "p1")); err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}

	routes, version, err := svc.Routes(ctx)
	if err != nil || len(routes) != 1 || version != 2 {
		t.Fatalf("Routes = (%d, v%d, %v), want (1, v2, nil)", len(routes), version, err)
	}
	pools, _, err := svc.Pools(ctx)
	if err != nil || len(pools) != 1 {
		t.Fatalf("Pools = (%d, %v), want (1, nil)", len(pools), err)
	}
	r, p, v, err := svc.Snapshot(ctx)
	if err != nil || len(r) != 1 || len(p) != 1 || v != 2 {
		t.Fatalf("Snapshot = (%d, %d, v%d, %v), want (1, 1, v2, nil)", len(r), len(p), v, err)
	}
	st, err := svc.Status(ctx)
	if err != nil || st.Version != 2 || st.RouteCount != 1 || st.PoolCount != 1 {
		t.Fatalf("Status = (%+v, %v), want v2/1/1", st, err)
	}
	newVersion, err := svc.Reload(ctx)
	if err != nil || newVersion != 3 {
		t.Fatalf("Reload = (v%d, %v), want (v3, nil)", newVersion, err)
	}
}

func TestProxyStoreService_ZoneMatrix(t *testing.T) {
	svc := newProxyStoreService(NewProxyStore(), newTestZoneService(t))

	matrix, err := svc.ZoneMatrix(context.Background())
	if err != nil {
		t.Fatalf("ZoneMatrix: %v", err)
	}
	if len(matrix.Zones) == 0 {
		t.Fatal("expected built-in zones, got none")
	}
	// Zone names must be sorted.
	for i := 1; i < len(matrix.Zones); i++ {
		if matrix.Zones[i-1] >= matrix.Zones[i] {
			t.Fatalf("zones not sorted: %v", matrix.Zones)
		}
	}
	// Non-isolated zones allow intra-zone traffic, so the matrix must
	// contain at least one (z, z) pair.
	foundSelf := false
	for _, pair := range matrix.Pairs {
		if pair.From == pair.To {
			foundSelf = true
			break
		}
	}
	if !foundSelf {
		t.Errorf("expected at least one intra-zone allow pair, pairs = %v", matrix.Pairs)
	}
}

func TestProxyStoreService_ZoneMatrix_NoZoneService(t *testing.T) {
	svc := newProxyStoreService(NewProxyStore(), nil)
	_, err := svc.ZoneMatrix(context.Background())
	var unavailable grpcapi.ErrProxyZoneMatrixUnavailable
	if !errors.As(err, &unavailable) {
		t.Fatalf("err = %v, want grpcapi.ErrProxyZoneMatrixUnavailable", err)
	}
}

func TestNewProxyGRPCService_EndToEnd(t *testing.T) {
	ctx := context.Background()
	svc := NewProxyGRPCService(nil, newTestZoneService(t))

	// Create a pool then a route through the full gRPC surface.
	poolResp, err := svc.CreatePool(ctx, &platformv1.CreateProxyPoolRequest{
		Pool: &platformv1.ProxyPool{
			Id: "web-pool",
			Backends: []*platformv1.ProxyBackend{
				{Url: "https://10.0.0.10:8443", Weight: 1},
			},
		},
	})
	if err != nil {
		t.Fatalf("CreatePool: %v", err)
	}
	if poolResp.GetVersion() != 1 {
		t.Errorf("pool version = %d, want 1", poolResp.GetVersion())
	}

	routeResp, err := svc.CreateRoute(ctx, &platformv1.CreateProxyRouteRequest{
		Route: &platformv1.ProxyRoute{
			Id:         "web",
			PathPrefix: "/",
			PoolId:     "web-pool",
			Auth:       &platformv1.ProxyAuthRequirements{Mode: proxy.AuthModePublic},
		},
	})
	if err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}
	if routeResp.GetVersion() != 2 {
		t.Errorf("route version = %d, want 2", routeResp.GetVersion())
	}

	// Deleting the in-use pool must be denied with FailedPrecondition.
	_, err = svc.DeletePool(ctx, &platformv1.DeleteProxyPoolRequest{Id: "web-pool"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("in-use delete code = %v, want FailedPrecondition", status.Code(err))
	}

	// Full config snapshot.
	cfg, err := svc.GetProxyConfig(ctx, &platformv1.GetProxyConfigRequest{})
	if err != nil {
		t.Fatalf("GetProxyConfig: %v", err)
	}
	if len(cfg.GetRoutes()) != 1 || len(cfg.GetPools()) != 1 || cfg.GetVersion() != 2 {
		t.Errorf("config = (%d routes, %d pools, v%d), want (1, 1, v2)",
			len(cfg.GetRoutes()), len(cfg.GetPools()), cfg.GetVersion())
	}

	// Reload bumps the version.
	reload, err := svc.ReloadProxyConfig(ctx, &platformv1.ReloadProxyConfigRequest{})
	if err != nil {
		t.Fatalf("ReloadProxyConfig: %v", err)
	}
	if reload.GetVersion() != 3 {
		t.Errorf("reload version = %d, want 3", reload.GetVersion())
	}

	// Zone matrix is served from the wired zone service.
	matrix, err := svc.GetZoneMatrix(ctx, &platformv1.GetProxyZoneMatrixRequest{})
	if err != nil {
		t.Fatalf("GetZoneMatrix: %v", err)
	}
	if len(matrix.GetZones()) == 0 {
		t.Error("expected built-in zones over gRPC surface")
	}
}
