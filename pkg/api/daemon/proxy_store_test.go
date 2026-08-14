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

	"github.com/jeremyhahn/go-trusted-platform/pkg/proxy"
)

// testPool returns a valid backend pool for store tests.
func testPool(id string) proxy.BackendPoolConfig {
	return proxy.BackendPoolConfig{
		ID: id,
		Backends: []proxy.BackendConfig{
			{URL: "https://10.0.0.10:8443", Weight: 1},
		},
	}
}

// testRoute returns a valid route for store tests referencing poolID.
func testRoute(id, poolID string) proxy.RouteConfig {
	return proxy.RouteConfig{
		ID:         id,
		Hosts:      []string{"Example.COM"},
		PathPrefix: "/",
		PoolID:     poolID,
		Auth:       proxy.AuthRequirements{Mode: proxy.AuthModePublic},
	}
}

func TestProxyStore_CreateRoute(t *testing.T) {
	ctx := context.Background()
	store := NewProxyStore()

	if _, _, err := store.CreatePool(ctx, testPool("pool-1")); err != nil {
		t.Fatalf("CreatePool: %v", err)
	}

	route, version, err := store.CreateRoute(ctx, testRoute("web", "pool-1"))
	if err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}
	if version != 2 {
		t.Errorf("version = %d, want 2", version)
	}
	// Validate normalizes hosts to lowercase in place.
	if route.Hosts[0] != "example.com" {
		t.Errorf("host = %q, want normalized %q", route.Hosts[0], "example.com")
	}
}

func TestProxyStore_CreateRoute_Duplicate(t *testing.T) {
	ctx := context.Background()
	store := NewProxyStore()

	if _, _, err := store.CreatePool(ctx, testPool("pool-1")); err != nil {
		t.Fatalf("CreatePool: %v", err)
	}
	if _, _, err := store.CreateRoute(ctx, testRoute("web", "pool-1")); err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}

	_, _, err := store.CreateRoute(ctx, testRoute("web", "pool-1"))
	var dup ErrRouteExists
	if !errors.As(err, &dup) || dup.ID != "web" {
		t.Fatalf("err = %v, want ErrRouteExists{web}", err)
	}
}

func TestProxyStore_CreateRoute_UnknownPool(t *testing.T) {
	ctx := context.Background()
	store := NewProxyStore()

	_, _, err := store.CreateRoute(ctx, testRoute("web", "missing"))
	if err == nil {
		t.Fatal("expected validation error for unknown pool")
	}
	if !errors.Is(err, proxy.ErrUnknownPoolID) {
		t.Fatalf("err = %v, want wrapped proxy.ErrUnknownPoolID", err)
	}
	// Failed mutation must not bump the version.
	status, statusErr := store.Status(ctx)
	if statusErr != nil {
		t.Fatalf("Status: %v", statusErr)
	}
	if status.Version != 0 {
		t.Errorf("version after failed create = %d, want 0", status.Version)
	}
}

func TestProxyStore_Route(t *testing.T) {
	ctx := context.Background()
	store := NewProxyStore()
	if _, _, err := store.CreatePool(ctx, testPool("pool-1")); err != nil {
		t.Fatalf("CreatePool: %v", err)
	}
	if _, _, err := store.CreateRoute(ctx, testRoute("web", "pool-1")); err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}

	route, err := store.Route(ctx, "web")
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if route.PoolID != "pool-1" {
		t.Errorf("pool id = %q, want pool-1", route.PoolID)
	}
}

func TestProxyStore_Route_NotFound(t *testing.T) {
	store := NewProxyStore()
	_, err := store.Route(context.Background(), "missing")
	var notFound ErrRouteNotFound
	if !errors.As(err, &notFound) || notFound.ID != "missing" {
		t.Fatalf("err = %v, want ErrRouteNotFound{missing}", err)
	}
}

func TestProxyStore_UpdateRoute(t *testing.T) {
	ctx := context.Background()
	store := NewProxyStore()
	if _, _, err := store.CreatePool(ctx, testPool("pool-1")); err != nil {
		t.Fatalf("CreatePool: %v", err)
	}
	if _, _, err := store.CreateRoute(ctx, testRoute("web", "pool-1")); err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}

	updated := testRoute("web", "pool-1")
	updated.PathPrefix = "/api"
	route, version, err := store.UpdateRoute(ctx, updated)
	if err != nil {
		t.Fatalf("UpdateRoute: %v", err)
	}
	if route.PathPrefix != "/api" {
		t.Errorf("path prefix = %q, want /api", route.PathPrefix)
	}
	if version != 3 {
		t.Errorf("version = %d, want 3", version)
	}
}

func TestProxyStore_UpdateRoute_NotFound(t *testing.T) {
	store := NewProxyStore()
	_, _, err := store.UpdateRoute(context.Background(), testRoute("ghost", "pool-1"))
	var notFound ErrRouteNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("err = %v, want ErrRouteNotFound", err)
	}
}

func TestProxyStore_UpdateRoute_InvalidConfig(t *testing.T) {
	ctx := context.Background()
	store := NewProxyStore()
	if _, _, err := store.CreatePool(ctx, testPool("pool-1")); err != nil {
		t.Fatalf("CreatePool: %v", err)
	}
	if _, _, err := store.CreateRoute(ctx, testRoute("web", "pool-1")); err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}

	bad := testRoute("web", "pool-1")
	bad.PathPrefix = "no-slash"
	if _, _, err := store.UpdateRoute(ctx, bad); !errors.Is(err, proxy.ErrInvalidPathPrefix) {
		t.Fatalf("err = %v, want wrapped proxy.ErrInvalidPathPrefix", err)
	}
	// The stored route must be unchanged after the failed update.
	route, err := store.Route(ctx, "web")
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if route.PathPrefix != "/" {
		t.Errorf("path prefix after failed update = %q, want /", route.PathPrefix)
	}
}

func TestProxyStore_DeleteRoute(t *testing.T) {
	ctx := context.Background()
	store := NewProxyStore()
	if _, _, err := store.CreatePool(ctx, testPool("pool-1")); err != nil {
		t.Fatalf("CreatePool: %v", err)
	}
	if _, _, err := store.CreateRoute(ctx, testRoute("web", "pool-1")); err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}

	version, err := store.DeleteRoute(ctx, "web")
	if err != nil {
		t.Fatalf("DeleteRoute: %v", err)
	}
	if version != 3 {
		t.Errorf("version = %d, want 3", version)
	}
	if _, err := store.Route(ctx, "web"); err == nil {
		t.Error("route still present after delete")
	}
}

func TestProxyStore_DeleteRoute_NotFound(t *testing.T) {
	store := NewProxyStore()
	_, err := store.DeleteRoute(context.Background(), "missing")
	var notFound ErrRouteNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("err = %v, want ErrRouteNotFound", err)
	}
}

func TestProxyStore_Routes_SortedAndVersioned(t *testing.T) {
	ctx := context.Background()
	store := NewProxyStore()
	if _, _, err := store.CreatePool(ctx, testPool("pool-1")); err != nil {
		t.Fatalf("CreatePool: %v", err)
	}
	for _, id := range []string{"zeta", "alpha", "mid"} {
		if _, _, err := store.CreateRoute(ctx, testRoute(id, "pool-1")); err != nil {
			t.Fatalf("CreateRoute(%s): %v", id, err)
		}
	}

	routes, version, err := store.Routes(ctx)
	if err != nil {
		t.Fatalf("Routes: %v", err)
	}
	if len(routes) != 3 {
		t.Fatalf("len(routes) = %d, want 3", len(routes))
	}
	if routes[0].ID != "alpha" || routes[1].ID != "mid" || routes[2].ID != "zeta" {
		t.Errorf("routes not sorted by ID: %v %v %v", routes[0].ID, routes[1].ID, routes[2].ID)
	}
	if version != 4 {
		t.Errorf("version = %d, want 4", version)
	}
}

func TestProxyStore_CreatePool_DuplicateAndInvalid(t *testing.T) {
	ctx := context.Background()
	store := NewProxyStore()

	if _, _, err := store.CreatePool(ctx, testPool("pool-1")); err != nil {
		t.Fatalf("CreatePool: %v", err)
	}

	_, _, err := store.CreatePool(ctx, testPool("pool-1"))
	var dup ErrPoolExists
	if !errors.As(err, &dup) || dup.ID != "pool-1" {
		t.Fatalf("err = %v, want ErrPoolExists{pool-1}", err)
	}

	// Pool with no backends fails pkg/proxy validation.
	if _, _, err := store.CreatePool(ctx, proxy.BackendPoolConfig{ID: "empty"}); !errors.Is(err, proxy.ErrNoBackends) {
		t.Fatalf("err = %v, want wrapped proxy.ErrNoBackends", err)
	}
}

func TestProxyStore_Pool_GetUpdateDelete(t *testing.T) {
	ctx := context.Background()
	store := NewProxyStore()
	if _, _, err := store.CreatePool(ctx, testPool("pool-1")); err != nil {
		t.Fatalf("CreatePool: %v", err)
	}

	pool, err := store.Pool(ctx, "pool-1")
	if err != nil {
		t.Fatalf("Pool: %v", err)
	}
	if len(pool.Backends) != 1 {
		t.Fatalf("backends = %d, want 1", len(pool.Backends))
	}

	updated := testPool("pool-1")
	updated.Backends = append(updated.Backends, proxy.BackendConfig{URL: "https://10.0.0.11:8443"})
	stored, version, err := store.UpdatePool(ctx, updated)
	if err != nil {
		t.Fatalf("UpdatePool: %v", err)
	}
	if len(stored.Backends) != 2 {
		t.Errorf("backends after update = %d, want 2", len(stored.Backends))
	}
	if version != 2 {
		t.Errorf("version = %d, want 2", version)
	}

	deleteVersion, err := store.DeletePool(ctx, "pool-1")
	if err != nil {
		t.Fatalf("DeletePool: %v", err)
	}
	if deleteVersion != 3 {
		t.Errorf("version = %d, want 3", deleteVersion)
	}
}

func TestProxyStore_Pool_NotFoundErrors(t *testing.T) {
	ctx := context.Background()
	store := NewProxyStore()

	var notFound ErrPoolNotFound
	if _, err := store.Pool(ctx, "ghost"); !errors.As(err, &notFound) {
		t.Fatalf("Pool err = %v, want ErrPoolNotFound", err)
	}
	if _, _, err := store.UpdatePool(ctx, testPool("ghost")); !errors.As(err, &notFound) {
		t.Fatalf("UpdatePool err = %v, want ErrPoolNotFound", err)
	}
	if _, err := store.DeletePool(ctx, "ghost"); !errors.As(err, &notFound) {
		t.Fatalf("DeletePool err = %v, want ErrPoolNotFound", err)
	}
}

func TestProxyStore_DeletePool_InUse(t *testing.T) {
	ctx := context.Background()
	store := NewProxyStore()
	if _, _, err := store.CreatePool(ctx, testPool("pool-1")); err != nil {
		t.Fatalf("CreatePool: %v", err)
	}
	if _, _, err := store.CreateRoute(ctx, testRoute("web", "pool-1")); err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}
	if _, _, err := store.CreateRoute(ctx, testRoute("api", "pool-1")); err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}

	_, err := store.DeletePool(ctx, "pool-1")
	var inUse ErrPoolInUse
	if !errors.As(err, &inUse) {
		t.Fatalf("err = %v, want ErrPoolInUse", err)
	}
	if inUse.ID != "pool-1" {
		t.Errorf("in-use pool = %q, want pool-1", inUse.ID)
	}
	if len(inUse.Routes) != 2 || inUse.Routes[0] != "api" || inUse.Routes[1] != "web" {
		t.Errorf("in-use routes = %v, want [api web]", inUse.Routes)
	}

	// Removing the routes unlocks the pool.
	if _, err := store.DeleteRoute(ctx, "web"); err != nil {
		t.Fatalf("DeleteRoute: %v", err)
	}
	if _, err := store.DeleteRoute(ctx, "api"); err != nil {
		t.Fatalf("DeleteRoute: %v", err)
	}
	if _, err := store.DeletePool(ctx, "pool-1"); err != nil {
		t.Fatalf("DeletePool after route removal: %v", err)
	}
}

func TestProxyStore_SnapshotStatusReload(t *testing.T) {
	ctx := context.Background()
	store := NewProxyStore()

	// Empty snapshot at version 0.
	routes, pools, version, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(routes) != 0 || len(pools) != 0 || version != 0 {
		t.Fatalf("empty snapshot = (%d routes, %d pools, v%d), want (0, 0, v0)", len(routes), len(pools), version)
	}

	if _, _, err := store.CreatePool(ctx, testPool("pool-1")); err != nil {
		t.Fatalf("CreatePool: %v", err)
	}
	if _, _, err := store.CreateRoute(ctx, testRoute("web", "pool-1")); err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}

	routes, pools, version, err = store.Snapshot(ctx)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(routes) != 1 || len(pools) != 1 || version != 2 {
		t.Fatalf("snapshot = (%d routes, %d pools, v%d), want (1, 1, v2)", len(routes), len(pools), version)
	}

	status, err := store.Status(ctx)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.Version != 2 || status.RouteCount != 1 || status.PoolCount != 1 {
		t.Errorf("status = %+v, want v2 / 1 route / 1 pool", status)
	}
	if status.UpdatedAt.IsZero() {
		t.Error("status.UpdatedAt is zero after mutations")
	}

	reloaded, err := store.Reload(ctx)
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if reloaded != 3 {
		t.Errorf("reload version = %d, want 3", reloaded)
	}
}

func TestProxyStore_StoredStateDoesNotAliasCaller(t *testing.T) {
	ctx := context.Background()
	store := NewProxyStore()
	if _, _, err := store.CreatePool(ctx, testPool("pool-1")); err != nil {
		t.Fatalf("CreatePool: %v", err)
	}
	route := testRoute("web", "pool-1")
	if _, _, err := store.CreateRoute(ctx, route); err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}

	// Mutating the caller's slice must not affect the stored route.
	route.Hosts[0] = "mutated.example"
	stored, err := store.Route(ctx, "web")
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if stored.Hosts[0] != "example.com" {
		t.Errorf("stored host = %q, want example.com (no aliasing)", stored.Hosts[0])
	}
}
