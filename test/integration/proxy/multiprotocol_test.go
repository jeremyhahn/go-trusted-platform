// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

//go:build integration

// Package proxy provides multi-protocol integration tests for the platformd
// reverse-proxy configuration service and the gatewayd trusted
// authenticating proxy built on it.
//
// Run via:
//
//	make integration-test-proxy
package proxy

import (
	"context"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/proxy"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestProxyMultiProtocol runs the same route/pool CRUD scenario against
// every transport plus the platformctl CLI.
func TestProxyMultiProtocol(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	t.Cleanup(cancel)

	adapters := []ProxyCommands{
		NewCLIAdapter(),
		NewRESTAdapter(),
		NewGRPCAdapter(),
		NewQUICAdapter(),
		NewMCPAdapter(),
		NewUnixAdapter(),
	}

	for _, adapter := range adapters {
		adapter := adapter
		t.Run(adapter.Name(), func(t *testing.T) {
			if err := adapter.Setup(ctx); err != nil {
				t.Fatalf("setup %s: %v", adapter.Name(), err)
			}
			t.Cleanup(func() {
				if err := adapter.Teardown(); err != nil {
					t.Logf("teardown %s: %v", adapter.Name(), err)
				}
			})
			runProxyCRUDScenario(t, ctx, adapter)
		})
	}
}

// runProxyCRUDScenario exercises the full route/pool CRUD lifecycle,
// version monotonicity, status, reload, and zone matrix retrieval on one
// transport.
func runProxyCRUDScenario(t *testing.T, ctx context.Context, cmd ProxyCommands) {
	t.Helper()

	poolID := UniqueID("pool-" + cmd.Name())
	routeID := UniqueID("route-" + cmd.Name())

	callCtx, cancel := ShortContext(ctx)
	defer cancel()

	// Create pool.
	pool := &platformv1.ProxyPool{
		Id: poolID,
		Backends: []*platformv1.ProxyBackend{
			{Url: "http://127.0.0.1:18080", Weight: 1},
		},
	}
	createdPool, poolVersion, err := cmd.CreatePool(callCtx, pool)
	if err != nil {
		t.Fatalf("CreatePool: %v", err)
	}
	if createdPool.GetId() != poolID || poolVersion == 0 {
		t.Fatalf("CreatePool = %v version %d", createdPool, poolVersion)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		cmd.DeleteRoute(cleanupCtx, routeID)
		cmd.DeletePool(cleanupCtx, poolID)
	})

	// Create an mTLS zone-scoped route referencing the pool.
	route := &platformv1.ProxyRoute{
		Id:         routeID,
		PathPrefix: "/api",
		PoolId:     poolID,
		Auth: &platformv1.ProxyAuthRequirements{
			Mode:         proxy.AuthModeMTLS,
			AllowedZones: []string{"control-plane"},
		},
		StripPrefix: true,
	}
	createdRoute, routeVersion, err := cmd.CreateRoute(callCtx, route)
	if err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}
	if createdRoute.GetId() != routeID || routeVersion <= poolVersion {
		t.Fatalf("CreateRoute = %v version %d (pool version %d)", createdRoute, routeVersion, poolVersion)
	}
	if createdRoute.GetAuth().GetMode() != proxy.AuthModeMTLS {
		t.Fatalf("route auth mode = %q, want mtls", createdRoute.GetAuth().GetMode())
	}

	// Read back.
	got, err := cmd.GetRoute(callCtx, routeID)
	if err != nil {
		t.Fatalf("GetRoute: %v", err)
	}
	if got.GetPoolId() != poolID || got.GetPathPrefix() != "/api" || !got.GetStripPrefix() {
		t.Fatalf("GetRoute = %+v", got)
	}
	if len(got.GetAuth().GetAllowedZones()) != 1 || got.GetAuth().GetAllowedZones()[0] != "control-plane" {
		t.Fatalf("allowed zones = %v", got.GetAuth().GetAllowedZones())
	}
	gotPool, err := cmd.GetPool(callCtx, poolID)
	if err != nil {
		t.Fatalf("GetPool: %v", err)
	}
	if len(gotPool.GetBackends()) != 1 || gotPool.GetBackends()[0].GetUrl() != "http://127.0.0.1:18080" {
		t.Fatalf("GetPool = %+v", gotPool)
	}

	// List contains both.
	routes, _, err := cmd.ListRoutes(callCtx)
	if err != nil {
		t.Fatalf("ListRoutes: %v", err)
	}
	if !containsRoute(routes, routeID) {
		t.Fatalf("route %s missing from list", routeID)
	}
	pools, _, err := cmd.ListPools(callCtx)
	if err != nil {
		t.Fatalf("ListPools: %v", err)
	}
	if !containsPool(pools, poolID) {
		t.Fatalf("pool %s missing from list", poolID)
	}

	// Update route (full replace).
	route.PathPrefix = "/api/v2"
	route.Auth.AllowedZones = []string{"control-plane", "services"}
	updatedRoute, updateVersion, err := cmd.UpdateRoute(callCtx, route)
	if err != nil {
		t.Fatalf("UpdateRoute: %v", err)
	}
	if updatedRoute.GetPathPrefix() != "/api/v2" || updateVersion <= routeVersion {
		t.Fatalf("UpdateRoute = %+v version %d", updatedRoute, updateVersion)
	}

	// Update pool.
	pool.Backends = append(pool.Backends, &platformv1.ProxyBackend{Url: "http://127.0.0.1:18081", Weight: 2})
	updatedPool, _, err := cmd.UpdatePool(callCtx, pool)
	if err != nil {
		t.Fatalf("UpdatePool: %v", err)
	}
	if len(updatedPool.GetBackends()) != 2 {
		t.Fatalf("UpdatePool backends = %+v", updatedPool.GetBackends())
	}

	// Status reflects the store.
	status, err := cmd.Status(callCtx)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.GetVersion() < updateVersion {
		t.Fatalf("status version %d < update version %d", status.GetVersion(), updateVersion)
	}

	// Reload bumps the version.
	reloadVersion, err := cmd.Reload(callCtx)
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if reloadVersion <= status.GetVersion() {
		t.Fatalf("reload version %d not beyond %d", reloadVersion, status.GetVersion())
	}

	// Zone matrix is retrievable (content depends on the SDN zone config of
	// the test daemon; the call must succeed on every transport).
	if _, err := cmd.ZoneMatrix(callCtx); err != nil {
		t.Fatalf("ZoneMatrix: %v", err)
	}

	// Pool deletion is blocked while the route references it.
	if _, err := cmd.DeletePool(callCtx, poolID); err == nil {
		t.Fatal("DeletePool must fail while a route references the pool")
	}

	// Delete route then pool.
	deleteVersion, err := cmd.DeleteRoute(callCtx, routeID)
	if err != nil {
		t.Fatalf("DeleteRoute: %v", err)
	}
	if deleteVersion <= reloadVersion {
		t.Fatalf("delete version %d not beyond %d", deleteVersion, reloadVersion)
	}
	if _, err := cmd.DeletePool(callCtx, poolID); err != nil {
		t.Fatalf("DeletePool: %v", err)
	}

	// Reading a deleted route fails.
	if _, err := cmd.GetRoute(callCtx, routeID); err == nil {
		t.Fatal("GetRoute after delete must fail")
	}
}

func containsRoute(routes []*platformv1.ProxyRoute, id string) bool {
	for _, r := range routes {
		if r.GetId() == id {
			return true
		}
	}
	return false
}

func containsPool(pools []*platformv1.ProxyPool, id string) bool {
	for _, p := range pools {
		if p.GetId() == id {
			return true
		}
	}
	return false
}
