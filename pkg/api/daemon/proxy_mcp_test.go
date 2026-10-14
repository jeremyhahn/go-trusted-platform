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

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// newProxyMCPProvider returns an MCP service provider wired with a live
// proxy service (empty store, built-in zone service).
func newProxyMCPProvider(t *testing.T) *MCPServiceProvider {
	t.Helper()
	return NewMCPServiceProvider(&MCPServiceProviderConfig{
		ProxyService: NewProxyGRPCServiceWithStore(nil, NewProxyStore(), newTestZoneService(t)),
	})
}

func TestMCPServiceProvider_ProxyLifecycle(t *testing.T) {
	ctx := context.Background()
	p := newProxyMCPProvider(t)

	// Pool create via protojson argument map.
	poolResult, err := p.ProxyPoolCreate(ctx, map[string]interface{}{
		"pool": map[string]interface{}{
			"id": "web-pool",
			"backends": []interface{}{
				map[string]interface{}{"url": "https://10.0.0.10:8443", "weight": 1},
			},
		},
	})
	if err != nil {
		t.Fatalf("ProxyPoolCreate: %v", err)
	}
	poolResp, ok := poolResult.(*platformv1.CreateProxyPoolResponse)
	if !ok || poolResp.GetPool().GetId() != "web-pool" {
		t.Fatalf("pool result = %#v, want CreateProxyPoolResponse{web-pool}", poolResult)
	}

	// Route create referencing the pool.
	routeResult, err := p.ProxyRouteCreate(ctx, map[string]interface{}{
		"route": map[string]interface{}{
			"id":          "web",
			"path_prefix": "/",
			"pool_id":     "web-pool",
			"auth":        map[string]interface{}{"mode": "public"},
		},
	})
	if err != nil {
		t.Fatalf("ProxyRouteCreate: %v", err)
	}
	routeResp, ok := routeResult.(*platformv1.CreateProxyRouteResponse)
	if !ok || routeResp.GetVersion() != 2 {
		t.Fatalf("route result = %#v, want version 2", routeResult)
	}

	// Get / list / update / config / status.
	if _, err := p.ProxyRouteGet(ctx, "web"); err != nil {
		t.Fatalf("ProxyRouteGet: %v", err)
	}
	listResult, err := p.ProxyRouteList(ctx)
	if err != nil {
		t.Fatalf("ProxyRouteList: %v", err)
	}
	if resp := listResult.(*platformv1.ListProxyRoutesResponse); len(resp.GetRoutes()) != 1 {
		t.Errorf("route list = %d entries, want 1", len(resp.GetRoutes()))
	}
	if _, err := p.ProxyRouteUpdate(ctx, map[string]interface{}{
		"id": "web",
		"route": map[string]interface{}{
			"path_prefix": "/app",
			"pool_id":     "web-pool",
			"auth":        map[string]interface{}{"mode": "public"},
		},
	}); err != nil {
		t.Fatalf("ProxyRouteUpdate: %v", err)
	}
	if _, err := p.ProxyPoolGet(ctx, "web-pool"); err != nil {
		t.Fatalf("ProxyPoolGet: %v", err)
	}
	if _, err := p.ProxyPoolUpdate(ctx, map[string]interface{}{
		"id": "web-pool",
		"pool": map[string]interface{}{
			"backends": []interface{}{
				map[string]interface{}{"url": "https://10.0.0.11:8443"},
			},
		},
	}); err != nil {
		t.Fatalf("ProxyPoolUpdate: %v", err)
	}
	if _, err := p.ProxyPoolList(ctx); err != nil {
		t.Fatalf("ProxyPoolList: %v", err)
	}
	configResult, err := p.ProxyConfig(ctx)
	if err != nil {
		t.Fatalf("ProxyConfig: %v", err)
	}
	if resp := configResult.(*platformv1.GetProxyConfigResponse); len(resp.GetRoutes()) != 1 || len(resp.GetPools()) != 1 {
		t.Errorf("config = (%d routes, %d pools), want (1, 1)", len(resp.GetRoutes()), len(resp.GetPools()))
	}
	if _, err := p.ProxyStatus(ctx); err != nil {
		t.Fatalf("ProxyStatus: %v", err)
	}
	if _, err := p.ProxyConfigReload(ctx); err != nil {
		t.Fatalf("ProxyConfigReload: %v", err)
	}
	matrixResult, err := p.ProxyZoneMatrix(ctx)
	if err != nil {
		t.Fatalf("ProxyZoneMatrix: %v", err)
	}
	if resp := matrixResult.(*platformv1.GetProxyZoneMatrixResponse); len(resp.GetZones()) == 0 {
		t.Error("zone matrix has no zones")
	}

	// In-use pool delete surfaces the gRPC FailedPrecondition error.
	if _, err := p.ProxyPoolDelete(ctx, "web-pool"); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("in-use delete code = %v, want FailedPrecondition", status.Code(err))
	}

	// Route delete then pool delete succeed.
	if _, err := p.ProxyRouteDelete(ctx, "web"); err != nil {
		t.Fatalf("ProxyRouteDelete: %v", err)
	}
	if _, err := p.ProxyPoolDelete(ctx, "web-pool"); err != nil {
		t.Fatalf("ProxyPoolDelete: %v", err)
	}
}

func TestMCPServiceProvider_Proxy_InvalidArgs(t *testing.T) {
	ctx := context.Background()
	p := newProxyMCPProvider(t)

	// Argument maps that don't decode into the protobuf request are
	// rejected with the typed invalid-args error.
	_, err := p.ProxyRouteCreate(ctx, map[string]interface{}{"route": "not-an-object"})
	var invalid ErrMCPProxyInvalidArgs
	if !errors.As(err, &invalid) {
		t.Fatalf("err = %v, want ErrMCPProxyInvalidArgs", err)
	}
	if _, err := p.ProxyPoolUpdate(ctx, map[string]interface{}{"pool": 42}); !errors.As(err, &invalid) {
		t.Fatalf("err = %v, want ErrMCPProxyInvalidArgs", err)
	}
}

func TestMCPServiceProvider_Proxy_NotConfigured(t *testing.T) {
	ctx := context.Background()
	p := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	var notConfigured ErrMCPProxyNotConfigured
	if _, err := p.ProxyRouteList(ctx); !errors.As(err, &notConfigured) {
		t.Fatalf("ProxyRouteList err = %v, want ErrMCPProxyNotConfigured", err)
	}
	if _, err := p.ProxyRouteCreate(ctx, map[string]interface{}{}); !errors.As(err, &notConfigured) {
		t.Fatalf("ProxyRouteCreate err = %v, want ErrMCPProxyNotConfigured", err)
	}
	if _, err := p.ProxyRouteGet(ctx, "x"); !errors.As(err, &notConfigured) {
		t.Fatalf("ProxyRouteGet err = %v, want ErrMCPProxyNotConfigured", err)
	}
	if _, err := p.ProxyRouteUpdate(ctx, map[string]interface{}{}); !errors.As(err, &notConfigured) {
		t.Fatalf("ProxyRouteUpdate err = %v, want ErrMCPProxyNotConfigured", err)
	}
	if _, err := p.ProxyRouteDelete(ctx, "x"); !errors.As(err, &notConfigured) {
		t.Fatalf("ProxyRouteDelete err = %v, want ErrMCPProxyNotConfigured", err)
	}
	if _, err := p.ProxyPoolCreate(ctx, map[string]interface{}{}); !errors.As(err, &notConfigured) {
		t.Fatalf("ProxyPoolCreate err = %v, want ErrMCPProxyNotConfigured", err)
	}
	if _, err := p.ProxyPoolGet(ctx, "x"); !errors.As(err, &notConfigured) {
		t.Fatalf("ProxyPoolGet err = %v, want ErrMCPProxyNotConfigured", err)
	}
	if _, err := p.ProxyPoolUpdate(ctx, map[string]interface{}{}); !errors.As(err, &notConfigured) {
		t.Fatalf("ProxyPoolUpdate err = %v, want ErrMCPProxyNotConfigured", err)
	}
	if _, err := p.ProxyPoolDelete(ctx, "x"); !errors.As(err, &notConfigured) {
		t.Fatalf("ProxyPoolDelete err = %v, want ErrMCPProxyNotConfigured", err)
	}
	if _, err := p.ProxyPoolList(ctx); !errors.As(err, &notConfigured) {
		t.Fatalf("ProxyPoolList err = %v, want ErrMCPProxyNotConfigured", err)
	}
	if _, err := p.ProxyConfig(ctx); !errors.As(err, &notConfigured) {
		t.Fatalf("ProxyConfig err = %v, want ErrMCPProxyNotConfigured", err)
	}
	if _, err := p.ProxyStatus(ctx); !errors.As(err, &notConfigured) {
		t.Fatalf("ProxyStatus err = %v, want ErrMCPProxyNotConfigured", err)
	}
	if _, err := p.ProxyConfigReload(ctx); !errors.As(err, &notConfigured) {
		t.Fatalf("ProxyConfigReload err = %v, want ErrMCPProxyNotConfigured", err)
	}
	if _, err := p.ProxyZoneMatrix(ctx); !errors.As(err, &notConfigured) {
		t.Fatalf("ProxyZoneMatrix err = %v, want ErrMCPProxyNotConfigured", err)
	}
}
