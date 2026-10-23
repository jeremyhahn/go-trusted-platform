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

package proxy

import (
	"testing"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func TestProtoConverters_RoundTrip(t *testing.T) {
	route := RouteConfig{
		ID:         "web",
		Hosts:      []string{"example.com"},
		PathPrefix: "/api",
		PoolID:     "pool-1",
		Auth: AuthRequirements{
			Mode:               AuthModeMTLS,
			RequireIDevID:      true,
			AllowedZones:       []string{"control-plane"},
			BackendZone:        "internal",
			RequireAttestation: true,
			AttestationMaxAge:  5 * time.Minute,
			RequiredScopes:     []string{"proxy:write"},
			OPAPolicy:          "policies/p.rego",
			TokenZone:          "edge",
		},
		StripPrefix:    true,
		PreserveHost:   true,
		PassthroughTCP: true,
	}
	back := RouteFromProto(RouteToProto(route))
	if back.ID != route.ID ||
		back.PathPrefix != route.PathPrefix ||
		back.PoolID != route.PoolID ||
		back.StripPrefix != route.StripPrefix ||
		back.PreserveHost != route.PreserveHost ||
		back.PassthroughTCP != route.PassthroughTCP ||
		back.Auth.Mode != route.Auth.Mode ||
		back.Auth.RequireIDevID != route.Auth.RequireIDevID ||
		back.Auth.AttestationMaxAge != route.Auth.AttestationMaxAge ||
		back.Auth.OPAPolicy != route.Auth.OPAPolicy ||
		back.Auth.TokenZone != route.Auth.TokenZone ||
		len(back.Auth.AllowedZones) != 1 {
		t.Errorf("route round trip mismatch:\n got %+v\nwant %+v", back, route)
	}

	pool := BackendPoolConfig{
		ID: "pool-1",
		Backends: []BackendConfig{
			{URL: "https://b:8443", Weight: 3},
		},
		Balancer: "round-robin",
		TLS: BackendTLSConfig{
			TrustClass:     "internal",
			MTLSClientCert: true,
		},
		MaxIdleConnsPerHost: 32,
		IdleConnTimeout:     90 * time.Second,
	}
	backPool := PoolFromProto(PoolToProto(pool))
	if backPool.ID != pool.ID ||
		backPool.Balancer != pool.Balancer ||
		backPool.MaxIdleConnsPerHost != pool.MaxIdleConnsPerHost ||
		backPool.IdleConnTimeout != pool.IdleConnTimeout ||
		backPool.TLS != pool.TLS ||
		len(backPool.Backends) != 1 ||
		backPool.Backends[0] != pool.Backends[0] {
		t.Errorf("pool round trip mismatch:\n got %+v\nwant %+v", backPool, pool)
	}
}

func TestProtoConverters_NilInputs(t *testing.T) {
	if got := RouteFromProto(nil); got.ID != "" {
		t.Errorf("RouteFromProto(nil) = %+v, want zero", got)
	}
	if got := RouteFromProto(&platformv1.ProxyRoute{Id: "web"}); got.Auth.Mode != "" {
		t.Errorf("route without auth = %+v, want zero auth", got.Auth)
	}
	if got := PoolFromProto(nil); got.ID != "" {
		t.Errorf("PoolFromProto(nil) = %+v, want zero", got)
	}
	if got := PoolFromProto(&platformv1.ProxyPool{Id: "p"}); got.TLS != (BackendTLSConfig{}) {
		t.Errorf("pool without TLS = %+v, want zero TLS", got.TLS)
	}
	routes, pools, version := ConfigFromProto(nil)
	if routes != nil || pools != nil || version != 0 {
		t.Errorf("ConfigFromProto(nil) = (%v, %v, %d), want (nil, nil, 0)", routes, pools, version)
	}
}

func TestConfigFromProto(t *testing.T) {
	resp := &platformv1.GetProxyConfigResponse{
		Routes:  []*platformv1.ProxyRoute{{Id: "web", PoolId: "p"}},
		Pools:   []*platformv1.ProxyPool{{Id: "p"}},
		Version: 42,
	}
	routes, pools, version := ConfigFromProto(resp)
	if len(routes) != 1 || routes[0].ID != "web" || routes[0].PoolID != "p" {
		t.Errorf("routes = %+v, want one route web -> p", routes)
	}
	if len(pools) != 1 || pools[0].ID != "p" {
		t.Errorf("pools = %+v, want one pool p", pools)
	}
	if version != 42 {
		t.Errorf("version = %d, want 42", version)
	}
}
