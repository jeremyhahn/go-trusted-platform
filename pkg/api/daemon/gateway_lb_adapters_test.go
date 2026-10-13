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
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/loadbalancer"
)

// seededLB returns a fake LB pre-populated with one VIP.
func seededLB(t *testing.T) *fakeGatewayLB {
	t.Helper()
	lb := newFakeGatewayLB()
	vip, err := (&VIPConfigSeed{}).vip()
	if err != nil {
		t.Fatalf("seed vip: %v", err)
	}
	if err := lb.AddVIP(context.Background(), vip); err != nil {
		t.Fatalf("seed AddVIP: %v", err)
	}
	return lb
}

// VIPConfigSeed builds the canonical test VIP.
type VIPConfigSeed struct{}

func (VIPConfigSeed) vip() (loadbalancer.VIP, error) {
	cfg := &rest.LBVIPRequest{
		Address:  "10.100.0.10",
		Port:     443,
		Protocol: "tcp",
		Backends: []rest.LBBackend{{Address: "10.0.1.5", Port: 8443, Weight: 2}},
	}
	backends, err := restLBBackends(cfg.Backends)
	if err != nil {
		return loadbalancer.VIP{}, err
	}
	protocol, target, err := restLBTarget(cfg.Protocol, cfg.Address, cfg.Port)
	if err != nil {
		return loadbalancer.VIP{}, err
	}
	return loadbalancer.VIP{
		Address:  target.Addr(),
		Port:     target.Port(),
		Protocol: protocol,
		Backends: backends,
	}, nil
}

// =============================================================================
// REST adapter
// =============================================================================

func TestRESTGatewayLBAdapter(t *testing.T) {
	svc := newGatewayRESTService(nil, slog.Default())
	svc.SetLoadBalancer(newFakeGatewayLB())
	ctx := context.Background()

	vip, err := svc.AddVIP(ctx, &rest.LBVIPRequest{
		Address:  "10.100.0.10",
		Port:     443,
		Protocol: "tcp",
		Backends: []rest.LBBackend{{Address: "10.0.1.5", Port: 8443, Weight: 2}},
	})
	if err != nil {
		t.Fatalf("AddVIP: %v", err)
	}
	if vip.GroupID != 0x4C420001 || vip.CTZone != 9 {
		t.Errorf("vip = %+v", vip)
	}

	got, err := svc.GetVIP(ctx, "tcp", "10.100.0.10", 443)
	if err != nil {
		t.Fatalf("GetVIP: %v", err)
	}
	if len(got.Backends) != 1 || !got.Backends[0].Healthy {
		t.Errorf("backends = %+v", got.Backends)
	}

	vips, err := svc.ListVIPs(ctx)
	if err != nil || len(vips) != 1 {
		t.Fatalf("ListVIPs = %v (%v)", vips, err)
	}

	updated, err := svc.SetVIPBackends(ctx, "tcp", "10.100.0.10", 443, []rest.LBBackend{
		{Address: "10.0.1.9", Port: 9000},
	})
	if err != nil {
		t.Fatalf("SetVIPBackends: %v", err)
	}
	if len(updated.Backends) != 1 || updated.Backends[0].Backend.Port != 9000 {
		t.Errorf("updated backends = %+v", updated.Backends)
	}

	lbStatus, err := svc.GetLBStatus(ctx)
	if err != nil {
		t.Fatalf("GetLBStatus: %v", err)
	}
	if !lbStatus.Active || lbStatus.VIPCount != 1 {
		t.Errorf("status = %+v", lbStatus)
	}

	if err := svc.RemoveVIP(ctx, "tcp", "10.100.0.10", 443); err != nil {
		t.Fatalf("RemoveVIP: %v", err)
	}
}

func TestRESTGatewayLBAdapterErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("not configured", func(t *testing.T) {
		svc := newGatewayRESTService(nil, slog.Default())
		if _, err := svc.GetLBStatus(ctx); !errors.Is(err, rest.ErrLBNotConfigured{}) {
			t.Errorf("GetLBStatus = %v", err)
		}
		if _, err := svc.ListVIPs(ctx); !errors.Is(err, rest.ErrLBNotConfigured{}) {
			t.Errorf("ListVIPs = %v", err)
		}
	})

	t.Run("error mapping", func(t *testing.T) {
		svc := newGatewayRESTService(nil, slog.Default())
		svc.SetLoadBalancer(newFakeGatewayLB())

		if _, err := svc.GetVIP(ctx, "tcp", "10.9.9.9", 1); !errors.Is(err, rest.ErrLBVIPNotFound{}) {
			t.Errorf("GetVIP unknown = %v", err)
		}
		if _, err := svc.GetVIP(ctx, "tcp", "bogus", 1); !errors.Is(err, rest.ErrLBInvalidVIP{Reason: "invalid address"}) {
			t.Errorf("GetVIP bad addr = %v", err)
		}
		if _, err := svc.AddVIP(ctx, nil); err == nil {
			t.Error("AddVIP(nil) succeeded")
		}
		if _, err := svc.AddVIP(ctx, &rest.LBVIPRequest{Address: "10.0.0.1", Protocol: "tcp"}); err == nil {
			t.Error("AddVIP zero port succeeded")
		}
	})

	t.Run("not started maps to not configured", func(t *testing.T) {
		svc := newGatewayRESTService(nil, slog.Default())
		lb := newFakeGatewayLB()
		lb.err = loadbalancer.ErrNotStarted
		svc.SetLoadBalancer(lb)
		if _, err := svc.GetLBStatus(ctx); !errors.Is(err, rest.ErrLBNotConfigured{}) {
			t.Errorf("GetLBStatus = %v", err)
		}
	})
}

// =============================================================================
// QUIC adapter
// =============================================================================

func TestQUICGatewayLBAdapter(t *testing.T) {
	adapter := newFullGatewayQUICAdapter(nil, nil, nil, nil, nil)
	adapter.SetLoadBalancer(newFakeGatewayLB())
	ctx := context.Background()

	vip, err := adapter.AddVIP(ctx, &quic.LBVIPSpec{
		Address:  "10.100.0.10",
		Port:     443,
		Protocol: "tcp",
		Backends: []*quic.LBBackendSpec{{Address: "10.0.1.5", Port: 8443, Weight: 2}},
	})
	if err != nil {
		t.Fatalf("AddVIP: %v", err)
	}
	if vip.GroupID != 0x4C420001 {
		t.Errorf("vip = %+v", vip)
	}

	got, err := adapter.GetVIP(ctx, "tcp", "10.100.0.10", 443)
	if err != nil || got.CTZone != 9 {
		t.Fatalf("GetVIP = %+v (%v)", got, err)
	}

	vips, err := adapter.ListVIPs(ctx)
	if err != nil || len(vips) != 1 {
		t.Fatalf("ListVIPs = %v (%v)", vips, err)
	}

	updated, err := adapter.SetVIPBackends(ctx, "tcp", "10.100.0.10", 443,
		[]*quic.LBBackendSpec{{Address: "10.0.1.9", Port: 9000}})
	if err != nil || len(updated.Backends) != 1 {
		t.Fatalf("SetVIPBackends = %+v (%v)", updated, err)
	}

	lbStatus, err := adapter.LBStatus(ctx)
	if err != nil || !lbStatus.Active || lbStatus.VIPCount != 1 {
		t.Fatalf("LBStatus = %+v (%v)", lbStatus, err)
	}

	if err := adapter.RemoveVIP(ctx, "tcp", "10.100.0.10", 443); err != nil {
		t.Fatalf("RemoveVIP: %v", err)
	}
}

func TestQUICGatewayLBAdapterErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("not configured", func(t *testing.T) {
		adapter := newFullGatewayQUICAdapter(nil, nil, nil, nil, nil)
		if _, err := adapter.LBStatus(ctx); !errors.Is(err, quic.ErrGatewayFeatureNotConfigured) {
			t.Errorf("LBStatus = %v", err)
		}
	})

	t.Run("error mapping", func(t *testing.T) {
		adapter := newFullGatewayQUICAdapter(nil, nil, nil, nil, nil)
		adapter.SetLoadBalancer(newFakeGatewayLB())

		if _, err := adapter.GetVIP(ctx, "tcp", "10.9.9.9", 1); !errors.Is(err, quic.ErrGatewayVIPNotFound) {
			t.Errorf("GetVIP unknown = %v", err)
		}
		if _, err := adapter.GetVIP(ctx, "tcp", "bogus", 1); !errors.Is(err, quic.ErrGatewayMissingVIPTarget) {
			t.Errorf("GetVIP bad addr = %v", err)
		}
		if _, err := adapter.AddVIP(ctx, nil); !errors.Is(err, quic.ErrGatewayMissingVIPTarget) {
			t.Errorf("AddVIP nil = %v", err)
		}
		if _, err := adapter.AddVIP(ctx, &quic.LBVIPSpec{
			Address: "10.100.0.10", Port: 443, Protocol: "tcp",
			Backends: []*quic.LBBackendSpec{{Address: "bogus", Port: 1}},
		}); !errors.Is(err, quic.ErrGatewayInvalidVIP) {
			t.Errorf("AddVIP bad backend = %v", err)
		}
	})

	t.Run("zone adapter always unavailable", func(t *testing.T) {
		adapter := newZoneGatewayAdapter(nil)
		if _, err := adapter.AddVIP(ctx, nil); !errors.Is(err, quic.ErrGatewayFeatureNotConfigured) {
			t.Errorf("AddVIP = %v", err)
		}
		if err := adapter.RemoveVIP(ctx, "tcp", "10.0.0.1", 1); !errors.Is(err, quic.ErrGatewayFeatureNotConfigured) {
			t.Errorf("RemoveVIP = %v", err)
		}
		if _, err := adapter.GetVIP(ctx, "tcp", "10.0.0.1", 1); !errors.Is(err, quic.ErrGatewayFeatureNotConfigured) {
			t.Errorf("GetVIP = %v", err)
		}
		if _, err := adapter.ListVIPs(ctx); !errors.Is(err, quic.ErrGatewayFeatureNotConfigured) {
			t.Errorf("ListVIPs = %v", err)
		}
		if _, err := adapter.SetVIPBackends(ctx, "tcp", "10.0.0.1", 1, nil); !errors.Is(err, quic.ErrGatewayFeatureNotConfigured) {
			t.Errorf("SetVIPBackends = %v", err)
		}
		if _, err := adapter.LBStatus(ctx); !errors.Is(err, quic.ErrGatewayFeatureNotConfigured) {
			t.Errorf("LBStatus = %v", err)
		}
	})
}

// =============================================================================
// MCP provider
// =============================================================================

func TestMCPGatewayLBProvider(t *testing.T) {
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})
	provider.SetGatewayLoadBalancer(seededLB(t))
	ctx := context.Background()

	got, err := provider.GatewayLBVIPGet(ctx, "tcp", "10.100.0.10", 443)
	if err != nil {
		t.Fatalf("GatewayLBVIPGet: %v", err)
	}
	if got.(*rest.LBVIPResponse).GroupID != 0x4C420001 {
		t.Errorf("vip = %+v", got)
	}

	vips, err := provider.GatewayLBVIPList(ctx)
	if err != nil || len(vips) != 1 {
		t.Fatalf("GatewayLBVIPList = %v (%v)", vips, err)
	}

	added, err := provider.GatewayLBVIPAdd(ctx, &mcp.LBVIPAddRequest{
		Address:  "10.100.0.11",
		Port:     80,
		Protocol: "tcp",
		Backends: []*mcp.LBBackendRequest{{Address: "10.0.1.7", Port: 8080}},
	})
	if err != nil || added == nil {
		t.Fatalf("GatewayLBVIPAdd = %v (%v)", added, err)
	}

	updated, err := provider.GatewayLBVIPSetBackends(ctx, "tcp", "10.100.0.11", 80,
		[]*mcp.LBBackendRequest{{Address: "10.0.1.8", Port: 8080, Weight: 3}})
	if err != nil || updated == nil {
		t.Fatalf("GatewayLBVIPSetBackends = %v (%v)", updated, err)
	}

	lbStatus, err := provider.GatewayLBStatus(ctx)
	if err != nil {
		t.Fatalf("GatewayLBStatus: %v", err)
	}
	if !lbStatus.(*rest.LBStatusResponse).Active {
		t.Errorf("status = %+v", lbStatus)
	}

	if err := provider.GatewayLBVIPRemove(ctx, "tcp", "10.100.0.11", 80); err != nil {
		t.Fatalf("GatewayLBVIPRemove: %v", err)
	}
}

func TestMCPGatewayLBProviderErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("not configured", func(t *testing.T) {
		provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})
		var unavailable ErrServiceNotAvailable
		if _, err := provider.GatewayLBStatus(ctx); !errors.As(err, &unavailable) {
			t.Errorf("GatewayLBStatus = %v", err)
		}
		if err := provider.GatewayLBVIPRemove(ctx, "tcp", "10.0.0.1", 1); !errors.As(err, &unavailable) {
			t.Errorf("GatewayLBVIPRemove = %v", err)
		}
	})

	t.Run("bad target", func(t *testing.T) {
		provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})
		provider.SetGatewayLoadBalancer(newFakeGatewayLB())
		if _, err := provider.GatewayLBVIPGet(ctx, "tcp", "bogus", 443); !errors.Is(err, mcp.ErrLBVIPTargetRequired) {
			t.Errorf("GatewayLBVIPGet = %v", err)
		}
		if _, err := provider.GatewayLBVIPAdd(ctx, nil); !errors.Is(err, mcp.ErrLBVIPTargetRequired) {
			t.Errorf("GatewayLBVIPAdd nil = %v", err)
		}
		if _, err := provider.GatewayLBVIPAdd(ctx, &mcp.LBVIPAddRequest{
			Address: "10.100.0.10", Port: 443, Protocol: "tcp",
			Backends: []*mcp.LBBackendRequest{{Address: "bogus", Port: 1}},
		}); !errors.Is(err, mcp.ErrLBBackendsRequired) {
			t.Errorf("GatewayLBVIPAdd bad backend = %v", err)
		}
	})

	t.Run("platform provider not configured", func(t *testing.T) {
		provider := &PlatformServiceProvider{}
		var unavailable ErrServiceNotAvailable
		if _, err := provider.GatewayLBStatus(ctx); !errors.As(err, &unavailable) {
			t.Errorf("GatewayLBStatus = %v", err)
		}
	})

	t.Run("platform provider configured", func(t *testing.T) {
		provider := &PlatformServiceProvider{}
		provider.SetGatewayLoadBalancer(seededLB(t))
		vips, err := provider.GatewayLBVIPList(ctx)
		if err != nil || len(vips) != 1 {
			t.Errorf("GatewayLBVIPList = %v (%v)", vips, err)
		}
	})
}
