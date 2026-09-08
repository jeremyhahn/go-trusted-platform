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

package gateway

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
)

// unhealthyTestHandler is a ServiceHandler whose Health always fails.
type unhealthyTestHandler struct {
	name   string
	active bool
}

func (h *unhealthyTestHandler) Name() string                    { return h.name }
func (h *unhealthyTestHandler) Start(ctx context.Context) error { h.active = true; return nil }
func (h *unhealthyTestHandler) Stop(ctx context.Context) error  { h.active = false; return nil }
func (h *unhealthyTestHandler) IsActive() bool                  { return h.active }
func (h *unhealthyTestHandler) Health() error {
	return errors.New("induced failure")
}

func TestSnapshotRunningGateway(t *testing.T) {
	cfg := validConfig()
	cfg.BGP = &bgp.BGPConfig{
		ASN:      65001,
		RouterID: netip.MustParseAddr("10.0.0.1"),
	}
	cfg.Host = &HostRuntime{BGPServer: &fakeBGPServer{}}
	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	if err := gw.RegisterServiceHandler(&registeredTestHandler{name: ServicePXE}); err != nil {
		t.Fatalf("RegisterServiceHandler: %v", err)
	}
	gw.SetNodeMetrics(validNodeMetrics())
	if err := gw.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() {
		if err := gw.Stop(context.Background()); err != nil {
			t.Fatalf("Stop: %v", err)
		}
	}()

	snap := gw.Snapshot()
	if snap.GatewayID != cfg.ID {
		t.Fatalf("GatewayID = %q, want %q", snap.GatewayID, cfg.ID)
	}
	if snap.Health.Status != healthStatusHealthy {
		t.Fatalf("Health.Status = %q, want healthy", snap.Health.Status)
	}
	if snap.Health.Components[ServicePXE] != componentHealthy {
		t.Fatalf("pxe component = %q, want healthy", snap.Health.Components[ServicePXE])
	}
	if !strings.Contains(snap.Mode, ServicePXE) {
		t.Fatalf("Mode = %q, want it to contain %q", snap.Mode, ServicePXE)
	}
	if snap.PXE.Status != "running" {
		t.Fatalf("PXE.Status = %q, want running", snap.PXE.Status)
	}
	if snap.DHCP.Status != "stopped" {
		t.Fatalf("DHCP.Status = %q, want stopped", snap.DHCP.Status)
	}
	if snap.BGP.LocalASN != 65001 || snap.BGP.RouterID != "10.0.0.1" {
		t.Fatalf("BGP state = %+v", snap.BGP)
	}
	if snap.Annotations["state"] == "" || snap.Annotations["uptime"] == "" {
		t.Fatalf("annotations missing: %+v", snap.Annotations)
	}
}

func TestSnapshotStoppedGateway(t *testing.T) {
	gw, err := NewGateway(validConfig())
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}

	snap := gw.Snapshot()
	if snap.Health.Status != healthStatusUnhealthy {
		t.Fatalf("Health.Status = %q, want unhealthy", snap.Health.Status)
	}
	if snap.PXE.Status != "stopped" || snap.DHCP.Status != "stopped" {
		t.Fatalf("PXE/DHCP status = %q/%q, want stopped", snap.PXE.Status, snap.DHCP.Status)
	}
	if snap.BGP.LocalASN != 0 || snap.BGP.RouterID != "" {
		t.Fatalf("BGP must be zero without a bgp section: %+v", snap.BGP)
	}
	if snap.Mode != "" {
		t.Fatalf("Mode = %q, want empty with no active services", snap.Mode)
	}
}

func TestSnapshotDegradedGateway(t *testing.T) {
	gw, err := NewGateway(validConfig())
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	if err := gw.RegisterServiceHandler(&unhealthyTestHandler{name: ServiceProxy}); err != nil {
		t.Fatalf("RegisterServiceHandler: %v", err)
	}
	gw.SetNodeMetrics(validNodeMetrics())
	if err := gw.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() {
		if err := gw.Stop(context.Background()); err != nil {
			t.Fatalf("Stop: %v", err)
		}
	}()

	snap := gw.Snapshot()
	if snap.Health.Status != healthStatusDegraded {
		t.Fatalf("Health.Status = %q, want degraded", snap.Health.Status)
	}
	if snap.Health.Components[ServiceProxy] != componentUnhealthy {
		t.Fatalf("proxy component = %q, want unhealthy", snap.Health.Components[ServiceProxy])
	}
}
