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
	"io"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/overlay"
)

// overlayTestApp is an App with a validated environment-4 SDN section.
func overlayTestApp(t *testing.T) *app.App {
	t.Helper()
	a := &app.App{
		Hostname: "cp-01",
		SDNConfig: &sdn.Config{
			Enabled:     true,
			Environment: &netplan.Environment{ID: 4},
			OVS:         &sdn.OVSConfig{Socket: "/var/run/openvswitch/db.sock", Bridge: "br-fabric"},
			Overlay:     &sdn.OverlayConfig{Enabled: true},
		},
	}
	if err := a.SDNConfig.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	return a
}

// TestBuildOverlayController_EnvironmentAndBridge wires the plan's
// environment and the br-int integration bridge, never the trunk bridge.
func TestBuildOverlayController_EnvironmentAndBridge(t *testing.T) {
	logger := logging.NewLoggerWithFormat(slog.LevelError, logging.FormatJSON, io.Discard)
	ctrl, err := buildOverlayController(context.Background(), overlayTestApp(t), "", logger)
	if err != nil {
		t.Fatalf("buildOverlayController: %v", err)
	}
	t.Cleanup(func() { _ = ctrl.Stop(context.Background()) })

	cfg := &overlay.VNIConfig{}
	if err := ctrl.AddVNI(context.Background(), cfg); err != nil {
		t.Fatalf("AddVNI: %v", err)
	}
	if cfg.VNI != 400001 {
		t.Fatalf("derived VNI %d, want 400001 (environment 4)", cfg.VNI)
	}
}

// TestBuildOverlayController_NoPlanNeedsExplicitVNIs starts without an
// environment; a derived VNI is then refused.
func TestBuildOverlayController_NoPlanNeedsExplicitVNIs(t *testing.T) {
	logger := logging.NewLoggerWithFormat(slog.LevelError, logging.FormatJSON, io.Discard)
	a := &app.App{Hostname: "cp-01", SDNConfig: &sdn.Config{Overlay: &sdn.OverlayConfig{}}}
	ctrl, err := buildOverlayController(context.Background(), a, "", logger)
	if err != nil {
		t.Fatalf("buildOverlayController: %v", err)
	}
	t.Cleanup(func() { _ = ctrl.Stop(context.Background()) })
	if err := ctrl.AddVNI(context.Background(), &overlay.VNIConfig{}); err == nil {
		t.Fatal("deriving a VNI without an environment must fail")
	}
}
