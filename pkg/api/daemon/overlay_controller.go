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
	"net/netip"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/overlay"
)

// buildOverlayController constructs and starts the overlay controller from App
// configuration. The controller config is derived as follows:
//
//   - NodeID: App.Hostname (unique per node).
//   - VTEPIP: App.PublicIPv4; falls back to 127.0.0.1 when nil (test / loopback nodes).
//   - UnderlayInterface: SDNConfig.Overlay.UnderlayInterface; defaults to "lo".
//   - BridgeName: SDNConfig.OVS.Bridge; falls back to the overlay default "br-overlay".
//   - OVSSocketPath: the configured path; empty if OVS is not available.
//   - VXLANPort: SDNConfig.Overlay.VXLANPort; defaults applied by ApplyDefaults.
//
// The controller is started synchronously. Start() only registers the local VTEP
// in memory and launches lightweight background goroutines, so it does not block
// daemon startup.
func buildOverlayController(ctx context.Context, a *app.App, ovsSocketPath string, logger *logging.Logger) (*overlay.Controller, error) {
	cfg := &overlay.Config{
		NodeID:       a.Hostname,
		StateBackend: overlay.DefaultStateBackend,
	}

	// VTEP IP: use the node's public IPv4, fall back to loopback for test nodes.
	if a.PublicIPv4 != nil {
		if addr, err := netip.ParseAddr(a.PublicIPv4.String()); err == nil {
			cfg.VTEPIP = addr
		}
	}
	if !cfg.VTEPIP.IsValid() || cfg.VTEPIP.IsUnspecified() {
		cfg.VTEPIP = netip.MustParseAddr("127.0.0.1")
	}

	// Underlay interface: from overlay config, default "lo".
	underlayIface := "lo"
	if a.SDNConfig.Overlay.UnderlayInterface != "" {
		underlayIface = a.SDNConfig.Overlay.UnderlayInterface
	}
	cfg.UnderlayInterface = underlayIface

	// VXLAN port from overlay config (ApplyDefaults fills in 4789 when zero).
	cfg.VXLANPort = a.SDNConfig.Overlay.VXLANPort

	// Bridge name from OVS config; overlay default applied by ApplyDefaults.
	if a.SDNConfig.OVS != nil && a.SDNConfig.OVS.Bridge != "" {
		cfg.BridgeName = a.SDNConfig.OVS.Bridge
	}

	// OVS socket: wired when available; controller health-checks log a warning
	// when nil but the in-memory state path remains fully operational.
	cfg.OVSSocketPath = ovsSocketPath

	// ApplyDefaults fills MTU, VXLANPort (4789), VNIBase, BridgeName
	// (br-overlay), StateBackend (memory), intervals.
	cfg.ApplyDefaults()

	ctrl, err := overlay.New(cfg)
	if err != nil {
		return nil, err
	}

	if err := ctrl.Start(ctx); err != nil {
		return nil, err
	}

	logger.Info("overlay controller started",
		"node_id", cfg.NodeID,
		"vtep_ip", cfg.VTEPIP,
		"underlay_iface", cfg.UnderlayInterface,
		"bridge", cfg.BridgeName,
		"vxlan_port", cfg.VXLANPort)

	return ctrl, nil
}
