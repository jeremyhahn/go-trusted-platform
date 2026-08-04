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

package commands

import (
	"path/filepath"

	"github.com/spf13/viper"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
)

// gatewayControlPlane bundles the two halves of the CP-side gateway
// control surface — the cached telemetry store + the desired-config
// source — so the serve.go wiring code can hand them to the
// HandlerRegistry as a pair.
type gatewayControlPlane struct {
	Store      *gwstate.FileStore
	DesiredCfg *viperDesiredConfigSource
}

// initGatewayControlPlane stands up the telemetry store under
// <PlatformDir>/gateway/state and wires the Viper-backed desired-
// config source. Failures are non-fatal: the daemon continues
// without the surface and clients see the structured 503 envelope.
func initGatewayControlPlane(logger *logging.Logger, a *app.App) *gatewayControlPlane {
	if a == nil {
		return nil
	}
	root := filepath.Join(a.PlatformDir, "gateway", "state")
	store, err := gwstate.NewFileStore(root)
	if err != nil {
		logger.Warnf("gateway control plane: store unavailable: %v", err)
		return nil
	}
	logger.Info("gateway control plane wired", "state_root", root)
	return &gatewayControlPlane{
		Store:      store,
		DesiredCfg: &viperDesiredConfigSource{},
	}
}

// viperDesiredConfigSource resolves the CP-side intended config for
// a given gatewayd by reading the platform's active Viper config
// tree. The returned map mirrors the "sdn" / "gateway" sections so
// gatewayd's reload loop can apply BGP ASN, IPAM pools, PXE flags,
// etc. without round-tripping through additional storage.
//
// gatewayID is currently advisory — Phase 2.3 first-ship ships the
// same configuration to every gatewayd. Per-gateway desired-config
// overrides land when the deployment grows beyond one gateway.
type viperDesiredConfigSource struct{}

// DesiredConfig satisfies restgateway.DesiredConfigSource. The
// returned map is a snapshot of the SDN-related sections of the live
// Viper config tree at call time.
func (v *viperDesiredConfigSource) DesiredConfig(gatewayID string) (map[string]interface{}, error) {
	out := map[string]interface{}{
		"gateway_id": gatewayID,
	}
	// Surface the SDN tree (subnets, pools, VLANs, gateway role).
	if sdn := viper.Get("sdn"); sdn != nil {
		out["sdn"] = sdn
	}
	// Gateway-specific config (BGP ASN, peer IPs, PXE flag, etc.)
	// lives under "gateway" if defined.
	if gw := viper.Get("gateway"); gw != nil {
		out["gateway"] = gw
	}
	// Surface DNS so gatewayd's resolver bootstrapping has the same
	// view of upstream + delegated zones the CP uses.
	if dns := viper.Get("dns"); dns != nil {
		out["dns"] = dns
	}
	return out, nil
}
