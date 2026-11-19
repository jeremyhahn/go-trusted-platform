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

//go:build fips

package commands

import (
	"log/slog"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/hostfw"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
)

// vpnDataPlanes is gatewayd's plane factory in a FIPS build. WireGuard is
// not a FIPS plane and the datapath builds no MASQUE plane yet, so it builds
// none and says so: the vpn process's peer RPCs keep their refusal.
func vpnDataPlanes(cfg *ServeConfig, _ *gateway.Gateway, logger *slog.Logger) ([]vpn.ManagedDataPlane, error) {
	offered := cfg.Gateway.ManagementVPN.Config.WithDefaults().DataPlanes
	logger.Warn("The datapath hosts no VPN data plane: the configuration does not name the plane's key and address",
		slog.Any("data_planes", offered))
	return nil, nil
}

// vpnHubListeners is empty in a FIPS build: it builds no WireGuard hub,
// so there is no hub port for the host filter to admit.
func vpnHubListeners(*ServeConfig, bool) []hostfw.Listener { return nil }
