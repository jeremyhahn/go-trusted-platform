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

//go:build !fips

package commands

import (
	"context"
	"log/slog"
	"net/netip"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/hostfw"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/tunnel"
)

// vpnDataPlanes is gatewayd's plane factory. It builds the WireGuard hub
// plane when the management VPN offers wireguard and names the hub's key
// reference (`wireguard.key-ref`) and address (`wireguard.address`), with
// the key resolved through the host's SecretResolver when the hub comes up.
// While any of these is missing it builds none and says so: the vpn
// process's peer RPCs keep their refusal.
func vpnDataPlanes(cfg *ServeConfig, gw *gateway.Gateway, logger *slog.Logger) ([]vpn.ManagedDataPlane, error) {
	c := cfg.Gateway.ManagementVPN.Config.WithDefaults()
	wg := c.WireGuard
	if !c.Offers(vpn.DataPlaneWireGuard) || wg.KeyRef == "" || !wg.Address.IsValid() {
		logger.Warn("The datapath hosts no VPN data plane: the configuration does not name the plane's key and address",
			slog.Any("data_planes", c.DataPlanes))
		return nil, nil
	}
	var resolve bgp.SecretResolver
	if host := gw.GetConfig().Host; host != nil {
		resolve = host.SecretResolver
	}
	if resolve == nil {
		logger.Warn("The datapath hosts no VPN data plane: no secret resolver for the WireGuard hub key",
			slog.String("key_ref", wg.KeyRef))
		return nil, nil
	}
	hub, err := tunnel.NewWireGuardHub(logger, tunnel.WireGuardHubConfig{
		Name:       vpnHubInterface,
		KeyRef:     wg.KeyRef,
		ListenPort: wg.ListenPort,
		Addresses:  []netip.Prefix{wg.Address},
	}, secretKeyProvider{resolve: resolve})
	if err != nil {
		return nil, err
	}
	plane, err := vpn.NewWireGuardPlane(hub, logger)
	if err != nil {
		return nil, err
	}
	return []vpn.ManagedDataPlane{plane}, nil
}

// vpnHubListeners is the WireGuard hub's UDP listener for the host
// filter's inventory: the hub binds its effective listen-port on every
// interface, and a default-drop input chain admits only declared
// listeners. It is empty when the datapath builds no hub (the same
// conditions as vpnDataPlanes, with haveResolver standing for the host's
// secret resolver), and when the operator already declared the port in
// hostfw.extra: that declaration, perhaps narrowed to one interface,
// stands, and a second one would be refused as a duplicate.
func vpnHubListeners(cfg *ServeConfig, haveResolver bool) []hostfw.Listener {
	if !haveResolver || cfg.Gateway == nil || cfg.Gateway.ManagementVPN == nil || !cfg.Gateway.ManagementVPN.Enabled {
		return nil
	}
	c := cfg.Gateway.ManagementVPN.Config.WithDefaults()
	wg := c.WireGuard
	if !c.Offers(vpn.DataPlaneWireGuard) || wg.KeyRef == "" || !wg.Address.IsValid() || wg.ListenPort <= 0 || wg.ListenPort > 65535 {
		return nil
	}
	port := uint16(wg.ListenPort)
	if hf := cfg.Gateway.HostFW; hf != nil {
		for _, l := range hf.Extra {
			if l.Protocol == hostfw.ProtocolUDP && l.Port == port {
				return nil
			}
		}
	}
	return []hostfw.Listener{{Protocol: hostfw.ProtocolUDP, Port: port, Comment: "management-vpn wireguard hub"}}
}

// secretKeyProvider is the tunnel.KeyProvider over the host's
// SecretResolver, the shape of gateway.resolverKeyProvider.
type secretKeyProvider struct {
	resolve bgp.SecretResolver
}

func (p secretKeyProvider) Key(ctx context.Context, ref string) ([]byte, error) {
	return p.resolve(ctx, ref)
}
