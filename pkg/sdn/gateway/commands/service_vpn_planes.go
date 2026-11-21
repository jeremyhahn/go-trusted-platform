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
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/hostfw"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/tunnel"
)

// vpnDataPlanes is gatewayd's plane factory. It builds the WireGuard hub
// plane when the management VPN offers wireguard and names the hub's key
// reference (`wireguard.key-ref`) and address (`wireguard.address`), with
// hubKey, the key resolveVPNHubKey resolved before EnterHardened; nil
// means there is no secret store for it.
// While any of these is missing it builds none and says so: the vpn
// process's peer RPCs keep their refusal.
func vpnDataPlanes(cfg *ServeConfig, hubKey *vpnHubKey, logger *slog.Logger) ([]vpn.ManagedDataPlane, error) {
	c := cfg.Gateway.ManagementVPN.WithDefaults()
	wg := c.WireGuard
	if !c.Offers(vpn.DataPlaneWireGuard) || wg.KeyRef == "" || !wg.Address.IsValid() {
		logger.Warn("The datapath hosts no VPN data plane: the configuration does not name the plane's key and address",
			slog.Any("data_planes", c.DataPlanes))
		return nil, nil
	}
	if hubKey == nil {
		logger.Warn("The datapath hosts no VPN data plane: no secret resolver for the WireGuard hub key",
			slog.String("key_ref", wg.KeyRef))
		return nil, nil
	}
	zones, err := installVPNHubZoneEnforcement(cfg, logger)
	if err != nil || zones == nil {
		hubKey.erase()
		logger.Error("The datapath hosts no VPN data plane: the WireGuard hub's destination-zone enforcement is not installed",
			slog.String("key_ref", wg.KeyRef), slog.Any("error", err))
		return nil, &ErrVPNHubZoneUnenforced{KeyRef: wg.KeyRef}
	}
	hub, err := tunnel.NewWireGuardHub(logger, tunnel.WireGuardHubConfig{
		Name:       vpnHubInterface,
		KeyRef:     wg.KeyRef,
		ListenPort: wg.ListenPort,
		Addresses:  []netip.Prefix{wg.Address},
	}, hubKey)
	if err != nil {
		return nil, err
	}
	plane, err := vpn.NewWireGuardPlane(hub, logger)
	if err != nil {
		return nil, err
	}
	return []vpn.ManagedDataPlane{hubNetworkPlane{ManagedDataPlane: plane, network: wg.Address.Masked(), hub: wg.Address.Addr(), zones: zones}}, nil
}

// vpnHubKeyRef is the hub key's reference when the configuration builds a
// WireGuard hub, and "" when it builds none.
func vpnHubKeyRef(cfg *ServeConfig) string {
	if cfg == nil || cfg.Gateway == nil || cfg.Gateway.ManagementVPN == nil || !cfg.Gateway.ManagementVPN.Enabled {
		return ""
	}
	c := cfg.Gateway.ManagementVPN.WithDefaults()
	if !c.Offers(vpn.DataPlaneWireGuard) || !c.WireGuard.Address.IsValid() {
		return ""
	}
	return c.WireGuard.KeyRef
}

// resolveVPNHubKey resolves the hub's private key from the secret store
// before EnterHardened: the store is reached over the network, which the
// hardened child's AF_UNIX/AF_NETLINK-only filter refuses (Codex #2029
// round 1). Nil means the configuration builds no hub or names no store.
func resolveVPNHubKey(ctx context.Context, cfg *ServeConfig, logger *slog.Logger) *vpnHubKey {
	ref := vpnHubKeyRef(cfg)
	if ref == "" {
		return nil
	}
	anchor, err := buildPlatformAnchor(cfg)
	if err != nil {
		return &vpnHubKey{ref: ref, err: err}
	}
	resolve, err := buildSecretResolver(cfg, anchor, logger)
	if err != nil {
		return &vpnHubKey{ref: ref, err: err}
	}
	return resolveVPNHubKeyWith(ctx, cfg, resolve)
}

// resolveVPNHubKeyWith resolves the hub key of cfg through resolve. A
// failure is held in the key, so the plane's start reports it.
func resolveVPNHubKeyWith(ctx context.Context, cfg *ServeConfig, resolve bgp.SecretResolver) *vpnHubKey {
	ref := vpnHubKeyRef(cfg)
	if ref == "" || resolve == nil {
		return nil
	}
	key, err := resolve(ctx, ref)
	return &vpnHubKey{ref: ref, key: key, err: err}
}

// hubNetworkPlane holds the WireGuard plane to the hub's network: a peer
// whose address is outside it, or is the hub's own, is refused (SPEC.md:80).
// The plane itself checks only that the address is a single host (Codex
// #2029 round 1).
type hubNetworkPlane struct {
	vpn.ManagedDataPlane
	network netip.Prefix
	hub     netip.Addr
	// zones is the installed destination-zone enforcement (#2093).
	zones *vpnHubZoneEnforcement
}

// InstallPeer refuses a lease address outside the hub's network.
func (p hubNetworkPlane) InstallPeer(ctx context.Context, lease *vpn.Lease) error {
	if lease != nil && lease.Address.IsValid() {
		addr := lease.Address.Addr()
		if !p.network.Contains(addr) {
			return &vpn.ErrPeerKeyInvalid{Kind: vpn.DataPlaneWireGuard, Reason: "lease address is outside the hub network " + p.network.String()}
		}
		if addr == p.hub {
			return &vpn.ErrPeerKeyInvalid{Kind: vpn.DataPlaneWireGuard, Reason: "lease address is the hub's own"}
		}
	}
	if err := p.zones.admitLease(lease); err != nil {
		return err
	}
	return p.ManagedDataPlane.InstallPeer(ctx, lease)
}

// ReconcilePeers forwards to the plane, which is a vpn.PeerReconciler.
func (p hubNetworkPlane) ReconcilePeers(ctx context.Context, keep []vpn.LeaseID) error {
	if r, ok := p.ManagedDataPlane.(vpn.PeerReconciler); ok {
		return r.ReconcilePeers(ctx, keep)
	}
	return nil
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
	c := cfg.Gateway.ManagementVPN.WithDefaults()
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
