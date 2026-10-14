//go:build !fips

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

package tunnel

import (
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"time"

	vnl "github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// wireGuardLinkType is the netlink kind of a kernel WireGuard interface.
const wireGuardLinkType = "wireguard"

// WireGuardClientConfig describes a client interface: one key, one peer —
// the gateway — and the prefixes reached through it. It is the spoke of a
// WireGuardHub: the remote-access VPN client keys it from its lease.
type WireGuardClientConfig struct {
	// Name is the interface name (at most 15 characters).
	Name string
	// PrivateKey is the 32-byte client private key. Up zeroizes it once the
	// kernel holds it, whether or not the bring-up succeeds.
	PrivateKey []byte
	// Address is the client's own address on the interface.
	Address netip.Prefix
	// PeerPublicKey is the gateway's 32-byte public key.
	PeerPublicKey []byte
	// PeerEndpoint is the gateway's UDP endpoint.
	PeerEndpoint netip.AddrPort
	// Routes are the prefixes routed through the interface; they are also the
	// addresses the gateway may source packets from.
	Routes []netip.Prefix
	// MTU is the link MTU; zero selects the WireGuard default.
	MTU int
	// Keepalive is the persistent-keepalive interval that holds NAT state
	// open; zero selects DefaultWireGuardKeepalive.
	Keepalive time.Duration
}

func (c WireGuardClientConfig) effectiveMTU() int {
	if c.MTU <= 0 {
		return DefaultMTU
	}
	return c.MTU
}

func (c WireGuardClientConfig) effectiveKeepalive() time.Duration {
	if c.Keepalive == 0 {
		return DefaultWireGuardKeepalive
	}
	return c.Keepalive
}

func (c WireGuardClientConfig) validate() error {
	if c.Name == "" || len(c.Name) > maxInterfaceNameLen {
		return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "device name must be 1-15 characters"}
	}
	if len(c.PrivateKey) != wireGuardKeyLen {
		return &ErrKeyMaterial{Name: c.Name, KeyRef: "client", Reason: "private key must be exactly " + itoa(wireGuardKeyLen) + " bytes"}
	}
	if len(c.PeerPublicKey) != wireGuardKeyLen {
		return &ErrPeerInvalid{Name: c.Name, Reason: "public key must be exactly " + itoa(wireGuardKeyLen) + " bytes"}
	}
	if !c.PeerEndpoint.IsValid() || c.PeerEndpoint.Port() == 0 {
		return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "peer endpoint must be an address and a non-zero port"}
	}
	if !c.Address.IsValid() {
		return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "address prefix is not valid"}
	}
	if len(c.Routes) == 0 {
		return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "at least one route is required"}
	}
	for _, r := range c.Routes {
		if !r.IsValid() {
			return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "route prefix is not valid"}
		}
		// A route over the gateway's own endpoint would send the tunnel's
		// UDP packets into the tunnel.
		if r.Contains(c.PeerEndpoint.Addr()) {
			return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "route " + r.String() + " covers the peer endpoint"}
		}
	}
	if c.MTU != 0 && (c.MTU < MinMTU || c.MTU > MaxMTU) {
		return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "MTU out of range"}
	}
	if c.Keepalive < 0 {
		return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "keepalive must not be negative"}
	}
	return nil
}

// GenerateWireGuardKey returns a fresh client private key and its public key.
// The caller owns the private key and hands it to WireGuardClient.Up, which
// zeroizes it.
func GenerateWireGuardKey() (privateKey, publicKey []byte, err error) {
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, nil, &ErrKeyMaterial{Name: "client", KeyRef: "generated", Reason: "generate a WireGuard private key", Cause: err}
	}
	pub := priv.PublicKey()
	privateKey = append([]byte(nil), priv[:]...)
	zeroize(priv[:])
	return privateKey, pub[:], nil
}

// WireGuardClient brings client WireGuard interfaces up and down. It holds no
// per-device state: Down finds the interface by name, so a device brought up
// by one process can be removed by another.
type WireGuardClient struct {
	logger *slog.Logger
	nl     netlinkOps
	newWG  func() (wgOps, error)
}

// NewWireGuardClient builds a client over the real netlink and WireGuard
// control sockets. Nothing is opened until Up.
func NewWireGuardClient(logger *slog.Logger) *WireGuardClient {
	return newWireGuardClientWithOps(logger, &realNetlinkOps{}, newRealWGOps)
}

func newWireGuardClientWithOps(logger *slog.Logger, nl netlinkOps, newWG func() (wgOps, error)) *WireGuardClient {
	if logger == nil {
		logger = slog.Default()
	}
	return &WireGuardClient{logger: logger, nl: nl, newWG: newWG}
}

// Up creates the interface, keys it with cfg.PrivateKey and the gateway as
// its only peer, addresses it, brings it up and routes cfg.Routes through it.
// The private key is zeroized before Up returns. A failed bring-up removes
// the interface, and with it every address and route it carried.
func (c *WireGuardClient) Up(cfg WireGuardClientConfig) error {
	defer zeroize(cfg.PrivateKey)
	if err := cfg.validate(); err != nil {
		return err
	}
	priv, err := wgtypes.NewKey(cfg.PrivateKey)
	if err != nil {
		return &ErrKeyMaterial{Name: cfg.Name, KeyRef: "client", Reason: "not a WireGuard private key", Cause: err}
	}
	defer zeroize(priv[:])
	peer, err := wgtypes.NewKey(cfg.PeerPublicKey)
	if err != nil {
		return &ErrPeerInvalid{Name: cfg.Name, Reason: "public key is not a WireGuard key"}
	}
	wg, err := c.newWG()
	if err != nil {
		return &ErrTunnelCreateFailed{Name: cfg.Name, Cause: err}
	}
	link := &vnl.Wireguard{LinkAttrs: vnl.LinkAttrs{Name: cfg.Name, MTU: cfg.effectiveMTU()}}
	if err := c.nl.LinkAdd(link); err != nil {
		return &ErrTunnelCreateFailed{Name: cfg.Name, Cause: errors.Join(err, wg.Close())}
	}
	err = c.configure(wg, cfg, &priv, peer)
	if closeErr := wg.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return &ErrTunnelCreateFailed{Name: cfg.Name, Cause: errors.Join(err, c.nl.LinkDel(link))}
	}
	c.logger.Info("wireguard client up", slog.String("device", cfg.Name), slog.String("peer", cfg.PeerEndpoint.String()), slog.Int("routes", len(cfg.Routes)))
	return nil
}

func (c *WireGuardClient) configure(wg wgOps, cfg WireGuardClientConfig, priv *wgtypes.Key, peer wgtypes.Key) error {
	link, err := c.nl.LinkByName(cfg.Name)
	if err != nil {
		return err
	}
	allowed := make([]net.IPNet, 0, len(cfg.Routes))
	for _, r := range cfg.Routes {
		allowed = append(allowed, *prefixToIPNet(r.Masked()))
	}
	keepalive := cfg.effectiveKeepalive()
	devCfg := wgtypes.Config{
		PrivateKey:   priv,
		ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{{
			PublicKey:                   peer,
			Endpoint:                    net.UDPAddrFromAddrPort(cfg.PeerEndpoint),
			PersistentKeepaliveInterval: &keepalive,
			ReplaceAllowedIPs:           true,
			AllowedIPs:                  allowed,
		}},
	}
	if err := wg.ConfigureDevice(cfg.Name, devCfg); err != nil {
		return err
	}
	if err := c.nl.LinkSetMTU(link, cfg.effectiveMTU()); err != nil {
		return err
	}
	if err := c.nl.AddrAdd(link, &vnl.Addr{IPNet: prefixToIPNet(cfg.Address)}); err != nil {
		return err
	}
	if err := c.nl.LinkSetUp(link); err != nil {
		return err
	}
	for _, r := range cfg.Routes {
		route := &vnl.Route{LinkIndex: link.Attrs().Index, Dst: prefixToIPNet(r.Masked()), Scope: vnl.SCOPE_LINK}
		if err := c.nl.RouteReplace(route); err != nil {
			return err
		}
	}
	return nil
}

// Down removes the routes through the named interface and then the interface.
// An interface that is already gone is not an error: the end state is what
// was asked for. A name that is not a WireGuard interface is refused, so a
// stale or edited name never removes some other link.
func (c *WireGuardClient) Down(name string) error {
	link, err := c.nl.LinkByName(name)
	if err != nil {
		var missing vnl.LinkNotFoundError
		if errors.As(err, &missing) {
			return nil
		}
		return &ErrTunnelRemoveFailed{Name: name, Cause: err}
	}
	if link.Type() != wireGuardLinkType {
		return &ErrTunnelRemoveFailed{Name: name, Cause: &ErrInvalidTunnelConfig{Name: name, Reason: "not a WireGuard interface"}}
	}
	index := link.Attrs().Index
	routes, err := c.nl.RouteListFiltered(vnl.FAMILY_ALL, &vnl.Route{LinkIndex: index}, vnl.RT_FILTER_OIF)
	if err != nil {
		return &ErrTunnelRemoveFailed{Name: name, Cause: err}
	}
	for i := range routes {
		if routes[i].LinkIndex != index {
			continue
		}
		if err := c.nl.RouteDel(&routes[i]); err != nil {
			return &ErrTunnelRemoveFailed{Name: name, Cause: err}
		}
	}
	if err := c.nl.LinkDel(link); err != nil {
		return &ErrTunnelRemoveFailed{Name: name, Cause: err}
	}
	c.logger.Info("wireguard client down", slog.String("device", name))
	return nil
}
