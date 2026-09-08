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
	"context"
	"encoding/base64"
	"net"

	vnl "github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// wireGuardAvailable is true in non-FIPS builds: WireGuard's primitives are
// not FIPS-approved, so the fips tag compiles the transport out.
const wireGuardAvailable = true

const wireGuardUnavailableReason = ""

// wgOps abstracts the WireGuard control socket for tests.
type wgOps interface {
	ConfigureDevice(name string, cfg wgtypes.Config) error
	Close() error
}

type realWGOps struct{ client *wgctrl.Client }

func newRealWGOps() (wgOps, error) {
	c, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	return &realWGOps{client: c}, nil
}

func (r *realWGOps) ConfigureDevice(name string, cfg wgtypes.Config) error {
	return r.client.ConfigureDevice(name, cfg)
}

func (r *realWGOps) Close() error { return r.client.Close() }

// wireGuardDeviceConfig builds the wgtypes.Config for one peer tunnel. key is
// the 32-byte private key; the caller zeroizes it. AllowedIPs is the
// remote's tunnel address only — a point-to-point link.
func wireGuardDeviceConfig(config TunnelConfig, key []byte) (wgtypes.Config, error) {
	priv, err := wgtypes.NewKey(key)
	if err != nil {
		return wgtypes.Config{}, &ErrKeyMaterial{Name: config.Name, KeyRef: config.WireGuard.KeyRef, Reason: "not a WireGuard private key", Cause: err}
	}
	pubRaw, err := base64.StdEncoding.DecodeString(config.WireGuard.PeerPublicKey)
	if err != nil {
		return wgtypes.Config{}, &ErrInvalidTunnelConfig{Name: config.Name, Reason: "wireguard.peer-public-key is not base64"}
	}
	pub, err := wgtypes.NewKey(pubRaw)
	if err != nil {
		return wgtypes.Config{}, &ErrInvalidTunnelConfig{Name: config.Name, Reason: "wireguard.peer-public-key is not a key"}
	}
	remote := net.ParseIP(config.Remote)
	allowed := []net.IPNet{}
	if _, peerNet, err := net.ParseCIDR(config.TunnelIP); err == nil {
		allowed = append(allowed, *peerNet)
	}
	if config.TunnelIPv6 != "" {
		if _, peerNet6, err := net.ParseCIDR(config.TunnelIPv6); err == nil {
			allowed = append(allowed, *peerNet6)
		}
	}
	keepalive := config.WireGuard.effectiveKeepalive()
	listen := config.WireGuard.ListenPort
	cfg := wgtypes.Config{
		PrivateKey:   &priv,
		ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{{
			PublicKey:                   pub,
			Endpoint:                    &net.UDPAddr{IP: remote, Port: config.WireGuard.RemotePort},
			PersistentKeepaliveInterval: &keepalive,
			ReplaceAllowedIPs:           true,
			AllowedIPs:                  allowed,
		}},
	}
	if listen > 0 {
		cfg.ListenPort = &listen
	}
	return cfg, nil
}

// createWireGuard creates the kernel interface, keys it through the control
// socket, addresses it and brings it up.
func (m *Manager) createWireGuard(ctx context.Context, config TunnelConfig) error {
	key, err := fetchKey(ctx, m.keys, config.Name, config.WireGuard.KeyRef, wireGuardKeyLen)
	if err != nil {
		return err
	}
	defer zeroize(key)
	devCfg, err := wireGuardDeviceConfig(config, key)
	if err != nil {
		return err
	}
	if m.wg == nil {
		ops, err := newRealWGOps()
		if err != nil {
			return &ErrTunnelCreateFailed{Name: config.Name, Cause: err}
		}
		m.wg = ops
	}
	link := &vnl.Wireguard{LinkAttrs: vnl.LinkAttrs{Name: config.Name, MTU: config.effectiveMTU()}}
	if err := m.nl.LinkAdd(link); err != nil {
		return &ErrTunnelCreateFailed{Name: config.Name, Cause: err}
	}
	created, err := m.nl.LinkByName(config.Name)
	if err != nil {
		return &ErrTunnelCreateFailed{Name: config.Name, Cause: err}
	}
	if err := m.wg.ConfigureDevice(config.Name, devCfg); err != nil {
		_ = m.nl.LinkDel(created)
		return &ErrTunnelCreateFailed{Name: config.Name, Cause: err}
	}
	if err := m.nl.LinkSetMTU(created, config.effectiveMTU()); err != nil {
		_ = m.nl.LinkDel(created)
		return &ErrTunnelCreateFailed{Name: config.Name, Cause: err}
	}
	if err := m.addAddress(created, config.TunnelIP); err != nil {
		_ = m.nl.LinkDel(created)
		return &ErrTunnelCreateFailed{Name: config.Name, Cause: err}
	}
	if config.TunnelIPv6 != "" {
		if err := m.addAddress(created, config.TunnelIPv6); err != nil {
			_ = m.nl.LinkDel(created)
			return &ErrTunnelCreateFailed{Name: config.Name, Cause: err}
		}
	}
	if err := m.nl.LinkSetUp(created); err != nil {
		_ = m.nl.LinkDel(created)
		return &ErrTunnelCreateFailed{Name: config.Name, Cause: err}
	}
	return nil
}

// rekeyWireGuard re-reads the private key and re-applies the device config;
// the peer's public key is unchanged, so a rotated private key requires the
// peer to learn the new public key through the control plane.
func (m *Manager) rekeyWireGuard(ctx context.Context, config TunnelConfig) error {
	key, err := fetchKey(ctx, m.keys, config.Name, config.WireGuard.KeyRef, wireGuardKeyLen)
	if err != nil {
		return &ErrRekeyFailed{Name: config.Name, Cause: err}
	}
	defer zeroize(key)
	devCfg, err := wireGuardDeviceConfig(config, key)
	if err != nil {
		return &ErrRekeyFailed{Name: config.Name, Cause: err}
	}
	if m.wg == nil {
		return &ErrRekeyFailed{Name: config.Name, Cause: &ErrTunnelNotFound{Name: config.Name}}
	}
	if err := m.wg.ConfigureDevice(config.Name, devCfg); err != nil {
		return &ErrRekeyFailed{Name: config.Name, Cause: err}
	}
	return nil
}
