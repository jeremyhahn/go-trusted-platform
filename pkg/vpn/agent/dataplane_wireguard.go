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

package agent

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"

	gwvpn "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/tunnel"
)

// WireGuardInterface is the client WireGuard interface. It is a kernel link,
// so it outlives the process that brought it up; disconnect finds it by name.
const WireGuardInterface = "vpn-wg0"

// wireGuardKeyLen is the length of a WireGuard (X25519) key.
const wireGuardKeyLen = 32

// wireGuardDevice is the seam over tunnel.WireGuardClient.
type wireGuardDevice interface {
	Up(cfg tunnel.WireGuardClientConfig) error
	Down(name string) error
}

// resolveFunc resolves the gateway's endpoint host.
type resolveFunc func(ctx context.Context, host string) ([]netip.Addr, error)

// wireGuardPlane is the client side of the gateway's WireGuard hub: one
// interface keyed with a fresh key per admission, the gateway as its only
// peer.
type wireGuardPlane struct {
	device  wireGuardDevice
	resolve resolveFunc
	newKey  func() (privateKey, publicKey []byte, err error)
	// pending is the private key Prepare made, held until Up keys the
	// interface with it.
	pending atomic.Pointer[[]byte]
}

// NewWireGuardPlane returns the WireGuard client data plane over the kernel's
// WireGuard and netlink. Absent from FIPS builds, as the gateway's hub is.
func NewWireGuardPlane(logger *slog.Logger) DataPlane {
	return newWireGuardPlane(tunnel.NewWireGuardClient(logger), lookupHost, tunnel.GenerateWireGuardKey)
}

func newWireGuardPlane(device wireGuardDevice, resolve resolveFunc, newKey func() ([]byte, []byte, error)) *wireGuardPlane {
	return &wireGuardPlane{device: device, resolve: resolve, newKey: newKey}
}

func lookupHost(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

func (p *wireGuardPlane) Kind() gwvpn.DataPlaneKind { return gwvpn.DataPlaneWireGuard }

// Prepare makes the key pair this admission is keyed with and returns the
// public half for the gateway. A key an earlier Prepare left unused is
// zeroized.
func (p *wireGuardPlane) Prepare(context.Context) (gwvpn.PeerWire, error) {
	privateKey, publicKey, err := p.newKey()
	if err != nil {
		return gwvpn.PeerWire{}, err
	}
	if stale := p.pending.Swap(&privateKey); stale != nil {
		clear(*stale)
	}
	return gwvpn.PeerWire{WireGuardPublicKey: publicKey}, nil
}

// Up keys the interface with the prepared key and the gateway the lease
// names, addresses it with the lease address and routes the lease's zones
// through it. The prepared key is zeroized whether or not the bring-up
// succeeds, and is never used twice.
func (p *wireGuardPlane) Up(ctx context.Context, lease *gwvpn.LeaseWire) (Session, error) {
	pending := p.pending.Swap(nil)
	if pending == nil {
		return Session{}, &ErrNotPrepared{Kind: p.Kind()}
	}
	privateKey := *pending
	defer clear(privateKey)

	cfg, err := p.config(ctx, lease)
	if err != nil {
		return Session{}, err
	}
	cfg.PrivateKey = privateKey
	if err := p.device.Up(cfg); err != nil {
		return Session{}, err
	}
	return Session{Interface: WireGuardInterface}, nil
}

// Down removes the interface and the routes through it.
func (p *wireGuardPlane) Down(_ context.Context, session Session) error {
	return p.device.Down(session.Interface)
}

func (p *wireGuardPlane) config(ctx context.Context, lease *gwvpn.LeaseWire) (tunnel.WireGuardClientConfig, error) {
	gateway := lease.Endpoint.WireGuard
	if gateway == nil {
		return tunnel.WireGuardClientConfig{}, &ErrLeaseUnusable{Kind: p.Kind(), Reason: "the lease carries no WireGuard endpoint"}
	}
	if len(gateway.PublicKey) != wireGuardKeyLen {
		return tunnel.WireGuardClientConfig{}, &ErrLeaseUnusable{Kind: p.Kind(), Reason: "the gateway public key is not " + strconv.Itoa(wireGuardKeyLen) + " bytes"}
	}
	endpoint, err := p.endpoint(ctx, gateway.Endpoint)
	if err != nil {
		return tunnel.WireGuardClientConfig{}, err
	}
	address, err := leaseAddress(p.Kind(), lease)
	if err != nil {
		return tunnel.WireGuardClientConfig{}, err
	}
	routes, err := leaseRoutes(p.Kind(), gateway.Routes)
	if err != nil {
		return tunnel.WireGuardClientConfig{}, err
	}
	return tunnel.WireGuardClientConfig{
		Name:          WireGuardInterface,
		Address:       address,
		PeerPublicKey: gateway.PublicKey,
		PeerEndpoint:  endpoint,
		Routes:        routes,
	}, nil
}

// endpoint resolves the gateway's UDP endpoint, an address or a host name
// with a port.
func (p *wireGuardPlane) endpoint(ctx context.Context, endpoint string) (netip.AddrPort, error) {
	host, portText, err := net.SplitHostPort(endpoint)
	if err != nil {
		return netip.AddrPort{}, &ErrLeaseUnusable{Kind: p.Kind(), Reason: "endpoint " + endpoint + " is not host:port", Cause: err}
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return netip.AddrPort{}, &ErrLeaseUnusable{Kind: p.Kind(), Reason: "endpoint " + endpoint + " has no usable port"}
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(addr.Unmap(), uint16(port)), nil
	}
	addrs, err := p.resolve(ctx, host)
	if err != nil {
		return netip.AddrPort{}, &ErrLeaseUnusable{Kind: p.Kind(), Reason: "resolve endpoint " + host, Cause: err}
	}
	if len(addrs) == 0 {
		return netip.AddrPort{}, &ErrLeaseUnusable{Kind: p.Kind(), Reason: "endpoint " + host + " resolves to no address"}
	}
	return netip.AddrPortFrom(addrs[0].Unmap(), uint16(port)), nil
}
