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

package vpn

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
)

// DataPlaneWireGuard is the kernel WireGuard plane. It exists only in
// non-FIPS builds: WireGuard's primitives are not FIPS-approved, so the fips
// tag compiles the plane out and Config.Validate refuses the kind.
const DataPlaneWireGuard = wireGuardKind

// wireGuardKeyLen is a Curve25519 public key.
const wireGuardKeyLen = 32

func init() {
	dataPlaneKinds[DataPlaneWireGuard] = true
}

// WireGuardHub is the kernel device the WireGuard plane programs peers
// into; *tunnel.WireGuardHub satisfies it. The hub owns the server key: the
// plane only ever sees client public keys.
type WireGuardHub interface {
	Up(ctx context.Context) error
	Down() error
	SetPeer(ctx context.Context, publicKey []byte, allowed []netip.Prefix) error
	RemovePeer(ctx context.Context, publicKey []byte) error
	PublicKey() []byte
	ListenPort() int
}

// wireguardPlane installs one kernel peer per lease. The peer's allowed
// address is exactly the lease address, so a client can source packets from
// nothing else, and the mapping lease → public key is kept so revocation
// needs only the lease id.
type wireguardPlane struct {
	hub    WireGuardHub
	logger *slog.Logger

	mu      sync.Mutex
	started bool
	peers   map[LeaseID][]byte
}

// NewWireGuardPlane returns the WireGuard data plane over hub.
func NewWireGuardPlane(hub WireGuardHub, logger *slog.Logger) (ManagedDataPlane, error) {
	if hub == nil {
		return nil, &ErrDepsMissing{Dep: "WireGuardHub"}
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &wireguardPlane{hub: hub, logger: logger, peers: make(map[LeaseID][]byte)}, nil
}

func (p *wireguardPlane) Kind() DataPlaneKind { return DataPlaneWireGuard }

// Start brings the hub device up.
func (p *wireguardPlane) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.started {
		return nil
	}
	if err := p.hub.Up(ctx); err != nil {
		return err
	}
	p.started = true
	return nil
}

// Stop removes every peer with the device and forgets the lease table.
func (p *wireguardPlane) Stop(_ context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.started {
		return nil
	}
	p.started = false
	p.peers = make(map[LeaseID][]byte)
	return p.hub.Down()
}

// InstallPeer programs the lease's client public key with the lease
// address as its only allowed prefix.
func (p *wireguardPlane) InstallPeer(ctx context.Context, lease *Lease) error {
	if lease == nil {
		return &ErrInvalidRequest{Field: "lease", Reason: "required"}
	}
	key := lease.Keys.WireGuardPublicKey
	if len(key) != wireGuardKeyLen {
		return &ErrPeerKeyInvalid{Kind: DataPlaneWireGuard, Reason: "wireguard public key must be exactly 32 bytes"}
	}
	if !lease.Address.IsValid() || !lease.Address.IsSingleIP() {
		return &ErrPeerKeyInvalid{Kind: DataPlaneWireGuard, Reason: "lease address must be a single host address"}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.started {
		return &ErrDataPlaneNotStarted{Kind: DataPlaneWireGuard}
	}
	if err := p.hub.SetPeer(ctx, key, []netip.Prefix{lease.Address}); err != nil {
		return err
	}
	p.peers[lease.ID] = append([]byte(nil), key...)
	p.logger.Info("vpn.wireguard.peer.install", slog.String("lease", string(lease.ID)), slog.String("address", lease.Address.String()))
	return nil
}

// RemovePeer removes the lease's peer. A lease this plane never installed
// (or already removed) is not an error: the peer is gone either way.
func (p *wireguardPlane) RemovePeer(ctx context.Context, leaseID LeaseID) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	key, ok := p.peers[leaseID]
	if !ok {
		return nil
	}
	if err := p.hub.RemovePeer(ctx, key); err != nil {
		return err
	}
	delete(p.peers, leaseID)
	p.logger.Info("vpn.wireguard.peer.remove", slog.String("lease", string(leaseID)))
	return nil
}
