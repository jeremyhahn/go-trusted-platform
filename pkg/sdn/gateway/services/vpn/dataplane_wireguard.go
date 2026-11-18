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
	"bytes"
	"context"
	"errors"
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
	// removed tombstones each lease removed before the plane held it, so
	// the install it cleaned up after cannot land late; removedOrder evicts
	// the oldest past maxRemovedTombstones.
	removed      map[LeaseID]struct{}
	removedOrder []LeaseID
}

// maxRemovedTombstones bounds the removal tombstones. A tombstone only has to
// outlive the delayed handler of one cancelled install, and lease IDs are new
// per admission, so the oldest can go once far more removals have followed.
const maxRemovedTombstones = 1024

// NewWireGuardPlane returns the WireGuard data plane over hub.
func NewWireGuardPlane(hub WireGuardHub, logger *slog.Logger) (ManagedDataPlane, error) {
	if hub == nil {
		return nil, &ErrDepsMissing{Dep: "WireGuardHub"}
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &wireguardPlane{
		hub:     hub,
		logger:  logger,
		peers:   make(map[LeaseID][]byte),
		removed: make(map[LeaseID]struct{}),
	}, nil
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
	p.removed = make(map[LeaseID]struct{})
	p.removedOrder = nil
	return p.hub.Down()
}

// tombstone records the removal of a lease the plane does not hold, evicting
// the oldest tombstone past maxRemovedTombstones. The caller holds p.mu.
func (p *wireguardPlane) tombstone(id LeaseID) {
	if _, ok := p.removed[id]; ok {
		return
	}
	p.removed[id] = struct{}{}
	p.removedOrder = append(p.removedOrder, id)
	if len(p.removedOrder) > maxRemovedTombstones {
		delete(p.removed, p.removedOrder[0])
		p.removedOrder = p.removedOrder[1:]
	}
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
	// A removal that ran first, the cleanup of a cancelled install, fences
	// the late install: its caller has already released the lease.
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, gone := p.removed[lease.ID]; gone {
		return &ErrLeaseNotFound{LeaseID: lease.ID}
	}
	// Peers are removed by key, so a key holds one lease at a time:
	// otherwise a retried removal of the old lease drops the new one.
	for id, held := range p.peers {
		if id != lease.ID && bytes.Equal(held, key) {
			return &ErrPeerConflict{Kind: DataPlaneWireGuard, LeaseID: lease.ID, Existing: id, Reason: "the public key already holds a lease"}
		}
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
		p.tombstone(leaseID)
		return nil
	}
	if !p.keyHeldByOther(leaseID, key) {
		if err := p.hub.RemovePeer(ctx, key); err != nil {
			return err
		}
	}
	delete(p.peers, leaseID)
	p.logger.Info("vpn.wireguard.peer.remove", slog.String("lease", string(leaseID)))
	return nil
}

// keyHeldByOther reports whether a lease other than leaseID still maps to
// key. Peers are removed by key, so removing leaseID's peer then would drop
// the other lease's session. Callers hold p.mu.
func (p *wireguardPlane) keyHeldByOther(leaseID LeaseID, key []byte) bool {
	for id, held := range p.peers {
		if id != leaseID && bytes.Equal(held, key) {
			return true
		}
	}
	return false
}

// ReconcilePeers removes every peer whose lease is not in keep: the plane
// lives in the datapath child and outlives a vpn child that died between a
// revoke's record deletion and its peer removal.
func (p *wireguardPlane) ReconcilePeers(ctx context.Context, keep []LeaseID) error {
	want := make(map[LeaseID]bool, len(keep))
	for _, id := range keep {
		want[id] = true
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	var errs []error
	for id, key := range p.peers {
		if want[id] {
			continue
		}
		if !p.keyHeldByOther(id, key) {
			if err := p.hub.RemovePeer(ctx, key); err != nil {
				errs = append(errs, err)
				continue
			}
		}
		delete(p.peers, id)
		p.logger.Info("vpn.wireguard.peer.reconcile.remove", slog.String("lease", string(id)))
	}
	return errors.Join(errs...)
}
