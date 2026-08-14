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

// Package ct allocates OVS connection-tracking zone identifiers to named
// platform subsystems. Conntrack zones partition the kernel connection
// tracker so independent consumers (the stateful firewall, the NAT gateway,
// load-balancer VIPs) never observe each other's connection state.
//
// Zone IDs are deterministic: the same owner/key pair always hashes to the
// same starting slot, so a restarted daemon converges on the same layout as
// long as the allocation order collisions permit. A Persister seam allows
// the authoritative assignment map to be stored in the OVS bridge
// external_ids column so restarts restore the exact prior layout.
package ct

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"

	"github.com/cespare/xxhash/v2"
)

// Conntrack zone space constants. Zone 0 is the kernel default zone and is
// never handed out.
const (
	// MinZone is the lowest allocatable conntrack zone ID.
	MinZone uint16 = 1

	// MaxZone is the highest allocatable conntrack zone ID.
	MaxZone uint16 = 65535
)

// zoneSpace is the number of allocatable zone IDs.
const zoneSpace = int(MaxZone) - int(MinZone) + 1

// Typed errors returned by the allocator.
var (
	// ErrZoneExhausted is returned when every conntrack zone ID is in use.
	ErrZoneExhausted = errors.New("ct: conntrack zone space exhausted")

	// ErrZoneNotAllocated is returned when releasing or looking up an
	// owner/key pair that holds no allocation.
	ErrZoneNotAllocated = errors.New("ct: conntrack zone not allocated")

	// ErrInvalidOwner is returned when the owner or key is empty.
	ErrInvalidOwner = errors.New("ct: owner and key must be non-empty")

	// ErrCorruptSnapshot is returned when a persisted snapshot contains an
	// out-of-range zone ID or duplicate zone assignments.
	ErrCorruptSnapshot = errors.New("ct: persisted zone snapshot is corrupt")
)

// ZoneError wraps a sentinel error with the allocation name and operation
// that produced it, preserving errors.Is matching on the sentinel.
type ZoneError struct {
	// Op is the operation that failed ("restore", "allocate", "release",
	// "persist", "load").
	Op string

	// Name is the owner/key allocation name involved, when known.
	Name string

	// Err is the underlying sentinel or transport error.
	Err error
}

// Error implements the error interface.
func (e *ZoneError) Error() string {
	if e.Name == "" {
		return "ct: " + e.Op + ": " + e.Err.Error()
	}
	return "ct: " + e.Op + " " + e.Name + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *ZoneError) Unwrap() error {
	return e.Err
}

// Persister stores and restores the allocation snapshot (owner/key → zone).
type Persister interface {
	// Save persists the full allocation snapshot.
	Save(ctx context.Context, allocations map[string]uint16) error

	// Load restores the last persisted snapshot. An empty (or nil) map with
	// a nil error means nothing was persisted yet.
	Load(ctx context.Context) (map[string]uint16, error)
}

// ZoneAllocator hands out disjoint conntrack zone IDs to named owners.
// Owners are subsystem identifiers ("firewall", "nat", "lb"); keys scope an
// allocation within an owner (zone name, VIP, ...). The zero value is not
// usable; construct with NewZoneAllocator.
type ZoneAllocator struct {
	mu        sync.RWMutex
	persister Persister
	byName    map[string]uint16 // owner/key → zone
	byZone    map[uint16]string // zone → owner/key
}

// NewZoneAllocator creates a ZoneAllocator. persister may be nil for a
// memory-only allocator; when non-nil, call Restore before the first
// Allocate to converge on the persisted layout.
func NewZoneAllocator(persister Persister) *ZoneAllocator {
	return &ZoneAllocator{
		persister: persister,
		byName:    make(map[string]uint16),
		byZone:    make(map[uint16]string),
	}
}

// name builds the composite allocation name for an owner/key pair.
func name(owner, key string) string {
	return owner + "/" + key
}

// hashZone maps an allocation name onto the [MinZone, MaxZone] space using
// a truncated xxhash so allocations are deterministic across restarts.
func hashZone(allocationName string) uint16 {
	h := xxhash.Sum64String(allocationName)
	return MinZone + uint16(h%uint64(zoneSpace))
}

// nextZone advances a candidate zone by one slot with wrap-around, skipping
// the reserved zone 0.
func nextZone(zone uint16) uint16 {
	if zone == MaxZone {
		return MinZone
	}
	return zone + 1
}

// Restore loads the persisted snapshot into the allocator, replacing any
// in-memory state. It is a no-op for allocators without a persister.
func (a *ZoneAllocator) Restore(ctx context.Context) error {
	if a.persister == nil {
		return nil
	}

	snapshot, err := a.persister.Load(ctx)
	if err != nil {
		return err
	}

	byName := make(map[string]uint16, len(snapshot))
	byZone := make(map[uint16]string, len(snapshot))
	for allocationName, zone := range snapshot {
		if zone < MinZone {
			return &ZoneError{Op: "restore", Name: allocationName, Err: ErrCorruptSnapshot}
		}
		if _, dup := byZone[zone]; dup {
			return &ZoneError{Op: "restore", Name: allocationName, Err: ErrCorruptSnapshot}
		}
		byName[allocationName] = zone
		byZone[zone] = allocationName
	}

	a.mu.Lock()
	a.byName = byName
	a.byZone = byZone
	a.mu.Unlock()

	return nil
}

// Allocate returns the conntrack zone ID for owner/key, assigning a new
// disjoint zone on first use. Allocation is idempotent: repeated calls with
// the same pair return the same zone. The starting slot is the stable hash
// of the allocation name; collisions fall back to linear probing.
func (a *ZoneAllocator) Allocate(ctx context.Context, owner, key string) (uint16, error) {
	if owner == "" || key == "" {
		return 0, ErrInvalidOwner
	}
	allocationName := name(owner, key)

	a.mu.Lock()

	if zone, ok := a.byName[allocationName]; ok {
		a.mu.Unlock()
		return zone, nil
	}

	if len(a.byZone) >= zoneSpace {
		a.mu.Unlock()
		return 0, ErrZoneExhausted
	}

	zone := hashZone(allocationName)
	for {
		if _, taken := a.byZone[zone]; !taken {
			break
		}
		zone = nextZone(zone)
	}

	a.byName[allocationName] = zone
	a.byZone[zone] = allocationName
	snapshot := a.snapshotLocked()
	a.mu.Unlock()

	if err := a.persist(ctx, snapshot, allocationName); err != nil {
		return 0, err
	}

	return zone, nil
}

// Release returns the zone held by owner/key to the free pool.
func (a *ZoneAllocator) Release(ctx context.Context, owner, key string) error {
	if owner == "" || key == "" {
		return ErrInvalidOwner
	}
	allocationName := name(owner, key)

	a.mu.Lock()

	zone, ok := a.byName[allocationName]
	if !ok {
		a.mu.Unlock()
		return &ZoneError{Op: "release", Name: allocationName, Err: ErrZoneNotAllocated}
	}

	delete(a.byName, allocationName)
	delete(a.byZone, zone)
	snapshot := a.snapshotLocked()
	a.mu.Unlock()

	return a.persist(ctx, snapshot, allocationName)
}

// persist saves the snapshot through the persister, rolling nothing back:
// the in-memory state is authoritative and a subsequent successful mutation
// re-persists the full map.
func (a *ZoneAllocator) persist(ctx context.Context, snapshot map[string]uint16, allocationName string) error {
	if a.persister == nil {
		return nil
	}
	if err := a.persister.Save(ctx, snapshot); err != nil {
		return &ZoneError{Op: "persist", Name: allocationName, Err: err}
	}
	return nil
}

// Lookup returns the zone held by owner/key, if any.
func (a *ZoneAllocator) Lookup(owner, key string) (uint16, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	zone, ok := a.byName[name(owner, key)]
	return zone, ok
}

// Snapshot returns a copy of the full allocation map keyed by "owner/key".
func (a *ZoneAllocator) Snapshot() map[string]uint16 {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.snapshotLocked()
}

// snapshotLocked copies the allocation map; the caller must hold at least a
// read lock.
func (a *ZoneAllocator) snapshotLocked() map[string]uint16 {
	out := make(map[string]uint16, len(a.byName))
	for k, v := range a.byName {
		out[k] = v
	}
	return out
}

// BridgeExternalIDsClient is the narrow OVSDB surface the external_ids
// persister needs. *ovs.Client satisfies it.
type BridgeExternalIDsClient interface {
	SetBridgeExternalIDs(ctx context.Context, name string, ids map[string]string) error
	GetBridgeExternalIDs(ctx context.Context, name string) (map[string]string, error)
}

// DefaultExternalIDsKey is the bridge external_ids key that stores the
// JSON-encoded conntrack zone allocation snapshot.
const DefaultExternalIDsKey = "trusted-platform-ct-zones"

// Typed errors returned by the external_ids persister.
var (
	// ErrNilClient is returned when the persister is constructed without an
	// OVSDB client.
	ErrNilClient = errors.New("ct: bridge external_ids client is nil")

	// ErrEmptyBridge is returned when the persister is constructed without
	// a bridge name.
	ErrEmptyBridge = errors.New("ct: bridge name must be non-empty")
)

// OVSExternalIDsPersister stores the allocation snapshot as JSON in the
// external_ids column of an OVS bridge, surviving daemon restarts alongside
// the bridge itself.
type OVSExternalIDsPersister struct {
	client BridgeExternalIDsClient
	bridge string
	key    string
}

// NewOVSExternalIDsPersister creates a persister writing to the named
// bridge under DefaultExternalIDsKey.
func NewOVSExternalIDsPersister(client BridgeExternalIDsClient, bridge string) (*OVSExternalIDsPersister, error) {
	if client == nil {
		return nil, ErrNilClient
	}
	if strings.TrimSpace(bridge) == "" {
		return nil, ErrEmptyBridge
	}
	return &OVSExternalIDsPersister{
		client: client,
		bridge: bridge,
		key:    DefaultExternalIDsKey,
	}, nil
}

// Save persists the snapshot as JSON under the persister's external_ids key.
func (p *OVSExternalIDsPersister) Save(ctx context.Context, allocations map[string]uint16) error {
	encoded, err := json.Marshal(allocations)
	if err != nil {
		return &ZoneError{Op: "persist", Err: err}
	}
	return p.client.SetBridgeExternalIDs(ctx, p.bridge, map[string]string{p.key: string(encoded)})
}

// Load restores the snapshot from the persister's external_ids key. A
// missing key yields an empty map.
func (p *OVSExternalIDsPersister) Load(ctx context.Context) (map[string]uint16, error) {
	ids, err := p.client.GetBridgeExternalIDs(ctx, p.bridge)
	if err != nil {
		return nil, err
	}

	raw, ok := ids[p.key]
	if !ok || raw == "" {
		return map[string]uint16{}, nil
	}

	var snapshot map[string]uint16
	if err := json.Unmarshal([]byte(raw), &snapshot); err != nil {
		return nil, &ZoneError{Op: "load", Err: ErrCorruptSnapshot}
	}
	return snapshot, nil
}

// Compile-time interface check.
var _ Persister = (*OVSExternalIDsPersister)(nil)
