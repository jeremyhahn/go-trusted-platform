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

package ct

import (
	"context"
	"errors"
	"sync"
	"testing"
)

// memPersister is an in-memory Persister with optional injected failures.
type memPersister struct {
	mu      sync.Mutex
	saved   map[string]uint16
	saveErr error
	loadErr error
}

func (p *memPersister) Save(ctx context.Context, allocations map[string]uint16) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.saveErr != nil {
		return p.saveErr
	}
	saved := make(map[string]uint16, len(allocations))
	for k, v := range allocations {
		saved[k] = v
	}
	p.saved = saved
	return nil
}

func (p *memPersister) Load(ctx context.Context) (map[string]uint16, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.loadErr != nil {
		return nil, p.loadErr
	}
	return p.saved, nil
}

func TestZoneAllocator_Allocate(t *testing.T) {
	a := NewZoneAllocator(nil)
	ctx := context.Background()

	zone, err := a.Allocate(ctx, "firewall", "control-plane")
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if zone < MinZone {
		t.Fatalf("zone %d below MinZone", zone)
	}

	// Idempotent for the same owner/key.
	again, err := a.Allocate(ctx, "firewall", "control-plane")
	if err != nil {
		t.Fatalf("re-allocate: %v", err)
	}
	if again != zone {
		t.Errorf("allocate not idempotent: %d != %d", again, zone)
	}

	// Distinct pair gets a distinct zone.
	other, err := a.Allocate(ctx, "nat", "default")
	if err != nil {
		t.Fatalf("allocate nat: %v", err)
	}
	if other == zone {
		t.Error("distinct owners must not share a zone")
	}
}

func TestZoneAllocator_AllocateDeterministic(t *testing.T) {
	ctx := context.Background()

	a := NewZoneAllocator(nil)
	b := NewZoneAllocator(nil)

	zoneA, err := a.Allocate(ctx, "firewall", "storage")
	if err != nil {
		t.Fatalf("allocate a: %v", err)
	}
	zoneB, err := b.Allocate(ctx, "firewall", "storage")
	if err != nil {
		t.Fatalf("allocate b: %v", err)
	}
	if zoneA != zoneB {
		t.Errorf("allocation not deterministic: %d != %d", zoneA, zoneB)
	}
}

func TestZoneAllocator_AllocateInvalidOwner(t *testing.T) {
	a := NewZoneAllocator(nil)
	ctx := context.Background()

	if _, err := a.Allocate(ctx, "", "key"); !errors.Is(err, ErrInvalidOwner) {
		t.Errorf("empty owner: expected ErrInvalidOwner, got %v", err)
	}
	if _, err := a.Allocate(ctx, "owner", ""); !errors.Is(err, ErrInvalidOwner) {
		t.Errorf("empty key: expected ErrInvalidOwner, got %v", err)
	}
}

func TestZoneAllocator_CollisionProbing(t *testing.T) {
	a := NewZoneAllocator(nil)
	ctx := context.Background()

	// Force a collision: occupy the hash slot of a known name, then
	// allocate that name and expect the next free slot.
	target := hashZone("firewall/collide")
	a.mu.Lock()
	a.byName["synthetic/occupier"] = target
	a.byZone[target] = "synthetic/occupier"
	a.mu.Unlock()

	zone, err := a.Allocate(ctx, "firewall", "collide")
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if zone == target {
		t.Error("collision must probe to a different slot")
	}
	if zone != nextZone(target) {
		t.Errorf("expected linear probe to %d, got %d", nextZone(target), zone)
	}
}

func TestZoneAllocator_Exhaustion(t *testing.T) {
	a := NewZoneAllocator(nil)
	ctx := context.Background()

	// Fill the entire space synthetically.
	a.mu.Lock()
	for z := int(MinZone); z <= int(MaxZone); z++ {
		a.byZone[uint16(z)] = "synthetic"
	}
	a.mu.Unlock()

	if _, err := a.Allocate(ctx, "firewall", "overflow"); !errors.Is(err, ErrZoneExhausted) {
		t.Errorf("expected ErrZoneExhausted, got %v", err)
	}
}

func TestZoneAllocator_Release(t *testing.T) {
	a := NewZoneAllocator(nil)
	ctx := context.Background()

	zone, err := a.Allocate(ctx, "firewall", "control-plane")
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}

	if err := a.Release(ctx, "firewall", "control-plane"); err != nil {
		t.Fatalf("release: %v", err)
	}
	if _, ok := a.Lookup("firewall", "control-plane"); ok {
		t.Error("released allocation still present")
	}

	// Re-allocating lands on the same deterministic slot.
	again, err := a.Allocate(ctx, "firewall", "control-plane")
	if err != nil {
		t.Fatalf("re-allocate: %v", err)
	}
	if again != zone {
		t.Errorf("re-allocation should reuse slot %d, got %d", zone, again)
	}
}

func TestZoneAllocator_ReleaseErrors(t *testing.T) {
	a := NewZoneAllocator(nil)
	ctx := context.Background()

	if err := a.Release(ctx, "firewall", "ghost"); !errors.Is(err, ErrZoneNotAllocated) {
		t.Errorf("expected ErrZoneNotAllocated, got %v", err)
	}
	if err := a.Release(ctx, "", "x"); !errors.Is(err, ErrInvalidOwner) {
		t.Errorf("expected ErrInvalidOwner, got %v", err)
	}
}

func TestZoneAllocator_LookupAndSnapshot(t *testing.T) {
	a := NewZoneAllocator(nil)
	ctx := context.Background()

	if _, ok := a.Lookup("firewall", "absent"); ok {
		t.Error("lookup of absent allocation must report false")
	}

	zone, err := a.Allocate(ctx, "lb", "vip-1")
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}

	got, ok := a.Lookup("lb", "vip-1")
	if !ok || got != zone {
		t.Errorf("lookup = (%d, %v), want (%d, true)", got, ok, zone)
	}

	snapshot := a.Snapshot()
	if snapshot["lb/vip-1"] != zone {
		t.Errorf("snapshot missing lb/vip-1=%d: %v", zone, snapshot)
	}

	// Snapshot is a copy.
	snapshot["lb/vip-1"] = 0
	if got, _ := a.Lookup("lb", "vip-1"); got != zone {
		t.Error("mutating the snapshot must not affect the allocator")
	}
}

func TestZoneAllocator_PersistOnMutate(t *testing.T) {
	p := &memPersister{}
	a := NewZoneAllocator(p)
	ctx := context.Background()

	zone, err := a.Allocate(ctx, "firewall", "control-plane")
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if p.saved["firewall/control-plane"] != zone {
		t.Errorf("allocation not persisted: %v", p.saved)
	}

	if err := a.Release(ctx, "firewall", "control-plane"); err != nil {
		t.Fatalf("release: %v", err)
	}
	if len(p.saved) != 0 {
		t.Errorf("release not persisted: %v", p.saved)
	}
}

func TestZoneAllocator_PersistError(t *testing.T) {
	p := &memPersister{saveErr: errors.New("ovsdb down")}
	a := NewZoneAllocator(p)
	ctx := context.Background()

	_, err := a.Allocate(ctx, "firewall", "control-plane")
	if err == nil {
		t.Fatal("expected persist error")
	}
	var zoneErr *ZoneError
	if !errors.As(err, &zoneErr) {
		t.Errorf("expected ZoneError, got %T", err)
	}
}

func TestZoneAllocator_Restore(t *testing.T) {
	p := &memPersister{saved: map[string]uint16{"firewall/control-plane": 42, "nat/default": 7}}
	a := NewZoneAllocator(p)
	ctx := context.Background()

	if err := a.Restore(ctx); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if zone, ok := a.Lookup("firewall", "control-plane"); !ok || zone != 42 {
		t.Errorf("restored zone = (%d, %v), want (42, true)", zone, ok)
	}

	// The restored slot is honored: a new allocation never collides with it.
	other, err := a.Allocate(ctx, "lb", "vip-1")
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if other == 42 || other == 7 {
		t.Errorf("new allocation %d collides with restored zones", other)
	}
}

func TestZoneAllocator_RestoreErrors(t *testing.T) {
	ctx := context.Background()

	// No persister: no-op.
	if err := NewZoneAllocator(nil).Restore(ctx); err != nil {
		t.Errorf("nil-persister restore: %v", err)
	}

	// Load failure propagates.
	pErr := &memPersister{loadErr: errors.New("ovsdb down")}
	if err := NewZoneAllocator(pErr).Restore(ctx); err == nil {
		t.Error("expected load error")
	}

	// Out-of-range zone.
	pBad := &memPersister{saved: map[string]uint16{"firewall/x": 0}}
	if err := NewZoneAllocator(pBad).Restore(ctx); !errors.Is(err, ErrCorruptSnapshot) {
		t.Errorf("expected ErrCorruptSnapshot, got %v", err)
	}

	// Duplicate zone assignment.
	pDup := &memPersister{saved: map[string]uint16{"a/x": 5, "b/y": 5}}
	if err := NewZoneAllocator(pDup).Restore(ctx); !errors.Is(err, ErrCorruptSnapshot) {
		t.Errorf("expected ErrCorruptSnapshot, got %v", err)
	}
}

func TestZoneAllocator_Concurrency(t *testing.T) {
	a := NewZoneAllocator(nil)
	ctx := context.Background()

	const goroutines = 32
	var wg sync.WaitGroup
	zones := make([]uint16, goroutines)
	errs := make([]error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			zones[i], errs[i] = a.Allocate(ctx, "fw", string(rune('a'+i)))
		}(i)
	}
	wg.Wait()

	seen := make(map[uint16]int, goroutines)
	for i := 0; i < goroutines; i++ {
		if errs[i] != nil {
			t.Fatalf("allocate %d: %v", i, errs[i])
		}
		seen[zones[i]]++
	}
	if len(seen) != goroutines {
		t.Errorf("expected %d disjoint zones, got %d", goroutines, len(seen))
	}
}

// fakeIDsClient implements BridgeExternalIDsClient in memory.
type fakeIDsClient struct {
	mu     sync.Mutex
	ids    map[string]map[string]string
	setErr error
	getErr error
}

func (f *fakeIDsClient) SetBridgeExternalIDs(ctx context.Context, name string, ids map[string]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.setErr != nil {
		return f.setErr
	}
	if f.ids == nil {
		f.ids = make(map[string]map[string]string)
	}
	bridge, ok := f.ids[name]
	if !ok {
		bridge = make(map[string]string)
		f.ids[name] = bridge
	}
	for k, v := range ids {
		bridge[k] = v
	}
	return nil
}

func (f *fakeIDsClient) GetBridgeExternalIDs(ctx context.Context, name string) (map[string]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.ids[name], nil
}

func TestNewOVSExternalIDsPersister(t *testing.T) {
	client := &fakeIDsClient{}

	p, err := NewOVSExternalIDsPersister(client, "br-int")
	if err != nil {
		t.Fatalf("new persister: %v", err)
	}
	if p.key != DefaultExternalIDsKey {
		t.Errorf("key = %q, want %q", p.key, DefaultExternalIDsKey)
	}

	if _, err := NewOVSExternalIDsPersister(nil, "br-int"); !errors.Is(err, ErrNilClient) {
		t.Errorf("nil client: expected ErrNilClient, got %v", err)
	}
	if _, err := NewOVSExternalIDsPersister(client, "  "); !errors.Is(err, ErrEmptyBridge) {
		t.Errorf("empty bridge: expected ErrEmptyBridge, got %v", err)
	}
}

func TestOVSExternalIDsPersister_SaveLoad(t *testing.T) {
	client := &fakeIDsClient{}
	p, err := NewOVSExternalIDsPersister(client, "br-int")
	if err != nil {
		t.Fatalf("new persister: %v", err)
	}
	ctx := context.Background()

	want := map[string]uint16{"firewall/control-plane": 42, "nat/default": 7}
	if err := p.Save(ctx, want); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err := p.Load(ctx)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("load = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("load[%q] = %d, want %d", k, got[k], v)
		}
	}
}

func TestOVSExternalIDsPersister_LoadEmpty(t *testing.T) {
	client := &fakeIDsClient{}
	p, err := NewOVSExternalIDsPersister(client, "br-int")
	if err != nil {
		t.Fatalf("new persister: %v", err)
	}

	got, err := p.Load(context.Background())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty snapshot, got %v", got)
	}
}

func TestOVSExternalIDsPersister_Errors(t *testing.T) {
	ctx := context.Background()

	// Transport failures propagate.
	failing := &fakeIDsClient{setErr: errors.New("set failed"), getErr: errors.New("get failed")}
	p, err := NewOVSExternalIDsPersister(failing, "br-int")
	if err != nil {
		t.Fatalf("new persister: %v", err)
	}
	if err := p.Save(ctx, map[string]uint16{"a/b": 1}); err == nil {
		t.Error("expected save error")
	}
	if _, err := p.Load(ctx); err == nil {
		t.Error("expected load error")
	}

	// Corrupt JSON yields ErrCorruptSnapshot.
	corrupt := &fakeIDsClient{}
	if err := corrupt.SetBridgeExternalIDs(ctx, "br-int", map[string]string{DefaultExternalIDsKey: "{not-json"}); err != nil {
		t.Fatalf("seed corrupt value: %v", err)
	}
	p2, err := NewOVSExternalIDsPersister(corrupt, "br-int")
	if err != nil {
		t.Fatalf("new persister: %v", err)
	}
	if _, err := p2.Load(ctx); !errors.Is(err, ErrCorruptSnapshot) {
		t.Errorf("expected ErrCorruptSnapshot, got %v", err)
	}
}

func TestZoneError_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("boom")

	withName := &ZoneError{Op: "allocate", Name: "fw/x", Err: inner}
	if withName.Error() != "ct: allocate fw/x: boom" {
		t.Errorf("unexpected message: %s", withName.Error())
	}
	if !errors.Is(withName, inner) {
		t.Error("Unwrap must expose the inner error")
	}

	withoutName := &ZoneError{Op: "load", Err: inner}
	if withoutName.Error() != "ct: load: boom" {
		t.Errorf("unexpected message: %s", withoutName.Error())
	}
}
