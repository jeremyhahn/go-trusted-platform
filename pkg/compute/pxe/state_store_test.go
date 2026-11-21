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

package pxe

import (
	"context"
	"errors"
	"net"
	"reflect"
	"runtime"
	"sync"
	"testing"
)

// fakeDeviceStore is an in-memory DeviceStore standing in for the
// deployment datastore (#2028): it outlives the StateManagers built over it.
type fakeDeviceStore struct {
	mu      sync.Mutex
	devices map[string]*DeviceInfo
	// putErr, when set, fails the next Put once (a transient outage).
	putErr error
	// deleteErr, when set, fails every Delete (a datastore outage).
	deleteErr error
	// deleteStarted and deleteGate, when set, make Delete signal its start
	// and wait for the gate before it removes the record.
	deleteStarted chan struct{}
	deleteGate    chan struct{}
}

func newFakeDeviceStore() *fakeDeviceStore {
	return &fakeDeviceStore{devices: make(map[string]*DeviceInfo)}
}

func (f *fakeDeviceStore) Put(_ context.Context, device *DeviceInfo) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.putErr; err != nil {
		f.putErr = nil
		return err
	}
	f.devices[device.ID] = copyDeviceInfo(device)
	return nil
}

func (f *fakeDeviceStore) Delete(_ context.Context, deviceID string) error {
	f.mu.Lock()
	started, gate := f.deleteStarted, f.deleteGate
	f.deleteStarted, f.deleteGate = nil, nil
	f.mu.Unlock()
	if started != nil {
		close(started)
	}
	if gate != nil {
		<-gate
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deleteErr != nil {
		return f.deleteErr
	}
	delete(f.devices, deviceID)
	return nil
}

func (f *fakeDeviceStore) List(_ context.Context) ([]*DeviceInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*DeviceInfo, 0, len(f.devices))
	for _, d := range f.devices {
		out = append(out, copyDeviceInfo(d))
	}
	return out, nil
}

// TestStateManager_RestartOverDeviceStore registers a device, moves it
// through a transition, bumps its retry count and binds its identity, then
// builds a new StateManager over the same store: after Load the device is in
// the same state, with the same retry count, events and binding (#2028).
func TestStateManager_RestartOverDeviceStore(t *testing.T) {
	ctx := context.Background()
	store := newFakeDeviceStore()

	sm := NewStateManager(WithDeviceStore(store))
	mac, _ := net.ParseMAC("02:00:00:00:20:28")
	device := &DeviceInfo{ID: "dev-2028", MACAddress: mac, State: StateDiscovered}
	if err := sm.Register(device); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := sm.Transition("dev-2028", StateBooting, "pxe boot"); err != nil {
		t.Fatalf("Transition: %v", err)
	}
	if err := sm.UpdateDevice("dev-2028", func(d *DeviceInfo) error {
		d.RetryCount = 2
		d.IDevIDFingerprint = "0f2028"
		return nil
	}); err != nil {
		t.Fatalf("UpdateDevice: %v", err)
	}
	before, err := sm.Get("dev-2028")
	if err != nil {
		t.Fatalf("Get before restart: %v", err)
	}

	restarted := NewStateManager(WithDeviceStore(store))
	if err := restarted.Load(ctx); err != nil {
		t.Fatalf("Load: %v", err)
	}
	after, err := restarted.Get("dev-2028")
	if err != nil {
		t.Fatalf("Get after restart: %v", err)
	}
	if after.State != StateBooting || after.RetryCount != 2 || after.IDevIDFingerprint != "0f2028" {
		t.Fatalf("after restart: state %q retries %d ek %q", after.State, after.RetryCount, after.IDevIDFingerprint)
	}
	if len(after.Events) == 0 || !reflect.DeepEqual(before.Events, after.Events) {
		t.Fatalf("events not restored: before %d after %d", len(before.Events), len(after.Events))
	}
	byMAC, err := restarted.GetByMAC(mac)
	if err != nil || byMAC.ID != "dev-2028" {
		t.Fatalf("GetByMAC after restart: %v %v", byMAC, err)
	}

	// Unregister writes through too: a further restart finds no device.
	if err := restarted.Unregister("dev-2028"); err != nil {
		t.Fatalf("Unregister: %v", err)
	}
	again := NewStateManager(WithDeviceStore(store))
	if err := again.Load(ctx); err != nil {
		t.Fatalf("Load after Unregister: %v", err)
	}
	if again.Count() != 0 {
		t.Fatalf("device survived Unregister: count %d", again.Count())
	}
}

// A datastore Delete that fails must leave the device registered, so a later
// Unregister retries the delete instead of returning ErrDeviceNotFound while
// the stale record would restore the device on the next restart.
func TestStateManager_UnregisterDeleteFailureIsRetryable(t *testing.T) {
	store := newFakeDeviceStore()
	sm := NewStateManager(WithDeviceStore(store))
	mac, _ := net.ParseMAC("02:00:00:00:20:81")
	if err := sm.Register(&DeviceInfo{ID: "dev-2081", MACAddress: mac, State: StateDiscovered}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	store.mu.Lock()
	store.deleteErr = errors.New("datastore unavailable")
	store.mu.Unlock()
	if err := sm.Unregister("dev-2081"); err == nil {
		t.Fatal("Unregister with a failing datastore Delete returned nil")
	}
	if _, err := sm.Get("dev-2081"); err != nil {
		t.Fatalf("Get after failed Unregister: %v", err)
	}
	if d, err := sm.GetByMAC(mac); err != nil || d.ID != "dev-2081" {
		t.Fatalf("GetByMAC after failed Unregister: %v %v", d, err)
	}

	store.mu.Lock()
	store.deleteErr = nil
	store.mu.Unlock()
	if err := sm.Unregister("dev-2081"); err != nil {
		t.Fatalf("Unregister retry: %v", err)
	}
	store.mu.Lock()
	_, stored := store.devices["dev-2081"]
	store.mu.Unlock()
	if stored {
		t.Fatal("datastore still holds the device after the retried Unregister")
	}
	var notFound ErrDeviceNotFound
	if _, err := sm.Get("dev-2081"); !errors.As(err, &notFound) {
		t.Fatalf("Get after Unregister: want ErrDeviceNotFound, got %v", err)
	}
}

// TestStateManager_UnregisterRacingPersist: an UpdateDevice that lands while
// Unregister's datastore delete is in flight must not write the device back
// once Unregister has removed it (#2081 Codex r1).
func TestStateManager_UnregisterRacingPersist(t *testing.T) {
	for i := 0; i < 200; i++ {
		store := newFakeDeviceStore()
		sm := NewStateManager(WithDeviceStore(store))
		mac, _ := net.ParseMAC("02:00:00:00:20:82")
		if err := sm.Register(&DeviceInfo{ID: "dev-race", MACAddress: mac, State: StateDiscovered}); err != nil {
			t.Fatalf("Register: %v", err)
		}

		started, gate := make(chan struct{}), make(chan struct{})
		store.mu.Lock()
		store.deleteStarted, store.deleteGate = started, gate
		store.mu.Unlock()

		unregistered := make(chan error, 1)
		go func() { unregistered <- sm.Unregister("dev-race") }()
		<-started

		updated := make(chan error, 1)
		go func() {
			updated <- sm.UpdateDevice("dev-race", func(d *DeviceInfo) error {
				d.StateReason = "racing update"
				return nil
			})
		}()
		// Let UpdateDevice reach the store lock Unregister holds: it
		// writes before it swaps (#2081 Codex), so it blocks there and,
		// once the delete lands, finds the device gone.
		for j := 0; j < 10; j++ {
			runtime.Gosched()
		}
		close(gate)

		if err := <-unregistered; err != nil {
			t.Fatalf("Unregister: %v", err)
		}
		if err := <-updated; err != nil {
			var notFound ErrDeviceNotFound
			if !errors.As(err, &notFound) {
				t.Fatalf("UpdateDevice: %v", err)
			}
		}

		store.mu.Lock()
		_, stored := store.devices["dev-race"]
		store.mu.Unlock()
		if stored {
			t.Fatalf("iteration %d: datastore holds the device after Unregister", i)
		}
		if _, err := sm.Get("dev-race"); err == nil {
			t.Fatalf("iteration %d: device still registered after Unregister", i)
		}
	}
}
