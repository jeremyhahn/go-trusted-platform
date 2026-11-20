package pxe

import (
	"context"
	"net"
	"reflect"
	"sync"
	"testing"
)

// fakeDeviceStore is an in-memory DeviceStore standing in for the
// deployment datastore (#2028): it outlives the StateManagers built over it.
type fakeDeviceStore struct {
	mu      sync.Mutex
	devices map[string]*DeviceInfo
}

func newFakeDeviceStore() *fakeDeviceStore {
	return &fakeDeviceStore{devices: make(map[string]*DeviceInfo)}
}

func (f *fakeDeviceStore) Put(_ context.Context, device *DeviceInfo) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.devices[device.ID] = copyDeviceInfo(device)
	return nil
}

func (f *fakeDeviceStore) Delete(_ context.Context, deviceID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
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
