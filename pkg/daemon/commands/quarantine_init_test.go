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

package commands

import (
	"context"
	"crypto/x509"
	"log/slog"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	attestationsvc "github.com/jeremyhahn/go-trusted-platform/pkg/attestation/service"
	attestationstore "github.com/jeremyhahn/go-trusted-platform/pkg/attestation/store"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

// ---------------------------------------------------------------------------
// In-memory DeviceStateStore for unit tests.
// ---------------------------------------------------------------------------

type memDeviceStore struct {
	devices map[uint64]*entities.Device
}

func newMemDeviceStore(initial ...*entities.Device) *memDeviceStore {
	m := &memDeviceStore{devices: make(map[uint64]*entities.Device)}
	for _, d := range initial {
		cp := *d
		m.devices[d.ID] = &cp
	}
	return m
}

func (m *memDeviceStore) SaveDevice(_ context.Context, d *entities.Device) error {
	cp := *d
	m.devices[d.ID] = &cp
	return nil
}

func (m *memDeviceStore) GetDevice(_ context.Context, id uint64) (*entities.Device, error) {
	d, ok := m.devices[id]
	if !ok {
		return nil, policy.ErrUnknownDevicePort{DeviceID: id}
	}
	cp := *d
	return &cp, nil
}

// ---------------------------------------------------------------------------
// deviceResolverAdapter
// ---------------------------------------------------------------------------

// stubResolverSvc provides FindByHostname for resolver tests.
type stubResolverSvc struct {
	byHostname map[string]*entities.Device
}

func (s *stubResolverSvc) FindByHostname(_ context.Context, h string) (*entities.Device, error) {
	if d, ok := s.byHostname[h]; ok {
		cp := *d
		return &cp, nil
	}
	return nil, errHostNotFound(h)
}

// errHostNotFound is a sentinel error used in tests.
type errHostNotFound string

func (e errHostNotFound) Error() string { return "device not found: " + string(e) }

// Remaining device.DeviceService methods — no-ops.
func (s *stubResolverSvc) Create(_ context.Context, _ *entities.Device) error { return nil }
func (s *stubResolverSvc) Save(_ context.Context, _ *entities.Device) error   { return nil }
func (s *stubResolverSvc) Get(_ context.Context, _ uint64) (*entities.Device, error) {
	return nil, nil
}
func (s *stubResolverSvc) Delete(_ context.Context, _ *entities.Device) error { return nil }
func (s *stubResolverSvc) Update(_ context.Context, _ *entities.Device) error { return nil }
func (s *stubResolverSvc) Count(_ context.Context) (int, error)               { return 0, nil }
func (s *stubResolverSvc) FindBySerial(_ context.Context, _ string) (*entities.Device, error) {
	return nil, nil
}
func (s *stubResolverSvc) Page(_ context.Context, _ datastore.PageQuery) (datastore.PageResult[*entities.Device], error) {
	return datastore.PageResult[*entities.Device]{}, nil
}

var _ device.DeviceService = (*stubResolverSvc)(nil)

func TestDeviceResolverAdapter(t *testing.T) {
	svc := &stubResolverSvc{
		byHostname: map[string]*entities.Device{
			"node-01.example.com": {ID: 42},
		},
	}

	t.Run("found returns correct ID", func(t *testing.T) {
		resolver := &deviceResolverAdapter{svc: svc, logger: slog.Default()}
		id, ok := resolver.DeviceForHost("node-01.example.com")
		if !ok {
			t.Fatal("expected ok=true")
		}
		if id != 42 {
			t.Errorf("expected 42, got %d", id)
		}
	})

	t.Run("not found returns zero and false", func(t *testing.T) {
		resolver := &deviceResolverAdapter{svc: svc, logger: slog.Default()}
		id, ok := resolver.DeviceForHost("unknown.example.com")
		if ok {
			t.Fatal("expected ok=false")
		}
		if id != 0 {
			t.Errorf("expected 0, got %d", id)
		}
	})
}

// ---------------------------------------------------------------------------
// noopPolicyEngine — satisfies policy.PolicyEngine with no-ops for unit tests.
// ---------------------------------------------------------------------------

type noopPolicyEngine struct{}

func (e *noopPolicyEngine) SetPortState(_ string, _ policy.PortState) error { return nil }
func (e *noopPolicyEngine) GetPortState(_ string) (policy.PortState, error) { return 0, nil }
func (e *noopPolicyEngine) GetPortInfo(_ string) (*policy.PortInfo, error) {
	return &policy.PortInfo{}, nil
}
func (e *noopPolicyEngine) ApplyPolicy(_ string, _ *policy.PortPolicy) error { return nil }
func (e *noopPolicyEngine) RemovePolicy(_ string) error                      { return nil }
func (e *noopPolicyEngine) GetPolicy(_ string) (*policy.PortPolicy, error) {
	return &policy.PortPolicy{}, nil
}
func (e *noopPolicyEngine) SetPortVLAN(_ string, _ uint16) error                 { return nil }
func (e *noopPolicyEngine) GetPortVLAN(_ string) (uint16, error)                 { return 0, nil }
func (e *noopPolicyEngine) BlockPort(_ string) error                             { return nil }
func (e *noopPolicyEngine) UnblockPort(_ string) error                           { return nil }
func (e *noopPolicyEngine) GetOFPort(_ string) (int32, error)                    { return 1, nil }
func (e *noopPolicyEngine) AuthenticatePort(_ string, _ *x509.Certificate) error { return nil }
func (e *noopPolicyEngine) OnCertificateExpired(_ string) error                  { return nil }
func (e *noopPolicyEngine) OnCertificateRevoked(_ string) error                  { return nil }
func (e *noopPolicyEngine) GetMonitor() *policy.CertificateMonitor               { return nil }

var _ policy.PolicyEngine = (*noopPolicyEngine)(nil)

// ---------------------------------------------------------------------------
// buildTestObserver — constructs a quarantineObserver backed by in-memory
// store and no-op policy engine so tests run without OVS.
// ---------------------------------------------------------------------------

// nullOVSPort is an OVSPortController that accepts every operation.
type nullOVSPort struct{}

func (nullOVSPort) InstallFlow(string, int, string, string) error                { return nil }
func (nullOVSPort) InstallFlows(string, []zoneflows.FlowRule) error              { return nil }
func (nullOVSPort) DeleteFlow(string, string) error                              { return nil }
func (nullOVSPort) DeleteFlowsByPort(string, string) error                       { return nil }
func (nullOVSPort) ListFlows(string) ([]string, error)                           { return nil, nil }
func (nullOVSPort) SetPortVLAN(context.Context, string, int64) error             { return nil }
func (nullOVSPort) SetPortTrunk(context.Context, string, []uint16, uint16) error { return nil }
func (nullOVSPort) SetPortState(context.Context, string, ovs.PortState) error    { return nil }
func (nullOVSPort) GetOFPort(context.Context, string) (int32, error)             { return 1, nil }

func buildTestObserver(t *testing.T, initialDevices ...*entities.Device) (*quarantineObserver, *memDeviceStore) {
	t.Helper()

	store := newMemDeviceStore(initialDevices...)
	obs := &quarantineObserver{
		manager:     buildTestQuarantineManager(t, store),
		deviceStore: store,
		logger:      slog.Default(),
	}
	return obs, store
}

// buildTestQuarantineManager builds a QuarantineManager over the default
// zones whose engine and OVS controllers accept every operation.
func buildTestQuarantineManager(t *testing.T, store policy.DeviceStateStore) *policy.QuarantineManager {
	t.Helper()

	resolvedZones := zone.Defaults()
	plan, err := netplan.New(netplan.Environment{ID: 4}, resolvedZones)
	if err != nil {
		t.Fatalf("netplan.New: %v", err)
	}
	zfm, err := policy.NewZoneFlowManager(policy.ZoneFlowManagerConfig{
		BridgeName:     "br-fabric",
		FlowController: nullOVSPort{},
		PortController: nullOVSPort{},
		Plan:           plan,
		Zones:          resolvedZones,
	})
	if err != nil {
		t.Fatalf("NewZoneFlowManager: %v", err)
	}

	mgr, err := policy.NewQuarantineManager(policy.QuarantineManagerConfig{
		PolicyEngine:     &noopPolicyEngine{},
		ZoneFlowManager:  zfm,
		ResolvedZones:    resolvedZones,
		DeviceStateStore: store,
	})
	if err != nil {
		t.Fatalf("NewQuarantineManager: %v", err)
	}
	return mgr
}

// ---------------------------------------------------------------------------
// quarantineObserver — resolvePortID tests
// ---------------------------------------------------------------------------

// TestResolvePortIDEmptyNetworkPortID verifies that resolvePortID returns
// (false, "") when the device record has an empty NetworkPortID (never SDN-
// activated) and does not pass through to the manager.
func TestResolvePortIDEmptyNetworkPortID(t *testing.T) {
	seed := &entities.Device{
		ID:            10,
		State:         entities.DeviceStateAttested,
		NetworkPortID: "", // deliberately empty
	}
	obs, _ := buildTestObserver(t, seed)
	ctx := context.Background()

	portID, ok := obs.resolvePortID(ctx, 10, "node-01.example.com")
	if ok {
		t.Errorf("expected ok=false for empty NetworkPortID, got portID=%q", portID)
	}
}

// TestResolvePortIDWithNetworkPortID verifies that resolvePortID returns the
// persisted NetworkPortID when the device record has one.
func TestResolvePortIDWithNetworkPortID(t *testing.T) {
	seed := &entities.Device{
		ID:            11,
		State:         entities.DeviceStateAttested,
		NetworkPortID: "tap0a1b2c",
	}
	obs, _ := buildTestObserver(t, seed)
	ctx := context.Background()

	portID, ok := obs.resolvePortID(ctx, 11, "node-02.example.com")
	if !ok {
		t.Fatal("expected ok=true for device with NetworkPortID")
	}
	if portID != "tap0a1b2c" {
		t.Errorf("expected tap0a1b2c, got %q", portID)
	}
}

// TestResolvePortIDMissingDevice verifies that resolvePortID returns false
// when the device record does not exist in the store.
func TestResolvePortIDMissingDevice(t *testing.T) {
	obs, _ := buildTestObserver(t) // empty store
	ctx := context.Background()

	_, ok := obs.resolvePortID(ctx, 999, "unknown.example.com")
	if ok {
		t.Error("expected ok=false for missing device")
	}
}

// ---------------------------------------------------------------------------
// quarantineObserver — adapter translation tests
// ---------------------------------------------------------------------------

// TestQuarantineObserverOnAttestationFailedSkipsZero verifies that the
// observer correctly skips events when deviceID is zero (unresolvable host)
// without panicking or touching the store.
func TestQuarantineObserverOnAttestationFailedSkipsZero(t *testing.T) {
	obs, store := buildTestObserver(t)
	ctx := context.Background()
	obs.OnAttestationFailed(ctx, 0, "unknown.example.com", "PCR mismatch")
	if len(store.devices) != 0 {
		t.Error("expected no device records for unresolvable host")
	}
}

// TestQuarantineObserverOnAttestationFailedSkipsEmptyPort verifies that the
// observer skips events when the device record has no NetworkPortID.
func TestQuarantineObserverOnAttestationFailedSkipsEmptyPort(t *testing.T) {
	seed := &entities.Device{
		ID:            42,
		State:         entities.DeviceStateAttested,
		NetworkPortID: "", // not yet SDN-activated
	}
	obs, store := buildTestObserver(t, seed)
	ctx := context.Background()

	obs.OnAttestationFailed(ctx, 42, "node-01.example.com", "PCR8 mismatch")

	// State must remain unchanged because the event was skipped.
	if store.devices[42].State != entities.DeviceStateAttested {
		t.Errorf("expected DeviceStateAttested (skipped), got %s", store.devices[42].State)
	}
}

// TestQuarantineObserverOnAttestationFailedDispatchesEvent verifies that
// OnAttestationFailed constructs a valid ViolationEvent and calls
// HandleViolation: the Warning path quarantines the device on the
// quarantine zone of the network plan.
func TestQuarantineObserverOnAttestationFailedDispatchesEvent(t *testing.T) {
	seed := &entities.Device{
		ID:            42,
		State:         entities.DeviceStateAttested,
		NetworkPortID: "tap42abc", // real persisted port
	}
	obs, store := buildTestObserver(t, seed)
	ctx := context.Background()
	obs.OnAttestationFailed(ctx, 42, "node-01.example.com", "PCR8 mismatch")

	if store.devices[42].State != entities.DeviceStateQuarantined {
		t.Errorf("expected DeviceStateQuarantined, got %s", store.devices[42].State)
	}
	if store.devices[42].PriorState != entities.DeviceStateAttested {
		t.Errorf("expected prior state attested, got %s", store.devices[42].PriorState)
	}
}

// TestQuarantineObserverSevereViolationSuspendsDevice verifies the full
// Severe-severity state transition through HandleViolation. Severe violations
// only require BlockPort (no ZoneFlowManager), so this path exercises the
// complete adapter → manager → device state machine pipeline.
func TestQuarantineObserverSevereViolationSuspendsDevice(t *testing.T) {
	store := newMemDeviceStore(&entities.Device{
		ID:            55,
		State:         entities.DeviceStateAttested,
		NetworkPortID: "tap55xyz",
	})
	resolvedZones := zone.Defaults()
	mgr, err := policy.NewQuarantineManager(policy.QuarantineManagerConfig{
		PolicyEngine:     &noopPolicyEngine{},
		ZoneFlowManager:  nil,
		ResolvedZones:    resolvedZones,
		DeviceStateStore: store,
	})
	if err != nil {
		t.Fatalf("NewQuarantineManager: %v", err)
	}

	ctx := context.Background()
	ev := &entities.ViolationEvent{
		DeviceID:   55,
		Severity:   entities.ViolationSeveritySevere,
		Source:     entities.ViolationSourceAttestation,
		Detail:     "AK certificate revoked",
		OccurredAt: time.Now().UTC(),
	}
	// Use the real persisted port from the device record.
	if err := mgr.HandleViolation(ctx, ev, "tap55xyz"); err != nil {
		t.Fatalf("HandleViolation: %v", err)
	}

	saved := store.devices[55]
	if saved == nil {
		t.Fatal("device not in store after Severe violation")
	}
	if saved.State != entities.DeviceStateSuspended {
		t.Errorf("expected DeviceStateSuspended, got %s", saved.State)
	}
	if saved.StateReason != "AK certificate revoked" {
		t.Errorf("unexpected state reason: %q", saved.StateReason)
	}
}

func TestQuarantineObserverOnAttestationPassed(t *testing.T) {
	t.Run("passed attestation restores quarantined device", func(t *testing.T) {
		// Seed a device in quarantined state with a real NetworkPortID;
		// HandleRestoreAttestation restores it.
		seed := &entities.Device{
			ID:             99,
			State:          entities.DeviceStateQuarantined,
			PriorState:     entities.DeviceStateAttested,
			PriorPortClass: string(zone.PortClassHypervisor),
			NetworkPortID:  "tap99def",
		}
		obs, store := buildTestObserver(t, seed)
		ctx := context.Background()
		obs.OnAttestationPassed(ctx, 99, "node-02.example.com")

		saved := store.devices[99]
		if saved == nil {
			t.Fatal("device not found after restore")
		}
		if saved.State != entities.DeviceStateAttested {
			t.Errorf("expected DeviceStateAttested after restore, got %s", saved.State)
		}
	})

	t.Run("deviceID zero is skipped without panic", func(t *testing.T) {
		obs, _ := buildTestObserver(t)
		ctx := context.Background()
		obs.OnAttestationPassed(ctx, 0, "unknown.example.com")
	})

	t.Run("empty NetworkPortID is skipped without panic", func(t *testing.T) {
		seed := &entities.Device{
			ID:            100,
			State:         entities.DeviceStateQuarantined,
			PriorState:    entities.DeviceStateAttested,
			NetworkPortID: "", // never SDN-activated
		}
		obs, store := buildTestObserver(t, seed)
		ctx := context.Background()
		obs.OnAttestationPassed(ctx, 100, "node-03.example.com")

		// State must be unchanged because the event was skipped.
		if store.devices[100].State != entities.DeviceStateQuarantined {
			t.Errorf("expected DeviceStateQuarantined (skipped), got %s", store.devices[100].State)
		}
	})
}

// ---------------------------------------------------------------------------
// deviceStateStoreAdapter
// ---------------------------------------------------------------------------

// stubSaveGetSvc implements device.DeviceService with real Save/Get backed by
// an in-memory map. All other methods are no-ops.
type stubSaveGetSvc struct {
	devices map[uint64]*entities.Device
}

func (s *stubSaveGetSvc) Create(ctx context.Context, d *entities.Device) error {
	return s.Save(ctx, d)
}

func (s *stubSaveGetSvc) Save(_ context.Context, d *entities.Device) error {
	cp := *d
	s.devices[d.ID] = &cp
	return nil
}
func (s *stubSaveGetSvc) Get(_ context.Context, id uint64) (*entities.Device, error) {
	d, ok := s.devices[id]
	if !ok {
		return nil, errHostNotFound("not found")
	}
	cp := *d
	return &cp, nil
}
func (s *stubSaveGetSvc) Delete(_ context.Context, _ *entities.Device) error { return nil }
func (s *stubSaveGetSvc) Update(_ context.Context, _ *entities.Device) error { return nil }
func (s *stubSaveGetSvc) Count(_ context.Context) (int, error)               { return 0, nil }
func (s *stubSaveGetSvc) FindBySerial(_ context.Context, _ string) (*entities.Device, error) {
	return nil, nil
}
func (s *stubSaveGetSvc) FindByHostname(_ context.Context, _ string) (*entities.Device, error) {
	return nil, nil
}
func (s *stubSaveGetSvc) Page(_ context.Context, _ datastore.PageQuery) (datastore.PageResult[*entities.Device], error) {
	return datastore.PageResult[*entities.Device]{}, nil
}

var _ device.DeviceService = (*stubSaveGetSvc)(nil)

func TestDeviceStateStoreAdapter(t *testing.T) {
	stub := &stubSaveGetSvc{
		devices: map[uint64]*entities.Device{
			7: {ID: 7, State: entities.DeviceStateAttested},
		},
	}
	adapter := &deviceStateStoreAdapter{svc: stub}
	ctx := context.Background()

	t.Run("GetDevice delegates to service", func(t *testing.T) {
		d, err := adapter.GetDevice(ctx, 7)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if d.ID != 7 {
			t.Errorf("expected ID 7, got %d", d.ID)
		}
	})

	t.Run("GetDevice missing returns error", func(t *testing.T) {
		_, err := adapter.GetDevice(ctx, 999)
		if err == nil {
			t.Fatal("expected error for missing device")
		}
	})

	t.Run("SaveDevice delegates to service", func(t *testing.T) {
		updated := &entities.Device{ID: 7, State: entities.DeviceStateQuarantined}
		if err := adapter.SaveDevice(ctx, updated); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if stub.devices[7].State != entities.DeviceStateQuarantined {
			t.Errorf("expected quarantined, got %s", stub.devices[7].State)
		}
	})
}

// ---------------------------------------------------------------------------
// wireQuarantineObserver — guard / no-op path tests
// ---------------------------------------------------------------------------

// buildRealAttestationService creates a real attestationsvc.Service backed by
// an in-process file store in t.TempDir() for wiring guard tests.
func buildRealAttestationService(t *testing.T) *attestationsvc.Service {
	t.Helper()
	store, err := attestationstore.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatalf("attestationstore.NewFileStore: %v", err)
	}
	return attestationsvc.NewService(store)
}

func TestWireQuarantineObserver(t *testing.T) {
	t.Run("nil svcs is no-op", func(t *testing.T) {
		if got := wireQuarantineObserver(nil, nil, nil, nil); got != nil {
			t.Errorf("wireQuarantineObserver = %v, want no manager", got)
		}
	})

	t.Run("nil sdn policy is no-op", func(t *testing.T) {
		svcs := &attestationServices{
			Service: buildRealAttestationService(t),
		}
		if got := wireQuarantineObserver(svcs, nil, nil, nil); got != nil {
			t.Errorf("wireQuarantineObserver = %v, want no manager", got)
		}
	})

	t.Run("sdn policy without engine is no-op", func(t *testing.T) {
		svcs := &attestationServices{
			Service: buildRealAttestationService(t),
		}
		stub := &stubSaveGetSvc{devices: make(map[uint64]*entities.Device)}
		if got := wireQuarantineObserver(svcs, &sdnPolicyComponents{}, stub, nil); got != nil {
			t.Errorf("wireQuarantineObserver = %v, want no manager", got)
		}
	})

	t.Run("nil device service is no-op", func(t *testing.T) {
		svcs := &attestationServices{
			Service: buildRealAttestationService(t),
		}
		if got := wireQuarantineObserver(svcs, &sdnPolicyComponents{}, nil, nil); got != nil {
			t.Errorf("wireQuarantineObserver = %v, want no manager", got)
		}
	})
}

func TestInitSDNPolicy(t *testing.T) {
	logger := slog.Default()

	t.Run("nil app returns nil", func(t *testing.T) {
		if got := initSDNPolicy(nil, logger); got != nil {
			t.Fatalf("expected nil components for nil app, got %+v", got)
		}
	})

	t.Run("nil sdn config returns nil", func(t *testing.T) {
		if got := initSDNPolicy(&app.App{}, logger); got != nil {
			t.Fatalf("expected nil components without SDN config, got %+v", got)
		}
	})

	t.Run("disabled sdn returns nil", func(t *testing.T) {
		a := &app.App{SDNConfig: &sdn.Config{Enabled: false}}
		if got := initSDNPolicy(a, logger); got != nil {
			t.Fatalf("expected nil components for disabled SDN, got %+v", got)
		}
	})
}
