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

package policy

import (
	"context"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// ---- in-memory device state store for tests ----

type memDeviceStore struct {
	devices map[uint64]*entities.Device
}

func newMemDeviceStore(devs ...*entities.Device) *memDeviceStore {
	m := &memDeviceStore{devices: make(map[uint64]*entities.Device)}
	for _, d := range devs {
		m.devices[d.ID] = d
	}
	return m
}

func (s *memDeviceStore) SaveDevice(_ context.Context, d *entities.Device) error {
	s.devices[d.ID] = d
	return nil
}

func (s *memDeviceStore) GetDevice(_ context.Context, id uint64) (*entities.Device, error) {
	d, ok := s.devices[id]
	if !ok {
		return nil, &errQMNotFound{}
	}
	return d, nil
}

type errQMNotFound struct{}

func (e *errQMNotFound) Error() string { return "device not found" }

// ---- zone configs for tests ----

func resolvedZonesWithQuarantine() []zone.ZoneConfig {
	return []zone.ZoneConfig{
		{Name: zone.ZoneControlPlane},
		{Name: zone.ZoneQuarantine, LifecycleRole: zone.LifecycleRoleQuarantine},
		{Name: zone.ZoneProvisioning, LifecycleRole: zone.LifecycleRoleProvisioning},
	}
}

func resolvedZonesWithoutQuarantine() []zone.ZoneConfig {
	return []zone.ZoneConfig{
		{Name: zone.ZoneControlPlane},
		{Name: zone.ZoneProvisioning, LifecycleRole: zone.LifecycleRoleProvisioning},
	}
}

// ---- mock policy engine ----

type mockPolicyEngine struct {
	blockedPorts   map[string]bool
	portStates     map[string]PortState
	blockPortErr   error
	unblockPortErr error
	setStateErr    error
}

func newMockPolicyEngine() *mockPolicyEngine {
	return &mockPolicyEngine{
		blockedPorts: make(map[string]bool),
		portStates:   make(map[string]PortState),
	}
}

func (m *mockPolicyEngine) SetPortState(portID string, state PortState) error {
	if m.setStateErr != nil {
		return m.setStateErr
	}
	m.portStates[portID] = state
	return nil
}

func (m *mockPolicyEngine) GetPortState(portID string) (PortState, error) {
	s, ok := m.portStates[portID]
	if !ok {
		return PortStateUnconnected, ErrPortNotFound
	}
	return s, nil
}

func (m *mockPolicyEngine) GetPortInfo(portID string) (*PortInfo, error) { return nil, nil }

func (m *mockPolicyEngine) ApplyPolicy(portID string, p *PortPolicy) error { return nil }

func (m *mockPolicyEngine) RemovePolicy(portID string) error { return nil }

func (m *mockPolicyEngine) GetPolicy(portID string) (*PortPolicy, error) {
	return nil, ErrPolicyNotFound
}

func (m *mockPolicyEngine) SetPortVLAN(portID string, vlan uint16) error { return nil }

func (m *mockPolicyEngine) GetPortVLAN(portID string) (uint16, error) { return 0, nil }

func (m *mockPolicyEngine) BlockPort(portID string) error {
	if m.blockPortErr != nil {
		return m.blockPortErr
	}
	m.blockedPorts[portID] = true
	m.portStates[portID] = PortStateBlocked
	return nil
}

func (m *mockPolicyEngine) UnblockPort(portID string) error {
	if m.unblockPortErr != nil {
		return m.unblockPortErr
	}
	delete(m.blockedPorts, portID)
	return nil
}

func (m *mockPolicyEngine) GetOFPort(portID string) (int32, error) { return 0, nil }

func (m *mockPolicyEngine) AuthenticatePort(portID string, cert *x509.Certificate) error {
	return nil
}

func (m *mockPolicyEngine) OnCertificateExpired(portID string) error { return nil }

func (m *mockPolicyEngine) OnCertificateRevoked(portID string) error { return nil }

func (m *mockPolicyEngine) GetMonitor() *CertificateMonitor { return nil }

var _ PolicyEngine = (*mockPolicyEngine)(nil)

// ---- null flow / port controllers ----

type nullFlowController struct{}

func (n *nullFlowController) InstallFlow(bridgeName string, priority int, match string, actions string) error {
	return nil
}

func (n *nullFlowController) InstallFlows(bridgeName string, rules []zoneflows.FlowRule) error {
	return nil
}

func (n *nullFlowController) DeleteFlow(bridgeName string, match string) error { return nil }

func (n *nullFlowController) DeleteFlowsByPort(bridgeName string, portID string) error { return nil }

func (n *nullFlowController) ListFlows(bridgeName string) ([]string, error) { return nil, nil }

type nullPortController struct {
	nullFlowController
}

func (n *nullPortController) SetPortVLAN(ctx context.Context, portName string, vlan int64) error {
	return nil
}

func (n *nullPortController) SetPortTrunk(ctx context.Context, portName string, allowed []uint16, native uint16) error {
	return nil
}

func (n *nullPortController) SetPortState(ctx context.Context, portName string, state ovs.PortState) error {
	return nil
}

func (n *nullPortController) GetOFPort(ctx context.Context, portName string) (int32, error) {
	return 1, nil
}

var _ OVSPortController = (*nullPortController)(nil)

// ---- helpers ----

func buildNullZoneFlowManager(t *testing.T, zones []zone.ZoneConfig) *ZoneFlowManager {
	t.Helper()
	zm, err := NewZoneFlowManager(ZoneFlowManagerConfig{
		BridgeName:     "br-test",
		FlowController: &nullFlowController{},
		PortController: &nullPortController{},
		Plan:           testPlan(t),
		Zones:          zones,
	})
	if err != nil {
		t.Fatalf("build null zone flow manager: %v", err)
	}
	return zm
}

func buildQM(t *testing.T, store DeviceStateStore, zones []zone.ZoneConfig, engine PolicyEngine) *QuarantineManager {
	t.Helper()
	zm := buildNullZoneFlowManager(t, zones)
	qm, err := NewQuarantineManager(QuarantineManagerConfig{
		PolicyEngine:     engine,
		ZoneFlowManager:  zm,
		ResolvedZones:    zones,
		DeviceStateStore: store,
	})
	if err != nil {
		t.Fatalf("NewQuarantineManager: %v", err)
	}
	return qm
}

// ---- constructor tests ----

func TestNewQuarantineManager_MissingEngine(t *testing.T) {
	_, err := NewQuarantineManager(QuarantineManagerConfig{
		DeviceStateStore: newMemDeviceStore(),
		ResolvedZones:    resolvedZonesWithQuarantine(),
	})
	if err == nil {
		t.Error("expected error when policy engine is nil")
	}
}

func TestNewQuarantineManager_MissingStore(t *testing.T) {
	_, err := NewQuarantineManager(QuarantineManagerConfig{
		PolicyEngine:  newMockPolicyEngine(),
		ResolvedZones: resolvedZonesWithQuarantine(),
	})
	if err == nil {
		t.Error("expected error when device state store is nil")
	}
}

func TestNewQuarantineManager_MissingZones(t *testing.T) {
	_, err := NewQuarantineManager(QuarantineManagerConfig{
		PolicyEngine:     newMockPolicyEngine(),
		DeviceStateStore: newMemDeviceStore(),
	})
	if err == nil {
		t.Error("expected error when resolved zones are empty")
	}
}

// ---- violation handling ----

func TestHandleViolation_NonSevere_Quarantines(t *testing.T) {
	device := &entities.Device{ID: 1, State: entities.DeviceStateAttested}
	store := newMemDeviceStore(device)
	engine := newMockPolicyEngine()
	qm := buildQM(t, store, resolvedZonesWithQuarantine(), engine)

	ev := &entities.ViolationEvent{
		DeviceID:   1,
		Severity:   entities.ViolationSeverityWarning,
		Source:     entities.ViolationSourceAttestation,
		Detail:     "PCR[7] mismatch",
		OccurredAt: time.Now(),
	}

	if err := qm.HandleViolation(context.Background(), ev, "port0"); err != nil {
		t.Fatalf("HandleViolation: %v", err)
	}

	saved := store.devices[1]
	if saved.State != entities.DeviceStateQuarantined {
		t.Errorf("expected quarantined, got %s", saved.State)
	}
	if saved.PriorState != entities.DeviceStateAttested {
		t.Errorf("expected prior state attested, got %s", saved.PriorState)
	}
	if saved.StateReason == "" {
		t.Error("StateReason should be set")
	}
	// Port should NOT be blocked (quarantine is not a hard block).
	if engine.blockedPorts["port0"] {
		t.Error("port should not be blocked for non-severe violation")
	}
	if engine.portStates["port0"] != PortStateQuarantined {
		t.Errorf("expected port quarantined state, got %v", engine.portStates["port0"])
	}
}

func TestHandleViolation_Severe_Suspends(t *testing.T) {
	device := &entities.Device{ID: 2, State: entities.DeviceStateAttested}
	store := newMemDeviceStore(device)
	engine := newMockPolicyEngine()
	qm := buildQM(t, store, resolvedZonesWithQuarantine(), engine)

	ev := &entities.ViolationEvent{
		DeviceID:   2,
		Severity:   entities.ViolationSeveritySevere,
		Source:     entities.ViolationSourceAttestation,
		Detail:     "AK mismatch — possible hardware swap",
		OccurredAt: time.Now(),
	}

	if err := qm.HandleViolation(context.Background(), ev, "port1"); err != nil {
		t.Fatalf("HandleViolation: %v", err)
	}

	saved := store.devices[2]
	if saved.State != entities.DeviceStateSuspended {
		t.Errorf("expected suspended, got %s", saved.State)
	}
	if !engine.blockedPorts["port1"] {
		t.Error("port should be blocked for severe violation")
	}
}

func TestHandleViolation_InvalidEvent_ReturnsError(t *testing.T) {
	qm := buildQM(t, newMemDeviceStore(), resolvedZonesWithQuarantine(), newMockPolicyEngine())

	ev := &entities.ViolationEvent{
		// DeviceID zero → validation error
		Severity:   entities.ViolationSeverityWarning,
		Source:     entities.ViolationSourceAttestation,
		OccurredAt: time.Now(),
	}
	if err := qm.HandleViolation(context.Background(), ev, "port0"); err == nil {
		t.Error("expected validation error for zero DeviceID")
	}
}

func TestHandleViolation_EmptyPortID_ReturnsError(t *testing.T) {
	device := &entities.Device{ID: 3, State: entities.DeviceStateAttested}
	qm := buildQM(t, newMemDeviceStore(device), resolvedZonesWithQuarantine(), newMockPolicyEngine())

	ev := &entities.ViolationEvent{
		DeviceID:   3,
		Severity:   entities.ViolationSeverityWarning,
		Source:     entities.ViolationSourceAttestation,
		OccurredAt: time.Now(),
	}
	if err := qm.HandleViolation(context.Background(), ev, ""); err == nil {
		t.Error("expected error for empty port ID")
	}
}

func TestHandleViolation_NoQuarantineZone_ReturnsError(t *testing.T) {
	device := &entities.Device{ID: 4, State: entities.DeviceStateAttested}
	store := newMemDeviceStore(device)
	engine := newMockPolicyEngine()

	zm := buildNullZoneFlowManager(t, resolvedZonesWithoutQuarantine())
	qm, err := NewQuarantineManager(QuarantineManagerConfig{
		PolicyEngine:     engine,
		ZoneFlowManager:  zm,
		ResolvedZones:    resolvedZonesWithoutQuarantine(),
		DeviceStateStore: store,
	})
	if err != nil {
		t.Fatalf("NewQuarantineManager: %v", err)
	}

	ev := &entities.ViolationEvent{
		DeviceID:   4,
		Severity:   entities.ViolationSeverityWarning,
		Source:     entities.ViolationSourceAttestation,
		OccurredAt: time.Now(),
	}
	if err := qm.HandleViolation(context.Background(), ev, "port4"); err == nil {
		t.Error("expected ErrNoQuarantineZone when quarantine role is missing")
	}
}

func TestHandleViolation_InvalidFromState_ReturnsError(t *testing.T) {
	// Revoked device cannot transition to quarantined.
	device := &entities.Device{ID: 5, State: entities.DeviceStateRevoked}
	store := newMemDeviceStore(device)
	engine := newMockPolicyEngine()
	qm := buildQM(t, store, resolvedZonesWithQuarantine(), engine)

	ev := &entities.ViolationEvent{
		DeviceID:   5,
		Severity:   entities.ViolationSeverityWarning,
		Source:     entities.ViolationSourceAttestation,
		OccurredAt: time.Now(),
	}
	if err := qm.HandleViolation(context.Background(), ev, "port5"); err == nil {
		t.Error("expected error: revoked device cannot transition to quarantined")
	}
}

// ---- restore tests ----

func TestHandleRestoreAttestation_Success(t *testing.T) {
	device := &entities.Device{
		ID:         6,
		State:      entities.DeviceStateQuarantined,
		PriorState: entities.DeviceStateAttested,
		PriorZone:  string(zone.ZoneControlPlane),
	}
	store := newMemDeviceStore(device)
	engine := newMockPolicyEngine()
	qm := buildQM(t, store, resolvedZonesWithQuarantine(), engine)

	if err := qm.HandleRestoreAttestation(context.Background(), 6, "port6"); err != nil {
		t.Fatalf("HandleRestoreAttestation: %v", err)
	}

	saved := store.devices[6]
	if saved.State != entities.DeviceStateAttested {
		t.Errorf("expected attested after restore, got %s", saved.State)
	}
	if saved.PriorState != "" {
		t.Error("PriorState should be cleared after restore")
	}
	if saved.PriorZone != "" {
		t.Error("PriorZone should be cleared after restore")
	}
}

func TestHandleRestoreAttestation_NotQuarantined_ReturnsError(t *testing.T) {
	device := &entities.Device{ID: 7, State: entities.DeviceStateAttested}
	store := newMemDeviceStore(device)
	qm := buildQM(t, store, resolvedZonesWithQuarantine(), newMockPolicyEngine())

	if err := qm.HandleRestoreAttestation(context.Background(), 7, "port7"); err == nil {
		t.Error("expected error when device is not quarantined")
	}
}

func TestHandleRestoreAttestation_EmptyPort_ReturnsError(t *testing.T) {
	qm := buildQM(t, newMemDeviceStore(), resolvedZonesWithQuarantine(), newMockPolicyEngine())
	if err := qm.HandleRestoreAttestation(context.Background(), 8, ""); err == nil {
		t.Error("expected error for empty port ID")
	}
}

// ---- error type tests ----

func TestErrNoQuarantineZone_Error(t *testing.T) {
	e := ErrNoQuarantineZone{}
	if e.Error() == "" {
		t.Error("Error() should return non-empty string")
	}
}

func TestErrUnknownDevicePort_Error(t *testing.T) {
	e := ErrUnknownDevicePort{DeviceID: 42}
	if e.Error() == "" {
		t.Error("Error() should return non-empty string")
	}
}

// TestQuarantine_RecordsAndRestoresPortClass quarantines a port admitted to
// the hypervisor class and restores that class on re-attestation.
func TestQuarantine_RecordsAndRestoresPortClass(t *testing.T) {
	device := &entities.Device{ID: 11, State: entities.DeviceStateAttested}
	store := newMemDeviceStore(device)
	engine := newMockPolicyEngine()
	qm := buildQM(t, store, resolvedZonesWithQuarantine(), engine)
	ctx := context.Background()

	if err := qm.zoneFlowManager.ApplyPortClassFlows(ctx, "port11", zone.PortClassHypervisor); err != nil {
		t.Fatalf("admit: %v", err)
	}
	ev := &entities.ViolationEvent{
		DeviceID: 11, Severity: entities.ViolationSeverityWarning,
		Source: entities.ViolationSourceAttestation, Detail: "PCR[7] mismatch", OccurredAt: time.Now(),
	}
	if err := qm.HandleViolation(ctx, ev, "port11"); err != nil {
		t.Fatalf("HandleViolation: %v", err)
	}
	saved := store.devices[11]
	if saved.PriorPortClass != string(zone.PortClassHypervisor) || saved.PriorZone != "" {
		t.Fatalf("prior placement = zone %q class %q, want class hypervisor", saved.PriorZone, saved.PriorPortClass)
	}
	if z, _ := qm.zoneFlowManager.GetPortZone("port11"); z != zone.ZoneQuarantine {
		t.Fatalf("port zone = %q, want quarantine", z)
	}

	if err := qm.HandleRestoreAttestation(ctx, 11, "port11"); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if c, err := qm.zoneFlowManager.GetPortClass("port11"); err != nil || c != zone.PortClassHypervisor {
		t.Fatalf("restored class = %q (%v), want hypervisor", c, err)
	}
	if store.devices[11].PriorPortClass != "" {
		t.Error("PriorPortClass should be cleared after restore")
	}
}

// TestHandleRestoreAttestation_NoTarget keeps a device quarantined when
// neither a prior zone nor a prior port class was recorded.
func TestHandleRestoreAttestation_NoTarget(t *testing.T) {
	device := &entities.Device{ID: 12, State: entities.DeviceStateQuarantined, PriorState: entities.DeviceStateAttested}
	store := newMemDeviceStore(device)
	qm := buildQM(t, store, resolvedZonesWithQuarantine(), newMockPolicyEngine())

	err := qm.HandleRestoreAttestation(context.Background(), 12, "port12")
	var target ErrNoRestoreTarget
	if !errors.As(err, &target) || target.DeviceID != 12 {
		t.Fatalf("want ErrNoRestoreTarget for device 12, got %v", err)
	}
	if !strings.Contains(err.Error(), "stays quarantined") {
		t.Errorf("message %q", err.Error())
	}
	if store.devices[12].State != entities.DeviceStateQuarantined {
		t.Error("the device must stay quarantined")
	}
}

// TestQuarantine_PortOnLifecycleZoneIsNoPlacement quarantines a device whose
// port already sits on a lifecycle zone (quarantine, put there by the
// adapter's quarantine phase). That zone is not recorded as the placement,
// so a restore refuses rather than re-applying quarantine to an attested
// device.
func TestQuarantine_PortOnLifecycleZoneIsNoPlacement(t *testing.T) {
	device := &entities.Device{ID: 13, State: entities.DeviceStateAttested}
	store := newMemDeviceStore(device)
	qm := buildQM(t, store, resolvedZonesWithQuarantine(), newMockPolicyEngine())
	ctx := context.Background()

	if err := qm.zoneFlowManager.ApplyZoneFlows(ctx, "port13", zone.ZoneQuarantine); err != nil {
		t.Fatalf("place on quarantine: %v", err)
	}
	ev := &entities.ViolationEvent{
		DeviceID: 13, Severity: entities.ViolationSeverityWarning,
		Source: entities.ViolationSourceAttestation, OccurredAt: time.Now(),
	}
	if err := qm.HandleViolation(ctx, ev, "port13"); err != nil {
		t.Fatalf("HandleViolation: %v", err)
	}
	if saved := store.devices[13]; saved.PriorZone != "" || saved.PriorPortClass != "" {
		t.Fatalf("a lifecycle zone must not be recorded, got zone %q class %q", saved.PriorZone, saved.PriorPortClass)
	}

	var target ErrNoRestoreTarget
	if err := qm.HandleRestoreAttestation(ctx, 13, "port13"); !errors.As(err, &target) {
		t.Fatalf("want ErrNoRestoreTarget, got %v", err)
	}
	if store.devices[13].State != entities.DeviceStateQuarantined {
		t.Error("the device must stay quarantined")
	}
}

// TestHandleRestoreAttestation_RecordedLifecycleZoneIsNoTarget refuses to
// restore onto a lifecycle zone recorded by an older record, and still
// restores a recorded ordinary zone.
func TestHandleRestoreAttestation_RecordedLifecycleZoneIsNoTarget(t *testing.T) {
	device := &entities.Device{
		ID: 14, State: entities.DeviceStateQuarantined,
		PriorState: entities.DeviceStateAttested, PriorZone: string(zone.ZoneProvisioning),
	}
	store := newMemDeviceStore(device)
	qm := buildQM(t, store, resolvedZonesWithQuarantine(), newMockPolicyEngine())

	var target ErrNoRestoreTarget
	if err := qm.HandleRestoreAttestation(context.Background(), 14, "port14"); !errors.As(err, &target) {
		t.Fatalf("want ErrNoRestoreTarget, got %v", err)
	}
	if qm.isLifecycleZone(zone.ZoneStorage) {
		t.Error("storage carries no lifecycle role")
	}
	if qm.isLifecycleZone("nowhere") {
		t.Error("an undeclared zone carries no lifecycle role")
	}
}
