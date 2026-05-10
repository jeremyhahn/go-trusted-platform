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

package fabric

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"sync"
	"testing"
)

// mockDriver records all operations for verification in tests.
type mockDriver struct {
	mu             sync.Mutex
	connected      bool
	pingErr        error
	connectErr     error
	ensureVLANErr  error
	ensureVNIErr   error
	ensureLAGErr   error
	setPortErr     error
	setTrunkErr    error
	vlans          []mockVLAN
	vnis           []mockVNI
	lags           []LAGConfig
	accessPorts    []mockAccess
	trunkPorts     []mockTrunk
}

type mockVLAN struct {
	VLAN uint16
	Name string
}

type mockVNI struct {
	VNI  uint32
	VLAN uint16
}

type mockAccess struct {
	Port PortRef
	VLAN uint16
}

type mockTrunk struct {
	Port    PortRef
	Allowed []uint16
	Native  uint16
}

func (m *mockDriver) Connect(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.connectErr != nil {
		return m.connectErr
	}
	m.connected = true
	return nil
}

func (m *mockDriver) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connected = false
	return nil
}

func (m *mockDriver) Ping(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pingErr
}

func (m *mockDriver) EnsureVLAN(_ context.Context, vlan uint16, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ensureVLANErr != nil {
		return m.ensureVLANErr
	}
	m.vlans = append(m.vlans, mockVLAN{VLAN: vlan, Name: name})
	return nil
}

func (m *mockDriver) EnsureVNI(_ context.Context, vni uint32, vlan uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ensureVNIErr != nil {
		return m.ensureVNIErr
	}
	m.vnis = append(m.vnis, mockVNI{VNI: vni, VLAN: vlan})
	return nil
}

func (m *mockDriver) EnsureLAG(_ context.Context, lag LAGConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ensureLAGErr != nil {
		return m.ensureLAGErr
	}
	m.lags = append(m.lags, lag)
	return nil
}

func (m *mockDriver) SetPortAccess(_ context.Context, port PortRef, vlan uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.setPortErr != nil {
		return m.setPortErr
	}
	m.accessPorts = append(m.accessPorts, mockAccess{Port: port, VLAN: vlan})
	return nil
}

func (m *mockDriver) SetPortTrunk(_ context.Context, port PortRef, allowed []uint16, native uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.setTrunkErr != nil {
		return m.setTrunkErr
	}
	m.trunkPorts = append(m.trunkPorts, mockTrunk{Port: port, Allowed: allowed, Native: native})
	return nil
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func testFabricConfig() *FabricConfig {
	return &FabricConfig{
		Mode: ModeVLAN,
		Switches: []SwitchConfig{
			{ID: "nexus-01", Vendor: "cisco-nexus", MgmtIP: "10.0.0.1"},
			{ID: "nexus-02", Vendor: "cisco-nexus", MgmtIP: "10.0.0.2"},
		},
		Peers: []PeerConfig{
			{
				SwitchA:       "nexus-01",
				SwitchB:       "nexus-02",
				PeerLinkPorts: []string{"Eth1/47", "Eth1/48"},
			},
		},
		LAGs: []LAGConfig{
			{
				ID:            "lag-server-01",
				PortChannelID: 10,
				MCLAG:         true,
				LACPMode:      "active",
				Members: []PortRef{
					{SwitchID: "nexus-01", Port: "Eth1/1"},
					{SwitchID: "nexus-02", Port: "Eth1/1"},
				},
			},
		},
		Segments: []SegmentConfig{
			{Name: "production", VLAN: 200, CIDR: "10.200.0.0/24", Gateway: "10.200.0.1"},
			{Name: "provisioning", VLAN: 201, CIDR: "10.201.0.0/24", Role: RoleProvisioning},
			{Name: "quarantine", VLAN: 203, CIDR: "10.203.0.0/24", Role: RoleQuarantine},
		},
	}
}

func TestApplyFabric_Success(t *testing.T) {
	cfg := testFabricConfig()
	drv1 := &mockDriver{}
	drv2 := &mockDriver{}
	drivers := map[string]Driver{
		"nexus-01": drv1,
		"nexus-02": drv2,
	}

	mgr, err := NewManagerWithDrivers(cfg, testLogger(), drivers)
	if err != nil {
		t.Fatalf("NewManagerWithDrivers: %s", err)
	}
	t.Cleanup(func() { mgr.Close() })

	ctx := context.Background()
	if err := mgr.ApplyFabric(ctx); err != nil {
		t.Fatalf("ApplyFabric: %s", err)
	}

	// Each switch should have all 3 VLANs.
	if len(drv1.vlans) != 3 {
		t.Fatalf("expected 3 VLANs on nexus-01, got %d", len(drv1.vlans))
	}
	if len(drv2.vlans) != 3 {
		t.Fatalf("expected 3 VLANs on nexus-02, got %d", len(drv2.vlans))
	}

	// LAG should be configured on both switches.
	if len(drv1.lags) != 1 {
		t.Fatalf("expected 1 LAG on nexus-01, got %d", len(drv1.lags))
	}
	if len(drv2.lags) != 1 {
		t.Fatalf("expected 1 LAG on nexus-02, got %d", len(drv2.lags))
	}
}

func TestApplyFabric_EVPNMode(t *testing.T) {
	cfg := testFabricConfig()
	cfg.Mode = ModeEVPN
	cfg.EVPN = &EVPNConfig{VNIBase: 100000}

	drv := &mockDriver{}
	drivers := map[string]Driver{
		"nexus-01": drv,
		"nexus-02": &mockDriver{},
	}

	mgr, err := NewManagerWithDrivers(cfg, testLogger(), drivers)
	if err != nil {
		t.Fatalf("NewManagerWithDrivers: %s", err)
	}
	t.Cleanup(func() { mgr.Close() })

	ctx := context.Background()
	if err := mgr.ApplyFabric(ctx); err != nil {
		t.Fatalf("ApplyFabric: %s", err)
	}

	// VNIs should be created in EVPN mode.
	if len(drv.vnis) != 3 {
		t.Fatalf("expected 3 VNIs on nexus-01, got %d", len(drv.vnis))
	}

	// Verify VNI calculation: VNIBase + VLAN.
	for _, vni := range drv.vnis {
		expected := uint32(100000) + uint32(vni.VLAN)
		if vni.VNI != expected {
			t.Fatalf("expected VNI %d for VLAN %d, got %d", expected, vni.VLAN, vni.VNI)
		}
	}
}

func TestApplyFabric_ConnectError(t *testing.T) {
	cfg := testFabricConfig()
	drv := &mockDriver{connectErr: errors.New("connection refused")}
	drivers := map[string]Driver{
		"nexus-01": drv,
		"nexus-02": &mockDriver{},
	}

	mgr, err := NewManagerWithDrivers(cfg, testLogger(), drivers)
	if err != nil {
		t.Fatalf("NewManagerWithDrivers: %s", err)
	}
	t.Cleanup(func() { mgr.Close() })

	ctx := context.Background()
	err = mgr.ApplyFabric(ctx)
	if err == nil {
		t.Fatal("expected error for connect failure")
	}
	var drvErr ErrDriverConnect
	if !errors.As(err, &drvErr) {
		t.Fatalf("expected ErrDriverConnect, got %T: %s", err, err)
	}
}

func TestApplyFabric_VLANError(t *testing.T) {
	cfg := testFabricConfig()
	drv := &mockDriver{ensureVLANErr: errors.New("vlan creation failed")}
	drivers := map[string]Driver{
		"nexus-01": drv,
		"nexus-02": &mockDriver{},
	}

	mgr, err := NewManagerWithDrivers(cfg, testLogger(), drivers)
	if err != nil {
		t.Fatalf("NewManagerWithDrivers: %s", err)
	}
	t.Cleanup(func() { mgr.Close() })

	ctx := context.Background()
	err = mgr.ApplyFabric(ctx)
	if err == nil {
		t.Fatal("expected error for VLAN failure")
	}
	var opErr ErrDriverOperation
	if !errors.As(err, &opErr) {
		t.Fatalf("expected ErrDriverOperation, got %T: %s", err, err)
	}
}

func TestProvisionPort_Success(t *testing.T) {
	cfg := testFabricConfig()
	drv1 := &mockDriver{}
	drv2 := &mockDriver{}
	drivers := map[string]Driver{
		"nexus-01": drv1,
		"nexus-02": drv2,
	}

	mgr, err := NewManagerWithDrivers(cfg, testLogger(), drivers)
	if err != nil {
		t.Fatalf("NewManagerWithDrivers: %s", err)
	}
	t.Cleanup(func() { mgr.Close() })

	ctx := context.Background()
	port := PortRef{SwitchID: "nexus-01", Port: "Eth1/5"}
	if err := mgr.ProvisionPort(ctx, port, "provisioning"); err != nil {
		t.Fatalf("ProvisionPort: %s", err)
	}

	if len(drv1.accessPorts) != 1 {
		t.Fatalf("expected 1 access port on nexus-01, got %d", len(drv1.accessPorts))
	}
	if drv1.accessPorts[0].VLAN != 201 {
		t.Fatalf("expected VLAN 201, got %d", drv1.accessPorts[0].VLAN)
	}

	// Peer switch should also get the port configured.
	if len(drv2.accessPorts) != 1 {
		t.Fatalf("expected 1 access port on peer nexus-02, got %d", len(drv2.accessPorts))
	}
}

func TestProvisionPort_WrongRole(t *testing.T) {
	cfg := testFabricConfig()
	drivers := map[string]Driver{
		"nexus-01": &mockDriver{},
		"nexus-02": &mockDriver{},
	}

	mgr, err := NewManagerWithDrivers(cfg, testLogger(), drivers)
	if err != nil {
		t.Fatalf("NewManagerWithDrivers: %s", err)
	}
	t.Cleanup(func() { mgr.Close() })

	ctx := context.Background()
	port := PortRef{SwitchID: "nexus-01", Port: "Eth1/5"}

	// Try to provision on a non-provisioning segment.
	err = mgr.ProvisionPort(ctx, port, "production")
	if err == nil {
		t.Fatal("expected error for wrong role")
	}
	var roleErr ErrSegmentRoleMismatch
	if !errors.As(err, &roleErr) {
		t.Fatalf("expected ErrSegmentRoleMismatch, got %T: %s", err, err)
	}
}

func TestProvisionPort_UnknownSegment(t *testing.T) {
	cfg := testFabricConfig()
	drivers := map[string]Driver{
		"nexus-01": &mockDriver{},
		"nexus-02": &mockDriver{},
	}

	mgr, err := NewManagerWithDrivers(cfg, testLogger(), drivers)
	if err != nil {
		t.Fatalf("NewManagerWithDrivers: %s", err)
	}
	t.Cleanup(func() { mgr.Close() })

	ctx := context.Background()
	port := PortRef{SwitchID: "nexus-01", Port: "Eth1/5"}
	err = mgr.ProvisionPort(ctx, port, "nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown segment")
	}
	var segErr ErrUnknownSegment
	if !errors.As(err, &segErr) {
		t.Fatalf("expected ErrUnknownSegment, got %T: %s", err, err)
	}
}

func TestActivatePort_Success(t *testing.T) {
	cfg := testFabricConfig()
	drv := &mockDriver{}
	drivers := map[string]Driver{
		"nexus-01": drv,
		"nexus-02": &mockDriver{},
	}

	mgr, err := NewManagerWithDrivers(cfg, testLogger(), drivers)
	if err != nil {
		t.Fatalf("NewManagerWithDrivers: %s", err)
	}
	t.Cleanup(func() { mgr.Close() })

	ctx := context.Background()
	port := PortRef{SwitchID: "nexus-01", Port: "Eth1/5"}
	if err := mgr.ActivatePort(ctx, port, "production"); err != nil {
		t.Fatalf("ActivatePort: %s", err)
	}

	if len(drv.accessPorts) != 1 {
		t.Fatalf("expected 1 access port, got %d", len(drv.accessPorts))
	}
	if drv.accessPorts[0].VLAN != 200 {
		t.Fatalf("expected VLAN 200, got %d", drv.accessPorts[0].VLAN)
	}
}

func TestActivatePort_DriverError(t *testing.T) {
	cfg := testFabricConfig()
	drv := &mockDriver{setPortErr: errors.New("port config failed")}
	drivers := map[string]Driver{
		"nexus-01": drv,
		"nexus-02": &mockDriver{},
	}

	mgr, err := NewManagerWithDrivers(cfg, testLogger(), drivers)
	if err != nil {
		t.Fatalf("NewManagerWithDrivers: %s", err)
	}
	t.Cleanup(func() { mgr.Close() })

	ctx := context.Background()
	port := PortRef{SwitchID: "nexus-01", Port: "Eth1/5"}
	err = mgr.ActivatePort(ctx, port, "production")
	if err == nil {
		t.Fatal("expected error for driver failure")
	}
	var opErr ErrDriverOperation
	if !errors.As(err, &opErr) {
		t.Fatalf("expected ErrDriverOperation, got %T: %s", err, err)
	}
}

func TestActivatePort_InvalidPortRef(t *testing.T) {
	cfg := testFabricConfig()
	drivers := map[string]Driver{
		"nexus-01": &mockDriver{},
		"nexus-02": &mockDriver{},
	}

	mgr, err := NewManagerWithDrivers(cfg, testLogger(), drivers)
	if err != nil {
		t.Fatalf("NewManagerWithDrivers: %s", err)
	}
	t.Cleanup(func() { mgr.Close() })

	ctx := context.Background()
	port := PortRef{Port: "Eth1/5"} // missing SwitchID
	err = mgr.ActivatePort(ctx, port, "production")
	if err == nil {
		t.Fatal("expected error for invalid port ref")
	}
}

func TestQuarantinePort_Success(t *testing.T) {
	cfg := testFabricConfig()
	drv := &mockDriver{}
	drivers := map[string]Driver{
		"nexus-01": drv,
		"nexus-02": &mockDriver{},
	}

	mgr, err := NewManagerWithDrivers(cfg, testLogger(), drivers)
	if err != nil {
		t.Fatalf("NewManagerWithDrivers: %s", err)
	}
	t.Cleanup(func() { mgr.Close() })

	ctx := context.Background()
	port := PortRef{SwitchID: "nexus-01", Port: "Eth1/5"}
	if err := mgr.QuarantinePort(ctx, port, "quarantine"); err != nil {
		t.Fatalf("QuarantinePort: %s", err)
	}

	if len(drv.accessPorts) != 1 {
		t.Fatalf("expected 1 access port, got %d", len(drv.accessPorts))
	}
	if drv.accessPorts[0].VLAN != 203 {
		t.Fatalf("expected VLAN 203, got %d", drv.accessPorts[0].VLAN)
	}
}

func TestQuarantinePort_WrongRole(t *testing.T) {
	cfg := testFabricConfig()
	drivers := map[string]Driver{
		"nexus-01": &mockDriver{},
		"nexus-02": &mockDriver{},
	}

	mgr, err := NewManagerWithDrivers(cfg, testLogger(), drivers)
	if err != nil {
		t.Fatalf("NewManagerWithDrivers: %s", err)
	}
	t.Cleanup(func() { mgr.Close() })

	ctx := context.Background()
	port := PortRef{SwitchID: "nexus-01", Port: "Eth1/5"}
	err = mgr.QuarantinePort(ctx, port, "production")
	if err == nil {
		t.Fatal("expected error for wrong role")
	}
}

func TestSegmentByName_Success(t *testing.T) {
	cfg := testFabricConfig()
	drivers := map[string]Driver{
		"nexus-01": &mockDriver{},
		"nexus-02": &mockDriver{},
	}

	mgr, err := NewManagerWithDrivers(cfg, testLogger(), drivers)
	if err != nil {
		t.Fatalf("NewManagerWithDrivers: %s", err)
	}
	t.Cleanup(func() { mgr.Close() })

	seg, err := mgr.SegmentByName("production")
	if err != nil {
		t.Fatalf("SegmentByName: %s", err)
	}
	if seg.VLAN != 200 {
		t.Fatalf("expected VLAN 200, got %d", seg.VLAN)
	}
	if seg.Name != "production" {
		t.Fatalf("expected name %q, got %q", "production", seg.Name)
	}
}

func TestSegmentByName_NotFound(t *testing.T) {
	cfg := testFabricConfig()
	drivers := map[string]Driver{
		"nexus-01": &mockDriver{},
		"nexus-02": &mockDriver{},
	}

	mgr, err := NewManagerWithDrivers(cfg, testLogger(), drivers)
	if err != nil {
		t.Fatalf("NewManagerWithDrivers: %s", err)
	}
	t.Cleanup(func() { mgr.Close() })

	_, err = mgr.SegmentByName("nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown segment")
	}
	var segErr ErrUnknownSegment
	if !errors.As(err, &segErr) {
		t.Fatalf("expected ErrUnknownSegment, got %T: %s", err, err)
	}
}

func TestSwitchStatus_Connected(t *testing.T) {
	cfg := testFabricConfig()
	drivers := map[string]Driver{
		"nexus-01": &mockDriver{},
		"nexus-02": &mockDriver{},
	}

	mgr, err := NewManagerWithDrivers(cfg, testLogger(), drivers)
	if err != nil {
		t.Fatalf("NewManagerWithDrivers: %s", err)
	}
	t.Cleanup(func() { mgr.Close() })

	ctx := context.Background()
	status, err := mgr.SwitchStatus(ctx, "nexus-01")
	if err != nil {
		t.Fatalf("SwitchStatus: %s", err)
	}
	if !status.Connected {
		t.Fatal("expected connected=true")
	}
	if status.Vendor != "cisco-nexus" {
		t.Fatalf("expected vendor %q, got %q", "cisco-nexus", status.Vendor)
	}
}

func TestSwitchStatus_Disconnected(t *testing.T) {
	cfg := testFabricConfig()
	drivers := map[string]Driver{
		"nexus-01": &mockDriver{pingErr: errors.New("timeout")},
		"nexus-02": &mockDriver{},
	}

	mgr, err := NewManagerWithDrivers(cfg, testLogger(), drivers)
	if err != nil {
		t.Fatalf("NewManagerWithDrivers: %s", err)
	}
	t.Cleanup(func() { mgr.Close() })

	ctx := context.Background()
	status, err := mgr.SwitchStatus(ctx, "nexus-01")
	if err != nil {
		t.Fatalf("SwitchStatus: %s", err)
	}
	if status.Connected {
		t.Fatal("expected connected=false")
	}
}

func TestSwitchStatus_UnknownSwitch(t *testing.T) {
	cfg := testFabricConfig()
	drivers := map[string]Driver{
		"nexus-01": &mockDriver{},
		"nexus-02": &mockDriver{},
	}

	mgr, err := NewManagerWithDrivers(cfg, testLogger(), drivers)
	if err != nil {
		t.Fatalf("NewManagerWithDrivers: %s", err)
	}
	t.Cleanup(func() { mgr.Close() })

	ctx := context.Background()
	_, err = mgr.SwitchStatus(ctx, "nexus-99")
	if err == nil {
		t.Fatal("expected error for unknown switch")
	}
	var unknownErr ErrUnknownSwitch
	if !errors.As(err, &unknownErr) {
		t.Fatalf("expected ErrUnknownSwitch, got %T: %s", err, err)
	}
}

func TestActivatePort_UnknownSwitch(t *testing.T) {
	cfg := testFabricConfig()
	drivers := map[string]Driver{
		"nexus-01": &mockDriver{},
		"nexus-02": &mockDriver{},
	}

	mgr, err := NewManagerWithDrivers(cfg, testLogger(), drivers)
	if err != nil {
		t.Fatalf("NewManagerWithDrivers: %s", err)
	}
	t.Cleanup(func() { mgr.Close() })

	ctx := context.Background()
	port := PortRef{SwitchID: "nexus-99", Port: "Eth1/5"}
	err = mgr.ActivatePort(ctx, port, "production")
	if err == nil {
		t.Fatal("expected error for unknown switch")
	}
	var unknownErr ErrUnknownSwitch
	if !errors.As(err, &unknownErr) {
		t.Fatalf("expected ErrUnknownSwitch, got %T: %s", err, err)
	}
}
