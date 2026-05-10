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
	"strings"
	"testing"
)

func TestErrUnknownSegment_Error(t *testing.T) {
	err := ErrUnknownSegment{Name: "test-seg"}
	if !strings.Contains(err.Error(), "test-seg") {
		t.Fatalf("expected segment name in error, got %q", err.Error())
	}
}

func TestErrUnknownSwitch_Error(t *testing.T) {
	err := ErrUnknownSwitch{ID: "sw-01"}
	if !strings.Contains(err.Error(), "sw-01") {
		t.Fatalf("expected switch ID in error, got %q", err.Error())
	}
}

func TestErrDuplicateVLAN_Error(t *testing.T) {
	err := ErrDuplicateVLAN{VLAN: 200, Segment1: "a", Segment2: "b"}
	msg := err.Error()
	if !strings.Contains(msg, "200") || !strings.Contains(msg, "a") || !strings.Contains(msg, "b") {
		t.Fatalf("expected VLAN and segment names in error, got %q", msg)
	}
}

func TestErrInvalidPortRef_Error(t *testing.T) {
	err := ErrInvalidPortRef{Reason: "missing field"}
	if !strings.Contains(err.Error(), "missing field") {
		t.Fatalf("expected reason in error, got %q", err.Error())
	}
}

func TestErrDriverConnect_Error_And_Unwrap(t *testing.T) {
	cause := errors.New("connection refused")
	err := ErrDriverConnect{SwitchID: "sw-01", Cause: cause}
	if !strings.Contains(err.Error(), "sw-01") {
		t.Fatalf("expected switch ID in error, got %q", err.Error())
	}
	if !errors.Is(err, cause) {
		t.Fatal("expected Unwrap to return cause")
	}
}

func TestErrSegmentRoleMismatch_Error(t *testing.T) {
	err := ErrSegmentRoleMismatch{Segment: "prod", Expected: RoleProvisioning, Got: RoleNone}
	msg := err.Error()
	if !strings.Contains(msg, "prod") {
		t.Fatalf("expected segment name in error, got %q", msg)
	}
}

func TestErrInvalidFabricConfig_Error(t *testing.T) {
	err := ErrInvalidFabricConfig{Reason: "bad field"}
	if !strings.Contains(err.Error(), "bad field") {
		t.Fatalf("expected reason in error, got %q", err.Error())
	}
}

func TestErrDriverNotFound_Error(t *testing.T) {
	err := ErrDriverNotFound{Vendor: "juniper"}
	if !strings.Contains(err.Error(), "juniper") {
		t.Fatalf("expected vendor in error, got %q", err.Error())
	}
}

func TestErrDriverOperation_Error_And_Unwrap(t *testing.T) {
	cause := errors.New("timeout")
	err := ErrDriverOperation{SwitchID: "sw-01", Operation: "EnsureVLAN", Cause: cause}
	msg := err.Error()
	if !strings.Contains(msg, "sw-01") || !strings.Contains(msg, "EnsureVLAN") {
		t.Fatalf("expected switch and operation in error, got %q", msg)
	}
	if !errors.Is(err, cause) {
		t.Fatal("expected Unwrap to return cause")
	}
}

func TestErrNilConfig_Error(t *testing.T) {
	err := ErrNilConfig{}
	if !strings.Contains(err.Error(), "nil") {
		t.Fatalf("expected nil in error, got %q", err.Error())
	}
}

func TestNewManager_NoDriverFactory(t *testing.T) {
	cfg := &FabricConfig{
		Mode: ModeVLAN,
		Switches: []SwitchConfig{
			{ID: "sw-01", Vendor: "nonexistent-vendor", MgmtIP: "10.0.0.1"},
		},
		Segments: []SegmentConfig{
			{Name: "test", VLAN: 100},
		},
	}
	_, err := NewManager(cfg, testLogger())
	if err == nil {
		t.Fatal("expected error for unknown vendor")
	}
	var drvErr ErrDriverConnect
	if !errors.As(err, &drvErr) {
		t.Fatalf("expected ErrDriverConnect, got %T: %s", err, err)
	}
}

func TestNewManager_InvalidConfig(t *testing.T) {
	cfg := &FabricConfig{}
	_, err := NewManager(cfg, testLogger())
	if err == nil {
		t.Fatal("expected error for invalid config")
	}
}

func TestNewManagerWithDrivers_InvalidConfig(t *testing.T) {
	cfg := &FabricConfig{}
	_, err := NewManagerWithDrivers(cfg, testLogger(), nil)
	if err == nil {
		t.Fatal("expected error for invalid config")
	}
}

func TestApplyFabric_LAGUnknownSwitch(t *testing.T) {
	cfg := &FabricConfig{
		Mode: ModeVLAN,
		Switches: []SwitchConfig{
			{ID: "sw-01", Vendor: "cisco-nexus", MgmtIP: "10.0.0.1"},
		},
		LAGs: []LAGConfig{
			{
				ID:            "lag-01",
				PortChannelID: 10,
				Members: []PortRef{
					{SwitchID: "sw-99", Port: "Eth1/1"},
				},
			},
		},
		Segments: []SegmentConfig{
			{Name: "test", VLAN: 100},
		},
	}
	drv := &mockDriver{}
	drivers := map[string]Driver{"sw-01": drv}

	mgr, err := NewManagerWithDrivers(cfg, testLogger(), drivers)
	if err != nil {
		t.Fatalf("NewManagerWithDrivers: %s", err)
	}
	t.Cleanup(func() { mgr.Close() })

	ctx := context.Background()
	err = mgr.ApplyFabric(ctx)
	if err == nil {
		t.Fatal("expected error for unknown switch in LAG")
	}
	var unknownErr ErrUnknownSwitch
	if !errors.As(err, &unknownErr) {
		t.Fatalf("expected ErrUnknownSwitch, got %T: %s", err, err)
	}
}

func TestApplyFabric_EnsureVNIError(t *testing.T) {
	cfg := &FabricConfig{
		Mode: ModeEVPN,
		EVPN: &EVPNConfig{VNIBase: 100000},
		Switches: []SwitchConfig{
			{ID: "sw-01", Vendor: "cisco-nexus", MgmtIP: "10.0.0.1"},
		},
		Segments: []SegmentConfig{
			{Name: "test", VLAN: 100},
		},
	}
	drv := &mockDriver{ensureVNIErr: errors.New("vni failed")}
	drivers := map[string]Driver{"sw-01": drv}

	mgr, err := NewManagerWithDrivers(cfg, testLogger(), drivers)
	if err != nil {
		t.Fatalf("NewManagerWithDrivers: %s", err)
	}
	t.Cleanup(func() { mgr.Close() })

	ctx := context.Background()
	err = mgr.ApplyFabric(ctx)
	if err == nil {
		t.Fatal("expected error for VNI failure")
	}
	var opErr ErrDriverOperation
	if !errors.As(err, &opErr) {
		t.Fatalf("expected ErrDriverOperation, got %T: %s", err, err)
	}
}

func TestApplyFabric_LAGError(t *testing.T) {
	cfg := &FabricConfig{
		Mode: ModeVLAN,
		Switches: []SwitchConfig{
			{ID: "sw-01", Vendor: "cisco-nexus", MgmtIP: "10.0.0.1"},
		},
		LAGs: []LAGConfig{
			{
				ID:            "lag-01",
				PortChannelID: 10,
				Members: []PortRef{
					{SwitchID: "sw-01", Port: "Eth1/1"},
				},
			},
		},
		Segments: []SegmentConfig{
			{Name: "test", VLAN: 100},
		},
	}
	drv := &mockDriver{ensureLAGErr: errors.New("lag failed")}
	drivers := map[string]Driver{"sw-01": drv}

	mgr, err := NewManagerWithDrivers(cfg, testLogger(), drivers)
	if err != nil {
		t.Fatalf("NewManagerWithDrivers: %s", err)
	}
	t.Cleanup(func() { mgr.Close() })

	ctx := context.Background()
	err = mgr.ApplyFabric(ctx)
	if err == nil {
		t.Fatal("expected error for LAG failure")
	}
}

func TestProvisionPort_DriverError(t *testing.T) {
	cfg := testFabricConfig()
	drv := &mockDriver{setPortErr: errors.New("port failed")}
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
	err = mgr.ProvisionPort(ctx, port, "provisioning")
	if err == nil {
		t.Fatal("expected error for driver failure")
	}
}

func TestQuarantinePort_InvalidPortRef(t *testing.T) {
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
	port := PortRef{}
	err = mgr.QuarantinePort(ctx, port, "quarantine")
	if err == nil {
		t.Fatal("expected error for invalid port ref")
	}
}
