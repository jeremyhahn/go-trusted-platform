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

package switchmgmt

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"reflect"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/switchwire"
)

func memoryTestConfig() *Config {
	return &Config{
		Name:   "sim-01",
		Vendor: VendorMemory,
		Ports: []PortConfig{
			{Port: "Eth1/1", Mode: "access", AccessVLAN: 10, Description: "uplink to rack"},
			{Port: "Eth1/2", Mode: "trunk", VLANs: []int{10, 20}, NativeVLAN: 1},
			{Port: "Eth1/3-5", Mode: "access", AccessVLAN: 20},
		},
	}
}

func newMemoryTestManager(t *testing.T) Manager {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	mgr, err := NewManager(memoryTestConfig(), logger)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Close() })
	return mgr
}

func TestMemoryManager_SeedsPortsInConfigOrder(t *testing.T) {
	mgr := newMemoryTestManager(t)
	ports, err := mgr.ListPorts(context.Background())
	if err != nil {
		t.Fatalf("ListPorts: %v", err)
	}
	want := []*switchwire.PortStatus{
		{Port: "Eth1/1", Mode: switchwire.PortModeAccess, AccessVLAN: 10, Enabled: true, LinkUp: true, Description: "uplink to rack"},
		{Port: "Eth1/2", Mode: switchwire.PortModeTrunk, TrunkVLANs: []uint16{10, 20}, NativeVLAN: 1, Enabled: true, LinkUp: true},
		{Port: "Eth1/3", Mode: switchwire.PortModeAccess, AccessVLAN: 20, Enabled: true, LinkUp: true},
		{Port: "Eth1/4", Mode: switchwire.PortModeAccess, AccessVLAN: 20, Enabled: true, LinkUp: true},
		{Port: "Eth1/5", Mode: switchwire.PortModeAccess, AccessVLAN: 20, Enabled: true, LinkUp: true},
	}
	if len(ports) != len(want) {
		t.Fatalf("ListPorts returned %d ports, want %d", len(ports), len(want))
	}
	for i := range want {
		if !reflect.DeepEqual(ports[i], want[i]) {
			t.Errorf("port %d = %+v, want %+v", i, ports[i], want[i])
		}
	}
}

func TestMemoryManager_SetPortVLAN(t *testing.T) {
	ctx := context.Background()
	mgr := newMemoryTestManager(t)
	if err := mgr.SetPortVLAN(ctx, "Eth1/2", 30); err != nil {
		t.Fatalf("SetPortVLAN: %v", err)
	}
	vlan, err := mgr.GetPortVLAN(ctx, "Eth1/2")
	if err != nil {
		t.Fatalf("GetPortVLAN: %v", err)
	}
	if vlan != 30 {
		t.Errorf("GetPortVLAN = %d, want 30", vlan)
	}
	st, err := mgr.GetPortStatus(ctx, "Eth1/2")
	if err != nil {
		t.Fatalf("GetPortStatus: %v", err)
	}
	if st.Mode != switchwire.PortModeAccess || st.AccessVLAN != 30 || len(st.TrunkVLANs) != 0 || st.NativeVLAN != 0 {
		t.Errorf("status after SetPortVLAN = %+v, want access VLAN 30 with no trunk VLANs", st)
	}
}

func TestMemoryManager_SetPortVLANRejectsOutOfRange(t *testing.T) {
	ctx := context.Background()
	mgr := newMemoryTestManager(t)
	for _, vlan := range []uint16{0, 4095} {
		err := mgr.SetPortVLAN(ctx, "Eth1/1", vlan)
		var cfgErr ErrInvalidConfig
		if !errors.As(err, &cfgErr) || cfgErr.Field != "vlan" {
			t.Errorf("SetPortVLAN(%d) error = %v, want ErrInvalidConfig{Field: vlan}", vlan, err)
		}
	}
	got, err := mgr.GetPortVLAN(ctx, "Eth1/1")
	if err != nil {
		t.Fatalf("GetPortVLAN: %v", err)
	}
	if got != 10 {
		t.Errorf("GetPortVLAN after refused moves = %d, want 10", got)
	}
}

func TestMemoryManager_DisableEnablePort(t *testing.T) {
	ctx := context.Background()
	mgr := newMemoryTestManager(t)
	if err := mgr.DisablePort(ctx, "Eth1/3"); err != nil {
		t.Fatalf("DisablePort: %v", err)
	}
	st, err := mgr.GetPortStatus(ctx, "Eth1/3")
	if err != nil {
		t.Fatalf("GetPortStatus: %v", err)
	}
	if st.Enabled || st.LinkUp {
		t.Errorf("after DisablePort Enabled=%v LinkUp=%v, want both false", st.Enabled, st.LinkUp)
	}
	if err := mgr.EnablePort(ctx, "Eth1/3"); err != nil {
		t.Fatalf("EnablePort: %v", err)
	}
	st, err = mgr.GetPortStatus(ctx, "Eth1/3")
	if err != nil {
		t.Fatalf("GetPortStatus: %v", err)
	}
	if !st.Enabled || !st.LinkUp {
		t.Errorf("after EnablePort Enabled=%v LinkUp=%v, want both true", st.Enabled, st.LinkUp)
	}
}

func TestMemoryManager_UnknownPort(t *testing.T) {
	ctx := context.Background()
	mgr := newMemoryTestManager(t)
	_, getVLANErr := mgr.GetPortVLAN(ctx, "Eth9/9")
	_, getStatusErr := mgr.GetPortStatus(ctx, "Eth9/9")
	calls := map[string]error{
		"SetPortVLAN":   mgr.SetPortVLAN(ctx, "Eth9/9", 10),
		"GetPortVLAN":   getVLANErr,
		"GetPortStatus": getStatusErr,
		"EnablePort":    mgr.EnablePort(ctx, "Eth9/9"),
		"DisablePort":   mgr.DisablePort(ctx, "Eth9/9"),
	}
	for name, err := range calls {
		var notFound ErrPortNotFound
		if !errors.As(err, &notFound) || notFound.Port != "Eth9/9" {
			t.Errorf("%s on unknown port error = %v, want ErrPortNotFound", name, err)
		}
	}
}

func TestMemoryManager_InvalidConfig(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cases := []struct {
		name  string
		ports []PortConfig
		field string
	}{
		{"hybrid mode", []PortConfig{{Port: "Eth1/1", Mode: "hybrid", AccessVLAN: 10}}, "mode"},
		{"duplicate port", []PortConfig{
			{Port: "Eth1/1", Mode: "access", AccessVLAN: 10},
			{Port: "Eth1/1-2", Mode: "access", AccessVLAN: 20},
		}, "port"},
		{"access vlan above 4094", []PortConfig{{Port: "Eth1/1", Mode: "access", AccessVLAN: 4095}}, "vlan"},
		{"trunk vlan above 4094", []PortConfig{{Port: "Eth1/1", Mode: "trunk", VLANs: []int{10, 5000}}}, "vlan"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewManager(&Config{Vendor: VendorMemory, Ports: tc.ports}, logger)
			var cfgErr ErrInvalidConfig
			if !errors.As(err, &cfgErr) || cfgErr.Field != tc.field {
				t.Fatalf("NewManager error = %v, want ErrInvalidConfig{Field: %q}", err, tc.field)
			}
		})
	}
	t.Run("malformed range", func(t *testing.T) {
		_, err := NewManager(&Config{Vendor: VendorMemory, Ports: []PortConfig{
			{Port: "Eth1/5-3", Mode: "access", AccessVLAN: 10},
		}}, logger)
		var rangeErr ErrInvalidPortRange
		if !errors.As(err, &rangeErr) {
			t.Fatalf("NewManager error = %v, want ErrInvalidPortRange", err)
		}
	})
}

func TestMemoryManager_ReturnsCopies(t *testing.T) {
	ctx := context.Background()
	mgr := newMemoryTestManager(t)
	st, err := mgr.GetPortStatus(ctx, "Eth1/2")
	if err != nil {
		t.Fatalf("GetPortStatus: %v", err)
	}
	st.Enabled = false
	st.AccessVLAN = 99
	st.TrunkVLANs[0] = 99
	ports, err := mgr.ListPorts(ctx)
	if err != nil {
		t.Fatalf("ListPorts: %v", err)
	}
	ports[0].Description = "changed"
	ports[1].TrunkVLANs[1] = 99

	again, err := mgr.GetPortStatus(ctx, "Eth1/2")
	if err != nil {
		t.Fatalf("GetPortStatus: %v", err)
	}
	if !again.Enabled || again.AccessVLAN != 0 || !reflect.DeepEqual(again.TrunkVLANs, []uint16{10, 20}) {
		t.Errorf("Eth1/2 after caller mutation = %+v, want the seeded state", again)
	}
	first, err := mgr.GetPortStatus(ctx, "Eth1/1")
	if err != nil {
		t.Fatalf("GetPortStatus: %v", err)
	}
	if first.Description != "uplink to rack" {
		t.Errorf("Eth1/1 description = %q, want the seeded one", first.Description)
	}
}

func TestMemoryManager_NewConfigurator(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg, err := NewConfigurator(memoryTestConfig(), logger)
	if err != nil {
		t.Fatalf("NewConfigurator: %v", err)
	}
	if cfg == nil {
		t.Fatal("NewConfigurator returned nil")
	}
}

func TestMemoryManager_Close(t *testing.T) {
	mgr := newMemoryTestManager(t)
	if err := mgr.Close(); err != nil {
		t.Errorf("Close = %v, want nil", err)
	}
}
