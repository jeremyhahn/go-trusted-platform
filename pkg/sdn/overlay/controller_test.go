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

package overlay

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  *Config
		wantErr error
	}{
		{
			name:    "nil config returns error",
			config:  nil,
			wantErr: ErrConfigNil,
		},
		{
			name: "empty node ID returns error",
			config: &Config{
				NodeID:            "",
				VTEPIP:            netip.MustParseAddr("10.0.0.1"),
				UnderlayInterface: "eth0",
			},
			wantErr: ErrNodeIDEmpty,
		},
		{
			name: "invalid VTEP IP returns error",
			config: &Config{
				NodeID:            "node1",
				VTEPIP:            netip.Addr{},
				UnderlayInterface: "eth0",
			},
			wantErr: ErrInvalidVTEPIP,
		},
		{
			name: "unspecified VTEP IP returns error",
			config: &Config{
				NodeID:            "node1",
				VTEPIP:            netip.MustParseAddr("0.0.0.0"),
				UnderlayInterface: "eth0",
			},
			wantErr: ErrInvalidVTEPIP,
		},
		{
			name: "empty underlay interface returns error",
			config: &Config{
				NodeID:            "node1",
				VTEPIP:            netip.MustParseAddr("10.0.0.1"),
				UnderlayInterface: "",
			},
			wantErr: ErrUnderlayInterfaceEmpty,
		},
		{
			name: "valid config creates controller",
			config: &Config{
				NodeID:            "node1",
				VTEPIP:            netip.MustParseAddr("10.0.0.1"),
				UnderlayInterface: "eth0",
				BridgeName:        "br-overlay",
			},
			wantErr: nil,
		},
		{
			name: "defaults are applied",
			config: &Config{
				NodeID:            "node1",
				VTEPIP:            netip.MustParseAddr("10.0.0.1"),
				UnderlayInterface: "eth0",
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl, err := New(tt.config)

			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				}
				if ctrl != nil {
					t.Errorf("New() returned non-nil controller with error")
				}
				return
			}

			if err != nil {
				t.Errorf("New() unexpected error = %v", err)
				return
			}

			if ctrl == nil {
				t.Errorf("New() returned nil controller without error")
				return
			}

			// Verify defaults were applied
			if ctrl.config.VXLANPort == 0 {
				t.Errorf("VXLANPort default not applied")
			}
			if ctrl.config.UnderlayMTU == 0 {
				t.Errorf("UnderlayMTU default not applied")
			}
			if ctrl.config.StateBackend == "" {
				t.Errorf("StateBackend default not applied")
			}

			// Verify initial state
			if ctrl.GetControllerState() != ControllerStateStopped {
				t.Errorf("Initial state = %v, want %v", ctrl.GetControllerState(), ControllerStateStopped)
			}
		})
	}
}

func TestNew_WithOptions(t *testing.T) {
	t.Parallel()

	config := &Config{
		NodeID:            "test-node",
		VTEPIP:            netip.MustParseAddr("10.0.0.1"),
		UnderlayInterface: "eth0",
		BridgeName:        "br-test",
	}

	logger := slog.Default()
	stateManager := NewStateManager()

	ctrl, err := New(config,
		WithLogger(logger),
		WithStateManager(stateManager),
	)
	if err != nil {
		t.Fatalf("New() with options error = %v", err)
	}

	if ctrl.logger != logger {
		t.Errorf("WithLogger() did not set logger")
	}
	if ctrl.state != stateManager {
		t.Errorf("WithStateManager() did not set state manager")
	}
}

func TestController_StartStop(t *testing.T) {
	t.Parallel()

	config := &Config{
		NodeID:              "test-node",
		VTEPIP:              netip.MustParseAddr("10.0.0.1"),
		UnderlayInterface:   "eth0",
		BridgeName:          "br-test",
		HealthCheckInterval: 1 * time.Hour, // Long interval to avoid timing issues
		MACExpiration:       1 * time.Hour,
	}

	ctrl, err := New(config)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx := context.Background()

	// Start controller
	if err := ctrl.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	if ctrl.GetControllerState() != ControllerStateRunning {
		t.Errorf("State after Start() = %v, want %v", ctrl.GetControllerState(), ControllerStateRunning)
	}

	if !ctrl.IsRunning() {
		t.Errorf("IsRunning() = false, want true")
	}

	// Starting again should return error
	if err := ctrl.Start(ctx); err != ErrControllerAlreadyRunning {
		t.Errorf("Start() on running controller = %v, want %v", err, ErrControllerAlreadyRunning)
	}

	// Stop controller
	if err := ctrl.Stop(ctx); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}

	if ctrl.GetControllerState() != ControllerStateStopped {
		t.Errorf("State after Stop() = %v, want %v", ctrl.GetControllerState(), ControllerStateStopped)
	}

	if ctrl.IsRunning() {
		t.Errorf("IsRunning() after stop = true, want false")
	}

	// Stopping again should be idempotent
	if err := ctrl.Stop(ctx); err != nil {
		t.Errorf("Stop() on stopped controller = %v, want nil", err)
	}
}

func TestController_StartStopWithCancel(t *testing.T) {
	t.Parallel()

	config := &Config{
		NodeID:              "test-node",
		VTEPIP:              netip.MustParseAddr("10.0.0.1"),
		UnderlayInterface:   "eth0",
		BridgeName:          "br-test",
		HealthCheckInterval: 1 * time.Hour,
		MACExpiration:       1 * time.Hour,
	}

	ctrl, err := New(config)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx := context.Background()

	if err := ctrl.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Stop with timeout context
	stopCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := ctrl.Stop(stopCtx); err != nil {
		t.Errorf("Stop() with timeout = %v, want nil", err)
	}
}

func TestController_VNIOperations(t *testing.T) {
	t.Parallel()

	ctrl := newTestController(t)
	ctx := context.Background()

	if err := ctrl.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer ctrl.Stop(ctx)

	t.Run("add VNI", func(t *testing.T) {
		vniConfig := &VNIConfig{
			VNI:  100000,
			VLAN: 100,
		}

		if err := ctrl.AddVNI(ctx, vniConfig); err != nil {
			t.Errorf("AddVNI() error = %v", err)
		}

		// Verify VNI exists
		vniInfo, err := ctrl.GetVNI(ctx, 100000)
		if err != nil {
			t.Errorf("GetVNI() error = %v", err)
		}
		if vniInfo.VNI != 100000 {
			t.Errorf("VNI = %d, want %d", vniInfo.VNI, 100000)
		}
		if vniInfo.VLAN != 100 {
			t.Errorf("VLAN = %d, want %d", vniInfo.VLAN, 100)
		}
	})

	t.Run("add duplicate VNI returns error", func(t *testing.T) {
		vniConfig := &VNIConfig{
			VNI:  100000,
			VLAN: 200,
		}

		err := ctrl.AddVNI(ctx, vniConfig)
		if err == nil {
			t.Errorf("AddVNI() duplicate should return error")
		}

		opErr, ok := err.(*ErrVNIOperationFailed)
		if !ok {
			t.Errorf("error type = %T, want *ErrVNIOperationFailed", err)
		} else if opErr.Operation != "add" {
			t.Errorf("operation = %s, want add", opErr.Operation)
		}
	})

	t.Run("list VNIs", func(t *testing.T) {
		// Add another VNI
		vniConfig := &VNIConfig{
			VNI:  200000,
			VLAN: 200,
		}
		if err := ctrl.AddVNI(ctx, vniConfig); err != nil {
			t.Errorf("AddVNI() error = %v", err)
		}

		vnis, err := ctrl.ListVNIs(ctx)
		if err != nil {
			t.Errorf("ListVNIs() error = %v", err)
		}
		if len(vnis) != 2 {
			t.Errorf("len(VNIs) = %d, want 2", len(vnis))
		}
	})

	t.Run("remove VNI", func(t *testing.T) {
		if err := ctrl.RemoveVNI(ctx, 100000); err != nil {
			t.Errorf("RemoveVNI() error = %v", err)
		}

		// Verify VNI is gone
		_, err := ctrl.GetVNI(ctx, 100000)
		if err != ErrVNINotFound {
			t.Errorf("GetVNI() after remove = %v, want %v", err, ErrVNINotFound)
		}
	})

	t.Run("remove nonexistent VNI returns error", func(t *testing.T) {
		err := ctrl.RemoveVNI(ctx, 999999)
		if err == nil {
			t.Errorf("RemoveVNI() nonexistent should return error")
		}
	})

	t.Run("invalid VNI config returns error", func(t *testing.T) {
		vniConfig := &VNIConfig{
			VNI:  MaxVNI + 1, // Invalid
			VLAN: 100,
		}

		err := ctrl.AddVNI(ctx, vniConfig)
		if err != ErrVNIOutOfRange {
			t.Errorf("AddVNI() with VNI=%d = %v, want %v", MaxVNI+1, err, ErrVNIOutOfRange)
		}
	})

	t.Run("VLAN out of range returns error", func(t *testing.T) {
		vniConfig := &VNIConfig{
			VNI:  300000,
			VLAN: 5000, // Invalid
		}

		err := ctrl.AddVNI(ctx, vniConfig)
		if err != ErrVLANOutOfRange {
			t.Errorf("AddVNI() with VLAN=5000 = %v, want %v", err, ErrVLANOutOfRange)
		}
	})

	t.Run("nil VNI config returns error", func(t *testing.T) {
		err := ctrl.AddVNI(ctx, nil)
		if err != ErrVNINotFound {
			t.Errorf("AddVNI(nil) = %v, want %v", err, ErrVNINotFound)
		}
	})
}

func TestController_MACOperations(t *testing.T) {
	t.Parallel()

	ctrl := newTestController(t)
	ctx := context.Background()

	if err := ctrl.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer ctrl.Stop(ctx)

	// Setup: Add a VNI first
	vniConfig := &VNIConfig{VNI: 100000, VLAN: 100}
	if err := ctrl.AddVNI(ctx, vniConfig); err != nil {
		t.Fatalf("AddVNI() error = %v", err)
	}

	testMAC, _ := net.ParseMAC("00:11:22:33:44:55")
	remoteVTEP := netip.MustParseAddr("10.0.0.2")

	t.Run("learn MAC", func(t *testing.T) {
		if err := ctrl.LearnMAC(ctx, testMAC, 100000, remoteVTEP); err != nil {
			t.Errorf("LearnMAC() error = %v", err)
		}

		// Verify MAC exists
		entry, err := ctrl.GetRemoteMAC(ctx, 100000, testMAC)
		if err != nil {
			t.Errorf("GetRemoteMAC() error = %v", err)
		}
		if entry.RemoteVTEP != remoteVTEP {
			t.Errorf("RemoteVTEP = %v, want %v", entry.RemoteVTEP, remoteVTEP)
		}
		if entry.Source != "datapath" {
			t.Errorf("Source = %s, want datapath", entry.Source)
		}
	})

	t.Run("learn MAC updates existing", func(t *testing.T) {
		newVTEP := netip.MustParseAddr("10.0.0.3")
		if err := ctrl.LearnMAC(ctx, testMAC, 100000, newVTEP); err != nil {
			t.Errorf("LearnMAC() update error = %v", err)
		}

		entry, _ := ctrl.GetRemoteMAC(ctx, 100000, testMAC)
		if entry.RemoteVTEP != newVTEP {
			t.Errorf("RemoteVTEP after update = %v, want %v", entry.RemoteVTEP, newVTEP)
		}
	})

	t.Run("learn MAC with IP", func(t *testing.T) {
		testMAC2, _ := net.ParseMAC("00:11:22:33:44:66")
		testIP := netip.MustParseAddr("192.168.1.100")

		if err := ctrl.LearnMACWithIP(ctx, testMAC2, testIP, 100000, remoteVTEP); err != nil {
			t.Errorf("LearnMACWithIP() error = %v", err)
		}

		entry, _ := ctrl.GetRemoteMAC(ctx, 100000, testMAC2)
		if entry.IP != testIP {
			t.Errorf("IP = %v, want %v", entry.IP, testIP)
		}
		if entry.Source != "evpn" {
			t.Errorf("Source = %s, want evpn", entry.Source)
		}
	})

	t.Run("learn MAC with IP updates existing", func(t *testing.T) {
		testMAC2, _ := net.ParseMAC("00:11:22:33:44:66")
		newIP := netip.MustParseAddr("192.168.1.200")
		newVTEP := netip.MustParseAddr("10.0.0.5")

		if err := ctrl.LearnMACWithIP(ctx, testMAC2, newIP, 100000, newVTEP); err != nil {
			t.Errorf("LearnMACWithIP() update error = %v", err)
		}

		entry, _ := ctrl.GetRemoteMAC(ctx, 100000, testMAC2)
		if entry.IP != newIP {
			t.Errorf("IP after update = %v, want %v", entry.IP, newIP)
		}
		if entry.RemoteVTEP != newVTEP {
			t.Errorf("RemoteVTEP after update = %v, want %v", entry.RemoteVTEP, newVTEP)
		}
	})

	t.Run("get remote MACs by VNI", func(t *testing.T) {
		macs, err := ctrl.GetRemoteMACs(ctx, 100000)
		if err != nil {
			t.Errorf("GetRemoteMACs() error = %v", err)
		}
		if len(macs) != 2 {
			t.Errorf("len(MACs) = %d, want 2", len(macs))
		}
	})

	t.Run("forget MAC", func(t *testing.T) {
		if err := ctrl.ForgetMAC(ctx, testMAC, 100000); err != nil {
			t.Errorf("ForgetMAC() error = %v", err)
		}

		_, err := ctrl.GetRemoteMAC(ctx, 100000, testMAC)
		if err != ErrMACNotFound {
			t.Errorf("GetRemoteMAC() after forget = %v, want %v", err, ErrMACNotFound)
		}
	})

	t.Run("forget nil MAC returns error", func(t *testing.T) {
		err := ctrl.ForgetMAC(ctx, nil, 100000)
		if err == nil {
			t.Errorf("ForgetMAC(nil) should return error")
		}
		if _, ok := err.(*ErrInvalidMAC); !ok {
			t.Errorf("error type = %T, want *ErrInvalidMAC", err)
		}
	})

	t.Run("learn MAC for nonexistent VNI returns error", func(t *testing.T) {
		newMAC, _ := net.ParseMAC("00:11:22:33:44:77")
		err := ctrl.LearnMAC(ctx, newMAC, 999999, remoteVTEP)
		if err == nil {
			t.Errorf("LearnMAC() for nonexistent VNI should return error")
		}

		opErr, ok := err.(*ErrMACOperationFailed)
		if !ok {
			t.Errorf("error type = %T, want *ErrMACOperationFailed", err)
		} else if opErr.Cause != ErrVNINotFound {
			t.Errorf("cause = %v, want %v", opErr.Cause, ErrVNINotFound)
		}
	})

	t.Run("learn nil MAC returns error", func(t *testing.T) {
		err := ctrl.LearnMAC(ctx, nil, 100000, remoteVTEP)
		if err == nil {
			t.Errorf("LearnMAC(nil) should return error")
		}
		if _, ok := err.(*ErrInvalidMAC); !ok {
			t.Errorf("error type = %T, want *ErrInvalidMAC", err)
		}
	})

	t.Run("learn MAC with invalid VTEP returns error", func(t *testing.T) {
		newMAC, _ := net.ParseMAC("00:11:22:33:44:88")
		err := ctrl.LearnMAC(ctx, newMAC, 100000, netip.Addr{})
		if err == nil {
			t.Errorf("LearnMAC() with invalid VTEP should return error")
		}
		if _, ok := err.(*ErrInvalidIP); !ok {
			t.Errorf("error type = %T, want *ErrInvalidIP", err)
		}
	})

	t.Run("learn MAC with IP nil MAC returns error", func(t *testing.T) {
		testIP := netip.MustParseAddr("192.168.1.100")
		err := ctrl.LearnMACWithIP(ctx, nil, testIP, 100000, remoteVTEP)
		if err == nil {
			t.Errorf("LearnMACWithIP(nil MAC) should return error")
		}
		if _, ok := err.(*ErrInvalidMAC); !ok {
			t.Errorf("error type = %T, want *ErrInvalidMAC", err)
		}
	})

	t.Run("learn MAC with IP invalid IP returns error", func(t *testing.T) {
		newMAC, _ := net.ParseMAC("00:11:22:33:44:99")
		err := ctrl.LearnMACWithIP(ctx, newMAC, netip.Addr{}, 100000, remoteVTEP)
		if err == nil {
			t.Errorf("LearnMACWithIP() with invalid IP should return error")
		}
		if _, ok := err.(*ErrInvalidIP); !ok {
			t.Errorf("error type = %T, want *ErrInvalidIP", err)
		}
	})

	t.Run("learn MAC with IP for nonexistent VNI returns error", func(t *testing.T) {
		newMAC, _ := net.ParseMAC("00:11:22:33:44:aa")
		testIP := netip.MustParseAddr("192.168.1.100")
		err := ctrl.LearnMACWithIP(ctx, newMAC, testIP, 999999, remoteVTEP)
		if err == nil {
			t.Errorf("LearnMACWithIP() for nonexistent VNI should return error")
		}

		opErr, ok := err.(*ErrMACOperationFailed)
		if !ok {
			t.Errorf("error type = %T, want *ErrMACOperationFailed", err)
		} else if opErr.Cause != ErrVNINotFound {
			t.Errorf("cause = %v, want %v", opErr.Cause, ErrVNINotFound)
		}
	})
}

func TestController_VTEPOperations(t *testing.T) {
	t.Parallel()

	ctrl := newTestController(t)
	ctx := context.Background()

	if err := ctrl.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer ctrl.Stop(ctx)

	t.Run("add VTEP", func(t *testing.T) {
		vtep := &VTEPInfo{
			NodeID:  "remote-node",
			IP:      netip.MustParseAddr("10.0.0.2"),
			Healthy: true,
		}

		if err := ctrl.AddVTEP(ctx, vtep); err != nil {
			t.Errorf("AddVTEP() error = %v", err)
		}

		// Verify VTEP exists
		retrieved, err := ctrl.GetVTEP(ctx, vtep.IP)
		if err != nil {
			t.Errorf("GetVTEP() error = %v", err)
		}
		if retrieved.NodeID != "remote-node" {
			t.Errorf("NodeID = %s, want remote-node", retrieved.NodeID)
		}
	})

	t.Run("add duplicate VTEP returns error", func(t *testing.T) {
		vtep := &VTEPInfo{
			NodeID:  "another-node",
			IP:      netip.MustParseAddr("10.0.0.2"),
			Healthy: true,
		}

		err := ctrl.AddVTEP(ctx, vtep)
		if err == nil {
			t.Errorf("AddVTEP() duplicate should return error")
		}
	})

	t.Run("list VTEPs", func(t *testing.T) {
		// Add another VTEP
		vtep := &VTEPInfo{
			NodeID:  "third-node",
			IP:      netip.MustParseAddr("10.0.0.3"),
			Healthy: true,
		}
		if err := ctrl.AddVTEP(ctx, vtep); err != nil {
			t.Errorf("AddVTEP() error = %v", err)
		}

		vteps, err := ctrl.ListVTEPs(ctx)
		if err != nil {
			t.Errorf("ListVTEPs() error = %v", err)
		}
		// Should include local VTEP + 2 remote
		if len(vteps) != 3 {
			t.Errorf("len(VTEPs) = %d, want 3", len(vteps))
		}
	})

	t.Run("remove VTEP", func(t *testing.T) {
		ip := netip.MustParseAddr("10.0.0.2")
		if err := ctrl.RemoveVTEP(ctx, ip); err != nil {
			t.Errorf("RemoveVTEP() error = %v", err)
		}

		_, err := ctrl.GetVTEP(ctx, ip)
		if err != ErrVTEPNotFound {
			t.Errorf("GetVTEP() after remove = %v, want %v", err, ErrVTEPNotFound)
		}
	})

	t.Run("remove nonexistent VTEP returns error", func(t *testing.T) {
		ip := netip.MustParseAddr("10.0.0.99")
		err := ctrl.RemoveVTEP(ctx, ip)
		if err == nil {
			t.Errorf("RemoveVTEP() nonexistent should return error")
		}
	})

	t.Run("add nil VTEP returns error", func(t *testing.T) {
		err := ctrl.AddVTEP(ctx, nil)
		if err != ErrVTEPNotFound {
			t.Errorf("AddVTEP(nil) = %v, want %v", err, ErrVTEPNotFound)
		}
	})
}

func TestController_GetState(t *testing.T) {
	t.Parallel()

	ctrl := newTestController(t)
	ctx := context.Background()

	if err := ctrl.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer ctrl.Stop(ctx)

	// Add some data
	vniConfig := &VNIConfig{VNI: 100000, VLAN: 100}
	if err := ctrl.AddVNI(ctx, vniConfig); err != nil {
		t.Fatalf("AddVNI() error = %v", err)
	}

	vtep := &VTEPInfo{
		NodeID:  "remote-node",
		IP:      netip.MustParseAddr("10.0.0.2"),
		Healthy: true,
	}
	if err := ctrl.AddVTEP(ctx, vtep); err != nil {
		t.Fatalf("AddVTEP() error = %v", err)
	}

	testMAC, _ := net.ParseMAC("00:11:22:33:44:55")
	if err := ctrl.LearnMAC(ctx, testMAC, 100000, vtep.IP); err != nil {
		t.Fatalf("LearnMAC() error = %v", err)
	}

	state := ctrl.GetState()

	if state.NodeID != "test-node" {
		t.Errorf("NodeID = %s, want test-node", state.NodeID)
	}
	if state.ControllerState != ControllerStateRunning {
		t.Errorf("ControllerState = %v, want %v", state.ControllerState, ControllerStateRunning)
	}
	if len(state.VNIs) != 1 {
		t.Errorf("len(VNIs) = %d, want 1", len(state.VNIs))
	}
	if len(state.VTEPs) != 2 { // Local + remote
		t.Errorf("len(VTEPs) = %d, want 2", len(state.VTEPs))
	}
	if len(state.RemoteMACs) != 1 {
		t.Errorf("len(RemoteMACs) = %d, want 1", len(state.RemoteMACs))
	}
}

func TestController_Uptime(t *testing.T) {
	t.Parallel()

	ctrl := newTestController(t)
	ctx := context.Background()

	// Before start, uptime should be 0
	if uptime := ctrl.Uptime(); uptime != 0 {
		t.Errorf("Uptime() before start = %v, want 0", uptime)
	}

	current := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ctrl.now = func() time.Time { return current }

	if err := ctrl.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	if uptime := ctrl.Uptime(); uptime != 0 {
		t.Errorf("Uptime() at start = %v, want 0", uptime)
	}

	current = current.Add(90 * time.Second)
	if uptime := ctrl.Uptime(); uptime != 90*time.Second {
		t.Errorf("Uptime() after 90s = %v, want 90s", uptime)
	}

	// After stop, uptime is 0 again
	if err := ctrl.Stop(ctx); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if uptime := ctrl.Uptime(); uptime != 0 {
		t.Errorf("Uptime() after stop = %v, want 0", uptime)
	}
}

func TestController_OperationsWhenNotRunning(t *testing.T) {
	t.Parallel()

	ctrl := newTestController(t)
	ctx := context.Background()

	// Don't start the controller

	t.Run("AddVNI returns error", func(t *testing.T) {
		err := ctrl.AddVNI(ctx, &VNIConfig{VNI: 100000})
		if err != ErrControllerNotRunning {
			t.Errorf("AddVNI() = %v, want %v", err, ErrControllerNotRunning)
		}
	})

	t.Run("RemoveVNI returns error", func(t *testing.T) {
		err := ctrl.RemoveVNI(ctx, 100000)
		if err != ErrControllerNotRunning {
			t.Errorf("RemoveVNI() = %v, want %v", err, ErrControllerNotRunning)
		}
	})

	t.Run("GetVNI returns error", func(t *testing.T) {
		_, err := ctrl.GetVNI(ctx, 100000)
		if err != ErrControllerNotRunning {
			t.Errorf("GetVNI() = %v, want %v", err, ErrControllerNotRunning)
		}
	})

	t.Run("ListVNIs returns error", func(t *testing.T) {
		_, err := ctrl.ListVNIs(ctx)
		if err != ErrControllerNotRunning {
			t.Errorf("ListVNIs() = %v, want %v", err, ErrControllerNotRunning)
		}
	})

	t.Run("LearnMAC returns error", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		err := ctrl.LearnMAC(ctx, mac, 100000, netip.MustParseAddr("10.0.0.2"))
		if err != ErrControllerNotRunning {
			t.Errorf("LearnMAC() = %v, want %v", err, ErrControllerNotRunning)
		}
	})

	t.Run("LearnMACWithIP returns error", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ip := netip.MustParseAddr("192.168.1.1")
		err := ctrl.LearnMACWithIP(ctx, mac, ip, 100000, netip.MustParseAddr("10.0.0.2"))
		if err != ErrControllerNotRunning {
			t.Errorf("LearnMACWithIP() = %v, want %v", err, ErrControllerNotRunning)
		}
	})

	t.Run("ForgetMAC returns error", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		err := ctrl.ForgetMAC(ctx, mac, 100000)
		if err != ErrControllerNotRunning {
			t.Errorf("ForgetMAC() = %v, want %v", err, ErrControllerNotRunning)
		}
	})

	t.Run("GetRemoteMAC returns error", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		_, err := ctrl.GetRemoteMAC(ctx, 100000, mac)
		if err != ErrControllerNotRunning {
			t.Errorf("GetRemoteMAC() = %v, want %v", err, ErrControllerNotRunning)
		}
	})

	t.Run("GetRemoteMACs returns error", func(t *testing.T) {
		_, err := ctrl.GetRemoteMACs(ctx, 100000)
		if err != ErrControllerNotRunning {
			t.Errorf("GetRemoteMACs() = %v, want %v", err, ErrControllerNotRunning)
		}
	})

	t.Run("AddVTEP returns error", func(t *testing.T) {
		err := ctrl.AddVTEP(ctx, &VTEPInfo{IP: netip.MustParseAddr("10.0.0.2")})
		if err != ErrControllerNotRunning {
			t.Errorf("AddVTEP() = %v, want %v", err, ErrControllerNotRunning)
		}
	})

	t.Run("RemoveVTEP returns error", func(t *testing.T) {
		err := ctrl.RemoveVTEP(ctx, netip.MustParseAddr("10.0.0.2"))
		if err != ErrControllerNotRunning {
			t.Errorf("RemoveVTEP() = %v, want %v", err, ErrControllerNotRunning)
		}
	})

	t.Run("GetVTEP returns error", func(t *testing.T) {
		_, err := ctrl.GetVTEP(ctx, netip.MustParseAddr("10.0.0.2"))
		if err != ErrControllerNotRunning {
			t.Errorf("GetVTEP() = %v, want %v", err, ErrControllerNotRunning)
		}
	})

	t.Run("ListVTEPs returns error", func(t *testing.T) {
		_, err := ctrl.ListVTEPs(ctx)
		if err != ErrControllerNotRunning {
			t.Errorf("ListVTEPs() = %v, want %v", err, ErrControllerNotRunning)
		}
	})
}

func TestController_IsOperational(t *testing.T) {
	t.Parallel()

	ctrl := newTestController(t)
	ctx := context.Background()

	if ctrl.IsOperational() {
		t.Errorf("IsOperational() before start = true, want false")
	}

	if err := ctrl.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	if !ctrl.IsOperational() {
		t.Errorf("IsOperational() after start = false, want true")
	}

	if err := ctrl.Stop(ctx); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}

	if ctrl.IsOperational() {
		t.Errorf("IsOperational() after stop = true, want false")
	}
}

func TestController_GetConfig(t *testing.T) {
	t.Parallel()

	config := &Config{
		NodeID:            "test-node",
		VTEPIP:            netip.MustParseAddr("10.0.0.1"),
		UnderlayInterface: "eth0",
		BridgeName:        "br-test",
	}

	ctrl, err := New(config)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	retrieved := ctrl.GetConfig()
	if retrieved.NodeID != config.NodeID {
		t.Errorf("NodeID = %s, want %s", retrieved.NodeID, config.NodeID)
	}
	if retrieved.BridgeName != config.BridgeName {
		t.Errorf("BridgeName = %s, want %s", retrieved.BridgeName, config.BridgeName)
	}
}

func TestController_ForgetMACNonexistent(t *testing.T) {
	t.Parallel()

	ctrl := newTestController(t)
	ctx := context.Background()

	if err := ctrl.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer ctrl.Stop(ctx)

	// Setup: Add a VNI first
	vniConfig := &VNIConfig{VNI: 100000, VLAN: 100}
	if err := ctrl.AddVNI(ctx, vniConfig); err != nil {
		t.Fatalf("AddVNI() error = %v", err)
	}

	// Try to forget a MAC that doesn't exist
	testMAC, _ := net.ParseMAC("00:11:22:33:44:55")
	err := ctrl.ForgetMAC(ctx, testMAC, 100000)
	if err == nil {
		t.Errorf("ForgetMAC() nonexistent should return error")
	}

	opErr, ok := err.(*ErrMACOperationFailed)
	if !ok {
		t.Errorf("error type = %T, want *ErrMACOperationFailed", err)
	} else if opErr.Operation != "forget" {
		t.Errorf("operation = %s, want forget", opErr.Operation)
	}
}

func TestController_PerformHealthCheck(t *testing.T) {
	t.Parallel()

	ctrl := newTestController(t)
	ctx := context.Background()

	if err := ctrl.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer ctrl.Stop(ctx)

	// Call performHealthCheck directly
	// This tests the internal method that checks component health
	ctrl.performHealthCheck()

	// The method should complete without panic or error
	// It logs warnings if components are not healthy
}

func TestController_ExpireMACs(t *testing.T) {
	t.Parallel()

	ctrl := newTestController(t)
	ctx := context.Background()

	if err := ctrl.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer ctrl.Stop(ctx)

	// Add a VNI and some MACs
	vniConfig := &VNIConfig{VNI: 100000, VLAN: 100}
	if err := ctrl.AddVNI(ctx, vniConfig); err != nil {
		t.Fatalf("AddVNI() error = %v", err)
	}

	// Add an expired MAC directly to state
	expiredMAC, _ := net.ParseMAC("00:11:22:33:44:55")
	entry := &RemoteMACEntry{
		MAC:        expiredMAC,
		VNI:        100000,
		RemoteVTEP: netip.MustParseAddr("10.0.0.2"),
		LearnedAt:  time.Now().Add(-1 * time.Hour),
		ExpiresAt:  time.Now().Add(-1 * time.Minute), // Already expired
		Source:     "test",
	}
	_ = ctrl.state.AddRemoteMAC(ctx, entry)

	// Call expireMACs directly
	ctrl.expireMACs()

	// Verify the expired MAC was removed
	_, err := ctrl.state.GetRemoteMAC(ctx, 100000, expiredMAC)
	if err != ErrMACNotFound {
		t.Errorf("GetRemoteMAC() after expire = %v, want %v", err, ErrMACNotFound)
	}
}

func TestController_AdvertiseIMET(t *testing.T) {
	t.Parallel()

	ctrl := newTestController(t)
	ctx := context.Background()

	if err := ctrl.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer ctrl.Stop(ctx)

	// Test advertiseIMET without EVPN manager
	err := ctrl.advertiseIMET(ctx, 100000)
	if err == nil {
		t.Errorf("advertiseIMET() without EVPNManager should return error")
	}

	compErr, ok := err.(*ErrComponentNotInitialized)
	if !ok {
		t.Errorf("error type = %T, want *ErrComponentNotInitialized", err)
	} else if compErr.Component != "EVPNManager" {
		t.Errorf("component = %s, want EVPNManager", compErr.Component)
	}
}

func TestController_WithdrawIMET(t *testing.T) {
	t.Parallel()

	ctrl := newTestController(t)
	ctx := context.Background()

	if err := ctrl.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer ctrl.Stop(ctx)

	// Test withdrawIMET without EVPN manager
	err := ctrl.withdrawIMET(ctx, 100000)
	if err == nil {
		t.Errorf("withdrawIMET() without EVPNManager should return error")
	}

	compErr, ok := err.(*ErrComponentNotInitialized)
	if !ok {
		t.Errorf("error type = %T, want *ErrComponentNotInitialized", err)
	} else if compErr.Component != "EVPNManager" {
		t.Errorf("component = %s, want EVPNManager", compErr.Component)
	}
}

func TestController_AddVNIWithEVPNAdvertisement(t *testing.T) {
	t.Parallel()

	config := &Config{
		NodeID:              "test-node",
		VTEPIP:              netip.MustParseAddr("10.0.0.1"),
		UnderlayInterface:   "eth0",
		BridgeName:          "br-test",
		HealthCheckInterval: 1 * time.Hour,
		MACExpiration:       1 * time.Hour,
		EnableEVPN:          true, // Enable EVPN
	}

	ctrl, err := New(config)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx := context.Background()

	if err := ctrl.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer ctrl.Stop(ctx)

	// Add VNI with IMET advertisement enabled
	// This tests the EVPN advertisement path when EVPN is enabled but evpnManager is nil
	vniConfig := &VNIConfig{
		VNI:           100000,
		VLAN:          100,
		AdvertiseIMET: true,
	}

	// Should succeed even though EVPN manager is not set (just logs warning)
	if err := ctrl.AddVNI(ctx, vniConfig); err != nil {
		t.Errorf("AddVNI() with EVPN enabled error = %v", err)
	}
}

func TestController_RemoveVNIWithIMETAdvertised(t *testing.T) {
	t.Parallel()

	config := &Config{
		NodeID:              "test-node",
		VTEPIP:              netip.MustParseAddr("10.0.0.1"),
		UnderlayInterface:   "eth0",
		BridgeName:          "br-test",
		HealthCheckInterval: 1 * time.Hour,
		MACExpiration:       1 * time.Hour,
		EnableEVPN:          true,
	}

	ctrl, err := New(config)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx := context.Background()

	if err := ctrl.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer ctrl.Stop(ctx)

	// Add VNI
	vniConfig := &VNIConfig{VNI: 100000, VLAN: 100}
	if err := ctrl.AddVNI(ctx, vniConfig); err != nil {
		t.Fatalf("AddVNI() error = %v", err)
	}

	// Manually set IMETAdvertised to true
	vniInfo, _ := ctrl.state.GetVNI(ctx, 100000)
	vniInfo.IMETAdvertised = true
	_ = ctrl.state.UpdateVNI(ctx, vniInfo)

	// Remove VNI - this should try to withdraw IMET (and log warning because evpnManager is nil)
	if err := ctrl.RemoveVNI(ctx, 100000); err != nil {
		t.Errorf("RemoveVNI() error = %v", err)
	}

	// Verify VNI was removed
	_, err = ctrl.GetVNI(ctx, 100000)
	if err != ErrVNINotFound {
		t.Errorf("GetVNI() after remove = %v, want %v", err, ErrVNINotFound)
	}
}

func TestController_StartFromInvalidState(t *testing.T) {
	t.Parallel()

	ctrl := newTestController(t)
	ctx := context.Background()

	// Start the controller
	if err := ctrl.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Now try starting while already initializing (simulate race)
	// First stop it properly
	if err := ctrl.Stop(ctx); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}

	// Manually set state to Error to test the invalid state path
	ctrl.controllerState.Store(uint32(ControllerStateError))

	err := ctrl.Start(ctx)
	if err == nil {
		t.Errorf("Start() from Error state should return error")
	}

	// Check it's an ErrInvalidState
	_, ok := err.(*ErrInvalidState)
	if !ok {
		t.Errorf("error type = %T, want *ErrInvalidState", err)
	}
}

// newTestController creates a controller for testing.
func newTestController(t *testing.T) *Controller {
	t.Helper()

	config := &Config{
		NodeID:              "test-node",
		VTEPIP:              netip.MustParseAddr("10.0.0.1"),
		UnderlayInterface:   "eth0",
		BridgeName:          "br-test",
		HealthCheckInterval: 1 * time.Hour, // Long interval to avoid background task issues
		MACExpiration:       1 * time.Hour,
	}

	ctrl, err := New(config)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	return ctrl
}
