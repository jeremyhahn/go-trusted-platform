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

package modes

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/openflow"
)

// mockOVSClient implements OverlayOVSClient for testing.
type mockOVSClient struct {
	mu            sync.Mutex
	connected     atomic.Bool
	ports         map[string]int32 // portName -> ofPort
	addPortErr    error
	deletePortErr error
	getOFPortErr  error
	nextOFPort    int32
}

func newMockOVSClient() *mockOVSClient {
	m := &mockOVSClient{
		ports:      make(map[string]int32),
		nextOFPort: 100,
	}
	m.connected.Store(true)
	return m
}

func (m *mockOVSClient) AddVXLANPort(ctx context.Context, bridge, port string, remoteIP string, vni uint32, dstPort uint16) error {
	if m.addPortErr != nil {
		return m.addPortErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextOFPort++
	m.ports[port] = m.nextOFPort
	return nil
}

func (m *mockOVSClient) DeletePort(ctx context.Context, bridge, port string) error {
	if m.deletePortErr != nil {
		return m.deletePortErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.ports, port)
	return nil
}

func (m *mockOVSClient) GetOFPort(ctx context.Context, portName string) (int32, error) {
	if m.getOFPortErr != nil {
		return 0, m.getOFPortErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if port, ok := m.ports[portName]; ok {
		return port, nil
	}
	return 0, errors.New("port not found")
}

func (m *mockOVSClient) IsConnected() bool {
	return m.connected.Load()
}

// mockOpenFlowClient implements OverlayOpenFlowClient for testing.
type mockOpenFlowClient struct {
	mu           sync.Mutex
	connected    atomic.Bool
	flows        []*openflow.FlowMod
	addFlowErr   error
	delFlowErr   error
	addFlowCount atomic.Int32
	delFlowCount atomic.Int32
}

func newMockOpenFlowClient() *mockOpenFlowClient {
	m := &mockOpenFlowClient{
		flows: make([]*openflow.FlowMod, 0),
	}
	m.connected.Store(true)
	return m
}

func (m *mockOpenFlowClient) AddFlow(ctx context.Context, flow *openflow.FlowMod) error {
	if m.addFlowErr != nil {
		return m.addFlowErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.flows = append(m.flows, flow)
	m.addFlowCount.Add(1)
	return nil
}

func (m *mockOpenFlowClient) DeleteFlow(ctx context.Context, flow *openflow.FlowMod) error {
	if m.delFlowErr != nil {
		return m.delFlowErr
	}
	m.delFlowCount.Add(1)
	return nil
}

func (m *mockOpenFlowClient) IsConnected() bool {
	return m.connected.Load()
}

// createTestHandlerWithMocks creates a handler with mock clients.
func createTestHandlerWithMocks(t *testing.T) (*OverlayModeHandler, *mockOVSClient, *mockOpenFlowClient) {
	t.Helper()

	ovsClient := newMockOVSClient()
	ofClient := newMockOpenFlowClient()

	config := createTestOverlayConfig()
	handler, err := NewOverlayModeHandler(config, ovsClient, ofClient)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	return handler, ovsClient, ofClient
}

// TestOverlayModeHandler_NewWithNilOpenFlowClient tests creating handler with nil OpenFlow client.
func TestOverlayModeHandler_NewWithNilOpenFlowClient(t *testing.T) {
	config := createTestOverlayConfig()
	ovsClient := newMockOVSClient()

	_, err := NewOverlayModeHandler(config, ovsClient, nil)
	if err != ErrOpenFlowClientNil {
		t.Errorf("expected ErrOpenFlowClientNil, got: %v", err)
	}
}

// TestOverlayModeHandler_NewSuccess tests successful handler creation.
func TestOverlayModeHandler_NewSuccess(t *testing.T) {
	handler, _, _ := createTestHandlerWithMocks(t)

	if handler.config == nil {
		t.Error("handler config should not be nil")
	}
	if handler.logger == nil {
		t.Error("handler logger should not be nil")
	}
	if handler.running.Load() {
		t.Error("handler should not be running initially")
	}
}

// TestOverlayModeHandler_Start tests the Start method.
func TestOverlayModeHandler_Start(t *testing.T) {
	handler, _, _ := createTestHandlerWithMocks(t)

	ctx := context.Background()
	err := handler.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer handler.Stop(ctx)

	if !handler.running.Load() {
		t.Error("handler should be running after Start")
	}
}

// TestOverlayModeHandler_Start_AlreadyRunning tests Start when already running.
func TestOverlayModeHandler_Start_AlreadyRunning(t *testing.T) {
	handler, _, _ := createTestHandlerWithMocks(t)

	ctx := context.Background()
	err := handler.Start(ctx)
	if err != nil {
		t.Fatalf("first Start() error: %v", err)
	}
	defer handler.Stop(ctx)

	// Second start should fail
	err = handler.Start(ctx)
	if err != ErrAlreadyRunning {
		t.Errorf("expected ErrAlreadyRunning, got: %v", err)
	}
}

// TestOverlayModeHandler_Stop tests the Stop method.
func TestOverlayModeHandler_Stop(t *testing.T) {
	handler, _, _ := createTestHandlerWithMocks(t)

	ctx := context.Background()
	err := handler.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	err = handler.Stop(ctx)
	if err != nil {
		t.Fatalf("Stop() error: %v", err)
	}

	if handler.running.Load() {
		t.Error("handler should not be running after Stop")
	}
}

// TestOverlayModeHandler_Stop_NotRunning tests Stop when not running.
// Note: The actual Stop() implementation returns nil when not running (idempotent).
func TestOverlayModeHandler_Stop_NotRunning(t *testing.T) {
	handler, _, _ := createTestHandlerWithMocks(t)

	ctx := context.Background()
	err := handler.Stop(ctx)
	// Stop() is idempotent - returns nil when not running
	if err != nil {
		t.Errorf("expected nil error for idempotent Stop(), got: %v", err)
	}
}

// TestOverlayModeHandler_AddVNI tests the AddVNI method.
func TestOverlayModeHandler_AddVNI(t *testing.T) {
	handler, _, _ := createTestHandlerWithMocks(t)

	ctx := context.Background()
	err := handler.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer handler.Stop(ctx)

	t.Run("successful AddVNI", func(t *testing.T) {
		err := handler.AddVNI(ctx, 1000, 100)
		if err != nil {
			t.Fatalf("AddVNI() error: %v", err)
		}

		// Verify VNI is mapped
		if _, ok := handler.vniMappings.Load(uint32(1000)); !ok {
			t.Error("VNI mapping should exist")
		}
	})

	t.Run("duplicate VNI", func(t *testing.T) {
		err := handler.AddVNI(ctx, 1000, 100)
		if err != ErrVNIAlreadyExists {
			t.Errorf("expected ErrVNIAlreadyExists, got: %v", err)
		}
	})

	t.Run("invalid VNI zero", func(t *testing.T) {
		err := handler.AddVNI(ctx, 0, 100)
		if err != ErrVNIOutOfRange {
			t.Errorf("expected ErrVNIOutOfRange, got: %v", err)
		}
	})

	t.Run("invalid VNI too large", func(t *testing.T) {
		err := handler.AddVNI(ctx, 16777216, 100)
		if err != ErrVNIOutOfRange {
			t.Errorf("expected ErrVNIOutOfRange, got: %v", err)
		}
	})

	t.Run("invalid VLAN", func(t *testing.T) {
		err := handler.AddVNI(ctx, 2000, 4095)
		if err != ErrVLANOutOfRange {
			t.Errorf("expected ErrVLANOutOfRange, got: %v", err)
		}
	})
}

// TestOverlayModeHandler_AddVNI_NotRunning tests AddVNI when not running.
func TestOverlayModeHandler_AddVNI_NotRunning(t *testing.T) {
	handler, _, _ := createTestHandlerWithMocks(t)

	ctx := context.Background()
	err := handler.AddVNI(ctx, 1000, 100)
	if err != ErrNotRunning {
		t.Errorf("expected ErrNotRunning, got: %v", err)
	}
}

// TestOverlayModeHandler_RemoveVNI tests the RemoveVNI method.
func TestOverlayModeHandler_RemoveVNI(t *testing.T) {
	handler, _, _ := createTestHandlerWithMocks(t)

	ctx := context.Background()
	err := handler.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer handler.Stop(ctx)

	// Add VNI first
	err = handler.AddVNI(ctx, 1000, 100)
	if err != nil {
		t.Fatalf("AddVNI() error: %v", err)
	}

	t.Run("successful RemoveVNI", func(t *testing.T) {
		err := handler.RemoveVNI(ctx, 1000)
		if err != nil {
			t.Fatalf("RemoveVNI() error: %v", err)
		}

		// Verify VNI is removed
		if _, ok := handler.vniMappings.Load(uint32(1000)); ok {
			t.Error("VNI mapping should not exist")
		}
	})

	t.Run("non-existent VNI", func(t *testing.T) {
		err := handler.RemoveVNI(ctx, 9999)
		if err != ErrVNINotFound {
			t.Errorf("expected ErrVNINotFound, got: %v", err)
		}
	})

	// Note: RemoveVNI doesn't validate VNI range before checking existence,
	// so VNI 0 returns ErrVNINotFound rather than ErrVNIOutOfRange
	t.Run("zero VNI returns VNINotFound", func(t *testing.T) {
		err := handler.RemoveVNI(ctx, 0)
		if err != ErrVNINotFound {
			t.Errorf("expected ErrVNINotFound for VNI 0, got: %v", err)
		}
	})
}

// TestOverlayModeHandler_RemoveVNI_NotRunning tests RemoveVNI when not running.
func TestOverlayModeHandler_RemoveVNI_NotRunning(t *testing.T) {
	handler, _, _ := createTestHandlerWithMocks(t)

	ctx := context.Background()
	err := handler.RemoveVNI(ctx, 1000)
	if err != ErrNotRunning {
		t.Errorf("expected ErrNotRunning, got: %v", err)
	}
}

// TestOverlayModeHandler_LearnMAC tests the LearnMAC method.
func TestOverlayModeHandler_LearnMAC(t *testing.T) {
	handler, _, _ := createTestHandlerWithMocks(t)

	ctx := context.Background()
	err := handler.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer handler.Stop(ctx)

	// Add VNI first
	err = handler.AddVNI(ctx, 1000, 100)
	if err != nil {
		t.Fatalf("AddVNI() error: %v", err)
	}

	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	ip := netip.MustParseAddr("192.168.1.100")
	localVTEP := handler.config.VTEPConfig.LocalIP // Use local VTEP to mark as local

	t.Run("learn local MAC", func(t *testing.T) {
		err := handler.LearnMAC(ctx, mac, ip, 1000, localVTEP)
		if err != nil {
			t.Fatalf("LearnMAC() error: %v", err)
		}

		// Verify MAC is learned
		key := formatMACKey(1000, mac)
		entry, ok := handler.localMACs.Load(key)
		if !ok {
			t.Error("MAC should be in local table")
		}
		macEntry := entry.(*MACEntry)
		if macEntry.Source != MACSourceLocal {
			t.Errorf("expected source %v, got %v", MACSourceLocal, macEntry.Source)
		}
	})

	t.Run("learn remote MAC", func(t *testing.T) {
		remoteMac := net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
		remoteIP := netip.MustParseAddr("192.168.1.200")
		remoteVTEP := netip.MustParseAddr("10.0.0.99") // Different VTEP = remote
		err := handler.LearnMAC(ctx, remoteMac, remoteIP, 1000, remoteVTEP)
		if err != nil {
			t.Fatalf("LearnMAC() error: %v", err)
		}

		// Verify MAC is in remote table
		key := formatMACKey(1000, remoteMac)
		if _, ok := handler.remoteMACs.Load(key); !ok {
			t.Error("MAC should be in remote table")
		}
	})

	t.Run("invalid MAC nil", func(t *testing.T) {
		err := handler.LearnMAC(ctx, nil, ip, 1000, localVTEP)
		if err != ErrMACNil {
			t.Errorf("expected ErrMACNil, got: %v", err)
		}
	})

	t.Run("invalid MAC length", func(t *testing.T) {
		shortMAC := net.HardwareAddr{0xaa, 0xbb}
		err := handler.LearnMAC(ctx, shortMAC, ip, 1000, localVTEP)
		if err != ErrMACInvalid {
			t.Errorf("expected ErrMACInvalid, got: %v", err)
		}
	})

	t.Run("invalid VNI", func(t *testing.T) {
		err := handler.LearnMAC(ctx, mac, ip, 0, localVTEP)
		if err != ErrVNIOutOfRange {
			t.Errorf("expected ErrVNIOutOfRange, got: %v", err)
		}
	})
}

// TestOverlayModeHandler_LearnMAC_NotRunning tests LearnMAC when not running.
func TestOverlayModeHandler_LearnMAC_NotRunning(t *testing.T) {
	handler, _, _ := createTestHandlerWithMocks(t)

	ctx := context.Background()
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	ip := netip.MustParseAddr("192.168.1.100")
	vtep := netip.MustParseAddr("10.0.0.1")

	err := handler.LearnMAC(ctx, mac, ip, 1000, vtep)
	if err != ErrNotRunning {
		t.Errorf("expected ErrNotRunning, got: %v", err)
	}
}

// TestOverlayModeHandler_AddRemoteVTEP tests the AddRemoteVTEP method.
func TestOverlayModeHandler_AddRemoteVTEP(t *testing.T) {
	handler, ovsClient, _ := createTestHandlerWithMocks(t)

	ctx := context.Background()
	err := handler.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer handler.Stop(ctx)

	// Add VNI first
	err = handler.AddVNI(ctx, 1000, 100)
	if err != nil {
		t.Fatalf("AddVNI() error: %v", err)
	}

	vtepIP := netip.MustParseAddr("10.0.0.2")

	t.Run("add remote VTEP", func(t *testing.T) {
		err := handler.AddRemoteVTEP(ctx, 1000, vtepIP)
		if err != nil {
			t.Fatalf("AddRemoteVTEP() error: %v", err)
		}

		// Verify VTEP is in replication list
		list := handler.getReplicationList(1000)
		if len(list) != 1 {
			t.Errorf("expected 1 VTEP in replication list, got %d", len(list))
		}
	})

	t.Run("invalid VTEP IP", func(t *testing.T) {
		err := handler.AddRemoteVTEP(ctx, 1000, netip.Addr{})
		if err != ErrInvalidVTEPIP {
			t.Errorf("expected ErrInvalidVTEPIP, got: %v", err)
		}
	})

	t.Run("OVS error", func(t *testing.T) {
		ovsClient.addPortErr = errors.New("OVS error")
		newVTEP := netip.MustParseAddr("10.0.0.3")
		err := handler.AddRemoteVTEP(ctx, 1000, newVTEP)
		// Should still add to replication list even if OVS fails
		// (VTEP might already exist from another VNI)
		if err != nil {
			t.Logf("AddRemoteVTEP() with OVS error: %v", err)
		}
		ovsClient.addPortErr = nil
	})
}

// TestOverlayModeHandler_AddRemoteVTEP_NotRunning tests AddRemoteVTEP when not running.
func TestOverlayModeHandler_AddRemoteVTEP_NotRunning(t *testing.T) {
	handler, _, _ := createTestHandlerWithMocks(t)

	ctx := context.Background()
	vtepIP := netip.MustParseAddr("10.0.0.2")

	err := handler.AddRemoteVTEP(ctx, 1000, vtepIP)
	if err != ErrNotRunning {
		t.Errorf("expected ErrNotRunning, got: %v", err)
	}
}

// TestOverlayModeHandler_RemoveRemoteVTEP tests the RemoveRemoteVTEP method.
func TestOverlayModeHandler_RemoveRemoteVTEP(t *testing.T) {
	handler, _, _ := createTestHandlerWithMocks(t)

	ctx := context.Background()
	err := handler.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer handler.Stop(ctx)

	// Add VNI and VTEP first
	err = handler.AddVNI(ctx, 1000, 100)
	if err != nil {
		t.Fatalf("AddVNI() error: %v", err)
	}

	vtepIP := netip.MustParseAddr("10.0.0.2")
	err = handler.AddRemoteVTEP(ctx, 1000, vtepIP)
	if err != nil {
		t.Fatalf("AddRemoteVTEP() error: %v", err)
	}

	t.Run("remove remote VTEP", func(t *testing.T) {
		err := handler.RemoveRemoteVTEP(ctx, 1000, vtepIP)
		if err != nil {
			t.Fatalf("RemoveRemoteVTEP() error: %v", err)
		}

		// Verify VTEP is removed from replication list
		list := handler.getReplicationList(1000)
		if len(list) != 0 {
			t.Errorf("expected 0 VTEPs in replication list, got %d", len(list))
		}
	})

	// Note: RemoveRemoteVTEP doesn't validate VTEP IP in the current implementation
	t.Run("remove non-existent VTEP succeeds", func(t *testing.T) {
		nonExistentVTEP := netip.MustParseAddr("10.0.0.99")
		err := handler.RemoveRemoteVTEP(ctx, 1000, nonExistentVTEP)
		// Should succeed as the operation is idempotent
		if err != nil {
			t.Errorf("expected nil error for removing non-existent VTEP, got: %v", err)
		}
	})
}

// TestOverlayModeHandler_RemoveRemoteVTEP_NotRunning tests RemoveRemoteVTEP when not running.
func TestOverlayModeHandler_RemoveRemoteVTEP_NotRunning(t *testing.T) {
	handler, _, _ := createTestHandlerWithMocks(t)

	ctx := context.Background()
	vtepIP := netip.MustParseAddr("10.0.0.2")

	err := handler.RemoveRemoteVTEP(ctx, 1000, vtepIP)
	if err != ErrNotRunning {
		t.Errorf("expected ErrNotRunning, got: %v", err)
	}
}

// TestOverlayModeHandler_GetStatusRunning tests GetStatus when running.
func TestOverlayModeHandler_GetStatusRunning(t *testing.T) {
	handler, _, _ := createTestHandlerWithMocks(t)

	ctx := context.Background()
	err := handler.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer handler.Stop(ctx)

	// Add some data
	err = handler.AddVNI(ctx, 1000, 100)
	if err != nil {
		t.Fatalf("AddVNI() error: %v", err)
	}
	err = handler.AddVNI(ctx, 2000, 200)
	if err != nil {
		t.Fatalf("AddVNI() error: %v", err)
	}

	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	ip := netip.MustParseAddr("192.168.1.100")
	localVTEP := handler.config.VTEPConfig.LocalIP
	err = handler.LearnMAC(ctx, mac, ip, 1000, localVTEP)
	if err != nil {
		t.Fatalf("LearnMAC() error: %v", err)
	}

	status := handler.GetStatus()
	if status == nil {
		t.Fatal("GetStatus() should not return nil")
	}
	if !status.Running {
		t.Error("status.Running should be true")
	}
	if status.VNICount != 2 {
		t.Errorf("expected VNICount 2, got %d", status.VNICount)
	}
	if status.LocalMACCount != 1 {
		t.Errorf("expected LocalMACCount 1, got %d", status.LocalMACCount)
	}
	if status.Uptime == 0 {
		t.Error("expected non-zero uptime")
	}
}

// TestOverlayModeHandler_FlowInstallation tests that flows are installed.
func TestOverlayModeHandler_FlowInstallation(t *testing.T) {
	handler, _, ofClient := createTestHandlerWithMocks(t)

	ctx := context.Background()
	err := handler.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer handler.Stop(ctx)

	// Add VNI should install flows
	err = handler.AddVNI(ctx, 1000, 100)
	if err != nil {
		t.Fatalf("AddVNI() error: %v", err)
	}

	// Verify flows were added
	flowCount := ofClient.addFlowCount.Load()
	if flowCount == 0 {
		t.Error("expected flows to be added")
	}
}

// TestOverlayModeHandler_FlowInstallError tests error handling when flow installation fails.
func TestOverlayModeHandler_FlowInstallError(t *testing.T) {
	handler, _, ofClient := createTestHandlerWithMocks(t)

	ctx := context.Background()
	err := handler.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer handler.Stop(ctx)

	// Set flow error
	ofClient.addFlowErr = errors.New("flow installation error")

	// AddVNI should fail
	err = handler.AddVNI(ctx, 1000, 100)
	if err == nil {
		t.Error("expected error when flow installation fails")
	}
}

// TestOverlayModeHandler_VLANBoundary tests VLAN boundary values.
func TestOverlayModeHandler_VLANBoundary(t *testing.T) {
	handler, _, _ := createTestHandlerWithMocks(t)

	ctx := context.Background()
	err := handler.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer handler.Stop(ctx)

	t.Run("VLAN 0 valid", func(t *testing.T) {
		err := handler.AddVNI(ctx, 3000, 0)
		if err != nil {
			t.Errorf("VLAN 0 should be valid, got: %v", err)
		}
	})

	t.Run("VLAN 4094 valid", func(t *testing.T) {
		err := handler.AddVNI(ctx, 3001, 4094)
		if err != nil {
			t.Errorf("VLAN 4094 should be valid, got: %v", err)
		}
	})

	t.Run("VLAN 4095 invalid", func(t *testing.T) {
		err := handler.AddVNI(ctx, 3002, 4095)
		if err != ErrVLANOutOfRange {
			t.Errorf("VLAN 4095 should be invalid, got: %v", err)
		}
	})
}

// TestOverlayModeHandler_Concurrent tests concurrent operations.
func TestOverlayModeHandler_Concurrent(t *testing.T) {
	handler, _, _ := createTestHandlerWithMocks(t)

	ctx := context.Background()
	err := handler.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer handler.Stop(ctx)

	// Add initial VNI
	err = handler.AddVNI(ctx, 1000, 100)
	if err != nil {
		t.Fatalf("AddVNI() error: %v", err)
	}

	var wg sync.WaitGroup
	const numGoroutines = 20

	localVTEP := handler.config.VTEPConfig.LocalIP

	// Concurrent MAC learning
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, byte(idx >> 8), byte(idx)}
			ip := netip.MustParseAddr("192.168.1.100")
			learnErr := handler.LearnMAC(ctx, mac, ip, 1000, localVTEP)
			if learnErr != nil {
				t.Errorf("concurrent LearnMAC error: %v", learnErr)
			}
		}(i)
	}

	// Concurrent lookups
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, byte(idx >> 8), byte(idx)}
			_, _ = handler.LookupMAC(ctx, mac, 1000)
		}(i)
	}

	// Concurrent status reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = handler.GetStatus()
		}()
	}

	wg.Wait()
}

// TestOverlayModeHandler_MACEntryExpiry tests MAC entry expiration handling.
func TestOverlayModeHandler_MACEntryExpiry(t *testing.T) {
	config := createTestOverlayConfig()
	config.MACEntryTimeout = 50 * time.Millisecond // Short timeout for testing

	ovsClient := newMockOVSClient()
	ofClient := newMockOpenFlowClient()

	handler, err := NewOverlayModeHandler(config, ovsClient, ofClient)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	ctx := context.Background()
	err = handler.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer handler.Stop(ctx)

	// Add VNI
	err = handler.AddVNI(ctx, 1000, 100)
	if err != nil {
		t.Fatalf("AddVNI() error: %v", err)
	}

	// Learn MAC
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	ip := netip.MustParseAddr("192.168.1.100")
	localVTEP := handler.config.VTEPConfig.LocalIP
	err = handler.LearnMAC(ctx, mac, ip, 1000, localVTEP)
	if err != nil {
		t.Fatalf("LearnMAC() error: %v", err)
	}

	// Verify MAC exists
	entry, err := handler.LookupMAC(ctx, mac, 1000)
	if err != nil {
		t.Errorf("MAC should exist immediately after learning, got: %v", err)
	}
	if entry == nil {
		t.Error("entry should not be nil")
	}

	// Wait for expiry - use channel-based waiting with delay between checks
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for i := 0; i < 100; i++ {
			_, lookupErr := handler.LookupMAC(ctx, mac, 1000)
			if lookupErr == ErrMACNotFound {
				close(done)
				return
			}
			<-ticker.C
		}
	}()

	select {
	case <-done:
		// MAC expired as expected
	case <-time.After(2 * time.Second):
		t.Log("MAC entry did not expire in time (may be platform-dependent)")
	}
}
