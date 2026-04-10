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

package container

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// MockOVSClient implements OVSClient for testing.
type MockOVSClient struct {
	mu              sync.Mutex
	connected       bool
	ports           map[string]map[string]uint16 // bridge -> port -> vlan
	ofPorts         map[string]int32             // port -> ofport
	flows           map[string][]*OVSFlow        // bridge -> flows
	connectErr      error
	addPortErr      error
	deletePortErr   error
	setVLANErr      error
	getOFPortErr    error
	addFlowErr      error
	deleteFlowErr   error
	addPortCalls    int
	deletePortCalls int
	addFlowCalls    int
	deleteFlowCalls int
}

func NewMockOVSClient() *MockOVSClient {
	return &MockOVSClient{
		ports:   make(map[string]map[string]uint16),
		ofPorts: make(map[string]int32),
		flows:   make(map[string][]*OVSFlow),
	}
}

func (m *MockOVSClient) Connect(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.connectErr != nil {
		return m.connectErr
	}
	m.connected = true
	return nil
}

func (m *MockOVSClient) Disconnect() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connected = false
	return nil
}

func (m *MockOVSClient) IsConnected() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.connected
}

func (m *MockOVSClient) AddPort(ctx context.Context, bridgeName, portName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.addPortCalls++
	if m.addPortErr != nil {
		return m.addPortErr
	}
	if _, exists := m.ports[bridgeName]; !exists {
		m.ports[bridgeName] = make(map[string]uint16)
	}
	m.ports[bridgeName][portName] = 0
	// Auto-assign OF port number
	m.ofPorts[portName] = int32(100 + len(m.ofPorts))
	return nil
}

func (m *MockOVSClient) DeletePort(ctx context.Context, bridgeName, portName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deletePortCalls++
	if m.deletePortErr != nil {
		return m.deletePortErr
	}
	if bridge, exists := m.ports[bridgeName]; exists {
		delete(bridge, portName)
	}
	delete(m.ofPorts, portName)
	return nil
}

func (m *MockOVSClient) SetPortVLAN(ctx context.Context, portName string, vlanID uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.setVLANErr != nil {
		return m.setVLANErr
	}
	for _, bridge := range m.ports {
		if _, exists := bridge[portName]; exists {
			bridge[portName] = vlanID
			return nil
		}
	}
	return errors.New("port not found")
}

func (m *MockOVSClient) GetOFPort(ctx context.Context, portName string) (int32, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.getOFPortErr != nil {
		return 0, m.getOFPortErr
	}
	if ofPort, exists := m.ofPorts[portName]; exists {
		return ofPort, nil
	}
	return 0, errors.New("port not found")
}

func (m *MockOVSClient) AddFlow(ctx context.Context, bridgeName string, flow *OVSFlow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.addFlowCalls++
	if m.addFlowErr != nil {
		return m.addFlowErr
	}
	m.flows[bridgeName] = append(m.flows[bridgeName], flow)
	return nil
}

func (m *MockOVSClient) DeleteFlow(ctx context.Context, bridgeName string, match string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteFlowCalls++
	if m.deleteFlowErr != nil {
		return m.deleteFlowErr
	}
	// Remove matching flows
	if flows, exists := m.flows[bridgeName]; exists {
		newFlows := make([]*OVSFlow, 0)
		for _, f := range flows {
			if f.Match != match {
				newFlows = append(newFlows, f)
			}
		}
		m.flows[bridgeName] = newFlows
	}
	return nil
}

func (m *MockOVSClient) DeleteFlowsByPort(ctx context.Context, bridgeName string, portName string, ofPort int32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteFlowCalls++
	if m.deleteFlowErr != nil {
		return m.deleteFlowErr
	}
	// Clear all flows for the bridge (simplified)
	delete(m.flows, bridgeName)
	return nil
}

// MockOpenFlowController implements OpenFlowController for testing.
type MockOpenFlowController struct {
	mu              sync.Mutex
	flows           []*InternalOpenFlowRule
	addFlowErr      error
	deleteFlowErr   error
	addFlowCalls    int
	deleteFlowCalls int
}

func NewMockOpenFlowController() *MockOpenFlowController {
	return &MockOpenFlowController{
		flows: make([]*InternalOpenFlowRule, 0),
	}
}

func (m *MockOpenFlowController) AddFlow(ctx context.Context, flow *InternalOpenFlowRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.addFlowCalls++
	if m.addFlowErr != nil {
		return m.addFlowErr
	}
	m.flows = append(m.flows, flow)
	return nil
}

func (m *MockOpenFlowController) DeleteFlow(ctx context.Context, flow *InternalOpenFlowRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteFlowCalls++
	if m.deleteFlowErr != nil {
		return m.deleteFlowErr
	}
	return nil
}

func (m *MockOpenFlowController) DeleteFlowsByPort(ctx context.Context, portName string, ofPort int32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteFlowCalls++
	if m.deleteFlowErr != nil {
		return m.deleteFlowErr
	}
	m.flows = nil
	return nil
}

func (m *MockOpenFlowController) ModifyFlow(ctx context.Context, flow *InternalOpenFlowRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return nil
}

func (m *MockOpenFlowController) ListFlows(ctx context.Context, match *InternalOpenFlowMatch) ([]*InternalOpenFlowRule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.flows, nil
}

// Test helper to create a default config.
func testNetworkManagerConfig() NetworkManagerConfig {
	return NetworkManagerConfig{
		OVSBridge:          "br-test",
		OpenFlowController: "tcp:127.0.0.1:6653",
		DefaultVLAN:        100,
		FlowTableBase:      0,
		FlowPriorityBase:   100,
		PortNamePrefix:     "test-",
		CleanupOnTeardown:  true,
		ConnectionTimeout:  5 * time.Second,
	}
}

// TestNetworkManagerConfigValidate tests NetworkManagerConfig validation.
func TestNetworkManagerConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  NetworkManagerConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: NetworkManagerConfig{
				OVSBridge:         "br-test",
				DefaultVLAN:       100,
				FlowTableBase:     0,
				FlowPriorityBase:  100,
				ConnectionTimeout: 5 * time.Second,
			},
			wantErr: false,
		},
		{
			name: "empty bridge name",
			config: NetworkManagerConfig{
				OVSBridge:   "",
				DefaultVLAN: 100,
			},
			wantErr: true,
		},
		{
			name: "invalid VLAN",
			config: NetworkManagerConfig{
				OVSBridge:   "br-test",
				DefaultVLAN: 5000, // > 4094
			},
			wantErr: true,
		},
		{
			name: "zero values use defaults",
			config: NetworkManagerConfig{
				OVSBridge:        "br-test",
				DefaultVLAN:      0,
				FlowTableBase:    -1, // Will be set to default
				FlowPriorityBase: 0,  // Will be set to default
				PortNamePrefix:   "", // Will use default
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestNewSDNNetworkManager tests SDNNetworkManager construction.
func TestNewSDNNetworkManager(t *testing.T) {
	tests := []struct {
		name    string
		config  NetworkManagerConfig
		ovs     OVSClient
		wantErr bool
	}{
		{
			name:    "valid construction",
			config:  testNetworkManagerConfig(),
			ovs:     NewMockOVSClient(),
			wantErr: false,
		},
		{
			name: "invalid config",
			config: NetworkManagerConfig{
				OVSBridge: "", // Invalid
			},
			ovs:     NewMockOVSClient(),
			wantErr: true,
		},
		{
			name:    "nil OVS client",
			config:  testNetworkManagerConfig(),
			ovs:     nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nm, err := NewSDNNetworkManager(tt.config, tt.ovs, nil, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewSDNNetworkManager() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && nm == nil {
				t.Error("NewSDNNetworkManager() returned nil without error")
			}
		})
	}
}

// TestSetupContainerNetwork tests container network setup.
func TestSetupContainerNetwork(t *testing.T) {
	ctx := context.Background()

	t.Run("SDN mode success", func(t *testing.T) {
		mockOVS := NewMockOVSClient()
		mockOVS.connected = true

		nm, err := NewSDNNetworkManager(testNetworkManagerConfig(), mockOVS, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create SDNNetworkManager: %v", err)
		}

		cfg := &ContainerNetworkConfig{
			Mode: NetworkModeSDN,
			SDN: &SDNConfig{
				Bridge: "br-test",
				VLANID: 200,
			},
		}

		err = nm.SetupContainerNetwork(ctx, "container-123456789012", cfg)
		if err != nil {
			t.Fatalf("SetupContainerNetwork() error = %v", err)
		}

		// Verify via GetContainerNetworkInfo
		info, err := nm.GetContainerNetworkInfo(ctx, "container-123456789012")
		if err != nil {
			t.Fatalf("GetContainerNetworkInfo() error = %v", err)
		}

		if info.VLANID != 200 {
			t.Errorf("VLANID = %d, want 200", info.VLANID)
		}

		if info.Mode != NetworkModeSDN {
			t.Errorf("Mode = %s, want %s", info.Mode, NetworkModeSDN)
		}

		if mockOVS.addPortCalls != 1 {
			t.Errorf("AddPort called %d times, want 1", mockOVS.addPortCalls)
		}
	})

	t.Run("bridge mode success", func(t *testing.T) {
		mockOVS := NewMockOVSClient()

		nm, err := NewSDNNetworkManager(testNetworkManagerConfig(), mockOVS, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create SDNNetworkManager: %v", err)
		}

		cfg := &ContainerNetworkConfig{
			Mode: NetworkModeBridge,
		}

		err = nm.SetupContainerNetwork(ctx, "container-bridge", cfg)
		if err != nil {
			t.Fatalf("SetupContainerNetwork() error = %v", err)
		}

		info, _ := nm.GetContainerNetworkInfo(ctx, "container-bridge")
		if info.Mode != NetworkModeBridge {
			t.Errorf("Mode = %s, want %s", info.Mode, NetworkModeBridge)
		}

		// Should not call OVS for bridge mode
		if mockOVS.addPortCalls != 0 {
			t.Errorf("AddPort called %d times, want 0 for bridge mode", mockOVS.addPortCalls)
		}
	})

	t.Run("host mode success", func(t *testing.T) {
		mockOVS := NewMockOVSClient()

		nm, err := NewSDNNetworkManager(testNetworkManagerConfig(), mockOVS, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create SDNNetworkManager: %v", err)
		}

		cfg := &ContainerNetworkConfig{
			Mode: NetworkModeHost,
		}

		err = nm.SetupContainerNetwork(ctx, "container-host", cfg)
		if err != nil {
			t.Fatalf("SetupContainerNetwork() error = %v", err)
		}

		info, _ := nm.GetContainerNetworkInfo(ctx, "container-host")
		if info.Mode != NetworkModeHost {
			t.Errorf("Mode = %s, want %s", info.Mode, NetworkModeHost)
		}
	})

	t.Run("none mode success", func(t *testing.T) {
		mockOVS := NewMockOVSClient()

		nm, err := NewSDNNetworkManager(testNetworkManagerConfig(), mockOVS, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create SDNNetworkManager: %v", err)
		}

		cfg := &ContainerNetworkConfig{
			Mode: NetworkModeNone,
		}

		err = nm.SetupContainerNetwork(ctx, "container-none", cfg)
		if err != nil {
			t.Fatalf("SetupContainerNetwork() error = %v", err)
		}

		info, _ := nm.GetContainerNetworkInfo(ctx, "container-none")
		if info.Mode != NetworkModeNone {
			t.Errorf("Mode = %s, want %s", info.Mode, NetworkModeNone)
		}
	})

	t.Run("empty container ID", func(t *testing.T) {
		mockOVS := NewMockOVSClient()

		nm, err := NewSDNNetworkManager(testNetworkManagerConfig(), mockOVS, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create SDNNetworkManager: %v", err)
		}

		err = nm.SetupContainerNetwork(ctx, "", &ContainerNetworkConfig{Mode: NetworkModeBridge})
		if !errors.Is(err, ErrInvalidContainerID) {
			t.Errorf("SetupContainerNetwork() error = %v, want ErrInvalidContainerID", err)
		}
	})

	t.Run("nil config", func(t *testing.T) {
		mockOVS := NewMockOVSClient()

		nm, err := NewSDNNetworkManager(testNetworkManagerConfig(), mockOVS, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create SDNNetworkManager: %v", err)
		}

		err = nm.SetupContainerNetwork(ctx, "container-123", nil)
		if !errors.Is(err, ErrInvalidNetworkMode) {
			t.Errorf("SetupContainerNetwork() error = %v, want ErrInvalidNetworkMode", err)
		}
	})

	t.Run("SDN mode without SDN config", func(t *testing.T) {
		mockOVS := NewMockOVSClient()

		nm, err := NewSDNNetworkManager(testNetworkManagerConfig(), mockOVS, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create SDNNetworkManager: %v", err)
		}

		cfg := &ContainerNetworkConfig{
			Mode: NetworkModeSDN,
			SDN:  nil,
		}

		err = nm.SetupContainerNetwork(ctx, "container-123", cfg)
		if !errors.Is(err, ErrInvalidNetworkMode) {
			t.Errorf("SetupContainerNetwork() error = %v, want ErrInvalidNetworkMode", err)
		}
	})

	t.Run("OVS not connected auto-connect", func(t *testing.T) {
		mockOVS := NewMockOVSClient()
		mockOVS.connected = false

		nm, err := NewSDNNetworkManager(testNetworkManagerConfig(), mockOVS, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create SDNNetworkManager: %v", err)
		}

		cfg := &ContainerNetworkConfig{
			Mode: NetworkModeSDN,
			SDN: &SDNConfig{
				Bridge: "br-test",
				VLANID: 100,
			},
		}

		err = nm.SetupContainerNetwork(ctx, "container-123", cfg)
		if err != nil {
			t.Fatalf("SetupContainerNetwork() should auto-connect: %v", err)
		}

		if !mockOVS.connected {
			t.Error("OVS should be connected after setup")
		}
	})

	t.Run("OVS connect error", func(t *testing.T) {
		mockOVS := NewMockOVSClient()
		mockOVS.connected = false
		mockOVS.connectErr = errors.New("connection refused")

		nm, err := NewSDNNetworkManager(testNetworkManagerConfig(), mockOVS, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create SDNNetworkManager: %v", err)
		}

		cfg := &ContainerNetworkConfig{
			Mode: NetworkModeSDN,
			SDN: &SDNConfig{
				Bridge: "br-test",
				VLANID: 100,
			},
		}

		err = nm.SetupContainerNetwork(ctx, "container-123", cfg)
		if !errors.Is(err, ErrOVSConnectionFailed) {
			t.Errorf("SetupContainerNetwork() error = %v, want ErrOVSConnectionFailed", err)
		}
	})

	t.Run("add port error", func(t *testing.T) {
		mockOVS := NewMockOVSClient()
		mockOVS.connected = true
		mockOVS.addPortErr = errors.New("port exists")

		nm, err := NewSDNNetworkManager(testNetworkManagerConfig(), mockOVS, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create SDNNetworkManager: %v", err)
		}

		cfg := &ContainerNetworkConfig{
			Mode: NetworkModeSDN,
			SDN: &SDNConfig{
				Bridge: "br-test",
				VLANID: 100,
			},
		}

		err = nm.SetupContainerNetwork(ctx, "container-123", cfg)
		if !errors.Is(err, ErrNetworkSetupFailed) {
			t.Errorf("SetupContainerNetwork() error = %v, want ErrNetworkSetupFailed", err)
		}
	})

	t.Run("set VLAN error cleans up port", func(t *testing.T) {
		mockOVS := NewMockOVSClient()
		mockOVS.connected = true
		mockOVS.setVLANErr = errors.New("VLAN error")

		nm, err := NewSDNNetworkManager(testNetworkManagerConfig(), mockOVS, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create SDNNetworkManager: %v", err)
		}

		cfg := &ContainerNetworkConfig{
			Mode: NetworkModeSDN,
			SDN: &SDNConfig{
				Bridge: "br-test",
				VLANID: 100,
			},
		}

		err = nm.SetupContainerNetwork(ctx, "container-123", cfg)
		if !errors.Is(err, ErrVLANConfigFailed) {
			t.Errorf("SetupContainerNetwork() error = %v, want ErrVLANConfigFailed", err)
		}

		// Port should be cleaned up
		if mockOVS.deletePortCalls != 1 {
			t.Errorf("DeletePort called %d times, want 1 for cleanup", mockOVS.deletePortCalls)
		}
	})

	t.Run("closed network manager", func(t *testing.T) {
		mockOVS := NewMockOVSClient()

		nm, err := NewSDNNetworkManager(testNetworkManagerConfig(), mockOVS, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create SDNNetworkManager: %v", err)
		}

		nm.Close()

		err = nm.SetupContainerNetwork(ctx, "container-123", &ContainerNetworkConfig{Mode: NetworkModeBridge})
		if !errors.Is(err, ErrOrchestratorClosed) {
			t.Errorf("SetupContainerNetwork() error = %v, want ErrOrchestratorClosed", err)
		}
	})
}

// TestTeardownContainerNetwork tests container network teardown.
func TestTeardownContainerNetwork(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		mockOVS := NewMockOVSClient()
		mockOVS.connected = true

		nm, err := NewSDNNetworkManager(testNetworkManagerConfig(), mockOVS, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create SDNNetworkManager: %v", err)
		}

		// Setup first
		cfg := &ContainerNetworkConfig{
			Mode: NetworkModeSDN,
			SDN: &SDNConfig{
				Bridge: "br-test",
				VLANID: 100,
			},
		}
		err = nm.SetupContainerNetwork(ctx, "container-123", cfg)
		if err != nil {
			t.Fatalf("SetupContainerNetwork() error = %v", err)
		}

		// Teardown
		err = nm.TeardownContainerNetwork(ctx, "container-123")
		if err != nil {
			t.Errorf("TeardownContainerNetwork() error = %v", err)
		}

		// Verify cleanup
		if mockOVS.deletePortCalls != 1 {
			t.Errorf("DeletePort called %d times, want 1", mockOVS.deletePortCalls)
		}
	})

	t.Run("container not found", func(t *testing.T) {
		mockOVS := NewMockOVSClient()

		nm, err := NewSDNNetworkManager(testNetworkManagerConfig(), mockOVS, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create SDNNetworkManager: %v", err)
		}

		err = nm.TeardownContainerNetwork(ctx, "nonexistent")
		if !errors.Is(err, ErrContainerNotFound) {
			t.Errorf("TeardownContainerNetwork() error = %v, want ErrContainerNotFound", err)
		}
	})

	t.Run("empty container ID", func(t *testing.T) {
		mockOVS := NewMockOVSClient()

		nm, err := NewSDNNetworkManager(testNetworkManagerConfig(), mockOVS, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create SDNNetworkManager: %v", err)
		}

		err = nm.TeardownContainerNetwork(ctx, "")
		if !errors.Is(err, ErrInvalidContainerID) {
			t.Errorf("TeardownContainerNetwork() error = %v, want ErrInvalidContainerID", err)
		}
	})

	t.Run("non-SDN mode skips OVS cleanup", func(t *testing.T) {
		mockOVS := NewMockOVSClient()

		nm, err := NewSDNNetworkManager(testNetworkManagerConfig(), mockOVS, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create SDNNetworkManager: %v", err)
		}

		// Setup bridge mode
		cfg := &ContainerNetworkConfig{
			Mode: NetworkModeBridge,
		}
		err = nm.SetupContainerNetwork(ctx, "container-bridge", cfg)
		if err != nil {
			t.Fatalf("SetupContainerNetwork() error = %v", err)
		}

		// Teardown should succeed without OVS calls
		err = nm.TeardownContainerNetwork(ctx, "container-bridge")
		if err != nil {
			t.Errorf("TeardownContainerNetwork() error = %v", err)
		}

		// Should not call delete port for bridge mode
		if mockOVS.deletePortCalls != 0 {
			t.Errorf("DeletePort called %d times, want 0 for bridge mode", mockOVS.deletePortCalls)
		}
	})

	t.Run("closed network manager", func(t *testing.T) {
		mockOVS := NewMockOVSClient()

		nm, err := NewSDNNetworkManager(testNetworkManagerConfig(), mockOVS, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create SDNNetworkManager: %v", err)
		}

		nm.Close()

		err = nm.TeardownContainerNetwork(ctx, "container-123")
		if !errors.Is(err, ErrOrchestratorClosed) {
			t.Errorf("TeardownContainerNetwork() error = %v, want ErrOrchestratorClosed", err)
		}
	})
}

// TestApplySecurityGroup tests security group application.
func TestApplySecurityGroup(t *testing.T) {
	ctx := context.Background()

	t.Run("success with security group manager", func(t *testing.T) {
		mockOVS := NewMockOVSClient()
		mockOVS.connected = true
		mockOF := NewMockOpenFlowController()
		sgMgr := NewDefaultSecurityGroupManager()

		// Register a security group
		sg := &SecurityGroup{
			Name: "web-frontend",
			Rules: []SecurityGroupRule{
				{
					Direction: DirectionIngress,
					Protocol:  "tcp",
					Port:      443,
					Action:    "allow",
				},
			},
		}
		sgMgr.RegisterSecurityGroup(sg)

		nm, err := NewSDNNetworkManager(testNetworkManagerConfig(), mockOVS, mockOF, sgMgr)
		if err != nil {
			t.Fatalf("Failed to create SDNNetworkManager: %v", err)
		}

		// Setup container
		cfg := &ContainerNetworkConfig{
			Mode: NetworkModeSDN,
			SDN: &SDNConfig{
				Bridge: "br-test",
				VLANID: 100,
			},
		}
		err = nm.SetupContainerNetwork(ctx, "container-123", cfg)
		if err != nil {
			t.Fatalf("SetupContainerNetwork() error = %v", err)
		}

		// Apply security group
		err = nm.ApplySecurityGroup(ctx, "container-123", "web-frontend")
		if err != nil {
			t.Errorf("ApplySecurityGroup() error = %v", err)
		}

		// Verify flows were installed
		if mockOF.addFlowCalls == 0 {
			t.Error("Expected OpenFlow rules to be installed")
		}
	})

	t.Run("container not found", func(t *testing.T) {
		mockOVS := NewMockOVSClient()

		nm, err := NewSDNNetworkManager(testNetworkManagerConfig(), mockOVS, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create SDNNetworkManager: %v", err)
		}

		err = nm.ApplySecurityGroup(ctx, "nonexistent", "sg-test")
		if !errors.Is(err, ErrContainerNotFound) {
			t.Errorf("ApplySecurityGroup() error = %v, want ErrContainerNotFound", err)
		}
	})

	t.Run("empty security group name", func(t *testing.T) {
		mockOVS := NewMockOVSClient()

		nm, err := NewSDNNetworkManager(testNetworkManagerConfig(), mockOVS, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create SDNNetworkManager: %v", err)
		}

		// Setup container
		cfg := &ContainerNetworkConfig{Mode: NetworkModeBridge}
		nm.SetupContainerNetwork(ctx, "container-123", cfg)

		err = nm.ApplySecurityGroup(ctx, "container-123", "")
		if !errors.Is(err, ErrNetworkSetupFailed) {
			t.Errorf("ApplySecurityGroup() error = %v, want ErrNetworkSetupFailed", err)
		}
	})

	t.Run("non-SDN mode returns nil", func(t *testing.T) {
		mockOVS := NewMockOVSClient()

		nm, err := NewSDNNetworkManager(testNetworkManagerConfig(), mockOVS, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create SDNNetworkManager: %v", err)
		}

		// Setup bridge mode container
		cfg := &ContainerNetworkConfig{Mode: NetworkModeBridge}
		nm.SetupContainerNetwork(ctx, "container-123", cfg)

		err = nm.ApplySecurityGroup(ctx, "container-123", "some-sg")
		if err != nil {
			t.Errorf("ApplySecurityGroup() for non-SDN should not error: %v", err)
		}
	})

	t.Run("duplicate security group is idempotent", func(t *testing.T) {
		mockOVS := NewMockOVSClient()
		mockOVS.connected = true
		sgMgr := NewDefaultSecurityGroupManager()

		sg := &SecurityGroup{Name: "test-sg", Rules: []SecurityGroupRule{}}
		sgMgr.RegisterSecurityGroup(sg)

		nm, err := NewSDNNetworkManager(testNetworkManagerConfig(), mockOVS, nil, sgMgr)
		if err != nil {
			t.Fatalf("Failed to create SDNNetworkManager: %v", err)
		}

		cfg := &ContainerNetworkConfig{
			Mode: NetworkModeSDN,
			SDN:  &SDNConfig{Bridge: "br-test", VLANID: 100},
		}
		nm.SetupContainerNetwork(ctx, "container-123", cfg)

		// Apply twice
		nm.ApplySecurityGroup(ctx, "container-123", "test-sg")
		err = nm.ApplySecurityGroup(ctx, "container-123", "test-sg")
		if err != nil {
			t.Errorf("Duplicate ApplySecurityGroup() should not error: %v", err)
		}
	})
}

// TestRemoveSecurityGroup tests security group removal.
func TestRemoveSecurityGroup(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		mockOVS := NewMockOVSClient()
		mockOVS.connected = true
		mockOF := NewMockOpenFlowController()
		sgMgr := NewDefaultSecurityGroupManager()

		sg := &SecurityGroup{Name: "web-frontend", Rules: []SecurityGroupRule{}}
		sgMgr.RegisterSecurityGroup(sg)

		nm, err := NewSDNNetworkManager(testNetworkManagerConfig(), mockOVS, mockOF, sgMgr)
		if err != nil {
			t.Fatalf("Failed to create SDNNetworkManager: %v", err)
		}

		cfg := &ContainerNetworkConfig{
			Mode: NetworkModeSDN,
			SDN:  &SDNConfig{Bridge: "br-test", VLANID: 100},
		}
		nm.SetupContainerNetwork(ctx, "container-123", cfg)
		nm.ApplySecurityGroup(ctx, "container-123", "web-frontend")

		err = nm.RemoveSecurityGroup(ctx, "container-123", "web-frontend")
		if err != nil {
			t.Errorf("RemoveSecurityGroup() error = %v", err)
		}
	})

	t.Run("container not found", func(t *testing.T) {
		mockOVS := NewMockOVSClient()

		nm, err := NewSDNNetworkManager(testNetworkManagerConfig(), mockOVS, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create SDNNetworkManager: %v", err)
		}

		err = nm.RemoveSecurityGroup(ctx, "nonexistent", "sg-test")
		if !errors.Is(err, ErrContainerNotFound) {
			t.Errorf("RemoveSecurityGroup() error = %v, want ErrContainerNotFound", err)
		}
	})

	t.Run("security group not applied returns nil", func(t *testing.T) {
		mockOVS := NewMockOVSClient()
		mockOVS.connected = true

		nm, err := NewSDNNetworkManager(testNetworkManagerConfig(), mockOVS, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create SDNNetworkManager: %v", err)
		}

		cfg := &ContainerNetworkConfig{
			Mode: NetworkModeSDN,
			SDN:  &SDNConfig{Bridge: "br-test", VLANID: 100},
		}
		nm.SetupContainerNetwork(ctx, "container-123", cfg)

		err = nm.RemoveSecurityGroup(ctx, "container-123", "not-applied")
		if err != nil {
			t.Errorf("RemoveSecurityGroup() for non-applied should not error: %v", err)
		}
	})
}

// TestGetContainerNetworkInfo tests retrieving container network info.
func TestGetContainerNetworkInfo(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		mockOVS := NewMockOVSClient()
		mockOVS.connected = true

		nm, err := NewSDNNetworkManager(testNetworkManagerConfig(), mockOVS, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create SDNNetworkManager: %v", err)
		}

		cfg := &ContainerNetworkConfig{
			Mode: NetworkModeSDN,
			SDN: &SDNConfig{
				Bridge:    "br-test",
				VLANID:    200,
				IPAddress: "192.168.1.100",
			},
		}
		nm.SetupContainerNetwork(ctx, "container-123", cfg)

		info, err := nm.GetContainerNetworkInfo(ctx, "container-123")
		if err != nil {
			t.Fatalf("GetContainerNetworkInfo() error = %v", err)
		}

		if info.VLANID != 200 {
			t.Errorf("VLANID = %d, want 200", info.VLANID)
		}

		if info.IPAddress != "192.168.1.100" {
			t.Errorf("IPAddress = %s, want 192.168.1.100", info.IPAddress)
		}
	})

	t.Run("container not found", func(t *testing.T) {
		mockOVS := NewMockOVSClient()

		nm, err := NewSDNNetworkManager(testNetworkManagerConfig(), mockOVS, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create SDNNetworkManager: %v", err)
		}

		_, err = nm.GetContainerNetworkInfo(ctx, "nonexistent")
		if !errors.Is(err, ErrContainerNotFound) {
			t.Errorf("GetContainerNetworkInfo() error = %v, want ErrContainerNotFound", err)
		}
	})

	t.Run("empty container ID", func(t *testing.T) {
		mockOVS := NewMockOVSClient()

		nm, err := NewSDNNetworkManager(testNetworkManagerConfig(), mockOVS, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create SDNNetworkManager: %v", err)
		}

		_, err = nm.GetContainerNetworkInfo(ctx, "")
		if !errors.Is(err, ErrInvalidContainerID) {
			t.Errorf("GetContainerNetworkInfo() error = %v, want ErrInvalidContainerID", err)
		}
	})

	t.Run("returns copy not reference", func(t *testing.T) {
		mockOVS := NewMockOVSClient()
		mockOVS.connected = true

		nm, err := NewSDNNetworkManager(testNetworkManagerConfig(), mockOVS, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create SDNNetworkManager: %v", err)
		}

		cfg := &ContainerNetworkConfig{
			Mode: NetworkModeSDN,
			SDN:  &SDNConfig{Bridge: "br-test", VLANID: 100, SecurityGroups: []string{"sg1"}},
		}
		nm.SetupContainerNetwork(ctx, "container-123", cfg)

		info1, _ := nm.GetContainerNetworkInfo(ctx, "container-123")
		info1.SecurityGroups = append(info1.SecurityGroups, "modified")

		info2, _ := nm.GetContainerNetworkInfo(ctx, "container-123")
		if len(info2.SecurityGroups) != 1 {
			t.Error("Modification of returned info should not affect stored info")
		}
	})
}

// TestListContainerNetworks tests listing all container networks.
func TestListContainerNetworks(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		mockOVS := NewMockOVSClient()
		mockOVS.connected = true

		nm, err := NewSDNNetworkManager(testNetworkManagerConfig(), mockOVS, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create SDNNetworkManager: %v", err)
		}

		// Setup multiple containers
		cfg := &ContainerNetworkConfig{
			Mode: NetworkModeSDN,
			SDN:  &SDNConfig{Bridge: "br-test", VLANID: 100},
		}
		nm.SetupContainerNetwork(ctx, "container-1", cfg)
		nm.SetupContainerNetwork(ctx, "container-2", cfg)

		list, err := nm.ListContainerNetworks(ctx)
		if err != nil {
			t.Fatalf("ListContainerNetworks() error = %v", err)
		}

		if len(list) != 2 {
			t.Errorf("ListContainerNetworks() returned %d items, want 2", len(list))
		}
	})

	t.Run("empty list", func(t *testing.T) {
		mockOVS := NewMockOVSClient()

		nm, err := NewSDNNetworkManager(testNetworkManagerConfig(), mockOVS, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create SDNNetworkManager: %v", err)
		}

		list, err := nm.ListContainerNetworks(ctx)
		if err != nil {
			t.Fatalf("ListContainerNetworks() error = %v", err)
		}

		if len(list) != 0 {
			t.Errorf("ListContainerNetworks() returned %d items, want 0", len(list))
		}
	})
}

// TestSDNNetworkManagerClose tests closing the network manager.
func TestSDNNetworkManagerClose(t *testing.T) {
	ctx := context.Background()

	t.Run("cleanup on close", func(t *testing.T) {
		mockOVS := NewMockOVSClient()
		mockOVS.connected = true

		config := testNetworkManagerConfig()
		config.CleanupOnTeardown = true

		nm, err := NewSDNNetworkManager(config, mockOVS, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create SDNNetworkManager: %v", err)
		}

		// Setup container
		cfg := &ContainerNetworkConfig{
			Mode: NetworkModeSDN,
			SDN:  &SDNConfig{Bridge: "br-test", VLANID: 100},
		}
		nm.SetupContainerNetwork(ctx, "container-123", cfg)

		// Close should cleanup
		nm.Close()

		if mockOVS.deletePortCalls != 1 {
			t.Errorf("DeletePort called %d times, want 1 for cleanup", mockOVS.deletePortCalls)
		}
	})

	t.Run("no cleanup when disabled", func(t *testing.T) {
		mockOVS := NewMockOVSClient()
		mockOVS.connected = true

		config := testNetworkManagerConfig()
		config.CleanupOnTeardown = false

		nm, err := NewSDNNetworkManager(config, mockOVS, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create SDNNetworkManager: %v", err)
		}

		cfg := &ContainerNetworkConfig{
			Mode: NetworkModeSDN,
			SDN:  &SDNConfig{Bridge: "br-test", VLANID: 100},
		}
		nm.SetupContainerNetwork(ctx, "container-123", cfg)

		nm.Close()

		if mockOVS.deletePortCalls != 0 {
			t.Errorf("DeletePort called %d times, want 0 when cleanup disabled", mockOVS.deletePortCalls)
		}
	})

	t.Run("double close is safe", func(t *testing.T) {
		mockOVS := NewMockOVSClient()

		nm, err := NewSDNNetworkManager(testNetworkManagerConfig(), mockOVS, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create SDNNetworkManager: %v", err)
		}

		nm.Close()
		err = nm.Close()
		if err != nil {
			t.Errorf("Double Close() should not error: %v", err)
		}
	})
}

// TestSecurityGroup tests security group types.
func TestSecurityGroup(t *testing.T) {
	t.Run("validate success", func(t *testing.T) {
		sg := &SecurityGroup{
			Name: "test-sg",
			Rules: []SecurityGroupRule{
				{
					Direction: DirectionIngress,
					Protocol:  "tcp",
					Port:      443,
					Action:    "allow",
				},
			},
		}

		if err := sg.Validate(); err != nil {
			t.Errorf("Validate() error = %v", err)
		}
	})

	t.Run("validate empty name", func(t *testing.T) {
		sg := &SecurityGroup{
			Name: "",
		}

		if err := sg.Validate(); err == nil {
			t.Error("Validate() should fail for empty name")
		}
	})

	t.Run("validate invalid rule", func(t *testing.T) {
		sg := &SecurityGroup{
			Name: "test-sg",
			Rules: []SecurityGroupRule{
				{
					Direction: "invalid", // Not ingress/egress
					Action:    "allow",
				},
			},
		}

		if err := sg.Validate(); err == nil {
			t.Error("Validate() should fail for invalid rule direction")
		}
	})
}

// TestSecurityGroupRule tests security group rule validation.
func TestSecurityGroupRule(t *testing.T) {
	tests := []struct {
		name    string
		rule    SecurityGroupRule
		wantErr bool
	}{
		{
			name: "valid ingress rule",
			rule: SecurityGroupRule{
				Direction: DirectionIngress,
				Protocol:  "tcp",
				Port:      443,
				Action:    "allow",
			},
			wantErr: false,
		},
		{
			name: "valid egress rule",
			rule: SecurityGroupRule{
				Direction: DirectionEgress,
				Protocol:  "udp",
				Port:      53,
				Action:    "allow",
			},
			wantErr: false,
		},
		{
			name: "valid port range",
			rule: SecurityGroupRule{
				Direction:      DirectionIngress,
				Protocol:       "tcp",
				PortRangeStart: 8080,
				PortRangeEnd:   8090,
				Action:         "allow",
			},
			wantErr: false,
		},
		{
			name: "invalid direction",
			rule: SecurityGroupRule{
				Direction: "invalid",
				Action:    "allow",
			},
			wantErr: true,
		},
		{
			name: "invalid action",
			rule: SecurityGroupRule{
				Direction: DirectionIngress,
				Action:    "invalid",
			},
			wantErr: true,
		},
		{
			name: "invalid port range",
			rule: SecurityGroupRule{
				Direction:      DirectionIngress,
				PortRangeStart: 8090,
				PortRangeEnd:   8080, // Start > End
				Action:         "allow",
			},
			wantErr: true,
		},
		{
			name: "default action is allow",
			rule: SecurityGroupRule{
				Direction: DirectionIngress,
				Action:    "", // Should default to allow
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rule.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestInternalOpenFlowMatch tests match string generation.
func TestInternalOpenFlowMatch(t *testing.T) {
	tests := []struct {
		name     string
		match    InternalOpenFlowMatch
		expected string
	}{
		{
			name: "full match",
			match: InternalOpenFlowMatch{
				InPort:  1,
				DLType:  EthTypeIPv4,
				NWProto: ProtocolTCP,
				TPDst:   443,
				NWSrc:   "192.168.1.0/24",
				VLANID:  100,
			},
			expected: "in_port=1,dl_type=0x0800,nw_proto=6,tp_dst=443,nw_src=192.168.1.0/24,dl_vlan=100",
		},
		{
			name: "simple port match",
			match: InternalOpenFlowMatch{
				InPort: 5,
			},
			expected: "in_port=5",
		},
		{
			name:     "empty match",
			match:    InternalOpenFlowMatch{},
			expected: "",
		},
		{
			name: "MAC addresses",
			match: InternalOpenFlowMatch{
				DLSrc: "00:11:22:33:44:55",
				DLDst: "aa:bb:cc:dd:ee:ff",
			},
			expected: "dl_src=00:11:22:33:44:55,dl_dst=aa:bb:cc:dd:ee:ff",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.match.ToMatchString()
			if result != tt.expected {
				t.Errorf("ToMatchString() = %s, want %s", result, tt.expected)
			}
		})
	}
}

// TestInternalOpenFlowAction tests action string generation.
func TestInternalOpenFlowAction(t *testing.T) {
	tests := []struct {
		name     string
		action   InternalOpenFlowAction
		expected string
	}{
		{
			name:     "allow action",
			action:   InternalOpenFlowAction{Type: InternalActionAllow},
			expected: "NORMAL",
		},
		{
			name:     "drop action",
			action:   InternalOpenFlowAction{Type: InternalActionDrop},
			expected: "drop",
		},
		{
			name:     "output action",
			action:   InternalOpenFlowAction{Type: InternalActionOutput, Port: 5},
			expected: "output:5",
		},
		{
			name:     "goto action",
			action:   InternalOpenFlowAction{Type: InternalActionGoto, Table: 10},
			expected: "resubmit(,10)",
		},
		{
			name:     "set VLAN action",
			action:   InternalOpenFlowAction{Type: InternalActionSetVLAN, VLAN: 200},
			expected: "mod_vlan_vid:200",
		},
		{
			name:     "strip VLAN action",
			action:   InternalOpenFlowAction{Type: InternalActionStripVLAN},
			expected: "strip_vlan",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.action.ToActionString()
			if result != tt.expected {
				t.Errorf("ToActionString() = %s, want %s", result, tt.expected)
			}
		})
	}
}

// TestDefaultSecurityGroupManager tests the default security group manager.
func TestDefaultSecurityGroupManager(t *testing.T) {
	ctx := context.Background()

	t.Run("register and get security group", func(t *testing.T) {
		mgr := NewDefaultSecurityGroupManager()

		sg := &SecurityGroup{
			Name:        "web-frontend",
			Description: "Web frontend security group",
			Rules: []SecurityGroupRule{
				{
					Direction: DirectionIngress,
					Protocol:  "tcp",
					Port:      443,
					Action:    "allow",
				},
			},
		}

		err := mgr.RegisterSecurityGroup(sg)
		if err != nil {
			t.Fatalf("RegisterSecurityGroup() error = %v", err)
		}

		retrieved, err := mgr.GetSecurityGroup(ctx, "web-frontend")
		if err != nil {
			t.Fatalf("GetSecurityGroup() error = %v", err)
		}

		if retrieved.Name != "web-frontend" {
			t.Errorf("Name = %s, want web-frontend", retrieved.Name)
		}
	})

	t.Run("get nonexistent security group", func(t *testing.T) {
		mgr := NewDefaultSecurityGroupManager()

		_, err := mgr.GetSecurityGroup(ctx, "nonexistent")
		if !errors.Is(err, ErrContainerNotFound) {
			t.Errorf("GetSecurityGroup() error = %v, want ErrContainerNotFound", err)
		}
	})

	t.Run("register nil security group", func(t *testing.T) {
		mgr := NewDefaultSecurityGroupManager()

		err := mgr.RegisterSecurityGroup(nil)
		if err == nil {
			t.Error("RegisterSecurityGroup(nil) should fail")
		}
	})

	t.Run("register empty name", func(t *testing.T) {
		mgr := NewDefaultSecurityGroupManager()

		err := mgr.RegisterSecurityGroup(&SecurityGroup{Name: ""})
		if err == nil {
			t.Error("RegisterSecurityGroup with empty name should fail")
		}
	})

	t.Run("security group to flows", func(t *testing.T) {
		mgr := NewDefaultSecurityGroupManager()

		sg := &SecurityGroup{
			Name:     "test-sg",
			Priority: 200,
			Table:    10,
			Rules: []SecurityGroupRule{
				{
					Direction: DirectionIngress,
					Protocol:  "tcp",
					Port:      443,
					Action:    "allow",
				},
				{
					Direction: DirectionEgress,
					Protocol:  "tcp",
					Port:      80,
					Action:    "allow",
				},
			},
		}

		flows := mgr.SecurityGroupToFlows(sg, "test-port", 5, 100)

		if len(flows) != 2 {
			t.Fatalf("SecurityGroupToFlows() returned %d flows, want 2", len(flows))
		}

		// Check first flow (ingress)
		if flows[0].Table != 10 {
			t.Errorf("Flow table = %d, want 10", flows[0].Table)
		}

		// Check second flow (egress) - should match in_port
		if flows[1].Match.InPort != 5 {
			t.Errorf("Egress flow InPort = %d, want 5", flows[1].Match.InPort)
		}
	})

	t.Run("security group to flows with CIDR", func(t *testing.T) {
		mgr := NewDefaultSecurityGroupManager()

		sg := &SecurityGroup{
			Name: "test-sg",
			Rules: []SecurityGroupRule{
				{
					Direction: DirectionIngress,
					Protocol:  "tcp",
					Port:      22,
					RemoteIP:  "10.0.0.0/8",
					Action:    "allow",
				},
			},
		}

		flows := mgr.SecurityGroupToFlows(sg, "test-port", 5, 100)

		if len(flows) != 1 {
			t.Fatalf("SecurityGroupToFlows() returned %d flows, want 1", len(flows))
		}

		if flows[0].Match.NWSrc != "10.0.0.0/8" {
			t.Errorf("NWSrc = %s, want 10.0.0.0/8", flows[0].Match.NWSrc)
		}
	})

	t.Run("security group to flows nil", func(t *testing.T) {
		mgr := NewDefaultSecurityGroupManager()

		flows := mgr.SecurityGroupToFlows(nil, "test-port", 5, 100)
		if flows != nil {
			t.Error("SecurityGroupToFlows(nil) should return nil")
		}
	})
}

// TestGeneratePortName tests port name generation.
func TestGeneratePortName(t *testing.T) {
	mockOVS := NewMockOVSClient()

	config := testNetworkManagerConfig()
	config.PortNamePrefix = "ctr-"

	nm, _ := NewSDNNetworkManager(config, mockOVS, nil, nil)

	tests := []struct {
		containerID string
		expected    string
	}{
		{
			containerID: "abc123456789xyz",
			expected:    "ctr-abc123456789",
		},
		{
			containerID: "short",
			expected:    "ctr-short",
		},
		{
			containerID: "exactly12ch",
			expected:    "ctr-exactly12ch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.containerID, func(t *testing.T) {
			result := nm.generatePortName(tt.containerID)
			if result != tt.expected {
				t.Errorf("generatePortName(%s) = %s, want %s", tt.containerID, result, tt.expected)
			}
		})
	}
}

// TestParseProtocol tests protocol parsing.
func TestParseProtocol(t *testing.T) {
	mockOVS := NewMockOVSClient()
	nm, _ := NewSDNNetworkManager(testNetworkManagerConfig(), mockOVS, nil, nil)

	tests := []struct {
		input    string
		expected uint8
	}{
		{"tcp", ProtocolTCP},
		{"TCP", ProtocolTCP},
		{"udp", ProtocolUDP},
		{"UDP", ProtocolUDP},
		{"icmp", ProtocolICMP},
		{"ICMP", ProtocolICMP},
		{"6", ProtocolTCP},
		{"17", ProtocolUDP},
		{"1", ProtocolICMP},
		{"invalid", 0},
		{"", 0},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := nm.parseProtocol(tt.input)
			if result != tt.expected {
				t.Errorf("parseProtocol(%s) = %d, want %d", tt.input, result, tt.expected)
			}
		})
	}
}

// TestConcurrentAccess tests thread safety of SDNNetworkManager.
func TestConcurrentAccess(t *testing.T) {
	ctx := context.Background()
	mockOVS := NewMockOVSClient()
	mockOVS.connected = true

	nm, err := NewSDNNetworkManager(testNetworkManagerConfig(), mockOVS, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create SDNNetworkManager: %v", err)
	}

	var wg sync.WaitGroup
	containerCount := 100

	// Concurrent setup
	for i := 0; i < containerCount; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			cfg := &ContainerNetworkConfig{
				Mode: NetworkModeSDN,
				SDN:  &SDNConfig{Bridge: "br-test", VLANID: uint16(100 + id%10)},
			}
			nm.SetupContainerNetwork(ctx, "container-"+string(rune('A'+id%26))+"-"+string(rune('0'+id)), cfg)
		}(i)
	}

	wg.Wait()

	// Concurrent read
	for i := 0; i < containerCount; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			nm.ListContainerNetworks(ctx)
			nm.GetContainerNetworkInfo(ctx, "container-"+string(rune('A'+id%26))+"-"+string(rune('0'+id)))
		}(i)
	}

	wg.Wait()
}

// TestSetupWithOpenFlowRules tests setup with custom OpenFlow rules.
func TestSetupWithOpenFlowRules(t *testing.T) {
	ctx := context.Background()
	mockOVS := NewMockOVSClient()
	mockOVS.connected = true

	nm, err := NewSDNNetworkManager(testNetworkManagerConfig(), mockOVS, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create SDNNetworkManager: %v", err)
	}

	cfg := &ContainerNetworkConfig{
		Mode: NetworkModeSDN,
		SDN: &SDNConfig{
			Bridge: "br-test",
			VLANID: 100,
			OpenFlowRules: []OpenFlowRule{
				{
					Match: OpenFlowMatch{
						DLType:  EthTypeIPv4,
						NWProto: ProtocolTCP,
						TPDst:   443,
					},
					Actions: []OpenFlowAction{
						{Type: ActionAllow},
					},
					Priority: 200,
					Table:    0,
				},
			},
		},
	}

	err = nm.SetupContainerNetwork(ctx, "container-with-rules", cfg)
	if err != nil {
		t.Fatalf("SetupContainerNetwork() error = %v", err)
	}

	info, _ := nm.GetContainerNetworkInfo(ctx, "container-with-rules")
	if info.FlowCount != 1 {
		t.Errorf("FlowCount = %d, want 1", info.FlowCount)
	}

	if mockOVS.addFlowCalls != 1 {
		t.Errorf("AddFlow called %d times, want 1", mockOVS.addFlowCalls)
	}
}

// TestSetupContainerNetworkWithInfo tests network setup with info return.
func TestSetupContainerNetworkWithInfo(t *testing.T) {
	config := testNetworkManagerConfig()
	mockOVS := NewMockOVSClient()
	mockOF := NewMockOpenFlowController()
	mockSG := NewDefaultSecurityGroupManager()

	nm, err := NewSDNNetworkManager(config, mockOVS, mockOF, mockSG)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}
	defer nm.Close()

	t.Run("setup non-SDN mode returns info", func(t *testing.T) {
		cfg := &ContainerNetworkConfig{
			Mode: NetworkModeBridge,
		}

		info, err := nm.SetupContainerNetworkWithInfo(context.Background(), "test-container-info", cfg)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if info == nil {
			t.Fatal("expected info, got nil")
		}
		if info.Mode != NetworkModeBridge {
			t.Errorf("expected mode %q, got %q", NetworkModeBridge, info.Mode)
		}
	})

	t.Run("setup with empty container ID", func(t *testing.T) {
		cfg := &ContainerNetworkConfig{
			Mode: NetworkModeBridge,
		}

		_, err := nm.SetupContainerNetworkWithInfo(context.Background(), "", cfg)
		if err == nil {
			t.Fatal("expected error for empty container ID")
		}
		if !errors.Is(err, ErrInvalidContainerID) {
			t.Errorf("expected ErrInvalidContainerID, got %v", err)
		}
	})

	t.Run("setup with nil config", func(t *testing.T) {
		_, err := nm.SetupContainerNetworkWithInfo(context.Background(), "test-container-nil", nil)
		if err == nil {
			t.Fatal("expected error for nil config")
		}
	})

	t.Run("setup SDN mode without SDN config", func(t *testing.T) {
		cfg := &ContainerNetworkConfig{
			Mode: NetworkModeSDN,
			SDN:  nil,
		}

		_, err := nm.SetupContainerNetworkWithInfo(context.Background(), "test-container-no-sdn", cfg)
		if err == nil {
			t.Fatal("expected error for SDN mode without config")
		}
	})

	t.Run("setup SDN mode with config", func(t *testing.T) {
		cfg := &ContainerNetworkConfig{
			Mode: NetworkModeSDN,
			SDN: &SDNConfig{
				Bridge: "br-test",
				VLANID: 100,
			},
		}

		info, err := nm.SetupContainerNetworkWithInfo(context.Background(), "sdn-container-info", cfg)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if info == nil {
			t.Fatal("expected info, got nil")
		}
		if info.VLANID != 100 {
			t.Errorf("expected VLANID 100, got %d", info.VLANID)
		}
	})
}

// TestBuildSecurityRuleMatch tests security rule match string building.
func TestBuildSecurityRuleMatch(t *testing.T) {
	config := testNetworkManagerConfig()
	mockOVS := NewMockOVSClient()
	mockOF := NewMockOpenFlowController()
	mockSG := NewDefaultSecurityGroupManager()

	nm, _ := NewSDNNetworkManager(config, mockOVS, mockOF, mockSG)
	defer nm.Close()

	t.Run("egress rule with port", func(t *testing.T) {
		rule := &SecurityGroupRule{
			Direction: DirectionEgress,
			Protocol:  "tcp",
			Port:      80,
		}

		match := nm.buildSecurityRuleMatch(5, 100, rule)
		if match == "" {
			t.Error("expected non-empty match string")
		}
	})

	t.Run("ingress rule with remote IP", func(t *testing.T) {
		rule := &SecurityGroupRule{
			Direction: DirectionIngress,
			Protocol:  "tcp",
			Port:      443,
			RemoteIP:  "10.0.0.0/8",
		}

		match := nm.buildSecurityRuleMatch(5, 100, rule)
		if match == "" {
			t.Error("expected non-empty match string")
		}
	})

	t.Run("rule with VLAN", func(t *testing.T) {
		rule := &SecurityGroupRule{
			Direction: DirectionEgress,
			Protocol:  "udp",
			Port:      53,
		}

		match := nm.buildSecurityRuleMatch(5, 200, rule)
		if len(match) == 0 {
			t.Error("expected non-empty match string")
		}
	})

	t.Run("rule without protocol", func(t *testing.T) {
		rule := &SecurityGroupRule{
			Direction: DirectionEgress,
		}

		match := nm.buildSecurityRuleMatch(5, 0, rule)
		if len(match) == 0 {
			t.Error("expected non-empty match string")
		}
	})

	t.Run("rule with ICMP protocol", func(t *testing.T) {
		rule := &SecurityGroupRule{
			Direction: DirectionEgress,
			Protocol:  "icmp",
		}

		match := nm.buildSecurityRuleMatch(5, 0, rule)
		if len(match) == 0 {
			t.Error("expected non-empty match string")
		}
	})
}

// TestInternalFlowToOVS tests internal flow conversion.
func TestInternalFlowToOVS(t *testing.T) {
	config := testNetworkManagerConfig()
	mockOVS := NewMockOVSClient()
	mockOF := NewMockOpenFlowController()
	mockSG := NewDefaultSecurityGroupManager()

	nm, _ := NewSDNNetworkManager(config, mockOVS, mockOF, mockSG)
	defer nm.Close()

	t.Run("convert flow with match", func(t *testing.T) {
		flow := &InternalOpenFlowRule{
			Table:    0,
			Priority: 100,
			Match: &InternalOpenFlowMatch{
				InPort: 5,
				VLANID: 100,
			},
			Actions: []InternalOpenFlowAction{
				{Type: InternalActionOutput, Port: 1},
			},
			Cookie: 12345,
		}

		ovsFlow := nm.internalFlowToOVS(flow)
		if ovsFlow == nil {
			t.Fatal("expected OVS flow, got nil")
		}
		if ovsFlow.Table != 0 {
			t.Errorf("expected table 0, got %d", ovsFlow.Table)
		}
		if ovsFlow.Priority != 100 {
			t.Errorf("expected priority 100, got %d", ovsFlow.Priority)
		}
	})

	t.Run("convert flow without match", func(t *testing.T) {
		flow := &InternalOpenFlowRule{
			Table:    1,
			Priority: 50,
			Match:    nil,
			Actions: []InternalOpenFlowAction{
				{Type: InternalActionDrop},
			},
		}

		ovsFlow := nm.internalFlowToOVS(flow)
		if ovsFlow == nil {
			t.Fatal("expected OVS flow, got nil")
		}
		if ovsFlow.Match != "" {
			t.Errorf("expected empty match, got %q", ovsFlow.Match)
		}
	})
}
