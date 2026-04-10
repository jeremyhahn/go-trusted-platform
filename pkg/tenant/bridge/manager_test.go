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

package bridge

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// mockOVSClient implements OVSClient for testing
type mockOVSClient struct {
	mu           sync.RWMutex
	bridges      map[string]*BridgeInfo
	ports        map[string][]string // bridge -> ports
	portVLANs    map[string]uint16   // port -> VLAN
	createErr    error
	deleteErr    error
	getErr       error
	listErr      error
	datapathErr  error
	failModeErr  error
	protocolsErr error
	addPortErr   error
	delPortErr   error
	setVLANErr   error
	createCount  atomic.Int32
	deleteCount  atomic.Int32
}

func newMockOVSClient() *mockOVSClient {
	return &mockOVSClient{
		bridges:   make(map[string]*BridgeInfo),
		ports:     make(map[string][]string),
		portVLANs: make(map[string]uint16),
	}
}

func (m *mockOVSClient) CreateBridge(ctx context.Context, name string) error {
	m.createCount.Add(1)
	if m.createErr != nil {
		return m.createErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.bridges[name]; exists {
		return errors.New("bridge already exists")
	}

	m.bridges[name] = &BridgeInfo{
		Name:         name,
		UUID:         "test-uuid-" + name,
		DatapathType: "system",
		Ports:        []string{},
		Status:       map[string]string{},
	}
	m.ports[name] = []string{}

	return nil
}

func (m *mockOVSClient) DeleteBridge(ctx context.Context, name string) error {
	m.deleteCount.Add(1)
	if m.deleteErr != nil {
		return m.deleteErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.bridges[name]; !exists {
		return errors.New("bridge not found")
	}

	delete(m.bridges, name)
	delete(m.ports, name)

	return nil
}

func (m *mockOVSClient) GetBridge(ctx context.Context, name string) (*BridgeInfo, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	info, exists := m.bridges[name]
	if !exists {
		return nil, errors.New("bridge not found")
	}

	// Return a copy
	return &BridgeInfo{
		Name:         info.Name,
		UUID:         info.UUID,
		DatapathType: info.DatapathType,
		Ports:        append([]string{}, info.Ports...),
		Status:       info.Status,
	}, nil
}

func (m *mockOVSClient) ListBridges(ctx context.Context) ([]string, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, 0, len(m.bridges))
	for name := range m.bridges {
		names = append(names, name)
	}

	return names, nil
}

func (m *mockOVSClient) SetBridgeDatapath(ctx context.Context, name string, datapathType string) error {
	if m.datapathErr != nil {
		return m.datapathErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if info, exists := m.bridges[name]; exists {
		info.DatapathType = datapathType
	}

	return nil
}

func (m *mockOVSClient) SetBridgeFailMode(ctx context.Context, name string, failMode string) error {
	if m.failModeErr != nil {
		return m.failModeErr
	}
	return nil
}

func (m *mockOVSClient) SetBridgeProtocols(ctx context.Context, name string, protocols []string) error {
	if m.protocolsErr != nil {
		return m.protocolsErr
	}
	return nil
}

func (m *mockOVSClient) AddPort(ctx context.Context, bridgeName, portName string) error {
	if m.addPortErr != nil {
		return m.addPortErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.bridges[bridgeName]; !exists {
		return errors.New("bridge not found")
	}

	m.ports[bridgeName] = append(m.ports[bridgeName], portName)
	m.bridges[bridgeName].Ports = m.ports[bridgeName]

	return nil
}

func (m *mockOVSClient) DeletePort(ctx context.Context, bridgeName, portName string) error {
	if m.delPortErr != nil {
		return m.delPortErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	ports := m.ports[bridgeName]
	for i, p := range ports {
		if p == portName {
			m.ports[bridgeName] = append(ports[:i], ports[i+1:]...)
			m.bridges[bridgeName].Ports = m.ports[bridgeName]
			break
		}
	}

	return nil
}

func (m *mockOVSClient) ListPorts(ctx context.Context, bridgeName string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ports, exists := m.ports[bridgeName]
	if !exists {
		return nil, errors.New("bridge not found")
	}

	return append([]string{}, ports...), nil
}

func (m *mockOVSClient) SetPortVLAN(ctx context.Context, portName string, tag uint16) error {
	if m.setVLANErr != nil {
		return m.setVLANErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.portVLANs[portName] = tag

	return nil
}

// mockOpenFlowClient implements OpenFlowClient for testing
type mockOpenFlowClient struct {
	mu           sync.RWMutex
	flows        map[string][]*Flow // bridge -> flows
	addErr       error
	deleteErr    error
	getErr       error
	deleteAllErr error
	addCount     atomic.Int32
	deleteCount  atomic.Int32
	// Support for failing after N successful calls
	addErrAfter int32 // fail after this many successful adds (0 = immediate fail)
}

func newMockOpenFlowClient() *mockOpenFlowClient {
	return &mockOpenFlowClient{
		flows: make(map[string][]*Flow),
	}
}

func (m *mockOpenFlowClient) AddFlow(ctx context.Context, bridge string, flow *Flow) error {
	count := m.addCount.Add(1)

	// If addErrAfter is set and we've reached that count, return error
	if m.addErr != nil {
		if m.addErrAfter == 0 || count > m.addErrAfter {
			return m.addErr
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.flows[bridge] = append(m.flows[bridge], flow)

	return nil
}

func (m *mockOpenFlowClient) DeleteFlows(ctx context.Context, bridge string, match *FlowMatch) error {
	m.deleteCount.Add(1)
	if m.deleteErr != nil {
		return m.deleteErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if match == nil || match.IsEmpty() {
		m.flows[bridge] = []*Flow{}
		return nil
	}

	// Filter flows based on match
	var remaining []*Flow
	for _, f := range m.flows[bridge] {
		if match.InPort != nil && f.Match.InPort != nil {
			if *match.InPort != *f.Match.InPort {
				remaining = append(remaining, f)
			}
		} else {
			remaining = append(remaining, f)
		}
	}
	m.flows[bridge] = remaining

	return nil
}

func (m *mockOpenFlowClient) GetFlows(ctx context.Context, bridge string) ([]*Flow, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	flows := m.flows[bridge]
	result := make([]*Flow, len(flows))
	copy(result, flows)

	return result, nil
}

func (m *mockOpenFlowClient) DeleteAllFlows(ctx context.Context, bridge string) error {
	if m.deleteAllErr != nil {
		return m.deleteAllErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.flows[bridge] = []*Flow{}

	return nil
}

func (m *mockOpenFlowClient) getFlowCount(bridge string) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.flows[bridge])
}

func TestNewManager(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	ovsClient := newMockOVSClient()
	ofClient := newMockOpenFlowClient()

	t.Run("with valid config", func(t *testing.T) {
		cfg := &Config{
			BridgePrefix: "br-test-",
			Datapath:     "netdev",
			FailMode:     "standalone",
			Protocols:    []string{"OpenFlow15"},
		}

		m := NewManager(ovsClient, ofClient, cfg, logger)

		if m == nil {
			t.Fatal("NewManager returned nil")
		}
		if m.config.BridgePrefix != "br-test-" {
			t.Errorf("BridgePrefix = %q, want %q", m.config.BridgePrefix, "br-test-")
		}
		if m.config.Datapath != "netdev" {
			t.Errorf("Datapath = %q, want %q", m.config.Datapath, "netdev")
		}
	})

	t.Run("with nil config uses defaults", func(t *testing.T) {
		m := NewManager(ovsClient, ofClient, nil, logger)

		if m == nil {
			t.Fatal("NewManager returned nil")
		}
		if m.config.BridgePrefix != DefaultBridgePrefix {
			t.Errorf("BridgePrefix = %q, want %q", m.config.BridgePrefix, DefaultBridgePrefix)
		}
		if m.config.Datapath != DefaultDatapath {
			t.Errorf("Datapath = %q, want %q", m.config.Datapath, DefaultDatapath)
		}
	})

	t.Run("with empty prefix uses default", func(t *testing.T) {
		cfg := &Config{
			BridgePrefix: "",
			Datapath:     "system",
		}

		m := NewManager(ovsClient, ofClient, cfg, logger)

		if m.config.BridgePrefix != DefaultBridgePrefix {
			t.Errorf("BridgePrefix = %q, want %q", m.config.BridgePrefix, DefaultBridgePrefix)
		}
	})

	t.Run("with empty datapath uses default", func(t *testing.T) {
		cfg := &Config{
			BridgePrefix: "br-test-",
			Datapath:     "",
		}

		m := NewManager(ovsClient, ofClient, cfg, logger)

		if m.config.Datapath != DefaultDatapath {
			t.Errorf("Datapath = %q, want %q", m.config.Datapath, DefaultDatapath)
		}
	})

	t.Run("with nil logger uses default", func(t *testing.T) {
		m := NewManager(ovsClient, ofClient, nil, nil)

		if m == nil {
			t.Fatal("NewManager returned nil")
		}
		if m.logger == nil {
			t.Error("logger should not be nil")
		}
	})
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg == nil {
		t.Fatal("DefaultConfig returned nil")
	}
	if cfg.BridgePrefix != DefaultBridgePrefix {
		t.Errorf("BridgePrefix = %q, want %q", cfg.BridgePrefix, DefaultBridgePrefix)
	}
	if cfg.Datapath != DefaultDatapath {
		t.Errorf("Datapath = %q, want %q", cfg.Datapath, DefaultDatapath)
	}
	if cfg.FailMode != DefaultFailMode {
		t.Errorf("FailMode = %q, want %q", cfg.FailMode, DefaultFailMode)
	}
	if len(cfg.Protocols) != 2 {
		t.Errorf("len(Protocols) = %d, want %d", len(cfg.Protocols), 2)
	}
	if cfg.OVSSocket != "/var/run/openvswitch/db.sock" {
		t.Errorf("OVSSocket = %q, want %q", cfg.OVSSocket, "/var/run/openvswitch/db.sock")
	}
}

func TestManager_CreateBridge(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("successful creation", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		m := NewManager(ovsClient, ofClient, nil, logger)

		bridge, err := m.CreateBridge(ctx, "tenant-1", "test", VLANRange{Start: 100, End: 200})
		if err != nil {
			t.Fatalf("CreateBridge failed: %v", err)
		}

		if bridge == nil {
			t.Fatal("bridge should not be nil")
		}
		if bridge.TenantID != "tenant-1" {
			t.Errorf("TenantID = %q, want %q", bridge.TenantID, "tenant-1")
		}
		if bridge.TenantName != "test" {
			t.Errorf("TenantName = %q, want %q", bridge.TenantName, "test")
		}
		if bridge.Status != StatusActive {
			t.Errorf("Status = %q, want %q", bridge.Status, StatusActive)
		}
		if !bridge.VLANRange.IsValid() {
			t.Error("VLANRange should be valid")
		}
	})

	t.Run("invalid tenant name - too short", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		m := NewManager(ovsClient, ofClient, nil, logger)

		_, err := m.CreateBridge(ctx, "tenant-1", "", VLANRange{Start: 100, End: 200})
		if err == nil {
			t.Error("CreateBridge should fail with empty tenant name")
		}

		var invalidNameErr ErrInvalidBridgeName
		if !errors.As(err, &invalidNameErr) {
			t.Errorf("error should be ErrInvalidBridgeName, got %T", err)
		}
	})

	t.Run("invalid tenant name - too long", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		m := NewManager(ovsClient, ofClient, nil, logger)

		longName := "a"
		for i := 0; i < MaxTenantNameLength+1; i++ {
			longName += "x"
		}

		_, err := m.CreateBridge(ctx, "tenant-1", longName, VLANRange{Start: 100, End: 200})
		if err == nil {
			t.Error("CreateBridge should fail with too long tenant name")
		}

		var invalidNameErr ErrInvalidBridgeName
		if !errors.As(err, &invalidNameErr) {
			t.Errorf("error should be ErrInvalidBridgeName, got %T", err)
		}
	})

	t.Run("invalid tenant name - bad characters", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		m := NewManager(ovsClient, ofClient, nil, logger)

		_, err := m.CreateBridge(ctx, "tenant-1", "123invalid", VLANRange{Start: 100, End: 200})
		if err == nil {
			t.Error("CreateBridge should fail with invalid tenant name")
		}
	})

	t.Run("invalid VLAN range - zero start", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		m := NewManager(ovsClient, ofClient, nil, logger)

		_, err := m.CreateBridge(ctx, "tenant-1", "test", VLANRange{Start: 0, End: 100})
		if err == nil {
			t.Error("CreateBridge should fail with zero VLAN start")
		}

		var vlanErr ErrInvalidVLANRange
		if !errors.As(err, &vlanErr) {
			t.Errorf("error should be ErrInvalidVLANRange, got %T", err)
		}
	})

	t.Run("invalid VLAN range - exceeds max", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		m := NewManager(ovsClient, ofClient, nil, logger)

		_, err := m.CreateBridge(ctx, "tenant-1", "test", VLANRange{Start: 100, End: 5000})
		if err == nil {
			t.Error("CreateBridge should fail with VLAN range exceeding max")
		}
	})

	t.Run("invalid VLAN range - start greater than end", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		m := NewManager(ovsClient, ofClient, nil, logger)

		_, err := m.CreateBridge(ctx, "tenant-1", "test", VLANRange{Start: 200, End: 100})
		if err == nil {
			t.Error("CreateBridge should fail with start > end")
		}
	})

	t.Run("bridge already exists", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		m := NewManager(ovsClient, ofClient, nil, logger)

		_, err := m.CreateBridge(ctx, "tenant-1", "test", VLANRange{Start: 100, End: 200})
		if err != nil {
			t.Fatalf("first CreateBridge failed: %v", err)
		}

		_, err = m.CreateBridge(ctx, "tenant-1", "test2", VLANRange{Start: 100, End: 200})
		if err == nil {
			t.Error("second CreateBridge should fail")
		}

		var existsErr ErrBridgeExists
		if !errors.As(err, &existsErr) {
			t.Errorf("error should be ErrBridgeExists, got %T: %v", err, err)
		}
	})

	t.Run("OVS create fails", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ovsClient.createErr = errors.New("OVS connection refused")
		ofClient := newMockOpenFlowClient()
		m := NewManager(ovsClient, ofClient, nil, logger)

		_, err := m.CreateBridge(ctx, "tenant-1", "test", VLANRange{Start: 100, End: 200})
		if err == nil {
			t.Error("CreateBridge should fail when OVS create fails")
		}

		var createErr ErrBridgeCreateFailed
		if !errors.As(err, &createErr) {
			t.Errorf("error should be ErrBridgeCreateFailed, got %T", err)
		}
	})

	t.Run("rollback on configuration failure", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ovsClient.failModeErr = errors.New("fail mode error")
		ofClient := newMockOpenFlowClient()
		m := NewManager(ovsClient, ofClient, nil, logger)

		_, err := m.CreateBridge(ctx, "tenant-1", "test", VLANRange{Start: 100, End: 200})
		if err == nil {
			t.Error("CreateBridge should fail when configuration fails")
		}

		// Verify rollback was attempted (delete was called)
		if ovsClient.deleteCount.Load() == 0 {
			t.Error("rollback should have deleted the bridge")
		}
	})

	t.Run("operation in progress", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		m := NewManager(ovsClient, ofClient, nil, logger)

		// Manually create a bridge with pending status
		m.bridges["tenant-1"] = &TenantBridge{
			Name:     "br-tenant-test",
			TenantID: "tenant-1",
			Status:   StatusPending,
		}

		_, err := m.CreateBridge(ctx, "tenant-1", "test", VLANRange{Start: 100, End: 200})
		if err == nil {
			t.Error("CreateBridge should fail when operation in progress")
		}

		var inProgressErr ErrOperationInProgress
		if !errors.As(err, &inProgressErr) {
			t.Errorf("error should be ErrOperationInProgress, got %T", err)
		}
	})
}

func TestManager_DeleteBridge(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("successful deletion", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		m := NewManager(ovsClient, ofClient, nil, logger)

		_, err := m.CreateBridge(ctx, "tenant-1", "test", VLANRange{Start: 100, End: 200})
		if err != nil {
			t.Fatalf("CreateBridge failed: %v", err)
		}

		err = m.DeleteBridge(ctx, "tenant-1")
		if err != nil {
			t.Fatalf("DeleteBridge failed: %v", err)
		}

		// Verify bridge is removed
		_, err = m.GetBridge(ctx, "tenant-1")
		if err == nil {
			t.Error("GetBridge should fail after deletion")
		}
	})

	t.Run("tenant not found", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		m := NewManager(ovsClient, ofClient, nil, logger)

		err := m.DeleteBridge(ctx, "nonexistent")
		if err == nil {
			t.Error("DeleteBridge should fail for nonexistent tenant")
		}

		var notFoundErr ErrTenantNotFound
		if !errors.As(err, &notFoundErr) {
			t.Errorf("error should be ErrTenantNotFound, got %T", err)
		}
	})

	t.Run("delete already in progress", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		m := NewManager(ovsClient, ofClient, nil, logger)

		// Manually create a bridge with deleting status
		m.bridges["tenant-1"] = &TenantBridge{
			Name:     "br-tenant-test",
			TenantID: "tenant-1",
			Status:   StatusDeleting,
		}

		err := m.DeleteBridge(ctx, "tenant-1")
		if err == nil {
			t.Error("DeleteBridge should fail when delete in progress")
		}

		var inProgressErr ErrOperationInProgress
		if !errors.As(err, &inProgressErr) {
			t.Errorf("error should be ErrOperationInProgress, got %T", err)
		}
	})

	t.Run("OVS delete fails", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		m := NewManager(ovsClient, ofClient, nil, logger)

		_, err := m.CreateBridge(ctx, "tenant-1", "test", VLANRange{Start: 100, End: 200})
		if err != nil {
			t.Fatalf("CreateBridge failed: %v", err)
		}

		ovsClient.deleteErr = errors.New("cannot delete bridge")

		err = m.DeleteBridge(ctx, "tenant-1")
		if err == nil {
			t.Error("DeleteBridge should fail when OVS delete fails")
		}

		var deleteErr ErrBridgeDeleteFailed
		if !errors.As(err, &deleteErr) {
			t.Errorf("error should be ErrBridgeDeleteFailed, got %T", err)
		}
	})

	t.Run("deletes flows before bridge", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		m := NewManager(ovsClient, ofClient, nil, logger)

		_, err := m.CreateBridge(ctx, "tenant-1", "test", VLANRange{Start: 100, End: 200})
		if err != nil {
			t.Fatalf("CreateBridge failed: %v", err)
		}

		// Add some flows
		err = ofClient.AddFlow(ctx, "br-tenant-tes", &Flow{Table: 0, Priority: 100})
		if err != nil {
			t.Fatalf("AddFlow setup failed: %v", err)
		}

		err = m.DeleteBridge(ctx, "tenant-1")
		if err != nil {
			t.Fatalf("DeleteBridge failed: %v", err)
		}
	})
}

func TestManager_GetBridge(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("existing bridge", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		m := NewManager(ovsClient, ofClient, nil, logger)

		created, err := m.CreateBridge(ctx, "tenant-1", "test", VLANRange{Start: 100, End: 200})
		if err != nil {
			t.Fatalf("CreateBridge failed: %v", err)
		}

		retrieved, err := m.GetBridge(ctx, "tenant-1")
		if err != nil {
			t.Fatalf("GetBridge failed: %v", err)
		}

		if retrieved.TenantID != created.TenantID {
			t.Errorf("TenantID = %q, want %q", retrieved.TenantID, created.TenantID)
		}
		if retrieved.Name != created.Name {
			t.Errorf("Name = %q, want %q", retrieved.Name, created.Name)
		}
	})

	t.Run("nonexistent bridge", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		m := NewManager(ovsClient, ofClient, nil, logger)

		_, err := m.GetBridge(ctx, "nonexistent")
		if err == nil {
			t.Error("GetBridge should fail for nonexistent tenant")
		}

		var notFoundErr ErrTenantNotFound
		if !errors.As(err, &notFoundErr) {
			t.Errorf("error should be ErrTenantNotFound, got %T", err)
		}
	})

	t.Run("returns copy not reference", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		m := NewManager(ovsClient, ofClient, nil, logger)

		_, err := m.CreateBridge(ctx, "tenant-1", "test", VLANRange{Start: 100, End: 200})
		if err != nil {
			t.Fatalf("CreateBridge failed: %v", err)
		}

		retrieved1, _ := m.GetBridge(ctx, "tenant-1")
		retrieved1.Status = StatusError

		retrieved2, _ := m.GetBridge(ctx, "tenant-1")
		if retrieved2.Status == StatusError {
			t.Error("modification of returned bridge should not affect internal state")
		}
	})
}

func TestManager_GetBridgeByName(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("existing bridge", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		m := NewManager(ovsClient, ofClient, nil, logger)

		created, err := m.CreateBridge(ctx, "tenant-1", "test", VLANRange{Start: 100, End: 200})
		if err != nil {
			t.Fatalf("CreateBridge failed: %v", err)
		}

		retrieved, err := m.GetBridgeByName(ctx, created.Name)
		if err != nil {
			t.Fatalf("GetBridgeByName failed: %v", err)
		}

		if retrieved.TenantID != "tenant-1" {
			t.Errorf("TenantID = %q, want %q", retrieved.TenantID, "tenant-1")
		}
	})

	t.Run("nonexistent bridge", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		m := NewManager(ovsClient, ofClient, nil, logger)

		_, err := m.GetBridgeByName(ctx, "br-nonexistent")
		if err == nil {
			t.Error("GetBridgeByName should fail for nonexistent bridge")
		}

		var notFoundErr ErrBridgeNotFound
		if !errors.As(err, &notFoundErr) {
			t.Errorf("error should be ErrBridgeNotFound, got %T", err)
		}
	})
}

func TestManager_ListBridges(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("empty list", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		m := NewManager(ovsClient, ofClient, nil, logger)

		bridges, err := m.ListBridges(ctx)
		if err != nil {
			t.Fatalf("ListBridges failed: %v", err)
		}

		if len(bridges) != 0 {
			t.Errorf("len(bridges) = %d, want 0", len(bridges))
		}
	})

	t.Run("multiple bridges", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		m := NewManager(ovsClient, ofClient, nil, logger)

		_, err := m.CreateBridge(ctx, "tenant-1", "test1", VLANRange{Start: 100, End: 200})
		if err != nil {
			t.Fatalf("CreateBridge 1 failed: %v", err)
		}

		_, err = m.CreateBridge(ctx, "tenant-2", "test2", VLANRange{Start: 201, End: 300})
		if err != nil {
			t.Fatalf("CreateBridge 2 failed: %v", err)
		}

		bridges, err := m.ListBridges(ctx)
		if err != nil {
			t.Fatalf("ListBridges failed: %v", err)
		}

		if len(bridges) != 2 {
			t.Errorf("len(bridges) = %d, want 2", len(bridges))
		}
	})
}

func TestManager_GetStatus(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("existing bridge", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		m := NewManager(ovsClient, ofClient, nil, logger)

		_, err := m.CreateBridge(ctx, "tenant-1", "test", VLANRange{Start: 100, End: 200})
		if err != nil {
			t.Fatalf("CreateBridge failed: %v", err)
		}

		status, err := m.GetStatus(ctx, "tenant-1")
		if err != nil {
			t.Fatalf("GetStatus failed: %v", err)
		}

		if status != StatusActive {
			t.Errorf("Status = %q, want %q", status, StatusActive)
		}
	})

	t.Run("nonexistent bridge", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		m := NewManager(ovsClient, ofClient, nil, logger)

		_, err := m.GetStatus(ctx, "nonexistent")
		if err == nil {
			t.Error("GetStatus should fail for nonexistent tenant")
		}
	})
}

func TestManager_SetStatus(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("update status", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		m := NewManager(ovsClient, ofClient, nil, logger)

		_, err := m.CreateBridge(ctx, "tenant-1", "test", VLANRange{Start: 100, End: 200})
		if err != nil {
			t.Fatalf("CreateBridge failed: %v", err)
		}

		err = m.SetStatus(ctx, "tenant-1", StatusSuspended)
		if err != nil {
			t.Fatalf("SetStatus failed: %v", err)
		}

		status, _ := m.GetStatus(ctx, "tenant-1")
		if status != StatusSuspended {
			t.Errorf("Status = %q, want %q", status, StatusSuspended)
		}
	})

	t.Run("nonexistent bridge", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		m := NewManager(ovsClient, ofClient, nil, logger)

		err := m.SetStatus(ctx, "nonexistent", StatusActive)
		if err == nil {
			t.Error("SetStatus should fail for nonexistent tenant")
		}
	})
}

func TestManager_Refresh(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("successful refresh", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		m := NewManager(ovsClient, ofClient, nil, logger)

		_, err := m.CreateBridge(ctx, "tenant-1", "test", VLANRange{Start: 100, End: 200})
		if err != nil {
			t.Fatalf("CreateBridge failed: %v", err)
		}

		// Add some flows
		err = ofClient.AddFlow(ctx, "br-tenant-tes", &Flow{Table: 0})
		if err != nil {
			t.Fatalf("AddFlow setup failed: %v", err)
		}
		err = ofClient.AddFlow(ctx, "br-tenant-tes", &Flow{Table: 1})
		if err != nil {
			t.Fatalf("AddFlow setup failed: %v", err)
		}

		err = m.Refresh(ctx, "tenant-1")
		if err != nil {
			t.Fatalf("Refresh failed: %v", err)
		}
	})

	t.Run("nonexistent bridge", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		m := NewManager(ovsClient, ofClient, nil, logger)

		err := m.Refresh(ctx, "nonexistent")
		if err == nil {
			t.Error("Refresh should fail for nonexistent tenant")
		}
	})

	t.Run("recovers from error state", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		m := NewManager(ovsClient, ofClient, nil, logger)

		_, err := m.CreateBridge(ctx, "tenant-1", "test", VLANRange{Start: 100, End: 200})
		if err != nil {
			t.Fatalf("CreateBridge failed: %v", err)
		}

		// Set to error state
		err = m.SetStatus(ctx, "tenant-1", StatusError)
		if err != nil {
			t.Fatalf("SetStatus setup failed: %v", err)
		}

		// Refresh should recover
		err = m.Refresh(ctx, "tenant-1")
		if err != nil {
			t.Fatalf("Refresh failed: %v", err)
		}

		status, _ := m.GetStatus(ctx, "tenant-1")
		if status != StatusActive {
			t.Errorf("Status = %q, want %q after recovery", status, StatusActive)
		}
	})

	t.Run("OVS get bridge fails", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		m := NewManager(ovsClient, ofClient, nil, logger)

		_, err := m.CreateBridge(ctx, "tenant-1", "test", VLANRange{Start: 100, End: 200})
		if err != nil {
			t.Fatalf("CreateBridge failed: %v", err)
		}

		ovsClient.getErr = errors.New("connection lost")

		err = m.Refresh(ctx, "tenant-1")
		if err == nil {
			t.Error("Refresh should fail when OVS get fails")
		}

		// Status should be error
		status, _ := m.GetStatus(ctx, "tenant-1")
		if status != StatusError {
			t.Errorf("Status = %q, want %q", status, StatusError)
		}
	})
}

func TestManager_Sync(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("successful sync", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		m := NewManager(ovsClient, ofClient, nil, logger)

		_, err := m.CreateBridge(ctx, "tenant-1", "test", VLANRange{Start: 100, End: 200})
		if err != nil {
			t.Fatalf("CreateBridge failed: %v", err)
		}

		err = m.Sync(ctx)
		if err != nil {
			t.Fatalf("Sync failed: %v", err)
		}
	})

	t.Run("OVS list fails", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ovsClient.listErr = errors.New("connection refused")
		ofClient := newMockOpenFlowClient()
		m := NewManager(ovsClient, ofClient, nil, logger)

		err := m.Sync(ctx)
		if err == nil {
			t.Error("Sync should fail when OVS list fails")
		}

		var connErr ErrOVSConnectionFailed
		if !errors.As(err, &connErr) {
			t.Errorf("error should be ErrOVSConnectionFailed, got %T", err)
		}
	})

	t.Run("marks missing bridges as error", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		m := NewManager(ovsClient, ofClient, nil, logger)

		// Add bridge to manager state without OVS
		m.bridges["tenant-1"] = &TenantBridge{
			Name:     "br-tenant-test",
			TenantID: "tenant-1",
			Status:   StatusActive,
		}

		err := m.Sync(ctx)
		if err != nil {
			t.Fatalf("Sync failed: %v", err)
		}

		// Bridge should be marked as error
		status, _ := m.GetStatus(ctx, "tenant-1")
		if status != StatusError {
			t.Errorf("Status = %q, want %q for missing bridge", status, StatusError)
		}
	})
}

func TestManager_ConcurrentOperations(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("concurrent bridge creation", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		m := NewManager(ovsClient, ofClient, nil, logger)

		var wg sync.WaitGroup
		errors := make(chan error, 10)

		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				tenantID := "tenant-" + string(rune('a'+idx))
				tenantName := "test" + string(rune('a'+idx))
				_, err := m.CreateBridge(ctx, tenantID, tenantName, VLANRange{Start: uint16(100 + idx*10), End: uint16(109 + idx*10)})
				if err != nil {
					errors <- err
				}
			}(i)
		}

		wg.Wait()
		close(errors)

		for err := range errors {
			t.Errorf("concurrent creation error: %v", err)
		}

		bridges, _ := m.ListBridges(ctx)
		if len(bridges) != 10 {
			t.Errorf("expected 10 bridges, got %d", len(bridges))
		}
	})

	t.Run("concurrent reads", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		m := NewManager(ovsClient, ofClient, nil, logger)

		_, err := m.CreateBridge(ctx, "tenant-1", "test", VLANRange{Start: 100, End: 200})
		if err != nil {
			t.Fatalf("CreateBridge failed: %v", err)
		}

		var wg sync.WaitGroup

		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := m.GetBridge(ctx, "tenant-1"); err != nil {
					t.Errorf("GetBridge failed: %v", err)
				}
				if _, err := m.GetStatus(ctx, "tenant-1"); err != nil {
					t.Errorf("GetStatus failed: %v", err)
				}
				if _, err := m.ListBridges(ctx); err != nil {
					t.Errorf("ListBridges failed: %v", err)
				}
			}()
		}

		wg.Wait()
	})

	t.Run("concurrent create and delete", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		m := NewManager(ovsClient, ofClient, nil, logger)

		// Create initial bridges
		for i := 0; i < 5; i++ {
			tenantID := "tenant-" + string(rune('a'+i))
			tenantName := "test" + string(rune('a'+i))
			_, err := m.CreateBridge(ctx, tenantID, tenantName, VLANRange{Start: uint16(100 + i*10), End: uint16(109 + i*10)})
			if err != nil {
				t.Fatalf("CreateBridge setup failed: %v", err)
			}
		}

		var wg sync.WaitGroup

		// Delete some bridges concurrently
		for i := 0; i < 3; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				tenantID := "tenant-" + string(rune('a'+idx))
				if err := m.DeleteBridge(ctx, tenantID); err != nil {
					t.Errorf("DeleteBridge failed: %v", err)
				}
			}(i)
		}

		// Create new bridges concurrently
		for i := 5; i < 8; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				tenantID := "tenant-" + string(rune('a'+idx))
				tenantName := "test" + string(rune('a'+idx))
				if _, err := m.CreateBridge(ctx, tenantID, tenantName, VLANRange{Start: uint16(100 + idx*10), End: uint16(109 + idx*10)}); err != nil {
					t.Errorf("CreateBridge failed: %v", err)
				}
			}(i)
		}

		wg.Wait()

		// Should have 5 bridges remaining (5 initial - 3 deleted + 3 new)
		bridges, _ := m.ListBridges(ctx)
		if len(bridges) != 5 {
			t.Errorf("expected 5 bridges, got %d", len(bridges))
		}
	})
}

func TestManager_BridgeName(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	ovsClient := newMockOVSClient()
	ofClient := newMockOpenFlowClient()

	t.Run("simple name", func(t *testing.T) {
		m := NewManager(ovsClient, ofClient, nil, logger)
		name := m.bridgeName("test")

		if name != "br-tenant-test" {
			t.Errorf("bridgeName = %q, want %q", name, "br-tenant-test")
		}
	})

	t.Run("name with spaces", func(t *testing.T) {
		m := NewManager(ovsClient, ofClient, nil, logger)
		name := m.bridgeName("my test")

		// "br-tenant-my-te" truncated to 15 chars
		if name != "br-tenant-my-te" {
			t.Errorf("bridgeName = %q, want %q", name, "br-tenant-my-te")
		}
	})

	t.Run("name with underscores", func(t *testing.T) {
		m := NewManager(ovsClient, ofClient, nil, logger)
		name := m.bridgeName("my_test")

		// "br-tenant-my-te" truncated to 15 chars
		if name != "br-tenant-my-te" {
			t.Errorf("bridgeName = %q, want %q", name, "br-tenant-my-te")
		}
	})

	t.Run("uppercase converted to lowercase", func(t *testing.T) {
		m := NewManager(ovsClient, ofClient, nil, logger)
		name := m.bridgeName("TEST")

		if name != "br-tenant-test" {
			t.Errorf("bridgeName = %q, want %q", name, "br-tenant-test")
		}
	})

	t.Run("truncated to max length", func(t *testing.T) {
		m := NewManager(ovsClient, ofClient, nil, logger)
		name := m.bridgeName("verylongtenantname")

		if len(name) > MaxBridgeNameLength {
			t.Errorf("len(bridgeName) = %d, want <= %d", len(name), MaxBridgeNameLength)
		}
	})

	t.Run("custom prefix", func(t *testing.T) {
		cfg := &Config{
			BridgePrefix: "ovs-",
			Datapath:     "system",
		}
		m := NewManager(ovsClient, ofClient, cfg, logger)
		name := m.bridgeName("test")

		if name != "ovs-test" {
			t.Errorf("bridgeName = %q, want %q", name, "ovs-test")
		}
	})
}

func TestManager_ValidateTenantName(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	ovsClient := newMockOVSClient()
	ofClient := newMockOpenFlowClient()
	m := NewManager(ovsClient, ofClient, nil, logger)

	tests := []struct {
		name      string
		input     string
		expectErr bool
	}{
		{
			name:      "valid simple name",
			input:     "test",
			expectErr: false,
		},
		{
			name:      "valid with hyphen",
			input:     "test-name",
			expectErr: false,
		},
		{
			name:      "valid with underscore",
			input:     "test_name",
			expectErr: false,
		},
		{
			name:      "valid with numbers",
			input:     "test123",
			expectErr: false,
		},
		{
			name:      "empty name",
			input:     "",
			expectErr: true,
		},
		{
			name:      "starts with number",
			input:     "123test",
			expectErr: true,
		},
		{
			name:      "contains special characters",
			input:     "test@name",
			expectErr: true,
		},
		{
			name:      "contains spaces",
			input:     "test name",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := m.validateTenantName(tt.input)
			if (err != nil) != tt.expectErr {
				t.Errorf("validateTenantName(%q) error = %v, expectErr = %v", tt.input, err, tt.expectErr)
			}
		})
	}
}

func TestManager_ConfigureBridge(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("with netdev datapath", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		cfg := &Config{
			BridgePrefix: "br-test-",
			Datapath:     "netdev",
			FailMode:     "secure",
			Protocols:    []string{"OpenFlow15"},
		}
		m := NewManager(ovsClient, ofClient, cfg, logger)

		// Create bridge in mock
		if err := ovsClient.CreateBridge(ctx, "br-test"); err != nil {
			t.Fatalf("CreateBridge failed: %v", err)
		}

		err := m.configureBridge(ctx, "br-test")
		if err != nil {
			t.Fatalf("configureBridge failed: %v", err)
		}

		// Verify datapath was set
		info, _ := ovsClient.GetBridge(ctx, "br-test")
		if info.DatapathType != "netdev" {
			t.Errorf("DatapathType = %q, want %q", info.DatapathType, "netdev")
		}
	})

	t.Run("datapath set fails", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ovsClient.datapathErr = errors.New("datapath error")
		ofClient := newMockOpenFlowClient()
		cfg := &Config{
			BridgePrefix: "br-test-",
			Datapath:     "netdev",
		}
		m := NewManager(ovsClient, ofClient, cfg, logger)

		if err := ovsClient.CreateBridge(ctx, "br-test"); err != nil {
			t.Fatalf("CreateBridge failed: %v", err)
		}

		err := m.configureBridge(ctx, "br-test")
		if err == nil {
			t.Error("configureBridge should fail when datapath set fails")
		}
	})

	t.Run("fail mode set fails", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ovsClient.failModeErr = errors.New("fail mode error")
		ofClient := newMockOpenFlowClient()
		cfg := &Config{
			BridgePrefix: "br-test-",
			Datapath:     "system",
			FailMode:     "secure",
		}
		m := NewManager(ovsClient, ofClient, cfg, logger)

		if err := ovsClient.CreateBridge(ctx, "br-test"); err != nil {
			t.Fatalf("CreateBridge failed: %v", err)
		}

		err := m.configureBridge(ctx, "br-test")
		if err == nil {
			t.Error("configureBridge should fail when fail mode set fails")
		}
	})

	t.Run("protocols set fails", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ovsClient.protocolsErr = errors.New("protocols error")
		ofClient := newMockOpenFlowClient()
		cfg := &Config{
			BridgePrefix: "br-test-",
			Datapath:     "system",
			FailMode:     "",
			Protocols:    []string{"OpenFlow15"},
		}
		m := NewManager(ovsClient, ofClient, cfg, logger)

		if err := ovsClient.CreateBridge(ctx, "br-test"); err != nil {
			t.Fatalf("CreateBridge failed: %v", err)
		}

		err := m.configureBridge(ctx, "br-test")
		if err == nil {
			t.Error("configureBridge should fail when protocols set fails")
		}
	})
}

func TestManager_CopyBridge(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	ovsClient := newMockOVSClient()
	ofClient := newMockOpenFlowClient()
	m := NewManager(ovsClient, ofClient, nil, logger)

	now := time.Now()
	original := &TenantBridge{
		Name:         "br-test",
		TenantID:     "tenant-1",
		TenantName:   "test",
		Datapath:     "system",
		VLANRange:    VLANRange{Start: 100, End: 200},
		CreatedAt:    now,
		UpdatedAt:    now,
		Status:       StatusActive,
		PortCount:    5,
		FlowCount:    10,
		UUID:         "uuid-123",
		ErrorMessage: "",
	}

	copied := m.copyBridge(original)

	// Verify all fields are copied
	if copied.Name != original.Name {
		t.Errorf("Name = %q, want %q", copied.Name, original.Name)
	}
	if copied.TenantID != original.TenantID {
		t.Errorf("TenantID = %q, want %q", copied.TenantID, original.TenantID)
	}
	if copied.TenantName != original.TenantName {
		t.Errorf("TenantName = %q, want %q", copied.TenantName, original.TenantName)
	}
	if copied.Status != original.Status {
		t.Errorf("Status = %q, want %q", copied.Status, original.Status)
	}
	if copied.PortCount != original.PortCount {
		t.Errorf("PortCount = %d, want %d", copied.PortCount, original.PortCount)
	}
	if copied.FlowCount != original.FlowCount {
		t.Errorf("FlowCount = %d, want %d", copied.FlowCount, original.FlowCount)
	}

	// Verify it's a copy, not a reference
	copied.Status = StatusError
	if original.Status == StatusError {
		t.Error("modifying copy should not affect original")
	}
}
