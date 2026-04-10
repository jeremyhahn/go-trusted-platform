//go:build integration

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

package stress

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/cluster"
)

// mockStateManager implements a subset of cluster.StateManager for stress testing.
type mockStateManager struct {
	mu         sync.RWMutex
	bridges    map[string]*cluster.BridgeState
	ports      map[string]*cluster.PortState
	flows      map[string]*cluster.FlowState
	vlans      map[uint16]*cluster.VLANState
	versions   map[string]uint64
	syncCount  atomic.Int64
	opDelay    time.Duration
	errorRate  float64
	errorCount atomic.Uint64
}

func newMockStateManager() *mockStateManager {
	return &mockStateManager{
		bridges:  make(map[string]*cluster.BridgeState),
		ports:    make(map[string]*cluster.PortState),
		flows:    make(map[string]*cluster.FlowState),
		vlans:    make(map[uint16]*cluster.VLANState),
		versions: make(map[string]uint64),
	}
}

func (m *mockStateManager) SetOpDelay(d time.Duration) {
	m.opDelay = d
}

func (m *mockStateManager) SetErrorRate(rate float64) {
	m.errorRate = rate
}

func (m *mockStateManager) shouldFail() bool {
	if m.errorRate <= 0 {
		return false
	}
	count := m.errorCount.Add(1)
	return float64(count%100) < m.errorRate
}

func (m *mockStateManager) delay(ctx context.Context) error {
	if m.opDelay > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(m.opDelay):
		}
	}
	return nil
}

func (m *mockStateManager) CreateBridge(ctx context.Context, bridge *cluster.BridgeState) error {
	if err := m.delay(ctx); err != nil {
		return err
	}
	if m.shouldFail() {
		return fmt.Errorf("simulated bridge create failure")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.bridges[bridge.ID]; exists {
		return cluster.ErrBridgeAlreadyExists{BridgeID: bridge.ID}
	}

	bridge.Version = 1
	bridge.CreatedAt = time.Now()
	bridge.UpdatedAt = time.Now()
	m.bridges[bridge.ID] = bridge
	m.versions[bridge.ID] = 1
	return nil
}

func (m *mockStateManager) GetBridge(ctx context.Context, bridgeID string) (*cluster.BridgeState, error) {
	if err := m.delay(ctx); err != nil {
		return nil, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	bridge, exists := m.bridges[bridgeID]
	if !exists {
		return nil, cluster.ErrBridgeNotFound{BridgeID: bridgeID}
	}
	return bridge, nil
}

func (m *mockStateManager) UpdateBridge(ctx context.Context, bridgeID string, updates *cluster.BridgeState, expectedVersion uint64) error {
	if err := m.delay(ctx); err != nil {
		return err
	}
	if m.shouldFail() {
		return fmt.Errorf("simulated bridge update failure")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	bridge, exists := m.bridges[bridgeID]
	if !exists {
		return cluster.ErrBridgeNotFound{BridgeID: bridgeID}
	}

	if bridge.Version != expectedVersion {
		return cluster.ErrVersionConflict{
			EntityType:      "bridge",
			EntityID:        bridgeID,
			ExpectedVersion: expectedVersion,
			ActualVersion:   bridge.Version,
		}
	}

	bridge.Version++
	bridge.UpdatedAt = time.Now()
	if updates.Name != "" {
		bridge.Name = updates.Name
	}
	if updates.FailMode != "" {
		bridge.FailMode = updates.FailMode
	}
	m.versions[bridgeID] = bridge.Version
	return nil
}

func (m *mockStateManager) DeleteBridge(ctx context.Context, bridgeID string, expectedVersion uint64) error {
	if err := m.delay(ctx); err != nil {
		return err
	}
	if m.shouldFail() {
		return fmt.Errorf("simulated bridge delete failure")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	bridge, exists := m.bridges[bridgeID]
	if !exists {
		return cluster.ErrBridgeNotFound{BridgeID: bridgeID}
	}

	if bridge.Version != expectedVersion {
		return cluster.ErrVersionConflict{
			EntityType:      "bridge",
			EntityID:        bridgeID,
			ExpectedVersion: expectedVersion,
			ActualVersion:   bridge.Version,
		}
	}

	delete(m.bridges, bridgeID)
	delete(m.versions, bridgeID)
	return nil
}

func (m *mockStateManager) ListBridges(ctx context.Context) ([]*cluster.BridgeState, error) {
	if err := m.delay(ctx); err != nil {
		return nil, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	bridges := make([]*cluster.BridgeState, 0, len(m.bridges))
	for _, bridge := range m.bridges {
		bridges = append(bridges, bridge)
	}
	return bridges, nil
}

func (m *mockStateManager) CreatePort(ctx context.Context, port *cluster.PortState) error {
	if err := m.delay(ctx); err != nil {
		return err
	}
	if m.shouldFail() {
		return fmt.Errorf("simulated port create failure")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.ports[port.ID]; exists {
		return cluster.ErrPortAlreadyExists{PortID: port.ID}
	}

	port.Version = 1
	port.CreatedAt = time.Now()
	port.UpdatedAt = time.Now()
	m.ports[port.ID] = port
	return nil
}

func (m *mockStateManager) ListPorts(ctx context.Context, bridgeID string) ([]*cluster.PortState, error) {
	if err := m.delay(ctx); err != nil {
		return nil, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	var ports []*cluster.PortState
	for _, port := range m.ports {
		if port.BridgeID == bridgeID {
			ports = append(ports, port)
		}
	}
	return ports, nil
}

func (m *mockStateManager) CreateFlow(ctx context.Context, flow *cluster.FlowState) error {
	if err := m.delay(ctx); err != nil {
		return err
	}
	if m.shouldFail() {
		return fmt.Errorf("simulated flow create failure")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	key := fmt.Sprintf("%s/%s", flow.BridgeID, flow.ID)
	if _, exists := m.flows[key]; exists {
		return cluster.ErrFlowAlreadyExists{FlowID: flow.ID}
	}

	flow.Version = 1
	flow.CreatedAt = time.Now()
	flow.UpdatedAt = time.Now()
	m.flows[key] = flow
	return nil
}

func (m *mockStateManager) ListFlows(ctx context.Context, bridgeID string) ([]*cluster.FlowState, error) {
	if err := m.delay(ctx); err != nil {
		return nil, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	var flows []*cluster.FlowState
	for key, flow := range m.flows {
		if flow.BridgeID == bridgeID || key[:len(bridgeID)] == bridgeID {
			flows = append(flows, flow)
		}
	}
	return flows, nil
}

func (m *mockStateManager) CreateVLAN(ctx context.Context, vlan *cluster.VLANState) error {
	if err := m.delay(ctx); err != nil {
		return err
	}
	if m.shouldFail() {
		return fmt.Errorf("simulated VLAN create failure")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.vlans[vlan.ID]; exists {
		return cluster.ErrVLANAlreadyExists{VLANID: vlan.ID}
	}

	vlan.Version = 1
	vlan.CreatedAt = time.Now()
	vlan.UpdatedAt = time.Now()
	m.vlans[vlan.ID] = vlan
	return nil
}

func (m *mockStateManager) ListVLANs(ctx context.Context) ([]*cluster.VLANState, error) {
	if err := m.delay(ctx); err != nil {
		return nil, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	vlans := make([]*cluster.VLANState, 0, len(m.vlans))
	for _, vlan := range m.vlans {
		vlans = append(vlans, vlan)
	}
	return vlans, nil
}

func (m *mockStateManager) BridgeCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.bridges)
}

func (m *mockStateManager) PortCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.ports)
}

func (m *mockStateManager) FlowCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.flows)
}

// TestClusterStateSyncStress tests state synchronization under load.
func TestClusterStateSyncStress(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	stateManager := newMockStateManager()

	config := StressConfig{
		Name:           "Cluster State Sync Stress",
		Duration:       8 * time.Second,
		Concurrency:    20,
		RateLimit:      500,
		ReportInterval: 4 * time.Second,
		WarmupDuration: 1 * time.Second,
	}

	opCounter := atomic.Uint64{}
	bridgeCount := atomic.Int64{}
	portCount := atomic.Int64{}
	flowCount := atomic.Int64{}

	op := func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		counter := opCounter.Add(1)
		action := counter % 10

		switch {
		case action < 3: // 30% bridge operations
			bridge := &cluster.BridgeState{
				ID:       fmt.Sprintf("br-%d", counter),
				Name:     fmt.Sprintf("stress-bridge-%d", counter),
				NodeID:   1,
				FailMode: "secure",
			}
			err := stateManager.CreateBridge(ctx, bridge)
			if err == nil {
				bridgeCount.Add(1)
			}
			return err

		case action < 6: // 30% port operations
			port := &cluster.PortState{
				ID:       fmt.Sprintf("port-%d", counter),
				Name:     fmt.Sprintf("eth%d", counter%100),
				BridgeID: fmt.Sprintf("br-%d", counter%100),
				Tag:      uint16(counter % 4095),
			}
			err := stateManager.CreatePort(ctx, port)
			if err == nil {
				portCount.Add(1)
			}
			return err

		case action < 9: // 30% flow operations
			flow := &cluster.FlowState{
				ID:       fmt.Sprintf("flow-%d", counter),
				BridgeID: fmt.Sprintf("br-%d", counter%100),
				Table:    uint8(counter % 256),
				Priority: uint16(counter % 65535),
				Cookie:   counter,
			}
			err := stateManager.CreateFlow(ctx, flow)
			if err == nil {
				flowCount.Add(1)
			}
			return err

		default: // 10% VLAN operations
			vlan := &cluster.VLANState{
				ID:   uint16((counter % 4094) + 1),
				Name: fmt.Sprintf("vlan-%d", counter),
			}
			return stateManager.CreateVLAN(ctx, vlan)
		}
	}

	reporter := NewTableReporter(os.Stdout)
	result, err := RunStressTest(ctx, config.Name, config, op, reporter)
	if err != nil {
		t.Fatalf("Stress test failed: %v", err)
	}

	t.Logf("Bridges: %d, Ports: %d, Flows: %d",
		bridgeCount.Load(), portCount.Load(), flowCount.Load())
	t.Logf("State manager counts - Bridges: %d, Ports: %d, Flows: %d",
		stateManager.BridgeCount(), stateManager.PortCount(), stateManager.FlowCount())

	if result.SuccessRate() < 90 {
		t.Errorf("Success rate too low: %.2f%% (expected >= 90%%)", result.SuccessRate())
	}
}

// TestClusterVersionConflictStress tests handling of version conflicts.
func TestClusterVersionConflictStress(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	stateManager := newMockStateManager()

	// Pre-create bridges for update testing
	numBridges := 100
	for i := 0; i < numBridges; i++ {
		bridge := &cluster.BridgeState{
			ID:       fmt.Sprintf("br-%d", i),
			Name:     fmt.Sprintf("bridge-%d", i),
			NodeID:   1,
			FailMode: "secure",
		}
		if err := stateManager.CreateBridge(ctx, bridge); err != nil {
			t.Fatalf("Failed to create bridge %d: %v", i, err)
		}
	}

	config := StressConfig{
		Name:           "Cluster Version Conflict Stress",
		Duration:       8 * time.Second,
		Concurrency:    30, // High concurrency to cause conflicts
		RateLimit:      0,  // Unlimited to maximize conflicts
		ReportInterval: 4 * time.Second,
		WarmupDuration: 1 * time.Second,
	}

	opCounter := atomic.Uint64{}
	successCount := atomic.Int64{}
	conflictCount := atomic.Int64{}

	op := func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		counter := opCounter.Add(1)
		bridgeID := fmt.Sprintf("br-%d", counter%uint64(numBridges))

		// Get current version
		bridge, err := stateManager.GetBridge(ctx, bridgeID)
		if err != nil {
			return err
		}

		// Try to update (may conflict with concurrent updates)
		updates := &cluster.BridgeState{
			Name: fmt.Sprintf("updated-bridge-%d-%d", counter, time.Now().UnixNano()),
		}
		err = stateManager.UpdateBridge(ctx, bridgeID, updates, bridge.Version)
		if err != nil {
			if _, ok := err.(cluster.ErrVersionConflict); ok {
				conflictCount.Add(1)
			}
			return err
		}

		successCount.Add(1)
		return nil
	}

	reporter := NewTableReporter(os.Stdout)
	result, err := RunStressTest(ctx, config.Name, config, op, reporter)
	if err != nil {
		t.Fatalf("Stress test failed: %v", err)
	}

	t.Logf("Successful updates: %d, Version conflicts: %d, Total: %d",
		successCount.Load(), conflictCount.Load(), result.TotalOperations)

	// We expect some conflicts with high concurrency
	if conflictCount.Load() == 0 && result.TotalOperations > 1000 {
		t.Log("Note: No version conflicts occurred (may indicate serialized execution)")
	}

	// Success rate will be lower due to expected conflicts
	if result.SuccessRate() < 50 {
		t.Errorf("Success rate too low: %.2f%% (expected >= 50%%)", result.SuccessRate())
	}
}

// TestClusterBridgeCRUDStress tests complete bridge CRUD operations.
func TestClusterBridgeCRUDStress(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	stateManager := newMockStateManager()

	config := StressConfig{
		Name:           "Cluster Bridge CRUD Stress",
		Duration:       8 * time.Second,
		Concurrency:    15,
		RateLimit:      300,
		ReportInterval: 4 * time.Second,
		WarmupDuration: 1 * time.Second,
	}

	opCounter := atomic.Uint64{}
	createCount := atomic.Int64{}
	readCount := atomic.Int64{}
	updateCount := atomic.Int64{}
	deleteCount := atomic.Int64{}

	// Track created bridges for other operations
	createdBridges := make(chan string, 200)

	op := func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		counter := opCounter.Add(1)
		action := counter % 10

		switch {
		case action < 4: // 40% create
			bridgeID := fmt.Sprintf("br-%d", counter)
			bridge := &cluster.BridgeState{
				ID:       bridgeID,
				Name:     fmt.Sprintf("bridge-%d", counter),
				NodeID:   1,
				FailMode: "secure",
			}
			err := stateManager.CreateBridge(ctx, bridge)
			if err == nil {
				createCount.Add(1)
				select {
				case createdBridges <- bridgeID:
				default:
				}
			}
			return err

		case action < 6: // 20% read
			select {
			case bridgeID := <-createdBridges:
				_, err := stateManager.GetBridge(ctx, bridgeID)
				if err == nil {
					readCount.Add(1)
				}
				select {
				case createdBridges <- bridgeID:
				default:
				}
				return err
			default:
				// List all bridges
				_, err := stateManager.ListBridges(ctx)
				if err == nil {
					readCount.Add(1)
				}
				return err
			}

		case action < 8: // 20% update
			select {
			case bridgeID := <-createdBridges:
				bridge, err := stateManager.GetBridge(ctx, bridgeID)
				if err != nil {
					return err
				}
				updates := &cluster.BridgeState{
					Name: fmt.Sprintf("updated-%d", counter),
				}
				err = stateManager.UpdateBridge(ctx, bridgeID, updates, bridge.Version)
				if err == nil {
					updateCount.Add(1)
					select {
					case createdBridges <- bridgeID:
					default:
					}
				}
				return err
			default:
				return nil
			}

		default: // 20% delete
			select {
			case bridgeID := <-createdBridges:
				bridge, err := stateManager.GetBridge(ctx, bridgeID)
				if err != nil {
					return err
				}
				err = stateManager.DeleteBridge(ctx, bridgeID, bridge.Version)
				if err == nil {
					deleteCount.Add(1)
				}
				return err
			default:
				return nil
			}
		}
	}

	reporter := NewTableReporter(os.Stdout)
	result, err := RunStressTest(ctx, config.Name, config, op, reporter)
	if err != nil {
		t.Fatalf("Stress test failed: %v", err)
	}

	t.Logf("Creates: %d, Reads: %d, Updates: %d, Deletes: %d",
		createCount.Load(), readCount.Load(), updateCount.Load(), deleteCount.Load())

	if result.SuccessRate() < 80 {
		t.Errorf("Success rate too low: %.2f%% (expected >= 80%%)", result.SuccessRate())
	}
}

// TestClusterFlowProgrammingStress tests high-rate flow programming.
func TestClusterFlowProgrammingStress(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	stateManager := newMockStateManager()

	// Pre-create bridges
	for i := 0; i < 10; i++ {
		bridge := &cluster.BridgeState{
			ID:       fmt.Sprintf("br-%d", i),
			Name:     fmt.Sprintf("bridge-%d", i),
			NodeID:   1,
			FailMode: "secure",
		}
		if err := stateManager.CreateBridge(ctx, bridge); err != nil {
			t.Fatalf("Failed to create bridge: %v", err)
		}
	}

	config := StressConfig{
		Name:           "Cluster Flow Programming Stress",
		Duration:       8 * time.Second,
		Concurrency:    25,
		RateLimit:      1000, // High rate for flow programming
		ReportInterval: 4 * time.Second,
		WarmupDuration: 1 * time.Second,
	}

	flowCounter := atomic.Uint64{}
	programmedCount := atomic.Int64{}

	op := func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		counter := flowCounter.Add(1)
		bridgeID := fmt.Sprintf("br-%d", counter%10)

		// Create a flow with match and actions
		inPort := uint32(counter % 48)
		outPort := uint32((counter + 1) % 48)

		flow := &cluster.FlowState{
			ID:       fmt.Sprintf("flow-%d", counter),
			BridgeID: bridgeID,
			Table:    uint8(counter % 256),
			Priority: uint16((counter % 65000) + 1),
			Cookie:   counter,
			Match: &cluster.FlowMatch{
				InPort:  &inPort,
				EthType: func() *uint16 { v := uint16(0x0800); return &v }(),
			},
			Actions: []*cluster.FlowAction{
				{
					Type: cluster.ActionOutput,
					Port: &outPort,
				},
			},
		}

		err := stateManager.CreateFlow(ctx, flow)
		if err == nil {
			programmedCount.Add(1)
		}
		return err
	}

	reporter := NewTableReporter(os.Stdout)
	result, err := RunStressTest(ctx, config.Name, config, op, reporter)
	if err != nil {
		t.Fatalf("Stress test failed: %v", err)
	}

	t.Logf("Flows programmed: %d, Total flows in state: %d",
		programmedCount.Load(), stateManager.FlowCount())

	if result.SuccessRate() < 95 {
		t.Errorf("Success rate too low: %.2f%% (expected >= 95%%)", result.SuccessRate())
	}

	if result.Latencies.P99 > 20*time.Millisecond {
		t.Errorf("P99 latency too high: %s (expected <= 20ms)", result.Latencies.P99)
	}
}

// TestClusterLatencyWithSimulatedDelay tests behavior with network-like delays.
func TestClusterLatencyWithSimulatedDelay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	delays := []time.Duration{
		0,
		1 * time.Millisecond,
		5 * time.Millisecond,
	}

	for _, delay := range delays {
		t.Run(fmt.Sprintf("Delay_%s", delay), func(t *testing.T) {
			subCtx, subCancel := context.WithTimeout(ctx, 8*time.Second)
			defer subCancel()

			stateManager := newMockStateManager()
			stateManager.SetOpDelay(delay)

			config := StressConfig{
				Name:           fmt.Sprintf("Cluster Latency (delay=%s)", delay),
				Duration:       4 * time.Second,
				Concurrency:    20,
				RateLimit:      200,
				ReportInterval: 2 * time.Second,
				WarmupDuration: 500 * time.Millisecond,
			}

			counter := atomic.Uint64{}
			op := func(ctx context.Context) error {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
				}
				c := counter.Add(1)
				bridge := &cluster.BridgeState{
					ID:       fmt.Sprintf("br-%d", c),
					Name:     fmt.Sprintf("bridge-%d", c),
					NodeID:   1,
					FailMode: "secure",
				}
				return stateManager.CreateBridge(ctx, bridge)
			}

			metricsReporter := NewMetricsReporter()
			result, err := RunStressTest(subCtx, config.Name, config, op, metricsReporter)
			if err != nil {
				t.Fatalf("Stress test failed: %v", err)
			}

			t.Logf("Delay=%s: Throughput=%.2f ops/s, P50=%s, P95=%s, P99=%s",
				delay,
				result.Throughput,
				result.Latencies.P50.Round(time.Microsecond),
				result.Latencies.P95.Round(time.Microsecond),
				result.Latencies.P99.Round(time.Microsecond))

			// Verify latencies are affected by simulated delay
			if delay > 0 && result.Latencies.P50 < delay {
				t.Errorf("P50 latency (%s) should be >= simulated delay (%s)",
					result.Latencies.P50, delay)
			}
		})
	}
}

// TestClusterErrorRecoveryStress tests behavior with simulated errors.
func TestClusterErrorRecoveryStress(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	stateManager := newMockStateManager()
	stateManager.SetErrorRate(5) // 5% error rate

	config := StressConfig{
		Name:           "Cluster Error Recovery Stress",
		Duration:       8 * time.Second,
		Concurrency:    15,
		RateLimit:      300,
		ReportInterval: 4 * time.Second,
		WarmupDuration: 1 * time.Second,
	}

	counter := atomic.Uint64{}
	op := func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		c := counter.Add(1)
		bridge := &cluster.BridgeState{
			ID:       fmt.Sprintf("br-%d", c),
			Name:     fmt.Sprintf("bridge-%d", c),
			NodeID:   1,
			FailMode: "secure",
		}
		return stateManager.CreateBridge(ctx, bridge)
	}

	reporter := NewTableReporter(os.Stdout)
	result, err := RunStressTest(ctx, config.Name, config, op, reporter)
	if err != nil {
		t.Fatalf("Stress test failed: %v", err)
	}

	// With 5% error rate, expect ~95% success
	if result.SuccessRate() < 90 || result.SuccessRate() > 98 {
		t.Errorf("Success rate outside expected range: %.2f%% (expected 90-98%%)", result.SuccessRate())
	}

	t.Logf("Success rate with 5%% simulated errors: %.2f%%", result.SuccessRate())
}
