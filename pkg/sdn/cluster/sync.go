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

package cluster

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
)

// SyncStatus represents the current state of the OVS synchronizer.
type SyncStatus struct {
	// LastSyncTime is the timestamp of the last successful sync
	LastSyncTime time.Time

	// SyncInProgress indicates whether a sync operation is currently running
	SyncInProgress bool

	// ErrorCount is the total number of sync errors encountered
	ErrorCount int

	// LastError is the most recent sync error, if any
	LastError error

	// BridgesSynced is the number of bridges synced in the last operation
	BridgesSynced int

	// PortsSynced is the number of ports synced in the last operation
	PortsSynced int

	// FlowsSynced is the number of flows synced in the last operation
	FlowsSynced int

	// VLANsSynced is the number of VLANs synced in the last operation
	VLANsSynced int
}

// SyncMode defines how synchronization should be performed.
type SyncMode int

const (
	// SyncModeFull performs a complete reconciliation of all state
	SyncModeFull SyncMode = iota

	// SyncModeIncremental only syncs changes since last sync
	SyncModeIncremental
)

// OVSSynchronizer synchronizes cluster-replicated state from QuicBaaS to local OVS.
type OVSSynchronizer interface {
	// Start begins the synchronization loop
	Start(ctx context.Context) error

	// Stop gracefully stops the synchronizer
	Stop() error

	// SyncAll performs a full synchronization of all entities
	SyncAll() error

	// SyncBridge synchronizes a specific bridge and its ports/flows
	SyncBridge(bridgeID string) error

	// GetSyncStatus returns the current synchronization status
	GetSyncStatus() SyncStatus
}

// SynchronizerConfig holds configuration for the OVS synchronizer.
type SynchronizerConfig struct {
	// SyncInterval is the interval between automatic sync operations
	SyncInterval time.Duration

	// RetryInterval is the initial interval between retries on failure
	RetryInterval time.Duration

	// MaxRetries is the maximum number of retries before giving up
	MaxRetries int

	// RetryBackoffFactor is the exponential backoff multiplier
	RetryBackoffFactor float64

	// MaxRetryInterval is the maximum retry interval after backoff
	MaxRetryInterval time.Duration

	// ReconcileOnStartup enables full reconciliation when the synchronizer starts
	ReconcileOnStartup bool

	// NodeID is the local node identifier for filtering state
	NodeID uint64
}

// DefaultSynchronizerConfig returns a configuration with sensible defaults.
func DefaultSynchronizerConfig() *SynchronizerConfig {
	return &SynchronizerConfig{
		SyncInterval:       30 * time.Second,
		RetryInterval:      1 * time.Second,
		MaxRetries:         5,
		RetryBackoffFactor: 2.0,
		MaxRetryInterval:   30 * time.Second,
		ReconcileOnStartup: true,
		NodeID:             1,
	}
}

// SynchronizerOption is a functional option for configuring the synchronizer.
type SynchronizerOption func(*synchronizerConfig)

type synchronizerConfig struct {
	syncInterval       time.Duration
	retryInterval      time.Duration
	maxRetries         int
	retryBackoffFactor float64
	maxRetryInterval   time.Duration
	reconcileOnStartup bool
	nodeID             uint64
}

// WithSyncInterval sets the synchronization interval.
func WithSyncInterval(interval time.Duration) SynchronizerOption {
	return func(c *synchronizerConfig) {
		c.syncInterval = interval
	}
}

// WithRetryConfig sets retry configuration.
func WithRetryConfig(interval time.Duration, maxRetries int, backoffFactor float64) SynchronizerOption {
	return func(c *synchronizerConfig) {
		c.retryInterval = interval
		c.maxRetries = maxRetries
		c.retryBackoffFactor = backoffFactor
	}
}

// WithMaxRetryInterval sets the maximum retry interval.
func WithMaxRetryInterval(interval time.Duration) SynchronizerOption {
	return func(c *synchronizerConfig) {
		c.maxRetryInterval = interval
	}
}

// WithReconcileOnStartup enables or disables startup reconciliation.
func WithReconcileOnStartup(enabled bool) SynchronizerOption {
	return func(c *synchronizerConfig) {
		c.reconcileOnStartup = enabled
	}
}

// WithNodeID sets the node identifier for filtering state.
func WithNodeID(nodeID uint64) SynchronizerOption {
	return func(c *synchronizerConfig) {
		c.nodeID = nodeID
	}
}

// quicbaasSynchronizer implements OVSSynchronizer.
type quicbaasSynchronizer struct {
	stateManager StateManager
	ovsClient    OVSClient
	logger       *logging.Logger
	config       *synchronizerConfig

	// Runtime state
	status     SyncStatus
	statusMu   sync.RWMutex
	running    atomic.Bool
	stopCh     chan struct{}
	doneCh     chan struct{}
	syncMu     sync.Mutex
	errorCount atomic.Int64
}

// OVSClient is an interface for OVS operations to enable testing.
type OVSClient interface {
	// Bridge operations
	CreateBridge(ctx context.Context, name string) (*ovs.Bridge, error)
	DeleteBridge(ctx context.Context, name string) error
	GetBridge(ctx context.Context, name string) (*ovs.Bridge, error)
	ListBridges(ctx context.Context) ([]*ovs.Bridge, error)
	UpdateBridge(ctx context.Context, name string, updates map[string]interface{}) error
	SetBridgeFailMode(ctx context.Context, name string, failMode string) error
	SetBridgeProtocols(ctx context.Context, name string, protocols []string) error

	// Port operations
	AddPort(ctx context.Context, bridgeName, portName string) (*ovs.Port, error)
	DeletePort(ctx context.Context, bridgeName, portName string) error
	GetPort(ctx context.Context, name string) (*ovs.Port, error)
	ListPorts(ctx context.Context, bridgeName string) ([]*ovs.Port, error)
	SetPortVLAN(ctx context.Context, portName string, tag int64) error
	SetPortTrunks(ctx context.Context, portName string, trunks []int64) error

	// Flow operations
	AddFlow(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error
	DeleteFlow(ctx context.Context, bridgeName string, match string) error
	ListFlows(ctx context.Context, bridgeName string) ([]*ovs.Flow, error)
	DeleteAllFlows(ctx context.Context, bridgeName string) error

	// Connection management
	IsConnected() bool
}

// NewOVSSynchronizer creates a new OVS synchronizer instance.
func NewOVSSynchronizer(
	stateManager StateManager,
	ovsClient OVSClient,
	logger *logging.Logger,
	opts ...SynchronizerOption,
) OVSSynchronizer {
	cfg := &synchronizerConfig{
		syncInterval:       30 * time.Second,
		retryInterval:      1 * time.Second,
		maxRetries:         5,
		retryBackoffFactor: 2.0,
		maxRetryInterval:   30 * time.Second,
		reconcileOnStartup: true,
		nodeID:             1,
	}

	for _, opt := range opts {
		opt(cfg)
	}

	return &quicbaasSynchronizer{
		stateManager: stateManager,
		ovsClient:    ovsClient,
		logger:       logger,
		config:       cfg,
		stopCh:       make(chan struct{}),
		doneCh:       make(chan struct{}),
	}
}

// Start begins the synchronization loop.
func (s *quicbaasSynchronizer) Start(ctx context.Context) error {
	if s.running.Load() {
		return ErrSyncAlreadyRunning{}
	}

	s.running.Store(true)
	s.stopCh = make(chan struct{})
	s.doneCh = make(chan struct{})

	// Perform initial reconciliation if enabled
	if s.config.reconcileOnStartup {
		s.logger.Info("Performing startup reconciliation")
		if err := s.reconcile(ctx); err != nil {
			s.logger.Error(err, "Startup reconciliation failed")
			// Continue running even if initial reconciliation fails
		}
	}

	// Start the sync loop
	go s.syncLoop(ctx)

	s.logger.Info("OVS synchronizer started",
		"sync_interval", s.config.syncInterval,
		"node_id", s.config.nodeID)

	return nil
}

// Stop gracefully stops the synchronizer.
func (s *quicbaasSynchronizer) Stop() error {
	if !s.running.Load() {
		return ErrSyncNotRunning{}
	}

	s.logger.Info("Stopping OVS synchronizer")

	// Signal shutdown
	close(s.stopCh)

	// Wait for sync loop to complete with timeout
	select {
	case <-s.doneCh:
		s.logger.Info("OVS synchronizer stopped")
	case <-time.After(10 * time.Second):
		s.logger.Warn("OVS synchronizer stop timed out")
	}

	s.running.Store(false)
	return nil
}

// SyncAll performs a full synchronization of all entities.
func (s *quicbaasSynchronizer) SyncAll() error {
	ctx := context.Background()
	return s.reconcile(ctx)
}

// SyncBridge synchronizes a specific bridge and its ports/flows.
func (s *quicbaasSynchronizer) SyncBridge(bridgeID string) error {
	if bridgeID == "" {
		return ErrInvalidBridgeID{BridgeID: bridgeID, Reason: "bridge ID is required"}
	}

	ctx := context.Background()
	return s.syncSingleBridge(ctx, bridgeID)
}

// GetSyncStatus returns the current synchronization status.
func (s *quicbaasSynchronizer) GetSyncStatus() SyncStatus {
	s.statusMu.RLock()
	defer s.statusMu.RUnlock()
	return s.status
}

// syncLoop runs the main synchronization loop.
func (s *quicbaasSynchronizer) syncLoop(ctx context.Context) {
	defer close(s.doneCh)

	ticker := time.NewTicker(s.config.syncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			if err := s.reconcile(ctx); err != nil {
				s.logger.Error(err, "Periodic sync failed")
			}
		}
	}
}

// reconcile performs a full reconciliation between QuicBaaS state and OVS.
func (s *quicbaasSynchronizer) reconcile(ctx context.Context) error {
	// Ensure only one sync runs at a time
	s.syncMu.Lock()
	defer s.syncMu.Unlock()

	s.updateSyncStatus(func(status *SyncStatus) {
		status.SyncInProgress = true
	})

	defer s.updateSyncStatus(func(status *SyncStatus) {
		status.SyncInProgress = false
	})

	startTime := time.Now()
	s.logger.Debug("Starting reconciliation")

	// Track sync statistics
	var bridgesSynced, portsSynced, flowsSynced, vlansSynced int
	var syncErr error

	// Step 1: Sync bridges
	bridgesSynced, syncErr = s.reconcileBridges(ctx)
	if syncErr != nil {
		s.handleSyncError(syncErr)
		return syncErr
	}

	// Step 2: Sync ports for each bridge
	portsSynced, syncErr = s.reconcilePorts(ctx)
	if syncErr != nil {
		s.handleSyncError(syncErr)
		return syncErr
	}

	// Step 3: Sync flows for each bridge
	flowsSynced, syncErr = s.reconcileFlows(ctx)
	if syncErr != nil {
		s.handleSyncError(syncErr)
		return syncErr
	}

	// Step 4: Sync VLANs (port VLAN assignments)
	vlansSynced, syncErr = s.reconcileVLANs(ctx)
	if syncErr != nil {
		s.handleSyncError(syncErr)
		return syncErr
	}

	// Update successful sync status
	s.updateSyncStatus(func(status *SyncStatus) {
		status.LastSyncTime = time.Now()
		status.LastError = nil
		status.BridgesSynced = bridgesSynced
		status.PortsSynced = portsSynced
		status.FlowsSynced = flowsSynced
		status.VLANsSynced = vlansSynced
	})

	elapsed := time.Since(startTime)
	s.logger.Info("Reconciliation completed",
		"duration", elapsed,
		"bridges", bridgesSynced,
		"ports", portsSynced,
		"flows", flowsSynced,
		"vlans", vlansSynced)

	return nil
}

// reconcileBridges synchronizes bridges from QuicBaaS to OVS.
func (s *quicbaasSynchronizer) reconcileBridges(ctx context.Context) (int, error) {
	// Get desired state from QuicBaaS
	desiredBridges, err := s.stateManager.ListBridges(ctx)
	if err != nil {
		return 0, ErrSyncFailed{Entity: "bridges", Operation: "list desired", Cause: err}
	}

	// Filter to only this node's bridges
	var localBridges []*BridgeState
	for _, b := range desiredBridges {
		if b.NodeID == s.config.nodeID {
			localBridges = append(localBridges, b)
		}
	}

	// Get current state from OVS
	currentBridges, err := s.ovsClient.ListBridges(ctx)
	if err != nil {
		return 0, ErrSyncFailed{Entity: "bridges", Operation: "list current", Cause: err}
	}

	// Build maps for efficient lookup
	desiredMap := make(map[string]*BridgeState)
	for _, b := range localBridges {
		desiredMap[b.Name] = b
	}

	currentMap := make(map[string]*ovs.Bridge)
	for _, b := range currentBridges {
		currentMap[b.Name] = b
	}

	synced := 0

	// Create missing bridges
	for name, desired := range desiredMap {
		if _, exists := currentMap[name]; !exists {
			if err := s.createBridgeWithRetry(ctx, desired); err != nil {
				s.logger.Error(err, "Failed to create bridge", "bridge", name)
				continue
			}
			synced++
		}
	}

	// Update existing bridges that have drifted
	for name, desired := range desiredMap {
		if current, exists := currentMap[name]; exists {
			if s.bridgeNeedsUpdate(desired, current) {
				if err := s.updateBridgeWithRetry(ctx, desired, current); err != nil {
					s.logger.Error(err, "Failed to update bridge", "bridge", name)
					continue
				}
				synced++
			}
		}
	}

	// Delete bridges that are in OVS but not in QuicBaaS
	// Only delete bridges that have our external ID marker
	for name, current := range currentMap {
		if _, exists := desiredMap[name]; !exists {
			if s.isManagedBridge(current) {
				if err := s.deleteBridgeWithRetry(ctx, name); err != nil {
					s.logger.Error(err, "Failed to delete bridge", "bridge", name)
					continue
				}
				synced++
			}
		}
	}

	return synced, nil
}

// reconcilePorts synchronizes ports from QuicBaaS to OVS.
func (s *quicbaasSynchronizer) reconcilePorts(ctx context.Context) (int, error) {
	// Get all bridges for this node
	bridges, err := s.stateManager.ListBridges(ctx)
	if err != nil {
		return 0, ErrSyncFailed{Entity: "ports", Operation: "list bridges", Cause: err}
	}

	synced := 0

	for _, bridge := range bridges {
		if bridge.NodeID != s.config.nodeID {
			continue
		}

		// Get desired ports for this bridge
		desiredPorts, err := s.stateManager.ListPorts(ctx, bridge.ID)
		if err != nil {
			s.logger.Error(err, "Failed to list desired ports", "bridge", bridge.Name)
			continue
		}

		// Get current ports from OVS
		currentPorts, err := s.ovsClient.ListPorts(ctx, bridge.Name)
		if err != nil {
			s.logger.Error(err, "Failed to list current ports", "bridge", bridge.Name)
			continue
		}

		// Build maps
		desiredMap := make(map[string]*PortState)
		for _, p := range desiredPorts {
			desiredMap[p.Name] = p
		}

		currentMap := make(map[string]*ovs.Port)
		for _, p := range currentPorts {
			currentMap[p.Name] = p
		}

		// Create missing ports
		for name, desired := range desiredMap {
			if _, exists := currentMap[name]; !exists {
				if err := s.createPortWithRetry(ctx, bridge.Name, desired); err != nil {
					s.logger.Error(err, "Failed to create port", "bridge", bridge.Name, "port", name)
					continue
				}
				synced++
			}
		}

		// Update existing ports that have drifted
		for name, desired := range desiredMap {
			if current, exists := currentMap[name]; exists {
				if s.portNeedsUpdate(desired, current) {
					if err := s.updatePortWithRetry(ctx, desired, current); err != nil {
						s.logger.Error(err, "Failed to update port", "bridge", bridge.Name, "port", name)
						continue
					}
					synced++
				}
			}
		}

		// Delete ports that are in OVS but not in QuicBaaS
		// Skip the internal bridge port (same name as bridge)
		for name, current := range currentMap {
			if name == bridge.Name {
				continue // Skip internal port
			}
			if _, exists := desiredMap[name]; !exists {
				if s.isManagedPort(current) {
					if err := s.deletePortWithRetry(ctx, bridge.Name, name); err != nil {
						s.logger.Error(err, "Failed to delete port", "bridge", bridge.Name, "port", name)
						continue
					}
					synced++
				}
			}
		}
	}

	return synced, nil
}

// reconcileFlows synchronizes flows from QuicBaaS to OVS.
func (s *quicbaasSynchronizer) reconcileFlows(ctx context.Context) (int, error) {
	// Get all bridges for this node
	bridges, err := s.stateManager.ListBridges(ctx)
	if err != nil {
		return 0, ErrSyncFailed{Entity: "flows", Operation: "list bridges", Cause: err}
	}

	synced := 0

	for _, bridge := range bridges {
		if bridge.NodeID != s.config.nodeID {
			continue
		}

		// Get desired flows for this bridge
		desiredFlows, err := s.stateManager.ListFlows(ctx, bridge.ID)
		if err != nil {
			s.logger.Error(err, "Failed to list desired flows", "bridge", bridge.Name)
			continue
		}

		// Get current flows from OVS
		currentFlows, err := s.ovsClient.ListFlows(ctx, bridge.Name)
		if err != nil {
			s.logger.Error(err, "Failed to list current flows", "bridge", bridge.Name)
			continue
		}

		// Build a map of current flows by cookie for comparison
		// This is a simplified approach - production systems might need more sophisticated matching
		currentFlowMap := make(map[string]*ovs.Flow)
		for _, f := range currentFlows {
			currentFlowMap[f.Cookie] = f
		}

		// Install missing flows
		for _, desired := range desiredFlows {
			cookieStr := fmt.Sprintf("0x%x", desired.Cookie)
			if _, exists := currentFlowMap[cookieStr]; !exists {
				if err := s.createFlowWithRetry(ctx, bridge.Name, desired); err != nil {
					s.logger.Error(err, "Failed to create flow", "bridge", bridge.Name, "flow", desired.ID)
					continue
				}
				synced++
			}
		}

		// For now, we don't delete flows that aren't in QuicBaaS
		// as they might have been installed by other controllers
	}

	return synced, nil
}

// reconcileVLANs synchronizes VLAN assignments from QuicBaaS to OVS.
func (s *quicbaasSynchronizer) reconcileVLANs(ctx context.Context) (int, error) {
	// VLAN assignments are handled during port sync
	// This method is for VLAN configuration state
	vlans, err := s.stateManager.ListVLANs(ctx)
	if err != nil {
		return 0, ErrSyncFailed{Entity: "vlans", Operation: "list", Cause: err}
	}

	// VLAN state is typically maintained in QuicBaaS for reference
	// The actual VLAN tagging happens at the port level
	return len(vlans), nil
}

// syncSingleBridge synchronizes a single bridge and its associated resources.
func (s *quicbaasSynchronizer) syncSingleBridge(ctx context.Context, bridgeID string) error {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()

	// Get bridge from QuicBaaS
	bridge, err := s.stateManager.GetBridge(ctx, bridgeID)
	if err != nil {
		return ErrSyncFailed{Entity: "bridge", Operation: "get", Cause: err}
	}

	// Verify this is our node's bridge
	if bridge.NodeID != s.config.nodeID {
		return ErrSyncFailed{Entity: "bridge", Operation: "sync", Cause: fmt.Errorf("bridge belongs to node %d, not %d", bridge.NodeID, s.config.nodeID)}
	}

	// Check if bridge exists in OVS
	ovsBridge, err := s.ovsClient.GetBridge(ctx, bridge.Name)
	if err != nil {
		// Bridge doesn't exist, create it
		if err := s.createBridgeWithRetry(ctx, bridge); err != nil {
			return err
		}
	} else {
		// Bridge exists, check for drift
		if s.bridgeNeedsUpdate(bridge, ovsBridge) {
			if err := s.updateBridgeWithRetry(ctx, bridge, ovsBridge); err != nil {
				return err
			}
		}
	}

	// Sync ports for this bridge
	desiredPorts, err := s.stateManager.ListPorts(ctx, bridgeID)
	if err != nil {
		return ErrSyncFailed{Entity: "ports", Operation: "list", Cause: err}
	}

	for _, port := range desiredPorts {
		_, err := s.ovsClient.GetPort(ctx, port.Name)
		if err != nil {
			// Port doesn't exist, create it
			if err := s.createPortWithRetry(ctx, bridge.Name, port); err != nil {
				s.logger.Error(err, "Failed to create port during bridge sync", "port", port.Name)
			}
		}
	}

	// Sync flows for this bridge
	desiredFlows, err := s.stateManager.ListFlows(ctx, bridgeID)
	if err != nil {
		return ErrSyncFailed{Entity: "flows", Operation: "list", Cause: err}
	}

	for _, flow := range desiredFlows {
		if err := s.createFlowWithRetry(ctx, bridge.Name, flow); err != nil {
			s.logger.Error(err, "Failed to create flow during bridge sync", "flow", flow.ID)
		}
	}

	return nil
}

// createBridgeWithRetry creates a bridge with retry logic.
func (s *quicbaasSynchronizer) createBridgeWithRetry(ctx context.Context, desired *BridgeState) error {
	return s.withRetry(ctx, "create bridge", func() error {
		_, err := s.ovsClient.CreateBridge(ctx, desired.Name)
		if err != nil {
			return err
		}

		// Set additional bridge properties
		if desired.FailMode != "" {
			if err := s.ovsClient.SetBridgeFailMode(ctx, desired.Name, desired.FailMode); err != nil {
				s.logger.Warn("Failed to set fail mode", "bridge", desired.Name, "error", err)
			}
		}

		if len(desired.FlowProtocols) > 0 {
			if err := s.ovsClient.SetBridgeProtocols(ctx, desired.Name, desired.FlowProtocols); err != nil {
				s.logger.Warn("Failed to set protocols", "bridge", desired.Name, "error", err)
			}
		}

		return nil
	})
}

// updateBridgeWithRetry updates a bridge with retry logic.
func (s *quicbaasSynchronizer) updateBridgeWithRetry(ctx context.Context, desired *BridgeState, current *ovs.Bridge) error {
	return s.withRetry(ctx, "update bridge", func() error {
		updates := make(map[string]interface{})

		if desired.FailMode != current.FailMode {
			updates["fail_mode"] = desired.FailMode
		}

		if desired.STPEnabled != current.STP {
			updates["stp_enable"] = desired.STPEnabled
		}

		if len(updates) > 0 {
			return s.ovsClient.UpdateBridge(ctx, desired.Name, updates)
		}

		return nil
	})
}

// deleteBridgeWithRetry deletes a bridge with retry logic.
func (s *quicbaasSynchronizer) deleteBridgeWithRetry(ctx context.Context, name string) error {
	return s.withRetry(ctx, "delete bridge", func() error {
		return s.ovsClient.DeleteBridge(ctx, name)
	})
}

// createPortWithRetry creates a port with retry logic.
func (s *quicbaasSynchronizer) createPortWithRetry(ctx context.Context, bridgeName string, desired *PortState) error {
	return s.withRetry(ctx, "create port", func() error {
		_, err := s.ovsClient.AddPort(ctx, bridgeName, desired.Name)
		if err != nil {
			return err
		}

		// Set VLAN tag if specified
		if desired.Tag > 0 {
			if err := s.ovsClient.SetPortVLAN(ctx, desired.Name, int64(desired.Tag)); err != nil {
				s.logger.Warn("Failed to set VLAN tag", "port", desired.Name, "error", err)
			}
		}

		// Set trunk VLANs if specified
		if len(desired.Trunks) > 0 {
			trunks := make([]int64, len(desired.Trunks))
			for i, v := range desired.Trunks {
				trunks[i] = int64(v)
			}
			if err := s.ovsClient.SetPortTrunks(ctx, desired.Name, trunks); err != nil {
				s.logger.Warn("Failed to set trunk VLANs", "port", desired.Name, "error", err)
			}
		}

		return nil
	})
}

// updatePortWithRetry updates a port with retry logic.
func (s *quicbaasSynchronizer) updatePortWithRetry(ctx context.Context, desired *PortState, current *ovs.Port) error {
	return s.withRetry(ctx, "update port", func() error {
		// Update VLAN tag if different
		if int64(desired.Tag) != current.Tag {
			if err := s.ovsClient.SetPortVLAN(ctx, desired.Name, int64(desired.Tag)); err != nil {
				return err
			}
		}

		// Update trunk VLANs if different
		if !s.trunksEqual(desired.Trunks, current.Trunks) {
			trunks := make([]int64, len(desired.Trunks))
			for i, v := range desired.Trunks {
				trunks[i] = int64(v)
			}
			if err := s.ovsClient.SetPortTrunks(ctx, desired.Name, trunks); err != nil {
				return err
			}
		}

		return nil
	})
}

// deletePortWithRetry deletes a port with retry logic.
func (s *quicbaasSynchronizer) deletePortWithRetry(ctx context.Context, bridgeName, portName string) error {
	return s.withRetry(ctx, "delete port", func() error {
		return s.ovsClient.DeletePort(ctx, bridgeName, portName)
	})
}

// createFlowWithRetry creates a flow with retry logic.
func (s *quicbaasSynchronizer) createFlowWithRetry(ctx context.Context, bridgeName string, desired *FlowState) error {
	return s.withRetry(ctx, "create flow", func() error {
		flowMod := s.convertFlowStateToFlowMod(desired)
		return s.ovsClient.AddFlow(ctx, bridgeName, flowMod)
	})
}

// convertFlowStateToFlowMod converts a FlowState to an OVS FlowMod.
func (s *quicbaasSynchronizer) convertFlowStateToFlowMod(flow *FlowState) *ovs.FlowMod {
	flowMod := &ovs.FlowMod{
		Table:       int(flow.Table),
		Priority:    int(flow.Priority),
		IdleTimeout: int(flow.IdleTimeout),
		HardTimeout: int(flow.HardTimeout),
		Cookie:      fmt.Sprintf("0x%x", flow.Cookie),
	}

	// Build match string from FlowMatch
	flowMod.Match = s.buildMatchString(flow.Match)

	// Build actions string from FlowActions
	flowMod.Actions = s.buildActionsString(flow.Actions)

	return flowMod
}

// buildMatchString converts FlowMatch to OVS match string format.
func (s *quicbaasSynchronizer) buildMatchString(match *FlowMatch) string {
	if match == nil {
		return ""
	}

	var parts []string

	if match.InPort != nil {
		parts = append(parts, fmt.Sprintf("in_port=%d", *match.InPort))
	}
	if match.EthSrc != "" {
		parts = append(parts, fmt.Sprintf("dl_src=%s", match.EthSrc))
	}
	if match.EthDst != "" {
		parts = append(parts, fmt.Sprintf("dl_dst=%s", match.EthDst))
	}
	if match.EthType != nil {
		parts = append(parts, fmt.Sprintf("dl_type=0x%04x", *match.EthType))
	}
	if match.VLANVid != nil {
		parts = append(parts, fmt.Sprintf("dl_vlan=%d", *match.VLANVid))
	}
	if match.IPv4Src != "" {
		parts = append(parts, fmt.Sprintf("nw_src=%s", match.IPv4Src))
	}
	if match.IPv4Dst != "" {
		parts = append(parts, fmt.Sprintf("nw_dst=%s", match.IPv4Dst))
	}
	if match.IPProto != nil {
		parts = append(parts, fmt.Sprintf("nw_proto=%d", *match.IPProto))
	}
	if match.TCPSrc != nil {
		parts = append(parts, fmt.Sprintf("tp_src=%d", *match.TCPSrc))
	}
	if match.TCPDst != nil {
		parts = append(parts, fmt.Sprintf("tp_dst=%d", *match.TCPDst))
	}
	if match.UDPSrc != nil {
		parts = append(parts, fmt.Sprintf("tp_src=%d", *match.UDPSrc))
	}
	if match.UDPDst != nil {
		parts = append(parts, fmt.Sprintf("tp_dst=%d", *match.UDPDst))
	}

	result := ""
	for i, p := range parts {
		if i > 0 {
			result += ","
		}
		result += p
	}
	return result
}

// buildActionsString converts FlowActions to OVS actions string format.
func (s *quicbaasSynchronizer) buildActionsString(actions []*FlowAction) string {
	if len(actions) == 0 {
		return "drop"
	}

	var parts []string

	for _, action := range actions {
		switch action.Type {
		case ActionOutput:
			if action.Port != nil {
				parts = append(parts, fmt.Sprintf("output:%d", *action.Port))
			}
		case ActionDrop:
			parts = append(parts, "drop")
		case ActionNormal:
			parts = append(parts, "NORMAL")
		case ActionFlood:
			parts = append(parts, "FLOOD")
		case ActionAll:
			parts = append(parts, "ALL")
		case ActionController:
			parts = append(parts, "CONTROLLER")
		case ActionLocal:
			parts = append(parts, "LOCAL")
		case ActionInPort:
			parts = append(parts, "IN_PORT")
		case ActionSetVLAN:
			if action.VLANVid != nil {
				parts = append(parts, fmt.Sprintf("mod_vlan_vid:%d", *action.VLANVid))
			}
		case ActionStripVLAN:
			parts = append(parts, "strip_vlan")
		case ActionSetEthSrc:
			if action.MAC != "" {
				parts = append(parts, fmt.Sprintf("mod_dl_src:%s", action.MAC))
			}
		case ActionSetEthDst:
			if action.MAC != "" {
				parts = append(parts, fmt.Sprintf("mod_dl_dst:%s", action.MAC))
			}
		case ActionSetIPv4Src:
			if action.IPv4 != "" {
				parts = append(parts, fmt.Sprintf("mod_nw_src:%s", action.IPv4))
			}
		case ActionSetIPv4Dst:
			if action.IPv4 != "" {
				parts = append(parts, fmt.Sprintf("mod_nw_dst:%s", action.IPv4))
			}
		case ActionGotoTable:
			if action.Table != nil {
				parts = append(parts, fmt.Sprintf("resubmit(,%d)", *action.Table))
			}
		}
	}

	result := ""
	for i, p := range parts {
		if i > 0 {
			result += ","
		}
		result += p
	}
	return result
}

// withRetry executes a function with exponential backoff retry.
func (s *quicbaasSynchronizer) withRetry(ctx context.Context, operation string, fn func() error) error {
	var lastErr error
	retryInterval := s.config.retryInterval

	for attempt := 0; attempt <= s.config.maxRetries; attempt++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.stopCh:
			return ErrSyncStopped{}
		default:
		}

		if err := fn(); err != nil {
			lastErr = err
			s.logger.Warn("Operation failed, retrying",
				"operation", operation,
				"attempt", attempt+1,
				"max_retries", s.config.maxRetries,
				"error", err)

			if attempt < s.config.maxRetries {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-s.stopCh:
					return ErrSyncStopped{}
				case <-time.After(retryInterval):
				}

				// Apply exponential backoff
				retryInterval = time.Duration(float64(retryInterval) * s.config.retryBackoffFactor)
				if retryInterval > s.config.maxRetryInterval {
					retryInterval = s.config.maxRetryInterval
				}
			}
		} else {
			return nil
		}
	}

	return ErrMaxRetriesExceeded{Operation: operation, LastError: lastErr}
}

// bridgeNeedsUpdate checks if a bridge needs to be updated.
func (s *quicbaasSynchronizer) bridgeNeedsUpdate(desired *BridgeState, current *ovs.Bridge) bool {
	if desired.FailMode != current.FailMode {
		return true
	}
	if desired.STPEnabled != current.STP {
		return true
	}
	if desired.RSTPEnabled != current.RSTP {
		return true
	}
	if desired.McastSnoopingEnabled != current.McastSnooping {
		return true
	}
	return false
}

// portNeedsUpdate checks if a port needs to be updated.
func (s *quicbaasSynchronizer) portNeedsUpdate(desired *PortState, current *ovs.Port) bool {
	if int64(desired.Tag) != current.Tag {
		return true
	}
	if !s.trunksEqual(desired.Trunks, current.Trunks) {
		return true
	}
	return false
}

// trunksEqual compares two trunk VLAN lists.
func (s *quicbaasSynchronizer) trunksEqual(a []uint16, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	aMap := make(map[uint16]bool)
	for _, v := range a {
		aMap[v] = true
	}
	for _, v := range b {
		if !aMap[uint16(v)] {
			return false
		}
	}
	return true
}

// isManagedBridge checks if a bridge is managed by this synchronizer.
func (s *quicbaasSynchronizer) isManagedBridge(bridge *ovs.Bridge) bool {
	// Check for our external ID marker
	if bridge.ExternalIDs == nil {
		return false
	}
	if managed, ok := bridge.ExternalIDs["managed-by"]; ok {
		return managed == "quicbaas"
	}
	return false
}

// isManagedPort checks if a port is managed by this synchronizer.
func (s *quicbaasSynchronizer) isManagedPort(port *ovs.Port) bool {
	// Check for our external ID marker
	if port.ExternalIDs == nil {
		return false
	}
	if managed, ok := port.ExternalIDs["managed-by"]; ok {
		return managed == "quicbaas"
	}
	return false
}

// updateSyncStatus safely updates the sync status.
func (s *quicbaasSynchronizer) updateSyncStatus(fn func(*SyncStatus)) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	fn(&s.status)
}

// handleSyncError records a sync error.
func (s *quicbaasSynchronizer) handleSyncError(err error) {
	s.errorCount.Add(1)
	s.updateSyncStatus(func(status *SyncStatus) {
		status.ErrorCount = int(s.errorCount.Load())
		status.LastError = err
	})
}

// Ensure quicbaasSynchronizer implements OVSSynchronizer
var _ OVSSynchronizer = (*quicbaasSynchronizer)(nil)
