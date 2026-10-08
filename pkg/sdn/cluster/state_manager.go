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
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
)

// QuicBaaSStateManager implements the StateManager interface using QuicBaaS.
// It coordinates all entity DAOs and provides a unified API for SDN state management.
type QuicBaaSStateManager struct {
	storage   quicbaas.Storage
	logger    *logging.Logger
	bridgeDAO *BridgeDAO
	portDAO   *PortDAO
	flowDAO   *FlowDAO
	vlanDAO   *VLANDAO
}

// StateManagerOption is a functional option for configuring QuicBaaSStateManager.
type StateManagerOption func(*stateManagerConfig)

type stateManagerConfig struct {
	requestTimeout time.Duration
}

// WithStateManagerTimeout sets the request timeout for all DAO operations.
func WithStateManagerTimeout(timeout time.Duration) StateManagerOption {
	return func(c *stateManagerConfig) {
		c.requestTimeout = timeout
	}
}

// NewQuicBaaSStateManager creates a new QuicBaaSStateManager instance.
func NewQuicBaaSStateManager(
	storage quicbaas.Storage,
	logger *logging.Logger,
	opts ...StateManagerOption,
) *QuicBaaSStateManager {
	cfg := &stateManagerConfig{
		requestTimeout: defaultRequestTimeout,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	return &QuicBaaSStateManager{
		storage:   storage,
		logger:    logger,
		bridgeDAO: NewBridgeDAO(storage, logger, WithBridgeRequestTimeout(cfg.requestTimeout)),
		portDAO:   NewPortDAO(storage, logger, WithPortRequestTimeout(cfg.requestTimeout)),
		flowDAO:   NewFlowDAO(storage, logger, WithFlowRequestTimeout(cfg.requestTimeout)),
		vlanDAO:   NewVLANDAO(storage, logger, WithVLANRequestTimeout(cfg.requestTimeout)),
	}
}

// BridgeDAO returns the underlying bridge DAO for direct access if needed.
func (sm *QuicBaaSStateManager) BridgeDAO() *BridgeDAO {
	return sm.bridgeDAO
}

// PortDAO returns the underlying port DAO for direct access if needed.
func (sm *QuicBaaSStateManager) PortDAO() *PortDAO {
	return sm.portDAO
}

// FlowDAO returns the underlying flow DAO for direct access if needed.
func (sm *QuicBaaSStateManager) FlowDAO() *FlowDAO {
	return sm.flowDAO
}

// VLANDAO returns the underlying VLAN DAO for direct access if needed.
func (sm *QuicBaaSStateManager) VLANDAO() *VLANDAO {
	return sm.vlanDAO
}

// Bridge operations

// CreateBridge creates a new bridge in the cluster state.
func (sm *QuicBaaSStateManager) CreateBridge(ctx context.Context, bridge *BridgeState) error {
	return sm.bridgeDAO.Create(ctx, bridge)
}

// UpdateBridge updates an existing bridge with optimistic locking.
func (sm *QuicBaaSStateManager) UpdateBridge(
	ctx context.Context,
	bridgeID string,
	updates *BridgeState,
	expectedVersion uint64,
) error {
	return sm.bridgeDAO.Update(ctx, bridgeID, updates, expectedVersion)
}

// DeleteBridge deletes a bridge with optimistic locking.
// This also deletes all associated ports and flows.
func (sm *QuicBaaSStateManager) DeleteBridge(ctx context.Context, bridgeID string, expectedVersion uint64) error {
	// First verify the bridge exists and get its current state
	bridge, err := sm.bridgeDAO.Get(ctx, bridgeID)
	if err != nil {
		return err
	}

	// Check version before cascading deletes
	if bridge.Version != expectedVersion {
		return ErrVersionConflict{
			EntityType:      entityTypeBridge,
			EntityID:        bridgeID,
			ExpectedVersion: expectedVersion,
			ActualVersion:   bridge.Version,
		}
	}

	// Delete all associated flows
	flows, err := sm.flowDAO.ListByBridge(ctx, bridgeID)
	if err != nil {
		return err
	}
	for _, flow := range flows {
		if delErr := sm.flowDAO.Delete(ctx, bridgeID, flow.ID, flow.Version); delErr != nil {
			sm.logger.Warn("Failed to delete flow during bridge deletion",
				"bridge", bridgeID, "flow", flow.ID, "error", delErr)
		}
	}

	// Delete all associated ports
	ports, err := sm.portDAO.ListByBridge(ctx, bridgeID)
	if err != nil {
		return err
	}
	for _, port := range ports {
		if delErr := sm.portDAO.Delete(ctx, port.ID, port.Version); delErr != nil {
			sm.logger.Warn("Failed to delete port during bridge deletion",
				"bridge", bridgeID, "port", port.ID, "error", delErr)
		}
	}

	// Finally delete the bridge
	return sm.bridgeDAO.Delete(ctx, bridgeID, expectedVersion)
}

// GetBridge retrieves a bridge by its ID.
func (sm *QuicBaaSStateManager) GetBridge(ctx context.Context, bridgeID string) (*BridgeState, error) {
	return sm.bridgeDAO.Get(ctx, bridgeID)
}

// ListBridges retrieves all bridges in the cluster state.
func (sm *QuicBaaSStateManager) ListBridges(ctx context.Context) ([]*BridgeState, error) {
	return sm.bridgeDAO.List(ctx)
}

// Port operations

// CreatePort creates a new port in the cluster state.
func (sm *QuicBaaSStateManager) CreatePort(ctx context.Context, port *PortState) error {
	// Verify the bridge exists
	if port != nil && port.BridgeID != "" {
		exists, err := sm.bridgeDAO.Exists(ctx, port.BridgeID)
		if err != nil {
			return err
		}
		if !exists {
			return ErrBridgeNotFound{BridgeID: port.BridgeID}
		}
	}

	return sm.portDAO.Create(ctx, port)
}

// UpdatePort updates an existing port with optimistic locking.
func (sm *QuicBaaSStateManager) UpdatePort(
	ctx context.Context,
	portID string,
	updates *PortState,
	expectedVersion uint64,
) error {
	return sm.portDAO.Update(ctx, portID, updates, expectedVersion)
}

// DeletePort deletes a port with optimistic locking.
func (sm *QuicBaaSStateManager) DeletePort(ctx context.Context, portID string, expectedVersion uint64) error {
	return sm.portDAO.Delete(ctx, portID, expectedVersion)
}

// GetPort retrieves a port by its ID.
func (sm *QuicBaaSStateManager) GetPort(ctx context.Context, portID string) (*PortState, error) {
	return sm.portDAO.Get(ctx, portID)
}

// ListPorts retrieves all ports for a specific bridge.
func (sm *QuicBaaSStateManager) ListPorts(ctx context.Context, bridgeID string) ([]*PortState, error) {
	return sm.portDAO.ListByBridge(ctx, bridgeID)
}

// Flow operations

// CreateFlow creates a new flow in the cluster state.
func (sm *QuicBaaSStateManager) CreateFlow(ctx context.Context, flow *FlowState) error {
	// Verify the bridge exists
	if flow != nil && flow.BridgeID != "" {
		exists, err := sm.bridgeDAO.Exists(ctx, flow.BridgeID)
		if err != nil {
			return err
		}
		if !exists {
			return ErrBridgeNotFound{BridgeID: flow.BridgeID}
		}
	}

	return sm.flowDAO.Create(ctx, flow)
}

// UpdateFlow updates an existing flow with optimistic locking.
func (sm *QuicBaaSStateManager) UpdateFlow(
	ctx context.Context,
	bridgeID, flowID string,
	updates *FlowState,
	expectedVersion uint64,
) error {
	return sm.flowDAO.Update(ctx, bridgeID, flowID, updates, expectedVersion)
}

// DeleteFlow deletes a flow with optimistic locking.
func (sm *QuicBaaSStateManager) DeleteFlow(
	ctx context.Context,
	bridgeID, flowID string,
	expectedVersion uint64,
) error {
	return sm.flowDAO.Delete(ctx, bridgeID, flowID, expectedVersion)
}

// GetFlow retrieves a flow by its bridge ID and flow ID.
func (sm *QuicBaaSStateManager) GetFlow(ctx context.Context, bridgeID, flowID string) (*FlowState, error) {
	return sm.flowDAO.Get(ctx, bridgeID, flowID)
}

// ListFlows retrieves all flows for a specific bridge.
func (sm *QuicBaaSStateManager) ListFlows(ctx context.Context, bridgeID string) ([]*FlowState, error) {
	return sm.flowDAO.ListByBridge(ctx, bridgeID)
}

// VLAN operations

// CreateVLAN creates a new VLAN in the cluster state.
func (sm *QuicBaaSStateManager) CreateVLAN(ctx context.Context, vlan *VLANState) error {
	return sm.vlanDAO.Create(ctx, vlan)
}

// UpdateVLAN updates an existing VLAN with optimistic locking.
func (sm *QuicBaaSStateManager) UpdateVLAN(
	ctx context.Context,
	vlanID uint16,
	updates *VLANState,
	expectedVersion uint64,
) error {
	return sm.vlanDAO.Update(ctx, vlanID, updates, expectedVersion)
}

// DeleteVLAN deletes a VLAN with optimistic locking.
func (sm *QuicBaaSStateManager) DeleteVLAN(ctx context.Context, vlanID uint16, expectedVersion uint64) error {
	return sm.vlanDAO.Delete(ctx, vlanID, expectedVersion)
}

// GetVLAN retrieves a VLAN by its ID.
func (sm *QuicBaaSStateManager) GetVLAN(ctx context.Context, vlanID uint16) (*VLANState, error) {
	return sm.vlanDAO.Get(ctx, vlanID)
}

// ListVLANs retrieves all VLANs in the cluster state.
func (sm *QuicBaaSStateManager) ListVLANs(ctx context.Context) ([]*VLANState, error) {
	return sm.vlanDAO.List(ctx)
}

// Query operations

// GetBridgeWithPorts retrieves a bridge and all its associated ports.
func (sm *QuicBaaSStateManager) GetBridgeWithPorts(ctx context.Context, bridgeID string) (*BridgeState, []*PortState, error) {
	bridge, err := sm.bridgeDAO.Get(ctx, bridgeID)
	if err != nil {
		return nil, nil, err
	}

	ports, err := sm.portDAO.ListByBridge(ctx, bridgeID)
	if err != nil {
		return bridge, nil, err
	}

	return bridge, ports, nil
}

// GetBridgeWithFlows retrieves a bridge and all its associated flows.
func (sm *QuicBaaSStateManager) GetBridgeWithFlows(ctx context.Context, bridgeID string) (*BridgeState, []*FlowState, error) {
	bridge, err := sm.bridgeDAO.Get(ctx, bridgeID)
	if err != nil {
		return nil, nil, err
	}

	flows, err := sm.flowDAO.ListByBridge(ctx, bridgeID)
	if err != nil {
		return bridge, nil, err
	}

	return bridge, flows, nil
}

// GetFullBridgeState retrieves a bridge with all associated ports and flows.
func (sm *QuicBaaSStateManager) GetFullBridgeState(ctx context.Context, bridgeID string) (*BridgeState, []*PortState, []*FlowState, error) {
	bridge, err := sm.bridgeDAO.Get(ctx, bridgeID)
	if err != nil {
		return nil, nil, nil, err
	}

	ports, err := sm.portDAO.ListByBridge(ctx, bridgeID)
	if err != nil {
		return bridge, nil, nil, err
	}

	flows, err := sm.flowDAO.ListByBridge(ctx, bridgeID)
	if err != nil {
		return bridge, ports, nil, err
	}

	return bridge, ports, flows, nil
}

// Statistics operations

// GetStatistics returns statistics about the SDN state.
func (sm *QuicBaaSStateManager) GetStatistics(ctx context.Context) (*SDNStatistics, error) {
	bridgeCount, err := sm.bridgeDAO.Count(ctx)
	if err != nil {
		return nil, err
	}

	portCount, err := sm.portDAO.Count(ctx)
	if err != nil {
		return nil, err
	}

	flowCount, err := sm.flowDAO.Count(ctx)
	if err != nil {
		return nil, err
	}

	vlanCount, err := sm.vlanDAO.Count(ctx)
	if err != nil {
		return nil, err
	}

	return &SDNStatistics{
		BridgeCount: bridgeCount,
		PortCount:   portCount,
		FlowCount:   flowCount,
		VLANCount:   vlanCount,
	}, nil
}

// SDNStatistics holds statistics about the SDN state.
type SDNStatistics struct {
	BridgeCount int `json:"bridge_count"`
	PortCount   int `json:"port_count"`
	FlowCount   int `json:"flow_count"`
	VLANCount   int `json:"vlan_count"`
}

// Ensure QuicBaaSStateManager implements StateManager
var _ StateManager = (*QuicBaaSStateManager)(nil)
