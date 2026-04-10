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
	"encoding/json"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
)

const entityTypeFlow = "SDNFlow"

// FlowDAO provides storage operations for FlowState entities.
// It implements CRUD operations with optimistic locking for version conflicts.
type FlowDAO struct {
	storage        quicbaas.Storage
	logger         *logging.Logger
	requestTimeout time.Duration
	shardID        uint64
}

// FlowDAOOption is a functional option for configuring FlowDAO.
type FlowDAOOption func(*flowDAOConfig)

type flowDAOConfig struct {
	requestTimeout time.Duration
	shardID        uint64
}

// WithFlowRequestTimeout sets the request timeout for DAO operations.
func WithFlowRequestTimeout(timeout time.Duration) FlowDAOOption {
	return func(c *flowDAOConfig) {
		c.requestTimeout = timeout
	}
}

// WithFlowShard sets the shard ID for DAO operations.
func WithFlowShard(shardID uint64) FlowDAOOption {
	return func(c *flowDAOConfig) {
		c.shardID = shardID
	}
}

// NewFlowDAO creates a new FlowDAO instance.
func NewFlowDAO(
	storage quicbaas.Storage,
	logger *logging.Logger,
	opts ...FlowDAOOption,
) *FlowDAO {
	cfg := &flowDAOConfig{
		requestTimeout: defaultRequestTimeout,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	return &FlowDAO{
		storage:        storage,
		logger:         logger,
		requestTimeout: cfg.requestTimeout,
		shardID:        cfg.shardID,
	}
}

// Create stores a new flow in the database.
// Returns ErrFlowAlreadyExists if a flow with the same ID already exists.
func (d *FlowDAO) Create(ctx context.Context, flow *FlowState) error {
	if flow == nil {
		return ErrNilEntity{EntityType: entityTypeFlow}
	}
	if flow.ID == "" {
		return ErrInvalidFlowID{FlowID: "", Reason: "flow ID is required"}
	}
	if flow.BridgeID == "" {
		return ErrInvalidBridgeID{BridgeID: "", Reason: "bridge ID is required for flow"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := flow.EntityID()

	// Check if flow already exists
	_, found, err := d.storage.Get(ctx, entityTypeFlow, entityID, d.shardID)
	if err != nil {
		return ErrOperationFailed{Operation: "create_flow_check", Cause: err}
	}
	if found {
		return ErrFlowAlreadyExists{BridgeID: flow.BridgeID, FlowID: flow.ID}
	}

	// Initialize timestamps and version
	now := time.Now()
	flow.CreatedAt = now
	flow.UpdatedAt = now
	flow.Version = 1

	data, err := json.Marshal(flow)
	if err != nil {
		return ErrSerializationFailed{EntityType: entityTypeFlow, Cause: err}
	}

	if err := d.storage.Put(ctx, entityTypeFlow, entityID, data, d.shardID); err != nil {
		return ErrOperationFailed{Operation: "create_flow", Cause: err}
	}

	d.logger.Debug("Flow created", "id", flow.ID, "bridge", flow.BridgeID, "table", flow.Table, "priority", flow.Priority)
	return nil
}

// Get retrieves a flow by its bridge ID and flow ID.
// Returns ErrFlowNotFound if the flow does not exist.
func (d *FlowDAO) Get(ctx context.Context, bridgeID, flowID string) (*FlowState, error) {
	if flowID == "" {
		return nil, ErrInvalidFlowID{FlowID: "", Reason: "flow ID is required"}
	}
	if bridgeID == "" {
		return nil, ErrInvalidBridgeID{BridgeID: "", Reason: "bridge ID is required"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := hashString(flowID)

	data, found, err := d.storage.Get(ctx, entityTypeFlow, entityID, d.shardID)
	if err != nil {
		return nil, ErrOperationFailed{Operation: "get_flow", Cause: err}
	}
	if !found {
		return nil, ErrFlowNotFound{BridgeID: bridgeID, FlowID: flowID}
	}

	var flow FlowState
	if err := json.Unmarshal(data, &flow); err != nil {
		return nil, ErrDeserializationFailed{EntityType: entityTypeFlow, Cause: err}
	}

	// Verify the flow belongs to the expected bridge
	if flow.BridgeID != bridgeID {
		return nil, ErrFlowNotFound{BridgeID: bridgeID, FlowID: flowID}
	}

	return &flow, nil
}

// Update modifies an existing flow with optimistic locking.
// Returns ErrFlowNotFound if the flow does not exist.
// Returns ErrVersionConflict if the expected version does not match.
func (d *FlowDAO) Update(
	ctx context.Context,
	bridgeID, flowID string,
	updates *FlowState,
	expectedVersion uint64,
) error {
	if flowID == "" {
		return ErrInvalidFlowID{FlowID: "", Reason: "flow ID is required"}
	}
	if bridgeID == "" {
		return ErrInvalidBridgeID{BridgeID: "", Reason: "bridge ID is required"}
	}
	if updates == nil {
		return ErrNilEntity{EntityType: entityTypeFlow}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := hashString(flowID)

	// Get current state for version check
	data, found, err := d.storage.Get(ctx, entityTypeFlow, entityID, d.shardID)
	if err != nil {
		return ErrOperationFailed{Operation: "update_flow_get", Cause: err}
	}
	if !found {
		return ErrFlowNotFound{BridgeID: bridgeID, FlowID: flowID}
	}

	var current FlowState
	if err := json.Unmarshal(data, &current); err != nil {
		return ErrDeserializationFailed{EntityType: entityTypeFlow, Cause: err}
	}

	// Verify the flow belongs to the expected bridge
	if current.BridgeID != bridgeID {
		return ErrFlowNotFound{BridgeID: bridgeID, FlowID: flowID}
	}

	// Check version for optimistic locking
	if current.Version != expectedVersion {
		return ErrVersionConflict{
			EntityType:      entityTypeFlow,
			EntityID:        flowID,
			ExpectedVersion: expectedVersion,
			ActualVersion:   current.Version,
		}
	}

	// Apply updates while preserving immutable fields
	updates.ID = current.ID
	updates.BridgeID = current.BridgeID
	updates.CreatedAt = current.CreatedAt
	updates.UpdatedAt = time.Now()
	updates.Version = current.Version + 1

	newData, err := json.Marshal(updates)
	if err != nil {
		return ErrSerializationFailed{EntityType: entityTypeFlow, Cause: err}
	}

	if err := d.storage.Put(ctx, entityTypeFlow, entityID, newData, d.shardID); err != nil {
		return ErrOperationFailed{Operation: "update_flow", Cause: err}
	}

	d.logger.Debug("Flow updated", "id", flowID, "bridge", bridgeID, "version", updates.Version)
	return nil
}

// Delete removes a flow with optimistic locking.
// Returns ErrFlowNotFound if the flow does not exist.
// Returns ErrVersionConflict if the expected version does not match.
func (d *FlowDAO) Delete(ctx context.Context, bridgeID, flowID string, expectedVersion uint64) error {
	if flowID == "" {
		return ErrInvalidFlowID{FlowID: "", Reason: "flow ID is required"}
	}
	if bridgeID == "" {
		return ErrInvalidBridgeID{BridgeID: "", Reason: "bridge ID is required"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := hashString(flowID)

	// Get current state for version check
	data, found, err := d.storage.Get(ctx, entityTypeFlow, entityID, d.shardID)
	if err != nil {
		return ErrOperationFailed{Operation: "delete_flow_get", Cause: err}
	}
	if !found {
		return ErrFlowNotFound{BridgeID: bridgeID, FlowID: flowID}
	}

	var current FlowState
	if err := json.Unmarshal(data, &current); err != nil {
		return ErrDeserializationFailed{EntityType: entityTypeFlow, Cause: err}
	}

	// Verify the flow belongs to the expected bridge
	if current.BridgeID != bridgeID {
		return ErrFlowNotFound{BridgeID: bridgeID, FlowID: flowID}
	}

	// Check version for optimistic locking
	if current.Version != expectedVersion {
		return ErrVersionConflict{
			EntityType:      entityTypeFlow,
			EntityID:        flowID,
			ExpectedVersion: expectedVersion,
			ActualVersion:   current.Version,
		}
	}

	if err := d.storage.Delete(ctx, entityTypeFlow, entityID, d.shardID); err != nil {
		return ErrOperationFailed{Operation: "delete_flow", Cause: err}
	}

	d.logger.Debug("Flow deleted", "id", flowID, "bridge", bridgeID)
	return nil
}

// List retrieves all flows from the database.
func (d *FlowDAO) List(ctx context.Context) ([]*FlowState, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	var flows []*FlowState
	pageToken := ""

	for {
		entities, nextToken, err := d.storage.List(ctx, entityTypeFlow, 1000, pageToken, d.shardID)
		if err != nil {
			return nil, ErrOperationFailed{Operation: "list_flows", Cause: err}
		}

		for _, entity := range entities {
			var flow FlowState
			if err := json.Unmarshal(entity.Data, &flow); err != nil {
				d.logger.Warn("Failed to deserialize flow", "id", entity.ID, "error", err)
				continue
			}
			flows = append(flows, &flow)
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return flows, nil
}

// ListByBridge retrieves all flows for a specific bridge.
func (d *FlowDAO) ListByBridge(ctx context.Context, bridgeID string) ([]*FlowState, error) {
	if bridgeID == "" {
		return nil, ErrInvalidBridgeID{BridgeID: "", Reason: "bridge ID is required"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	var flows []*FlowState
	pageToken := ""

	for {
		entities, nextToken, err := d.storage.List(ctx, entityTypeFlow, 1000, pageToken, d.shardID)
		if err != nil {
			return nil, ErrOperationFailed{Operation: "list_flows_by_bridge", Cause: err}
		}

		for _, entity := range entities {
			var flow FlowState
			if err := json.Unmarshal(entity.Data, &flow); err != nil {
				d.logger.Warn("Failed to deserialize flow", "id", entity.ID, "error", err)
				continue
			}
			if flow.BridgeID == bridgeID {
				flows = append(flows, &flow)
			}
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return flows, nil
}

// ListByBridgeAndTable retrieves all flows for a specific bridge and table number.
func (d *FlowDAO) ListByBridgeAndTable(ctx context.Context, bridgeID string, table uint8) ([]*FlowState, error) {
	if bridgeID == "" {
		return nil, ErrInvalidBridgeID{BridgeID: "", Reason: "bridge ID is required"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	var flows []*FlowState
	pageToken := ""

	for {
		entities, nextToken, err := d.storage.List(ctx, entityTypeFlow, 1000, pageToken, d.shardID)
		if err != nil {
			return nil, ErrOperationFailed{Operation: "list_flows_by_table", Cause: err}
		}

		for _, entity := range entities {
			var flow FlowState
			if err := json.Unmarshal(entity.Data, &flow); err != nil {
				d.logger.Warn("Failed to deserialize flow", "id", entity.ID, "error", err)
				continue
			}
			if flow.BridgeID == bridgeID && flow.Table == table {
				flows = append(flows, &flow)
			}
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return flows, nil
}

// Count returns the total number of flows.
func (d *FlowDAO) Count(ctx context.Context) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	count := 0
	pageToken := ""

	for {
		entities, nextToken, err := d.storage.List(ctx, entityTypeFlow, 1000, pageToken, d.shardID)
		if err != nil {
			return 0, ErrOperationFailed{Operation: "count_flows", Cause: err}
		}

		count += len(entities)

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return count, nil
}

// CountByBridge returns the number of flows for a specific bridge.
func (d *FlowDAO) CountByBridge(ctx context.Context, bridgeID string) (int, error) {
	if bridgeID == "" {
		return 0, ErrInvalidBridgeID{BridgeID: "", Reason: "bridge ID is required"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	count := 0
	pageToken := ""

	for {
		entities, nextToken, err := d.storage.List(ctx, entityTypeFlow, 1000, pageToken, d.shardID)
		if err != nil {
			return 0, ErrOperationFailed{Operation: "count_flows_by_bridge", Cause: err}
		}

		for _, entity := range entities {
			var flow FlowState
			if err := json.Unmarshal(entity.Data, &flow); err != nil {
				continue
			}
			if flow.BridgeID == bridgeID {
				count++
			}
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return count, nil
}

// Exists checks if a flow exists by its bridge ID and flow ID.
func (d *FlowDAO) Exists(ctx context.Context, bridgeID, flowID string) (bool, error) {
	if flowID == "" {
		return false, ErrInvalidFlowID{FlowID: "", Reason: "flow ID is required"}
	}
	if bridgeID == "" {
		return false, ErrInvalidBridgeID{BridgeID: "", Reason: "bridge ID is required"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := hashString(flowID)

	data, found, err := d.storage.Get(ctx, entityTypeFlow, entityID, d.shardID)
	if err != nil {
		return false, ErrOperationFailed{Operation: "exists_flow", Cause: err}
	}
	if !found {
		return false, nil
	}

	// Verify the flow belongs to the expected bridge
	var flow FlowState
	if err := json.Unmarshal(data, &flow); err != nil {
		return false, ErrDeserializationFailed{EntityType: entityTypeFlow, Cause: err}
	}

	return flow.BridgeID == bridgeID, nil
}
