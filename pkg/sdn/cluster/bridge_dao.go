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

const (
	entityTypeBridge = "SDNBridge"

	// defaultRequestTimeout is the default timeout for DAO operations.
	defaultRequestTimeout = 30 * time.Second
)

// BridgeDAO provides storage operations for BridgeState entities.
// It implements CRUD operations with optimistic locking for version conflicts.
type BridgeDAO struct {
	storage        quicbaas.Storage
	logger         *logging.Logger
	requestTimeout time.Duration
	shardID        uint64
}

// BridgeDAOOption is a functional option for configuring BridgeDAO.
type BridgeDAOOption func(*bridgeDAOConfig)

type bridgeDAOConfig struct {
	requestTimeout time.Duration
	shardID        uint64
}

// WithBridgeRequestTimeout sets the request timeout for DAO operations.
func WithBridgeRequestTimeout(timeout time.Duration) BridgeDAOOption {
	return func(c *bridgeDAOConfig) {
		c.requestTimeout = timeout
	}
}

// WithBridgeShard sets the shard ID for DAO operations.
func WithBridgeShard(shardID uint64) BridgeDAOOption {
	return func(c *bridgeDAOConfig) {
		c.shardID = shardID
	}
}

// NewBridgeDAO creates a new BridgeDAO instance.
func NewBridgeDAO(
	storage quicbaas.Storage,
	logger *logging.Logger,
	opts ...BridgeDAOOption,
) *BridgeDAO {
	cfg := &bridgeDAOConfig{
		requestTimeout: defaultRequestTimeout,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	return &BridgeDAO{
		storage:        storage,
		logger:         logger,
		requestTimeout: cfg.requestTimeout,
		shardID:        cfg.shardID,
	}
}

// Create stores a new bridge in the database.
// Returns ErrBridgeAlreadyExists if a bridge with the same ID already exists.
func (d *BridgeDAO) Create(ctx context.Context, bridge *BridgeState) error {
	if bridge == nil {
		return ErrNilEntity{EntityType: entityTypeBridge}
	}
	if bridge.ID == "" {
		return ErrInvalidBridgeID{BridgeID: "", Reason: "bridge ID is required"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := bridge.EntityID()

	// Check if bridge already exists
	_, found, err := d.storage.Get(ctx, entityTypeBridge, entityID, d.shardID)
	if err != nil {
		return ErrOperationFailed{Operation: "create_bridge_check", Cause: err}
	}
	if found {
		return ErrBridgeAlreadyExists{BridgeID: bridge.ID}
	}

	// Initialize timestamps and version
	now := time.Now()
	bridge.CreatedAt = now
	bridge.UpdatedAt = now
	bridge.Version = 1

	data, err := json.Marshal(bridge)
	if err != nil {
		return ErrSerializationFailed{EntityType: entityTypeBridge, Cause: err}
	}

	if err := d.storage.Put(ctx, entityTypeBridge, entityID, data, d.shardID); err != nil {
		return ErrOperationFailed{Operation: "create_bridge", Cause: err}
	}

	d.logger.Debug("Bridge created", "id", bridge.ID, "name", bridge.Name)
	return nil
}

// Get retrieves a bridge by its ID.
// Returns ErrBridgeNotFound if the bridge does not exist.
func (d *BridgeDAO) Get(ctx context.Context, bridgeID string) (*BridgeState, error) {
	if bridgeID == "" {
		return nil, ErrInvalidBridgeID{BridgeID: "", Reason: "bridge ID is required"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := hashString(bridgeID)

	data, found, err := d.storage.Get(ctx, entityTypeBridge, entityID, d.shardID)
	if err != nil {
		return nil, ErrOperationFailed{Operation: "get_bridge", Cause: err}
	}
	if !found {
		return nil, ErrBridgeNotFound{BridgeID: bridgeID}
	}

	var bridge BridgeState
	if err := json.Unmarshal(data, &bridge); err != nil {
		return nil, ErrDeserializationFailed{EntityType: entityTypeBridge, Cause: err}
	}

	return &bridge, nil
}

// Update modifies an existing bridge with optimistic locking.
// Returns ErrBridgeNotFound if the bridge does not exist.
// Returns ErrVersionConflict if the expected version does not match.
func (d *BridgeDAO) Update(
	ctx context.Context,
	bridgeID string,
	updates *BridgeState,
	expectedVersion uint64,
) error {
	if bridgeID == "" {
		return ErrInvalidBridgeID{BridgeID: "", Reason: "bridge ID is required"}
	}
	if updates == nil {
		return ErrNilEntity{EntityType: entityTypeBridge}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := hashString(bridgeID)

	// Get current state for version check
	data, found, err := d.storage.Get(ctx, entityTypeBridge, entityID, d.shardID)
	if err != nil {
		return ErrOperationFailed{Operation: "update_bridge_get", Cause: err}
	}
	if !found {
		return ErrBridgeNotFound{BridgeID: bridgeID}
	}

	var current BridgeState
	if err := json.Unmarshal(data, &current); err != nil {
		return ErrDeserializationFailed{EntityType: entityTypeBridge, Cause: err}
	}

	// Check version for optimistic locking
	if current.Version != expectedVersion {
		return ErrVersionConflict{
			EntityType:      entityTypeBridge,
			EntityID:        bridgeID,
			ExpectedVersion: expectedVersion,
			ActualVersion:   current.Version,
		}
	}

	// Apply updates while preserving immutable fields
	updates.ID = current.ID
	updates.CreatedAt = current.CreatedAt
	updates.UpdatedAt = time.Now()
	updates.Version = current.Version + 1

	newData, err := json.Marshal(updates)
	if err != nil {
		return ErrSerializationFailed{EntityType: entityTypeBridge, Cause: err}
	}

	if err := d.storage.Put(ctx, entityTypeBridge, entityID, newData, d.shardID); err != nil {
		return ErrOperationFailed{Operation: "update_bridge", Cause: err}
	}

	d.logger.Debug("Bridge updated", "id", bridgeID, "version", updates.Version)
	return nil
}

// Delete removes a bridge with optimistic locking.
// Returns ErrBridgeNotFound if the bridge does not exist.
// Returns ErrVersionConflict if the expected version does not match.
func (d *BridgeDAO) Delete(ctx context.Context, bridgeID string, expectedVersion uint64) error {
	if bridgeID == "" {
		return ErrInvalidBridgeID{BridgeID: "", Reason: "bridge ID is required"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := hashString(bridgeID)

	// Get current state for version check
	data, found, err := d.storage.Get(ctx, entityTypeBridge, entityID, d.shardID)
	if err != nil {
		return ErrOperationFailed{Operation: "delete_bridge_get", Cause: err}
	}
	if !found {
		return ErrBridgeNotFound{BridgeID: bridgeID}
	}

	var current BridgeState
	if err := json.Unmarshal(data, &current); err != nil {
		return ErrDeserializationFailed{EntityType: entityTypeBridge, Cause: err}
	}

	// Check version for optimistic locking
	if current.Version != expectedVersion {
		return ErrVersionConflict{
			EntityType:      entityTypeBridge,
			EntityID:        bridgeID,
			ExpectedVersion: expectedVersion,
			ActualVersion:   current.Version,
		}
	}

	if err := d.storage.Delete(ctx, entityTypeBridge, entityID, d.shardID); err != nil {
		return ErrOperationFailed{Operation: "delete_bridge", Cause: err}
	}

	d.logger.Debug("Bridge deleted", "id", bridgeID)
	return nil
}

// List retrieves all bridges from the database.
func (d *BridgeDAO) List(ctx context.Context) ([]*BridgeState, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	var bridges []*BridgeState
	pageToken := ""

	for {
		entities, nextToken, err := d.storage.List(ctx, entityTypeBridge, 1000, pageToken, d.shardID)
		if err != nil {
			return nil, ErrOperationFailed{Operation: "list_bridges", Cause: err}
		}

		for _, entity := range entities {
			var bridge BridgeState
			if err := json.Unmarshal(entity.Data, &bridge); err != nil {
				d.logger.Warn("Failed to deserialize bridge", "id", entity.ID, "error", err)
				continue
			}
			bridges = append(bridges, &bridge)
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return bridges, nil
}

// ListByNode retrieves all bridges owned by a specific node.
func (d *BridgeDAO) ListByNode(ctx context.Context, nodeID uint64) ([]*BridgeState, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	var bridges []*BridgeState
	pageToken := ""

	for {
		entities, nextToken, err := d.storage.List(ctx, entityTypeBridge, 1000, pageToken, d.shardID)
		if err != nil {
			return nil, ErrOperationFailed{Operation: "list_bridges_by_node", Cause: err}
		}

		for _, entity := range entities {
			var bridge BridgeState
			if err := json.Unmarshal(entity.Data, &bridge); err != nil {
				d.logger.Warn("Failed to deserialize bridge", "id", entity.ID, "error", err)
				continue
			}
			if bridge.NodeID == nodeID {
				bridges = append(bridges, &bridge)
			}
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return bridges, nil
}

// Count returns the total number of bridges.
func (d *BridgeDAO) Count(ctx context.Context) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	count := 0
	pageToken := ""

	for {
		entities, nextToken, err := d.storage.List(ctx, entityTypeBridge, 1000, pageToken, d.shardID)
		if err != nil {
			return 0, ErrOperationFailed{Operation: "count_bridges", Cause: err}
		}

		count += len(entities)

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return count, nil
}

// Exists checks if a bridge exists by its ID.
func (d *BridgeDAO) Exists(ctx context.Context, bridgeID string) (bool, error) {
	if bridgeID == "" {
		return false, ErrInvalidBridgeID{BridgeID: "", Reason: "bridge ID is required"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := hashString(bridgeID)

	_, found, err := d.storage.Get(ctx, entityTypeBridge, entityID, d.shardID)
	if err != nil {
		return false, ErrOperationFailed{Operation: "exists_bridge", Cause: err}
	}

	return found, nil
}
