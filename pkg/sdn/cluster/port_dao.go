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

const entityTypePort = "SDNPort"

// PortDAO provides storage operations for PortState entities.
// It implements CRUD operations with optimistic locking for version conflicts.
type PortDAO struct {
	storage        quicbaas.Storage
	logger         *logging.Logger
	requestTimeout time.Duration
	shardID        uint64
}

// PortDAOOption is a functional option for configuring PortDAO.
type PortDAOOption func(*portDAOConfig)

type portDAOConfig struct {
	requestTimeout time.Duration
	shardID        uint64
}

// WithPortRequestTimeout sets the request timeout for DAO operations.
func WithPortRequestTimeout(timeout time.Duration) PortDAOOption {
	return func(c *portDAOConfig) {
		c.requestTimeout = timeout
	}
}

// WithPortShard sets the shard ID for DAO operations.
func WithPortShard(shardID uint64) PortDAOOption {
	return func(c *portDAOConfig) {
		c.shardID = shardID
	}
}

// NewPortDAO creates a new PortDAO instance.
func NewPortDAO(
	storage quicbaas.Storage,
	logger *logging.Logger,
	opts ...PortDAOOption,
) *PortDAO {
	cfg := &portDAOConfig{
		requestTimeout: defaultRequestTimeout,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	return &PortDAO{
		storage:        storage,
		logger:         logger,
		requestTimeout: cfg.requestTimeout,
		shardID:        cfg.shardID,
	}
}

// Create stores a new port in the database.
// Returns ErrPortAlreadyExists if a port with the same ID already exists.
func (d *PortDAO) Create(ctx context.Context, port *PortState) error {
	if port == nil {
		return ErrNilEntity{EntityType: entityTypePort}
	}
	if port.ID == "" {
		return ErrInvalidPortID{PortID: "", Reason: "port ID is required"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := port.EntityID()

	// Check if port already exists
	_, found, err := d.storage.Get(ctx, entityTypePort, entityID, d.shardID)
	if err != nil {
		return ErrOperationFailed{Operation: "create_port_check", Cause: err}
	}
	if found {
		return ErrPortAlreadyExists{PortID: port.ID}
	}

	// Initialize timestamps and version
	now := time.Now()
	port.CreatedAt = now
	port.UpdatedAt = now
	port.Version = 1

	data, err := json.Marshal(port)
	if err != nil {
		return ErrSerializationFailed{EntityType: entityTypePort, Cause: err}
	}

	if err := d.storage.Put(ctx, entityTypePort, entityID, data, d.shardID); err != nil {
		return ErrOperationFailed{Operation: "create_port", Cause: err}
	}

	d.logger.Debug("Port created", "id", port.ID, "name", port.Name, "bridge", port.BridgeID)
	return nil
}

// Get retrieves a port by its ID.
// Returns ErrPortNotFound if the port does not exist.
func (d *PortDAO) Get(ctx context.Context, portID string) (*PortState, error) {
	if portID == "" {
		return nil, ErrInvalidPortID{PortID: "", Reason: "port ID is required"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := hashString(portID)

	data, found, err := d.storage.Get(ctx, entityTypePort, entityID, d.shardID)
	if err != nil {
		return nil, ErrOperationFailed{Operation: "get_port", Cause: err}
	}
	if !found {
		return nil, ErrPortNotFound{PortID: portID}
	}

	var port PortState
	if err := json.Unmarshal(data, &port); err != nil {
		return nil, ErrDeserializationFailed{EntityType: entityTypePort, Cause: err}
	}

	return &port, nil
}

// Update modifies an existing port with optimistic locking.
// Returns ErrPortNotFound if the port does not exist.
// Returns ErrVersionConflict if the expected version does not match.
func (d *PortDAO) Update(
	ctx context.Context,
	portID string,
	updates *PortState,
	expectedVersion uint64,
) error {
	if portID == "" {
		return ErrInvalidPortID{PortID: "", Reason: "port ID is required"}
	}
	if updates == nil {
		return ErrNilEntity{EntityType: entityTypePort}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := hashString(portID)

	// Get current state for version check
	data, found, err := d.storage.Get(ctx, entityTypePort, entityID, d.shardID)
	if err != nil {
		return ErrOperationFailed{Operation: "update_port_get", Cause: err}
	}
	if !found {
		return ErrPortNotFound{PortID: portID}
	}

	var current PortState
	if err := json.Unmarshal(data, &current); err != nil {
		return ErrDeserializationFailed{EntityType: entityTypePort, Cause: err}
	}

	// Check version for optimistic locking
	if current.Version != expectedVersion {
		return ErrVersionConflict{
			EntityType:      entityTypePort,
			EntityID:        portID,
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
		return ErrSerializationFailed{EntityType: entityTypePort, Cause: err}
	}

	if err := d.storage.Put(ctx, entityTypePort, entityID, newData, d.shardID); err != nil {
		return ErrOperationFailed{Operation: "update_port", Cause: err}
	}

	d.logger.Debug("Port updated", "id", portID, "version", updates.Version)
	return nil
}

// Delete removes a port with optimistic locking.
// Returns ErrPortNotFound if the port does not exist.
// Returns ErrVersionConflict if the expected version does not match.
func (d *PortDAO) Delete(ctx context.Context, portID string, expectedVersion uint64) error {
	if portID == "" {
		return ErrInvalidPortID{PortID: "", Reason: "port ID is required"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := hashString(portID)

	// Get current state for version check
	data, found, err := d.storage.Get(ctx, entityTypePort, entityID, d.shardID)
	if err != nil {
		return ErrOperationFailed{Operation: "delete_port_get", Cause: err}
	}
	if !found {
		return ErrPortNotFound{PortID: portID}
	}

	var current PortState
	if err := json.Unmarshal(data, &current); err != nil {
		return ErrDeserializationFailed{EntityType: entityTypePort, Cause: err}
	}

	// Check version for optimistic locking
	if current.Version != expectedVersion {
		return ErrVersionConflict{
			EntityType:      entityTypePort,
			EntityID:        portID,
			ExpectedVersion: expectedVersion,
			ActualVersion:   current.Version,
		}
	}

	if err := d.storage.Delete(ctx, entityTypePort, entityID, d.shardID); err != nil {
		return ErrOperationFailed{Operation: "delete_port", Cause: err}
	}

	d.logger.Debug("Port deleted", "id", portID)
	return nil
}

// List retrieves all ports from the database.
func (d *PortDAO) List(ctx context.Context) ([]*PortState, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	var ports []*PortState
	pageToken := ""

	for {
		entities, nextToken, err := d.storage.List(ctx, entityTypePort, 1000, pageToken, d.shardID)
		if err != nil {
			return nil, ErrOperationFailed{Operation: "list_ports", Cause: err}
		}

		for _, entity := range entities {
			var port PortState
			if err := json.Unmarshal(entity.Data, &port); err != nil {
				d.logger.Warn("Failed to deserialize port", "id", entity.ID, "error", err)
				continue
			}
			ports = append(ports, &port)
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return ports, nil
}

// ListByBridge retrieves all ports attached to a specific bridge.
func (d *PortDAO) ListByBridge(ctx context.Context, bridgeID string) ([]*PortState, error) {
	if bridgeID == "" {
		return nil, ErrInvalidBridgeID{BridgeID: "", Reason: "bridge ID is required"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	var ports []*PortState
	pageToken := ""

	for {
		entities, nextToken, err := d.storage.List(ctx, entityTypePort, 1000, pageToken, d.shardID)
		if err != nil {
			return nil, ErrOperationFailed{Operation: "list_ports_by_bridge", Cause: err}
		}

		for _, entity := range entities {
			var port PortState
			if err := json.Unmarshal(entity.Data, &port); err != nil {
				d.logger.Warn("Failed to deserialize port", "id", entity.ID, "error", err)
				continue
			}
			if port.BridgeID == bridgeID {
				ports = append(ports, &port)
			}
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return ports, nil
}

// ListByNode retrieves all ports owned by a specific node.
func (d *PortDAO) ListByNode(ctx context.Context, nodeID uint64) ([]*PortState, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	var ports []*PortState
	pageToken := ""

	for {
		entities, nextToken, err := d.storage.List(ctx, entityTypePort, 1000, pageToken, d.shardID)
		if err != nil {
			return nil, ErrOperationFailed{Operation: "list_ports_by_node", Cause: err}
		}

		for _, entity := range entities {
			var port PortState
			if err := json.Unmarshal(entity.Data, &port); err != nil {
				d.logger.Warn("Failed to deserialize port", "id", entity.ID, "error", err)
				continue
			}
			if port.NodeID == nodeID {
				ports = append(ports, &port)
			}
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return ports, nil
}

// Count returns the total number of ports.
func (d *PortDAO) Count(ctx context.Context) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	count := 0
	pageToken := ""

	for {
		entities, nextToken, err := d.storage.List(ctx, entityTypePort, 1000, pageToken, d.shardID)
		if err != nil {
			return 0, ErrOperationFailed{Operation: "count_ports", Cause: err}
		}

		count += len(entities)

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return count, nil
}

// Exists checks if a port exists by its ID.
func (d *PortDAO) Exists(ctx context.Context, portID string) (bool, error) {
	if portID == "" {
		return false, ErrInvalidPortID{PortID: "", Reason: "port ID is required"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := hashString(portID)

	_, found, err := d.storage.Get(ctx, entityTypePort, entityID, d.shardID)
	if err != nil {
		return false, ErrOperationFailed{Operation: "exists_port", Cause: err}
	}

	return found, nil
}
