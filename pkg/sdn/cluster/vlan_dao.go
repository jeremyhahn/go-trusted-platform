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

const entityTypeVLAN = "SDNVLAN"

// VLANDAO provides storage operations for VLANState entities.
// It implements CRUD operations with optimistic locking for version conflicts.
type VLANDAO struct {
	storage        quicbaas.Storage
	logger         *logging.Logger
	requestTimeout time.Duration
	shardID        uint64
}

// VLANDAOOption is a functional option for configuring VLANDAO.
type VLANDAOOption func(*vlanDAOConfig)

type vlanDAOConfig struct {
	requestTimeout time.Duration
	shardID        uint64
}

// WithVLANRequestTimeout sets the request timeout for DAO operations.
func WithVLANRequestTimeout(timeout time.Duration) VLANDAOOption {
	return func(c *vlanDAOConfig) {
		c.requestTimeout = timeout
	}
}

// WithVLANShard sets the shard ID for DAO operations.
func WithVLANShard(shardID uint64) VLANDAOOption {
	return func(c *vlanDAOConfig) {
		c.shardID = shardID
	}
}

// NewVLANDAO creates a new VLANDAO instance.
func NewVLANDAO(
	storage quicbaas.Storage,
	logger *logging.Logger,
	opts ...VLANDAOOption,
) *VLANDAO {
	cfg := &vlanDAOConfig{
		requestTimeout: defaultRequestTimeout,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	return &VLANDAO{
		storage:        storage,
		logger:         logger,
		requestTimeout: cfg.requestTimeout,
		shardID:        cfg.shardID,
	}
}

// Create stores a new VLAN in the database.
// Returns ErrVLANAlreadyExists if a VLAN with the same ID already exists.
func (d *VLANDAO) Create(ctx context.Context, vlan *VLANState) error {
	if vlan == nil {
		return ErrNilEntity{EntityType: entityTypeVLAN}
	}
	if vlan.ID < 1 || vlan.ID > 4094 {
		return ErrInvalidVLANID{VLANID: vlan.ID, Reason: "VLAN ID must be 1-4094"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := vlan.EntityID()

	// Check if VLAN already exists
	_, found, err := d.storage.Get(ctx, entityTypeVLAN, entityID, d.shardID)
	if err != nil {
		return ErrOperationFailed{Operation: "create_vlan_check", Cause: err}
	}
	if found {
		return ErrVLANAlreadyExists{VLANID: vlan.ID}
	}

	// Initialize timestamps and version
	now := time.Now()
	vlan.CreatedAt = now
	vlan.UpdatedAt = now
	vlan.Version = 1

	data, err := json.Marshal(vlan)
	if err != nil {
		return ErrSerializationFailed{EntityType: entityTypeVLAN, Cause: err}
	}

	if err := d.storage.Put(ctx, entityTypeVLAN, entityID, data, d.shardID); err != nil {
		return ErrOperationFailed{Operation: "create_vlan", Cause: err}
	}

	d.logger.Debug("VLAN created", "id", vlan.ID, "name", vlan.Name)
	return nil
}

// Get retrieves a VLAN by its ID.
// Returns ErrVLANNotFound if the VLAN does not exist.
func (d *VLANDAO) Get(ctx context.Context, vlanID uint16) (*VLANState, error) {
	if vlanID < 1 || vlanID > 4094 {
		return nil, ErrInvalidVLANID{VLANID: vlanID, Reason: "VLAN ID must be 1-4094"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := uint64(vlanID)

	data, found, err := d.storage.Get(ctx, entityTypeVLAN, entityID, d.shardID)
	if err != nil {
		return nil, ErrOperationFailed{Operation: "get_vlan", Cause: err}
	}
	if !found {
		return nil, ErrVLANNotFound{VLANID: vlanID}
	}

	var vlan VLANState
	if err := json.Unmarshal(data, &vlan); err != nil {
		return nil, ErrDeserializationFailed{EntityType: entityTypeVLAN, Cause: err}
	}

	return &vlan, nil
}

// Update modifies an existing VLAN with optimistic locking.
// Returns ErrVLANNotFound if the VLAN does not exist.
// Returns ErrVersionConflict if the expected version does not match.
func (d *VLANDAO) Update(
	ctx context.Context,
	vlanID uint16,
	updates *VLANState,
	expectedVersion uint64,
) error {
	if vlanID < 1 || vlanID > 4094 {
		return ErrInvalidVLANID{VLANID: vlanID, Reason: "VLAN ID must be 1-4094"}
	}
	if updates == nil {
		return ErrNilEntity{EntityType: entityTypeVLAN}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := uint64(vlanID)

	// Get current state for version check
	data, found, err := d.storage.Get(ctx, entityTypeVLAN, entityID, d.shardID)
	if err != nil {
		return ErrOperationFailed{Operation: "update_vlan_get", Cause: err}
	}
	if !found {
		return ErrVLANNotFound{VLANID: vlanID}
	}

	var current VLANState
	if err := json.Unmarshal(data, &current); err != nil {
		return ErrDeserializationFailed{EntityType: entityTypeVLAN, Cause: err}
	}

	// Check version for optimistic locking
	if current.Version != expectedVersion {
		return ErrVersionConflict{
			EntityType:      entityTypeVLAN,
			EntityID:        string(rune(vlanID)),
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
		return ErrSerializationFailed{EntityType: entityTypeVLAN, Cause: err}
	}

	if err := d.storage.Put(ctx, entityTypeVLAN, entityID, newData, d.shardID); err != nil {
		return ErrOperationFailed{Operation: "update_vlan", Cause: err}
	}

	d.logger.Debug("VLAN updated", "id", vlanID, "version", updates.Version)
	return nil
}

// Delete removes a VLAN with optimistic locking.
// Returns ErrVLANNotFound if the VLAN does not exist.
// Returns ErrVersionConflict if the expected version does not match.
func (d *VLANDAO) Delete(ctx context.Context, vlanID uint16, expectedVersion uint64) error {
	if vlanID < 1 || vlanID > 4094 {
		return ErrInvalidVLANID{VLANID: vlanID, Reason: "VLAN ID must be 1-4094"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := uint64(vlanID)

	// Get current state for version check
	data, found, err := d.storage.Get(ctx, entityTypeVLAN, entityID, d.shardID)
	if err != nil {
		return ErrOperationFailed{Operation: "delete_vlan_get", Cause: err}
	}
	if !found {
		return ErrVLANNotFound{VLANID: vlanID}
	}

	var current VLANState
	if err := json.Unmarshal(data, &current); err != nil {
		return ErrDeserializationFailed{EntityType: entityTypeVLAN, Cause: err}
	}

	// Check version for optimistic locking
	if current.Version != expectedVersion {
		return ErrVersionConflict{
			EntityType:      entityTypeVLAN,
			EntityID:        string(rune(vlanID)),
			ExpectedVersion: expectedVersion,
			ActualVersion:   current.Version,
		}
	}

	if err := d.storage.Delete(ctx, entityTypeVLAN, entityID, d.shardID); err != nil {
		return ErrOperationFailed{Operation: "delete_vlan", Cause: err}
	}

	d.logger.Debug("VLAN deleted", "id", vlanID)
	return nil
}

// List retrieves all VLANs from the database.
func (d *VLANDAO) List(ctx context.Context) ([]*VLANState, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	var vlans []*VLANState
	pageToken := ""

	for {
		entities, nextToken, err := d.storage.List(ctx, entityTypeVLAN, 1000, pageToken, d.shardID)
		if err != nil {
			return nil, ErrOperationFailed{Operation: "list_vlans", Cause: err}
		}

		for _, entity := range entities {
			var vlan VLANState
			if err := json.Unmarshal(entity.Data, &vlan); err != nil {
				d.logger.Warn("Failed to deserialize VLAN", "id", entity.ID, "error", err)
				continue
			}
			vlans = append(vlans, &vlan)
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return vlans, nil
}

// ListByPort retrieves all VLANs that contain a specific port.
func (d *VLANDAO) ListByPort(ctx context.Context, portID string) ([]*VLANState, error) {
	if portID == "" {
		return nil, ErrInvalidPortID{PortID: "", Reason: "port ID is required"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	var vlans []*VLANState
	pageToken := ""

	for {
		entities, nextToken, err := d.storage.List(ctx, entityTypeVLAN, 1000, pageToken, d.shardID)
		if err != nil {
			return nil, ErrOperationFailed{Operation: "list_vlans_by_port", Cause: err}
		}

		for _, entity := range entities {
			var vlan VLANState
			if err := json.Unmarshal(entity.Data, &vlan); err != nil {
				d.logger.Warn("Failed to deserialize VLAN", "id", entity.ID, "error", err)
				continue
			}
			if containsPort(vlan.Ports, portID) || containsPort(vlan.TrunkPorts, portID) {
				vlans = append(vlans, &vlan)
			}
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return vlans, nil
}

// Count returns the total number of VLANs.
func (d *VLANDAO) Count(ctx context.Context) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	count := 0
	pageToken := ""

	for {
		entities, nextToken, err := d.storage.List(ctx, entityTypeVLAN, 1000, pageToken, d.shardID)
		if err != nil {
			return 0, ErrOperationFailed{Operation: "count_vlans", Cause: err}
		}

		count += len(entities)

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return count, nil
}

// Exists checks if a VLAN exists by its ID.
func (d *VLANDAO) Exists(ctx context.Context, vlanID uint16) (bool, error) {
	if vlanID < 1 || vlanID > 4094 {
		return false, ErrInvalidVLANID{VLANID: vlanID, Reason: "VLAN ID must be 1-4094"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := uint64(vlanID)

	_, found, err := d.storage.Get(ctx, entityTypeVLAN, entityID, d.shardID)
	if err != nil {
		return false, ErrOperationFailed{Operation: "exists_vlan", Cause: err}
	}

	return found, nil
}

// containsPort checks if a port ID is in a slice of port IDs.
func containsPort(ports []string, portID string) bool {
	for _, p := range ports {
		if p == portID {
			return true
		}
	}
	return false
}
