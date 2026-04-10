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

const entityTypeVNIMapping = "SDNVNIMapping"

// Maximum valid VNI value (24-bit field)
const maxVNI uint32 = 16777215

// VNIMappingDAO provides storage operations for VNIMappingState entities.
// It implements CRUD operations with optimistic locking for version conflicts.
type VNIMappingDAO struct {
	storage        quicbaas.Storage
	logger         *logging.Logger
	requestTimeout time.Duration
	shardID        uint64
}

// VNIMappingDAOOption is a functional option for configuring VNIMappingDAO.
type VNIMappingDAOOption func(*vniMappingDAOConfig)

type vniMappingDAOConfig struct {
	requestTimeout time.Duration
	shardID        uint64
}

// WithVNIMappingRequestTimeout sets the request timeout for DAO operations.
func WithVNIMappingRequestTimeout(timeout time.Duration) VNIMappingDAOOption {
	return func(c *vniMappingDAOConfig) {
		c.requestTimeout = timeout
	}
}

// WithVNIMappingShard sets the shard ID for DAO operations.
func WithVNIMappingShard(shardID uint64) VNIMappingDAOOption {
	return func(c *vniMappingDAOConfig) {
		c.shardID = shardID
	}
}

// NewVNIMappingDAO creates a new VNIMappingDAO instance.
func NewVNIMappingDAO(
	storage quicbaas.Storage,
	logger *logging.Logger,
	opts ...VNIMappingDAOOption,
) *VNIMappingDAO {
	cfg := &vniMappingDAOConfig{
		requestTimeout: defaultRequestTimeout,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	return &VNIMappingDAO{
		storage:        storage,
		logger:         logger,
		requestTimeout: cfg.requestTimeout,
		shardID:        cfg.shardID,
	}
}

// Create stores a new VNI mapping in the database.
// Returns ErrVNIAlreadyMapped if a mapping with the same VNI already exists.
func (d *VNIMappingDAO) Create(ctx context.Context, mapping *VNIMappingState) error {
	if mapping == nil {
		return ErrNilEntity{EntityType: entityTypeVNIMapping}
	}
	if mapping.VNI == 0 || mapping.VNI > maxVNI {
		return ErrInvalidVNI{VNI: mapping.VNI, Reason: "VNI must be 1-16777215"}
	}
	if mapping.VLAN < 1 || mapping.VLAN > 4094 {
		return ErrInvalidVLANID{VLANID: mapping.VLAN, Reason: "VLAN ID must be 1-4094"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := mapping.EntityID()

	// Check if VNI mapping already exists
	_, found, err := d.storage.Get(ctx, entityTypeVNIMapping, entityID, d.shardID)
	if err != nil {
		return ErrOperationFailed{Operation: "create_vni_mapping_check", Cause: err}
	}
	if found {
		return ErrVNIAlreadyMapped{VNI: mapping.VNI, VLAN: mapping.VLAN}
	}

	// Initialize timestamps and version
	now := time.Now()
	mapping.CreatedAt = now
	mapping.UpdatedAt = now
	mapping.Version = 1

	data, err := json.Marshal(mapping)
	if err != nil {
		return ErrSerializationFailed{EntityType: entityTypeVNIMapping, Cause: err}
	}

	if err := d.storage.Put(ctx, entityTypeVNIMapping, entityID, data, d.shardID); err != nil {
		return ErrOperationFailed{Operation: "create_vni_mapping", Cause: err}
	}

	d.logger.Debug("VNI mapping created", "vni", mapping.VNI, "vlan", mapping.VLAN, "bridge", mapping.BridgeID)
	return nil
}

// Get retrieves a VNI mapping by its VNI.
// Returns ErrVNIMappingNotFound if the mapping does not exist.
func (d *VNIMappingDAO) Get(ctx context.Context, vni uint32) (*VNIMappingState, error) {
	if vni == 0 || vni > maxVNI {
		return nil, ErrInvalidVNI{VNI: vni, Reason: "VNI must be 1-16777215"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := uint64(vni)

	data, found, err := d.storage.Get(ctx, entityTypeVNIMapping, entityID, d.shardID)
	if err != nil {
		return nil, ErrOperationFailed{Operation: "get_vni_mapping", Cause: err}
	}
	if !found {
		return nil, ErrVNIMappingNotFound{VNI: vni}
	}

	var mapping VNIMappingState
	if err := json.Unmarshal(data, &mapping); err != nil {
		return nil, ErrDeserializationFailed{EntityType: entityTypeVNIMapping, Cause: err}
	}

	return &mapping, nil
}

// GetByVLAN retrieves a VNI mapping by its VLAN ID.
// Returns ErrVNIMappingNotFound if no mapping with the VLAN exists.
func (d *VNIMappingDAO) GetByVLAN(ctx context.Context, vlan uint16) (*VNIMappingState, error) {
	if vlan < 1 || vlan > 4094 {
		return nil, ErrInvalidVLANID{VLANID: vlan, Reason: "VLAN ID must be 1-4094"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	mappings, err := d.List(ctx)
	if err != nil {
		return nil, err
	}

	for _, mapping := range mappings {
		if mapping.VLAN == vlan {
			return mapping, nil
		}
	}

	return nil, ErrVNIMappingNotFound{VNI: 0}
}

// GetByBridge retrieves all VNI mappings associated with a specific bridge.
func (d *VNIMappingDAO) GetByBridge(ctx context.Context, bridgeID string) ([]*VNIMappingState, error) {
	if bridgeID == "" {
		return nil, ErrInvalidBridgeID{BridgeID: "", Reason: "bridge ID is required"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	var mappings []*VNIMappingState
	pageToken := ""

	for {
		entities, nextToken, err := d.storage.List(ctx, entityTypeVNIMapping, 1000, pageToken, d.shardID)
		if err != nil {
			return nil, ErrOperationFailed{Operation: "list_vni_mappings_by_bridge", Cause: err}
		}

		for _, entity := range entities {
			var mapping VNIMappingState
			if err := json.Unmarshal(entity.Data, &mapping); err != nil {
				d.logger.Warn("Failed to deserialize VNI mapping", "id", entity.ID, "error", err)
				continue
			}
			if mapping.BridgeID == bridgeID {
				mappings = append(mappings, &mapping)
			}
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return mappings, nil
}

// Update modifies an existing VNI mapping with optimistic locking.
// Returns ErrVNIMappingNotFound if the mapping does not exist.
// Returns ErrVersionConflict if the expected version does not match.
func (d *VNIMappingDAO) Update(
	ctx context.Context,
	vni uint32,
	updates *VNIMappingState,
	expectedVersion uint64,
) error {
	if vni == 0 || vni > maxVNI {
		return ErrInvalidVNI{VNI: vni, Reason: "VNI must be 1-16777215"}
	}
	if updates == nil {
		return ErrNilEntity{EntityType: entityTypeVNIMapping}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := uint64(vni)

	// Get current state for version check
	data, found, err := d.storage.Get(ctx, entityTypeVNIMapping, entityID, d.shardID)
	if err != nil {
		return ErrOperationFailed{Operation: "update_vni_mapping_get", Cause: err}
	}
	if !found {
		return ErrVNIMappingNotFound{VNI: vni}
	}

	var current VNIMappingState
	if err := json.Unmarshal(data, &current); err != nil {
		return ErrDeserializationFailed{EntityType: entityTypeVNIMapping, Cause: err}
	}

	// Check version for optimistic locking
	if current.Version != expectedVersion {
		return ErrVersionConflict{
			EntityType:      entityTypeVNIMapping,
			EntityID:        string(rune(vni)),
			ExpectedVersion: expectedVersion,
			ActualVersion:   current.Version,
		}
	}

	// Apply updates while preserving immutable fields
	updates.VNI = current.VNI
	updates.CreatedAt = current.CreatedAt
	updates.UpdatedAt = time.Now()
	updates.Version = current.Version + 1

	newData, err := json.Marshal(updates)
	if err != nil {
		return ErrSerializationFailed{EntityType: entityTypeVNIMapping, Cause: err}
	}

	if err := d.storage.Put(ctx, entityTypeVNIMapping, entityID, newData, d.shardID); err != nil {
		return ErrOperationFailed{Operation: "update_vni_mapping", Cause: err}
	}

	d.logger.Debug("VNI mapping updated", "vni", vni, "version", updates.Version)
	return nil
}

// Delete removes a VNI mapping with optimistic locking.
// Returns ErrVNIMappingNotFound if the mapping does not exist.
// Returns ErrVersionConflict if the expected version does not match.
func (d *VNIMappingDAO) Delete(ctx context.Context, vni uint32, expectedVersion uint64) error {
	if vni == 0 || vni > maxVNI {
		return ErrInvalidVNI{VNI: vni, Reason: "VNI must be 1-16777215"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := uint64(vni)

	// Get current state for version check
	data, found, err := d.storage.Get(ctx, entityTypeVNIMapping, entityID, d.shardID)
	if err != nil {
		return ErrOperationFailed{Operation: "delete_vni_mapping_get", Cause: err}
	}
	if !found {
		return ErrVNIMappingNotFound{VNI: vni}
	}

	var current VNIMappingState
	if err := json.Unmarshal(data, &current); err != nil {
		return ErrDeserializationFailed{EntityType: entityTypeVNIMapping, Cause: err}
	}

	// Check version for optimistic locking
	if current.Version != expectedVersion {
		return ErrVersionConflict{
			EntityType:      entityTypeVNIMapping,
			EntityID:        string(rune(vni)),
			ExpectedVersion: expectedVersion,
			ActualVersion:   current.Version,
		}
	}

	if err := d.storage.Delete(ctx, entityTypeVNIMapping, entityID, d.shardID); err != nil {
		return ErrOperationFailed{Operation: "delete_vni_mapping", Cause: err}
	}

	d.logger.Debug("VNI mapping deleted", "vni", vni)
	return nil
}

// List retrieves all VNI mappings from the database.
func (d *VNIMappingDAO) List(ctx context.Context) ([]*VNIMappingState, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	var mappings []*VNIMappingState
	pageToken := ""

	for {
		entities, nextToken, err := d.storage.List(ctx, entityTypeVNIMapping, 1000, pageToken, d.shardID)
		if err != nil {
			return nil, ErrOperationFailed{Operation: "list_vni_mappings", Cause: err}
		}

		for _, entity := range entities {
			var mapping VNIMappingState
			if err := json.Unmarshal(entity.Data, &mapping); err != nil {
				d.logger.Warn("Failed to deserialize VNI mapping", "id", entity.ID, "error", err)
				continue
			}
			mappings = append(mappings, &mapping)
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return mappings, nil
}

// ListByTenant retrieves all VNI mappings for a specific tenant.
func (d *VNIMappingDAO) ListByTenant(ctx context.Context, tenantID string) ([]*VNIMappingState, error) {
	if tenantID == "" {
		return nil, ErrInvalidConfig{Field: "tenant_id", Reason: "tenant ID is required"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	var mappings []*VNIMappingState
	pageToken := ""

	for {
		entities, nextToken, err := d.storage.List(ctx, entityTypeVNIMapping, 1000, pageToken, d.shardID)
		if err != nil {
			return nil, ErrOperationFailed{Operation: "list_vni_mappings_by_tenant", Cause: err}
		}

		for _, entity := range entities {
			var mapping VNIMappingState
			if err := json.Unmarshal(entity.Data, &mapping); err != nil {
				d.logger.Warn("Failed to deserialize VNI mapping", "id", entity.ID, "error", err)
				continue
			}
			if mapping.TenantID == tenantID {
				mappings = append(mappings, &mapping)
			}
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return mappings, nil
}

// Count returns the total number of VNI mappings.
func (d *VNIMappingDAO) Count(ctx context.Context) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	count := 0
	pageToken := ""

	for {
		entities, nextToken, err := d.storage.List(ctx, entityTypeVNIMapping, 1000, pageToken, d.shardID)
		if err != nil {
			return 0, ErrOperationFailed{Operation: "count_vni_mappings", Cause: err}
		}

		count += len(entities)

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return count, nil
}

// Exists checks if a VNI mapping exists by its VNI.
func (d *VNIMappingDAO) Exists(ctx context.Context, vni uint32) (bool, error) {
	if vni == 0 || vni > maxVNI {
		return false, ErrInvalidVNI{VNI: vni, Reason: "VNI must be 1-16777215"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := uint64(vni)

	_, found, err := d.storage.Get(ctx, entityTypeVNIMapping, entityID, d.shardID)
	if err != nil {
		return false, ErrOperationFailed{Operation: "exists_vni_mapping", Cause: err}
	}

	return found, nil
}
