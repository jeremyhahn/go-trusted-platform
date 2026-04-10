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
	"net/netip"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
)

const entityTypeVTEP = "SDNVTEP"

// VTEPDAO provides storage operations for VTEPState entities.
// It implements CRUD operations with optimistic locking for version conflicts.
type VTEPDAO struct {
	storage        quicbaas.Storage
	logger         *logging.Logger
	requestTimeout time.Duration
	shardID        uint64
}

// VTEPDAOOption is a functional option for configuring VTEPDAO.
type VTEPDAOOption func(*vtepDAOConfig)

type vtepDAOConfig struct {
	requestTimeout time.Duration
	shardID        uint64
}

// WithVTEPRequestTimeout sets the request timeout for DAO operations.
func WithVTEPRequestTimeout(timeout time.Duration) VTEPDAOOption {
	return func(c *vtepDAOConfig) {
		c.requestTimeout = timeout
	}
}

// WithVTEPShard sets the shard ID for DAO operations.
func WithVTEPShard(shardID uint64) VTEPDAOOption {
	return func(c *vtepDAOConfig) {
		c.shardID = shardID
	}
}

// NewVTEPDAO creates a new VTEPDAO instance.
func NewVTEPDAO(
	storage quicbaas.Storage,
	logger *logging.Logger,
	opts ...VTEPDAOOption,
) *VTEPDAO {
	cfg := &vtepDAOConfig{
		requestTimeout: defaultRequestTimeout,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	return &VTEPDAO{
		storage:        storage,
		logger:         logger,
		requestTimeout: cfg.requestTimeout,
		shardID:        cfg.shardID,
	}
}

// Create stores a new VTEP in the database.
// Returns ErrVTEPAlreadyExists if a VTEP with the same ID already exists.
func (d *VTEPDAO) Create(ctx context.Context, vtep *VTEPState) error {
	if vtep == nil {
		return ErrNilEntity{EntityType: entityTypeVTEP}
	}
	if vtep.ID == "" {
		return ErrInvalidVTEPID{VTEPID: "", Reason: "VTEP ID is required"}
	}
	if !vtep.IP.IsValid() {
		return ErrInvalidVTEPID{VTEPID: vtep.ID, Reason: "valid IP address is required"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := vtep.EntityID()

	// Check if VTEP already exists
	_, found, err := d.storage.Get(ctx, entityTypeVTEP, entityID, d.shardID)
	if err != nil {
		return ErrOperationFailed{Operation: "create_vtep_check", Cause: err}
	}
	if found {
		return ErrVTEPAlreadyExists{IP: vtep.IP}
	}

	// Check if a VTEP with the same IP already exists
	existing, err := d.GetByIP(ctx, vtep.IP)
	if err == nil && existing != nil {
		return ErrVTEPAlreadyExists{IP: vtep.IP}
	}

	// Initialize timestamps and version
	now := time.Now()
	vtep.CreatedAt = now
	vtep.UpdatedAt = now
	vtep.Version = 1

	data, err := json.Marshal(vtep)
	if err != nil {
		return ErrSerializationFailed{EntityType: entityTypeVTEP, Cause: err}
	}

	if err := d.storage.Put(ctx, entityTypeVTEP, entityID, data, d.shardID); err != nil {
		return ErrOperationFailed{Operation: "create_vtep", Cause: err}
	}

	d.logger.Debug("VTEP created", "id", vtep.ID, "ip", vtep.IP.String(), "node_id", vtep.NodeID)
	return nil
}

// Get retrieves a VTEP by its ID.
// Returns ErrVTEPNotFound if the VTEP does not exist.
func (d *VTEPDAO) Get(ctx context.Context, vtepID string) (*VTEPState, error) {
	if vtepID == "" {
		return nil, ErrInvalidVTEPID{VTEPID: "", Reason: "VTEP ID is required"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := hashString(vtepID)

	data, found, err := d.storage.Get(ctx, entityTypeVTEP, entityID, d.shardID)
	if err != nil {
		return nil, ErrOperationFailed{Operation: "get_vtep", Cause: err}
	}
	if !found {
		return nil, ErrVTEPNotFound{VTEPID: vtepID}
	}

	var vtep VTEPState
	if err := json.Unmarshal(data, &vtep); err != nil {
		return nil, ErrDeserializationFailed{EntityType: entityTypeVTEP, Cause: err}
	}

	return &vtep, nil
}

// GetByIP retrieves a VTEP by its IP address.
// Returns ErrVTEPNotFound if no VTEP with the IP exists.
func (d *VTEPDAO) GetByIP(ctx context.Context, ip netip.Addr) (*VTEPState, error) {
	if !ip.IsValid() {
		return nil, ErrInvalidVTEPID{VTEPID: "", Reason: "valid IP address is required"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	vteps, err := d.List(ctx)
	if err != nil {
		return nil, err
	}

	for _, vtep := range vteps {
		if vtep.IP == ip {
			return vtep, nil
		}
	}

	return nil, ErrVTEPNotFound{VTEPID: ip.String()}
}

// Update modifies an existing VTEP with optimistic locking.
// Returns ErrVTEPNotFound if the VTEP does not exist.
// Returns ErrVersionConflict if the expected version does not match.
func (d *VTEPDAO) Update(
	ctx context.Context,
	vtepID string,
	updates *VTEPState,
	expectedVersion uint64,
) error {
	if vtepID == "" {
		return ErrInvalidVTEPID{VTEPID: "", Reason: "VTEP ID is required"}
	}
	if updates == nil {
		return ErrNilEntity{EntityType: entityTypeVTEP}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := hashString(vtepID)

	// Get current state for version check
	data, found, err := d.storage.Get(ctx, entityTypeVTEP, entityID, d.shardID)
	if err != nil {
		return ErrOperationFailed{Operation: "update_vtep_get", Cause: err}
	}
	if !found {
		return ErrVTEPNotFound{VTEPID: vtepID}
	}

	var current VTEPState
	if err := json.Unmarshal(data, &current); err != nil {
		return ErrDeserializationFailed{EntityType: entityTypeVTEP, Cause: err}
	}

	// Check version for optimistic locking
	if current.Version != expectedVersion {
		return ErrVersionConflict{
			EntityType:      entityTypeVTEP,
			EntityID:        vtepID,
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
		return ErrSerializationFailed{EntityType: entityTypeVTEP, Cause: err}
	}

	if err := d.storage.Put(ctx, entityTypeVTEP, entityID, newData, d.shardID); err != nil {
		return ErrOperationFailed{Operation: "update_vtep", Cause: err}
	}

	d.logger.Debug("VTEP updated", "id", vtepID, "version", updates.Version)
	return nil
}

// Delete removes a VTEP with optimistic locking.
// Returns ErrVTEPNotFound if the VTEP does not exist.
// Returns ErrVersionConflict if the expected version does not match.
func (d *VTEPDAO) Delete(ctx context.Context, vtepID string, expectedVersion uint64) error {
	if vtepID == "" {
		return ErrInvalidVTEPID{VTEPID: "", Reason: "VTEP ID is required"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := hashString(vtepID)

	// Get current state for version check
	data, found, err := d.storage.Get(ctx, entityTypeVTEP, entityID, d.shardID)
	if err != nil {
		return ErrOperationFailed{Operation: "delete_vtep_get", Cause: err}
	}
	if !found {
		return ErrVTEPNotFound{VTEPID: vtepID}
	}

	var current VTEPState
	if err := json.Unmarshal(data, &current); err != nil {
		return ErrDeserializationFailed{EntityType: entityTypeVTEP, Cause: err}
	}

	// Check version for optimistic locking
	if current.Version != expectedVersion {
		return ErrVersionConflict{
			EntityType:      entityTypeVTEP,
			EntityID:        vtepID,
			ExpectedVersion: expectedVersion,
			ActualVersion:   current.Version,
		}
	}

	if err := d.storage.Delete(ctx, entityTypeVTEP, entityID, d.shardID); err != nil {
		return ErrOperationFailed{Operation: "delete_vtep", Cause: err}
	}

	d.logger.Debug("VTEP deleted", "id", vtepID)
	return nil
}

// List retrieves all VTEPs from the database.
func (d *VTEPDAO) List(ctx context.Context) ([]*VTEPState, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	var vteps []*VTEPState
	pageToken := ""

	for {
		entities, nextToken, err := d.storage.List(ctx, entityTypeVTEP, 1000, pageToken, d.shardID)
		if err != nil {
			return nil, ErrOperationFailed{Operation: "list_vteps", Cause: err}
		}

		for _, entity := range entities {
			var vtep VTEPState
			if err := json.Unmarshal(entity.Data, &vtep); err != nil {
				d.logger.Warn("Failed to deserialize VTEP", "id", entity.ID, "error", err)
				continue
			}
			vteps = append(vteps, &vtep)
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return vteps, nil
}

// ListByNode retrieves all VTEPs owned by a specific node.
func (d *VTEPDAO) ListByNode(ctx context.Context, nodeID uint64) ([]*VTEPState, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	var vteps []*VTEPState
	pageToken := ""

	for {
		entities, nextToken, err := d.storage.List(ctx, entityTypeVTEP, 1000, pageToken, d.shardID)
		if err != nil {
			return nil, ErrOperationFailed{Operation: "list_vteps_by_node", Cause: err}
		}

		for _, entity := range entities {
			var vtep VTEPState
			if err := json.Unmarshal(entity.Data, &vtep); err != nil {
				d.logger.Warn("Failed to deserialize VTEP", "id", entity.ID, "error", err)
				continue
			}
			if vtep.NodeID == nodeID {
				vteps = append(vteps, &vtep)
			}
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return vteps, nil
}

// Count returns the total number of VTEPs.
func (d *VTEPDAO) Count(ctx context.Context) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	count := 0
	pageToken := ""

	for {
		entities, nextToken, err := d.storage.List(ctx, entityTypeVTEP, 1000, pageToken, d.shardID)
		if err != nil {
			return 0, ErrOperationFailed{Operation: "count_vteps", Cause: err}
		}

		count += len(entities)

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return count, nil
}

// Exists checks if a VTEP exists by its ID.
func (d *VTEPDAO) Exists(ctx context.Context, vtepID string) (bool, error) {
	if vtepID == "" {
		return false, ErrInvalidVTEPID{VTEPID: "", Reason: "VTEP ID is required"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := hashString(vtepID)

	_, found, err := d.storage.Get(ctx, entityTypeVTEP, entityID, d.shardID)
	if err != nil {
		return false, ErrOperationFailed{Operation: "exists_vtep", Cause: err}
	}

	return found, nil
}
