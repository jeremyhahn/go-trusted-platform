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
	"net"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
)

const entityTypeRemoteMAC = "SDNRemoteMAC"

// RemoteMACDAO provides storage operations for RemoteMACState entities.
// It implements CRUD operations with optimistic locking for version conflicts.
type RemoteMACDAO struct {
	storage        quicbaas.Storage
	logger         *logging.Logger
	requestTimeout time.Duration
	shardID        uint64
}

// RemoteMACDAOOption is a functional option for configuring RemoteMACDAO.
type RemoteMACDAOOption func(*remoteMACDAOConfig)

type remoteMACDAOConfig struct {
	requestTimeout time.Duration
	shardID        uint64
}

// WithRemoteMACRequestTimeout sets the request timeout for DAO operations.
func WithRemoteMACRequestTimeout(timeout time.Duration) RemoteMACDAOOption {
	return func(c *remoteMACDAOConfig) {
		c.requestTimeout = timeout
	}
}

// WithRemoteMACShard sets the shard ID for DAO operations.
func WithRemoteMACShard(shardID uint64) RemoteMACDAOOption {
	return func(c *remoteMACDAOConfig) {
		c.shardID = shardID
	}
}

// NewRemoteMACDAO creates a new RemoteMACDAO instance.
func NewRemoteMACDAO(
	storage quicbaas.Storage,
	logger *logging.Logger,
	opts ...RemoteMACDAOOption,
) *RemoteMACDAO {
	cfg := &remoteMACDAOConfig{
		requestTimeout: defaultRequestTimeout,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	return &RemoteMACDAO{
		storage:        storage,
		logger:         logger,
		requestTimeout: cfg.requestTimeout,
		shardID:        cfg.shardID,
	}
}

// Create stores a new remote MAC entry in the database.
// Returns ErrRemoteMACAlreadyExists if an entry with the same ID already exists.
func (d *RemoteMACDAO) Create(ctx context.Context, entry *RemoteMACState) error {
	if entry == nil {
		return ErrNilEntity{EntityType: entityTypeRemoteMAC}
	}
	if entry.ID == "" {
		return ErrInvalidRemoteMACID{RemoteMACID: "", Reason: "remote MAC ID is required"}
	}
	if len(entry.MAC) == 0 {
		return ErrInvalidRemoteMACID{RemoteMACID: entry.ID, Reason: "MAC address is required"}
	}
	if entry.RemoteVTEP == "" {
		return ErrInvalidRemoteMACID{RemoteMACID: entry.ID, Reason: "remote VTEP ID is required"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := entry.EntityID()

	// Check if remote MAC already exists
	_, found, err := d.storage.Get(ctx, entityTypeRemoteMAC, entityID, d.shardID)
	if err != nil {
		return ErrOperationFailed{Operation: "create_remote_mac_check", Cause: err}
	}
	if found {
		return ErrRemoteMACAlreadyExists{MAC: entry.MAC.String(), VNI: entry.VNI}
	}

	// Initialize timestamps and version
	now := time.Now()
	entry.LearnedAt = now
	entry.Version = 1

	data, err := json.Marshal(entry)
	if err != nil {
		return ErrSerializationFailed{EntityType: entityTypeRemoteMAC, Cause: err}
	}

	if err := d.storage.Put(ctx, entityTypeRemoteMAC, entityID, data, d.shardID); err != nil {
		return ErrOperationFailed{Operation: "create_remote_mac", Cause: err}
	}

	d.logger.Debug("Remote MAC created",
		"id", entry.ID,
		"mac", entry.MAC.String(),
		"vni", entry.VNI,
		"remote_vtep", entry.RemoteVTEP)
	return nil
}

// Get retrieves a remote MAC entry by its ID.
// Returns ErrRemoteMACNotFound if the entry does not exist.
func (d *RemoteMACDAO) Get(ctx context.Context, remoteMACID string) (*RemoteMACState, error) {
	if remoteMACID == "" {
		return nil, ErrInvalidRemoteMACID{RemoteMACID: "", Reason: "remote MAC ID is required"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := hashString(remoteMACID)

	data, found, err := d.storage.Get(ctx, entityTypeRemoteMAC, entityID, d.shardID)
	if err != nil {
		return nil, ErrOperationFailed{Operation: "get_remote_mac", Cause: err}
	}
	if !found {
		return nil, ErrRemoteMACNotFound{MAC: "", VNI: 0}
	}

	var entry RemoteMACState
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, ErrDeserializationFailed{EntityType: entityTypeRemoteMAC, Cause: err}
	}

	return &entry, nil
}

// GetByMAC retrieves a remote MAC entry by its MAC address and VNI.
// Returns ErrRemoteMACNotFound if no entry with the MAC and VNI exists.
func (d *RemoteMACDAO) GetByMAC(ctx context.Context, mac net.HardwareAddr, vni uint32) (*RemoteMACState, error) {
	if len(mac) == 0 {
		return nil, ErrInvalidRemoteMACID{RemoteMACID: "", Reason: "MAC address is required"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entries, err := d.List(ctx)
	if err != nil {
		return nil, err
	}

	macStr := mac.String()
	for _, entry := range entries {
		if entry.MAC.String() == macStr && entry.VNI == vni {
			return entry, nil
		}
	}

	return nil, ErrRemoteMACNotFound{MAC: macStr, VNI: vni}
}

// Update modifies an existing remote MAC entry with optimistic locking.
// Returns ErrRemoteMACNotFound if the entry does not exist.
// Returns ErrVersionConflict if the expected version does not match.
func (d *RemoteMACDAO) Update(
	ctx context.Context,
	remoteMACID string,
	updates *RemoteMACState,
	expectedVersion uint64,
) error {
	if remoteMACID == "" {
		return ErrInvalidRemoteMACID{RemoteMACID: "", Reason: "remote MAC ID is required"}
	}
	if updates == nil {
		return ErrNilEntity{EntityType: entityTypeRemoteMAC}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := hashString(remoteMACID)

	// Get current state for version check
	data, found, err := d.storage.Get(ctx, entityTypeRemoteMAC, entityID, d.shardID)
	if err != nil {
		return ErrOperationFailed{Operation: "update_remote_mac_get", Cause: err}
	}
	if !found {
		return ErrRemoteMACNotFound{MAC: "", VNI: 0}
	}

	var current RemoteMACState
	if err := json.Unmarshal(data, &current); err != nil {
		return ErrDeserializationFailed{EntityType: entityTypeRemoteMAC, Cause: err}
	}

	// Check version for optimistic locking
	if current.Version != expectedVersion {
		return ErrVersionConflict{
			EntityType:      entityTypeRemoteMAC,
			EntityID:        remoteMACID,
			ExpectedVersion: expectedVersion,
			ActualVersion:   current.Version,
		}
	}

	// Apply updates while preserving immutable fields
	updates.ID = current.ID
	updates.MAC = current.MAC
	updates.VNI = current.VNI
	updates.LearnedAt = current.LearnedAt
	updates.Version = current.Version + 1

	newData, err := json.Marshal(updates)
	if err != nil {
		return ErrSerializationFailed{EntityType: entityTypeRemoteMAC, Cause: err}
	}

	if err := d.storage.Put(ctx, entityTypeRemoteMAC, entityID, newData, d.shardID); err != nil {
		return ErrOperationFailed{Operation: "update_remote_mac", Cause: err}
	}

	d.logger.Debug("Remote MAC updated", "id", remoteMACID, "version", updates.Version)
	return nil
}

// Delete removes a remote MAC entry with optimistic locking.
// Returns ErrRemoteMACNotFound if the entry does not exist.
// Returns ErrVersionConflict if the expected version does not match.
func (d *RemoteMACDAO) Delete(ctx context.Context, remoteMACID string, expectedVersion uint64) error {
	if remoteMACID == "" {
		return ErrInvalidRemoteMACID{RemoteMACID: "", Reason: "remote MAC ID is required"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := hashString(remoteMACID)

	// Get current state for version check
	data, found, err := d.storage.Get(ctx, entityTypeRemoteMAC, entityID, d.shardID)
	if err != nil {
		return ErrOperationFailed{Operation: "delete_remote_mac_get", Cause: err}
	}
	if !found {
		return ErrRemoteMACNotFound{MAC: "", VNI: 0}
	}

	var current RemoteMACState
	if err := json.Unmarshal(data, &current); err != nil {
		return ErrDeserializationFailed{EntityType: entityTypeRemoteMAC, Cause: err}
	}

	// Check version for optimistic locking
	if current.Version != expectedVersion {
		return ErrVersionConflict{
			EntityType:      entityTypeRemoteMAC,
			EntityID:        remoteMACID,
			ExpectedVersion: expectedVersion,
			ActualVersion:   current.Version,
		}
	}

	if err := d.storage.Delete(ctx, entityTypeRemoteMAC, entityID, d.shardID); err != nil {
		return ErrOperationFailed{Operation: "delete_remote_mac", Cause: err}
	}

	d.logger.Debug("Remote MAC deleted", "id", remoteMACID)
	return nil
}

// List retrieves all remote MAC entries from the database.
func (d *RemoteMACDAO) List(ctx context.Context) ([]*RemoteMACState, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	var entries []*RemoteMACState
	pageToken := ""

	for {
		entities, nextToken, err := d.storage.List(ctx, entityTypeRemoteMAC, 1000, pageToken, d.shardID)
		if err != nil {
			return nil, ErrOperationFailed{Operation: "list_remote_macs", Cause: err}
		}

		for _, entity := range entities {
			var entry RemoteMACState
			if err := json.Unmarshal(entity.Data, &entry); err != nil {
				d.logger.Warn("Failed to deserialize remote MAC", "id", entity.ID, "error", err)
				continue
			}
			entries = append(entries, &entry)
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return entries, nil
}

// ListByVNI retrieves all remote MAC entries for a specific VNI.
func (d *RemoteMACDAO) ListByVNI(ctx context.Context, vni uint32) ([]*RemoteMACState, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	var entries []*RemoteMACState
	pageToken := ""

	for {
		entities, nextToken, err := d.storage.List(ctx, entityTypeRemoteMAC, 1000, pageToken, d.shardID)
		if err != nil {
			return nil, ErrOperationFailed{Operation: "list_remote_macs_by_vni", Cause: err}
		}

		for _, entity := range entities {
			var entry RemoteMACState
			if err := json.Unmarshal(entity.Data, &entry); err != nil {
				d.logger.Warn("Failed to deserialize remote MAC", "id", entity.ID, "error", err)
				continue
			}
			if entry.VNI == vni {
				entries = append(entries, &entry)
			}
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return entries, nil
}

// ListByVTEP retrieves all remote MAC entries for a specific VTEP.
func (d *RemoteMACDAO) ListByVTEP(ctx context.Context, vtepID string) ([]*RemoteMACState, error) {
	if vtepID == "" {
		return nil, ErrInvalidVTEPID{VTEPID: "", Reason: "VTEP ID is required"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	var entries []*RemoteMACState
	pageToken := ""

	for {
		entities, nextToken, err := d.storage.List(ctx, entityTypeRemoteMAC, 1000, pageToken, d.shardID)
		if err != nil {
			return nil, ErrOperationFailed{Operation: "list_remote_macs_by_vtep", Cause: err}
		}

		for _, entity := range entities {
			var entry RemoteMACState
			if err := json.Unmarshal(entity.Data, &entry); err != nil {
				d.logger.Warn("Failed to deserialize remote MAC", "id", entity.ID, "error", err)
				continue
			}
			if entry.RemoteVTEP == vtepID {
				entries = append(entries, &entry)
			}
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return entries, nil
}

// ListByNode retrieves all remote MAC entries owned by a specific node.
func (d *RemoteMACDAO) ListByNode(ctx context.Context, nodeID uint64) ([]*RemoteMACState, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	var entries []*RemoteMACState
	pageToken := ""

	for {
		entities, nextToken, err := d.storage.List(ctx, entityTypeRemoteMAC, 1000, pageToken, d.shardID)
		if err != nil {
			return nil, ErrOperationFailed{Operation: "list_remote_macs_by_node", Cause: err}
		}

		for _, entity := range entities {
			var entry RemoteMACState
			if err := json.Unmarshal(entity.Data, &entry); err != nil {
				d.logger.Warn("Failed to deserialize remote MAC", "id", entity.ID, "error", err)
				continue
			}
			if entry.NodeID == nodeID {
				entries = append(entries, &entry)
			}
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return entries, nil
}

// DeleteExpired removes all expired remote MAC entries.
// Returns the count of deleted entries.
func (d *RemoteMACDAO) DeleteExpired(ctx context.Context) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entries, err := d.List(ctx)
	if err != nil {
		return 0, err
	}

	deleted := 0
	now := time.Now()

	for _, entry := range entries {
		if !entry.ExpiresAt.IsZero() && now.After(entry.ExpiresAt) {
			if err := d.storage.Delete(ctx, entityTypeRemoteMAC, entry.EntityID(), d.shardID); err != nil {
				d.logger.Warn("Failed to delete expired remote MAC",
					"id", entry.ID,
					"mac", entry.MAC.String(),
					"error", err)
				continue
			}
			deleted++
			d.logger.Debug("Deleted expired remote MAC",
				"id", entry.ID,
				"mac", entry.MAC.String(),
				"expired_at", entry.ExpiresAt)
		}
	}

	return deleted, nil
}

// Count returns the total number of remote MAC entries.
func (d *RemoteMACDAO) Count(ctx context.Context) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	count := 0
	pageToken := ""

	for {
		entities, nextToken, err := d.storage.List(ctx, entityTypeRemoteMAC, 1000, pageToken, d.shardID)
		if err != nil {
			return 0, ErrOperationFailed{Operation: "count_remote_macs", Cause: err}
		}

		count += len(entities)

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return count, nil
}

// Exists checks if a remote MAC entry exists by its ID.
func (d *RemoteMACDAO) Exists(ctx context.Context, remoteMACID string) (bool, error) {
	if remoteMACID == "" {
		return false, ErrInvalidRemoteMACID{RemoteMACID: "", Reason: "remote MAC ID is required"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := hashString(remoteMACID)

	_, found, err := d.storage.Get(ctx, entityTypeRemoteMAC, entityID, d.shardID)
	if err != nil {
		return false, ErrOperationFailed{Operation: "exists_remote_mac", Cause: err}
	}

	return found, nil
}
