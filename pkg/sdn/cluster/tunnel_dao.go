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

const entityTypeTunnel = "SDNTunnel"

// TunnelDAO provides storage operations for TunnelState entities.
// It implements CRUD operations with optimistic locking for version conflicts.
type TunnelDAO struct {
	storage        quicbaas.Storage
	logger         *logging.Logger
	requestTimeout time.Duration
	shardID        uint64
}

// TunnelDAOOption is a functional option for configuring TunnelDAO.
type TunnelDAOOption func(*tunnelDAOConfig)

type tunnelDAOConfig struct {
	requestTimeout time.Duration
	shardID        uint64
}

// WithTunnelRequestTimeout sets the request timeout for DAO operations.
func WithTunnelRequestTimeout(timeout time.Duration) TunnelDAOOption {
	return func(c *tunnelDAOConfig) {
		c.requestTimeout = timeout
	}
}

// WithTunnelShard sets the shard ID for DAO operations.
func WithTunnelShard(shardID uint64) TunnelDAOOption {
	return func(c *tunnelDAOConfig) {
		c.shardID = shardID
	}
}

// NewTunnelDAO creates a new TunnelDAO instance.
func NewTunnelDAO(
	storage quicbaas.Storage,
	logger *logging.Logger,
	opts ...TunnelDAOOption,
) *TunnelDAO {
	cfg := &tunnelDAOConfig{
		requestTimeout: defaultRequestTimeout,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	return &TunnelDAO{
		storage:        storage,
		logger:         logger,
		requestTimeout: cfg.requestTimeout,
		shardID:        cfg.shardID,
	}
}

// Create stores a new tunnel in the database.
// Returns ErrTunnelAlreadyExists if a tunnel with the same ID already exists.
func (d *TunnelDAO) Create(ctx context.Context, tunnel *TunnelState) error {
	if tunnel == nil {
		return ErrNilEntity{EntityType: entityTypeTunnel}
	}
	if tunnel.ID == "" {
		return ErrInvalidTunnelID{TunnelID: "", Reason: "tunnel ID is required"}
	}
	if tunnel.LocalVTEP == "" {
		return ErrInvalidTunnelID{TunnelID: tunnel.ID, Reason: "local VTEP ID is required"}
	}
	if tunnel.RemoteVTEP == "" {
		return ErrInvalidTunnelID{TunnelID: tunnel.ID, Reason: "remote VTEP ID is required"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := tunnel.EntityID()

	// Check if tunnel already exists
	_, found, err := d.storage.Get(ctx, entityTypeTunnel, entityID, d.shardID)
	if err != nil {
		return ErrOperationFailed{Operation: "create_tunnel_check", Cause: err}
	}
	if found {
		return ErrTunnelAlreadyExists{TunnelID: tunnel.ID}
	}

	// Initialize timestamps and version
	now := time.Now()
	tunnel.CreatedAt = now
	tunnel.UpdatedAt = now
	tunnel.Version = 1

	data, err := json.Marshal(tunnel)
	if err != nil {
		return ErrSerializationFailed{EntityType: entityTypeTunnel, Cause: err}
	}

	if err := d.storage.Put(ctx, entityTypeTunnel, entityID, data, d.shardID); err != nil {
		return ErrOperationFailed{Operation: "create_tunnel", Cause: err}
	}

	d.logger.Debug("Tunnel created",
		"id", tunnel.ID,
		"local_vtep", tunnel.LocalVTEP,
		"remote_vtep", tunnel.RemoteVTEP,
		"vni", tunnel.VNI)
	return nil
}

// Get retrieves a tunnel by its ID.
// Returns ErrTunnelNotFound if the tunnel does not exist.
func (d *TunnelDAO) Get(ctx context.Context, tunnelID string) (*TunnelState, error) {
	if tunnelID == "" {
		return nil, ErrInvalidTunnelID{TunnelID: "", Reason: "tunnel ID is required"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := hashString(tunnelID)

	data, found, err := d.storage.Get(ctx, entityTypeTunnel, entityID, d.shardID)
	if err != nil {
		return nil, ErrOperationFailed{Operation: "get_tunnel", Cause: err}
	}
	if !found {
		return nil, ErrTunnelNotFound{TunnelID: tunnelID}
	}

	var tunnel TunnelState
	if err := json.Unmarshal(data, &tunnel); err != nil {
		return nil, ErrDeserializationFailed{EntityType: entityTypeTunnel, Cause: err}
	}

	return &tunnel, nil
}

// GetByEndpoints retrieves a tunnel by its local IP, remote IP, and VNI.
// Returns ErrTunnelNotFound if no tunnel with the endpoints exists.
func (d *TunnelDAO) GetByEndpoints(
	ctx context.Context,
	localIP, remoteIP netip.Addr,
	vni uint32,
) (*TunnelState, error) {
	if !localIP.IsValid() {
		return nil, ErrInvalidTunnelID{TunnelID: "", Reason: "valid local IP is required"}
	}
	if !remoteIP.IsValid() {
		return nil, ErrInvalidTunnelID{TunnelID: "", Reason: "valid remote IP is required"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	tunnels, err := d.List(ctx)
	if err != nil {
		return nil, err
	}

	for _, tunnel := range tunnels {
		if tunnel.LocalIP == localIP && tunnel.RemoteIP == remoteIP && tunnel.VNI == vni {
			return tunnel, nil
		}
	}

	return nil, ErrTunnelNotFound{TunnelID: ""}
}

// Update modifies an existing tunnel with optimistic locking.
// Returns ErrTunnelNotFound if the tunnel does not exist.
// Returns ErrVersionConflict if the expected version does not match.
func (d *TunnelDAO) Update(
	ctx context.Context,
	tunnelID string,
	updates *TunnelState,
	expectedVersion uint64,
) error {
	if tunnelID == "" {
		return ErrInvalidTunnelID{TunnelID: "", Reason: "tunnel ID is required"}
	}
	if updates == nil {
		return ErrNilEntity{EntityType: entityTypeTunnel}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := hashString(tunnelID)

	// Get current state for version check
	data, found, err := d.storage.Get(ctx, entityTypeTunnel, entityID, d.shardID)
	if err != nil {
		return ErrOperationFailed{Operation: "update_tunnel_get", Cause: err}
	}
	if !found {
		return ErrTunnelNotFound{TunnelID: tunnelID}
	}

	var current TunnelState
	if err := json.Unmarshal(data, &current); err != nil {
		return ErrDeserializationFailed{EntityType: entityTypeTunnel, Cause: err}
	}

	// Check version for optimistic locking
	if current.Version != expectedVersion {
		return ErrVersionConflict{
			EntityType:      entityTypeTunnel,
			EntityID:        tunnelID,
			ExpectedVersion: expectedVersion,
			ActualVersion:   current.Version,
		}
	}

	// Apply updates while preserving immutable fields
	updates.ID = current.ID
	updates.LocalVTEP = current.LocalVTEP
	updates.RemoteVTEP = current.RemoteVTEP
	updates.CreatedAt = current.CreatedAt
	updates.UpdatedAt = time.Now()
	updates.Version = current.Version + 1

	newData, err := json.Marshal(updates)
	if err != nil {
		return ErrSerializationFailed{EntityType: entityTypeTunnel, Cause: err}
	}

	if err := d.storage.Put(ctx, entityTypeTunnel, entityID, newData, d.shardID); err != nil {
		return ErrOperationFailed{Operation: "update_tunnel", Cause: err}
	}

	d.logger.Debug("Tunnel updated", "id", tunnelID, "version", updates.Version)
	return nil
}

// Delete removes a tunnel with optimistic locking.
// Returns ErrTunnelNotFound if the tunnel does not exist.
// Returns ErrVersionConflict if the expected version does not match.
func (d *TunnelDAO) Delete(ctx context.Context, tunnelID string, expectedVersion uint64) error {
	if tunnelID == "" {
		return ErrInvalidTunnelID{TunnelID: "", Reason: "tunnel ID is required"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := hashString(tunnelID)

	// Get current state for version check
	data, found, err := d.storage.Get(ctx, entityTypeTunnel, entityID, d.shardID)
	if err != nil {
		return ErrOperationFailed{Operation: "delete_tunnel_get", Cause: err}
	}
	if !found {
		return ErrTunnelNotFound{TunnelID: tunnelID}
	}

	var current TunnelState
	if err := json.Unmarshal(data, &current); err != nil {
		return ErrDeserializationFailed{EntityType: entityTypeTunnel, Cause: err}
	}

	// Check version for optimistic locking
	if current.Version != expectedVersion {
		return ErrVersionConflict{
			EntityType:      entityTypeTunnel,
			EntityID:        tunnelID,
			ExpectedVersion: expectedVersion,
			ActualVersion:   current.Version,
		}
	}

	if err := d.storage.Delete(ctx, entityTypeTunnel, entityID, d.shardID); err != nil {
		return ErrOperationFailed{Operation: "delete_tunnel", Cause: err}
	}

	d.logger.Debug("Tunnel deleted", "id", tunnelID)
	return nil
}

// List retrieves all tunnels from the database.
func (d *TunnelDAO) List(ctx context.Context) ([]*TunnelState, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	var tunnels []*TunnelState
	pageToken := ""

	for {
		entities, nextToken, err := d.storage.List(ctx, entityTypeTunnel, 1000, pageToken, d.shardID)
		if err != nil {
			return nil, ErrOperationFailed{Operation: "list_tunnels", Cause: err}
		}

		for _, entity := range entities {
			var tunnel TunnelState
			if err := json.Unmarshal(entity.Data, &tunnel); err != nil {
				d.logger.Warn("Failed to deserialize tunnel", "id", entity.ID, "error", err)
				continue
			}
			tunnels = append(tunnels, &tunnel)
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return tunnels, nil
}

// ListByVTEP retrieves all tunnels associated with a specific VTEP (local or remote).
func (d *TunnelDAO) ListByVTEP(ctx context.Context, vtepID string) ([]*TunnelState, error) {
	if vtepID == "" {
		return nil, ErrInvalidVTEPID{VTEPID: "", Reason: "VTEP ID is required"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	var tunnels []*TunnelState
	pageToken := ""

	for {
		entities, nextToken, err := d.storage.List(ctx, entityTypeTunnel, 1000, pageToken, d.shardID)
		if err != nil {
			return nil, ErrOperationFailed{Operation: "list_tunnels_by_vtep", Cause: err}
		}

		for _, entity := range entities {
			var tunnel TunnelState
			if err := json.Unmarshal(entity.Data, &tunnel); err != nil {
				d.logger.Warn("Failed to deserialize tunnel", "id", entity.ID, "error", err)
				continue
			}
			if tunnel.LocalVTEP == vtepID || tunnel.RemoteVTEP == vtepID {
				tunnels = append(tunnels, &tunnel)
			}
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return tunnels, nil
}

// ListByVNI retrieves all tunnels with a specific VNI.
func (d *TunnelDAO) ListByVNI(ctx context.Context, vni uint32) ([]*TunnelState, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	var tunnels []*TunnelState
	pageToken := ""

	for {
		entities, nextToken, err := d.storage.List(ctx, entityTypeTunnel, 1000, pageToken, d.shardID)
		if err != nil {
			return nil, ErrOperationFailed{Operation: "list_tunnels_by_vni", Cause: err}
		}

		for _, entity := range entities {
			var tunnel TunnelState
			if err := json.Unmarshal(entity.Data, &tunnel); err != nil {
				d.logger.Warn("Failed to deserialize tunnel", "id", entity.ID, "error", err)
				continue
			}
			if tunnel.VNI == vni {
				tunnels = append(tunnels, &tunnel)
			}
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return tunnels, nil
}

// ListByNode retrieves all tunnels owned by a specific node.
func (d *TunnelDAO) ListByNode(ctx context.Context, nodeID uint64) ([]*TunnelState, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	var tunnels []*TunnelState
	pageToken := ""

	for {
		entities, nextToken, err := d.storage.List(ctx, entityTypeTunnel, 1000, pageToken, d.shardID)
		if err != nil {
			return nil, ErrOperationFailed{Operation: "list_tunnels_by_node", Cause: err}
		}

		for _, entity := range entities {
			var tunnel TunnelState
			if err := json.Unmarshal(entity.Data, &tunnel); err != nil {
				d.logger.Warn("Failed to deserialize tunnel", "id", entity.ID, "error", err)
				continue
			}
			if tunnel.NodeID == nodeID {
				tunnels = append(tunnels, &tunnel)
			}
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return tunnels, nil
}

// Count returns the total number of tunnels.
func (d *TunnelDAO) Count(ctx context.Context) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	count := 0
	pageToken := ""

	for {
		entities, nextToken, err := d.storage.List(ctx, entityTypeTunnel, 1000, pageToken, d.shardID)
		if err != nil {
			return 0, ErrOperationFailed{Operation: "count_tunnels", Cause: err}
		}

		count += len(entities)

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return count, nil
}

// Exists checks if a tunnel exists by its ID.
func (d *TunnelDAO) Exists(ctx context.Context, tunnelID string) (bool, error) {
	if tunnelID == "" {
		return false, ErrInvalidTunnelID{TunnelID: "", Reason: "tunnel ID is required"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := hashString(tunnelID)

	_, found, err := d.storage.Get(ctx, entityTypeTunnel, entityID, d.shardID)
	if err != nil {
		return false, ErrOperationFailed{Operation: "exists_tunnel", Cause: err}
	}

	return found, nil
}
