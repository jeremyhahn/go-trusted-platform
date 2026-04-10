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
	"hash/fnv"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// CurrentCRLID is the conventional ID used for the current/active CRL.
const CurrentCRLID = "current"

// CRLDAO provides QuicBaaS-backed storage for CRL entities.
// It implements CRUD operations with optimistic locking and tenant isolation.
//
// Thread Safety: All methods are thread-safe as they delegate to the
// underlying QuicBaaS service which handles concurrency internally.
type CRLDAO struct {
	storage                 DAOStorage
	logger                  *logging.Logger
	requestTimeout          time.Duration
	enableOptimisticLocking bool
}

// CRLDAOOption is a functional option for configuring CRLDAO.
type CRLDAOOption func(*crlDAOConfig)

type crlDAOConfig struct {
	requestTimeout          time.Duration
	enableOptimisticLocking bool
}

// WithCRLRequestTimeout sets the request timeout for DAO operations.
func WithCRLRequestTimeout(timeout time.Duration) CRLDAOOption {
	return func(c *crlDAOConfig) {
		c.requestTimeout = timeout
	}
}

// WithCRLOptimisticLocking enables or disables optimistic locking.
func WithCRLOptimisticLocking(enabled bool) CRLDAOOption {
	return func(c *crlDAOConfig) {
		c.enableOptimisticLocking = enabled
	}
}

// NewCRLDAO creates a new CRLDAO.
func NewCRLDAO(
	storage DAOStorage,
	logger *logging.Logger,
	opts ...CRLDAOOption,
) *CRLDAO {
	cfg := &crlDAOConfig{
		requestTimeout:          DefaultRequestTimeout,
		enableOptimisticLocking: true,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	return &CRLDAO{
		storage:                 storage,
		logger:                  logger,
		requestTimeout:          cfg.requestTimeout,
		enableOptimisticLocking: cfg.enableOptimisticLocking,
	}
}

// Create stores a new CRL in the database.
// This will overwrite any existing CRL with the same ID.
func (d *CRLDAO) Create(ctx context.Context, crl *CRL) error {
	if crl == nil {
		return ErrInvalidInput{Field: "crl", Reason: "cannot be nil"}
	}
	if crl.CRLID == "" {
		return ErrInvalidInput{Field: "crl_id", Reason: "cannot be empty"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := crlIDToEntityID(crl.CRLID, crl.TenantID)
	crl.SetEntityID(entityID)

	// Set initial version
	crl.Version = 1

	data, err := json.Marshal(crl)
	if err != nil {
		return ErrInvalidCRL{Reason: "serialization failed", Cause: err}
	}

	if err := d.storage.Put(ctx, EntityTypeCRL, entityID, data, DefaultShardID); err != nil {
		return ErrOperationFailed{Operation: "create CRL", Cause: err}
	}

	d.logger.Debug("CRL created",
		"id", crl.CRLID,
		"issuer", crl.Issuer,
		"tenant", crl.TenantID)

	return nil
}

// Get retrieves a CRL by ID and tenant ID.
// Returns ErrCRLNotFound if the CRL does not exist.
func (d *CRLDAO) Get(ctx context.Context, crlID string, tenantID string) (*CRL, error) {
	if crlID == "" {
		return nil, ErrInvalidInput{Field: "crl_id", Reason: "cannot be empty"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := crlIDToEntityID(crlID, tenantID)

	data, found, err := d.storage.Get(ctx, EntityTypeCRL, entityID, DefaultShardID)
	if err != nil {
		return nil, ErrOperationFailed{Operation: "get CRL", Cause: err}
	}
	if !found {
		return nil, ErrCRLNotFound{CRLID: crlID, TenantID: tenantID}
	}

	var crl CRL
	if err := json.Unmarshal(data, &crl); err != nil {
		return nil, ErrInvalidCRL{Reason: "deserialization failed", Cause: err}
	}

	crl.SetEntityID(entityID)
	return &crl, nil
}

// GetCurrent retrieves the current CRL for a tenant.
// Returns ErrCRLNotFound if no current CRL exists.
func (d *CRLDAO) GetCurrent(ctx context.Context, tenantID string) (*CRL, error) {
	return d.Get(ctx, CurrentCRLID, tenantID)
}

// Update updates an existing CRL.
// Returns ErrCRLNotFound if the CRL does not exist.
// Returns ErrVersionConflict if optimistic locking is enabled and version mismatch occurs.
func (d *CRLDAO) Update(ctx context.Context, crl *CRL) error {
	if crl == nil {
		return ErrInvalidInput{Field: "crl", Reason: "cannot be nil"}
	}
	if crl.CRLID == "" {
		return ErrInvalidInput{Field: "crl_id", Reason: "cannot be empty"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := crlIDToEntityID(crl.CRLID, crl.TenantID)

	// Get current version for optimistic locking
	data, found, err := d.storage.Get(ctx, EntityTypeCRL, entityID, DefaultShardID)
	if err != nil {
		return ErrOperationFailed{Operation: "update CRL", Cause: err}
	}
	if !found {
		return ErrCRLNotFound{CRLID: crl.CRLID, TenantID: crl.TenantID}
	}

	if d.enableOptimisticLocking {
		var existing CRL
		if err := json.Unmarshal(data, &existing); err != nil {
			return ErrInvalidCRL{Reason: "deserialization failed", Cause: err}
		}

		if crl.Version != existing.Version {
			return ErrVersionConflict{
				EntityType:      EntityTypeCRL,
				EntityID:        crl.CRLID,
				ExpectedVersion: crl.Version,
				ActualVersion:   existing.Version,
			}
		}
	}

	// Increment version
	crl.Version++
	crl.SetEntityID(entityID)

	updatedData, err := json.Marshal(crl)
	if err != nil {
		return ErrInvalidCRL{Reason: "serialization failed", Cause: err}
	}

	if err := d.storage.Put(ctx, EntityTypeCRL, entityID, updatedData, DefaultShardID); err != nil {
		return ErrOperationFailed{Operation: "update CRL", Cause: err}
	}

	d.logger.Debug("CRL updated",
		"id", crl.CRLID,
		"version", crl.Version)

	return nil
}

// Delete removes a CRL from storage.
// Returns ErrCRLNotFound if the CRL does not exist.
func (d *CRLDAO) Delete(ctx context.Context, crlID string, tenantID string) error {
	if crlID == "" {
		return ErrInvalidInput{Field: "crl_id", Reason: "cannot be empty"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := crlIDToEntityID(crlID, tenantID)

	// Verify CRL exists
	_, found, err := d.storage.Get(ctx, EntityTypeCRL, entityID, DefaultShardID)
	if err != nil {
		return ErrOperationFailed{Operation: "delete CRL", Cause: err}
	}
	if !found {
		return ErrCRLNotFound{CRLID: crlID, TenantID: tenantID}
	}

	if err := d.storage.Delete(ctx, EntityTypeCRL, entityID, DefaultShardID); err != nil {
		return ErrOperationFailed{Operation: "delete CRL", Cause: err}
	}

	d.logger.Debug("CRL deleted", "id", crlID)
	return nil
}

// List retrieves all CRLs for a tenant.
func (d *CRLDAO) List(ctx context.Context, tenantID string) ([]*CRL, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	var crls []*CRL
	pageToken := ""

	for {
		entities, nextToken, err := d.storage.List(ctx, EntityTypeCRL, 100, pageToken, DefaultShardID)
		if err != nil {
			return nil, ErrOperationFailed{Operation: "list CRLs", Cause: err}
		}

		for _, entity := range entities {
			var crl CRL
			if err := json.Unmarshal(entity.Data, &crl); err != nil {
				d.logger.Warn("Failed to deserialize CRL",
					"id", entity.ID,
					"error", err)
				continue
			}

			// Filter by tenant if specified
			if tenantID != "" && crl.TenantID != tenantID {
				continue
			}

			crl.SetEntityID(entity.ID)
			crls = append(crls, &crl)
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return crls, nil
}

// SaveCurrent saves a CRL as the current CRL for a tenant.
// This is a convenience method that sets the CRLID to CurrentCRLID and calls Create.
func (d *CRLDAO) SaveCurrent(ctx context.Context, crl *CRL) error {
	crl.CRLID = CurrentCRLID
	return d.Create(ctx, crl)
}

// Count returns the total number of CRLs for a tenant.
func (d *CRLDAO) Count(ctx context.Context, tenantID string) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	count := 0
	pageToken := ""

	for {
		entities, nextToken, err := d.storage.List(ctx, EntityTypeCRL, 1000, pageToken, DefaultShardID)
		if err != nil {
			return 0, ErrOperationFailed{Operation: "count CRLs", Cause: err}
		}

		if tenantID == "" {
			count += len(entities)
		} else {
			for _, entity := range entities {
				var crl CRL
				if err := json.Unmarshal(entity.Data, &crl); err != nil {
					continue
				}
				if crl.TenantID == tenantID {
					count++
				}
			}
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return count, nil
}

// crlIDToEntityID converts a CRL ID and tenant ID to a QuicBaaS entity ID.
// Uses FNV-1a hashing for fast, deterministic conversion.
// Combines CRLID and TenantID to ensure tenant isolation.
func crlIDToEntityID(crlID, tenantID string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(tenantID))
	h.Write([]byte("/"))
	h.Write([]byte(crlID))
	return h.Sum64()
}
