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
	"math/big"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// DefaultRequestTimeout is the default timeout for DAO operations.
const DefaultRequestTimeout = 30 * time.Second

// DefaultShardID is the default shard ID used for storage operations.
const DefaultShardID = uint64(0)

// CertificateDAO provides QuicBaaS-backed storage for Certificate entities.
// It implements CRUD operations with optimistic locking and tenant isolation.
//
// Thread Safety: All methods are thread-safe as they delegate to the
// underlying QuicBaaS service which handles concurrency internally.
type CertificateDAO struct {
	storage                 DAOStorage
	logger                  *logging.Logger
	requestTimeout          time.Duration
	enableOptimisticLocking bool
}

// DAOStorage defines the interface for storage operations required by DAOs.
// This interface enables dependency injection and testing.
type DAOStorage interface {
	Put(ctx context.Context, entityType string, id uint64, data []byte, shardID uint64) error
	Get(ctx context.Context, entityType string, id uint64, shardID uint64) ([]byte, bool, error)
	Delete(ctx context.Context, entityType string, id uint64, shardID uint64) error
	List(ctx context.Context, entityType string, pageSize uint64, pageToken string, shardID uint64) ([]*service.Entity, string, error)
	Query(ctx context.Context, entityType, indexField string, value []byte, shardID uint64) ([]*service.Entity, error)
}

// CertificateDAOOption is a functional option for configuring CertificateDAO.
type CertificateDAOOption func(*certificateDAOConfig)

type certificateDAOConfig struct {
	requestTimeout          time.Duration
	enableOptimisticLocking bool
}

// WithCertificateRequestTimeout sets the request timeout for DAO operations.
func WithCertificateRequestTimeout(timeout time.Duration) CertificateDAOOption {
	return func(c *certificateDAOConfig) {
		c.requestTimeout = timeout
	}
}

// WithCertificateOptimisticLocking enables or disables optimistic locking.
func WithCertificateOptimisticLocking(enabled bool) CertificateDAOOption {
	return func(c *certificateDAOConfig) {
		c.enableOptimisticLocking = enabled
	}
}

// NewCertificateDAO creates a new CertificateDAO.
func NewCertificateDAO(
	storage DAOStorage,
	logger *logging.Logger,
	opts ...CertificateDAOOption,
) *CertificateDAO {
	cfg := &certificateDAOConfig{
		requestTimeout:          DefaultRequestTimeout,
		enableOptimisticLocking: true,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	return &CertificateDAO{
		storage:                 storage,
		logger:                  logger,
		requestTimeout:          cfg.requestTimeout,
		enableOptimisticLocking: cfg.enableOptimisticLocking,
	}
}

// Create stores a new certificate in the database.
// Returns ErrCertificateAlreadyExists if a certificate with the same serial exists.
func (d *CertificateDAO) Create(ctx context.Context, cert *Certificate) error {
	if cert == nil {
		return ErrInvalidInput{Field: "certificate", Reason: "cannot be nil"}
	}
	if cert.SerialNumber == nil {
		return ErrInvalidInput{Field: "serial_number", Reason: "cannot be nil"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	// Generate entity ID from serial number
	entityID := serialToEntityID(cert.SerialNumber)
	cert.SetEntityID(entityID)

	// Check if certificate already exists
	_, found, err := d.storage.Get(ctx, EntityTypeCertificate, entityID, DefaultShardID)
	if err != nil {
		return ErrOperationFailed{Operation: "create certificate", Cause: err}
	}
	if found {
		return ErrCertificateAlreadyExists{
			SerialNumber: cert.SerialNumber.Text(16),
			TenantID:     cert.TenantID,
		}
	}

	// Set initial version
	cert.Version = 1

	// Serialize and store
	data, err := json.Marshal(cert)
	if err != nil {
		return ErrInvalidCertificate{Reason: "serialization failed", Cause: err}
	}

	if err := d.storage.Put(ctx, EntityTypeCertificate, entityID, data, DefaultShardID); err != nil {
		return ErrOperationFailed{Operation: "create certificate", Cause: err}
	}

	d.logger.Debug("Certificate created",
		"serial", cert.SerialNumber.Text(16),
		"subject", cert.Subject,
		"tenant", cert.TenantID)

	return nil
}

// Get retrieves a certificate by serial number and tenant ID.
// Returns ErrCertificateNotFound if the certificate does not exist.
// Returns ErrTenantMismatch if the certificate belongs to a different tenant.
func (d *CertificateDAO) Get(ctx context.Context, serialNumber *big.Int, tenantID string) (*Certificate, error) {
	if serialNumber == nil {
		return nil, ErrInvalidInput{Field: "serial_number", Reason: "cannot be nil"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := serialToEntityID(serialNumber)

	data, found, err := d.storage.Get(ctx, EntityTypeCertificate, entityID, DefaultShardID)
	if err != nil {
		return nil, ErrOperationFailed{Operation: "get certificate", Cause: err}
	}
	if !found {
		return nil, ErrCertificateNotFound{
			SerialNumber: serialNumber.Text(16),
			TenantID:     tenantID,
		}
	}

	var cert Certificate
	if err := json.Unmarshal(data, &cert); err != nil {
		return nil, ErrInvalidCertificate{Reason: "deserialization failed", Cause: err}
	}

	// Verify tenant isolation (empty tenantID means admin access)
	if tenantID != "" && cert.TenantID != tenantID {
		return nil, ErrTenantMismatch{
			EntityType:     EntityTypeCertificate,
			EntityID:       serialNumber.Text(16),
			ExpectedTenant: tenantID,
			ActualTenant:   cert.TenantID,
		}
	}

	cert.SetEntityID(entityID)
	return &cert, nil
}

// Update updates an existing certificate.
// Returns ErrCertificateNotFound if the certificate does not exist.
// Returns ErrVersionConflict if optimistic locking is enabled and version mismatch occurs.
func (d *CertificateDAO) Update(ctx context.Context, cert *Certificate) error {
	if cert == nil {
		return ErrInvalidInput{Field: "certificate", Reason: "cannot be nil"}
	}
	if cert.SerialNumber == nil {
		return ErrInvalidInput{Field: "serial_number", Reason: "cannot be nil"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := serialToEntityID(cert.SerialNumber)

	// Get current version for optimistic locking
	data, found, err := d.storage.Get(ctx, EntityTypeCertificate, entityID, DefaultShardID)
	if err != nil {
		return ErrOperationFailed{Operation: "update certificate", Cause: err}
	}
	if !found {
		return ErrCertificateNotFound{
			SerialNumber: cert.SerialNumber.Text(16),
			TenantID:     cert.TenantID,
		}
	}

	if d.enableOptimisticLocking {
		var existing Certificate
		if err := json.Unmarshal(data, &existing); err != nil {
			return ErrInvalidCertificate{Reason: "deserialization failed", Cause: err}
		}

		if cert.Version != existing.Version {
			return ErrVersionConflict{
				EntityType:      EntityTypeCertificate,
				EntityID:        cert.SerialNumber.Text(16),
				ExpectedVersion: cert.Version,
				ActualVersion:   existing.Version,
			}
		}
	}

	// Increment version
	cert.Version++
	cert.SetEntityID(entityID)

	// Serialize and store
	updatedData, err := json.Marshal(cert)
	if err != nil {
		return ErrInvalidCertificate{Reason: "serialization failed", Cause: err}
	}

	if err := d.storage.Put(ctx, EntityTypeCertificate, entityID, updatedData, DefaultShardID); err != nil {
		return ErrOperationFailed{Operation: "update certificate", Cause: err}
	}

	d.logger.Debug("Certificate updated",
		"serial", cert.SerialNumber.Text(16),
		"version", cert.Version)

	return nil
}

// Delete removes a certificate from storage.
// Returns ErrCertificateNotFound if the certificate does not exist.
func (d *CertificateDAO) Delete(ctx context.Context, serialNumber *big.Int, tenantID string) error {
	if serialNumber == nil {
		return ErrInvalidInput{Field: "serial_number", Reason: "cannot be nil"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := serialToEntityID(serialNumber)

	// Verify certificate exists and tenant matches
	data, found, err := d.storage.Get(ctx, EntityTypeCertificate, entityID, DefaultShardID)
	if err != nil {
		return ErrOperationFailed{Operation: "delete certificate", Cause: err}
	}
	if !found {
		return ErrCertificateNotFound{
			SerialNumber: serialNumber.Text(16),
			TenantID:     tenantID,
		}
	}

	// Verify tenant isolation
	if tenantID != "" {
		var cert Certificate
		if err := json.Unmarshal(data, &cert); err != nil {
			return ErrInvalidCertificate{Reason: "deserialization failed", Cause: err}
		}
		if cert.TenantID != tenantID {
			return ErrTenantMismatch{
				EntityType:     EntityTypeCertificate,
				EntityID:       serialNumber.Text(16),
				ExpectedTenant: tenantID,
				ActualTenant:   cert.TenantID,
			}
		}
	}

	if err := d.storage.Delete(ctx, EntityTypeCertificate, entityID, DefaultShardID); err != nil {
		return ErrOperationFailed{Operation: "delete certificate", Cause: err}
	}

	d.logger.Debug("Certificate deleted", "serial", serialNumber.Text(16))
	return nil
}

// List retrieves certificates with pagination support.
// If tenantID is empty, returns certificates for all tenants (admin operation).
func (d *CertificateDAO) List(
	ctx context.Context,
	tenantID string,
	pageSize int,
	pageToken string,
) ([]*Certificate, string, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	if pageSize <= 0 {
		pageSize = 100
	}

	entities, nextToken, err := d.storage.List(ctx, EntityTypeCertificate, uint64(pageSize), pageToken, DefaultShardID)
	if err != nil {
		return nil, "", ErrOperationFailed{Operation: "list certificates", Cause: err}
	}

	certificates := make([]*Certificate, 0, len(entities))
	for _, entity := range entities {
		var cert Certificate
		if err := json.Unmarshal(entity.Data, &cert); err != nil {
			d.logger.Warn("Failed to deserialize certificate",
				"id", entity.ID,
				"error", err)
			continue
		}

		// Filter by tenant if specified
		if tenantID != "" && cert.TenantID != tenantID {
			continue
		}

		cert.SetEntityID(entity.ID)
		certificates = append(certificates, &cert)
	}

	return certificates, nextToken, nil
}

// ListValid retrieves all non-revoked, non-expired certificates for a tenant.
func (d *CertificateDAO) ListValid(ctx context.Context, tenantID string) ([]*Certificate, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	var certificates []*Certificate
	pageToken := ""

	for {
		entities, nextToken, err := d.storage.List(ctx, EntityTypeCertificate, 1000, pageToken, DefaultShardID)
		if err != nil {
			return nil, ErrOperationFailed{Operation: "list valid certificates", Cause: err}
		}

		for _, entity := range entities {
			var cert Certificate
			if err := json.Unmarshal(entity.Data, &cert); err != nil {
				d.logger.Warn("Failed to deserialize certificate",
					"id", entity.ID,
					"error", err)
				continue
			}

			// Filter by tenant if specified
			if tenantID != "" && cert.TenantID != tenantID {
				continue
			}

			// Only include valid certificates
			if cert.IsValid() {
				cert.SetEntityID(entity.ID)
				certificates = append(certificates, &cert)
			}
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return certificates, nil
}

// Revoke marks a certificate as revoked.
// Returns ErrCertificateNotFound if the certificate does not exist.
// Returns ErrCertificateAlreadyRevoked if already revoked.
func (d *CertificateDAO) Revoke(
	ctx context.Context,
	serialNumber *big.Int,
	reason int,
	tenantID string,
) error {
	cert, err := d.Get(ctx, serialNumber, tenantID)
	if err != nil {
		return err
	}

	if cert.IsRevoked() {
		return ErrCertificateAlreadyRevoked{
			SerialNumber: serialNumber.Text(16),
			RevokedAt:    cert.RevokedAt.Format(time.RFC3339),
		}
	}

	now := time.Now().UTC()
	cert.RevokedAt = &now
	cert.RevocationReason = reason

	return d.Update(ctx, cert)
}

// CleanupExpired removes expired certificates that are past the grace period.
// Returns the number of certificates deleted.
func (d *CertificateDAO) CleanupExpired(
	ctx context.Context,
	tenantID string,
	gracePeriod time.Duration,
) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout*10) // Extended timeout for cleanup
	defer cancel()

	cutoff := time.Now().UTC().Add(-gracePeriod)
	var deletedCount int
	pageToken := ""

	for {
		entities, nextToken, err := d.storage.List(ctx, EntityTypeCertificate, 1000, pageToken, DefaultShardID)
		if err != nil {
			return deletedCount, ErrOperationFailed{Operation: "cleanup expired certificates", Cause: err}
		}

		for _, entity := range entities {
			var cert Certificate
			if err := json.Unmarshal(entity.Data, &cert); err != nil {
				d.logger.Warn("Failed to deserialize certificate during cleanup",
					"id", entity.ID,
					"error", err)
				continue
			}

			// Filter by tenant if specified
			if tenantID != "" && cert.TenantID != tenantID {
				continue
			}

			// Delete if expired and past grace period
			if cert.NotAfter.Before(cutoff) {
				if err := d.storage.Delete(ctx, EntityTypeCertificate, entity.ID, DefaultShardID); err != nil {
					d.logger.Warn("Failed to delete expired certificate",
						"serial", cert.SerialNumber.Text(16),
						"error", err)
					continue
				}
				deletedCount++
			}
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return deletedCount, nil
}

// Count returns the total number of certificates for a tenant.
func (d *CertificateDAO) Count(ctx context.Context, tenantID string) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	count := 0
	pageToken := ""

	for {
		entities, nextToken, err := d.storage.List(ctx, EntityTypeCertificate, 1000, pageToken, DefaultShardID)
		if err != nil {
			return 0, ErrOperationFailed{Operation: "count certificates", Cause: err}
		}

		if tenantID == "" {
			count += len(entities)
		} else {
			for _, entity := range entities {
				var cert Certificate
				if err := json.Unmarshal(entity.Data, &cert); err != nil {
					continue
				}
				if cert.TenantID == tenantID {
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

// serialToEntityID converts a certificate serial number to a QuicBaaS entity ID.
// Uses FNV-1a hashing for fast, deterministic conversion.
func serialToEntityID(serial *big.Int) uint64 {
	h := fnv.New64a()
	h.Write(serial.Bytes())
	return h.Sum64()
}
