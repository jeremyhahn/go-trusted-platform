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
	"math/big"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// QuicBaaSStorage implements the Storage interface from operations.go.
// It coordinates the CertificateDAO, CRLDAO, and ACMEDAO to provide
// a unified storage layer for cluster-aware CA operations.
//
// Thread Safety: All operations are thread-safe as they delegate to
// individual DAOs which handle concurrency internally.
type QuicBaaSStorage struct {
	config         *Config
	logger         *logging.Logger
	certDAO        *CertificateDAO
	crlDAO         *CRLDAO
	acmeDAO        *ACMEDAO
	requestTimeout time.Duration

	// Statistics for monitoring
	stats StorageStats
}

// StorageStats provides statistics about storage operations.
type StorageStats struct {
	CertificatesCreated   atomic.Uint64
	CertificatesRetrieved atomic.Uint64
	CertificatesUpdated   atomic.Uint64
	CertificatesDeleted   atomic.Uint64
	CertificatesRevoked   atomic.Uint64
	CRLsCreated           atomic.Uint64
	CRLsRetrieved         atomic.Uint64
	CRLsUpdated           atomic.Uint64
	ACMEAccountsCreated   atomic.Uint64
	ACMEOrdersCreated     atomic.Uint64
	ACMEAuthzCreated      atomic.Uint64
	CleanupOperations     atomic.Uint64
	TotalErrors           atomic.Uint64
}

// StorageOption is a functional option for configuring QuicBaaSStorage.
type StorageOption func(*storageConfig)

type storageConfig struct {
	requestTimeout time.Duration
}

// WithStorageRequestTimeout sets the request timeout for storage operations.
func WithStorageRequestTimeout(timeout time.Duration) StorageOption {
	return func(c *storageConfig) {
		c.requestTimeout = timeout
	}
}

// NewQuicBaaSStorage creates a new QuicBaaSStorage.
func NewQuicBaaSStorage(
	storage DAOStorage,
	config *Config,
	logger *logging.Logger,
	opts ...StorageOption,
) (*QuicBaaSStorage, error) {
	if storage == nil {
		return nil, ErrInvalidInput{Field: "storage", Reason: "cannot be nil"}
	}
	if config == nil {
		return nil, ErrInvalidInput{Field: "config", Reason: "cannot be nil"}
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if logger == nil {
		return nil, ErrInvalidInput{Field: "logger", Reason: "cannot be nil"}
	}

	cfg := &storageConfig{
		requestTimeout: DefaultRequestTimeout,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	// Create DAOs with shared configuration
	certDAO := NewCertificateDAO(
		storage,
		logger,
		WithCertificateRequestTimeout(cfg.requestTimeout),
		WithCertificateOptimisticLocking(config.EnableOptimisticLocking),
	)

	crlDAO := NewCRLDAO(
		storage,
		logger,
		WithCRLRequestTimeout(cfg.requestTimeout),
		WithCRLOptimisticLocking(config.EnableOptimisticLocking),
	)

	acmeDAO := NewACMEDAO(
		storage,
		logger,
		WithACMERequestTimeout(cfg.requestTimeout),
		WithACMEOptimisticLocking(config.EnableOptimisticLocking),
	)

	return &QuicBaaSStorage{
		config:         config,
		logger:         logger,
		certDAO:        certDAO,
		crlDAO:         crlDAO,
		acmeDAO:        acmeDAO,
		requestTimeout: cfg.requestTimeout,
	}, nil
}

// ============================================================================
// Certificate Operations
// ============================================================================

// StoreCertificate persists an issued certificate to the cluster.
func (s *QuicBaaSStorage) StoreCertificate(ctx context.Context, cert *Certificate) error {
	err := s.certDAO.Create(ctx, cert)
	if err != nil {
		s.stats.TotalErrors.Add(1)
		return err
	}
	s.stats.CertificatesCreated.Add(1)
	return nil
}

// GetCertificate retrieves a certificate by serial number.
func (s *QuicBaaSStorage) GetCertificate(ctx context.Context, serialNumber *big.Int, tenantID string) (*Certificate, error) {
	cert, err := s.certDAO.Get(ctx, serialNumber, tenantID)
	if err != nil {
		s.stats.TotalErrors.Add(1)
		return nil, err
	}
	s.stats.CertificatesRetrieved.Add(1)
	return cert, nil
}

// ListCertificates returns all certificates with pagination support.
func (s *QuicBaaSStorage) ListCertificates(
	ctx context.Context,
	tenantID string,
	pageSize int,
	pageToken string,
) ([]*Certificate, string, error) {
	return s.certDAO.List(ctx, tenantID, pageSize, pageToken)
}

// ListValidCertificates returns all non-revoked, non-expired certificates.
func (s *QuicBaaSStorage) ListValidCertificates(ctx context.Context, tenantID string) ([]*Certificate, error) {
	return s.certDAO.ListValid(ctx, tenantID)
}

// RevokeCertificate marks a certificate as revoked with the given reason.
func (s *QuicBaaSStorage) RevokeCertificate(
	ctx context.Context,
	serialNumber *big.Int,
	reason int,
	tenantID string,
) error {
	err := s.certDAO.Revoke(ctx, serialNumber, reason, tenantID)
	if err != nil {
		s.stats.TotalErrors.Add(1)
		return err
	}
	s.stats.CertificatesRevoked.Add(1)
	return nil
}

// UpdateCertificate updates an existing certificate.
func (s *QuicBaaSStorage) UpdateCertificate(ctx context.Context, cert *Certificate) error {
	err := s.certDAO.Update(ctx, cert)
	if err != nil {
		s.stats.TotalErrors.Add(1)
		return err
	}
	s.stats.CertificatesUpdated.Add(1)
	return nil
}

// DeleteCertificate removes a certificate from storage.
func (s *QuicBaaSStorage) DeleteCertificate(ctx context.Context, serialNumber *big.Int, tenantID string) error {
	err := s.certDAO.Delete(ctx, serialNumber, tenantID)
	if err != nil {
		s.stats.TotalErrors.Add(1)
		return err
	}
	s.stats.CertificatesDeleted.Add(1)
	return nil
}

// ============================================================================
// CRL Operations
// ============================================================================

// StoreCRL persists a CRL to the cluster.
func (s *QuicBaaSStorage) StoreCRL(ctx context.Context, crl *CRL) error {
	err := s.crlDAO.Create(ctx, crl)
	if err != nil {
		s.stats.TotalErrors.Add(1)
		return err
	}
	s.stats.CRLsCreated.Add(1)
	return nil
}

// GetCRL retrieves a CRL by ID.
func (s *QuicBaaSStorage) GetCRL(ctx context.Context, crlID string, tenantID string) (*CRL, error) {
	crl, err := s.crlDAO.Get(ctx, crlID, tenantID)
	if err != nil {
		s.stats.TotalErrors.Add(1)
		return nil, err
	}
	s.stats.CRLsRetrieved.Add(1)
	return crl, nil
}

// GetCurrentCRL retrieves the most recent CRL.
func (s *QuicBaaSStorage) GetCurrentCRL(ctx context.Context, tenantID string) (*CRL, error) {
	crl, err := s.crlDAO.GetCurrent(ctx, tenantID)
	if err != nil {
		s.stats.TotalErrors.Add(1)
		return nil, err
	}
	s.stats.CRLsRetrieved.Add(1)
	return crl, nil
}

// UpdateCRL updates an existing CRL.
func (s *QuicBaaSStorage) UpdateCRL(ctx context.Context, crl *CRL) error {
	err := s.crlDAO.Update(ctx, crl)
	if err != nil {
		s.stats.TotalErrors.Add(1)
		return err
	}
	s.stats.CRLsUpdated.Add(1)
	return nil
}

// DeleteCRL removes a CRL from storage.
func (s *QuicBaaSStorage) DeleteCRL(ctx context.Context, crlID string, tenantID string) error {
	err := s.crlDAO.Delete(ctx, crlID, tenantID)
	if err != nil {
		s.stats.TotalErrors.Add(1)
		return err
	}
	return nil
}

// ============================================================================
// ACME Account Operations
// ============================================================================

// StoreACMEAccount persists an ACME account to the cluster.
func (s *QuicBaaSStorage) StoreACMEAccount(ctx context.Context, account *ACMEAccount) error {
	err := s.acmeDAO.CreateAccount(ctx, account)
	if err != nil {
		s.stats.TotalErrors.Add(1)
		return err
	}
	s.stats.ACMEAccountsCreated.Add(1)
	return nil
}

// GetACMEAccount retrieves an ACME account by ID.
func (s *QuicBaaSStorage) GetACMEAccount(ctx context.Context, accountID string, tenantID string) (*ACMEAccount, error) {
	account, err := s.acmeDAO.GetAccount(ctx, accountID, tenantID)
	if err != nil {
		s.stats.TotalErrors.Add(1)
		return nil, err
	}
	return account, nil
}

// UpdateACMEAccount updates an existing ACME account.
func (s *QuicBaaSStorage) UpdateACMEAccount(ctx context.Context, account *ACMEAccount) error {
	err := s.acmeDAO.UpdateAccount(ctx, account)
	if err != nil {
		s.stats.TotalErrors.Add(1)
		return err
	}
	return nil
}

// DeleteACMEAccount removes an ACME account from storage.
func (s *QuicBaaSStorage) DeleteACMEAccount(ctx context.Context, accountID string, tenantID string) error {
	err := s.acmeDAO.DeleteAccount(ctx, accountID, tenantID)
	if err != nil {
		s.stats.TotalErrors.Add(1)
		return err
	}
	return nil
}

// ============================================================================
// ACME Order Operations
// ============================================================================

// StoreACMEOrder persists an ACME order to the cluster.
func (s *QuicBaaSStorage) StoreACMEOrder(ctx context.Context, order *ACMEOrder) error {
	err := s.acmeDAO.CreateOrder(ctx, order)
	if err != nil {
		s.stats.TotalErrors.Add(1)
		return err
	}
	s.stats.ACMEOrdersCreated.Add(1)
	return nil
}

// GetACMEOrder retrieves an ACME order by ID.
func (s *QuicBaaSStorage) GetACMEOrder(ctx context.Context, orderID string, tenantID string) (*ACMEOrder, error) {
	order, err := s.acmeDAO.GetOrder(ctx, orderID, tenantID)
	if err != nil {
		s.stats.TotalErrors.Add(1)
		return nil, err
	}
	return order, nil
}

// ListACMEOrdersByAccount returns all orders for a given account.
func (s *QuicBaaSStorage) ListACMEOrdersByAccount(
	ctx context.Context,
	accountID string,
	tenantID string,
) ([]*ACMEOrder, error) {
	return s.acmeDAO.ListOrdersByAccount(ctx, accountID, tenantID)
}

// UpdateACMEOrder updates an existing ACME order.
func (s *QuicBaaSStorage) UpdateACMEOrder(ctx context.Context, order *ACMEOrder) error {
	err := s.acmeDAO.UpdateOrder(ctx, order)
	if err != nil {
		s.stats.TotalErrors.Add(1)
		return err
	}
	return nil
}

// DeleteACMEOrder removes an ACME order from storage.
func (s *QuicBaaSStorage) DeleteACMEOrder(ctx context.Context, orderID string, tenantID string) error {
	err := s.acmeDAO.DeleteOrder(ctx, orderID, tenantID)
	if err != nil {
		s.stats.TotalErrors.Add(1)
		return err
	}
	return nil
}

// ============================================================================
// ACME Authorization Operations
// ============================================================================

// StoreACMEAuthorization persists an ACME authorization to the cluster.
func (s *QuicBaaSStorage) StoreACMEAuthorization(ctx context.Context, authz *ACMEAuthorization) error {
	err := s.acmeDAO.CreateAuthorization(ctx, authz)
	if err != nil {
		s.stats.TotalErrors.Add(1)
		return err
	}
	s.stats.ACMEAuthzCreated.Add(1)
	return nil
}

// GetACMEAuthorization retrieves an ACME authorization by ID.
func (s *QuicBaaSStorage) GetACMEAuthorization(
	ctx context.Context,
	authzID string,
	tenantID string,
) (*ACMEAuthorization, error) {
	authz, err := s.acmeDAO.GetAuthorization(ctx, authzID, tenantID)
	if err != nil {
		s.stats.TotalErrors.Add(1)
		return nil, err
	}
	return authz, nil
}

// ListACMEAuthorizationsByOrder returns all authorizations for a given order.
func (s *QuicBaaSStorage) ListACMEAuthorizationsByOrder(
	ctx context.Context,
	orderID string,
	tenantID string,
) ([]*ACMEAuthorization, error) {
	return s.acmeDAO.ListAuthorizationsByOrder(ctx, orderID, tenantID)
}

// UpdateACMEAuthorization updates an existing ACME authorization.
func (s *QuicBaaSStorage) UpdateACMEAuthorization(ctx context.Context, authz *ACMEAuthorization) error {
	err := s.acmeDAO.UpdateAuthorization(ctx, authz)
	if err != nil {
		s.stats.TotalErrors.Add(1)
		return err
	}
	return nil
}

// DeleteACMEAuthorization removes an ACME authorization from storage.
func (s *QuicBaaSStorage) DeleteACMEAuthorization(ctx context.Context, authzID string, tenantID string) error {
	err := s.acmeDAO.DeleteAuthorization(ctx, authzID, tenantID)
	if err != nil {
		s.stats.TotalErrors.Add(1)
		return err
	}
	return nil
}

// ============================================================================
// Lifecycle and Maintenance Operations
// ============================================================================

// CleanupExpiredOrders removes expired ACME orders from storage.
func (s *QuicBaaSStorage) CleanupExpiredOrders(ctx context.Context, tenantID string) (int, error) {
	count, err := s.acmeDAO.CleanupExpiredOrders(ctx, tenantID)
	if err != nil {
		s.stats.TotalErrors.Add(1)
		return count, err
	}
	s.stats.CleanupOperations.Add(1)
	return count, nil
}

// CleanupExpiredAuthorizations removes expired ACME authorizations from storage.
func (s *QuicBaaSStorage) CleanupExpiredAuthorizations(ctx context.Context, tenantID string) (int, error) {
	count, err := s.acmeDAO.CleanupExpiredAuthorizations(ctx, tenantID)
	if err != nil {
		s.stats.TotalErrors.Add(1)
		return count, err
	}
	s.stats.CleanupOperations.Add(1)
	return count, nil
}

// CleanupExpiredCertificates removes expired certificates from storage.
func (s *QuicBaaSStorage) CleanupExpiredCertificates(
	ctx context.Context,
	tenantID string,
	gracePeriod time.Duration,
) (int, error) {
	count, err := s.certDAO.CleanupExpired(ctx, tenantID, gracePeriod)
	if err != nil {
		s.stats.TotalErrors.Add(1)
		return count, err
	}
	s.stats.CleanupOperations.Add(1)
	return count, nil
}

// ============================================================================
// Statistics and Monitoring
// ============================================================================

// GetStats returns a snapshot of storage statistics.
func (s *QuicBaaSStorage) GetStats() StorageStatsSnapshot {
	return StorageStatsSnapshot{
		CertificatesCreated:   s.stats.CertificatesCreated.Load(),
		CertificatesRetrieved: s.stats.CertificatesRetrieved.Load(),
		CertificatesUpdated:   s.stats.CertificatesUpdated.Load(),
		CertificatesDeleted:   s.stats.CertificatesDeleted.Load(),
		CertificatesRevoked:   s.stats.CertificatesRevoked.Load(),
		CRLsCreated:           s.stats.CRLsCreated.Load(),
		CRLsRetrieved:         s.stats.CRLsRetrieved.Load(),
		CRLsUpdated:           s.stats.CRLsUpdated.Load(),
		ACMEAccountsCreated:   s.stats.ACMEAccountsCreated.Load(),
		ACMEOrdersCreated:     s.stats.ACMEOrdersCreated.Load(),
		ACMEAuthzCreated:      s.stats.ACMEAuthzCreated.Load(),
		CleanupOperations:     s.stats.CleanupOperations.Load(),
		TotalErrors:           s.stats.TotalErrors.Load(),
	}
}

// StorageStatsSnapshot is a point-in-time snapshot of storage statistics.
type StorageStatsSnapshot struct {
	CertificatesCreated   uint64
	CertificatesRetrieved uint64
	CertificatesUpdated   uint64
	CertificatesDeleted   uint64
	CertificatesRevoked   uint64
	CRLsCreated           uint64
	CRLsRetrieved         uint64
	CRLsUpdated           uint64
	ACMEAccountsCreated   uint64
	ACMEOrdersCreated     uint64
	ACMEAuthzCreated      uint64
	CleanupOperations     uint64
	TotalErrors           uint64
}

// GetCertificateCount returns the total number of certificates.
func (s *QuicBaaSStorage) GetCertificateCount(ctx context.Context, tenantID string) (int, error) {
	return s.certDAO.Count(ctx, tenantID)
}

// GetCRLCount returns the total number of CRLs.
func (s *QuicBaaSStorage) GetCRLCount(ctx context.Context, tenantID string) (int, error) {
	return s.crlDAO.Count(ctx, tenantID)
}

// GetACMEAccountCount returns the total number of ACME accounts.
func (s *QuicBaaSStorage) GetACMEAccountCount(ctx context.Context, tenantID string) (int, error) {
	return s.acmeDAO.CountAccounts(ctx, tenantID)
}

// GetACMEOrderCount returns the total number of ACME orders.
func (s *QuicBaaSStorage) GetACMEOrderCount(ctx context.Context, tenantID string) (int, error) {
	return s.acmeDAO.CountOrders(ctx, tenantID)
}

// GetACMEAuthorizationCount returns the total number of ACME authorizations.
func (s *QuicBaaSStorage) GetACMEAuthorizationCount(ctx context.Context, tenantID string) (int, error) {
	return s.acmeDAO.CountAuthorizations(ctx, tenantID)
}

// Config returns the storage configuration.
func (s *QuicBaaSStorage) Config() *Config {
	return s.config
}

// Compile-time interface verification
var _ Storage = (*QuicBaaSStorage)(nil)
