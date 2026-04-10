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
	"crypto/x509"
	"math/big"
	"time"
)

// Storage defines the interface for cluster-wide CA state storage operations.
// Implementations must provide distributed storage with configurable consistency
// guarantees for certificate lifecycle management and ACME protocol support.
//
// All operations support multi-tenancy through the TenantID field in entities.
// Implementations should enforce tenant isolation at the storage layer.
type Storage interface {
	// Certificate Operations

	// StoreCertificate persists an issued certificate to the cluster.
	// Returns ErrCertificateAlreadyExists if a certificate with the same serial exists.
	StoreCertificate(ctx context.Context, cert *Certificate) error

	// GetCertificate retrieves a certificate by serial number.
	// Returns ErrCertificateNotFound if the certificate does not exist.
	GetCertificate(ctx context.Context, serialNumber *big.Int, tenantID string) (*Certificate, error)

	// ListCertificates returns all certificates with pagination support.
	// If tenantID is empty, returns certificates for all tenants (admin operation).
	ListCertificates(ctx context.Context, tenantID string, pageSize int, pageToken string) ([]*Certificate, string, error)

	// ListValidCertificates returns all non-revoked, non-expired certificates.
	// This is used for CRL generation and certificate inventory operations.
	ListValidCertificates(ctx context.Context, tenantID string) ([]*Certificate, error)

	// RevokeCertificate marks a certificate as revoked with the given reason.
	// Returns ErrCertificateNotFound if the certificate does not exist.
	// Returns ErrCertificateAlreadyRevoked if already revoked.
	RevokeCertificate(ctx context.Context, serialNumber *big.Int, reason int, tenantID string) error

	// UpdateCertificate updates an existing certificate (for metadata changes).
	// Returns ErrCertificateNotFound if the certificate does not exist.
	// Returns ErrVersionConflict if optimistic locking is enabled and version mismatch occurs.
	UpdateCertificate(ctx context.Context, cert *Certificate) error

	// DeleteCertificate removes a certificate from storage.
	// This should only be used for administrative cleanup, not normal revocation.
	// Returns ErrCertificateNotFound if the certificate does not exist.
	DeleteCertificate(ctx context.Context, serialNumber *big.Int, tenantID string) error

	// CRL Operations

	// StoreCRL persists a CRL to the cluster.
	// This overwrites any existing CRL with the same ID.
	StoreCRL(ctx context.Context, crl *CRL) error

	// GetCRL retrieves the current CRL.
	// Returns ErrCRLNotFound if no CRL exists.
	GetCRL(ctx context.Context, crlID string, tenantID string) (*CRL, error)

	// GetCurrentCRL retrieves the most recent CRL (convenience method).
	// Uses the conventional "current" CRL ID.
	// Returns ErrCRLNotFound if no current CRL exists.
	GetCurrentCRL(ctx context.Context, tenantID string) (*CRL, error)

	// UpdateCRL updates an existing CRL.
	// Returns ErrCRLNotFound if the CRL does not exist.
	// Returns ErrVersionConflict if optimistic locking is enabled and version mismatch occurs.
	UpdateCRL(ctx context.Context, crl *CRL) error

	// DeleteCRL removes a CRL from storage.
	// Returns ErrCRLNotFound if the CRL does not exist.
	DeleteCRL(ctx context.Context, crlID string, tenantID string) error

	// ACME Account Operations

	// StoreACMEAccount persists an ACME account to the cluster.
	// Returns ErrACMEAccountAlreadyExists if an account with the same ID exists.
	StoreACMEAccount(ctx context.Context, account *ACMEAccount) error

	// GetACMEAccount retrieves an ACME account by ID.
	// Returns ErrACMEAccountNotFound if the account does not exist.
	GetACMEAccount(ctx context.Context, accountID string, tenantID string) (*ACMEAccount, error)

	// UpdateACMEAccount updates an existing ACME account.
	// Returns ErrACMEAccountNotFound if the account does not exist.
	// Returns ErrVersionConflict if optimistic locking is enabled and version mismatch occurs.
	UpdateACMEAccount(ctx context.Context, account *ACMEAccount) error

	// DeleteACMEAccount removes an ACME account from storage.
	// Returns ErrACMEAccountNotFound if the account does not exist.
	DeleteACMEAccount(ctx context.Context, accountID string, tenantID string) error

	// ACME Order Operations

	// StoreACMEOrder persists an ACME order to the cluster.
	StoreACMEOrder(ctx context.Context, order *ACMEOrder) error

	// GetACMEOrder retrieves an ACME order by ID.
	// Returns ErrACMEOrderNotFound if the order does not exist.
	GetACMEOrder(ctx context.Context, orderID string, tenantID string) (*ACMEOrder, error)

	// ListACMEOrdersByAccount returns all orders for a given account.
	ListACMEOrdersByAccount(ctx context.Context, accountID string, tenantID string) ([]*ACMEOrder, error)

	// UpdateACMEOrder updates an existing ACME order.
	// Returns ErrACMEOrderNotFound if the order does not exist.
	// Returns ErrVersionConflict if optimistic locking is enabled and version mismatch occurs.
	UpdateACMEOrder(ctx context.Context, order *ACMEOrder) error

	// DeleteACMEOrder removes an ACME order from storage.
	// Returns ErrACMEOrderNotFound if the order does not exist.
	DeleteACMEOrder(ctx context.Context, orderID string, tenantID string) error

	// ACME Authorization Operations

	// StoreACMEAuthorization persists an ACME authorization to the cluster.
	StoreACMEAuthorization(ctx context.Context, authz *ACMEAuthorization) error

	// GetACMEAuthorization retrieves an ACME authorization by ID.
	// Returns ErrACMEAuthorizationNotFound if the authorization does not exist.
	GetACMEAuthorization(ctx context.Context, authzID string, tenantID string) (*ACMEAuthorization, error)

	// ListACMEAuthorizationsByOrder returns all authorizations for a given order.
	ListACMEAuthorizationsByOrder(ctx context.Context, orderID string, tenantID string) ([]*ACMEAuthorization, error)

	// UpdateACMEAuthorization updates an existing ACME authorization.
	// Returns ErrACMEAuthorizationNotFound if the authorization does not exist.
	// Returns ErrVersionConflict if optimistic locking is enabled and version mismatch occurs.
	UpdateACMEAuthorization(ctx context.Context, authz *ACMEAuthorization) error

	// DeleteACMEAuthorization removes an ACME authorization from storage.
	// Returns ErrACMEAuthorizationNotFound if the authorization does not exist.
	DeleteACMEAuthorization(ctx context.Context, authzID string, tenantID string) error

	// Lifecycle and Maintenance Operations

	// CleanupExpiredOrders removes expired ACME orders from storage.
	// Returns the number of orders deleted.
	CleanupExpiredOrders(ctx context.Context, tenantID string) (int, error)

	// CleanupExpiredAuthorizations removes expired ACME authorizations from storage.
	// Returns the number of authorizations deleted.
	CleanupExpiredAuthorizations(ctx context.Context, tenantID string) (int, error)

	// CleanupExpiredCertificates removes expired certificates from storage.
	// This should be used carefully as it permanently deletes certificate records.
	// Returns the number of certificates deleted.
	CleanupExpiredCertificates(ctx context.Context, tenantID string, gracePeriod time.Duration) (int, error)
}

// Operator defines high-level CA operations that orchestrate multiple storage operations.
// This interface provides business logic on top of the Storage interface, implementing
// complex workflows like CRL regeneration and ACME order processing.
type Operator interface {
	// RegenerateCRL creates a new CRL including all revoked certificates.
	// This is typically called periodically based on Config.CRLUpdateInterval.
	RegenerateCRL(ctx context.Context, tenantID string, signerCert *x509.Certificate, signerKey interface{}) (*CRL, error)

	// IssueCertificateForOrder processes an ACME order and issues a certificate.
	// This validates that all authorizations are valid before issuing.
	// Returns ErrACMEOrderInvalidStatus if the order is not ready for finalization.
	IssueCertificateForOrder(ctx context.Context, orderID string, csr *x509.CertificateRequest, tenantID string) (*Certificate, error)

	// ValidateChallenge validates an ACME challenge and updates its status.
	// This performs the actual challenge validation (HTTP-01, DNS-01, TLS-ALPN-01).
	ValidateChallenge(ctx context.Context, authzID string, challengeID string, tenantID string) error

	// FinalizeAuthorization checks if all challenges are valid and updates authorization status.
	// This is called after challenge validation to mark the authorization as "valid".
	FinalizeAuthorization(ctx context.Context, authzID string, tenantID string) error

	// CleanupExpiredResources runs all cleanup operations (orders, authorizations, certificates).
	// This should be called periodically for resource management.
	CleanupExpiredResources(ctx context.Context, tenantID string, certificateGracePeriod time.Duration) (*CleanupStats, error)
}

// CleanupStats provides statistics about cleanup operations.
type CleanupStats struct {
	OrdersDeleted         int
	AuthorizationsDeleted int
	CertificatesDeleted   int
	Errors                []error
}

// CertificateFilter provides filtering options for certificate queries.
type CertificateFilter struct {
	// TenantID filters by tenant (empty = all tenants)
	TenantID string

	// IncludeRevoked includes revoked certificates in results
	IncludeRevoked bool

	// IncludeExpired includes expired certificates in results
	IncludeExpired bool

	// NotBefore filters certificates issued after this time
	NotBefore *time.Time

	// NotAfter filters certificates expiring before this time
	NotAfter *time.Time
}

// ACMEOrderFilter provides filtering options for ACME order queries.
type ACMEOrderFilter struct {
	// TenantID filters by tenant (empty = all tenants)
	TenantID string

	// AccountID filters by ACME account
	AccountID string

	// Status filters by order status (empty = all statuses)
	Status string

	// IncludeExpired includes expired orders in results
	IncludeExpired bool
}
