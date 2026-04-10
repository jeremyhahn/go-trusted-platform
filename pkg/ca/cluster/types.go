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

// Package cluster provides cluster-aware CA state management types and operations
// for distributed QuicBaaS storage. It defines data structures and interfaces for
// replicating CA state (certificates, CRLs, ACME resources) across cluster nodes.
package cluster

import (
	"crypto/x509"
	"math/big"
	"time"
)

const (
	// Entity types for QuicBaaS storage partitioning
	EntityTypeCertificate   = "CACertificate"
	EntityTypeCRL           = "CACRL"
	EntityTypeACMEAccount   = "ACMEAccount"
	EntityTypeACMEOrder     = "ACMEOrder"
	EntityTypeACMEAuth      = "ACMEAuthorization"
	EntityTypeACMEChallenge = "ACMEChallenge"
)

// Certificate represents an issued X.509 certificate stored in the cluster.
// It implements entities.KeyValueEntity for QuicBaaS storage and includes
// metadata for lifecycle management and audit trails.
//
// Key Scheme: /ca/certs/{serial}
//   - serial: Certificate serial number (hex-encoded)
//   - EntityID: FNV-1a hash of serial number for QuicBaaS indexing
type Certificate struct {
	// EntityID is the QuicBaaS primary key (FNV-1a hash of SerialNumber)
	entityID uint64

	// SerialNumber is the unique certificate serial number
	SerialNumber *big.Int `json:"serial_number"`

	// DER is the ASN.1 DER-encoded certificate
	DER []byte `json:"der"`

	// Subject is the certificate subject DN
	Subject string `json:"subject"`

	// Issuer is the certificate issuer DN
	Issuer string `json:"issuer"`

	// NotBefore is the certificate validity start time
	NotBefore time.Time `json:"not_before"`

	// NotAfter is the certificate validity end time
	NotAfter time.Time `json:"not_after"`

	// IssuedAt is the timestamp when the certificate was issued
	IssuedAt time.Time `json:"issued_at"`

	// RevokedAt is the timestamp when the certificate was revoked (nil if active)
	RevokedAt *time.Time `json:"revoked_at,omitempty"`

	// RevocationReason is the CRL reason code (0 if not revoked)
	RevocationReason int `json:"revocation_reason,omitempty"`

	// TenantID is the tenant identifier for multi-tenancy support
	TenantID string `json:"tenant_id,omitempty"`

	// Version tracks the entity version for optimistic locking
	Version uint64 `json:"version"`
}

// NewCertificate creates a new Certificate from an x509.Certificate.
func NewCertificate(cert *x509.Certificate, tenantID string) *Certificate {
	return &Certificate{
		SerialNumber: new(big.Int).Set(cert.SerialNumber),
		DER:          cert.Raw,
		Subject:      cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		IssuedAt:     time.Now().UTC(),
		TenantID:     tenantID,
		Version:      1,
	}
}

// EntityID returns the QuicBaaS entity ID (implements KeyValueEntity).
func (c *Certificate) EntityID() uint64 {
	return c.entityID
}

// SetEntityID sets the QuicBaaS entity ID (implements KeyValueEntity).
func (c *Certificate) SetEntityID(id uint64) {
	c.entityID = id
}

// IsRevoked returns true if the certificate has been revoked.
func (c *Certificate) IsRevoked() bool {
	return c.RevokedAt != nil
}

// IsExpired returns true if the certificate is past its NotAfter time.
func (c *Certificate) IsExpired() bool {
	return time.Now().UTC().After(c.NotAfter)
}

// IsValid returns true if the certificate is not revoked and not expired.
func (c *Certificate) IsValid() bool {
	return !c.IsRevoked() && !c.IsExpired()
}

// CRL represents a Certificate Revocation List stored in the cluster.
// It implements entities.KeyValueEntity for QuicBaaS storage.
//
// Key Scheme: /ca/crls/{id}
//   - id: CRL identifier (typically "current" or timestamp-based)
//   - EntityID: FNV-1a hash of CRL ID for QuicBaaS indexing
type CRL struct {
	// EntityID is the QuicBaaS primary key (FNV-1a hash of CRLID)
	entityID uint64

	// CRLID is the unique identifier for this CRL
	CRLID string `json:"crl_id"`

	// DER is the ASN.1 DER-encoded CRL
	DER []byte `json:"der"`

	// Issuer is the CRL issuer DN
	Issuer string `json:"issuer"`

	// ThisUpdate is the CRL issuance time
	ThisUpdate time.Time `json:"this_update"`

	// NextUpdate is the next expected CRL update time
	NextUpdate time.Time `json:"next_update"`

	// RevokedCertificates contains serial numbers of revoked certificates
	RevokedCertificates []*RevokedCertificate `json:"revoked_certificates"`

	// TenantID is the tenant identifier for multi-tenancy support
	TenantID string `json:"tenant_id,omitempty"`

	// Version tracks the entity version for optimistic locking
	Version uint64 `json:"version"`
}

// NewCRL creates a new CRL entity.
func NewCRL(id string, der []byte, issuer string, thisUpdate, nextUpdate time.Time, tenantID string) *CRL {
	return &CRL{
		CRLID:               id,
		DER:                 der,
		Issuer:              issuer,
		ThisUpdate:          thisUpdate,
		NextUpdate:          nextUpdate,
		RevokedCertificates: make([]*RevokedCertificate, 0),
		TenantID:            tenantID,
		Version:             1,
	}
}

// EntityID returns the QuicBaaS entity ID (implements KeyValueEntity).
func (c *CRL) EntityID() uint64 {
	return c.entityID
}

// SetEntityID sets the QuicBaaS entity ID (implements KeyValueEntity).
func (c *CRL) SetEntityID(id uint64) {
	c.entityID = id
}

// IsExpired returns true if the CRL is past its NextUpdate time.
func (c *CRL) IsExpired() bool {
	return time.Now().UTC().After(c.NextUpdate)
}

// RevokedCertificate represents a single entry in a CRL.
type RevokedCertificate struct {
	SerialNumber     *big.Int  `json:"serial_number"`
	RevocationTime   time.Time `json:"revocation_time"`
	RevocationReason int       `json:"revocation_reason"`
}

// ACMEAccount represents an ACME account stored in the cluster.
// It implements entities.KeyValueEntity for QuicBaaS storage.
//
// Key Scheme: /ca/acme/accounts/{id}
//   - id: ACME account ID (URL-safe base64)
//   - EntityID: FNV-1a hash of account ID for QuicBaaS indexing
type ACMEAccount struct {
	// EntityID is the QuicBaaS primary key (FNV-1a hash of AccountID)
	entityID uint64

	// AccountID is the unique ACME account identifier
	AccountID string `json:"account_id"`

	// Status is the account status (valid, deactivated, revoked)
	Status string `json:"status"`

	// Contact is the account contact information (email addresses)
	Contact []string `json:"contact,omitempty"`

	// PublicKeyJWK is the account public key in JWK format
	PublicKeyJWK []byte `json:"public_key_jwk"`

	// TermsOfServiceAgreed indicates ToS acceptance
	TermsOfServiceAgreed bool `json:"terms_of_service_agreed"`

	// ExternalAccountBinding contains EAB details if used
	ExternalAccountBinding []byte `json:"external_account_binding,omitempty"`

	// CreatedAt is the account creation timestamp
	CreatedAt time.Time `json:"created_at"`

	// TenantID is the tenant identifier for multi-tenancy support
	TenantID string `json:"tenant_id,omitempty"`

	// Version tracks the entity version for optimistic locking
	Version uint64 `json:"version"`
}

// NewACMEAccount creates a new ACME account entity.
func NewACMEAccount(accountID string, publicKeyJWK []byte, contact []string, tenantID string) *ACMEAccount {
	return &ACMEAccount{
		AccountID:            accountID,
		Status:               "valid",
		Contact:              contact,
		PublicKeyJWK:         publicKeyJWK,
		TermsOfServiceAgreed: true,
		CreatedAt:            time.Now().UTC(),
		TenantID:             tenantID,
		Version:              1,
	}
}

// EntityID returns the QuicBaaS entity ID (implements KeyValueEntity).
func (a *ACMEAccount) EntityID() uint64 {
	return a.entityID
}

// SetEntityID sets the QuicBaaS entity ID (implements KeyValueEntity).
func (a *ACMEAccount) SetEntityID(id uint64) {
	a.entityID = id
}

// IsActive returns true if the account status is "valid".
func (a *ACMEAccount) IsActive() bool {
	return a.Status == "valid"
}

// ACMEOrder represents an ACME certificate order stored in the cluster.
// It implements entities.KeyValueEntity for QuicBaaS storage.
//
// Key Scheme: /ca/acme/orders/{id}
//   - id: ACME order ID (URL-safe base64)
//   - EntityID: FNV-1a hash of order ID for QuicBaaS indexing
type ACMEOrder struct {
	// EntityID is the QuicBaaS primary key (FNV-1a hash of OrderID)
	entityID uint64

	// OrderID is the unique ACME order identifier
	OrderID string `json:"order_id"`

	// AccountID is the account that created this order
	AccountID string `json:"account_id"`

	// Status is the order status (pending, ready, processing, valid, invalid)
	Status string `json:"status"`

	// Identifiers contains the DNS names or IP addresses being validated
	Identifiers []ACMEIdentifier `json:"identifiers"`

	// AuthorizationIDs are the IDs of associated authorizations
	AuthorizationIDs []string `json:"authorization_ids"`

	// NotBefore is the requested certificate validity start (optional)
	NotBefore *time.Time `json:"not_before,omitempty"`

	// NotAfter is the requested certificate validity end (optional)
	NotAfter *time.Time `json:"not_after,omitempty"`

	// Error contains error details if status is invalid
	Error *ACMEError `json:"error,omitempty"`

	// CertificateID is the ID of the issued certificate (when status=valid)
	CertificateID string `json:"certificate_id,omitempty"`

	// CreatedAt is the order creation timestamp
	CreatedAt time.Time `json:"created_at"`

	// ExpiresAt is when the order expires if not completed
	ExpiresAt time.Time `json:"expires_at"`

	// TenantID is the tenant identifier for multi-tenancy support
	TenantID string `json:"tenant_id,omitempty"`

	// Version tracks the entity version for optimistic locking
	Version uint64 `json:"version"`
}

// NewACMEOrder creates a new ACME order entity.
func NewACMEOrder(orderID, accountID string, identifiers []ACMEIdentifier, tenantID string) *ACMEOrder {
	now := time.Now().UTC()
	return &ACMEOrder{
		OrderID:          orderID,
		AccountID:        accountID,
		Status:           "pending",
		Identifiers:      identifiers,
		AuthorizationIDs: make([]string, 0),
		CreatedAt:        now,
		ExpiresAt:        now.Add(7 * 24 * time.Hour), // 7 days default
		TenantID:         tenantID,
		Version:          1,
	}
}

// EntityID returns the QuicBaaS entity ID (implements KeyValueEntity).
func (o *ACMEOrder) EntityID() uint64 {
	return o.entityID
}

// SetEntityID sets the QuicBaaS entity ID (implements KeyValueEntity).
func (o *ACMEOrder) SetEntityID(id uint64) {
	o.entityID = id
}

// IsExpired returns true if the order is past its expiration time.
func (o *ACMEOrder) IsExpired() bool {
	return time.Now().UTC().After(o.ExpiresAt)
}

// ACMEIdentifier represents an identifier in an ACME order.
type ACMEIdentifier struct {
	Type  string `json:"type"`  // "dns" or "ip"
	Value string `json:"value"` // Domain name or IP address
}

// ACMEError represents an ACME error response.
type ACMEError struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
	Status int    `json:"status,omitempty"`
}

// ACMEAuthorization represents an ACME authorization stored in the cluster.
// It implements entities.KeyValueEntity for QuicBaaS storage.
//
// Key Scheme: /ca/acme/authorizations/{id}
//   - id: ACME authorization ID (URL-safe base64)
//   - EntityID: FNV-1a hash of authorization ID for QuicBaaS indexing
type ACMEAuthorization struct {
	// EntityID is the QuicBaaS primary key (FNV-1a hash of AuthorizationID)
	entityID uint64

	// AuthorizationID is the unique ACME authorization identifier
	AuthorizationID string `json:"authorization_id"`

	// AccountID is the account that owns this authorization
	AccountID string `json:"account_id"`

	// OrderID is the order this authorization belongs to
	OrderID string `json:"order_id"`

	// Status is the authorization status (pending, valid, invalid, expired, revoked)
	Status string `json:"status"`

	// Identifier is the identifier being authorized
	Identifier ACMEIdentifier `json:"identifier"`

	// Challenges contains the available challenge methods
	Challenges []ACMEChallenge `json:"challenges"`

	// Wildcard indicates if this is for a wildcard domain
	Wildcard bool `json:"wildcard,omitempty"`

	// CreatedAt is the authorization creation timestamp
	CreatedAt time.Time `json:"created_at"`

	// ExpiresAt is when the authorization expires
	ExpiresAt time.Time `json:"expires_at"`

	// TenantID is the tenant identifier for multi-tenancy support
	TenantID string `json:"tenant_id,omitempty"`

	// Version tracks the entity version for optimistic locking
	Version uint64 `json:"version"`
}

// NewACMEAuthorization creates a new ACME authorization entity.
func NewACMEAuthorization(authzID, accountID, orderID string, identifier ACMEIdentifier, tenantID string) *ACMEAuthorization {
	now := time.Now().UTC()
	return &ACMEAuthorization{
		AuthorizationID: authzID,
		AccountID:       accountID,
		OrderID:         orderID,
		Status:          "pending",
		Identifier:      identifier,
		Challenges:      make([]ACMEChallenge, 0),
		CreatedAt:       now,
		ExpiresAt:       now.Add(7 * 24 * time.Hour), // 7 days default
		TenantID:        tenantID,
		Version:         1,
	}
}

// EntityID returns the QuicBaaS entity ID (implements KeyValueEntity).
func (a *ACMEAuthorization) EntityID() uint64 {
	return a.entityID
}

// SetEntityID sets the QuicBaaS entity ID (implements KeyValueEntity).
func (a *ACMEAuthorization) SetEntityID(id uint64) {
	a.entityID = id
}

// IsExpired returns true if the authorization is past its expiration time.
func (a *ACMEAuthorization) IsExpired() bool {
	return time.Now().UTC().After(a.ExpiresAt)
}

// ACMEChallenge represents an ACME challenge.
type ACMEChallenge struct {
	// ChallengeID is the unique challenge identifier
	ChallengeID string `json:"challenge_id"`

	// Type is the challenge type (http-01, dns-01, tls-alpn-01)
	Type string `json:"type"`

	// Status is the challenge status (pending, processing, valid, invalid)
	Status string `json:"status"`

	// Token is the challenge token
	Token string `json:"token" secret:"true"`

	// KeyAuthorization is the key authorization string
	KeyAuthorization string `json:"key_authorization,omitempty" secret:"true"`

	// Validated is the timestamp when the challenge was validated
	Validated *time.Time `json:"validated,omitempty"`

	// Error contains error details if status is invalid
	Error *ACMEError `json:"error,omitempty"`
}

// ClusterMetadata provides cluster-wide metadata for CA operations.
// This is used for coordinating operations across cluster nodes.
type ClusterMetadata struct {
	// NodeID is the cluster node that last modified this entity
	NodeID string `json:"node_id"`

	// Timestamp is when this entity was last modified
	Timestamp time.Time `json:"timestamp"`

	// Checksum is a hash of the entity data for integrity verification
	Checksum string `json:"checksum,omitempty"`
}
