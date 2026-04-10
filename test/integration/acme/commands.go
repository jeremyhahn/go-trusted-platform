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

// Package acme provides multi-protocol integration tests for ACME certificate services.
// Each protocol adapter (CLI, REST, gRPC, QUIC, MCP, Unix) implements the ACMECommands
// interface, enabling unified testing across all transport layers.

//go:build integration

package acme

import (
	"context"
	"time"
)

// ACMECommands defines the central command set for ACME integration testing.
// Each protocol adapter (CLI, REST, gRPC, QUIC, MCP, Unix) implements this interface.
// Tests are written once against this interface and run against all protocols.
type ACMECommands interface {
	// Protocol identification and lifecycle
	Name() string
	Setup(ctx context.Context) error
	Teardown() error

	// Account Management Commands (platformctl acme account ...)
	AccountCreate(ctx context.Context, opts AccountCreateOptions) (*AccountCreateResult, error)
	AccountList(ctx context.Context, opts AccountListOptions) (*AccountListResult, error)
	AccountDelete(ctx context.Context, accountID string) (*AccountDeleteResult, error)

	// Order Management Commands (platformctl acme order ...)
	OrderCreate(ctx context.Context, opts OrderCreateOptions) (*OrderCreateResult, error)
	OrderList(ctx context.Context, opts OrderListOptions) (*OrderListResult, error)
	OrderGet(ctx context.Context, orderID string) (*OrderGetResult, error)

	// Certificate Commands (platformctl acme certificate ...)
	CertificateRequest(ctx context.Context, opts CertificateRequestOptions) (*CertificateRequestResult, error)
	CertificateRenew(ctx context.Context, opts CertificateRenewOptions) (*CertificateRenewResult, error)
	CertificateRevoke(ctx context.Context, opts CertificateRevokeOptions) (*CertificateRevokeResult, error)

	// Challenge Commands (platformctl acme challenge ...)
	ChallengeEnroll01(ctx context.Context, opts ChallengeEnroll01Options) (*ChallengeEnroll01Result, error)
}

// =============================================================================
// Account Management Types
// =============================================================================

// AccountCreateOptions contains options for creating an ACME account.
type AccountCreateOptions struct {
	Email              string
	DirectoryURL       string
	TermsOfService     bool
	ExternalAccountID  string
	ExternalAccountKey string
}

// AccountCreateResult contains the result of an ACME account creation.
type AccountCreateResult struct {
	AccountID    string
	Status       string
	Email        string
	DirectoryURL string
	CreatedAt    time.Time
	KeyID        string
}

// AccountListOptions contains options for listing ACME accounts.
type AccountListOptions struct {
	Limit  int32
	Cursor string
}

// AccountListResult contains the result of listing ACME accounts.
type AccountListResult struct {
	Accounts   []AccountSummary
	TotalCount int32
	HasMore    bool
	NextCursor string
}

// AccountSummary contains summary information about an ACME account.
type AccountSummary struct {
	AccountID    string
	Status       string
	Email        string
	DirectoryURL string
	CreatedAt    time.Time
}

// AccountDeleteResult contains the result of deleting an ACME account.
type AccountDeleteResult struct {
	AccountID string
	Deleted   bool
}

// =============================================================================
// Order Management Types
// =============================================================================

// OrderCreateOptions contains options for creating an ACME order.
type OrderCreateOptions struct {
	AccountID   string
	Identifiers []OrderIdentifier
	NotBefore   time.Time
	NotAfter    time.Time
}

// OrderIdentifier represents an identifier in an ACME order.
type OrderIdentifier struct {
	Type  string // dns, ip, permanent-identifier
	Value string
}

// OrderCreateResult contains the result of creating an ACME order.
type OrderCreateResult struct {
	OrderID        string
	Status         string
	Expires        time.Time
	Identifiers    []OrderIdentifier
	Authorizations []string
	Finalize       string
	CreatedAt      time.Time
}

// OrderListOptions contains options for listing ACME orders.
type OrderListOptions struct {
	AccountID string
	Status    string
	Limit     int32
	Cursor    string
}

// OrderListResult contains the result of listing ACME orders.
type OrderListResult struct {
	Orders     []OrderSummary
	TotalCount int32
	HasMore    bool
	NextCursor string
}

// OrderSummary contains summary information about an ACME order.
type OrderSummary struct {
	OrderID     string
	Status      string
	Expires     time.Time
	Identifiers []OrderIdentifier
	CreatedAt   time.Time
}

// OrderGetResult contains the result of retrieving an ACME order.
type OrderGetResult struct {
	OrderID        string
	Status         string
	Expires        time.Time
	Identifiers    []OrderIdentifier
	Authorizations []AuthorizationInfo
	Finalize       string
	Certificate    string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// AuthorizationInfo contains information about an ACME authorization.
type AuthorizationInfo struct {
	URL        string
	Status     string
	Identifier OrderIdentifier
	Challenges []ChallengeInfo
	Expires    time.Time
}

// ChallengeInfo contains information about an ACME challenge.
type ChallengeInfo struct {
	Type      string
	URL       string
	Status    string
	Token     string
	Validated time.Time
}

// =============================================================================
// Certificate Types
// =============================================================================

// CertificateRequestOptions contains options for requesting a certificate.
type CertificateRequestOptions struct {
	// Subject fields
	CommonName         string
	Organization       string
	OrganizationalUnit string
	Country            string
	Province           string
	Locality           string
	StreetAddress      string
	PostalCode         string

	// SAN fields
	SANsDNS    []string
	SANsEmails []string
	SANsIPs    []string

	// Authorization options
	AuthorizationType string // dns, ip, permanent-identifier
	ChallengeType     string // http-01, dns-01, endorse-01, device-01, device-attest-01

	// ACME options
	DirectoryURL string
	CACert       string
	Email        string
}

// CertificateRequestResult contains the result of requesting a certificate.
type CertificateRequestResult struct {
	OrderID        string
	Status         string
	CertificateURL string
	CertificatePEM string
	ChainPEM       string
	NotBefore      time.Time
	NotAfter       time.Time
	SerialNumber   string
	Issuer         string
	Subject        string
}

// CertificateRenewOptions contains options for renewing a certificate.
type CertificateRenewOptions struct {
	// Subject fields
	CommonName         string
	Organization       string
	OrganizationalUnit string
	Country            string
	Province           string
	Locality           string
	StreetAddress      string
	PostalCode         string

	// SAN fields
	SANsDNS    []string
	SANsEmails []string
	SANsIPs    []string

	// Authorization options
	AuthorizationType string
	ChallengeType     string

	// ACME options
	DirectoryURL string
	CACert       string
	Email        string
}

// CertificateRenewResult contains the result of renewing a certificate.
type CertificateRenewResult struct {
	OrderID        string
	Status         string
	CertificateURL string
	CertificatePEM string
	ChainPEM       string
	NotBefore      time.Time
	NotAfter       time.Time
	SerialNumber   string
	Issuer         string
	Subject        string
	RenewedAt      time.Time
}

// CertificateRevokeOptions contains options for revoking a certificate.
type CertificateRevokeOptions struct {
	CertificateURL string
	SerialNumber   string
	Reason         int // RFC 5280 CRLReason
}

// CertificateRevokeResult contains the result of revoking a certificate.
type CertificateRevokeResult struct {
	CertificateURL string
	SerialNumber   string
	Revoked        bool
	RevokedAt      time.Time
	Reason         int
}

// =============================================================================
// Challenge Types
// =============================================================================

// ChallengeEnroll01Options contains options for the enroll-01 custom challenge.
// This is a TPM-based device attestation challenge type.
type ChallengeEnroll01Options struct {
	OrderID      string
	AccountID    string
	DeviceSerial string
	DeviceModel  string
	TPMHandle    uint32
	AttestKeyPEM string
	QuoteData    []byte
	PCRValues    map[uint32][]byte
}

// ChallengeEnroll01Result contains the result of the enroll-01 challenge.
type ChallengeEnroll01Result struct {
	Status         string
	Validated      bool
	ValidatedAt    time.Time
	CertificateURL string
	DeviceID       string
	AttestationOK  bool
	PCRsVerified   bool
}
