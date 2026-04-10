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

package eab

import (
	"context"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

// Status represents the status of an EAB credential.
type Status uint8

const (
	// StatusActive indicates the credential is valid and can be used.
	StatusActive Status = iota
	// StatusRevoked indicates the credential has been revoked.
	StatusRevoked
	// StatusExpired indicates the credential has expired.
	StatusExpired
	// StatusUsed indicates the credential has already been used for enrollment.
	StatusUsed
)

// String returns the string representation of the status.
func (s Status) String() string {
	switch s {
	case StatusActive:
		return "active"
	case StatusRevoked:
		return "revoked"
	case StatusExpired:
		return "expired"
	case StatusUsed:
		return "used"
	default:
		return "unknown"
	}
}

// ParseStatus parses a string into a Status value.
func ParseStatus(s string) Status {
	switch s {
	case "active":
		return StatusActive
	case "revoked":
		return StatusRevoked
	case "expired":
		return StatusExpired
	case "used":
		return StatusUsed
	default:
		return StatusActive
	}
}

// Credential represents an External Account Binding credential used for ACME device enrollment.
type Credential struct {
	ID        uint64    `yaml:"id" json:"id"`
	KeyID     string    `yaml:"key_id" json:"key_id"`
	HMACKey   []byte    `yaml:"hmac_key" json:"hmac_key"`
	ProfileID uint64    `yaml:"profile_id" json:"profile_id"`
	TenantID  string    `yaml:"tenant_id" json:"tenant_id"`
	ExpiresAt time.Time `yaml:"expires_at" json:"expires_at"`
	Status    Status    `yaml:"status" json:"status"`
	CreatedAt time.Time `yaml:"created_at" json:"created_at"`
	UsedAt    time.Time `yaml:"used_at,omitempty" json:"used_at,omitempty"`
}

// IsExpired returns true if the credential has expired.
func (c *Credential) IsExpired() bool {
	if c.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(c.ExpiresAt)
}

// IsValid returns true if the credential is active and not expired.
func (c *Credential) IsValid() bool {
	return c.Status == StatusActive && !c.IsExpired()
}

// GenerateParams contains parameters for generating a new EAB credential.
type GenerateParams struct {
	ProfileID  uint64
	TenantID   string
	ExpiresIn  time.Duration
	HMACKeyLen int // Length in bytes, minimum 32
}

// Validate validates the GenerateParams.
func (p GenerateParams) Validate() error {
	if p.ProfileID == 0 {
		return ErrInvalidProfileID{ProfileID: p.ProfileID}
	}
	if p.TenantID == "" {
		return ErrInvalidTenantID{TenantID: p.TenantID}
	}
	if p.ExpiresIn < 0 {
		return ErrInvalidExpiresAt{Reason: "expiration duration cannot be negative"}
	}
	if p.HMACKeyLen > 0 && p.HMACKeyLen < MinHMACKeyLength {
		return ErrInvalidCredential{Reason: "HMAC key length must be at least 32 bytes"}
	}
	return nil
}

// MinHMACKeyLength is the minimum length for HMAC keys (256 bits).
const MinHMACKeyLength = 32

// DefaultHMACKeyLength is the default length for HMAC keys (256 bits).
const DefaultHMACKeyLength = 32

// DefaultCredentialExpiry is the default expiration duration for credentials.
const DefaultCredentialExpiry = 24 * time.Hour

// Service defines the interface for EAB credential management.
type Service interface {
	// Generate creates a new EAB credential for a device profile.
	Generate(ctx context.Context, params GenerateParams) (*Credential, error)

	// Get retrieves an EAB credential by its ID.
	Get(ctx context.Context, id uint64) (*Credential, error)

	// GetByKeyID retrieves an EAB credential by its KeyID.
	GetByKeyID(ctx context.Context, keyID string) (*Credential, error)

	// Revoke marks a credential as revoked.
	Revoke(ctx context.Context, id uint64) error

	// MarkUsed marks a credential as used after successful enrollment.
	MarkUsed(ctx context.Context, id uint64) error

	// Validate checks if a credential is valid for use.
	Validate(ctx context.Context, keyID string, hmacKey []byte) (*Credential, error)

	// ListByProfile retrieves all credentials for a given profile ID.
	ListByProfile(ctx context.Context, profileID uint64) ([]*Credential, error)

	// ListByTenant retrieves all credentials for a given tenant ID.
	ListByTenant(ctx context.Context, tenantID string) ([]*Credential, error)

	// CleanupExpired removes all expired credentials.
	CleanupExpired(ctx context.Context) (int, error)

	// Delete removes a credential by ID.
	Delete(ctx context.Context, id uint64) error

	// Count returns the total number of credentials.
	Count(ctx context.Context) (int, error)

	// Page retrieves a paginated list of credentials.
	Page(ctx context.Context, query datastore.PageQuery) (datastore.PageResult[*Credential], error)
}
