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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestStatus_String(t *testing.T) {
	tests := []struct {
		status   Status
		expected string
	}{
		{StatusActive, "active"},
		{StatusRevoked, "revoked"},
		{StatusExpired, "expired"},
		{StatusUsed, "used"},
		{Status(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.status.String())
		})
	}
}

func TestParseStatus(t *testing.T) {
	tests := []struct {
		input    string
		expected Status
	}{
		{"active", StatusActive},
		{"revoked", StatusRevoked},
		{"expired", StatusExpired},
		{"used", StatusUsed},
		{"invalid", StatusActive}, // default
		{"", StatusActive},        // default
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, ParseStatus(tt.input))
		})
	}
}

func TestCredential_IsExpired(t *testing.T) {
	t.Run("not expired when ExpiresAt is zero", func(t *testing.T) {
		cred := &Credential{ExpiresAt: time.Time{}}
		assert.False(t, cred.IsExpired())
	})

	t.Run("not expired when ExpiresAt is in the future", func(t *testing.T) {
		cred := &Credential{ExpiresAt: time.Now().Add(time.Hour)}
		assert.False(t, cred.IsExpired())
	})

	t.Run("expired when ExpiresAt is in the past", func(t *testing.T) {
		cred := &Credential{ExpiresAt: time.Now().Add(-time.Hour)}
		assert.True(t, cred.IsExpired())
	})
}

func TestCredential_IsValid(t *testing.T) {
	t.Run("valid when active and not expired", func(t *testing.T) {
		cred := &Credential{
			Status:    StatusActive,
			ExpiresAt: time.Now().Add(time.Hour),
		}
		assert.True(t, cred.IsValid())
	})

	t.Run("valid when active with no expiration", func(t *testing.T) {
		cred := &Credential{
			Status:    StatusActive,
			ExpiresAt: time.Time{},
		}
		assert.True(t, cred.IsValid())
	})

	t.Run("invalid when revoked", func(t *testing.T) {
		cred := &Credential{
			Status:    StatusRevoked,
			ExpiresAt: time.Now().Add(time.Hour),
		}
		assert.False(t, cred.IsValid())
	})

	t.Run("invalid when expired status", func(t *testing.T) {
		cred := &Credential{
			Status:    StatusExpired,
			ExpiresAt: time.Now().Add(time.Hour),
		}
		assert.False(t, cred.IsValid())
	})

	t.Run("invalid when used", func(t *testing.T) {
		cred := &Credential{
			Status:    StatusUsed,
			ExpiresAt: time.Now().Add(time.Hour),
		}
		assert.False(t, cred.IsValid())
	})

	t.Run("invalid when active but expired by time", func(t *testing.T) {
		cred := &Credential{
			Status:    StatusActive,
			ExpiresAt: time.Now().Add(-time.Hour),
		}
		assert.False(t, cred.IsValid())
	})
}

func TestGenerateParams_Validate(t *testing.T) {
	t.Run("valid params", func(t *testing.T) {
		params := GenerateParams{
			ProfileID: 123,
			TenantID:  "tenant-1",
			ExpiresIn: time.Hour,
		}
		assert.NoError(t, params.Validate())
	})

	t.Run("valid params with custom HMAC key length", func(t *testing.T) {
		params := GenerateParams{
			ProfileID:  123,
			TenantID:   "tenant-1",
			HMACKeyLen: 64,
		}
		assert.NoError(t, params.Validate())
	})

	t.Run("invalid zero profile ID", func(t *testing.T) {
		params := GenerateParams{
			ProfileID: 0,
			TenantID:  "tenant-1",
		}
		err := params.Validate()
		assert.Error(t, err)
		var profileErr ErrInvalidProfileID
		assert.ErrorAs(t, err, &profileErr)
	})

	t.Run("invalid empty tenant ID", func(t *testing.T) {
		params := GenerateParams{
			ProfileID: 123,
			TenantID:  "",
		}
		err := params.Validate()
		assert.Error(t, err)
		var tenantErr ErrInvalidTenantID
		assert.ErrorAs(t, err, &tenantErr)
	})

	t.Run("invalid negative expiration", func(t *testing.T) {
		params := GenerateParams{
			ProfileID: 123,
			TenantID:  "tenant-1",
			ExpiresIn: -time.Hour,
		}
		err := params.Validate()
		assert.Error(t, err)
		var expiresErr ErrInvalidExpiresAt
		assert.ErrorAs(t, err, &expiresErr)
	})

	t.Run("invalid HMAC key length too short", func(t *testing.T) {
		params := GenerateParams{
			ProfileID:  123,
			TenantID:   "tenant-1",
			HMACKeyLen: 16, // Less than 32
		}
		err := params.Validate()
		assert.Error(t, err)
		var credErr ErrInvalidCredential
		assert.ErrorAs(t, err, &credErr)
	})

	t.Run("zero HMAC key length uses default", func(t *testing.T) {
		params := GenerateParams{
			ProfileID:  123,
			TenantID:   "tenant-1",
			HMACKeyLen: 0, // Will use default
		}
		assert.NoError(t, params.Validate())
	})
}

func TestConstants(t *testing.T) {
	assert.Equal(t, 32, MinHMACKeyLength)
	assert.Equal(t, 32, DefaultHMACKeyLength)
	assert.Equal(t, 24*time.Hour, DefaultCredentialExpiry)
}
