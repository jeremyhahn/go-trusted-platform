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

package attestation

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAttestationToken_IsExpired(t *testing.T) {
	tests := []struct {
		name    string
		token   *AttestationToken
		expired bool
	}{
		{
			name: "not expired - future expiry",
			token: &AttestationToken{
				Expires: time.Now().Add(time.Hour),
			},
			expired: false,
		},
		{
			name: "expired - past expiry",
			token: &AttestationToken{
				Expires: time.Now().Add(-time.Hour),
			},
			expired: true,
		},
		{
			name: "expired - exactly now",
			token: &AttestationToken{
				Expires: time.Now().Add(-time.Millisecond),
			},
			expired: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.token.IsExpired()
			assert.Equal(t, tt.expired, result)
		})
	}
}

func TestAttestationToken_IsValidFor(t *testing.T) {
	tests := []struct {
		name      string
		token     *AttestationToken
		operation string
		zone      string
		valid     bool
	}{
		{
			name: "valid - exact operation and zone match",
			token: &AttestationToken{
				Expires:           time.Now().Add(time.Hour),
				AllowedOperations: []string{"A", "AAAA"},
				AllowedZones:      []string{"example.com.", "test.com."},
			},
			operation: "A",
			zone:      "example.com.",
			valid:     true,
		},
		{
			name: "valid - wildcard operation",
			token: &AttestationToken{
				Expires:           time.Now().Add(time.Hour),
				AllowedOperations: []string{"*"},
				AllowedZones:      []string{"example.com."},
			},
			operation: "TXT",
			zone:      "example.com.",
			valid:     true,
		},
		{
			name: "valid - wildcard zone",
			token: &AttestationToken{
				Expires:           time.Now().Add(time.Hour),
				AllowedOperations: []string{"A"},
				AllowedZones:      []string{"*"},
			},
			operation: "A",
			zone:      "any.zone.com.",
			valid:     true,
		},
		{
			name: "valid - both wildcards",
			token: &AttestationToken{
				Expires:           time.Now().Add(time.Hour),
				AllowedOperations: []string{"*"},
				AllowedZones:      []string{"*"},
			},
			operation: "MX",
			zone:      "random.zone.",
			valid:     true,
		},
		{
			name: "valid - match on a later list entry",
			token: &AttestationToken{
				Expires:           time.Now().Add(time.Hour),
				AllowedOperations: []string{"A", "AAAA", "TLSA"},
				AllowedZones:      []string{"example.com.", "test.org."},
			},
			operation: "AAAA",
			zone:      "test.org.",
			valid:     true,
		},
		{
			name: "invalid - wildcard operation, zone not allowed",
			token: &AttestationToken{
				Expires:           time.Now().Add(time.Hour),
				AllowedOperations: []string{"*"},
				AllowedZones:      []string{"example.com."},
			},
			operation: "A",
			zone:      "other.com.",
			valid:     false,
		},
		{
			name: "invalid - wildcard zone, operation not allowed",
			token: &AttestationToken{
				Expires:           time.Now().Add(time.Hour),
				AllowedOperations: []string{"A"},
				AllowedZones:      []string{"*"},
			},
			operation: "MX",
			zone:      "any-domain.com.",
			valid:     false,
		},
		{
			name: "invalid - operation not allowed",
			token: &AttestationToken{
				Expires:           time.Now().Add(time.Hour),
				AllowedOperations: []string{"A", "AAAA"},
				AllowedZones:      []string{"example.com."},
			},
			operation: "TXT",
			zone:      "example.com.",
			valid:     false,
		},
		{
			name: "invalid - zone not allowed",
			token: &AttestationToken{
				Expires:           time.Now().Add(time.Hour),
				AllowedOperations: []string{"A"},
				AllowedZones:      []string{"example.com."},
			},
			operation: "A",
			zone:      "other.com.",
			valid:     false,
		},
		{
			name: "invalid - expired token",
			token: &AttestationToken{
				Expires:           time.Now().Add(-time.Hour),
				AllowedOperations: []string{"A"},
				AllowedZones:      []string{"example.com."},
			},
			operation: "A",
			zone:      "example.com.",
			valid:     false,
		},
		{
			name: "invalid - empty operations",
			token: &AttestationToken{
				Expires:           time.Now().Add(time.Hour),
				AllowedOperations: []string{},
				AllowedZones:      []string{"example.com."},
			},
			operation: "A",
			zone:      "example.com.",
			valid:     false,
		},
		{
			name: "invalid - empty zones",
			token: &AttestationToken{
				Expires:           time.Now().Add(time.Hour),
				AllowedOperations: []string{"A"},
				AllowedZones:      []string{},
			},
			operation: "A",
			zone:      "example.com.",
			valid:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.token.IsValidFor(tt.operation, tt.zone)
			assert.Equal(t, tt.valid, result)
		})
	}
}

func TestDefaultZoneAttestationConfig(t *testing.T) {
	config := DefaultZoneAttestationConfig()

	assert.NotNil(t, config)
	assert.True(t, config.Required, "default config should require attestation")
	assert.Equal(t, 5*time.Minute, config.MaxAge)
	assert.Equal(t, "standard-boot", config.PCRPolicy)
	assert.Equal(t, FallbackDeny, config.Fallback)
	assert.Empty(t, config.AllowedEKCerts)
}

func TestAttestationToken_FullFields(t *testing.T) {
	now := time.Now()
	token := &AttestationToken{
		Version:           1,
		Issued:            now,
		Expires:           now.Add(time.Hour),
		DeviceID:          "device-123",
		EKFingerprint:     "sha256:abc123",
		PCRDigest:         "sha256:def456",
		AllowedOperations: []string{"A", "AAAA", "TXT"},
		AllowedZones:      []string{"example.com.", "test.com."},
		Signature:         "base64signature",
	}

	assert.Equal(t, 1, token.Version)
	assert.Equal(t, now, token.Issued)
	assert.Equal(t, "device-123", token.DeviceID)
	assert.Equal(t, "sha256:abc123", token.EKFingerprint)
	assert.Equal(t, "sha256:def456", token.PCRDigest)
	assert.Len(t, token.AllowedOperations, 3)
	assert.Len(t, token.AllowedZones, 2)
	assert.Equal(t, "base64signature", token.Signature)
	assert.False(t, token.IsExpired())
}

func TestFallbackModeConstants(t *testing.T) {
	assert.Equal(t, "deny", FallbackDeny)
	assert.Equal(t, "allow-with-warning", FallbackAllowWithWarning)
	assert.Equal(t, "cached-quote", FallbackCachedQuote)
}
