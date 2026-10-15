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

//go:build integration

// Package dns provides integration tests for attestation-gated DNS updates.
// These tests verify the attestation guard functionality for DNS operations.
// Run via: make integration-test-dns
package dns

import (
	"context"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/attestation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestToken creates a valid attestation token for testing.
func createTestToken(deviceID string, zones []string, operations []string) *attestation.AttestationToken {
	now := time.Now()
	return &attestation.AttestationToken{
		Version:           1,
		Issued:            now,
		Expires:           now.Add(5 * time.Minute),
		DeviceID:          deviceID,
		EKFingerprint:     "SHA256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		PCRDigest:         "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		AllowedOperations: operations,
		AllowedZones:      zones,
		Signature:         "test-signature",
	}
}

// createExpiredToken creates an expired attestation token for testing.
func createExpiredToken(deviceID string) *attestation.AttestationToken {
	expired := time.Now().Add(-1 * time.Hour)
	return &attestation.AttestationToken{
		Version:           1,
		Issued:            expired.Add(-1 * time.Hour),
		Expires:           expired,
		DeviceID:          deviceID,
		EKFingerprint:     "SHA256:expired",
		PCRDigest:         "expired-digest",
		AllowedOperations: []string{"*"},
		AllowedZones:      []string{"*"},
		Signature:         "expired-signature",
	}
}

// TestAttestationGuard_Create_DefaultConfig tests guard creation with default config.
func TestAttestationGuard_Create_DefaultConfig(t *testing.T) {
	guard := attestation.NewGuard(nil)
	require.NotNil(t, guard)

	defaultConfig := guard.DefaultConfig()
	assert.True(t, defaultConfig.Required)
	assert.Equal(t, 5*time.Minute, defaultConfig.MaxAge)
	assert.Equal(t, "standard-boot", defaultConfig.PCRPolicy)
	assert.Equal(t, attestation.FallbackDeny, defaultConfig.Fallback)
}

// TestAttestationGuard_Create_CustomConfig tests guard creation with custom config.
func TestAttestationGuard_Create_CustomConfig(t *testing.T) {
	customConfig := &attestation.ZoneAttestationConfig{
		Required:  false,
		MaxAge:    10 * time.Minute,
		PCRPolicy: "custom-policy",
		Fallback:  attestation.FallbackAllowWithWarning,
	}

	guard := attestation.NewGuard(customConfig)
	require.NotNil(t, guard)

	assert.Equal(t, customConfig.Required, guard.DefaultConfig().Required)
	assert.Equal(t, customConfig.MaxAge, guard.DefaultConfig().MaxAge)
	assert.Equal(t, customConfig.PCRPolicy, guard.DefaultConfig().PCRPolicy)
	assert.Equal(t, customConfig.Fallback, guard.DefaultConfig().Fallback)
}

// TestAttestationGuard_SetZoneConfig tests setting zone-specific configuration.
func TestAttestationGuard_SetZoneConfig(t *testing.T) {
	guard := attestation.NewGuard(nil)

	zoneConfig := &attestation.ZoneAttestationConfig{
		Required:  true,
		MaxAge:    2 * time.Minute,
		PCRPolicy: "high-security",
		Fallback:  attestation.FallbackDeny,
	}

	guard.SetZoneConfig("secure.example.com.", zoneConfig)

	retrieved := guard.GetZoneConfig("secure.example.com.")
	assert.Equal(t, zoneConfig.Required, retrieved.Required)
	assert.Equal(t, zoneConfig.MaxAge, retrieved.MaxAge)
	assert.Equal(t, zoneConfig.PCRPolicy, retrieved.PCRPolicy)
}

// TestAttestationGuard_GetZoneConfig_Fallback tests fallback to default config.
func TestAttestationGuard_GetZoneConfig_Fallback(t *testing.T) {
	defaultConfig := &attestation.ZoneAttestationConfig{
		Required: true,
		MaxAge:   5 * time.Minute,
	}

	guard := attestation.NewGuard(defaultConfig)

	// Get config for zone without specific config should return default
	config := guard.GetZoneConfig("unknown.example.com.")
	assert.Equal(t, defaultConfig.Required, config.Required)
	assert.Equal(t, defaultConfig.MaxAge, config.MaxAge)
}

// TestAttestationGuard_RemoveZoneConfig tests removing zone configuration.
func TestAttestationGuard_RemoveZoneConfig(t *testing.T) {
	guard := attestation.NewGuard(nil)

	zoneConfig := &attestation.ZoneAttestationConfig{
		Required: true,
		MaxAge:   1 * time.Minute,
	}

	guard.SetZoneConfig("temp.example.com.", zoneConfig)
	assert.Equal(t, 1, guard.ZoneCount())

	guard.RemoveZoneConfig("temp.example.com.")
	assert.Equal(t, 0, guard.ZoneCount())

	// Should now return default config
	config := guard.GetZoneConfig("temp.example.com.")
	assert.Equal(t, guard.DefaultConfig().Required, config.Required)
}

// TestAttestationGuard_VerifyForUpdate_NotRequired tests update when attestation not required.
func TestAttestationGuard_VerifyForUpdate_NotRequired(t *testing.T) {
	config := &attestation.ZoneAttestationConfig{
		Required: false,
		MaxAge:   5 * time.Minute,
	}
	guard := attestation.NewGuard(config)

	ctx := context.Background()
	result := guard.VerifyForUpdate(ctx, "example.com.", "A", nil)

	assert.True(t, result.Allowed)
	assert.Nil(t, result.Error)
	assert.Contains(t, result.Message, "not required")
}

// TestAttestationGuard_VerifyForUpdate_RequiredNoToken tests update fails without token.
func TestAttestationGuard_VerifyForUpdate_RequiredNoToken(t *testing.T) {
	config := &attestation.ZoneAttestationConfig{
		Required: true,
		MaxAge:   5 * time.Minute,
	}
	guard := attestation.NewGuard(config)

	ctx := context.Background()
	result := guard.VerifyForUpdate(ctx, "example.com.", "A", nil)

	assert.False(t, result.Allowed)
	assert.NotNil(t, result.Error)

	var reqErr attestation.ErrAttestationRequired
	assert.ErrorAs(t, result.Error, &reqErr)
}

// TestAttestationGuard_VerifyForUpdate_ExpiredToken tests update fails with expired token.
func TestAttestationGuard_VerifyForUpdate_ExpiredToken(t *testing.T) {
	config := &attestation.ZoneAttestationConfig{
		Required: true,
		MaxAge:   5 * time.Minute,
	}
	guard := attestation.NewGuard(config)

	token := createExpiredToken("device-123")
	ctx := context.Background()
	result := guard.VerifyForUpdate(ctx, "example.com.", "A", token)

	assert.False(t, result.Allowed)
	assert.NotNil(t, result.Error)

	var expErr attestation.ErrAttestationExpired
	assert.ErrorAs(t, result.Error, &expErr)
}

// TestAttestationGuard_VerifyForUpdate_TooOld tests update fails when token too old.
func TestAttestationGuard_VerifyForUpdate_TooOld(t *testing.T) {
	config := &attestation.ZoneAttestationConfig{
		Required: true,
		MaxAge:   1 * time.Second, // Very short max age
	}
	guard := attestation.NewGuard(config)

	// Create token that was issued 2 seconds ago
	token := &attestation.AttestationToken{
		Version:           1,
		Issued:            time.Now().Add(-2 * time.Second),
		Expires:           time.Now().Add(5 * time.Minute),
		DeviceID:          "device-123",
		AllowedOperations: []string{"*"},
		AllowedZones:      []string{"*"},
	}

	ctx := context.Background()
	result := guard.VerifyForUpdate(ctx, "example.com.", "A", token)

	assert.False(t, result.Allowed)
	assert.NotNil(t, result.Error)

	var oldErr attestation.ErrAttestationTooOld
	assert.ErrorAs(t, result.Error, &oldErr)
}

// TestAttestationGuard_VerifyForUpdate_OperationNotAllowed tests update fails for disallowed operation.
func TestAttestationGuard_VerifyForUpdate_OperationNotAllowed(t *testing.T) {
	config := &attestation.ZoneAttestationConfig{
		Required: true,
		MaxAge:   5 * time.Minute,
	}
	guard := attestation.NewGuard(config)

	// Token only allows A records, not TLSA
	token := createTestToken("device-123", []string{"*"}, []string{"A", "AAAA"})
	ctx := context.Background()
	result := guard.VerifyForUpdate(ctx, "example.com.", "TLSA", token)

	assert.False(t, result.Allowed)
	assert.NotNil(t, result.Error)

	var opErr attestation.ErrOperationNotAllowed
	assert.ErrorAs(t, result.Error, &opErr)
}

// TestAttestationGuard_VerifyForUpdate_ZoneNotAllowed tests update fails for disallowed zone.
func TestAttestationGuard_VerifyForUpdate_ZoneNotAllowed(t *testing.T) {
	config := &attestation.ZoneAttestationConfig{
		Required: true,
		MaxAge:   5 * time.Minute,
	}
	guard := attestation.NewGuard(config)

	// Token only allows specific zone
	token := createTestToken("device-123", []string{"allowed.com."}, []string{"*"})
	ctx := context.Background()
	result := guard.VerifyForUpdate(ctx, "notallowed.com.", "A", token)

	assert.False(t, result.Allowed)
	assert.NotNil(t, result.Error)

	var zoneErr attestation.ErrZoneNotAllowed
	assert.ErrorAs(t, result.Error, &zoneErr)
}

// TestAttestationGuard_VerifyForUpdate_Success tests successful update verification.
func TestAttestationGuard_VerifyForUpdate_Success(t *testing.T) {
	config := &attestation.ZoneAttestationConfig{
		Required: true,
		MaxAge:   5 * time.Minute,
	}
	guard := attestation.NewGuard(config)

	token := createTestToken("device-123", []string{"example.com."}, []string{"A", "AAAA", "TLSA"})
	ctx := context.Background()
	result := guard.VerifyForUpdate(ctx, "example.com.", "A", token)

	assert.True(t, result.Allowed)
	assert.Nil(t, result.Error)
	assert.NotNil(t, result.Token)
	assert.Contains(t, result.Message, "verified")
}

// TestAttestationGuard_VerifyForUpdate_WildcardOperations tests wildcard operation permission.
func TestAttestationGuard_VerifyForUpdate_WildcardOperations(t *testing.T) {
	config := &attestation.ZoneAttestationConfig{
		Required: true,
		MaxAge:   5 * time.Minute,
	}
	guard := attestation.NewGuard(config)

	// Token with wildcard operations
	token := createTestToken("device-123", []string{"example.com."}, []string{"*"})
	ctx := context.Background()

	// Should allow any operation type
	for _, recordType := range []string{"A", "AAAA", "CNAME", "MX", "TXT", "TLSA", "CAA"} {
		result := guard.VerifyForUpdate(ctx, "example.com.", recordType, token)
		assert.True(t, result.Allowed, "wildcard should allow %s record type", recordType)
	}
}

// TestAttestationGuard_VerifyForUpdate_WildcardZones tests wildcard zone permission.
func TestAttestationGuard_VerifyForUpdate_WildcardZones(t *testing.T) {
	config := &attestation.ZoneAttestationConfig{
		Required: true,
		MaxAge:   5 * time.Minute,
	}
	guard := attestation.NewGuard(config)

	// Token with wildcard zones
	token := createTestToken("device-123", []string{"*"}, []string{"A"})
	ctx := context.Background()

	// Should allow any zone
	for _, zone := range []string{"example.com.", "test.org.", "internal.local."} {
		result := guard.VerifyForUpdate(ctx, zone, "A", token)
		assert.True(t, result.Allowed, "wildcard should allow zone %s", zone)
	}
}

// TestAttestationGuard_VerifyForQuery_NotRequired tests query when attestation not required.
func TestAttestationGuard_VerifyForQuery_NotRequired(t *testing.T) {
	config := &attestation.ZoneAttestationConfig{
		Required: false,
		MaxAge:   5 * time.Minute,
	}
	guard := attestation.NewGuard(config)

	ctx := context.Background()
	result := guard.VerifyForQuery(ctx, "example.com.", "A", nil)

	assert.True(t, result.Allowed)
	assert.Nil(t, result.Error)
}

// TestAttestationGuard_VerifyForQuery_RequiredNoToken tests query without token (allowed for queries).
func TestAttestationGuard_VerifyForQuery_RequiredNoToken(t *testing.T) {
	config := &attestation.ZoneAttestationConfig{
		Required: true,
		MaxAge:   5 * time.Minute,
	}
	guard := attestation.NewGuard(config)

	ctx := context.Background()
	result := guard.VerifyForQuery(ctx, "example.com.", "A", nil)

	// Queries are typically allowed without token
	assert.True(t, result.Allowed)
}

// TestAttestationGuard_VerifyForQuery_WithValidToken tests query with valid token.
func TestAttestationGuard_VerifyForQuery_WithValidToken(t *testing.T) {
	config := &attestation.ZoneAttestationConfig{
		Required: true,
		MaxAge:   5 * time.Minute,
	}
	guard := attestation.NewGuard(config)

	token := createTestToken("device-123", []string{"*"}, []string{"*"})
	ctx := context.Background()
	result := guard.VerifyForQuery(ctx, "example.com.", "A", token)

	assert.True(t, result.Allowed)
	assert.NotNil(t, result.Token)
}

// TestAttestationGuard_VerifyForQuery_WithExpiredToken tests query with expired token (still allowed).
func TestAttestationGuard_VerifyForQuery_WithExpiredToken(t *testing.T) {
	config := &attestation.ZoneAttestationConfig{
		Required: true,
		MaxAge:   5 * time.Minute,
	}
	guard := attestation.NewGuard(config)

	token := createExpiredToken("device-123")
	ctx := context.Background()
	result := guard.VerifyForQuery(ctx, "example.com.", "A", token)

	// Queries are typically allowed even with expired token
	assert.True(t, result.Allowed)
	assert.Contains(t, result.Message, "expired")
}

// TestAttestationGuard_ContextCancellation tests behavior when context is cancelled.
func TestAttestationGuard_ContextCancellation(t *testing.T) {
	config := &attestation.ZoneAttestationConfig{
		Required: true,
		MaxAge:   5 * time.Minute,
	}
	guard := attestation.NewGuard(config)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	token := createTestToken("device-123", []string{"*"}, []string{"*"})

	// Update should fail with cancelled context
	result := guard.VerifyForUpdate(ctx, "example.com.", "A", token)
	assert.False(t, result.Allowed)

	var svcErr attestation.ErrServiceUnavailable
	assert.ErrorAs(t, result.Error, &svcErr)

	// Query should also fail with cancelled context
	result = guard.VerifyForQuery(ctx, "example.com.", "A", token)
	assert.False(t, result.Allowed)
}

// TestAttestationGuard_MultipleZoneConfigs tests managing multiple zone configurations.
func TestAttestationGuard_MultipleZoneConfigs(t *testing.T) {
	defaultConfig := &attestation.ZoneAttestationConfig{
		Required: true,
		MaxAge:   5 * time.Minute,
	}
	guard := attestation.NewGuard(defaultConfig)

	// Set configs for different zones
	zones := map[string]*attestation.ZoneAttestationConfig{
		"public.example.com.": {
			Required: true,
			MaxAge:   2 * time.Minute,
			Fallback: attestation.FallbackDeny,
		},
		"internal.local.": {
			Required: false,
			MaxAge:   10 * time.Minute,
			Fallback: attestation.FallbackAllowWithWarning,
		},
		"secure.corp.": {
			Required: true,
			MaxAge:   1 * time.Minute,
			Fallback: attestation.FallbackDeny,
		},
	}

	for zone, config := range zones {
		guard.SetZoneConfig(zone, config)
	}

	assert.Equal(t, 3, guard.ZoneCount())

	// Verify each zone has correct config
	for zone, expected := range zones {
		config := guard.GetZoneConfig(zone)
		assert.Equal(t, expected.Required, config.Required, "zone %s required mismatch", zone)
		assert.Equal(t, expected.MaxAge, config.MaxAge, "zone %s max age mismatch", zone)
	}
}

// TestAttestationGuard_ZoneSpecificConfig_Override tests zone config overrides default.
func TestAttestationGuard_ZoneSpecificConfig_Override(t *testing.T) {
	defaultConfig := &attestation.ZoneAttestationConfig{
		Required: true,
		MaxAge:   5 * time.Minute,
	}
	guard := attestation.NewGuard(defaultConfig)

	// Create zone-specific config that disables requirement
	zoneConfig := &attestation.ZoneAttestationConfig{
		Required: false,
		MaxAge:   10 * time.Minute,
	}
	guard.SetZoneConfig("relaxed.example.com.", zoneConfig)

	ctx := context.Background()

	// Update to relaxed zone should be allowed without token
	result := guard.VerifyForUpdate(ctx, "relaxed.example.com.", "A", nil)
	assert.True(t, result.Allowed)

	// Update to other zone should require token
	result = guard.VerifyForUpdate(ctx, "other.example.com.", "A", nil)
	assert.False(t, result.Allowed)
}

// TestAttestationToken_IsExpired tests token expiration check.
func TestAttestationToken_IsExpired(t *testing.T) {
	// Valid token
	validToken := createTestToken("device-123", []string{"*"}, []string{"*"})
	assert.False(t, validToken.IsExpired())

	// Expired token
	expiredToken := createExpiredToken("device-123")
	assert.True(t, expiredToken.IsExpired())
}

// TestAttestationToken_IsValidFor tests token validation for operation and zone.
func TestAttestationToken_IsValidFor(t *testing.T) {
	token := createTestToken("device-123", []string{"example.com.", "test.org."}, []string{"A", "AAAA", "TLSA"})

	// Valid combinations
	assert.True(t, token.IsValidFor("A", "example.com."))
	assert.True(t, token.IsValidFor("AAAA", "test.org."))
	assert.True(t, token.IsValidFor("TLSA", "example.com."))

	// Invalid operation
	assert.False(t, token.IsValidFor("MX", "example.com."))

	// Invalid zone
	assert.False(t, token.IsValidFor("A", "unknown.com."))

	// Expired token should be invalid
	expiredToken := createExpiredToken("device-123")
	assert.False(t, expiredToken.IsValidFor("A", "example.com."))
}

// TestAttestationToken_WildcardValidation tests wildcard validation.
func TestAttestationToken_WildcardValidation(t *testing.T) {
	// Wildcard operations
	token := createTestToken("device-123", []string{"example.com."}, []string{"*"})
	assert.True(t, token.IsValidFor("A", "example.com."))
	assert.True(t, token.IsValidFor("ANY_OPERATION", "example.com."))
	assert.False(t, token.IsValidFor("A", "other.com."))

	// Wildcard zones
	token2 := createTestToken("device-123", []string{"*"}, []string{"A"})
	assert.True(t, token2.IsValidFor("A", "any-domain.com."))
	assert.False(t, token2.IsValidFor("MX", "any-domain.com."))

	// Both wildcards
	token3 := createTestToken("device-123", []string{"*"}, []string{"*"})
	assert.True(t, token3.IsValidFor("ANYTHING", "anywhere.com."))
}

// TestDefaultZoneAttestationConfig tests default configuration values.
func TestDefaultZoneAttestationConfig(t *testing.T) {
	config := attestation.DefaultZoneAttestationConfig()

	assert.True(t, config.Required)
	assert.Equal(t, 5*time.Minute, config.MaxAge)
	assert.Equal(t, "standard-boot", config.PCRPolicy)
	assert.Equal(t, attestation.FallbackDeny, config.Fallback)
}

// TestAttestationGuard_SetZoneConfig_Nil tests setting nil config removes zone.
func TestAttestationGuard_SetZoneConfig_Nil(t *testing.T) {
	guard := attestation.NewGuard(nil)

	guard.SetZoneConfig("test.example.com.", &attestation.ZoneAttestationConfig{
		Required: true,
		MaxAge:   1 * time.Minute,
	})
	assert.Equal(t, 1, guard.ZoneCount())

	// Setting nil removes the config
	guard.SetZoneConfig("test.example.com.", nil)
	assert.Equal(t, 0, guard.ZoneCount())
}
