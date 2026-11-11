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
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewGuard(t *testing.T) {
	t.Run("with nil config uses default", func(t *testing.T) {
		guard := NewGuard(nil)
		require.NotNil(t, guard)

		defaultConfig := guard.DefaultConfig()
		assert.True(t, defaultConfig.Required)
		assert.Equal(t, 5*time.Minute, defaultConfig.MaxAge)
		assert.Equal(t, "standard-boot", defaultConfig.PCRPolicy)
		assert.Equal(t, FallbackDeny, defaultConfig.Fallback)
	})

	t.Run("with custom config", func(t *testing.T) {
		customConfig := &ZoneAttestationConfig{
			Required:  false,
			MaxAge:    10 * time.Minute,
			PCRPolicy: "custom-policy",
			Fallback:  FallbackAllowWithWarning,
		}
		guard := NewGuard(customConfig)
		require.NotNil(t, guard)

		config := guard.DefaultConfig()
		assert.False(t, config.Required)
		assert.Equal(t, 10*time.Minute, config.MaxAge)
		assert.Equal(t, "custom-policy", config.PCRPolicy)
		assert.Equal(t, FallbackAllowWithWarning, config.Fallback)
	})
}

func TestGuard_SetZoneConfig(t *testing.T) {
	guard := NewGuard(nil)

	t.Run("set zone config", func(t *testing.T) {
		zoneConfig := &ZoneAttestationConfig{
			Required:  true,
			MaxAge:    15 * time.Minute,
			PCRPolicy: "zone-policy",
		}
		guard.SetZoneConfig("example.com.", zoneConfig)

		retrieved := guard.GetZoneConfig("example.com.")
		assert.Equal(t, zoneConfig, retrieved)
		assert.Equal(t, 1, guard.ZoneCount())
	})

	t.Run("set nil removes config", func(t *testing.T) {
		guard.SetZoneConfig("example.com.", nil)
		retrieved := guard.GetZoneConfig("example.com.")
		// Should return default config when zone-specific is removed
		assert.Equal(t, guard.DefaultConfig(), retrieved)
		assert.Equal(t, 0, guard.ZoneCount())
	})
}

func TestGuard_GetZoneConfig(t *testing.T) {
	guard := NewGuard(nil)

	t.Run("returns zone-specific config when set", func(t *testing.T) {
		zoneConfig := &ZoneAttestationConfig{
			Required:  false,
			MaxAge:    20 * time.Minute,
			PCRPolicy: "zone-specific",
		}
		guard.SetZoneConfig("example.com.", zoneConfig)

		retrieved := guard.GetZoneConfig("example.com.")
		assert.Equal(t, zoneConfig, retrieved)
	})

	t.Run("returns default config for unknown zone", func(t *testing.T) {
		retrieved := guard.GetZoneConfig("unknown.com.")
		assert.Equal(t, guard.DefaultConfig(), retrieved)
	})
}

func TestGuard_RemoveZoneConfig(t *testing.T) {
	guard := NewGuard(nil)

	zoneConfig := &ZoneAttestationConfig{Required: true}
	guard.SetZoneConfig("example.com.", zoneConfig)
	assert.Equal(t, 1, guard.ZoneCount())

	guard.RemoveZoneConfig("example.com.")
	assert.Equal(t, 0, guard.ZoneCount())

	retrieved := guard.GetZoneConfig("example.com.")
	assert.Equal(t, guard.DefaultConfig(), retrieved)
}

func TestGuard_MultipleZoneConfigs(t *testing.T) {
	guard := NewGuard(&ZoneAttestationConfig{Required: true, MaxAge: 5 * time.Minute})

	zones := map[string]*ZoneAttestationConfig{
		"public.example.com.": {Required: true, MaxAge: 2 * time.Minute, Fallback: FallbackDeny},
		"internal.local.":     {Required: false, MaxAge: 10 * time.Minute, Fallback: FallbackAllowWithWarning},
		"secure.corp.":        {Required: true, MaxAge: 1 * time.Minute, Fallback: FallbackDeny},
	}
	for zone, config := range zones {
		guard.SetZoneConfig(zone, config)
	}

	assert.Equal(t, 3, guard.ZoneCount())
	for zone, expected := range zones {
		assert.Equal(t, expected, guard.GetZoneConfig(zone), zone)
	}
}

func TestGuard_VerifyForUpdate_AttestationNotRequired(t *testing.T) {
	config := &ZoneAttestationConfig{Required: false}
	guard := NewGuard(config)
	ctx := context.Background()

	result := guard.VerifyForUpdate(ctx, "example.com.", "A", nil)

	assert.True(t, result.Allowed)
	assert.Nil(t, result.Error)
	assert.Equal(t, "attestation not required", result.Message)
}

func TestGuard_VerifyForUpdate_NoTokenWhenRequired(t *testing.T) {
	guard := NewGuard(nil) // Default requires attestation
	ctx := context.Background()

	result := guard.VerifyForUpdate(ctx, "example.com.", "A", nil)

	assert.False(t, result.Allowed)
	assert.NotNil(t, result.Error)

	var errRequired ErrAttestationRequired
	assert.ErrorAs(t, result.Error, &errRequired)
	assert.Equal(t, "example.com.", errRequired.Zone)
}

func TestGuard_VerifyForUpdate_ExpiredToken(t *testing.T) {
	guard := NewGuard(nil)
	ctx := context.Background()

	token := &AttestationToken{
		DeviceID:          "device-123",
		Issued:            time.Now().Add(-2 * time.Hour),
		Expires:           time.Now().Add(-1 * time.Hour),
		AllowedOperations: []string{"A"},
		AllowedZones:      []string{"example.com."},
	}

	result := guard.VerifyForUpdate(ctx, "example.com.", "A", token)

	assert.False(t, result.Allowed)
	assert.NotNil(t, result.Error)
	assert.Equal(t, token, result.Token)

	var errExpired ErrAttestationExpired
	assert.ErrorAs(t, result.Error, &errExpired)
	assert.Equal(t, "device-123", errExpired.DeviceID)
}

func TestGuard_VerifyForUpdate_TokenTooOld(t *testing.T) {
	config := &ZoneAttestationConfig{
		Required: true,
		MaxAge:   5 * time.Minute,
	}
	guard := NewGuard(config)
	ctx := context.Background()

	token := &AttestationToken{
		DeviceID:          "device-123",
		Issued:            time.Now().Add(-10 * time.Minute), // Issued 10 minutes ago
		Expires:           time.Now().Add(time.Hour),         // Not expired yet
		AllowedOperations: []string{"A"},
		AllowedZones:      []string{"example.com."},
	}

	result := guard.VerifyForUpdate(ctx, "example.com.", "A", token)

	assert.False(t, result.Allowed)
	assert.NotNil(t, result.Error)
	assert.Equal(t, token, result.Token)

	var errTooOld ErrAttestationTooOld
	assert.ErrorAs(t, result.Error, &errTooOld)
}

func TestGuard_VerifyForUpdate_OperationNotAllowed(t *testing.T) {
	guard := NewGuard(nil)
	ctx := context.Background()

	token := &AttestationToken{
		DeviceID:          "device-123",
		Issued:            time.Now(),
		Expires:           time.Now().Add(time.Hour),
		AllowedOperations: []string{"A", "AAAA"},
		AllowedZones:      []string{"example.com."},
	}

	result := guard.VerifyForUpdate(ctx, "example.com.", "TXT", token)

	assert.False(t, result.Allowed)
	assert.NotNil(t, result.Error)
	assert.Equal(t, token, result.Token)

	var errOp ErrOperationNotAllowed
	assert.ErrorAs(t, result.Error, &errOp)
	assert.Equal(t, "TXT", errOp.Operation)
	assert.Equal(t, []string{"A", "AAAA"}, errOp.AllowedOperations)
}

func TestGuard_VerifyForUpdate_ZoneNotAllowed(t *testing.T) {
	guard := NewGuard(nil)
	ctx := context.Background()

	token := &AttestationToken{
		DeviceID:          "device-123",
		Issued:            time.Now(),
		Expires:           time.Now().Add(time.Hour),
		AllowedOperations: []string{"A"},
		AllowedZones:      []string{"example.com.", "test.com."},
	}

	result := guard.VerifyForUpdate(ctx, "other.com.", "A", token)

	assert.False(t, result.Allowed)
	assert.NotNil(t, result.Error)
	assert.Equal(t, token, result.Token)

	var errZone ErrZoneNotAllowed
	assert.ErrorAs(t, result.Error, &errZone)
	assert.Equal(t, "other.com.", errZone.Zone)
	assert.Equal(t, []string{"example.com.", "test.com."}, errZone.AllowedZones)
}

func TestGuard_VerifyForUpdate_ValidToken(t *testing.T) {
	guard := NewGuard(nil)
	ctx := context.Background()

	token := &AttestationToken{
		DeviceID:          "device-123",
		Issued:            time.Now(),
		Expires:           time.Now().Add(time.Hour),
		AllowedOperations: []string{"A", "AAAA", "TXT"},
		AllowedZones:      []string{"example.com."},
	}

	result := guard.VerifyForUpdate(ctx, "example.com.", "A", token)

	assert.True(t, result.Allowed)
	assert.Nil(t, result.Error)
	assert.Equal(t, token, result.Token)
	assert.Equal(t, "attestation verified", result.Message)
}

func TestGuard_VerifyForUpdate_WildcardOperation(t *testing.T) {
	guard := NewGuard(nil)
	ctx := context.Background()

	token := &AttestationToken{
		DeviceID:          "device-123",
		Issued:            time.Now(),
		Expires:           time.Now().Add(time.Hour),
		AllowedOperations: []string{"*"},
		AllowedZones:      []string{"example.com."},
	}

	result := guard.VerifyForUpdate(ctx, "example.com.", "MX", token)

	assert.True(t, result.Allowed)
	assert.Nil(t, result.Error)
}

func TestGuard_VerifyForUpdate_WildcardZone(t *testing.T) {
	guard := NewGuard(nil)
	ctx := context.Background()

	token := &AttestationToken{
		DeviceID:          "device-123",
		Issued:            time.Now(),
		Expires:           time.Now().Add(time.Hour),
		AllowedOperations: []string{"A"},
		AllowedZones:      []string{"*"},
	}

	result := guard.VerifyForUpdate(ctx, "any.zone.com.", "A", token)

	assert.True(t, result.Allowed)
	assert.Nil(t, result.Error)
}

func TestGuard_VerifyForUpdate_ContextCanceled(t *testing.T) {
	guard := NewGuard(nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	token := &AttestationToken{
		DeviceID:          "device-123",
		Issued:            time.Now(),
		Expires:           time.Now().Add(time.Hour),
		AllowedOperations: []string{"A"},
		AllowedZones:      []string{"example.com."},
	}

	result := guard.VerifyForUpdate(ctx, "example.com.", "A", token)

	assert.False(t, result.Allowed)
	assert.NotNil(t, result.Error)

	var errUnavail ErrServiceUnavailable
	assert.ErrorAs(t, result.Error, &errUnavail)
}

func TestGuard_VerifyForUpdate_ZoneSpecificConfig(t *testing.T) {
	guard := NewGuard(nil) // Default requires attestation

	// Set zone-specific config that doesn't require attestation
	zoneConfig := &ZoneAttestationConfig{
		Required: false,
	}
	guard.SetZoneConfig("unrestricted.com.", zoneConfig)

	ctx := context.Background()

	t.Run("zone with attestation not required", func(t *testing.T) {
		result := guard.VerifyForUpdate(ctx, "unrestricted.com.", "A", nil)
		assert.True(t, result.Allowed)
	})

	t.Run("zone with default (attestation required)", func(t *testing.T) {
		result := guard.VerifyForUpdate(ctx, "restricted.com.", "A", nil)
		assert.False(t, result.Allowed)
	})
}

func TestGuard_VerifyForQuery(t *testing.T) {
	guard := NewGuard(nil)
	ctx := context.Background()

	t.Run("query allowed without token when attestation not required", func(t *testing.T) {
		notRequiredConfig := &ZoneAttestationConfig{Required: false}
		guardNoAttest := NewGuard(notRequiredConfig)

		result := guardNoAttest.VerifyForQuery(ctx, "example.com.", "A", nil)
		assert.True(t, result.Allowed)
		assert.Equal(t, "attestation not required for queries", result.Message)
	})

	t.Run("query allowed without token even when attestation required", func(t *testing.T) {
		result := guard.VerifyForQuery(ctx, "example.com.", "A", nil)
		assert.True(t, result.Allowed)
		assert.Equal(t, "query allowed without attestation", result.Message)
	})

	t.Run("query allowed with valid token", func(t *testing.T) {
		token := &AttestationToken{
			DeviceID: "device-123",
			Issued:   time.Now(),
			Expires:  time.Now().Add(time.Hour),
		}
		result := guard.VerifyForQuery(ctx, "example.com.", "A", token)
		assert.True(t, result.Allowed)
		assert.Equal(t, token, result.Token)
		assert.Equal(t, "query with valid attestation", result.Message)
	})

	t.Run("query allowed with expired token (with warning)", func(t *testing.T) {
		token := &AttestationToken{
			DeviceID: "device-123",
			Issued:   time.Now().Add(-2 * time.Hour),
			Expires:  time.Now().Add(-1 * time.Hour),
		}
		result := guard.VerifyForQuery(ctx, "example.com.", "A", token)
		assert.True(t, result.Allowed)
		assert.Equal(t, "query allowed with expired attestation token", result.Message)
	})

	t.Run("query fails on context cancellation", func(t *testing.T) {
		canceledCtx, cancel := context.WithCancel(ctx)
		cancel()

		result := guard.VerifyForQuery(canceledCtx, "example.com.", "A", nil)
		assert.False(t, result.Allowed)
		assert.NotNil(t, result.Error)
	})
}

func TestGuard_ZoneCount(t *testing.T) {
	guard := NewGuard(nil)
	assert.Equal(t, 0, guard.ZoneCount())

	guard.SetZoneConfig("zone1.com.", &ZoneAttestationConfig{})
	assert.Equal(t, 1, guard.ZoneCount())

	guard.SetZoneConfig("zone2.com.", &ZoneAttestationConfig{})
	assert.Equal(t, 2, guard.ZoneCount())

	guard.RemoveZoneConfig("zone1.com.")
	assert.Equal(t, 1, guard.ZoneCount())
}

func TestGuard_ConcurrentAccess(t *testing.T) {
	guard := NewGuard(nil)
	ctx := context.Background()

	// Spawn multiple goroutines to test concurrent access
	done := make(chan bool, 100)

	for i := 0; i < 50; i++ {
		go func(id int) {
			zoneName := "zone" + string(rune('A'+id%26)) + ".com."
			guard.SetZoneConfig(zoneName, &ZoneAttestationConfig{Required: id%2 == 0})
			_ = guard.GetZoneConfig(zoneName)
			done <- true
		}(i)
	}

	for i := 0; i < 50; i++ {
		go func(id int) {
			token := &AttestationToken{
				DeviceID:          "device",
				Issued:            time.Now(),
				Expires:           time.Now().Add(time.Hour),
				AllowedOperations: []string{"A"},
				AllowedZones:      []string{"*"},
			}
			_ = guard.VerifyForUpdate(ctx, "example.com.", "A", token)
			done <- true
		}(i)
	}

	for i := 0; i < 100; i++ {
		<-done
	}
}
