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

package installer

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewFIDO2Enrollment(t *testing.T) {
	t.Run("nil config", func(t *testing.T) {
		_, err := NewFIDO2Enrollment(nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "config is required")
	})

	t.Run("valid config with defaults", func(t *testing.T) {
		config := &FIDO2EnrollmentConfig{
			LUKSDevice:     "/dev/vda2",
			LUKSPassphrase: "test-password",
		}

		enrollment, err := NewFIDO2Enrollment(config)
		require.NoError(t, err)
		assert.NotNil(t, enrollment)

		// Check defaults were applied
		assert.Equal(t, 3, config.TargetKeyslot)
		assert.Equal(t, "luks-alpine", config.RelyingPartyID)
		assert.Equal(t, "luks-user", config.UserName)
	})

	t.Run("valid config with custom values", func(t *testing.T) {
		config := &FIDO2EnrollmentConfig{
			LUKSDevice:     "/dev/sda2",
			LUKSPassphrase: "my-password",
			TargetKeyslot:  4,
			RelyingPartyID: "custom-rp",
			UserName:       "custom-user",
		}

		enrollment, err := NewFIDO2Enrollment(config)
		require.NoError(t, err)
		assert.NotNil(t, enrollment)

		// Custom values should be preserved
		assert.Equal(t, 4, config.TargetKeyslot)
		assert.Equal(t, "custom-rp", config.RelyingPartyID)
		assert.Equal(t, "custom-user", config.UserName)
	})
}

func TestFIDO2Token(t *testing.T) {
	t.Run("valid token structure", func(t *testing.T) {
		token := FIDO2Token{
			Type:            "fido2-manual",
			Keyslots:        []string{"3"},
			FIDO2Credential: "Y3JlZGVudGlhbC1pZC1iYXNlNjQ=",
			FIDO2Salt:       "c2FsdC1iYXNlNjQ=",
			FIDO2RP:         "luks-alpine",
			FIDO2UPRequired: true,
		}

		assert.Equal(t, "fido2-manual", token.Type)
		assert.Len(t, token.Keyslots, 1)
		assert.Equal(t, "3", token.Keyslots[0])
		assert.NotEmpty(t, token.FIDO2Credential)
		assert.NotEmpty(t, token.FIDO2Salt)
		assert.Equal(t, "luks-alpine", token.FIDO2RP)
		assert.True(t, token.FIDO2UPRequired)
	})
}

func TestRandomRead(t *testing.T) {
	t.Run("read random bytes", func(t *testing.T) {
		buf := make([]byte, 32)
		n, err := randomRead(buf)
		require.NoError(t, err)
		assert.Equal(t, 32, n)

		// Check that buffer was filled (not all zeros)
		allZeros := true
		for _, b := range buf {
			if b != 0 {
				allZeros = false
				break
			}
		}
		assert.False(t, allZeros, "buffer should contain non-zero bytes")
	})

	t.Run("different reads produce different results", func(t *testing.T) {
		buf1 := make([]byte, 32)
		buf2 := make([]byte, 32)

		_, err := randomRead(buf1)
		require.NoError(t, err)

		_, err = randomRead(buf2)
		require.NoError(t, err)

		// Buffers should be different (extremely unlikely to be same)
		assert.NotEqual(t, buf1, buf2)
	})
}

func TestMin(t *testing.T) {
	tests := []struct {
		a, b, expected int
	}{
		{1, 2, 1},
		{2, 1, 1},
		{0, 0, 0},
		{-1, 1, -1},
		{100, 50, 50},
	}

	for _, tt := range tests {
		result := min(tt.a, tt.b)
		assert.Equal(t, tt.expected, result)
	}
}

func TestDetectFIDO2Device(t *testing.T) {
	t.Run("no fido2 tools available", func(t *testing.T) {
		// This test will pass on systems without fido2-token
		// The function should gracefully return empty string
		device, err := DetectFIDO2Device()
		require.NoError(t, err)
		// Either empty (no tools) or actual device path
		_ = device // Just check no panic/error
	})
}

func TestIsFIDO2Available(t *testing.T) {
	t.Run("check availability", func(t *testing.T) {
		// This should not panic or error
		available := IsFIDO2Available()
		// Result depends on system configuration
		_ = available
	})
}
