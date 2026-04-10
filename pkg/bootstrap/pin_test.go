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

package bootstrap

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateNumericPIN_ValidLength(t *testing.T) {
	pin, err := GenerateNumericPIN(6)

	require.NoError(t, err)
	assert.Len(t, pin, 6)

	// Verify all characters are digits
	for i, b := range pin {
		assert.True(t, b >= '0' && b <= '9',
			"character at index %d should be a digit, got %c", i, b)
	}
}

func TestGenerateNumericPIN_VariousLengths(t *testing.T) {
	tests := []struct {
		name   string
		length int
	}{
		{name: "1 digit", length: 1},
		{name: "4 digits", length: 4},
		{name: "6 digits", length: 6},
		{name: "8 digits", length: 8},
		{name: "32 digits", length: 32},
		{name: "128 digits", length: 128},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pin, err := GenerateNumericPIN(tt.length)

			require.NoError(t, err)
			assert.Len(t, pin, tt.length)

			for _, b := range pin {
				assert.True(t, b >= '0' && b <= '9',
					"all characters should be digits, got %c", b)
			}
		})
	}
}

func TestGenerateNumericPIN_ZeroLength(t *testing.T) {
	pin, err := GenerateNumericPIN(0)

	require.Error(t, err)
	assert.Nil(t, pin)
	var invalidErr ErrInvalidPINLength
	assert.ErrorAs(t, err, &invalidErr)
	assert.Equal(t, 0, invalidErr.Length)
}

func TestGenerateNumericPIN_NegativeLength(t *testing.T) {
	pin, err := GenerateNumericPIN(-5)

	require.Error(t, err)
	assert.Nil(t, pin)
	var invalidErr ErrInvalidPINLength
	assert.ErrorAs(t, err, &invalidErr)
	assert.Equal(t, -5, invalidErr.Length)
}

func TestGenerateNumericPIN_Uniqueness(t *testing.T) {
	// Generate 100 PINs and verify they are not all the same
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		pin, err := GenerateNumericPIN(6)
		require.NoError(t, err)
		seen[string(pin)] = true
	}
	// With 6-digit PINs and 100 samples, we should see many unique values
	// The probability of getting fewer than 2 unique values is astronomically low
	assert.Greater(t, len(seen), 1,
		"100 random 6-digit PINs should produce more than 1 unique value")
}

func TestGenerateNumericPIN_DigitDistribution(t *testing.T) {
	// Generate many PINs and verify all 10 digits appear
	// This is a statistical test; with 1000 8-digit PINs (8000 digits),
	// each digit should appear ~800 times
	digitCount := make(map[byte]int)
	for i := 0; i < 1000; i++ {
		pin, err := GenerateNumericPIN(8)
		require.NoError(t, err)
		for _, b := range pin {
			digitCount[b]++
		}
	}
	// All 10 digits should appear
	for d := byte('0'); d <= '9'; d++ {
		assert.Greater(t, digitCount[d], 0,
			"digit %c should appear at least once in 8000 random digits", d)
	}
}

func TestErrInvalidPINLength_Error(t *testing.T) {
	err := ErrInvalidPINLength{Length: -3}

	assert.Contains(t, err.Error(), "invalid PIN length")
	assert.Contains(t, err.Error(), "-3")
	assert.Contains(t, err.Error(), "must be > 0")
}

func TestErrPINGeneration_Error(t *testing.T) {
	cause := assert.AnError
	err := ErrPINGeneration{Cause: cause}

	assert.Contains(t, err.Error(), "failed to generate PIN")
	assert.ErrorIs(t, err.Unwrap(), cause)
}

func TestErrPINGeneration_NilCause(t *testing.T) {
	err := ErrPINGeneration{}

	assert.Contains(t, err.Error(), "failed to generate PIN")
	assert.Nil(t, err.Unwrap())
}
