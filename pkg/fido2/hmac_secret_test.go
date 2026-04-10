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

package fido2

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHMACSecretExtension(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer ctapDev.Close()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	// Mock authenticator supports hmac-secret
	hmacExt, err := NewHMACSecretExtension(auth)
	assert.NoError(t, err)
	assert.NotNil(t, hmacExt)
}

func TestNewHMACSecretExtension_NotSupported(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer ctapDev.Close()

	// Create auth without getting info (so no extensions)
	auth := &Authenticator{
		device: ctapDev,
		config: &config,
		info: &DeviceInfo{
			Extensions: []string{}, // No hmac-secret
		},
	}

	hmacExt, err := NewHMACSecretExtension(auth)
	assert.Error(t, err)
	assert.Nil(t, hmacExt)
	assert.ErrorIs(t, err, ErrUnsupportedExtension)
}

func TestHMACSecretExtension_EnrollCredential(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer ctapDev.Close()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	hmacExt, err := NewHMACSecretExtension(auth)
	require.NoError(t, err)

	enrollConfig := &EnrollmentConfig{
		RelyingParty: RelyingParty{
			ID:   "example.com",
			Name: "Example Corp",
		},
		User: User{
			Name:        "test@example.com",
			DisplayName: "Test User",
		},
		RequireUserVerification: false,
	}

	result, err := hmacExt.EnrollCredential(enrollConfig)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.NotEmpty(t, result.CredentialID)
	assert.NotEmpty(t, result.Salt)
	// Note: PublicKey requires a fully-formed COSE key in mock response
	// which is complex to mock. The field may be empty with basic mock.
	assert.Equal(t, 16, len(result.AAGUID))
	assert.Equal(t, "example.com", result.RelyingParty.ID)
	assert.NotEmpty(t, result.User.ID)
}

func TestHMACSecretExtension_EnrollCredential_WithCustomSalt(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer ctapDev.Close()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	hmacExt, err := NewHMACSecretExtension(auth)
	require.NoError(t, err)

	customSalt := make([]byte, 32)
	for i := range customSalt {
		customSalt[i] = byte(i)
	}

	enrollConfig := &EnrollmentConfig{
		RelyingParty: RelyingParty{
			ID:   "example.com",
			Name: "Example Corp",
		},
		User: User{
			Name:        "test@example.com",
			DisplayName: "Test User",
		},
		Salt:                    customSalt,
		RequireUserVerification: false,
	}

	result, err := hmacExt.EnrollCredential(enrollConfig)
	require.NoError(t, err)

	assert.Equal(t, customSalt, result.Salt)
}

func TestHMACSecretExtension_DeriveSecret(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer ctapDev.Close()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	hmacExt, err := NewHMACSecretExtension(auth)
	require.NoError(t, err)

	credID := make([]byte, 32)
	salt := make([]byte, 32)

	authConfig := &AuthenticationConfig{
		RelyingPartyID:          "example.com",
		CredentialID:            credID,
		Salt:                    salt,
		RequireUserVerification: false,
	}

	result, err := hmacExt.DeriveSecret(authConfig)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.NotEmpty(t, result.HMACSecret)
	assert.NotEmpty(t, result.AuthData)
	assert.NotEmpty(t, result.Signature)
	assert.True(t, result.UserPresent)
}

func TestGenerateLUKSKey(t *testing.T) {
	tests := []struct {
		name        string
		hmacSecret  []byte
		expectError bool
	}{
		{
			name:        "valid 32-byte secret",
			hmacSecret:  make([]byte, 32),
			expectError: false,
		},
		{
			name:        "invalid length - too short",
			hmacSecret:  make([]byte, 16),
			expectError: true,
		},
		{
			name:        "invalid length - too long",
			hmacSecret:  make([]byte, 64),
			expectError: true,
		},
		{
			name:        "empty secret",
			hmacSecret:  []byte{},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			luksKey, err := GenerateLUKSKey(tt.hmacSecret)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, luksKey)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, luksKey)
				assert.Equal(t, 64, len(luksKey), "LUKS key should be 512 bits (64 bytes)")

				// Verify deterministic output
				luksKey2, err := GenerateLUKSKey(tt.hmacSecret)
				assert.NoError(t, err)
				assert.Equal(t, luksKey, luksKey2, "same input should produce same output")
			}
		})
	}
}

func TestGenerateLUKSKey_Uniqueness(t *testing.T) {
	secret1 := make([]byte, 32)
	secret2 := make([]byte, 32)
	secret2[0] = 1 // Make it different

	key1, err := GenerateLUKSKey(secret1)
	require.NoError(t, err)

	key2, err := GenerateLUKSKey(secret2)
	require.NoError(t, err)

	assert.NotEqual(t, key1, key2, "different secrets should produce different keys")
}

func TestVerifyHMACSecret(t *testing.T) {
	tests := []struct {
		name        string
		secret      []byte
		expectError bool
	}{
		{
			name:        "valid 32-byte secret",
			secret:      make([]byte, 32),
			expectError: false,
		},
		{
			name:        "valid 64-byte secret",
			secret:      make([]byte, 64),
			expectError: false,
		},
		{
			name:        "invalid length",
			secret:      make([]byte, 16),
			expectError: true,
		},
		{
			name:        "empty secret",
			secret:      []byte{},
			expectError: true,
		},
		{
			name:        "nil secret",
			secret:      nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyHMACSecret(tt.secret)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestParseAuthDataExtensions(t *testing.T) {
	tests := []struct {
		name        string
		authData    []byte
		expectError bool
		expectNil   bool
	}{
		{
			name:        "too short",
			authData:    make([]byte, 30),
			expectError: true,
		},
		{
			name: "no extensions flag",
			authData: func() []byte {
				data := make([]byte, 37)
				data[32] = 0x00 // flags with no ED bit
				return data
			}(),
			expectError: false,
			expectNil:   true,
		},
		{
			name: "extensions flag set",
			authData: func() []byte {
				data := make([]byte, 40)
				data[32] = 0x80 // flags with ED bit
				return data
			}(),
			expectError: false,
			expectNil:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extensions, err := ParseAuthDataExtensions(tt.authData)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.expectNil {
					assert.Nil(t, extensions)
				}
			}
		})
	}
}

func TestHMACSecretExtension_FullFlow(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer ctapDev.Close()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	hmacExt, err := NewHMACSecretExtension(auth)
	require.NoError(t, err)

	// Step 1: Enroll credential
	enrollConfig := &EnrollmentConfig{
		RelyingParty: RelyingParty{
			ID:   "luks-unlock",
			Name: "LUKS Disk Encryption",
		},
		User: User{
			Name:        "testuser",
			DisplayName: "Test User",
		},
		RequireUserVerification: false,
	}

	enrollResult, err := hmacExt.EnrollCredential(enrollConfig)
	require.NoError(t, err)
	require.NotNil(t, enrollResult)

	// Step 2: Derive secret using enrolled credential
	authConfig := &AuthenticationConfig{
		RelyingPartyID:          enrollResult.RelyingParty.ID,
		CredentialID:            enrollResult.CredentialID,
		Salt:                    enrollResult.Salt,
		RequireUserVerification: false,
	}

	authResult, err := hmacExt.DeriveSecret(authConfig)
	require.NoError(t, err)
	require.NotNil(t, authResult)

	// Step 3: Generate LUKS key
	luksKey, err := GenerateLUKSKey(authResult.HMACSecret)
	require.NoError(t, err)
	require.NotNil(t, luksKey)

	assert.Equal(t, 64, len(luksKey))

	// Verify deterministic key generation
	luksKey2, err := GenerateLUKSKey(authResult.HMACSecret)
	require.NoError(t, err)
	assert.Equal(t, luksKey, luksKey2)
}

func TestHMACSecretOutput(t *testing.T) {
	output := &HMACSecretOutput{
		Output: make([]byte, 32),
	}

	assert.Equal(t, 32, len(output.Output))
}

func TestAuthenticationResult_Flags(t *testing.T) {
	result := &AuthenticationResult{
		HMACSecret:     make([]byte, 32),
		SignCount:      5,
		UserPresent:    true,
		UserVerified:   false,
		BackupEligible: false,
		BackupState:    false,
		Signature:      make([]byte, 64),
		AuthData:       make([]byte, 37),
	}

	assert.True(t, result.UserPresent)
	assert.False(t, result.UserVerified)
	assert.False(t, result.BackupEligible)
	assert.Equal(t, uint32(5), result.SignCount)
}

// TestHMACSecretExtension_DeriveSecret_WithCustomChallenge tests derivation with custom challenge
func TestHMACSecretExtension_DeriveSecret_WithCustomChallenge(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer ctapDev.Close()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	hmacExt, err := NewHMACSecretExtension(auth)
	require.NoError(t, err)

	customChallenge := make([]byte, 32)
	for i := range customChallenge {
		customChallenge[i] = byte(i)
	}

	authConfig := &AuthenticationConfig{
		RelyingPartyID:          "example.com",
		CredentialID:            make([]byte, 32),
		Salt:                    make([]byte, 32),
		Challenge:               customChallenge,
		RequireUserVerification: false,
	}

	result, err := hmacExt.DeriveSecret(authConfig)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.NotEmpty(t, result.HMACSecret)
}

// TestGenerateLUKSKey_Deterministic tests that the same input always produces the same output
func TestGenerateLUKSKey_Deterministic(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}

	// Generate multiple times
	key1, err := GenerateLUKSKey(secret)
	require.NoError(t, err)

	key2, err := GenerateLUKSKey(secret)
	require.NoError(t, err)

	key3, err := GenerateLUKSKey(secret)
	require.NoError(t, err)

	// All should be identical
	assert.Equal(t, key1, key2)
	assert.Equal(t, key2, key3)
}

// TestGenerateLUKSKey_DifferentInputs tests that different inputs produce different outputs
func TestGenerateLUKSKey_DifferentInputs(t *testing.T) {
	secret1 := make([]byte, 32)
	secret2 := make([]byte, 32)
	secret3 := make([]byte, 32)

	// Make them different
	secret1[0] = 0x01
	secret2[0] = 0x02
	secret3[0] = 0x03

	key1, err := GenerateLUKSKey(secret1)
	require.NoError(t, err)

	key2, err := GenerateLUKSKey(secret2)
	require.NoError(t, err)

	key3, err := GenerateLUKSKey(secret3)
	require.NoError(t, err)

	// All should be different
	assert.NotEqual(t, key1, key2)
	assert.NotEqual(t, key2, key3)
	assert.NotEqual(t, key1, key3)
}

// TestHMACSecretOutput_Structure tests the HMACSecretOutput struct
func TestHMACSecretOutput_Structure(t *testing.T) {
	output := &HMACSecretOutput{
		Output: make([]byte, 32),
	}

	assert.NotNil(t, output.Output)
	assert.Equal(t, 32, len(output.Output))

	// Test with 64-byte output
	output64 := &HMACSecretOutput{
		Output: make([]byte, 64),
	}

	assert.Equal(t, 64, len(output64.Output))
}

// TestParseAuthDataExtensions_NoExtensionsData tests when extensions flag is set but no data
func TestParseAuthDataExtensions_NoExtensionsData(t *testing.T) {
	// Create minimal authData with ED flag but at exact boundary
	authData := make([]byte, 37)
	authData[32] = 0x80 // ED flag only

	extensions, err := ParseAuthDataExtensions(authData)
	assert.NoError(t, err)
	assert.Nil(t, extensions)
}

// TestVerifyHMACSecret_AllCases tests all VerifyHMACSecret cases comprehensively
func TestVerifyHMACSecret_AllCases(t *testing.T) {
	tests := []struct {
		name        string
		secret      []byte
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid 32 bytes",
			secret:      make([]byte, 32),
			expectError: false,
		},
		{
			name:        "valid 64 bytes",
			secret:      make([]byte, 64),
			expectError: false,
		},
		{
			name:        "invalid: too short",
			secret:      make([]byte, 16),
			expectError: true,
			errorMsg:    "invalid HMAC secret length",
		},
		{
			name:        "invalid: too long",
			secret:      make([]byte, 128),
			expectError: true,
			errorMsg:    "invalid HMAC secret length",
		},
		{
			name:        "invalid: empty",
			secret:      []byte{},
			expectError: true,
		},
		{
			name:        "invalid: nil",
			secret:      nil,
			expectError: true,
		},
		{
			name:        "invalid: single byte",
			secret:      []byte{0x00},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyHMACSecret(tt.secret)
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
