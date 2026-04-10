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

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		config      Config
		expectError bool
		checkFields func(*testing.T, *Config)
	}{
		{
			name:        "valid default config",
			config:      DefaultConfig,
			expectError: false,
		},
		{
			name: "zero timeout gets default",
			config: Config{
				Timeout: 0,
			},
			expectError: false,
			checkFields: func(t *testing.T, c *Config) {
				assert.Equal(t, DefaultTimeout, c.Timeout)
			},
		},
		{
			name: "negative retry count gets default",
			config: Config{
				RetryCount: -1,
			},
			expectError: false,
			checkFields: func(t *testing.T, c *Config) {
				assert.Equal(t, DefaultRetryCount, c.RetryCount)
			},
		},
		{
			name: "empty RP ID gets default",
			config: Config{
				RelyingPartyID: "",
			},
			expectError: false,
			checkFields: func(t *testing.T, c *Config) {
				assert.Equal(t, "luks-unlock", c.RelyingPartyID)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.checkFields != nil {
					tt.checkFields(t, &tt.config)
				}
			}
		})
	}
}

func TestDeviceInfo_Fields(t *testing.T) {
	info := &DeviceInfo{
		Versions:   []string{"FIDO_2_0", "U2F_V2"},
		Extensions: []string{"hmac-secret", "credProtect"},
		AAGUID:     make([]byte, 16),
		Options: map[string]bool{
			"rk":   true,
			"up":   true,
			"plat": false,
		},
		MaxMsgSize:   1200,
		PINProtocols: []uint64{1},
	}

	assert.Equal(t, 2, len(info.Versions))
	assert.Equal(t, "FIDO_2_0", info.Versions[0])
	assert.Equal(t, 2, len(info.Extensions))
	assert.Equal(t, "hmac-secret", info.Extensions[0])
	assert.True(t, info.Options["rk"])
	assert.False(t, info.Options["plat"])
	assert.Equal(t, uint64(1200), info.MaxMsgSize)
}

func TestDefaultPublicKeyCredentialParameters(t *testing.T) {
	params := DefaultPublicKeyCredentialParameters()

	require.NotEmpty(t, params)
	assert.GreaterOrEqual(t, len(params), 3)

	// Check for common algorithms
	hasES256 := false
	hasRS256 := false

	for _, param := range params {
		assert.Equal(t, "public-key", param.Type)
		if param.Alg == COSEAlgES256 {
			hasES256 = true
		}
		if param.Alg == COSEAlgRS256 {
			hasRS256 = true
		}
	}

	assert.True(t, hasES256, "should include ES256 algorithm")
	assert.True(t, hasRS256, "should include RS256 algorithm")
}

func TestCreateClientDataHash(t *testing.T) {
	challenge := []byte("test challenge data")
	hash := CreateClientDataHash(challenge)

	assert.NotNil(t, hash)
	assert.Equal(t, 32, len(hash), "SHA-256 hash should be 32 bytes")

	// Same input should produce same hash
	hash2 := CreateClientDataHash(challenge)
	assert.Equal(t, hash, hash2)

	// Different input should produce different hash
	hash3 := CreateClientDataHash([]byte("different challenge"))
	assert.NotEqual(t, hash, hash3)
}

func TestEnrollmentConfig_Defaults(t *testing.T) {
	config := DefaultEnrollmentConfig("testuser")

	assert.Equal(t, "luks-unlock", config.RelyingParty.ID)
	assert.Equal(t, "LUKS Disk Encryption", config.RelyingParty.Name)
	assert.Equal(t, "testuser", config.User.Name)
	assert.Equal(t, "testuser", config.User.DisplayName)
	assert.False(t, config.RequireUserVerification)
	assert.Equal(t, DefaultUserPresenceTimeout, config.Timeout)
}

func TestAuthenticationConfig_Defaults(t *testing.T) {
	credID := make([]byte, 32)
	salt := make([]byte, 32)

	config := DefaultAuthenticationConfig(credID, salt)

	assert.Equal(t, "luks-unlock", config.RelyingPartyID)
	assert.Equal(t, credID, config.CredentialID)
	assert.Equal(t, salt, config.Salt)
	assert.False(t, config.RequireUserVerification)
	assert.Equal(t, DefaultUserPresenceTimeout, config.Timeout)
}

func TestDevice_Fields(t *testing.T) {
	device := Device{
		Path:         "/dev/hidraw0",
		VendorID:     0x1234,
		ProductID:    0x5678,
		Manufacturer: "Test Manufacturer",
		Product:      "Test Security Key",
		SerialNumber: "ABC123",
		Transport:    "usb",
	}

	assert.Equal(t, "/dev/hidraw0", device.Path)
	assert.Equal(t, uint16(0x1234), device.VendorID)
	assert.Equal(t, uint16(0x5678), device.ProductID)
	assert.Equal(t, "Test Manufacturer", device.Manufacturer)
	assert.Equal(t, "Test Security Key", device.Product)
	assert.Equal(t, "ABC123", device.SerialNumber)
	assert.Equal(t, "usb", device.Transport)
}

func TestErrorTypes(t *testing.T) {
	// Verify error constants are defined
	errors := []error{
		ErrNoDeviceFound,
		ErrDeviceNotResponding,
		ErrInvalidCredentialID,
		ErrInvalidSalt,
		ErrUserPresenceRequired,
		ErrOperationTimeout,
		ErrInvalidCBOR,
		ErrUnsupportedExtension,
		ErrInvalidHMACSecret,
		ErrDeviceError,
		ErrInvalidAssertion,
		ErrCredentialNotFound,
		ErrPINRequired,
		ErrInvalidPIN,
		ErrPINBlocked,
		ErrUVRequired,
		ErrInvalidRelyingParty,
		ErrInvalidClientDataHash,
		ErrCBORTruncated,
	}

	for _, err := range errors {
		assert.NotNil(t, err)
		assert.NotEmpty(t, err.Error())
	}
}

func TestPublicKeyCredentialDescriptor(t *testing.T) {
	desc := PublicKeyCredentialDescriptor{
		Type:       "public-key",
		ID:         make([]byte, 32),
		Transports: []string{"usb", "nfc"},
	}

	assert.Equal(t, "public-key", desc.Type)
	assert.Equal(t, 32, len(desc.ID))
	assert.Equal(t, 2, len(desc.Transports))
	assert.Equal(t, "usb", desc.Transports[0])
}

func TestAuthenticatorOptions(t *testing.T) {
	opts := AuthenticatorOptions{
		RK: true,
		UP: true,
		UV: false,
	}

	assert.True(t, opts.RK)
	assert.True(t, opts.UP)
	assert.False(t, opts.UV)
}

func TestRelyingParty(t *testing.T) {
	rp := RelyingParty{
		ID:   "example.com",
		Name: "Example Corp",
		Icon: "https://example.com/icon.png",
	}

	assert.Equal(t, "example.com", rp.ID)
	assert.Equal(t, "Example Corp", rp.Name)
	assert.Equal(t, "https://example.com/icon.png", rp.Icon)
}

func TestUser(t *testing.T) {
	user := User{
		ID:          []byte("user123"),
		Name:        "john@example.com",
		DisplayName: "John Doe",
		Icon:        "https://example.com/user.png",
	}

	assert.Equal(t, []byte("user123"), user.ID)
	assert.Equal(t, "john@example.com", user.Name)
	assert.Equal(t, "John Doe", user.DisplayName)
	assert.Equal(t, "https://example.com/user.png", user.Icon)
}
