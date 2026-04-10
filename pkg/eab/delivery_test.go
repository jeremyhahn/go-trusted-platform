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
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func testCredential() *Credential {
	return &Credential{
		ID:        12345,
		KeyID:     "test-key-id-abc123",
		HMACKey:   []byte("this-is-a-32-byte-hmac-key-test!"),
		ProfileID: 100,
		TenantID:  "tenant-xyz",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		Status:    StatusActive,
		CreatedAt: time.Now(),
	}
}

func TestDefaultDeliveryConfig(t *testing.T) {
	config := DefaultDeliveryConfig()
	assert.Equal(t, 256, config.QRCodeSize)
	assert.Empty(t, config.BaseURL)
}

func TestNewDelivery(t *testing.T) {
	t.Run("uses provided config", func(t *testing.T) {
		config := DeliveryConfig{
			BaseURL:    "https://example.com",
			QRCodeSize: 512,
		}
		delivery := NewDelivery(config)
		assert.Equal(t, 512, delivery.config.QRCodeSize)
		assert.Equal(t, "https://example.com", delivery.config.BaseURL)
	})

	t.Run("defaults QRCodeSize when zero", func(t *testing.T) {
		config := DeliveryConfig{QRCodeSize: 0}
		delivery := NewDelivery(config)
		assert.Equal(t, 256, delivery.config.QRCodeSize)
	})

	t.Run("defaults QRCodeSize when negative", func(t *testing.T) {
		config := DeliveryConfig{QRCodeSize: -100}
		delivery := NewDelivery(config)
		assert.Equal(t, 256, delivery.config.QRCodeSize)
	})
}

func TestDelivery_ToQRCode(t *testing.T) {
	t.Run("generates valid PNG", func(t *testing.T) {
		delivery := NewDelivery(DefaultDeliveryConfig())
		cred := testCredential()

		data, err := delivery.ToQRCode(cred)
		assert.NoError(t, err)
		assert.NotEmpty(t, data)

		// Check PNG magic bytes
		assert.True(t, len(data) > 8)
		assert.Equal(t, byte(0x89), data[0])
		assert.Equal(t, byte('P'), data[1])
		assert.Equal(t, byte('N'), data[2])
		assert.Equal(t, byte('G'), data[3])
	})

	t.Run("generates QR code with custom size", func(t *testing.T) {
		config := DeliveryConfig{QRCodeSize: 128}
		delivery := NewDelivery(config)
		cred := testCredential()

		data, err := delivery.ToQRCode(cred)
		assert.NoError(t, err)
		assert.NotEmpty(t, data)
	})
}

func TestDelivery_ToQRCodeFile(t *testing.T) {
	t.Run("writes QR code to file", func(t *testing.T) {
		delivery := NewDelivery(DefaultDeliveryConfig())
		cred := testCredential()

		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "qr.png")

		err := delivery.ToQRCodeFile(cred, path)
		assert.NoError(t, err)

		data, err := os.ReadFile(path)
		assert.NoError(t, err)
		assert.NotEmpty(t, data)

		// Check PNG magic bytes
		assert.Equal(t, byte(0x89), data[0])
	})

	t.Run("creates parent directories", func(t *testing.T) {
		delivery := NewDelivery(DefaultDeliveryConfig())
		cred := testCredential()

		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "subdir", "nested", "qr.png")

		err := delivery.ToQRCodeFile(cred, path)
		assert.NoError(t, err)

		_, err = os.Stat(path)
		assert.NoError(t, err)
	})
}

func TestDelivery_ToFile(t *testing.T) {
	t.Run("writes JSON to file", func(t *testing.T) {
		delivery := NewDelivery(DefaultDeliveryConfig())
		cred := testCredential()

		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "cred.json")

		err := delivery.ToFile(cred, path)
		assert.NoError(t, err)

		data, err := os.ReadFile(path)
		assert.NoError(t, err)

		var exported ExportedCredential
		err = json.Unmarshal(data, &exported)
		assert.NoError(t, err)
		assert.Equal(t, cred.KeyID, exported.KeyID)
	})

	t.Run("creates parent directories", func(t *testing.T) {
		delivery := NewDelivery(DefaultDeliveryConfig())
		cred := testCredential()

		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "subdir", "cred.json")

		err := delivery.ToFile(cred, path)
		assert.NoError(t, err)

		_, err = os.Stat(path)
		assert.NoError(t, err)
	})

	t.Run("file has secure permissions", func(t *testing.T) {
		delivery := NewDelivery(DefaultDeliveryConfig())
		cred := testCredential()

		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "cred.json")

		err := delivery.ToFile(cred, path)
		assert.NoError(t, err)

		info, err := os.Stat(path)
		assert.NoError(t, err)
		assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
	})
}

func TestDelivery_ToJSON(t *testing.T) {
	t.Run("exports credential to JSON", func(t *testing.T) {
		delivery := NewDelivery(DefaultDeliveryConfig())
		cred := testCredential()

		data, err := delivery.ToJSON(cred)
		assert.NoError(t, err)

		var exported ExportedCredential
		err = json.Unmarshal(data, &exported)
		assert.NoError(t, err)
		assert.Equal(t, cred.KeyID, exported.KeyID)
		assert.Equal(t, cred.ProfileID, exported.ProfileID)
		assert.Equal(t, cred.TenantID, exported.TenantID)
	})

	t.Run("HMAC key is base64 encoded", func(t *testing.T) {
		delivery := NewDelivery(DefaultDeliveryConfig())
		cred := testCredential()

		data, err := delivery.ToJSON(cred)
		assert.NoError(t, err)

		var exported ExportedCredential
		err = json.Unmarshal(data, &exported)
		assert.NoError(t, err)

		decoded, err := exported.DecodeHMACKey()
		assert.NoError(t, err)
		assert.Equal(t, cred.HMACKey, decoded)
	})

	t.Run("includes expiration when set", func(t *testing.T) {
		delivery := NewDelivery(DefaultDeliveryConfig())
		cred := testCredential()

		data, err := delivery.ToJSON(cred)
		assert.NoError(t, err)

		var exported ExportedCredential
		err = json.Unmarshal(data, &exported)
		assert.NoError(t, err)
		assert.NotEmpty(t, exported.ExpiresAt)
	})

	t.Run("omits expiration when not set", func(t *testing.T) {
		delivery := NewDelivery(DefaultDeliveryConfig())
		cred := testCredential()
		cred.ExpiresAt = time.Time{}

		data, err := delivery.ToJSON(cred)
		assert.NoError(t, err)

		var exported ExportedCredential
		err = json.Unmarshal(data, &exported)
		assert.NoError(t, err)
		assert.Empty(t, exported.ExpiresAt)
	})
}

func TestDelivery_ToURL(t *testing.T) {
	t.Run("generates enrollment URL", func(t *testing.T) {
		config := DeliveryConfig{BaseURL: "https://acme.example.com"}
		delivery := NewDelivery(config)
		cred := testCredential()

		url, err := delivery.ToURL(cred)
		assert.NoError(t, err)
		assert.Contains(t, url, "https://acme.example.com")
		assert.Contains(t, url, "kid="+cred.KeyID)
		assert.Contains(t, url, "hmac=")
	})

	t.Run("returns error when base URL not configured", func(t *testing.T) {
		delivery := NewDelivery(DefaultDeliveryConfig())
		cred := testCredential()

		_, err := delivery.ToURL(cred)
		assert.Error(t, err)
		var invalidErr ErrInvalidCredential
		assert.ErrorAs(t, err, &invalidErr)
	})

	t.Run("returns error for invalid base URL", func(t *testing.T) {
		config := DeliveryConfig{BaseURL: "://invalid"}
		delivery := NewDelivery(config)
		cred := testCredential()

		_, err := delivery.ToURL(cred)
		assert.Error(t, err)
	})
}

func TestDelivery_ToURLWithPath(t *testing.T) {
	t.Run("generates URL with custom path", func(t *testing.T) {
		config := DeliveryConfig{BaseURL: "https://acme.example.com"}
		delivery := NewDelivery(config)
		cred := testCredential()

		url, err := delivery.ToURLWithPath(cred, "/enroll/device")
		assert.NoError(t, err)
		assert.Contains(t, url, "https://acme.example.com/enroll/device")
		assert.Contains(t, url, "kid="+cred.KeyID)
	})

	t.Run("returns error when base URL not configured", func(t *testing.T) {
		delivery := NewDelivery(DefaultDeliveryConfig())
		cred := testCredential()

		_, err := delivery.ToURLWithPath(cred, "/enroll")
		assert.Error(t, err)
	})
}

func TestParseExportedCredential(t *testing.T) {
	t.Run("parses valid JSON", func(t *testing.T) {
		exported := ExportedCredential{
			KeyID:     "test-key",
			HMACKey:   base64.RawURLEncoding.EncodeToString([]byte("secret")),
			ProfileID: 100,
			TenantID:  "tenant",
		}
		data, _ := json.Marshal(exported)

		parsed, err := ParseExportedCredential(data)
		assert.NoError(t, err)
		assert.Equal(t, exported.KeyID, parsed.KeyID)
	})

	t.Run("returns error for invalid JSON", func(t *testing.T) {
		_, err := ParseExportedCredential([]byte("invalid"))
		assert.Error(t, err)
	})
}

func TestExportedCredential_DecodeHMACKey(t *testing.T) {
	t.Run("decodes valid base64", func(t *testing.T) {
		original := []byte("this-is-a-secret-key")
		exported := ExportedCredential{
			HMACKey: base64.RawURLEncoding.EncodeToString(original),
		}

		decoded, err := exported.DecodeHMACKey()
		assert.NoError(t, err)
		assert.Equal(t, original, decoded)
	})

	t.Run("returns error for invalid base64", func(t *testing.T) {
		exported := ExportedCredential{
			HMACKey: "not-valid-base64!!!",
		}

		_, err := exported.DecodeHMACKey()
		assert.Error(t, err)
	})
}
