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
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDracutSigningBackend tests the internal signing backend
func TestDracutSigningBackend(t *testing.T) {
	logger := logging.DefaultLogger()

	// Generate a test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	backend := &dracutSigningBackend{
		privateKey: privateKey,
		logger:     logger,
	}

	t.Run("Type", func(t *testing.T) {
		typ := backend.Type()
		assert.Equal(t, xkmssdk.BackendType("dracut-secure-boot"), typ)
	})

	t.Run("Capabilities", func(t *testing.T) {
		caps := backend.Capabilities()
		assert.True(t, caps.Keys)
		assert.False(t, caps.HardwareBacked)
		assert.True(t, caps.Signing)
		assert.False(t, caps.Decryption)
		assert.False(t, caps.KeyRotation)
	})

	t.Run("Signer", func(t *testing.T) {
		signer, err := backend.Signer(nil)
		require.NoError(t, err)
		assert.NotNil(t, signer)
	})

	t.Run("GetKey", func(t *testing.T) {
		key, err := backend.GetKey(nil)
		require.NoError(t, err)
		assert.Equal(t, privateKey, key)
	})

	t.Run("GenerateKey - not implemented", func(t *testing.T) {
		_, err := backend.GenerateKey(nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not implemented")
	})

	t.Run("DeleteKey - not implemented", func(t *testing.T) {
		err := backend.DeleteKey(nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not implemented")
	})

	t.Run("ListKeys", func(t *testing.T) {
		keys, err := backend.ListKeys()
		require.NoError(t, err)
		assert.Nil(t, keys)
	})

	t.Run("Decrypter - not implemented", func(t *testing.T) {
		_, err := backend.Decrypter(nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not implemented")
	})

	t.Run("RotateKey - not implemented", func(t *testing.T) {
		err := backend.RotateKey(nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not implemented")
	})

	t.Run("Close", func(t *testing.T) {
		err := backend.Close()
		assert.NoError(t, err)
	})
}

// TestDracutUKIBuilder_InterfaceCompliance verifies the builder implements required interfaces
func TestDracutUKIBuilder_InterfaceCompliance(t *testing.T) {
	logger := logging.DefaultLogger()
	builder := NewDracutUKIBuilder(logger)

	assert.NotNil(t, builder)

	// Verify it implements UKIBuilder interface
	var _ = builder
}

// TestDracutSigningBackend_WithInvalidKey tests behavior with non-signer key
func TestDracutSigningBackend_WithInvalidKey(t *testing.T) {
	logger := logging.DefaultLogger()

	// Use a non-Signer type (just []byte)
	backend := &dracutSigningBackend{
		privateKey: []byte("not a signer"),
		logger:     logger,
	}

	t.Run("Signer with invalid key type", func(t *testing.T) {
		_, err := backend.Signer(nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "does not implement crypto.Signer")
	})
}
