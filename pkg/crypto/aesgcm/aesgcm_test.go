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

package aesgcm

import (
	"crypto/rand"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Mock reader that always returns an error
type errorReader struct{}

func (e *errorReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("random reader error")
}

// Mock reader that returns EOF immediately
type eofReader struct{}

func (e *eofReader) Read(p []byte) (n int, err error) {
	return 0, io.ErrUnexpectedEOF
}

func TestSealWithoutAdditionalData(t *testing.T) {

	// Use rand.Reader for entropy
	aesgcm := NewAESGCM(nil)

	// Generate a key
	key := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, key)
	assert.Nil(t, err)

	// Seal returns one self-framing blob: nonce || ciphertext || tag
	secret := []byte("my-secret")
	ciphertext, err := aesgcm.Seal(key, secret, nil)
	assert.Nil(t, err)
	assert.Equal(t, NonceSize+len(secret)+TagSize, len(ciphertext))
	assert.NotContains(t, string(ciphertext), string(secret))

	decrypted, err := aesgcm.Open(key, ciphertext, nil)
	assert.Nil(t, err)
	assert.Equal(t, secret, decrypted)

	// A corrupted nonce prefix must not authenticate
	corrupt := append([]byte{}, ciphertext...)
	corrupt[0] ^= 0xff
	_, err = aesgcm.Open(key, corrupt, nil)
	assert.NotNil(t, err)
}

func TestSealProducesDistinctCiphertexts(t *testing.T) {
	// The nonce is drawn per call, so sealing the same plaintext twice under
	// the same key must not repeat — nonce reuse is the one failure that
	// breaks GCM outright.
	aesgcm := NewAESGCM(nil)

	key := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, key)
	assert.Nil(t, err)

	secret := []byte("my-secret")
	first, err := aesgcm.Seal(key, secret, nil)
	assert.Nil(t, err)
	second, err := aesgcm.Seal(key, secret, nil)
	assert.Nil(t, err)
	assert.NotEqual(t, first, second)
}

func TestSealWithAdditionalData(t *testing.T) {

	// Use rand.Reader for entropy
	aesgcm := NewAESGCM(nil)

	// Generate a key
	key := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, key)
	assert.Nil(t, err)

	// Create "additional data". The Open operation will fail
	// if the additional data does not match the same data
	// that was passed to Seal.
	additionalData := []byte("some authorization data")

	secret := []byte("my-secret")
	ciphertext, err := aesgcm.Seal(key, secret, additionalData)
	assert.Nil(t, err)

	decrypted, err := aesgcm.Open(key, ciphertext, additionalData)
	assert.Nil(t, err)
	assert.Equal(t, secret, decrypted)

	// Ensure failure when additional data doesnt match
	_, err = aesgcm.Open(key, ciphertext, []byte("foo"))
	assert.NotNil(t, err)
}

func TestGenerateKey(t *testing.T) {
	aesgcm := NewAESGCM(nil)
	key := aesgcm.GenerateKey()
	assert.Equal(t, 32, len(key))
	assert.NotEqual(t, string(key), string(aesgcm.GenerateKey()))
}

// TestGenerateKeyWithRandomReaderError covers the entropy seam's error path.
// The seam feeds key generation only: since #209 the AEAD nonce comes from the
// cipher itself, because an explicit-nonce GCM cannot be constructed at all
// under GODEBUG=fips140=only.
func TestGenerateKeyWithRandomReaderError(t *testing.T) {
	aesgcm := NewAESGCM(&errorReader{})
	assert.PanicsWithValue(t, "random reader error", func() { aesgcm.GenerateKey() })
}

func TestGenerateKeyWithEOFReader(t *testing.T) {
	aesgcm := NewAESGCM(&eofReader{})
	assert.Panics(t, func() { aesgcm.GenerateKey() })
}

func TestSealWithInvalidKey(t *testing.T) {
	aesgcm := NewAESGCM(nil)

	// Test with invalid key size (AES requires 16, 24, or 32 bytes)
	invalidKey := []byte("short")
	data := []byte("test data")

	_, err := aesgcm.Seal(invalidKey, data, nil)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "invalid key size")
}

func TestOpenWithInvalidKey(t *testing.T) {
	aesgcm := NewAESGCM(nil)

	// Test with invalid key size
	invalidKey := []byte("short")
	ciphertext := make([]byte, NonceSize+TagSize)

	_, err := aesgcm.Open(invalidKey, ciphertext, nil)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "invalid key size")
}

func TestOpenWithInvalidCiphertext(t *testing.T) {
	aesgcm := NewAESGCM(nil)

	key := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, key)
	assert.Nil(t, err)

	sealed, err := aesgcm.Seal(key, []byte("secret"), nil)
	assert.Nil(t, err)

	t.Run("a blob shorter than nonce and tag is a typed error", func(t *testing.T) {
		_, err := aesgcm.Open(key, sealed[:NonceSize+TagSize-1], nil)
		var tooShort ErrCiphertextTooShort
		assert.ErrorAs(t, err, &tooShort)
		assert.Equal(t, NonceSize+TagSize-1, tooShort.Length)
	})

	t.Run("a blob of exactly nonce and tag reaches authentication", func(t *testing.T) {
		_, err := aesgcm.Open(key, sealed[:NonceSize+TagSize], nil)
		assert.Error(t, err)
		var tooShort ErrCiphertextTooShort
		assert.False(t, errors.As(err, &tooShort))
	})
}

func TestNewAESGCMWithCustomReader(t *testing.T) {
	// Test with a custom reader
	aesgcm := NewAESGCM(rand.Reader)
	assert.NotNil(t, aesgcm)

	// Verify it works with custom reader
	key := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, key)
	assert.Nil(t, err)

	secret := []byte("test-secret")
	ciphertext, err := aesgcm.Seal(key, secret, nil)
	assert.Nil(t, err)
	assert.NotNil(t, ciphertext)

	// Verify decryption works
	decrypted, err := aesgcm.Open(key, ciphertext, nil)
	assert.Nil(t, err)
	assert.Equal(t, secret, decrypted)
}

func TestErrCiphertextTooShort(t *testing.T) {
	err := ErrCiphertextTooShort{Length: 5}
	assert.EqualError(t, err,
		"aesgcm: ciphertext of 5 bytes is shorter than nonce and tag (28 bytes)")
}
