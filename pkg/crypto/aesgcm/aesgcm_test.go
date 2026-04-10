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

	// Seal the data and get back the cipher-text and nonce
	secret := []byte("my-secret")
	ciphertext, nonce, err := aesgcm.Seal(key, secret, nil)
	assert.Nil(t, err)

	// Open the cipher-text using the nonce returned from Seal
	decrypted, err := aesgcm.Open(key, ciphertext, nonce, nil)
	assert.Nil(t, err)
	assert.Equal(t, secret, decrypted)

	// Ensure failure with a bad nonce
	_, err = aesgcm.Open(key, ciphertext, []byte("foo"), nil)
	assert.NotNil(t, err)
	assert.Equal(t, ErrInvalidNonce, err)
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

	// Seal the data and get back the cipher-text and nonce
	secret := []byte("my-secret")
	ciphertext, nonce, err := aesgcm.Seal(key, secret, additionalData)
	assert.Nil(t, err)

	// Open the cipher-text using the nonce returned from Seal
	decrypted, err := aesgcm.Open(key, ciphertext, nonce, additionalData)
	assert.Nil(t, err)
	assert.Equal(t, secret, decrypted)

	// Ensure failure when additional data doesnt match
	_, err = aesgcm.Open(key, ciphertext, nonce, []byte("foo"))
	assert.NotNil(t, err)
}

func TestGenerateKey(t *testing.T) {
	aesgcm := NewAESGCM(nil)

	// Test successful key generation
	key := aesgcm.GenerateKey()
	assert.NotNil(t, key)
	assert.Equal(t, 32, len(key)) // 16 bytes encoded as hex = 32 characters
}

func TestSealWithInvalidKey(t *testing.T) {
	aesgcm := NewAESGCM(nil)

	// Test with invalid key size (AES requires 16, 24, or 32 bytes)
	invalidKey := []byte("short")
	data := []byte("test data")

	_, _, err := aesgcm.Seal(invalidKey, data, nil)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "invalid key size")
}

func TestSealWithRandomReaderError(t *testing.T) {
	// Use a mock reader that always returns an error
	aesgcm := NewAESGCM(&errorReader{})

	key := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, key)
	assert.Nil(t, err)

	data := []byte("test data")

	_, _, err = aesgcm.Seal(key, data, nil)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "random reader error")
}

func TestSealWithEOFReader(t *testing.T) {
	// Use a mock reader that returns EOF immediately
	aesgcm := NewAESGCM(&eofReader{})

	key := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, key)
	assert.Nil(t, err)

	data := []byte("test data")

	_, _, err = aesgcm.Seal(key, data, nil)
	assert.NotNil(t, err)
}

func TestOpenWithInvalidKey(t *testing.T) {
	aesgcm := NewAESGCM(nil)

	// Test with invalid key size
	invalidKey := []byte("short")
	ciphertext := []byte("test ciphertext")
	nonce := make([]byte, 12)

	_, err := aesgcm.Open(invalidKey, ciphertext, nonce, nil)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "invalid key size")
}

func TestOpenWithInvalidCiphertext(t *testing.T) {
	aesgcm := NewAESGCM(nil)

	// Generate a valid key
	key := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, key)
	assert.Nil(t, err)

	// Use invalid ciphertext (too short to contain auth tag)
	invalidCiphertext := []byte("short")
	nonce := make([]byte, 12)

	_, err = aesgcm.Open(key, invalidCiphertext, nonce, nil)
	assert.NotNil(t, err)
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
	ciphertext, nonce, err := aesgcm.Seal(key, secret, nil)
	assert.Nil(t, err)
	assert.NotNil(t, ciphertext)
	assert.NotNil(t, nonce)

	// Verify decryption works
	decrypted, err := aesgcm.Open(key, ciphertext, nonce, nil)
	assert.Nil(t, err)
	assert.Equal(t, secret, decrypted)
}
