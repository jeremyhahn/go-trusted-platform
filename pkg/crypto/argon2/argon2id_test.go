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

package argon2

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

// sharedHash hashes sharedPassword once with the default parameters. A
// default-parameter argon2id run costs tens of milliseconds, so the tests
// that only read a valid hash share this one.
const sharedPassword = "correct-password"

var sharedHash = sync.OnceValues(func() (string, error) {
	return NewArgon2(rand.Reader).Hash(sharedPassword)
})

func TestCreateArgon2(t *testing.T) {

	password := "$ecret!"

	params := Argon2Config{
		Memory:      1,
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32}

	passwordHasher := CreateArgon2(rand.Reader, params)
	hash, err := passwordHasher.Hash(password)
	assert.Nil(t, err)
	assert.NotNil(t, hash)

	match, err := passwordHasher.Compare(password, hash)
	assert.Nil(t, err)
	assert.True(t, match)

	fmt.Println(hash)
}

// TestHash_Success tests successful password hashing
func TestHash_Success(t *testing.T) {
	hash, err := sharedHash()

	assert.NoError(t, err)
	assert.NotEmpty(t, hash)
	assert.Contains(t, hash, "$argon2id$v=19$")
}

// TestHash_RNGError tests hash failure when RNG fails
func TestHash_RNGError(t *testing.T) {
	// Create a failing reader
	failingReader := &errorReader{err: errors.New("rng failure")}
	hasher := CreateArgon2(failingReader, Argon2Config{
		Memory:      1024,
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	})

	hash, err := hasher.Hash("password")

	assert.Error(t, err)
	assert.Empty(t, hash)
	assert.Contains(t, err.Error(), "rng failure")
}

// TestCompare_Success tests successful password comparison
func TestCompare_Success(t *testing.T) {
	hasher := NewArgon2(rand.Reader)

	hash, err := sharedHash()
	assert.NoError(t, err)

	match, err := hasher.Compare(sharedPassword, hash)

	assert.NoError(t, err)
	assert.True(t, match)
}

// TestCompare_WrongPassword tests comparison with incorrect password
func TestCompare_WrongPassword(t *testing.T) {
	hasher := NewArgon2(rand.Reader)

	hash, err := sharedHash()
	assert.NoError(t, err)

	match, err := hasher.Compare("wrong-password", hash)

	assert.NoError(t, err)
	assert.False(t, match)
}

// TestCompare_InvalidHashFormat tests comparison with invalid hash format
func TestCompare_InvalidHashFormat(t *testing.T) {
	hasher := NewArgon2(rand.Reader)

	match, err := hasher.Compare("password", "invalid-hash-format")

	assert.Error(t, err)
	assert.False(t, match)
	assert.Equal(t, ErrInvalidHash, err)
}

// TestCompare_IncompatibleVersion tests comparison with incompatible version
func TestCompare_IncompatibleVersion(t *testing.T) {
	hasher := NewArgon2(rand.Reader)
	invalidHash := "$argon2id$v=99$m=65536,t=3,p=2$c29tZXNhbHQ$c29tZWhhc2g"

	match, err := hasher.Compare("password", invalidHash)

	assert.Error(t, err)
	assert.False(t, match)
	assert.Equal(t, ErrIncompatibleVersion, err)
}

// TestCompare_InvalidParameters tests comparison with malformed parameters
func TestCompare_InvalidParameters(t *testing.T) {
	hasher := NewArgon2(rand.Reader)
	invalidHash := "$argon2id$v=19$m=invalid,t=3,p=2$c29tZXNhbHQ$c29tZWhhc2g"

	match, err := hasher.Compare("password", invalidHash)

	assert.Error(t, err)
	assert.False(t, match)
}

// TestCompare_InvalidSaltEncoding tests comparison with invalid base64 salt
func TestCompare_InvalidSaltEncoding(t *testing.T) {
	hasher := NewArgon2(rand.Reader)
	invalidHash := "$argon2id$v=19$m=65536,t=3,p=2$!!!invalid-base64!!!$c29tZWhhc2g"

	match, err := hasher.Compare("password", invalidHash)

	assert.Error(t, err)
	assert.False(t, match)
}

// TestCompare_InvalidHashEncoding tests comparison with invalid base64 hash
func TestCompare_InvalidHashEncoding(t *testing.T) {
	hasher := NewArgon2(rand.Reader)
	invalidHash := "$argon2id$v=19$m=65536,t=3,p=2$c29tZXNhbHQ$!!!invalid-base64!!!"

	match, err := hasher.Compare("password", invalidHash)

	assert.Error(t, err)
	assert.False(t, match)
}

// TestCreateSalt_Success tests successful salt creation
func TestCreateSalt_Success(t *testing.T) {
	hasher := Argon2Hasher{
		random: rand.Reader,
		config: Argon2Config{SaltLength: 16},
	}

	salt, err := hasher.createSalt()

	assert.NoError(t, err)
	assert.Len(t, salt, 16)
}

// TestCreateSalt_RNGError tests salt creation failure when RNG fails
func TestCreateSalt_RNGError(t *testing.T) {
	failingReader := &errorReader{err: errors.New("rng error")}
	hasher := Argon2Hasher{
		random: failingReader,
		config: Argon2Config{SaltLength: 16},
	}

	salt, err := hasher.createSalt()

	assert.Error(t, err)
	assert.Nil(t, salt)
	assert.Contains(t, err.Error(), "rng error")
}

// TestCreateSalt_ShortRead tests salt creation failure when RNG returns fewer bytes
func TestCreateSalt_ShortRead(t *testing.T) {
	shortReader := &shortReader{}
	hasher := Argon2Hasher{
		random: shortReader,
		config: Argon2Config{SaltLength: 16},
	}

	salt, err := hasher.createSalt()

	assert.Error(t, err)
	assert.Nil(t, salt)
	assert.Contains(t, err.Error(), "unexpected number of bytes from RNG")
}

// TestDecodeHash_Success tests successful hash decoding
func TestDecodeHash_Success(t *testing.T) {
	hasher := NewArgon2(rand.Reader)

	hash, err := sharedHash()
	assert.NoError(t, err)

	hasherImpl := hasher.(Argon2Hasher)
	config, salt, decodedHash, err := hasherImpl.decodeHash(hash)

	assert.NoError(t, err)
	assert.NotNil(t, salt)
	assert.NotNil(t, decodedHash)
	assert.Equal(t, uint32(64*1024), config.Memory)
	assert.Equal(t, uint32(3), config.Iterations)
	assert.Equal(t, uint8(2), config.Parallelism)
}

// TestDecodeHash_InvalidFormat tests decoding with wrong number of segments
func TestDecodeHash_InvalidFormat(t *testing.T) {
	hasher := Argon2Hasher{}
	invalidHash := "$argon2id$v=19$m=65536"

	_, _, _, err := hasher.decodeHash(invalidHash)

	assert.Error(t, err)
	assert.Equal(t, ErrInvalidHash, err)
}

// TestDecodeHash_InvalidVersionFormat tests decoding with malformed version
func TestDecodeHash_InvalidVersionFormat(t *testing.T) {
	hasher := Argon2Hasher{}
	invalidHash := "$argon2id$v=notanumber$m=65536,t=3,p=2$c29tZXNhbHQ$c29tZWhhc2g"

	_, _, _, err := hasher.decodeHash(invalidHash)

	assert.Error(t, err)
}

// errorReader is a test helper that always returns an error
type errorReader struct {
	err error
}

func (r *errorReader) Read(p []byte) (n int, err error) {
	return 0, r.err
}

// shortReader is a test helper that returns fewer bytes than requested
type shortReader struct{}

func (r *shortReader) Read(p []byte) (n int, err error) {
	if len(p) > 0 {
		return len(p) - 1, nil // Always return one fewer byte
	}
	return 0, io.EOF
}
