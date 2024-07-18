package keystore

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseHash(t *testing.T) {
	hashes := AvailableHashes()
	hash, ok := hashes["SHA-256"]
	assert.True(t, ok)
	assert.Equal(t, crypto.SHA256, hash)
}

func TestParseBadHash(t *testing.T) {
	hashes := AvailableHashes()
	hash, ok := hashes["SHA256"]
	assert.False(t, ok)
	assert.Equal(t, crypto.Hash(0), hash)
}
