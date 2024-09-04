package keystore

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShareAndCombine(t *testing.T) {

	secret := []byte("secret")
	shares := 5
	required := 3

	shards, err := ShareSecret(required, secret, shares)
	assert.Nil(t, err)
	assert.Equal(t, shares, len(shards))

	valid := []string{
		shards[0],
		shards[3],
		shards[4],
	}
	combinedSecret, err := SecretFromShares(valid)
	assert.Nil(t, err)
	assert.Equal(t, string(secret), combinedSecret)

	invalid := []string{
		shards[0],
		shards[3],
	}
	nullSecret, err := SecretFromShares(invalid)
	assert.Nil(t, err)
	assert.NotEqual(t, string(secret), nullSecret)
}
