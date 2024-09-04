package argon2

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestArgon2(t *testing.T) {

	password := "$ecret!"
	passwordHasher := NewArgon2(rand.Reader)
	hash, err := passwordHasher.Hash(password)
	assert.Nil(t, err)
	assert.NotNil(t, hash)

	match, err := passwordHasher.Compare(password, hash)
	assert.Nil(t, err)
	assert.True(t, match)

	fmt.Println(hash)
}

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
