//go:build quantum_safe

package dilithium2

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	d, err := New()
	defer d.Clean()
	assert.NoError(t, err)
	assert.NotNil(t, d.signer)
}

func TestClean(t *testing.T) {
	d, err := New()
	defer d.Clean()
	assert.NoError(t, err)
	d.Clean()
	assert.Nil(t, d.signer)
}

func TestGenerateKeyPair(t *testing.T) {
	d, err := New()
	defer d.Clean()
	assert.NoError(t, err)
	pubKey, err := d.GenerateKeyPair()
	assert.NoError(t, err)
	assert.NotNil(t, pubKey)
}

func TestSignAndVerify(t *testing.T) {
	d, err := New()
	defer d.Clean()
	assert.NoError(t, err)
	pubKey, err := d.GenerateKeyPair()
	assert.NoError(t, err)

	data := []byte("test data")
	signature, err := d.Sign(data)
	assert.NoError(t, err)
	assert.NotNil(t, signature)

	err = d.Verify(data, signature, pubKey)
	assert.NoError(t, err)
}

func TestVerifyInvalidSignature(t *testing.T) {
	d, err := New()
	defer d.Clean()
	assert.NoError(t, err)
	pubKey, err := d.GenerateKeyPair()
	assert.NoError(t, err)

	data := []byte("test data")
	invalidSignature := []byte("invalid signature")

	err = d.Verify(data, invalidSignature, pubKey)
	assert.Error(t, err)
	assert.Equal(t, "signature verification failed", err.Error())
}
