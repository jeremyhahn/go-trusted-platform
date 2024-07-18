package store

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/stretchr/testify/assert"
)

func TestEncodeDecodePrivKey(t *testing.T) {

	attrs := keystore.TemplateRSA
	attrs.Domain = "example.com"
	attrs.CN = "testkey"
	attrs.KeyType = keystore.KEY_TYPE_CA

	key, err := rsa.GenerateKey(rand.Reader, 512)
	assert.Nil(t, err)

	der, err := EncodePrivKey(key, nil)
	assert.Nil(t, err)

	backend := defaultStore()
	err = backend.Save(attrs, der, FSEXT_PRIVATE_PKCS8, nil)
	assert.Nil(t, err)

	persisted, err := backend.Get(attrs, FSEXT_PRIVATE_PKCS8, nil)
	assert.Nil(t, err)
	assert.Equal(t, der, persisted)
}

func TestEncodeDecodePrivKeyPEM(t *testing.T) {

	attrs := keystore.TemplateRSA
	attrs.Domain = "example.com"
	attrs.CN = "testkey"
	attrs.KeyType = keystore.KEY_TYPE_CA

	key, err := rsa.GenerateKey(rand.Reader, 512)
	assert.Nil(t, err)

	pem, err := EncodePrivKeyPEM(attrs, key)
	assert.Nil(t, err)

	backend := defaultStore()
	err = backend.Save(attrs, pem, FSEXT_PRIVATE_PKCS8_PEM, nil)
	assert.Nil(t, err)

	persisted, err := backend.Get(attrs, FSEXT_PRIVATE_PKCS8_PEM, nil)
	assert.Nil(t, err)
	assert.Equal(t, pem, persisted)
}

func TestEncodeDecodePrivKeyPEM_WithPassword(t *testing.T) {

	attrs := keystore.TemplateRSA
	attrs.Domain = "example.com"
	attrs.CN = "testkey"
	attrs.KeyType = keystore.KEY_TYPE_CA
	attrs.Password = []byte("test")

	key, err := rsa.GenerateKey(rand.Reader, 512)
	assert.Nil(t, err)

	pem, err := EncodePrivKeyPEM(attrs, key)
	assert.Nil(t, err)

	backend := defaultStore()
	err = backend.Save(attrs, pem, FSEXT_PRIVATE_PKCS8_PEM, nil)
	assert.Nil(t, err)

	persisted, err := backend.Get(attrs, FSEXT_PRIVATE_PKCS8_PEM, nil)
	assert.Nil(t, err)
	assert.Equal(t, pem, persisted)

	priv, err := DecodePrivKeyPEM(pem, attrs.Password)
	assert.Nil(t, err)
	assert.True(t, key.Equal(priv))

	_, err = DecodePrivKeyPEM(pem, []byte("incorrect-password"))
	assert.Equal(t, ErrInvalidPassword, err)
}
