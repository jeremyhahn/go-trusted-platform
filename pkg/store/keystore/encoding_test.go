package keystore

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncodeDecodePrivKey(t *testing.T) {

	attrs := TemplateRSA
	attrs.CN = "testkey"
	attrs.KeyType = KEY_TYPE_CA

	key, err := rsa.GenerateKey(rand.Reader, 512)
	assert.Nil(t, err)

	der, err := EncodePrivKey(key, nil)
	assert.Nil(t, err)

	backend := defaultStore()
	err = backend.Save(attrs, der, FSEXT_PRIVATE_PKCS8, false)
	assert.Nil(t, err)

	persisted, err := backend.Get(attrs, FSEXT_PRIVATE_PKCS8)
	assert.Nil(t, err)
	assert.Equal(t, der, persisted)
}

func TestEncodeDecodePrivKeyPEM(t *testing.T) {

	attrs := TemplateRSA
	attrs.CN = "testkey"
	attrs.KeyType = KEY_TYPE_CA

	key, err := rsa.GenerateKey(rand.Reader, 512)
	assert.Nil(t, err)

	pem, err := EncodePrivKeyPEM(attrs, key)
	assert.Nil(t, err)

	backend := defaultStore()
	err = backend.Save(attrs, pem, FSEXT_PRIVATE_PKCS8_PEM, false)
	assert.Nil(t, err)

	persisted, err := backend.Get(attrs, FSEXT_PRIVATE_PKCS8_PEM)
	assert.Nil(t, err)
	assert.Equal(t, pem, persisted)
}

func TestEncodeDecodePrivKeyPEM_WithPassword(t *testing.T) {

	attrs := TemplateRSA
	attrs.CN = "testkey"
	attrs.KeyType = KEY_TYPE_CA
	attrs.Password = NewClearPassword([]byte("test"))

	key, err := rsa.GenerateKey(rand.Reader, 512)
	assert.Nil(t, err)

	pem, err := EncodePrivKeyPEM(attrs, key)
	assert.Nil(t, err)

	backend := defaultStore()
	err = backend.Save(attrs, pem, FSEXT_PRIVATE_PKCS8_PEM, false)
	assert.Nil(t, err)

	persisted, err := backend.Get(attrs, FSEXT_PRIVATE_PKCS8_PEM)
	assert.Nil(t, err)
	assert.Equal(t, pem, persisted)

	priv, err := DecodePrivKeyPEM(pem, attrs.Password)
	assert.Nil(t, err)
	assert.True(t, key.Equal(priv))

	_, err = DecodePrivKeyPEM(pem, NewClearPassword([]byte("incorrect-password")))
	assert.Equal(t, ErrInvalidPassword, err)
}
