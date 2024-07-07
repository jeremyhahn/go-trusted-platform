package ca

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewEncryptionKeyWithPassword(t *testing.T) {

	config, err := defaultConfig()
	assert.Nil(t, err)
	assert.NotNil(t, config)

	rootPass := []byte("root-password")
	intermediatePass := []byte("intermediate-password")
	logger, _, intermediateCA, err := createService(config, rootPass, intermediatePass, true)
	defer cleanTempDir(config.Home)

	cn := "localhost"
	keyName := "test-with-password"
	secret := []byte("app-secret")
	keyPass := []byte("key-password")

	pub, err := intermediateCA.NewEncryptionKey(cn, keyName, keyPass, intermediatePass)
	assert.Nil(t, err)
	assert.NotNil(t, pub)

	ciphertext, err := intermediateCA.RSAEncrypt(cn, keyName, secret)
	assert.Nil(t, err)
	assert.NotEqual(t, secret, ciphertext)

	decrypted, err := intermediateCA.RSADecrypt(cn, keyName, keyPass, ciphertext)
	assert.Nil(t, err)
	assert.Equal(t, secret, decrypted)

	logger.Debugf("encryption-key: cn: %s", cn)
	logger.Debugf("encryption-key: keyName: %s", keyName)
	logger.Debugf("encryption-key: secret: %s", secret)
	logger.Debugf("encryption-key: ciphertext: %s", ciphertext)
	logger.Debugf("encryption-key: decrypted: %s", decrypted)

	// Create a 2nd key
	keyName2 := "test2-with-password"
	secret2 := []byte("password2")
	pub2, err := intermediateCA.NewEncryptionKey(cn, keyName2, keyPass, intermediatePass)
	assert.Nil(t, err)
	assert.NotNil(t, pub2)

	ciphertext2, err := intermediateCA.RSAEncrypt(cn, keyName2, secret2)
	assert.Nil(t, err)
	assert.NotEqual(t, secret, ciphertext)

	decrypted2, err := intermediateCA.RSADecrypt(cn, keyName2, keyPass, ciphertext2)
	assert.Nil(t, err)
	assert.Equal(t, secret2, decrypted2)

	// Ensure encryption fails
	_, err = intermediateCA.RSADecrypt(cn, keyName, keyPass, ciphertext2)
	assert.NotNil(t, err)
	assert.Equal(t, "crypto/rsa: decryption error", err.Error())
}

func TestNewEncryptionKeyWihtInvalidPasswordCombinations(t *testing.T) {

	config, err := defaultConfig()
	assert.Nil(t, err)
	assert.NotNil(t, config)

	rootPass := []byte("root-password")
	intermediatePass := []byte("intermediate-password")
	_, _, intermediateCA, err := createService(config, nil, nil, true)
	defer cleanTempDir(config.Home)
	assert.Equal(t, ErrPrivateKeyPasswordRequired, err)

	cn := "localhost"
	keyName := "test-without-password"
	secret := []byte("app-secret")
	keyPass := []byte("key-password")

	// Create the Root and Intermediate CA
	config, err = defaultConfig()
	assert.Nil(t, err)
	assert.NotNil(t, config)

	logger, _, intermediateCA, err := createService(config, rootPass, intermediatePass, true)
	defer cleanTempDir(config.Home)

	// Create new encryption key
	pub, err := intermediateCA.NewEncryptionKey(cn, keyName, keyPass, intermediatePass)
	assert.Nil(t, err)
	assert.NotNil(t, pub)

	// Encrypt the secret
	ciphertext, err := intermediateCA.RSAEncrypt(cn, keyName, secret)
	assert.Nil(t, err)
	assert.NotEqual(t, secret, ciphertext)

	// Decrypt without a password (should fail with invalid password)
	decrypted, err := intermediateCA.RSADecrypt(cn, keyName, nil, ciphertext)
	assert.Equal(t, ErrInvalidPassword, err)

	// Decrypt with a bad password (should fail with invalid password)
	decrypted, err = intermediateCA.RSADecrypt(cn, keyName, secret, ciphertext)
	assert.Equal(t, ErrInvalidPassword, err)

	// Decrypt with correct password (should work)
	decrypted, err = intermediateCA.RSADecrypt(cn, keyName, keyPass, ciphertext)
	assert.Nil(t, err)
	assert.Equal(t, secret, decrypted)

	logger.Debugf("encryption-key: cn: %s", cn)
	logger.Debugf("encryption-key: keyName: %s", keyName)
	logger.Debugf("encryption-key: secret: %s", secret)
	logger.Debugf("encryption-key: ciphertext: %s", ciphertext)
	logger.Debugf("encryption-key: decrypted: %s", decrypted)

	// Create a 2nd key without a password
	keyName2 := "test2-without-password"
	pub2, err := intermediateCA.NewEncryptionKey(cn, keyName2, nil, intermediatePass)
	assert.Equal(t, ErrPrivateKeyPasswordRequired, err)
	assert.Nil(t, pub2)

	pub3, err := intermediateCA.NewEncryptionKey(cn, keyName2, nil, intermediatePass)
	assert.Equal(t, ErrPrivateKeyPasswordRequired, err)
	assert.Nil(t, pub3)

	// Create a 3rd with a bad password
	keyName3 := "test2-without-password"
	secret3 := []byte("password2")

	// Try to decrypt using a key that doesnt exist
	_, err = intermediateCA.RSAEncrypt(cn, keyName3, secret3)
	assert.Equal(t, ErrFileNotFound, err)

	// Create the missing key
	pub4, err := intermediateCA.NewEncryptionKey(cn, keyName3, keyPass, intermediatePass)
	assert.Nil(t, err)
	assert.NotNil(t, pub4)

	ciphertext3, err := intermediateCA.RSAEncrypt(cn, keyName3, secret3)
	assert.Nil(t, err)
	assert.NotEqual(t, secret3, ciphertext3)

	// It works
	decrypted3, err := intermediateCA.RSADecrypt(cn, keyName3, keyPass, ciphertext3)
	assert.Nil(t, err)
	assert.Equal(t, secret3, decrypted3)
}
