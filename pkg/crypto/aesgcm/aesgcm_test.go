package aesgcm

import (
	"crypto/rand"
	"io"
	"os"
	"testing"

	"github.com/op/go-logging"
	"github.com/stretchr/testify/assert"
)

func TestSealWithoutAdditionalData(t *testing.T) {

	logger := createLogger()

	// Use rand.Reader for entropy
	aesgcm := NewAESGCM(logger, true, nil)

	// Generate a key
	key := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, key)
	assert.Nil(t, err)

	// Seal the data and get back the cipher-text and nonce
	secret := []byte("my-secret")
	ciphertext, nonce, err := aesgcm.Seal(key, secret, nil)

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

	logger := createLogger()

	// Use rand.Reader for entropy
	aesgcm := NewAESGCM(logger, true, nil)

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

	// Open the cipher-text using the nonce returned from Seal
	decrypted, err := aesgcm.Open(key, ciphertext, nonce, additionalData)
	assert.Nil(t, err)
	assert.Equal(t, secret, decrypted)

	// Ensure failure when additional data doesnt match
	_, err = aesgcm.Open(key, ciphertext, nonce, []byte("foo"))
	assert.NotNil(t, err)
}

// Create a logger for the tests
func createLogger() *logging.Logger {
	stdout := logging.NewLogBackend(os.Stdout, "", 0)
	logging.SetBackend(stdout)
	logger := logging.MustGetLogger("tpm")

	logFormat := logging.MustStringFormatter(
		`%{color}%{time:15:04:05.000} %{shortpkg}.%{shortfunc} %{level:.4s} %{id:03x}%{color:reset} %{message}`,
	)
	logFormatter := logging.NewBackendFormatter(stdout, logFormat)
	backends := logging.MultiLogger(stdout, logFormatter)
	logging.SetBackend(backends)

	return logger
}
