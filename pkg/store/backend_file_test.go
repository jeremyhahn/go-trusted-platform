package store

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	"github.com/op/go-logging"
	"github.com/stretchr/testify/assert"
)

func expectedKeyPathCA(attrs keystore.KeyAttributes) string {
	return fmt.Sprintf(
		"%s/%s.%s%s",
		TEST_TMP_DIR,
		attrs.Domain,
		strings.ToLower(attrs.KeyAlgorithm.String()),
		FSEXT_PRIVATE_PKCS8)
}

func expectedKeyPathTLS(attrs keystore.KeyAttributes) string {
	return fmt.Sprintf(
		"%s/%s/%s/%s.%s%s",
		TEST_TMP_DIR,
		PARTITION_TLS,
		attrs.CN,
		attrs.CN,
		strings.ToLower(attrs.KeyAlgorithm.String()),
		FSEXT_PRIVATE_PKCS8)
}

func expectedKeyPathSigning(attrs keystore.KeyAttributes) string {
	return fmt.Sprintf(
		"%s/%s/%s/%s.%s%s",
		TEST_TMP_DIR,
		PARTITION_SIGNING_KEYS,
		attrs.CN,
		attrs.CN,
		strings.ToLower(attrs.KeyAlgorithm.String()),
		FSEXT_PRIVATE_PKCS8)
}

func expectedKeyPathEncryption(attrs keystore.KeyAttributes) string {
	return fmt.Sprintf(
		"%s/%s/%s/%s.%s%s",
		TEST_TMP_DIR,
		PARTITION_ENCRYPTION_KEYS,
		attrs.CN,
		attrs.CN,
		strings.ToLower(attrs.KeyAlgorithm.String()),
		FSEXT_PRIVATE_PKCS8)
}

func expectedPathCACRL(attrs keystore.KeyAttributes) string {
	return fmt.Sprintf(
		"%s/%s%s",
		TEST_TMP_DIR,
		attrs.Domain,
		FSEXT_CRL)
}

func expectedPathCRL(attrs keystore.KeyAttributes) string {
	return fmt.Sprintf(
		"%s/%s/%s%s",
		TEST_TMP_DIR,
		PARTITION_CRL,
		attrs.Domain,
		FSEXT_CRL)
}

func expectedPathRevoked(attrs keystore.KeyAttributes) string {
	return fmt.Sprintf(
		"%s/%s/%s.rsa%s",
		TEST_TMP_DIR,
		PARTITION_REVOKED,
		attrs.Domain,
		FSEXT_PEM)
}

func expectedPathTrustedRoot(attrs keystore.KeyAttributes) string {
	return fmt.Sprintf(
		"%s/%s/%s.rsa%s",
		TEST_TMP_DIR,
		PARTITION_TRUSTED_ROOT,
		attrs.Domain,
		FSEXT_PEM)
}

func expectedPathTrustedIntermediate(attrs keystore.KeyAttributes) string {
	return fmt.Sprintf(
		"%s/%s/%s.rsa%s",
		TEST_TMP_DIR,
		PARTITION_TRUSTED_INTERMEDIATE,
		attrs.Domain,
		FSEXT_PEM)
}

func expectedPathBlob(attrs keystore.KeyAttributes) string {
	return fmt.Sprintf(
		"%s/%s/%s%s",
		TEST_TMP_DIR,
		PARTITION_SIGNED_BLOB,
		attrs.CN,
		FSEXT_PEM)
}

func TestSaveAndGetCA(t *testing.T) {

	fakeKey := []byte("test")

	attrs := keystore.TemplateRSA
	attrs.Domain = "example.com"
	attrs.CN = "testkey"
	attrs.KeyType = keystore.KEY_TYPE_CA

	backend := defaultStore()
	err := backend.Save(attrs, fakeKey, FSEXT_PRIVATE_PKCS8, nil)
	assert.Nil(t, err)

	persisted, err := backend.Get(attrs, FSEXT_PRIVATE_PKCS8, nil)
	assert.Nil(t, err)
	assert.Equal(t, fakeKey, persisted)

	expectedPath := expectedKeyPathCA(attrs)

	path, err := util.FileExists(expectedPath)
	assert.Nil(t, err)
	assert.True(t, path)
}

func TestSaveAndGetTLS(t *testing.T) {

	fakeKey := []byte("test")

	attrs := keystore.TemplateRSA
	attrs.Domain = "example.com"
	attrs.CN = "testkey"
	attrs.KeyType = keystore.KEY_TYPE_TLS

	backend := defaultStore()
	err := backend.Save(attrs, fakeKey, FSEXT_PRIVATE_PKCS8, nil)
	assert.Nil(t, err)

	persisted, err := backend.Get(attrs, FSEXT_PRIVATE_PKCS8, nil)
	assert.Nil(t, err)
	assert.Equal(t, fakeKey, persisted)

	expectedPath := expectedKeyPathTLS(attrs)

	path, err := util.FileExists(expectedPath)
	assert.Nil(t, err)
	assert.True(t, path)
}

func TestSaveAndGetSigningKey(t *testing.T) {

	fakeKey := []byte("test")

	attrs := keystore.TemplateRSA
	attrs.Domain = "example.com"
	attrs.CN = "testkey"
	attrs.KeyType = keystore.KEY_TYPE_SIGNING

	backend := defaultStore()
	err := backend.Save(attrs, fakeKey, FSEXT_PRIVATE_PKCS8, nil)
	assert.Nil(t, err)

	persisted, err := backend.Get(attrs, FSEXT_PRIVATE_PKCS8, nil)
	assert.Nil(t, err)
	assert.Equal(t, fakeKey, persisted)

	expectedPath := expectedKeyPathSigning(attrs)

	path, err := util.FileExists(expectedPath)
	assert.Nil(t, err)
	assert.True(t, path)
}

func TestSaveAndGetEncryptionKey(t *testing.T) {

	fakeKey := []byte("test")

	attrs := keystore.TemplateRSA
	attrs.Domain = "example.com"
	attrs.CN = "testkey"
	attrs.KeyType = keystore.KEY_TYPE_ENCRYPTION

	backend := defaultStore()
	err := backend.Save(attrs, fakeKey, FSEXT_PRIVATE_PKCS8, nil)
	assert.Nil(t, err)

	persisted, err := backend.Get(attrs, FSEXT_PRIVATE_PKCS8, nil)
	assert.Nil(t, err)
	assert.Equal(t, fakeKey, persisted)

	expectedPath := expectedKeyPathEncryption(attrs)

	path, err := util.FileExists(expectedPath)
	assert.Nil(t, err)
	assert.True(t, path)
}

func TestSaveAndGetCACRL(t *testing.T) {

	data := []byte("test")

	attrs := keystore.TemplateRSA
	attrs.Domain = "example.com"
	attrs.CN = "testkey"
	attrs.KeyType = keystore.KEY_TYPE_CA

	backend := defaultStore()
	err := backend.Save(attrs, data, FSEXT_CRL, nil)
	assert.Nil(t, err)

	persisted, err := backend.Get(attrs, FSEXT_CRL, nil)
	assert.Nil(t, err)
	assert.Equal(t, data, persisted)

	expectedPath := expectedPathCACRL(attrs)

	path, err := util.FileExists(expectedPath)
	assert.Nil(t, err)
	assert.True(t, path)
}

func TestSaveAndGetImportedCRL(t *testing.T) {

	data := []byte("test")

	attrs := keystore.TemplateRSA
	attrs.Domain = "example.com"
	attrs.CN = "testkey"
	attrs.KeyType = keystore.KEY_TYPE_CA

	backend := defaultStore()
	partition := PARTITION_CRL

	err := backend.Save(attrs, data, FSEXT_CRL, &partition)
	assert.Nil(t, err)

	persisted, err := backend.Get(attrs, FSEXT_CRL, &partition)
	assert.Nil(t, err)
	assert.Equal(t, data, persisted)

	expectedPath := expectedPathCRL(attrs)

	path, err := util.FileExists(expectedPath)
	assert.Nil(t, err)
	assert.True(t, path)
}

func TestSaveAndGetRevoked(t *testing.T) {

	data := []byte("test")

	attrs := keystore.TemplateRSA
	attrs.Domain = "example.com"
	attrs.CN = "testkey"
	attrs.KeyType = keystore.KEY_TYPE_CA

	backend := defaultStore()
	partition := PARTITION_REVOKED

	err := backend.Save(attrs, data, FSEXT_PEM, &partition)
	assert.Nil(t, err)

	persisted, err := backend.Get(attrs, FSEXT_PEM, &partition)
	assert.Nil(t, err)
	assert.Equal(t, data, persisted)

	expectedPath := expectedPathRevoked(attrs)

	path, err := util.FileExists(expectedPath)
	assert.Nil(t, err)
	assert.True(t, path)
}

func TestSaveAndGetTrustedRoot(t *testing.T) {

	data := []byte("test")

	attrs := keystore.TemplateRSA
	attrs.Domain = "example.com"
	attrs.CN = "testkey"
	attrs.KeyType = keystore.KEY_TYPE_CA

	backend := defaultStore()
	partition := PARTITION_TRUSTED_ROOT

	err := backend.Save(attrs, data, FSEXT_PEM, &partition)
	assert.Nil(t, err)

	persisted, err := backend.Get(attrs, FSEXT_PEM, &partition)
	assert.Nil(t, err)
	assert.Equal(t, data, persisted)

	expectedPath := expectedPathTrustedRoot(attrs)

	path, err := util.FileExists(expectedPath)
	assert.Nil(t, err)
	assert.True(t, path)
}

func TestSaveAndGetTrustedIntermediate(t *testing.T) {

	data := []byte("test")

	attrs := keystore.TemplateRSA
	attrs.Domain = "example.com"
	attrs.CN = "testkey"
	attrs.KeyType = keystore.KEY_TYPE_CA

	backend := defaultStore()
	partition := PARTITION_TRUSTED_INTERMEDIATE

	err := backend.Save(attrs, data, FSEXT_PEM, &partition)
	assert.Nil(t, err)

	persisted, err := backend.Get(attrs, FSEXT_PEM, &partition)
	assert.Nil(t, err)
	assert.Equal(t, data, persisted)

	expectedPath := expectedPathTrustedIntermediate(attrs)

	path, err := util.FileExists(expectedPath)
	assert.Nil(t, err)
	assert.True(t, path)
}

func TestAppend(t *testing.T) {

	data := []byte("test")

	attrs := keystore.TemplateRSA
	attrs.Domain = "example.com"
	attrs.CN = "testkey"
	attrs.KeyType = keystore.KEY_TYPE_CA

	backend := defaultStore()
	partition := PARTITION_TRUSTED_INTERMEDIATE

	err := backend.Save(attrs, data, FSEXT_PEM, &partition)
	assert.Nil(t, err)

	persisted, err := backend.Get(attrs, FSEXT_PEM, &partition)
	assert.Nil(t, err)
	assert.Equal(t, data, persisted)

	expectedPath := expectedPathTrustedIntermediate(attrs)

	path, err := util.FileExists(expectedPath)
	assert.Nil(t, err)
	assert.True(t, path)

	// Perform append operation
	newData := []byte("test2")
	err = backend.Append(attrs, newData, FSEXT_PEM, &partition)
	assert.Nil(t, err)

	// Ensure the data was appended
	latest, err := backend.Get(attrs, FSEXT_PEM, &partition)
	assert.Nil(t, err)
	assert.Equal(t, []byte("testtest2"), latest)
}

// func TestSaveAndGetBlob(t *testing.T) {

// 	data := []byte("test")

// 	attrs := TemplateRSA
// 	attrs.CN = "example.com"
// 	attrs.KeyName = "testkey"
// 	attrs.KeyType = KEY_TYPE_CA

// 	backend := defaultStore()
// 	partition := PARTITION_SIGNED_BLOB

// 	err := backend.Save(attrs, data, FSEXT_BLOB, &partition)
// 	assert.Nil(t, err)

// 	persisted, err := backend.Get(attrs, FSEXT_BLOB, &partition)
// 	assert.Nil(t, err)
// 	assert.Equal(t, data, persisted)

// 	expectedPath := expectedPathBlob(attrs)

// 	path, err := util.FileExists(expectedPath)
// 	assert.Nil(t, err)
// 	assert.True(t, path)
// }

func defaultStore() Backend {

	stdout := logging.NewLogBackend(os.Stdout, "", 0)
	logging.SetBackend(stdout)
	logger := logging.MustGetLogger("keystore-x509")
	logFormat := logging.MustStringFormatter(
		`%{color}%{time:15:04:05.000} %{shortpkg}.%{shortfunc} %{level:.4s} %{id:03x}%{color:reset} %{message}`,
	)
	logFormatter := logging.NewBackendFormatter(stdout, logFormat)
	backends := logging.MultiLogger(stdout, logFormatter)
	logging.SetBackend(backends)

	// Create a temp directory for each instantiation
	// so parallel tests don't corrupt each other.
	buf := make([]byte, 8)
	_, err := rand.Reader.Read(buf)
	if err != nil {
		panic(err)
	}
	tmpDir := hex.EncodeToString(buf)

	caCN := "example.com"
	TEST_TMP_DIR = fmt.Sprintf("%s/%s/%s", TEST_DATA_DIR, tmpDir, caCN)

	return NewFileBackend(logger, TEST_TMP_DIR)
}
