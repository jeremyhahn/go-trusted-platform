package keystore

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/spf13/afero"
)

// func expectedKeyPathCA(attrs *KeyAttributes) string {
// 	return fmt.Sprintf(
// 		"%s/%s.%s%s",
// 		TEST_TMP_DIR,
// 		attrs.CN,
// 		strings.ToLower(attrs.KeyAlgorithm.String()),
// 		FSEXT_PRIVATE_PKCS8)
// }

// func expectedKeyPathTLS(attrs *KeyAttributes) string {
// 	return fmt.Sprintf(
// 		"%s/%s/%s/%s.%s%s",
// 		TEST_TMP_DIR,
// 		PARTITION_TLS,
// 		attrs.CN,
// 		attrs.CN,
// 		strings.ToLower(attrs.KeyAlgorithm.String()),
// 		FSEXT_PRIVATE_PKCS8)
// }

// func expectedKeyPathSigning(attrs *KeyAttributes) string {
// 	return fmt.Sprintf(
// 		"%s/%s/%s/%s.%s%s",
// 		TEST_TMP_DIR,
// 		PARTITION_SIGNING_KEYS,
// 		attrs.CN,
// 		attrs.CN,
// 		strings.ToLower(attrs.KeyAlgorithm.String()),
// 		FSEXT_PRIVATE_PKCS8)
// }

// func expectedKeyPathEncryption(attrs *KeyAttributes) string {
// 	return fmt.Sprintf(
// 		"%s/%s/%s/%s.%s%s",
// 		TEST_TMP_DIR,
// 		PARTITION_ENCRYPTION_KEYS,
// 		attrs.CN,
// 		attrs.CN,
// 		strings.ToLower(attrs.KeyAlgorithm.String()),
// 		FSEXT_PRIVATE_PKCS8)
// }

// func TestSaveAndGetCA(t *testing.T) {

// 	fakeKey := []byte("test")

// 	attrs := TemplateRSA
// 	attrs.CN = "testkey"
// 	attrs.KeyType = KEY_TYPE_CA

// 	backend := defaultStore()
// 	err := backend.Save(attrs, fakeKey, FSEXT_PRIVATE_PKCS8)
// 	assert.Nil(t, err)

// 	persisted, err := backend.Get(attrs, FSEXT_PRIVATE_PKCS8)
// 	assert.Nil(t, err)
// 	assert.Equal(t, fakeKey, persisted)

// 	expectedPath := expectedKeyPathCA(attrs)

// 	path := util.FileExists(expectedPath)
// 	assert.True(t, path)
// }

// func TestSaveAndGetTLS(t *testing.T) {

// 	fakeKey := []byte("test")

// 	attrs := TemplateRSA
// 	attrs.CN = "testkey"
// 	attrs.KeyType = KEY_TYPE_TLS

// 	backend := defaultStore()
// 	err := backend.Save(attrs, fakeKey, FSEXT_PRIVATE_PKCS8)
// 	assert.Nil(t, err)

// 	persisted, err := backend.Get(attrs, FSEXT_PRIVATE_PKCS8)
// 	assert.Nil(t, err)
// 	assert.Equal(t, fakeKey, persisted)

// 	expectedPath := expectedKeyPathTLS(attrs)

// 	path := util.FileExists(expectedPath)
// 	assert.True(t, path)
// }

// func TestSaveAndGetSigningKey(t *testing.T) {

// 	fakeKey := []byte("test")

// 	attrs := TemplateRSA
// 	attrs.CN = "testkey"
// 	attrs.KeyType = KEY_TYPE_SIGNING

// 	backend := defaultStore()
// 	err := backend.Save(attrs, fakeKey, FSEXT_PRIVATE_PKCS8)
// 	assert.Nil(t, err)

// 	persisted, err := backend.Get(attrs, FSEXT_PRIVATE_PKCS8)
// 	assert.Nil(t, err)
// 	assert.Equal(t, fakeKey, persisted)

// 	expectedPath := expectedKeyPathSigning(attrs)

// 	path := util.FileExists(expectedPath)
// 	assert.True(t, path)
// }

// func TestSaveAndGetEncryptionKey(t *testing.T) {

// 	fakeKey := []byte("test")

// 	attrs := TemplateRSA
// 	attrs.CN = "testkey"
// 	attrs.KeyType = KEY_TYPE_ENCRYPTION

// 	backend := defaultStore()
// 	err := backend.Save(attrs, fakeKey, FSEXT_PRIVATE_PKCS8)
// 	assert.Nil(t, err)

// 	persisted, err := backend.Get(attrs, FSEXT_PRIVATE_PKCS8)
// 	assert.Nil(t, err)
// 	assert.Equal(t, fakeKey, persisted)

// 	expectedPath := expectedKeyPathEncryption(attrs)

// 	path := util.FileExists(expectedPath)
// 	assert.True(t, path)
// }

func defaultStore() KeyBackend {

	logger := defaultLogger()

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

	return NewFileBackend(logger, afero.NewMemMapFs(), TEST_TMP_DIR)
}
