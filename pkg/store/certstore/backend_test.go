package certstore

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/blob"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
)

func FileExists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	return false
}

func TestSaveAndGetCA(t *testing.T) {

	backend, _ := defaultStore()

	cert, err := DecodePEM(TEST_CERT_PEM)
	assert.Nil(t, err)

	id, err := ParseCertificateID(cert, nil)
	assert.Nil(t, err)

	expectedPath := fmt.Sprintf("%s/blobs/%s", TEST_DATA_DIR, id)

	err = backend.ImportCertificate(id, cert)
	assert.Nil(t, err)
	assert.True(t, FileExists(expectedPath))

	err = backend.DeleteCertificate(id)
	assert.Nil(t, err)
	assert.False(t, FileExists(expectedPath))

	_, err = backend.Get(id)
	assert.Equal(t, ErrCertNotFound, err)
}

func defaultStore() (CertificateBackend, string) {

	logger := logging.DefaultLogger()

	// Create a temp directory for each instantiation
	// so parallel tests don't corrupt each other.
	buf := make([]byte, 8)
	_, err := rand.Reader.Read(buf)
	if err != nil {
		panic(err)
	}
	tmpDir := hex.EncodeToString(buf)

	caCN := "example.com"
	temp := fmt.Sprintf("%s/%s/%s", TEST_DATA_DIR, tmpDir, caCN)

	fs := afero.NewMemMapFs()
	blobStore, err := blob.NewFSBlobStore(logger, fs, TEST_DATA_DIR, nil)
	if err != nil {
		logger.FatalError(err)
	}

	return NewBlobStoreBackend(blobStore), temp
}
