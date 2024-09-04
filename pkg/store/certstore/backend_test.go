package certstore

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/blob"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	"github.com/stretchr/testify/assert"
)

func TestSaveAndGetCA(t *testing.T) {

	backend, _ := defaultStore()

	cert, err := DecodePEM(TEST_CERT_PEM)
	assert.Nil(t, err)

	id, err := ParseCertificateID(cert, nil)
	assert.Nil(t, err)

	expectedPath := fmt.Sprintf("%s/blobs/%s", TEST_DATA_DIR, id)

	err = backend.ImportCertificate(id, cert)
	assert.Nil(t, err)
	assert.True(t, util.FileExists(expectedPath))

	err = backend.DeleteCertificate(id)
	assert.Nil(t, err)
	assert.False(t, util.FileExists(expectedPath))

	_, err = backend.Get(id)
	assert.Equal(t, ErrCertNotFound, err)
}

func defaultStore() (CertificateBackend, string) {

	logger := util.Logger()

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

	blobStore, err := blob.NewFSBlobStore(logger, TEST_DATA_DIR, nil)
	if err != nil {
		logger.Fatal(err)
	}

	return NewBlobStoreBackend(blobStore), temp
}
