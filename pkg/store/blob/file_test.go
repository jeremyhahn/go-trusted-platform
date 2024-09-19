package blob

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
)

func TestBlobStore(t *testing.T) {

	data := []byte("test")

	store := createStore()

	blobKey := []byte("/test/path.txt")

	// Save the blob
	err := store.Save(blobKey, data)
	assert.Nil(t, err)

	// Get the persisted blob
	persisted, err := store.Get(blobKey)
	assert.Nil(t, err)
	assert.Equal(t, data, persisted)

	// Ensure it exists
	path := store.Exists(blobKey)
	assert.True(t, path)

	// Delete the org
	err = store.Delete(blobKey)
	assert.Nil(t, err)

	// Ensure it's deleted
	_, err = store.Get(blobKey)
	assert.NotNil(t, err)
	assert.True(t, errors.Is(err, ErrBlobNotFound))
}

func TestCount(t *testing.T) {

	data := []byte("test")

	store := createStore()

	partition := "/test"

	count := 1000
	for i := 0; i < count; i++ {
		filename := fmt.Sprintf("%s/file-%d.txt", partition, i)
		err := store.Save([]byte(filename), data)
		assert.Nil(t, err)
	}

	_count, err := store.Count(&partition)
	assert.Nil(t, err)
	assert.True(t, _count == count)
}

func createStore() BlobStorer {

	logger := logging.DefaultLogger()

	caCN := "example.com"

	fs := afero.NewMemMapFs()
	store, err := NewFSBlobStore(logger, fs, caCN, nil)
	if err != nil {
		logger.FatalError(err)
	}

	return store
}
