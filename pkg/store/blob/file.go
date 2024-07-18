package blobstore

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/op/go-logging"
)

const (
	PARTITION_SIGNED_BLOB = "blobs"
)

var (
	ErrBlobNotFound = errors.New("store/blob: signed blob not found")
)

type BlobStorer interface {
	Blob(key string) ([]byte, error)
	Save(key string, data []byte) error
}

type BlobStore struct {
	logger        *logging.Logger
	blobDir       string
	signedBlobDir string
	BlobStorer
}

// Creates a new local file system backed blob store
func NewFSBlobStore(logger *logging.Logger, blobDir string) (BlobStorer, error) {
	dir := fmt.Sprintf("%s/%s", blobDir, PARTITION_SIGNED_BLOB)
	if err := os.MkdirAll(dir, fs.ModePerm); err != nil {
		logger.Error(err)
		return nil, err
	}
	return BlobStore{
		logger:        logger,
		blobDir:       blobDir,
		signedBlobDir: fmt.Sprintf("%s/%s", blobDir, PARTITION_SIGNED_BLOB),
	}, nil
}

// Saves a blob to the blob storage partition. If the blob key contains
// forward slashes, a directory hierarchy will be created to match the
// key. For example, the blob key /my/secret/blob.dat would get saved to
// ca-name/blobs/my/secret/blob.dat
func (store BlobStore) Save(key string, data []byte) error {
	trimmed := strings.TrimLeft(key, "/")
	dir := fmt.Sprintf("%s/%s", store.signedBlobDir, filepath.Dir(trimmed))
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		store.logger.Error(err)
		return err
	}
	blobFile := fmt.Sprintf("%s/%s", store.signedBlobDir, trimmed)
	if err := os.WriteFile(blobFile, data, 0644); err != nil {
		store.logger.Error(err)
		return err
	}
	return nil
}

// Retrieves a signed blob from the "signed" partition. ErrBlobNotFound is
// returned if the signed data could not be found.
func (store BlobStore) Blob(key string) ([]byte, error) {
	trimmed := strings.TrimLeft(key, "/")
	dir := fmt.Sprintf("%s/%s/", store.signedBlobDir, filepath.Dir(trimmed))
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		store.logger.Error(err)
		return nil, err
	}
	blobFile := fmt.Sprintf("%s/%s", store.signedBlobDir, trimmed)
	bytes, err := os.ReadFile(blobFile)
	if err != nil {
		if os.IsNotExist(err) {
			store.logger.Errorf("store/blob: error retrieving blob: %s, key: %s",
				blobFile, key)
			return nil, ErrBlobNotFound
		}
		return nil, err
	}
	return bytes, nil
}
