package blob

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	"github.com/op/go-logging"
)

const (
	PARTITION_BLOBS = "blobs"
)

var (
	ErrBlobNotFound = errors.New("store/blob: blob not found")
)

type BlobStorer interface {
	Delete(key []byte) error
	Get(key []byte) ([]byte, error)
	Save(key, data []byte) error
}

type BlobStore struct {
	logger        *logging.Logger
	blobDir       string
	signedBlobDir string
	partition     string
	BlobStorer
}

// Creates a new blob key using the provided root and file name
func NewKey(root, path string) []byte {
	return []byte(fmt.Sprintf("%s/%s", root, path))
}

// Creates a new local file system backed blob store
func NewFSBlobStore(
	logger *logging.Logger,
	rootDir string,
	partition *string) (BlobStorer, error) {

	var partitionName string
	if partition == nil {
		partitionName = PARTITION_BLOBS
	} else {
		partitionName = *partition
	}
	dir := fmt.Sprintf("%s/%s", rootDir, partitionName)
	if err := os.MkdirAll(dir, fs.ModePerm); err != nil {
		logger.Error(err)
		return nil, err
	}
	return &BlobStore{
		logger:    logger,
		blobDir:   dir,
		partition: partitionName,
	}, nil
}

// Saves a blob to the blob store. If the blob key contains forward slashes,
// a directory hierarchy will be created to match the key. For example, the
// blob key /my/secret/blob.dat would get saved to
// platform-dir/blobs/my/secret/blob.dat
func (store *BlobStore) Save(key, data []byte) error {
	trimmed := strings.TrimLeft(string(key), "/")
	dir := fmt.Sprintf("%s/%s", store.blobDir, filepath.Dir(trimmed))
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		store.logger.Errorf("%s: %s", err, trimmed)
		return err
	}
	blobFile := fmt.Sprintf("%s/%s", store.blobDir, trimmed)
	if err := os.WriteFile(blobFile, data, 0644); err != nil {
		store.logger.Errorf("%s: %s", err, trimmed)
		return err
	}
	return nil
}

// Retrieves a signed blob from the "signed" partition. ErrBlobNotFound is
// returned if the signed data could not be found.
func (store *BlobStore) Get(key []byte) ([]byte, error) {
	trimmed := strings.TrimLeft(string(key), "/")
	dir := fmt.Sprintf("%s/%s/", store.blobDir, filepath.Dir(trimmed))
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		store.logger.Error("%s: %s", err, key)
		return nil, err
	}
	blobFile := fmt.Sprintf("%s/%s", store.blobDir, trimmed)
	bytes, err := os.ReadFile(blobFile)
	if err != nil {
		if os.IsNotExist(err) {
			store.logger.Errorf("store/blob: error retrieving blob: %s, key: %s",
				blobFile, key)
			store.logger.Warningf("%s: %s", ErrBlobNotFound, trimmed)
			return nil, ErrBlobNotFound
		}
		return nil, err
	}
	return bytes, nil
}

// Deleted blob the blob store. ErrBlobNotFound is returned if the
// provided blob key could not be found.
func (store *BlobStore) Delete(key []byte) error {
	trimmed := strings.TrimLeft(string(key), "/")
	blobFile := fmt.Sprintf("%s/%s", store.blobDir, trimmed)
	if !util.FileExists(blobFile) {
		store.logger.Errorf("%s: %s", ErrBlobNotFound, trimmed)
		return ErrBlobNotFound
	}
	return os.RemoveAll(blobFile)
}
