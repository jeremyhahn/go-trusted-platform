package blob

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/spf13/afero"
)

const (
	PARTITION_BLOBS = "blobs"
)

var (
	ErrBlobNotFound = errors.New("store/blob: blob not found")
)

type BlobStorer interface {
	Delete(key []byte) error
	Exists(key []byte) bool
	Get(key []byte) ([]byte, error)
	Save(key, data []byte) error
	Count(partition *string) (int, error)
}

type BlobStore struct {
	logger    *logging.Logger
	fs        afero.Fs
	blobDir   string
	partition string
	BlobStorer
}

// Creates a new local file system backed blob store
func NewFSBlobStore(
	logger *logging.Logger,
	fs afero.Fs,
	rootDir string,
	partition *string) (BlobStorer, error) {

	var partitionName string
	if partition == nil {
		partitionName = PARTITION_BLOBS
	} else {
		partitionName = *partition
	}
	if rootDir[len(rootDir)-1] == '/' {
		rootDir = strings.TrimRight(rootDir, "/")
	}
	dir := fmt.Sprintf("%s/%s", rootDir, partitionName)
	if err := fs.MkdirAll(dir, os.ModePerm); err != nil {
		logger.Error(err)
		return nil, err
	}
	return &BlobStore{
		logger:    logger,
		blobDir:   dir,
		fs:        fs,
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
	if err := store.fs.MkdirAll(dir, os.ModePerm); err != nil {
		store.logger.Error(err, slog.String("key", trimmed))
		return err
	}
	blobFile := fmt.Sprintf("%s/%s", store.blobDir, trimmed)
	if err := afero.WriteFile(store.fs, blobFile, data, 0644); err != nil {
		store.logger.Error(err, slog.String("key", trimmed))
		return err
	}
	return nil
}

// Retrieves a signed blob from the "signed" partition. ErrBlobNotFound is
// returned if the signed data could not be found.
func (store *BlobStore) Get(key []byte) ([]byte, error) {
	trimmed := strings.TrimLeft(string(key), "/")
	dir := fmt.Sprintf("%s/%s/", store.blobDir, filepath.Dir(trimmed))
	if err := store.fs.MkdirAll(dir, os.ModePerm); err != nil {
		store.logger.Error(err, slog.String("key", trimmed))
		return nil, err
	}
	blobFile := fmt.Sprintf("%s/%s", store.blobDir, trimmed)
	bytes, err := afero.ReadFile(store.fs, blobFile)
	if err != nil {
		if os.IsNotExist(err) {
			store.logger.MaybeError(ErrBlobNotFound, slog.String("key", trimmed))
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
	if _, err := store.fs.Stat(blobFile); err != nil {
		store.logger.Error(err, slog.String("key", trimmed))
		return ErrBlobNotFound
	}
	return store.fs.RemoveAll(blobFile)
}

// Returns true if the file exists
func (store *BlobStore) Exists(key []byte) bool {
	trimmed := strings.TrimLeft(string(key), "/")
	blobFile := fmt.Sprintf("%s/%s", store.blobDir, trimmed)
	if _, err := store.fs.Stat(blobFile); err != nil {
		return false
	}
	return true
}

// Deleted blob the blob store. ErrBlobNotFound is returned if the
// provided blob key could not be found.
func (store *BlobStore) Count(partition *string) (int, error) {
	count := 0
	limit := 50
	dir := store.blobDir
	if partition != nil {
		trimmed := strings.TrimLeft(*partition, "/")
		dir = fmt.Sprintf("%s/%s", store.blobDir, trimmed)
	}
	f, err := store.fs.Open(dir)
	if err != nil {
		return 0, err
	}
	var list []string
	for err != io.EOF {
		list, err = f.Readdirnames(limit)
		count = count + len(list)
	}
	f.Close()
	if err != nil && err != io.EOF {
		return 0, err
	}
	return count, nil
}
