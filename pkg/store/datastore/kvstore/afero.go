package kvstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/spf13/afero"
)

var (
	ErrInvalidReadBufferSize = errors.New("kvstore/afero: invalid read buffer size")
)

type AferoDAO[E any] struct {
	readBufferSize int
	logger         *logging.Logger
	fs             afero.Fs
	partitionDir   string
	datastore.GenericDAO[E]
}

// Creates a key/value blob storage backend
func NewAferoDAO[E any](logger *logging.Logger,
	fs afero.Fs,
	rootDir string,
	partition string,
	serializer datastore.Serializer,
	readBufferSize int) (datastore.GenericDAO[E], error) {

	if rootDir[len(rootDir)-1] == '/' {
		rootDir = strings.TrimRight(rootDir, "/")
	}
	partitionDir := fmt.Sprintf("%s/%s", rootDir, partition)
	if err := fs.MkdirAll(partitionDir, os.ModePerm); err != nil {
		logger.Error(err)
		return nil, err
	}
	if readBufferSize == 0 {
		return nil, ErrInvalidReadBufferSize
	}
	return &AferoDAO[E]{
		logger:         logger,
		fs:             fs,
		partitionDir:   partitionDir,
		readBufferSize: readBufferSize,
	}, nil
}

// Retrieves the entity with the provided ID from the blob datastore. Returns
// an error if the entity can't be found or if it can't be unmarshalled.
func (aferoDAO *AferoDAO[E]) Get(id uint64, CONSISTENCY_LEVEL int) (E, error) {
	key := fmt.Sprintf("%d.%s", id, "json")
	// bytes, err := blobDAO.datastore.Get([]byte(key))
	trimmed := strings.TrimLeft(string(key), "/")
	dir := fmt.Sprintf("%s/%s/", aferoDAO.partitionDir, filepath.Dir(trimmed))
	if err := aferoDAO.fs.MkdirAll(dir, os.ModePerm); err != nil {
		aferoDAO.logger.Error(err, slog.String("key", trimmed))
		return *new(E), err
	}
	blobFile := fmt.Sprintf("%s/%s", aferoDAO.partitionDir, trimmed)
	bytes, err := afero.ReadFile(aferoDAO.fs, blobFile)
	if err != nil {
		if os.IsNotExist(err) {
			aferoDAO.logger.MaybeError(ErrRecordNotFound, slog.String("key", trimmed))
			return *new(E), ErrRecordNotFound
		}
		return *new(E), err
	}
	e := new(E)
	err = json.Unmarshal(bytes, e)
	if err != nil {
		return *new(E), err
	}
	return *e, nil
}

// Saves the provided entity to the blob datastore. Returns an error if
// the entity can not be serialized or there is a problem saving to
// blob storage.
func (aferoDAO *AferoDAO[E]) Save(entity E) error {
	kvEntity := any(entity).(entities.KeyValueEntity)
	data, err := json.Marshal(entity)
	if err != nil {
		return err
	}
	key := fmt.Sprintf("%d.%s", kvEntity.EntityID(), "json")
	blobFile := fmt.Sprintf("%s/%s", aferoDAO.partitionDir, key)
	if err := afero.WriteFile(aferoDAO.fs, blobFile, data, 0644); err != nil {
		aferoDAO.logger.Error(err, slog.String("key", key))
		return err
	}
	return nil
}

// Deletes the provided entity from the blob datastore. Returns an
// error if the provided entity can't be found.
func (aferoDAO *AferoDAO[E]) Delete(entity E) error {
	kvEntity := any(entity).(entities.KeyValueEntity)
	key := fmt.Sprintf("%d.%s", kvEntity.EntityID(), "json")
	blobFile := fmt.Sprintf("%s/%s", aferoDAO.partitionDir, key)
	if _, err := aferoDAO.fs.Stat(blobFile); err != nil {
		aferoDAO.logger.Error(err, slog.String("key", key))
		return ErrRecordNotFound
	}
	return aferoDAO.fs.RemoveAll(blobFile)
}

// Returns the number of items in the blob store partition using a buffered
// read
func (aferoDAO *AferoDAO[E]) Count(CONSISTENCY_LEVEL int) (int, error) {
	count := 0
	f, err := aferoDAO.fs.Open(aferoDAO.partitionDir)
	if err != nil {
		return 0, err
	}
	var list []string
	for err != io.EOF {
		list, err = f.Readdirnames(aferoDAO.readBufferSize)
		count = count + len(list)
	}
	f.Close()
	if err != nil && err != io.EOF {
		return 0, err
	}
	return count, nil
}

// Returns a page of items in the blob store partition
func (aferoDAO *AferoDAO[E]) Page(
	pageQuery datastore.PageQuery,
	CONSISTENCY_LEVEL int) (datastore.PageResult[E], error) {

	pageResult := datastore.PageResult[E]{
		Page:     pageQuery.Page,
		PageSize: pageQuery.PageSize}

	page := pageQuery.Page
	if page < 1 {
		page = 1
	}
	offset := (page - 1) * pageQuery.PageSize

	var list []string
	var err error

	// Open the partition directory for reading
	f, err := aferoDAO.fs.Open(aferoDAO.partitionDir)
	if err != nil {
		return pageResult, err
	}

	idx := 0
	for err != io.EOF {

		// Start reading the directories one at a time until
		// the offset index is reached
		if idx >= offset {

			list, err = f.Readdirnames(pageQuery.PageSize)

			// Peek ahead to the next record to see if there
			// are more results to return
			if _, err := f.Readdirnames(1); err != io.EOF {
				pageResult.HasMore = true
			}

			pageResult.Entities = make([]E, len(list))

			// Read and deserialize each record
			for i, file := range list {
				path := fmt.Sprintf("%s/%s", aferoDAO.partitionDir, file)
				bytes, err := afero.ReadFile(aferoDAO.fs, path)
				if err != nil {
					if err == io.EOF {
						pageResult.HasMore = false
						return pageResult, nil
					}
					return pageResult, nil
				}
				e := new(E)
				err = json.Unmarshal(bytes, e)
				if err != nil {
					return pageResult, err
				}
				pageResult.Entities[i] = *e
			}
			return pageResult, nil

		} else {
			_, err = f.Readdirnames(1)
			idx++
		}
	}

	return pageResult, nil
}

// Reads all records in batches of PageQuery.PageSize, passing each page to
// the provided pageProcFunc to process the resultset.
func (aferoDAO *AferoDAO[E]) ForEachPage(
	pageQuery datastore.PageQuery,
	pagerProcFunc datastore.PagerProcFunc[E],
	CONSISTENCY_LEVEL int) error {

	pageResult, err := aferoDAO.Page(pageQuery, CONSISTENCY_LEVEL)
	if err != nil {
		return err
	}
	if err = pagerProcFunc(pageResult.Entities); err != nil {
		return err
	}
	if pageResult.HasMore {
		nextPageQuery := datastore.PageQuery{
			Page:      pageQuery.Page + 1,
			PageSize:  pageQuery.PageSize,
			SortOrder: pageQuery.SortOrder}
		return aferoDAO.ForEachPage(nextPageQuery, pagerProcFunc, CONSISTENCY_LEVEL)
	}

	return nil
}
