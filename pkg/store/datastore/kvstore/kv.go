package kvstore

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/spf13/afero"
)

type Params struct {
	Fs             afero.Fs
	Logger         *logging.Logger
	Partition      string
	ReadBufferSize int
	RootDir        string
	Serializer     datastore.Serializer
}

type KVStore[E any] struct {
	dao    datastore.GenericDAO[E]
	logger *logging.Logger
	datastore.GenericDAO[E]
}

func New[E any](
	logger *logging.Logger,
	dao datastore.GenericDAO[E]) datastore.GenericDAO[E] {

	return &KVStore[E]{
		dao:    dao,
		logger: logger,
	}
}

func (kvstore *KVStore[E]) Save(entity E) error {
	return kvstore.dao.Save(entity)
}

func (kvstore *KVStore[E]) Get(id uint64, CONSISTENCY_LEVEL int) (E, error) {
	return kvstore.dao.Get(id, CONSISTENCY_LEVEL)
}

func (kvstore *KVStore[E]) Delete(entity E) error {
	return kvstore.dao.Delete(entity)
}

func (kvstore *KVStore[E]) Count(CONSISTENCY_LEVEL int) (int, error) {
	return kvstore.dao.Count(CONSISTENCY_LEVEL)
}

func (kvstore *KVStore[E]) Page(
	pageQuery datastore.PageQuery,
	CONSISTENCY_LEVEL int) (datastore.PageResult[E], error) {

	return kvstore.dao.Page(pageQuery, CONSISTENCY_LEVEL)
}

func (kvstore *KVStore[E]) ForEachPage(
	pageQuery datastore.PageQuery,
	pagerProcFunc datastore.PagerProcFunc[E],
	CONSISTENCY_LEVEL int) error {

	return kvstore.dao.ForEachPage(pageQuery, pagerProcFunc, CONSISTENCY_LEVEL)
}
