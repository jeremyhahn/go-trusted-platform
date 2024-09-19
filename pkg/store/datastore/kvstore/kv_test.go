package kvstore

import (
	"errors"
	"fmt"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
)

func TestKV(t *testing.T) {

	fs := afero.NewMemMapFs()

	logger := logging.NewLogger(slog.LevelDebug, nil)

	rootDir := "./test"
	partition := "organizations"
	readBufferSize := 50

	serializers := []datastore.Serializer{
		datastore.SERIALIZER_JSON,
		datastore.SERIALIZER_YAML,
	}

	for _, serializer := range serializers {

		aferoDAO, err := NewAferoDAO[*entities.Organization](
			logger, fs, rootDir, partition, serializer, readBufferSize)
		assert.Nil(t, err)

		kvstore := New(logger, aferoDAO)

		// Create new org
		org := entities.NewOrganization("Example Org")
		err = kvstore.Save(org)
		assert.Nil(t, err)

		// Ensure it exists
		expected := fmt.Sprintf("%s/%s/%d.json", rootDir, org.Partition(), org.ID)
		_, err = fs.Stat(expected)
		assert.Nil(t, err)

		// Retrieve the org
		persisted, err := kvstore.Get(org.ID, datastore.CONSISTENCY_LOCAL)
		assert.Nil(t, err)
		assert.True(t, persisted.ID == org.ID)

		// Delete the org
		err = kvstore.Delete(org)
		assert.Nil(t, err)

		// Ensure it's deleted
		_, err = kvstore.Get(org.ID, datastore.CONSISTENCY_LOCAL)
		assert.NotNil(t, err)
		assert.True(t, errors.Is(err, ErrRecordNotFound))
	}
}

func TestKVCount(t *testing.T) {

	fs := afero.NewMemMapFs()

	logger := logging.NewLogger(slog.LevelDebug, nil)

	rootDir := "./test"
	partition := "organizations"
	readBufferSize := 50

	serializers := []datastore.Serializer{
		datastore.SERIALIZER_JSON,
		datastore.SERIALIZER_YAML,
	}

	for _, serializer := range serializers {

		aferoDAO, err := NewAferoDAO[*entities.Organization](
			logger, fs, rootDir, partition, serializer, readBufferSize)
		assert.Nil(t, err)

		kvstore := New(logger, aferoDAO)

		count := 1000
		for i := 0; i < count; i++ {
			org := entities.NewOrganization(fmt.Sprintf("Example Org %d", i))
			err = kvstore.Save(org)
			assert.Nil(t, err)
		}

		_count, err := kvstore.Count(datastore.CONSISTENCY_LOCAL)
		assert.Nil(t, err)
		assert.True(t, _count == count)
	}
}

func TestKVPage(t *testing.T) {

	fs := afero.NewMemMapFs()

	logger := logging.NewLogger(slog.LevelDebug, nil)

	rootDir := "./test"
	partition := "organizations"
	readBufferSize := 50

	serializers := []datastore.Serializer{
		datastore.SERIALIZER_JSON,
		datastore.SERIALIZER_YAML,
	}

	for _, serializer := range serializers {

		aferoDAO, err := NewAferoDAO[*entities.Organization](
			logger, fs, rootDir, partition, serializer, readBufferSize)
		assert.Nil(t, err)

		kvstore := New(logger, aferoDAO)

		count := 1000
		created := make([]*entities.Organization, count)
		for i := 0; i < count; i++ {
			org := entities.NewOrganization(fmt.Sprintf("Example Org %d", i))
			err = aferoDAO.Save(org)
			assert.Nil(t, err)
			created[i] = org
		}

		pageSize := 100

		page1, err := kvstore.Page(datastore.PageQuery{Page: 1, PageSize: pageSize}, datastore.CONSISTENCY_LOCAL)
		assert.Nil(t, err)
		assert.Equal(t, pageSize, len(page1.Entities))
		assert.True(t, page1.HasMore)
		// assert.Equal(t, created[0].ID, page1.Entities[0].ID)

		page2, err := kvstore.Page(datastore.PageQuery{Page: 2, PageSize: pageSize}, datastore.CONSISTENCY_LOCAL)
		assert.Nil(t, err)
		assert.Equal(t, pageSize, len(page2.Entities))
		assert.True(t, page2.HasMore)
		// assert.Equal(t, created[5].ID, page2.Entities[0].ID)

		page3, err := kvstore.Page(datastore.PageQuery{Page: 3, PageSize: pageSize}, datastore.CONSISTENCY_LOCAL)
		assert.Nil(t, err)
		assert.Equal(t, pageSize, len(page3.Entities))
		assert.True(t, page3.HasMore)
		// assert.Equal(t, created[10].ID, page3.Entities[0].ID)

		page4, err := kvstore.Page(datastore.PageQuery{Page: 10, PageSize: pageSize}, datastore.CONSISTENCY_LOCAL)
		assert.Nil(t, err)
		assert.Equal(t, pageSize, len(page4.Entities))
		assert.False(t, page4.HasMore)

		page5, err := kvstore.Page(datastore.PageQuery{Page: 11, PageSize: pageSize}, datastore.CONSISTENCY_LOCAL)
		assert.Nil(t, err)
		assert.Equal(t, 0, len(page5.Entities))
		assert.False(t, page5.HasMore)
	}
}

func TestKVForEachPage(t *testing.T) {

	fs := afero.NewMemMapFs()

	logger := logging.NewLogger(slog.LevelDebug, nil)

	rootDir := "./test"
	partition := "organizations"
	readBufferSize := 50

	serializers := []datastore.Serializer{
		datastore.SERIALIZER_JSON,
		datastore.SERIALIZER_YAML,
	}

	for _, serializer := range serializers {

		aferoDAO, err := NewAferoDAO[*entities.Organization](
			logger, fs, rootDir, partition, serializer, readBufferSize)
		assert.Nil(t, err)

		kvstore := New(logger, aferoDAO)

		count := 1000
		created := make([]*entities.Organization, count)
		for i := 0; i < count; i++ {
			org := entities.NewOrganization(fmt.Sprintf("Example Org %d", i))
			err = kvstore.Save(org)
			assert.Nil(t, err)
			created[i] = org
		}

		pageSize := 100

		pages := 0
		pagerProcFunc := func(entities []*entities.Organization) error {
			pages++
			return nil
		}

		pageQuery := datastore.PageQuery{Page: 1, PageSize: pageSize}

		err = kvstore.ForEachPage(pageQuery, pagerProcFunc, datastore.CONSISTENCY_LOCAL)
		assert.Nil(t, err)
		assert.Equal(t, 10, pages)
	}
}
