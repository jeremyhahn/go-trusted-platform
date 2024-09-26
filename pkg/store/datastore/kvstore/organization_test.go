package kvstore

import (
	"errors"
	"fmt"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/stretchr/testify/assert"
)

func TestOrganization(t *testing.T) {

	serializers := []datastore.Serializer{
		datastore.SERIALIZER_JSON,
		datastore.SERIALIZER_YAML,
	}

	for _, serializer := range serializers {

		params := aferoTestParams()
		params.Partition = organization_partition
		params.Serializer = serializer

		organizationDAO, err := NewOrganizationDAO(params)
		assert.Nil(t, err)

		// Create new org
		org := entities.NewOrganization("Example Organization")
		err = organizationDAO.Save(org)
		assert.Nil(t, err)

		// Ensure it exists
		expected := fmt.Sprintf("%s/%s/%d.json", params.RootDir, org.Partition(), org.ID)
		_, err = params.Fs.Stat(expected)
		assert.Nil(t, err)

		// Retrieve the org
		persisted, err := organizationDAO.Get(org.ID, datastore.CONSISTENCY_LOCAL)
		assert.Nil(t, err)
		assert.True(t, persisted.ID == org.ID)

		// Delete the org
		err = organizationDAO.Delete(org)
		assert.Nil(t, err)

		// Ensure it's deleted
		_, err = organizationDAO.Get(org.ID, datastore.CONSISTENCY_LOCAL)
		assert.NotNil(t, err)
		assert.True(t, errors.Is(err, datastore.ErrRecordNotFound))
	}
}

func TestOrganizationCount(t *testing.T) {

	logger := logging.NewLogger(slog.LevelDebug, nil)

	serializers := []datastore.Serializer{
		datastore.SERIALIZER_JSON,
		datastore.SERIALIZER_YAML,
	}

	for _, serializer := range serializers {

		params := aferoTestParams()
		params.Partition = organization_partition
		params.Serializer = serializer

		organizationDAO, err := NewOrganizationDAO(params)
		assert.Nil(t, err)

		kvstore := New(logger, organizationDAO)

		count := 1000
		for i := 0; i < count; i++ {
			org := entities.NewOrganization(fmt.Sprintf("Example Organization %d", i))
			err = kvstore.Save(org)
			assert.Nil(t, err)
		}

		_count, err := kvstore.Count(datastore.CONSISTENCY_LOCAL)
		assert.Nil(t, err)
		assert.True(t, _count == count)
	}
}

func TestOrganizationPage(t *testing.T) {

	serializers := []datastore.Serializer{
		datastore.SERIALIZER_JSON,
		datastore.SERIALIZER_YAML,
	}

	for _, serializer := range serializers {

		params := aferoTestParams()
		params.Partition = organization_partition
		params.Serializer = serializer

		organizationDAO, err := NewOrganizationDAO(params)
		assert.Nil(t, err)

		count := 1000
		created := make([]*entities.Organization, count)
		for i := 0; i < count; i++ {
			org := entities.NewOrganization(fmt.Sprintf("Example Organization %d", i))
			err = organizationDAO.Save(org)
			assert.Nil(t, err)
			created[i] = org
		}

		pageSize := 100

		page1, err := organizationDAO.Page(datastore.PageQuery{Page: 1, PageSize: pageSize}, datastore.CONSISTENCY_LOCAL)
		assert.Nil(t, err)
		assert.Equal(t, pageSize, len(page1.Entities))
		assert.True(t, page1.HasMore)
		// assert.Equal(t, created[0].ID, page1.Entities[0].ID)

		page2, err := organizationDAO.Page(datastore.PageQuery{Page: 2, PageSize: pageSize}, datastore.CONSISTENCY_LOCAL)
		assert.Nil(t, err)
		assert.Equal(t, pageSize, len(page2.Entities))
		assert.True(t, page2.HasMore)
		// assert.Equal(t, created[5].ID, page2.Entities[0].ID)

		page3, err := organizationDAO.Page(datastore.PageQuery{Page: 3, PageSize: pageSize}, datastore.CONSISTENCY_LOCAL)
		assert.Nil(t, err)
		assert.Equal(t, pageSize, len(page3.Entities))
		assert.True(t, page3.HasMore)
		// assert.Equal(t, created[10].ID, page3.Entities[0].ID)

		page4, err := organizationDAO.Page(datastore.PageQuery{Page: 10, PageSize: pageSize}, datastore.CONSISTENCY_LOCAL)
		assert.Nil(t, err)
		assert.Equal(t, pageSize, len(page4.Entities))
		assert.False(t, page4.HasMore)

		page5, err := organizationDAO.Page(datastore.PageQuery{Page: 11, PageSize: pageSize}, datastore.CONSISTENCY_LOCAL)
		assert.Nil(t, err)
		assert.Equal(t, 0, len(page5.Entities))
		assert.False(t, page5.HasMore)
	}
}

func TestOrganizationForEachPage(t *testing.T) {

	serializers := []datastore.Serializer{
		datastore.SERIALIZER_JSON,
		datastore.SERIALIZER_YAML,
	}

	for _, serializer := range serializers {

		params := aferoTestParams()
		params.Partition = organization_partition
		params.Serializer = serializer

		organizationDAO, err := NewOrganizationDAO(params)
		assert.Nil(t, err)

		count := 1000
		created := make([]*entities.Organization, count)
		for i := 0; i < count; i++ {
			org := entities.NewOrganization(fmt.Sprintf("Example Organization %d", i))
			err = organizationDAO.Save(org)
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

		err = organizationDAO.ForEachPage(pageQuery, pagerProcFunc, datastore.CONSISTENCY_LOCAL)
		assert.Nil(t, err)
		assert.Equal(t, 10, pages)
	}
}
