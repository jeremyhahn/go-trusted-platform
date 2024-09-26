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

func TestRegistration(t *testing.T) {

	serializers := []datastore.Serializer{
		datastore.SERIALIZER_JSON,
		datastore.SERIALIZER_YAML,
	}

	for _, serializer := range serializers {

		params := aferoTestParams()
		params.Partition = registration_partition
		params.Serializer = serializer

		registrationDAO, err := NewRegistrationDAO(params)
		assert.Nil(t, err)

		// Create new registration
		reg := entities.NewRegistration("Example Registration")
		err = registrationDAO.Save(reg)
		assert.Nil(t, err)

		// Ensure it exists
		expected := fmt.Sprintf("%s/%s/%d.json", params.RootDir, reg.Partition(), reg.ID)
		_, err = params.Fs.Stat(expected)
		assert.Nil(t, err)

		// Retrieve the registration
		persisted, err := registrationDAO.Get(reg.ID, datastore.CONSISTENCY_LOCAL)
		assert.Nil(t, err)
		assert.True(t, persisted.ID == reg.ID)

		// Delete the registration
		err = registrationDAO.Delete(reg)
		assert.Nil(t, err)

		// Ensure it's deleted
		_, err = registrationDAO.Get(reg.ID, datastore.CONSISTENCY_LOCAL)
		assert.NotNil(t, err)
		assert.True(t, errors.Is(err, datastore.ErrRecordNotFound))
	}
}

func TestRegistrationCount(t *testing.T) {

	logger := logging.NewLogger(slog.LevelDebug, nil)

	serializers := []datastore.Serializer{
		datastore.SERIALIZER_JSON,
		datastore.SERIALIZER_YAML,
	}

	for _, serializer := range serializers {

		params := aferoTestParams()
		params.Partition = registration_partition
		params.Serializer = serializer

		registrationDAO, err := NewRegistrationDAO(params)
		assert.Nil(t, err)

		kvstore := New(logger, registrationDAO)

		count := 1000
		for i := 0; i < count; i++ {
			registration := entities.NewRegistration(fmt.Sprintf("Example Registration %d", i))
			err = kvstore.Save(registration)
			assert.Nil(t, err)
		}

		_count, err := kvstore.Count(datastore.CONSISTENCY_LOCAL)
		assert.Nil(t, err)
		assert.True(t, _count == count)
	}
}

func TestRegistrationPage(t *testing.T) {

	serializers := []datastore.Serializer{
		datastore.SERIALIZER_JSON,
		datastore.SERIALIZER_YAML,
	}

	for _, serializer := range serializers {

		params := aferoTestParams()
		params.Partition = registration_partition
		params.Serializer = serializer

		registrationDAO, err := NewRegistrationDAO(params)
		assert.Nil(t, err)

		count := 1000
		created := make([]*entities.Registration, count)
		for i := 0; i < count; i++ {
			registration := entities.NewRegistration(fmt.Sprintf("Example Registration %d", i))
			err = registrationDAO.Save(registration)
			assert.Nil(t, err)
			created[i] = registration
		}

		pageSize := 100

		page1, err := registrationDAO.Page(datastore.PageQuery{Page: 1, PageSize: pageSize}, datastore.CONSISTENCY_LOCAL)
		assert.Nil(t, err)
		assert.Equal(t, pageSize, len(page1.Entities))
		assert.True(t, page1.HasMore)
		// assert.Equal(t, created[0].ID, page1.Entities[0].ID)

		page2, err := registrationDAO.Page(datastore.PageQuery{Page: 2, PageSize: pageSize}, datastore.CONSISTENCY_LOCAL)
		assert.Nil(t, err)
		assert.Equal(t, pageSize, len(page2.Entities))
		assert.True(t, page2.HasMore)
		// assert.Equal(t, created[5].ID, page2.Entities[0].ID)

		page3, err := registrationDAO.Page(datastore.PageQuery{Page: 3, PageSize: pageSize}, datastore.CONSISTENCY_LOCAL)
		assert.Nil(t, err)
		assert.Equal(t, pageSize, len(page3.Entities))
		assert.True(t, page3.HasMore)
		// assert.Equal(t, created[10].ID, page3.Entities[0].ID)

		page4, err := registrationDAO.Page(datastore.PageQuery{Page: 10, PageSize: pageSize}, datastore.CONSISTENCY_LOCAL)
		assert.Nil(t, err)
		assert.Equal(t, pageSize, len(page4.Entities))
		assert.False(t, page4.HasMore)

		page5, err := registrationDAO.Page(datastore.PageQuery{Page: 11, PageSize: pageSize}, datastore.CONSISTENCY_LOCAL)
		assert.Nil(t, err)
		assert.Equal(t, 0, len(page5.Entities))
		assert.False(t, page5.HasMore)
	}
}

func TestRegistrationForEachPage(t *testing.T) {

	serializers := []datastore.Serializer{
		datastore.SERIALIZER_JSON,
		datastore.SERIALIZER_YAML,
	}

	for _, serializer := range serializers {

		params := aferoTestParams()
		params.Partition = registration_partition
		params.Serializer = serializer

		registrationDAO, err := NewRegistrationDAO(params)
		assert.Nil(t, err)

		count := 1000
		created := make([]*entities.Registration, count)
		for i := 0; i < count; i++ {
			registration := entities.NewRegistration(fmt.Sprintf("Example Registration %d", i))
			err = registrationDAO.Save(registration)
			assert.Nil(t, err)
			created[i] = registration
		}

		pageSize := 100

		pages := 0
		pagerProcFunc := func(entities []*entities.Registration) error {
			pages++
			return nil
		}

		pageQuery := datastore.PageQuery{Page: 1, PageSize: pageSize}

		err = registrationDAO.ForEachPage(pageQuery, pagerProcFunc, datastore.CONSISTENCY_LOCAL)
		assert.Nil(t, err)
		assert.Equal(t, 10, pages)
	}
}
