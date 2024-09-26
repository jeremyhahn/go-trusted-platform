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

func TestUser(t *testing.T) {

	serializers := []datastore.Serializer{
		datastore.SERIALIZER_JSON,
		datastore.SERIALIZER_YAML,
	}

	for _, serializer := range serializers {

		params := aferoTestParams()
		params.Partition = "users"
		params.Serializer = serializer

		userDAO, err := NewUserDAO(params)
		assert.Nil(t, err)

		// Create new user
		user := entities.NewUser("Example User")
		err = userDAO.Save(user)
		assert.Nil(t, err)

		// Ensure it exists
		expected := fmt.Sprintf("%s/%s/%d.json", params.RootDir, user.Partition(), user.ID)
		_, err = params.Fs.Stat(expected)
		assert.Nil(t, err)

		// Retrieve the user
		persisted, err := userDAO.Get(user.ID, datastore.CONSISTENCY_LOCAL)
		assert.Nil(t, err)
		assert.True(t, persisted.ID == user.ID)

		// Delete the user
		err = userDAO.Delete(user)
		assert.Nil(t, err)

		// Ensure it's deleted
		_, err = userDAO.Get(user.ID, datastore.CONSISTENCY_LOCAL)
		assert.NotNil(t, err)
		assert.True(t, errors.Is(err, datastore.ErrRecordNotFound))
	}
}

func TestUserCount(t *testing.T) {

	serializers := []datastore.Serializer{
		datastore.SERIALIZER_JSON,
		datastore.SERIALIZER_YAML,
	}

	for _, serializer := range serializers {

		params := aferoTestParams()
		params.Partition = "users"
		params.Serializer = serializer

		userDAO, err := NewUserDAO(params)
		assert.Nil(t, err)

		count := 1000
		for i := 0; i < count; i++ {
			user := entities.NewUser(fmt.Sprintf("Example User %d", i))
			err = userDAO.Save(user)
			assert.Nil(t, err)
		}

		_count, err := userDAO.Count(datastore.CONSISTENCY_LOCAL)
		assert.Nil(t, err)
		assert.True(t, _count == count)
	}
}

func TestUserPage(t *testing.T) {

	logger := logging.NewLogger(slog.LevelDebug, nil)

	serializers := []datastore.Serializer{
		datastore.SERIALIZER_JSON,
		datastore.SERIALIZER_YAML,
	}

	for _, serializer := range serializers {

		params := aferoTestParams()
		params.Partition = "users"
		params.Serializer = serializer

		userDAO, err := NewUserDAO(params)
		assert.Nil(t, err)

		kvstore := New(logger, userDAO)

		count := 1000
		created := make([]*entities.User, count)
		for i := 0; i < count; i++ {
			user := entities.NewUser(fmt.Sprintf("Example User %d", i))
			err = userDAO.Save(user)
			assert.Nil(t, err)
			created[i] = user
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

func TestUserForEachPage(t *testing.T) {

	logger := logging.NewLogger(slog.LevelDebug, nil)

	serializers := []datastore.Serializer{
		datastore.SERIALIZER_JSON,
		datastore.SERIALIZER_YAML,
	}

	for _, serializer := range serializers {

		params := aferoTestParams()
		params.Partition = "users"
		params.Serializer = serializer

		userDAO, err := NewUserDAO(params)
		assert.Nil(t, err)

		kvstore := New(logger, userDAO)

		count := 1000
		created := make([]*entities.User, count)
		for i := 0; i < count; i++ {
			user := entities.NewUser(fmt.Sprintf("Example User %d", i))
			err = kvstore.Save(user)
			assert.Nil(t, err)
			created[i] = user
		}

		pageSize := 100

		pages := 0
		pagerProcFunc := func(entities []*entities.User) error {
			pages++
			return nil
		}

		pageQuery := datastore.PageQuery{Page: 1, PageSize: pageSize}

		err = kvstore.ForEachPage(pageQuery, pagerProcFunc, datastore.CONSISTENCY_LOCAL)
		assert.Nil(t, err)
		assert.Equal(t, 10, pages)
	}
}
