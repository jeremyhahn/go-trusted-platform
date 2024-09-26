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

func TestRole(t *testing.T) {

	serializers := []datastore.Serializer{
		datastore.SERIALIZER_JSON,
		datastore.SERIALIZER_YAML,
	}

	for _, serializer := range serializers {

		params := aferoTestParams()
		params.Partition = role_partition
		params.Serializer = serializer

		roleDAO, err := NewRoleDAO(params)
		assert.Nil(t, err)

		// Create new role
		role := entities.NewRole("Example Role")
		err = roleDAO.Save(role)
		assert.Nil(t, err)

		// Ensure it exists
		expected := fmt.Sprintf("%s/%s/%d.json", params.RootDir, role.Partition(), role.ID)
		_, err = params.Fs.Stat(expected)
		assert.Nil(t, err)

		// Retrieve the role
		persisted, err := roleDAO.Get(role.ID, datastore.CONSISTENCY_LOCAL)
		assert.Nil(t, err)
		assert.True(t, persisted.ID == role.ID)

		// Delete the role
		err = roleDAO.Delete(role)
		assert.Nil(t, err)

		// Ensure it's deleted
		_, err = roleDAO.Get(role.ID, datastore.CONSISTENCY_LOCAL)
		assert.NotNil(t, err)
		assert.True(t, errors.Is(err, datastore.ErrRecordNotFound))
	}
}

func TestRoleCount(t *testing.T) {

	logger := logging.NewLogger(slog.LevelDebug, nil)

	serializers := []datastore.Serializer{
		datastore.SERIALIZER_JSON,
		datastore.SERIALIZER_YAML,
	}

	for _, serializer := range serializers {

		params := aferoTestParams()
		params.Partition = role_partition
		params.Serializer = serializer

		roleDAO, err := NewRoleDAO(params)
		assert.Nil(t, err)

		kvstore := New(logger, roleDAO)

		count := 1000
		for i := 0; i < count; i++ {
			role := entities.NewRole(fmt.Sprintf("Example Role %d", i))
			err = kvstore.Save(role)
			assert.Nil(t, err)
		}

		_count, err := kvstore.Count(datastore.CONSISTENCY_LOCAL)
		assert.Nil(t, err)
		assert.True(t, _count == count)
	}
}

func TestRolePage(t *testing.T) {

	serializers := []datastore.Serializer{
		datastore.SERIALIZER_JSON,
		datastore.SERIALIZER_YAML,
	}

	for _, serializer := range serializers {

		params := aferoTestParams()
		params.Partition = role_partition
		params.Serializer = serializer

		roleDAO, err := NewRoleDAO(params)
		assert.Nil(t, err)

		count := 1000
		created := make([]*entities.Role, count)
		for i := 0; i < count; i++ {
			role := entities.NewRole(fmt.Sprintf("Example Role %d", i))
			err = roleDAO.Save(role)
			assert.Nil(t, err)
			created[i] = role
		}

		pageSize := 100

		page1, err := roleDAO.Page(datastore.PageQuery{Page: 1, PageSize: pageSize}, datastore.CONSISTENCY_LOCAL)
		assert.Nil(t, err)
		assert.Equal(t, pageSize, len(page1.Entities))
		assert.True(t, page1.HasMore)
		// assert.Equal(t, created[0].ID, page1.Entities[0].ID)

		page2, err := roleDAO.Page(datastore.PageQuery{Page: 2, PageSize: pageSize}, datastore.CONSISTENCY_LOCAL)
		assert.Nil(t, err)
		assert.Equal(t, pageSize, len(page2.Entities))
		assert.True(t, page2.HasMore)
		// assert.Equal(t, created[5].ID, page2.Entities[0].ID)

		page3, err := roleDAO.Page(datastore.PageQuery{Page: 3, PageSize: pageSize}, datastore.CONSISTENCY_LOCAL)
		assert.Nil(t, err)
		assert.Equal(t, pageSize, len(page3.Entities))
		assert.True(t, page3.HasMore)
		// assert.Equal(t, created[10].ID, page3.Entities[0].ID)

		page4, err := roleDAO.Page(datastore.PageQuery{Page: 10, PageSize: pageSize}, datastore.CONSISTENCY_LOCAL)
		assert.Nil(t, err)
		assert.Equal(t, pageSize, len(page4.Entities))
		assert.False(t, page4.HasMore)

		page5, err := roleDAO.Page(datastore.PageQuery{Page: 11, PageSize: pageSize}, datastore.CONSISTENCY_LOCAL)
		assert.Nil(t, err)
		assert.Equal(t, 0, len(page5.Entities))
		assert.False(t, page5.HasMore)
	}
}

func TestRoleForEachPage(t *testing.T) {

	serializers := []datastore.Serializer{
		datastore.SERIALIZER_JSON,
		datastore.SERIALIZER_YAML,
	}

	for _, serializer := range serializers {

		params := aferoTestParams()
		params.Partition = role_partition
		params.Serializer = serializer

		roleDAO, err := NewRoleDAO(params)
		assert.Nil(t, err)

		count := 1000
		created := make([]*entities.Role, count)
		for i := 0; i < count; i++ {
			role := entities.NewRole(fmt.Sprintf("Example Role %d", i))
			err = roleDAO.Save(role)
			assert.Nil(t, err)
			created[i] = role
		}

		pageSize := 100

		pages := 0
		pagerProcFunc := func(entities []*entities.Role) error {
			pages++
			return nil
		}

		pageQuery := datastore.PageQuery{Page: 1, PageSize: pageSize}

		err = roleDAO.ForEachPage(pageQuery, pagerProcFunc, datastore.CONSISTENCY_LOCAL)
		assert.Nil(t, err)
		assert.Equal(t, 10, pages)
	}
}
