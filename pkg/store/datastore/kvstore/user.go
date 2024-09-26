package kvstore

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

const (
	user_partition = "users"
)

type UserDAO struct {
	*AferoDAO[*entities.User]
}

func NewUserDAO(params *Params) (datastore.UserDAO, error) {
	if params.Partition == "" {
		params.Partition = user_partition
	}
	aferoDAO, err := NewAferoDAO[*entities.User](params)
	if err != nil {
		return nil, err
	}
	return &UserDAO{
		AferoDAO: aferoDAO,
	}, nil
}

func (userDAO *UserDAO) Save(entity *entities.User) error {
	return userDAO.AferoDAO.Save(entity)
}

func (userDAO *UserDAO) Get(id uint64, CONSISTENCY_LEVEL int) (*entities.User, error) {
	return userDAO.AferoDAO.Get(id, CONSISTENCY_LEVEL)
}

func (userDAO *UserDAO) Delete(entity *entities.User) error {
	return userDAO.AferoDAO.Delete(entity)
}

func (userDAO *UserDAO) Count(CONSISTENCY_LEVEL int) (int, error) {
	return userDAO.AferoDAO.Count(CONSISTENCY_LEVEL)
}

func (userDAO *UserDAO) Page(
	pageQuery datastore.PageQuery,
	CONSISTENCY_LEVEL int) (datastore.PageResult[*entities.User], error) {

	return userDAO.AferoDAO.Page(pageQuery, CONSISTENCY_LEVEL)
}

func (userDAO *UserDAO) ForEachPage(
	pageQuery datastore.PageQuery,
	pagerProcFunc datastore.PagerProcFunc[*entities.User],
	CONSISTENCY_LEVEL int) error {

	return userDAO.AferoDAO.ForEachPage(pageQuery, pagerProcFunc, CONSISTENCY_LEVEL)
}
