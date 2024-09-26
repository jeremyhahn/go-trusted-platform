package kvstore

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
)

const (
	role_partition = "roles"
)

type RoleDAO struct {
	*AferoDAO[*entities.Role]
}

func NewRoleDAO(params *Params) (datastore.RoleDAO, error) {
	if params.Partition == "" {
		params.Partition = role_partition
	}
	aferoDAO, err := NewAferoDAO[*entities.Role](params)
	if err != nil {
		return nil, err
	}
	return &RoleDAO{
		AferoDAO: aferoDAO,
	}, nil
}

func (roleDAO *RoleDAO) Save(entity *entities.Role) error {
	return roleDAO.AferoDAO.Save(entity)
}

func (roleDAO *RoleDAO) Get(id uint64, CONSISTENCY_LEVEL int) (*entities.Role, error) {
	return roleDAO.AferoDAO.Get(id, CONSISTENCY_LEVEL)
}

func (roleDAO *RoleDAO) Delete(entity *entities.Role) error {
	return roleDAO.AferoDAO.Delete(entity)
}

func (roleDAO *RoleDAO) Count(CONSISTENCY_LEVEL int) (int, error) {
	return roleDAO.AferoDAO.Count(CONSISTENCY_LEVEL)
}

func (roleDAO *RoleDAO) Page(
	pageQuery datastore.PageQuery,
	CONSISTENCY_LEVEL int) (datastore.PageResult[*entities.Role], error) {

	return roleDAO.AferoDAO.Page(pageQuery, CONSISTENCY_LEVEL)
}

func (roleDAO *RoleDAO) ForEachPage(
	pageQuery datastore.PageQuery,
	pagerProcFunc datastore.PagerProcFunc[*entities.Role],
	CONSISTENCY_LEVEL int) error {

	return roleDAO.AferoDAO.ForEachPage(pageQuery, pagerProcFunc, CONSISTENCY_LEVEL)
}

func (roleDAO *RoleDAO) GetByName(name string, CONSISTENCY_LEVEL int) (*entities.Role, error) {
	id := util.NewID([]byte(name))
	return roleDAO.Get(id, CONSISTENCY_LEVEL)
}
