package service

import (
	"errors"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

var (
	ErrRoleNotFound = errors.New("role not found")
)

type RoleServicer interface {
	GetPage(pageQuery datastore.PageQuery) (datastore.PageResult[*entities.Role], error)
	GetByName(name string, CONSISTENCY_LEVEL datastore.ConsistencyLevel) (*entities.Role, error)
}

type RoleService struct {
	logger  *logging.Logger
	roleDAO datastore.RoleDAO
	RoleServicer
}

func NewRoleService(
	logger *logging.Logger,
	roleDAO datastore.RoleDAO) RoleServicer {

	return &RoleService{
		logger:  logger,
		roleDAO: roleDAO}
}

// Returns a single page of role entities from the database
func (service *RoleService) Page(pageQuery datastore.PageQuery) (datastore.PageResult[*entities.Role], error) {
	return service.roleDAO.Page(pageQuery, datastore.ConsistencyLevelLocal)
}

// Returns the role with the given name
func (service *RoleService) GetByName(name string, CONSISTENCY_LEVEL datastore.ConsistencyLevel) (*entities.Role, error) {
	return service.roleDAO.GetByName(name, CONSISTENCY_LEVEL)
}
