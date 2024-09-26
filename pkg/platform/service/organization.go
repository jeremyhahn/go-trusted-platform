package service

import (
	"errors"

	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"

	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
)

var (
	ErrOrganizationNotFound = errors.New("organization not found")
)

type OrganizationService interface {
	Create(organization *entities.Organization) error
	Page(session Session, pageQuery datastore.PageQuery) (datastore.PageResult[*entities.Organization], error)
	GetUsers(session Session) ([]*entities.User, error)
	Delete(session Session) error
}

type Organization struct {
	logger *logging.Logger
	orgDAO datastore.OrganizationDAO
	OrganizationService
}

func NewOrganizationService(
	logger *logging.Logger,
	orgDAO datastore.OrganizationDAO) OrganizationService {

	return &Organization{
		logger: logger,
		orgDAO: orgDAO}
}

// Creates a new organization
func (service *Organization) Create(organization *entities.Organization) error {
	organization.SetEntityID(util.NewID([]byte(organization.Name)))
	return service.orgDAO.Save(organization)
}

// Returns a single page of organization entities
func (service *Organization) Page(session Session,
	pageQuery datastore.PageQuery) (datastore.PageResult[*entities.Organization], error) {

	if !session.User().HasRole(common.ROLE_ADMIN) {
		return datastore.PageResult[*entities.Organization]{}, ErrPermissionDenied
	}
	return service.orgDAO.Page(pageQuery, datastore.CONSISTENCY_LOCAL)
}

// Returns a list of User entities that belong to the organization
func (service *Organization) GetUsers(session Session) ([]*entities.User, error) {
	if !session.User().HasRole(common.ROLE_ADMIN) {
		return nil, ErrPermissionDenied
	}
	users, err := service.orgDAO.GetUsers(session.RequestedOrganizationID(), session.ConsistencyLevel())
	if err != nil {
		service.logger.Error(err)
		return nil, err
	}
	// userModels := make([]model.User, len(userStructs))
	// for i, user := range userStructs {
	// 	//userModels[i] = service.userMapper.MapUserConfigToModel(user)
	// }
	return users, nil
}

// Deletes an existing organization and all associated entites from the database
func (service *Organization) Delete(session Session) error {
	if !session.User().HasRole(common.ROLE_ADMIN) {
		return ErrPermissionDenied
	}
	return service.orgDAO.Delete(
		&entities.Organization{
			ID: session.RequestedOrganizationID()})
}
