package service

import (
	"errors"

	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

var (
	ErrUnsupportedAuthType = errors.New("unsupported auth type")
	ErrUserNotFound        = errors.New("user not found")
)

type UserServicer interface {
	CreateUser(user *entities.User) error
	UpdateUser(user *entities.User) error
	Delete(session Session, userID uint64) error
	// DeletePermission(session Session, userID uint64) error
	Get(userID uint64) (*entities.User, error)
	// SetPermission(session Session, permission *entities.Permission) error
	// probably needs to be moved to auth service; not implemented in google_auth yet
	// Refresh(userID uint64) (*entities.User, []*entities.Organization, []*entities.Service, error)
	AuthServicer
}

type User struct {
	logger  *logging.Logger
	userDAO datastore.UserDAO
	orgDAO  datastore.OrganizationDAO
	roleDAO datastore.RoleDAO
	// permissionDAO datastore.PermissionDAO
	// serviceDAO    datastore.ServiceDAO
	authServices map[int]AuthServicer
	UserServicer
	AuthServicer
}

func NewUserService(
	logger *logging.Logger,
	userDAO datastore.UserDAO,
	orgDAO datastore.OrganizationDAO,
	roleDAO datastore.RoleDAO,
	// permissionDAO datastore.PermissionDAO,
	// serviceDAO datastore.ServiceDAO,
	authServices map[int]AuthServicer) UserServicer {

	return &User{
		logger:  logger,
		userDAO: userDAO,
		orgDAO:  orgDAO,
		roleDAO: roleDAO} //,
	// permissionDAO: permissionDAO,
	// serviceDAO:       serviceDAO,
	// authServices: authServices}
}

// Looks up the user account by user ID
func (service *User) Get(userID uint64) (*entities.User, error) {
	userEntity, err := service.userDAO.Get(userID, datastore.CONSISTENCY_LOCAL)
	if err != nil {
		return nil, err
	}
	// return service.userMapper.MapUserConfigToModel(userEntity), nil
	return userEntity, nil
}

// Sets a new user password
func (service *User) ResetPassword(userCredential *UserCredential) error {
	if authService, ok := service.authServices[userCredential.AuthType]; ok {
		return authService.ResetPassword(userCredential)
	}
	return ErrUnsupportedAuthType
}

// Register signs up a new account
func (service *User) Register(userCredential *UserCredential,
	baseURI string) (*entities.User, error) {

	if authService, ok := service.authServices[userCredential.AuthType]; ok {
		return authService.Register(userCredential, baseURI)
	}
	return nil, ErrUnsupportedAuthType
}

// Activates a pending registration
func (service *User) Activate(registrationID uint64) (*entities.User, error) {
	if authService, ok := service.authServices[common.AUTH_TYPE_LOCAL]; ok {
		return authService.Activate(registrationID)
	}
	return nil, ErrUnsupportedAuthType
}

// Login authenticates a user account against the AuthService
func (service *User) Login(userCredential *UserCredential) (*entities.User,
	[]*entities.Organization, []*entities.Service, error) {

	if authService, ok := service.authServices[userCredential.AuthType]; ok {
		user, orgs, services, err := authService.Login(userCredential)
		if err != nil {
			return nil, nil, nil, err
		}
		return user, orgs, services, nil
	}
	return nil, nil, nil, ErrUnsupportedAuthType
}

// Reloads the users organizations, services and permissions
func (service *User) Refresh(userID uint64) (*entities.User,
	[]*entities.Organization, []*entities.Service, error) {

	// 	service.logger.Debugf("Refreshing user: %d", userID)

	// 	var user *entities.User

	// 	organizations, err := service.permissionDAO.GetOrganizations(userID, datastore.CONSISTENCY_LOCAL)
	// 	if err != nil && err.Error() != ErrRecordNotFound.Error() {
	// 		return nil, nil, nil, ErrInvalidCredentials
	// 	}
	// 	if err != nil {
	// 		return nil, nil, nil, err
	// 	}

	// ORG_LOOP:
	// 	for _, org := range organizations {
	// 		for _, u := range org.GetUsers() {
	// 			if user.Identifier() == userID {
	// 				user = u
	// 				user.RedactPassword()
	// 				break ORG_LOOP
	// 			}
	// 			// user.SetRoles([]*entities.Role{{ID: 1, Name: common.DEFAULT_ROLE}})
	// 		}
	// 	}

	// 	farms, err := service.farmDAO.GetByUserID(userID, common.CONSISTENCY_LOCAL)
	// 	if err != nil {
	// 		return nil, nil, nil, err
	// 	}

	// 	if user == nil {
	// 		user, err = service.userDAO.Get(userID, common.CONSISTENCY_LOCAL)
	// 		if err != nil {
	// 			return nil, nil, nil, err
	// 		}
	// 		userModel := service.userMapper.MapUserConfigToModel(user)
	// 		orgs := make([]*entities.Organization, len(organizations))
	// 		for i, org := range organizations {
	// 			orgs[i] = org
	// 		}
	// 		_farms := make([]*entities.Farm, len(farms))
	// 		for i, farm := range farms {
	// 			_farms[i] = farm
	// 		}
	// 		return userModel, orgs, _farms, nil
	// 	}

	// 	if user.ID == 0 && len(organizations) == 0 {
	// 	FARM_LOOP:
	// 		for _, farm := range farms {
	// 			for _, u := range farm.GetUsers() {
	// 				if u.ID == userID {
	// 					user = u
	// 					user.RedactPassword()
	// 					break FARM_LOOP
	// 				}
	// 			}
	// 		}
	// 	}

	// 	if user.ID == 0 {
	// 		return nil, nil, nil, ErrUserNotFound
	// 	}

	// 	// Convert structs to interfaces
	// 	orgs := make([]*entities.Organization, len(organizations))
	// 	for i, org := range organizations {
	// 		orgs[i] = org
	// 	}
	// 	_farms := make([]*entities.Farm, len(farms))
	// 	for i, farm := range farms {
	// 		_farms[i] = farm
	// 	}
	// 	return service.userMapper.MapUserConfigToModel(user), orgs, _farms, nil

	return &entities.User{}, nil, nil, nil
}

// CreateUser creates a new user account
func (service *User) CreateUser(user *entities.User) error {
	return service.userDAO.Save(user)
}

// UpdateUser an existing user account
func (service *User) UpdateUser(user *entities.User) error {
	return service.userDAO.Save(user)
}

// Deletes an existing user account
func (service *User) Delete(session Session, userID uint64) error {
	// if err := service.DeletePermission(session, userID); err != nil {
	// 	return err
	// }
	return service.userDAO.Delete(&entities.User{ID: userID})
}
