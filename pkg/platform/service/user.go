package service

import (
	"errors"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

var (
	ErrUnsupportedAuthType = errors.New("unsupported auth type")
	ErrUserNotFound        = errors.New("user not found")
)

type UserServicer interface {
	Save(user *entities.User) error
	Delete(session Session, userID uint64) error
	Get(userID uint64) (*entities.User, error)
}

type User struct {
	logger  *logging.Logger
	userDAO datastore.UserDAO
	orgDAO  datastore.OrganizationDAO
	roleDAO datastore.RoleDAO
	UserServicer
}

func NewUserService(
	logger *logging.Logger,
	userDAO datastore.UserDAO,
	orgDAO datastore.OrganizationDAO,
	roleDAO datastore.RoleDAO,
	authServices map[int]AuthServicer) UserServicer {

	return &User{
		logger:  logger,
		userDAO: userDAO,
		orgDAO:  orgDAO,
		roleDAO: roleDAO}
}

// Create a new user
func (service *User) Save(user *entities.User) error {
	return service.userDAO.Save(user)
}

// Delete an existing user
func (service *User) Delete(session Session, userID uint64) error {
	return service.userDAO.Delete(&entities.User{ID: userID})
}

// Retrieves a user with the given id or ErrRecordNotFound
func (service *User) Get(userID uint64) (*entities.User, error) {
	userEntity, err := service.userDAO.Get(userID, datastore.ConsistencyLevelLocal)
	if err != nil {
		return nil, err
	}
	return userEntity, nil
}
