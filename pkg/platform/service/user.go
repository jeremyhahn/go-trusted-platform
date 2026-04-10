// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

var (
	ErrUnsupportedAuthType = errors.New("unsupported auth type")
)

// UserServicer defines the interface for user management operations.
type UserServicer interface {
	// Save saves a user entity.
	Save(ctx context.Context, user *entities.User) error
	// Delete removes a user by ID.
	Delete(ctx context.Context, userID uint64) error
	// Get retrieves a user by ID.
	Get(ctx context.Context, userID uint64) (*entities.User, error)
	// GetByEmail finds a user by email address.
	GetByEmail(ctx context.Context, email string) (*entities.User, error)
	// GetByTenant returns all users in a tenant.
	GetByTenant(ctx context.Context, tenantID string) ([]*entities.User, error)
	// IsTenantOwner checks if a user owns their tenant.
	IsTenantOwner(ctx context.Context, userID uint64) (bool, error)
}

// User implements UserServicer.
type User struct {
	logger  *logging.Logger
	userDAO datastore.UserDAO
	orgDAO  datastore.OrganizationDAO
	roleDAO datastore.RoleDAO
}

// NewUserService creates a new user service.
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
		roleDAO: roleDAO,
	}
}

// Save saves a user entity.
func (service *User) Save(ctx context.Context, user *entities.User) error {
	return service.userDAO.Save(ctx, user)
}

// Delete removes a user by ID.
func (service *User) Delete(ctx context.Context, userID uint64) error {
	return service.userDAO.Delete(ctx, &entities.User{ID: userID})
}

// Get retrieves a user by ID.
func (service *User) Get(ctx context.Context, userID uint64) (*entities.User, error) {
	userEntity, err := service.userDAO.Get(ctx, userID)
	if err != nil {
		return nil, err
	}
	return userEntity, nil
}

// GetByEmail finds a user by email address.
// Iterates through all users to find a match since UserDAO doesn't have
// a secondary index on email.
func (service *User) GetByEmail(ctx context.Context, email string) (*entities.User, error) {
	service.logger.Debug("searching for user by email", "email", email)

	pageQuery := datastore.NewPageQuery()
	pageQuery.PageSize = 100

	var foundUser *entities.User

	err := service.userDAO.ForEachPage(ctx, pageQuery, func(result datastore.PageResult[*entities.User]) error {
		for _, user := range result.Entities {
			if user.Email == email {
				foundUser = user
				return datastore.ErrStopIteration
			}
		}
		return nil
	})

	if err != nil && err != datastore.ErrStopIteration {
		service.logger.Error(err, "failed to search users by email")
		return nil, err
	}

	if foundUser == nil {
		return nil, ErrUserNotFound{Email: email}
	}

	return foundUser, nil
}

// GetByTenant returns all users belonging to a tenant.
// Iterates through all users and filters by TenantID.
func (service *User) GetByTenant(ctx context.Context, tenantID string) ([]*entities.User, error) {
	service.logger.Debug("listing users by tenant", "tenant_id", tenantID)

	pageQuery := datastore.NewPageQuery()
	pageQuery.PageSize = 100

	var users []*entities.User

	err := service.userDAO.ForEachPage(ctx, pageQuery, func(result datastore.PageResult[*entities.User]) error {
		for _, user := range result.Entities {
			if user.TenantID == tenantID {
				users = append(users, user)
			}
		}
		return nil
	})

	if err != nil {
		service.logger.Error(err, "failed to list users by tenant")
		return nil, err
	}

	return users, nil
}

// IsTenantOwner checks if a user is the owner of their tenant.
func (service *User) IsTenantOwner(ctx context.Context, userID uint64) (bool, error) {
	user, err := service.userDAO.Get(ctx, userID)
	if err != nil {
		return false, err
	}

	return user.IsTenantOwner, nil
}

// ErrUserNotFound is returned when a user cannot be found.
type ErrUserNotFound struct {
	ID    uint64
	Email string
}

func (e ErrUserNotFound) Error() string {
	if e.Email != "" {
		return fmt.Sprintf("user not found: email=%s", e.Email)
	}
	if e.ID != 0 {
		return fmt.Sprintf("user not found: id=%d", e.ID)
	}
	return "user not found"
}
