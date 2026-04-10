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

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

var (
	ErrRoleNotFound = errors.New("role not found")
)

type RoleServicer interface {
	GetPage(ctx context.Context, pageQuery datastore.PageQuery) (datastore.PageResult[*entities.Role], error)
	GetByName(ctx context.Context, name string) (*entities.Role, error)
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
func (service *RoleService) GetPage(ctx context.Context, pageQuery datastore.PageQuery) (datastore.PageResult[*entities.Role], error) {
	return service.roleDAO.Page(ctx, pageQuery)
}

// Returns the role with the given name
func (service *RoleService) GetByName(ctx context.Context, name string) (*entities.Role, error) {
	return service.roleDAO.GetByName(ctx, name)
}
