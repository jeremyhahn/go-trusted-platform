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
	Create(ctx context.Context, organization *entities.Organization) error
	Page(ctx context.Context, session Session, pageQuery datastore.PageQuery) (datastore.PageResult[*entities.Organization], error)
	GetUsers(ctx context.Context, session Session) ([]*entities.User, error)
	Delete(ctx context.Context, session Session) error
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
func (service *Organization) Create(ctx context.Context, organization *entities.Organization) error {
	organization.SetEntityID(util.NewID([]byte(organization.Name)))
	return service.orgDAO.Save(ctx, organization)
}

// Returns a single page of organization entities
func (service *Organization) Page(ctx context.Context, session Session,
	pageQuery datastore.PageQuery) (datastore.PageResult[*entities.Organization], error) {

	if !session.User().HasRole(common.ROLE_ADMIN) {
		return datastore.PageResult[*entities.Organization]{}, ErrPermissionDenied
	}
	return service.orgDAO.Page(ctx, pageQuery)
}

// Returns a list of User entities that belong to the organization
func (service *Organization) GetUsers(ctx context.Context, session Session) ([]*entities.User, error) {
	if !session.User().HasRole(common.ROLE_ADMIN) {
		return nil, ErrPermissionDenied
	}
	users, err := service.orgDAO.GetUsers(ctx, session.RequestedOrganizationID())
	if err != nil {
		service.logger.Error(err)
		return nil, err
	}
	return users, nil
}

// Deletes an existing organization and all associated entites from the database
func (service *Organization) Delete(ctx context.Context, session Session) error {
	if !session.User().HasRole(common.ROLE_ADMIN) {
		return ErrPermissionDenied
	}
	return service.orgDAO.Delete(ctx,
		&entities.Organization{
			ID: session.RequestedOrganizationID()})
}
