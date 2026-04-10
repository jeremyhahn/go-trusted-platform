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
	ErrRegistrationNotFound = errors.New("registration not found")
)

type RegistrationServicer interface {
	Create(ctx context.Context, registration *entities.Registration) error
	Delete(ctx context.Context, session Session, registrationID uint64) error
	Get(ctx context.Context, session Session, registrationID uint64) (*entities.Registration, error)
}

type Registration struct {
	logger          *logging.Logger
	registrationDAO datastore.RegistrationDAO
	RegistrationServicer
}

func NewRegistrationService(
	logger *logging.Logger,
	registrationDAO datastore.RegistrationDAO) RegistrationServicer {

	return &Registration{
		logger:          logger,
		registrationDAO: registrationDAO}
}

// Deletes an existing registration account
func (service *Registration) Delete(ctx context.Context, session Session, registrationID uint64) error {
	return service.registrationDAO.Delete(ctx,
		&entities.Registration{
			ID: registrationID,
		})
}

// Looks up the registration account by registration ID
func (service *Registration) Get(ctx context.Context, session Session, registrationID uint64) (*entities.Registration, error) {
	entity, err := service.registrationDAO.Get(ctx, registrationID)
	if err != nil {
		return nil, err
	}
	return entity, nil
}

// CreateRegistration creates a new registration account
func (service *Registration) Create(ctx context.Context, registration *entities.Registration) error {
	return service.registrationDAO.Save(ctx, registration)
}
