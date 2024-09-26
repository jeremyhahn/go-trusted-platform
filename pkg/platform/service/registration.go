package service

import (
	"errors"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

var (
	ErrRegistrationNotFound = errors.New("registration not found")
)

type RegistrationServicer interface {
	Create(registration *entities.Registration) error
	Delete(session Session, registrationID uint64) error
	Get(session Session, registrationID uint64) (*entities.Registration, error)
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
func (service *Registration) Delete(session Session, registrationID uint64) error {
	return service.registrationDAO.Delete(
		&entities.Registration{
			ID: registrationID,
		})
}

// Looks up the registration account by registration ID
func (service *Registration) Get(session Session, registrationID uint64) (*entities.Registration, error) {
	entity, err := service.registrationDAO.Get(registrationID, datastore.CONSISTENCY_LOCAL)
	if err != nil {
		return nil, err
	}
	return entity, nil
}

// CreateRegistration creates a new registration account
func (service *Registration) Create(registration *entities.Registration) error {
	return service.registrationDAO.Save(registration)
}
