package service

import (
	"errors"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

var (
	ErrWebAuthnNotFound = errors.New("service/webauthn: webauthn session data not found")
)

type WebAuthnSessionServicer interface {
	Delete(session Session, sessionData *entities.Blob) error
	Get(session Session, id uint64) (*entities.Blob, error)
	Page(session Session, pageQuery datastore.PageQuery) (datastore.PageResult[*entities.Blob], error)
	Save(sessionData *entities.Blob) error
}

type WebAuthnSessionService struct {
	logger      *logging.Logger
	webAuthnDAO datastore.WebAuthnDAO
	WebAuthnSessionServicer
}

func NewWebAuthnSessionService(
	logger *logging.Logger,
	webAuthnDAO datastore.WebAuthnDAO) WebAuthnSessionServicer {

	return &WebAuthnSessionService{
		logger:      logger,
		webAuthnDAO: webAuthnDAO}
}

func (service *WebAuthnSessionService) Delete(session Session, sessionData *entities.Blob) error {
	return service.webAuthnDAO.Delete(sessionData)
}

// Retrieves webauthn session data by it's session id
func (service *WebAuthnSessionService) Get(session Session, id uint64) (*entities.Blob, error) {
	return service.webAuthnDAO.Get(id, session.ConsistencyLevel())
}

// Returns a single page of webauthn session data blobs from the database
func (service *WebAuthnSessionService) Page(
	session Session, pageQuery datastore.PageQuery) (datastore.PageResult[*entities.Blob], error) {

	return service.webAuthnDAO.Page(pageQuery, session.ConsistencyLevel())
}

// Saves the provided webauthn session data to the data store
func (service *WebAuthnSessionService) Save(sessionData *entities.Blob) error {
	return service.webAuthnDAO.Save(sessionData)
}
