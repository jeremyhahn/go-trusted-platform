package service

import (
	"fmt"

	logging "github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

type Session interface {
	Close()
	Logger() *logging.Logger
	RequestedOrganizationID() uint64
	RequestedServiceID() uint64
	SetLogger(*logging.Logger)
	User() *entities.User
}

type ServiceSession struct {
	logger             *logging.Logger
	orgClaims          []uint64
	requestedOrgID     uint64
	requestedServiceID uint64
	serviceClaims      []uint64
	user               *entities.User
	Session
}

func CreateSession(
	logger *logging.Logger,
	orgClaims []uint64,
	requestedOrgID uint64,
	requestedServiceID uint64,
	serviceClaims []uint64,
	user *entities.User) Session {

	return &ServiceSession{
		logger:             logger,
		orgClaims:          orgClaims,
		requestedOrgID:     requestedOrgID,
		requestedServiceID: requestedServiceID,
		serviceClaims:      serviceClaims,
		user:               user}
}

func (session *ServiceSession) Logger() *logging.Logger {
	return session.logger
}

func (session *ServiceSession) RequestedOrganizationID() uint64 {
	return session.requestedOrgID
}

func (session *ServiceSession) RequestedServiceID() uint64 {
	return session.requestedServiceID
}

func (session *ServiceSession) IsMemberOfOrganization(organizationID uint64) bool {
	for _, orgClaim := range session.orgClaims {
		if orgClaim == organizationID {
			return true
		}
	}
	return false
}

func (session *ServiceSession) User() *entities.User {
	return session.user
}

func (session *ServiceSession) Close() {
	if session.logger != nil {
		session.logger.Debugf("service/session: closing session")
	}
}

func (session *ServiceSession) String() string {
	return fmt.Sprintf("user=%s, serviceID=%d",
		"", session.requestedServiceID)
}

func (session *ServiceSession) Error(err error) {
	session.logger.Error(fmt.Errorf("session: %+v, error: %s", session, err))
}
