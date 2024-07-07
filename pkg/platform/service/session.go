package service

import (
	"fmt"

	logging "github.com/op/go-logging"
)

type Session interface {
	GetLogger() *logging.Logger
	SetLogger(*logging.Logger)
	GetRequestedServiceID() uint64
	Close()
}

type DefaultSession struct {
	logger             *logging.Logger
	requestedServiceID uint64
	serviceClaims      []ServiceClaim
	Session
}

func CreateSession(
	logger *logging.Logger,
	serviceClaims []ServiceClaim,
	requestedServiceID uint64) Session {

	return &DefaultSession{
		logger:             logger,
		requestedServiceID: requestedServiceID,
		serviceClaims:      serviceClaims}
}

func CreateSystemSession(logger *logging.Logger) Session {

	return &DefaultSession{
		logger: logger}
}

func (session *DefaultSession) GetLogger() *logging.Logger {
	return session.logger
}

func (session *DefaultSession) SetLogger(logger *logging.Logger) {
	session.logger = logger
}

func (session *DefaultSession) GetRequestedServiceID() uint64 {
	return session.requestedServiceID
}

func (session *DefaultSession) IsMemberOfOrganization(organizationID uint64) bool {
	for _, orgClaim := range session.serviceClaims {
		if orgClaim.ID == organizationID {
			return true
		}
	}
	return false
}

func (session *DefaultSession) Close() {
	if session.logger != nil {
		session.GetLogger().Debugf("[common.Context] Closing session")
	}
}

func (session *DefaultSession) String() string {
	return fmt.Sprintf("user=%s, serviceID=%d",
		"", session.requestedServiceID)
}

func (session *DefaultSession) Error(err error) {
	session.logger.Error("session: %+v, error: %s", session, err)
}
