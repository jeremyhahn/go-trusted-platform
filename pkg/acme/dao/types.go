package dao

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/acme/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/serializer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

type ACMEAccountDAO interface {
	datastore.GenericDAO[*entities.ACMEAccount]
}

type ACMEAuthorizationDAO interface {
	datastore.GenericDAO[*entities.ACMEAuthorization]
}

type ACMECertificateDAO interface {
	datastore.GenericDAO[*entities.ACMECertificate]
}

type ACMEChallengeDAO interface {
	datastore.GenericDAO[*entities.ACMEChallenge]
}

type ACMEOrderDAO interface {
	GetByAccountID(
		CONSISTENCY_LEVEL datastore.ConsistencyLevel) (datastore.PageResult[*entities.ACMEOrder], error)
	datastore.GenericDAO[*entities.ACMEOrder]
}

type ACMEIdentifierDAO interface {
	datastore.GenericDAO[*entities.ACMEIdentifier]
}

type ACMENonceDAO interface {
	datastore.GenericDAO[*entities.ACMENonce]
}

type Factory interface {
	ACMEAccountDAO() (ACMEAccountDAO, error)
	ACMEAuthorizationDAO(accountID uint64) (ACMEAuthorizationDAO, error)
	ACMECertificateDAO() (ACMECertificateDAO, error)
	ACMEChallengeDAO(accountID uint64) (ACMEChallengeDAO, error)
	ACMEOrderDAO(accountID uint64) (ACMEOrderDAO, error)
	ACMENonceDAO() (ACMENonceDAO, error)
	SerializerType() serializer.SerializerType
	ConsistencyLevel() datastore.ConsistencyLevel
}
