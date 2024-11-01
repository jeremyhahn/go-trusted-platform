package datastore

import (
	"errors"

	"github.com/jeremyhahn/go-trusted-platform/pkg/serializer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

type ConsistencyLevel int

const (
	CONSISTENCY_LOCAL ConsistencyLevel = iota
	CONSISTENCY_QUORUM
)

func (c ConsistencyLevel) String() string {
	if c == CONSISTENCY_QUORUM {
		return "quorum"
	}
	return "local"
}

var (
	ErrRecordNotFound     = errors.New("datastore: record not found")
	ErrInvalidIndexEntity = errors.New("datastore: invalid index entity")
)

type PagerProcFunc[E any] func(entities []E) error

const (
	QUERY_TYPE_COUNT = iota
)

const (
	SORT_ASCENDING = iota
	SORT_DESCENDING
)

// PageQuery represents a datastore query for a single
// page of records
type PageQuery struct {
	Page      int
	PageSize  int
	SortOrder int
}

func NewPageQuery() PageQuery {
	return PageQuery{
		Page:     1,
		PageSize: 25}
}

// PageResult represents a datastore page query resultset
type PageResult[E any] struct {
	Entities []E  `yaml:"entities" json:"entities"`
	Page     int  `yaml:"page" json:"page"`
	PageSize int  `yaml:"size" json:"size"`
	HasMore  bool `yaml:"has_more" json:"has_more"`
}

func NewPageResult[E any]() PageResult[E] {
	return PageResult[E]{Entities: make([]E, 0)}
}

func NewPageResultFromQuery[E any](q PageQuery) PageResult[E] {
	return PageResult[E]{
		Entities: make([]E, q.PageSize),
		Page:     q.Page,
		PageSize: q.PageSize}
}

// DAO interfaces
type Pager[E any] interface {
	Page(pageQuery PageQuery, CONSISTENCY_LEVEL ConsistencyLevel) (PageResult[E], error)
	ForEachPage(pageQuery PageQuery, pagerProcFunc PagerProcFunc[E], CONSISTENCY_LEVEL ConsistencyLevel) error
}
type GenericDAO[E any] interface {
	Save(entity E) error
	Get(id uint64, CONSISTENCY_LEVEL ConsistencyLevel) (E, error)
	Delete(entity E) error
	Count(CONSISTENCY_LEVEL ConsistencyLevel) (int, error)
	Pager[E]
}

type OrganizationDAO interface {
	GetUsers(id uint64, CONSISTENCY_LEVEL ConsistencyLevel) ([]*entities.User, error)
	GenericDAO[*entities.Organization]
}

type UserDAO interface {
	GenericDAO[*entities.User]
}

type RegistrationDAO interface {
	GenericDAO[*entities.Registration]
}

type RoleDAO interface {
	GetByName(name string, CONSISTENCY_LEVEL ConsistencyLevel) (*entities.Role, error)
	GenericDAO[*entities.Role]
}

type WebAuthnDAO interface {
	GenericDAO[*entities.Blob]
}

// ACME DAOs
type ACMEAccountDAO interface {
	GenericDAO[*entities.ACMEAccount]
}

type ACMEAuthorizationDAO interface {
	// GetAuthorizationByURL(url string, CONSISTENCY_LEVEL int) (*entities.ACMEAuthorization, error)
	GenericDAO[*entities.ACMEAuthorization]
}

type ACMECertificateDAO interface {
	GenericDAO[*entities.ACMECertificate]
}

type ACMEChallengeDAO interface {
	GenericDAO[*entities.ACMEChallenge]
}

type ACMEOrderDAO interface {
	GetByAccountID(accountID uint64, CONSISTENCY_LEVEL ConsistencyLevel) (PageResult[*entities.ACMEOrder], error)
	GenericDAO[*entities.ACMEOrder]
}

type ACMEIdentifierDAO interface {
	GenericDAO[*entities.ACMEIdentifier]
}

type ACMENonceDAO interface {
	GenericDAO[*entities.ACMENonce]
}

// DAO Factory interface
type Factory interface {
	ACMEAccountDAO() (ACMEAccountDAO, error)
	ACMEAuthorizationDAO(accountID uint64) (ACMEAuthorizationDAO, error)
	ACMECertificateDAO() (ACMECertificateDAO, error)
	ACMEChallengeDAO(accountID uint64) (ACMEChallengeDAO, error)
	ACMEOrderDAO(accountID uint64) (ACMEOrderDAO, error)
	ACMENonceDAO() (ACMENonceDAO, error)
	OrganizationDAO() (OrganizationDAO, error)
	UserDAO() (UserDAO, error)
	RegistrationDAO() (RegistrationDAO, error)
	RoleDAO() (RoleDAO, error)
	SerializerType() serializer.SerializerType
	WebAuthnDAO() (WebAuthnDAO, error)
}
