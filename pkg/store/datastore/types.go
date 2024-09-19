package datastore

import "github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"

const (
	CONSISTENCY_LOCAL int = iota
	CONSISTENCY_QUORUM
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
	Page(pageQuery PageQuery, CONSISTENCY_LEVEL int) (PageResult[E], error)
	ForEachPage(pageQuery PageQuery, pagerProcFunc PagerProcFunc[E], CONSISTENCY_LEVEL int) error
}

type GenericDAO[E any] interface {
	Save(entity E) error
	Get(id uint64, CONSISTENCY_LEVEL int) (E, error)
	Delete(entity E) error
	Count(CONSISTENCY_LEVEL int) (int, error)
	Pager[E]
}

type OrganizationDAO interface {
	GetUsers(id uint64) ([]*entities.User, error)
	GenericDAO[*entities.Organization]
}

type UserDAO interface {
	GenericDAO[*entities.User]
}

type RoleDAO interface {
	GetByName(name string, CONSISTENCY_LEVEL int) (*entities.Role, error)
	GenericDAO[*entities.Role]
}
