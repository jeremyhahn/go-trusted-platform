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

package datastore

import (
	"context"
	"errors"

	"github.com/jeremyhahn/go-trusted-platform/pkg/serializer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

var (
	ErrRecordNotFound = errors.New("datastore: record not found")
	ErrStopIteration  = errors.New("datastore: stop iteration")
)

type StoreType string

func (s StoreType) String() string {
	return string(s)
}

// ConsistencyLevel is retained for configuration purposes but removed from
// individual method signatures. Consistency is now configured at the DAO level.
type ConsistencyLevel int

const (
	ConsistencyLevelLocal ConsistencyLevel = iota
	ConsistencyLevelQuorum
)

func (c ConsistencyLevel) String() string {
	if c == ConsistencyLevelQuorum {
		return "quorum"
	}
	return "local"
}

// PagerFunc is a callback function for processing pages of entities.
// The callback receives the full PageResult including pagination metadata.
// Return nil to continue to the next page, or an error to stop iteration.
type PagerFunc[E any] func(result PageResult[E]) error

const (
	QUERY_TYPE_COUNT = iota
)

// Sort order constants for pagination queries.
const (
	SortAscending  = iota // Sort results in ascending order by key
	SortDescending        // Sort results in descending order by key
)

// Legacy constants for backwards compatibility
const (
	SORT_ASCENDING  = SortAscending
	SORT_DESCENDING = SortDescending
)

// PageQuery represents pagination parameters for list operations.
type PageQuery struct {
	// Page is the 1-based page number to retrieve.
	Page int
	// PageSize is the maximum number of entities to return per page.
	PageSize int
	// SortOrder determines the ordering of results (SortAscending or SortDescending).
	SortOrder int
}

// NewPageQuery creates a PageQuery with sensible defaults.
// Defaults: Page=1, PageSize=25, SortOrder=SortAscending
func NewPageQuery() PageQuery {
	return PageQuery{
		Page:      1,
		PageSize:  25,
		SortOrder: SortAscending,
	}
}

// PageResult represents a paginated result set.
type PageResult[E any] struct {
	// Entities contains the entities for this page.
	Entities []E `json:"entities" yaml:"entities"`
	// Page is the current page number (1-based).
	Page int `json:"page" yaml:"page"`
	// PageSize is the maximum entities per page.
	PageSize int `json:"page_size" yaml:"page_size"`
	// Total is the total number of entities across all pages.
	Total int `json:"total" yaml:"total"`
	// HasMore indicates whether additional pages exist.
	HasMore bool `json:"has_more" yaml:"has_more"`
}

// NewPageResult creates an empty PageResult.
func NewPageResult[E any]() PageResult[E] {
	return PageResult[E]{Entities: make([]E, 0)}
}

// NewPageResultFromQuery creates a PageResult initialized from a PageQuery.
func NewPageResultFromQuery[E any](q PageQuery) PageResult[E] {
	return PageResult[E]{
		Entities: make([]E, 0, q.PageSize),
		Page:     q.Page,
		PageSize: q.PageSize,
	}
}

// Entity represents a persistable entity with a unique identifier.
// All entities stored via GenericDAO must implement this interface.
type Entity interface {
	EntityID() uint64
	SetEntityID(id uint64)
}

// Pager provides pagination operations for entity collections.
type Pager[E any] interface {
	// Page retrieves a single page of entities.
	Page(ctx context.Context, query PageQuery) (PageResult[E], error)
	// ForEachPage iterates over all entities page by page.
	// Return nil from callback to continue, ErrStopIteration to stop gracefully.
	ForEachPage(ctx context.Context, query PageQuery, fn PagerFunc[E]) error
}

// GenericDAO provides generic CRUD operations for entities.
// All methods accept a context for cancellation and timeout support.
type GenericDAO[E Entity] interface {
	// Save persists an entity. If EntityID() returns 0, a new ID is generated.
	Save(ctx context.Context, entity E) error
	// Get retrieves an entity by ID. Returns ErrRecordNotFound if not found.
	Get(ctx context.Context, id uint64) (E, error)
	// Delete removes an entity from storage.
	Delete(ctx context.Context, entity E) error
	// Count returns the total number of entities.
	Count(ctx context.Context) (int, error)
	// Pager provides pagination operations.
	Pager[E]
}

// OrganizationDAO provides operations for Organization entities.
type OrganizationDAO interface {
	// GetUsers returns all users belonging to the organization.
	GetUsers(ctx context.Context, id uint64) ([]*entities.User, error)
	GenericDAO[*entities.Organization]
}

// UserDAO provides operations for User entities.
type UserDAO interface {
	GenericDAO[*entities.User]
}

// RegistrationDAO provides operations for Registration entities.
type RegistrationDAO interface {
	GenericDAO[*entities.Registration]
}

// InvitationDAO provides operations for Invitation entities.
type InvitationDAO interface {
	// GetByToken retrieves an invitation by its secure token.
	GetByToken(ctx context.Context, token string) (*entities.Invitation, error)
	// GetByEmail retrieves an invitation by email address.
	GetByEmail(ctx context.Context, email string) (*entities.Invitation, error)
	// GetByTenant retrieves all invitations for a tenant.
	GetByTenant(ctx context.Context, tenantID string) ([]*entities.Invitation, error)
	// GetPendingByTenant retrieves pending invitations for a tenant.
	GetPendingByTenant(ctx context.Context, tenantID string) ([]*entities.Invitation, error)
	GenericDAO[*entities.Invitation]
}

// RoleDAO provides operations for Role entities.
type RoleDAO interface {
	// GetByName retrieves a role by its name.
	GetByName(ctx context.Context, name string) (*entities.Role, error)
	GenericDAO[*entities.Role]
}

// WebAuthnDAO provides operations for WebAuthn credential blobs.
type WebAuthnDAO interface {
	GenericDAO[*entities.Blob]
}

// Factory provides access to all DAO implementations.
type Factory interface {
	OrganizationDAO() (OrganizationDAO, error)
	UserDAO() (UserDAO, error)
	RegistrationDAO() (RegistrationDAO, error)
	InvitationDAO() (InvitationDAO, error)
	RoleDAO() (RoleDAO, error)
	SerializerType() serializer.SerializerType
	WebAuthnDAO() (WebAuthnDAO, error)
}

// LifecycleFactory extends Factory with lifecycle management methods.
// Factories that require initialization before use (like QuicBaaS) should
// implement this interface. Callers should type-assert to check if a Factory
// supports lifecycle management and call Start() before use and Stop() during shutdown.
type LifecycleFactory interface {
	Factory
	// Start initializes the factory and any underlying resources.
	// Must be called before any DAO methods for factories requiring initialization.
	Start(ctx context.Context) error
	// Stop gracefully shuts down the factory and releases resources.
	Stop(ctx context.Context) error
	// IsStarted returns true if the factory has been started.
	IsStarted() bool
}
