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

package quicbaas

import (
	"context"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

// ClientInterface defines the interface for QuicBaaS client operations.
// This interface allows for mocking in unit tests while the concrete
// Client type provides the actual QuicBaaS implementation.
type ClientInterface interface {
	// Lifecycle management
	Start(ctx context.Context) error
	StartWithService(ctx context.Context, svc service.QuicBaaS) error
	Stop(ctx context.Context) error
	IsStarted() bool
	IsClosed() bool
	IsEmbedded() bool

	// Storage operations
	// shardID specifies which Raft shard handles this operation (0 = default shard).
	Put(ctx context.Context, entityType string, id uint64, data []byte, shardID uint64) error
	Get(ctx context.Context, entityType string, id uint64, shardID uint64) ([]byte, bool, error)
	Delete(ctx context.Context, entityType string, id uint64, shardID uint64) error
	List(ctx context.Context, entityType string, pageSize uint64, pageToken string, shardID uint64) ([]*service.Entity, string, error)
	Query(ctx context.Context, entityType, indexField string, value []byte, shardID uint64) ([]*service.Entity, error)

	// Entity type discovery
	ListEntityTypes(ctx context.Context, pageSize int, pageToken string) ([]string, string, int, error)

	// Service access for authentication and authorization
	Service() service.QuicBaaS
}

// ServiceInterface defines the authentication-related operations from QuicBaaS service.
// This interface is used for token validation in MCP authorization.
type ServiceInterface interface {
	// ValidateToken validates an access token and returns user information.
	ValidateToken(ctx context.Context, req *ValidateTokenRequest) (*ValidateTokenResponse, error)
}

// ValidateTokenRequest contains the token to validate.
type ValidateTokenRequest struct {
	AccessToken string
}

// ValidateTokenResponse contains the validation result from QuicBaaS.
type ValidateTokenResponse struct {
	Valid     bool
	UserID    string
	Username  string
	Roles     []string
	ExpiresAt int64
}

// FactoryInterface defines the interface for QuicBaaS factory operations.
// This interface allows the daemon package to work with mock factories
// in unit tests without type-asserting to concrete types.
type FactoryInterface interface {
	datastore.LifecycleFactory

	// QuicBaaSClient returns the underlying QuicBaaS client interface.
	// Use this method when you need the interface for mocking.
	QuicBaaSClient() ClientInterface

	// DataDir returns the database directory path
	DataDir() string
}

// Verify that Client implements ClientInterface at compile time
var _ ClientInterface = (*Client)(nil)

// Verify that Factory implements FactoryInterface at compile time
var _ FactoryInterface = (*Factory)(nil)
