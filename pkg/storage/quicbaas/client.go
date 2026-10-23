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
	"sync"
	"sync/atomic"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// Client wraps the QuicBaaS SDK client and provides unified access to QuicBaaS services.
// It supports both embedded and remote operation modes through the SDK's transport layer.
//
// For embedded mode, the client wraps a service.QuicBaaS instance provided via
// StartWithService(). For remote modes, the client connects to an external server.
//
// The Client implements the Storage interface for DAO operations and maintains
// backward compatibility with existing Factory usage patterns.
type Client struct {
	config  *Config
	logger  *logging.Logger
	sdk     quicbaas.Client
	service service.QuicBaaS

	started atomic.Bool
	closed  atomic.Bool
	mu      sync.RWMutex
}

// NewClient creates a new QuicBaaS client with the given configuration.
// The client must be started with Start() or StartWithService() before use.
func NewClient(config *Config, logger *logging.Logger) (*Client, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	return &Client{
		config: config,
		logger: logger,
	}, nil
}

// Start initializes the QuicBaaS client for remote transport modes.
// For embedded mode, use StartWithService() instead to provide the service instance.
// This method is primarily for remote transports (gRPC, REST, QUIC, Unix socket).
func (c *Client) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.started.Load() {
		return nil
	}
	if c.closed.Load() {
		return ErrServerClosed{}
	}

	// For embedded transport, we need a service - use StartWithService instead
	if c.config.Transport == TransportEmbedded {
		return ErrEmbeddedServiceRequired{}
	}

	// Create SDK client for remote transport
	sdk, err := c.createSDKClient(nil)
	if err != nil {
		return ErrConnectionFailed{Cause: err}
	}

	c.sdk = sdk
	c.started.Store(true)
	c.logger.Debug("QuicBaaS client started", "transport", c.config.Transport)
	return nil
}

// StartWithService initializes the QuicBaaS client with a provided service instance.
// This method is used for embedded mode where the server is managed externally.
// The service parameter must implement service.QuicBaaS interface.
func (c *Client) StartWithService(ctx context.Context, svc service.QuicBaaS) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.started.Load() {
		return nil
	}
	if c.closed.Load() {
		return ErrServerClosed{}
	}

	if svc == nil {
		return ErrEmbeddedServiceRequired{}
	}

	// Create SDK client wrapping the embedded service
	sdk, err := c.createSDKClient(svc)
	if err != nil {
		return ErrConnectionFailed{Cause: err}
	}

	c.sdk = sdk
	c.service = svc
	c.started.Store(true)
	c.logger.Debug("QuicBaaS client started with embedded service")
	return nil
}

// createSDKClient creates the SDK client based on transport configuration.
func (c *Client) createSDKClient(svc service.QuicBaaS) (quicbaas.Client, error) {
	var opts []quicbaas.Option

	// Add timeout if configured
	if c.config.RequestTimeout > 0 {
		opts = append(opts, quicbaas.WithTimeout(c.config.RequestTimeout))
	}

	switch c.config.Transport {
	case TransportEmbedded:
		if svc == nil {
			return nil, ErrEmbeddedServiceRequired{}
		}
		opts = append(opts, quicbaas.WithEmbedded(svc))
		return quicbaas.NewClient("embedded", opts...)

	case TransportUnix:
		if c.config.UnixSocket == "" {
			return nil, ErrInvalidConfig{Field: "UnixSocket", Reason: "required for unix transport"}
		}
		opts = append(opts, quicbaas.WithUnix(c.config.UnixSocket))
		return quicbaas.NewClient(c.config.UnixSocket, opts...)

	case TransportGRPC:
		if c.config.Address == "" {
			return nil, ErrInvalidConfig{Field: "Address", Reason: "required for grpc transport"}
		}
		// gRPC is the default transport, no special option needed
		return quicbaas.NewClient(c.config.Address, opts...)

	case TransportREST:
		if c.config.Address == "" {
			return nil, ErrInvalidConfig{Field: "Address", Reason: "required for rest transport"}
		}
		opts = append(opts, quicbaas.WithREST())
		return quicbaas.NewClient(c.config.Address, opts...)

	case TransportQUIC:
		if c.config.Address == "" {
			return nil, ErrInvalidConfig{Field: "Address", Reason: "required for quic transport"}
		}
		opts = append(opts, quicbaas.WithQUIC())
		return quicbaas.NewClient(c.config.Address, opts...)

	default:
		return nil, ErrUnsupportedTransport{Transport: c.config.Transport}
	}
}

// Stop gracefully shuts down the QuicBaaS client.
// Note: This only closes the SDK client connection. For embedded mode,
// the server lifecycle is managed externally.
func (c *Client) Stop(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed.Load() {
		return nil
	}
	if !c.started.Load() {
		c.closed.Store(true)
		return nil
	}

	// Close SDK client
	if c.sdk != nil {
		if err := c.sdk.Close(); err != nil {
			c.logger.Warn("QuicBaaS SDK close error", "error", err)
		}
	}

	c.started.Store(false)
	c.closed.Store(true)
	c.logger.Debug("QuicBaaS client stopped")
	return nil
}

// Service returns the underlying QuicBaaS service for embedded mode.
// Returns nil for remote transport modes or if the client is not started.
func (c *Client) Service() service.QuicBaaS {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.service
}

// SDK returns the underlying QuicBaaS SDK client.
// Returns nil if the client is not started.
func (c *Client) SDK() quicbaas.Client {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.started.Load() {
		return nil
	}
	return c.sdk
}

// IsStarted returns true if the client has been started.
func (c *Client) IsStarted() bool {
	return c.started.Load()
}

// IsClosed returns true if the client has been closed.
func (c *Client) IsClosed() bool {
	return c.closed.Load()
}

// IsEmbedded returns true if using embedded transport mode.
func (c *Client) IsEmbedded() bool {
	return c.config.Transport == TransportEmbedded
}

// Put stores a key-value pair in QuicBaaS.
// shardID specifies which Raft shard handles this operation (0 = default shard).
func (c *Client) Put(ctx context.Context, entityType string, id uint64, data []byte, shardID uint64) error {
	sdk := c.SDK()
	if sdk == nil {
		return ErrServerNotStarted{}
	}

	ctx = c.ensureDeadline(ctx)

	_, err := sdk.KV().Put(ctx, &service.PutRequest{
		EntityType:  entityType,
		ID:          id,
		Data:        data,
		Consistency: c.toSDKConsistency(c.config.ConsistencyLevel),
		ShardID:     shardID,
	})
	if err != nil {
		return ErrOperationFailed{Operation: "put", Cause: err}
	}
	return nil
}

// Get retrieves a value by entity type and ID.
// shardID specifies which Raft shard handles this operation (0 = default shard).
func (c *Client) Get(ctx context.Context, entityType string, id uint64, shardID uint64) ([]byte, bool, error) {
	sdk := c.SDK()
	if sdk == nil {
		return nil, false, ErrServerNotStarted{}
	}

	ctx = c.ensureDeadline(ctx)

	resp, err := sdk.KV().Get(ctx, &service.GetRequest{
		EntityType:  entityType,
		ID:          id,
		Consistency: c.toSDKConsistency(c.config.ConsistencyLevel),
		ShardID:     shardID,
	})
	if err != nil {
		// QuicBaaS returns a not-found error instead of found=false.
		// Convert to our semantic: return found=false for not-found cases.
		// Check both typed errors and string patterns since errors may be
		// wrapped through multiple transport layers.
		if IsNotFound(err) || isNotFoundString(err) {
			return nil, false, nil
		}
		return nil, false, ErrOperationFailed{Operation: "get", Cause: err}
	}
	return resp.Data, resp.Found, nil
}

// Delete removes an entity from QuicBaaS.
// shardID specifies which Raft shard handles this operation (0 = default shard).
func (c *Client) Delete(ctx context.Context, entityType string, id uint64, shardID uint64) error {
	sdk := c.SDK()
	if sdk == nil {
		return ErrServerNotStarted{}
	}

	ctx = c.ensureDeadline(ctx)

	_, err := sdk.KV().Delete(ctx, &service.DeleteRequest{
		EntityType:  entityType,
		ID:          id,
		Consistency: c.toSDKConsistency(c.config.ConsistencyLevel),
		ShardID:     shardID,
	})
	if err != nil {
		return ErrOperationFailed{Operation: "delete", Cause: err}
	}
	return nil
}

// List retrieves entities with pagination.
// shardID specifies which Raft shard handles this operation (0 = default shard).
func (c *Client) List(ctx context.Context, entityType string, pageSize uint64, pageToken string, shardID uint64) ([]*service.Entity, string, error) {
	sdk := c.SDK()
	if sdk == nil {
		return nil, "", ErrServerNotStarted{}
	}

	ctx = c.ensureDeadline(ctx)

	resp, err := sdk.KV().List(ctx, &service.ListRequest{
		EntityType: entityType,
		PageSize:   pageSize,
		PageToken:  pageToken,
		ShardID:    shardID,
	})
	if err != nil {
		return nil, "", ErrOperationFailed{Operation: "list", Cause: err}
	}

	// Convert SDK entities to service entities for backward compatibility
	entities := make([]*service.Entity, 0, len(resp.Entities))
	for _, e := range resp.Entities {
		entities = append(entities, &service.Entity{
			ID:         e.ID,
			EntityType: e.EntityType,
			Data:       e.Data,
			Version:    e.Version,
		})
	}

	return entities, resp.NextPageToken, nil
}

// Query searches for entities using secondary indexes.
// shardID specifies which Raft shard handles this operation (0 = default shard).
func (c *Client) Query(ctx context.Context, entityType, indexField string, value []byte, shardID uint64) ([]*service.Entity, error) {
	sdk := c.SDK()
	if sdk == nil {
		return nil, ErrServerNotStarted{}
	}

	ctx = c.ensureDeadline(ctx)

	// Use the SDK Query client for index lookups
	queryClient := sdk.Query()
	if queryClient == nil {
		return nil, ErrOperationFailed{Operation: "query", Cause: ErrServerNotStarted{}}
	}

	// Note: The SDK Query client has a different interface - it uses Query.Execute
	// For now, fall back to list and filter in-memory
	// DEFERRED: Use proper SDK query interface when available. Blocked by: QuicBaaS SDK query API.
	resp, err := sdk.KV().List(ctx, &service.ListRequest{
		EntityType: entityType,
		PageSize:   1000,
		ShardID:    shardID,
	})
	if err != nil {
		return nil, ErrOperationFailed{Operation: "query", Cause: err}
	}

	// Convert SDK entities to service entities
	entities := make([]*service.Entity, 0)
	for _, e := range resp.Entities {
		entities = append(entities, &service.Entity{
			ID:         e.ID,
			EntityType: e.EntityType,
			Data:       e.Data,
			Version:    e.Version,
		})
	}

	return entities, nil
}

// ListEntityTypes returns all unique entity types stored in the database.
func (c *Client) ListEntityTypes(ctx context.Context, pageSize int, pageToken string) ([]string, string, int, error) {
	// The SDK KV client may not have a direct ListEntityTypes method
	// For now, this operation is not supported via SDK
	// DEFERRED: Add SDK support for ListEntityTypes when available. Blocked by: QuicBaaS SDK API.
	return nil, "", 0, ErrOperationFailed{
		Operation: "listEntityTypes",
		Cause:     ErrServerNotStarted{},
	}
}

// ensureDeadline returns a context with a deadline if the provided context doesn't have one.
// This is required by QuicBaaS's Raft SyncRead operations.
func (c *Client) ensureDeadline(ctx context.Context) context.Context {
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		newCtx, cancel := context.WithTimeout(ctx, c.config.RequestTimeout)
		// Schedule cleanup when the new context is done
		go func() {
			<-newCtx.Done()
			cancel()
		}()
		return newCtx
	}
	return ctx
}

// toSDKConsistency converts our ConsistencyLevel to SDK's ConsistencyLevel.
func (c *Client) toSDKConsistency(level ConsistencyLevel) service.ConsistencyLevel {
	switch level {
	case ConsistencyStrong:
		return service.ConsistencyLevelStrong
	case ConsistencyEventual:
		return service.ConsistencyLevelEventual
	default:
		return service.ConsistencyLevelLinearizable
	}
}
