// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package daemon

import (
	"context"
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/pkg/proxy"
)

// ProxyPersistence is the durable half of the ProxyStore (#570, ruling R4):
// the in-memory working set stays the validation owner and the source every
// transport reads, and every accepted mutation is written through here
// before it takes effect. Load is called once at construction; the backend
// is expected to return the complete set.
type ProxyPersistence interface {
	// Load returns every persisted route and pool.
	Load(ctx context.Context) (routes []proxy.RouteConfig, pools []proxy.BackendPoolConfig, err error)
	// SaveRoute creates or replaces the route with route.ID.
	SaveRoute(ctx context.Context, route proxy.RouteConfig) error
	// DeleteRoute removes the route with id; a missing route is not an error.
	DeleteRoute(ctx context.Context, id string) error
	// SavePool creates or replaces the pool with pool.ID.
	SavePool(ctx context.Context, pool proxy.BackendPoolConfig) error
	// DeletePool removes the pool with id; a missing pool is not an error.
	DeletePool(ctx context.Context, id string) error
}

// ErrProxyPersistenceRequired is returned when a persistent store is asked
// for with no backend.
type ErrProxyPersistenceRequired struct{}

// Error implements the error interface.
func (e ErrProxyPersistenceRequired) Error() string {
	return "proxy store: a persistence backend is required"
}

// ErrProxyStoreLoad is returned when the persisted set cannot be loaded or
// would not validate as a whole.
type ErrProxyStoreLoad struct {
	Cause error
}

// Error implements the error interface.
func (e ErrProxyStoreLoad) Error() string {
	return fmt.Sprintf("proxy store: loading the persisted routes and pools failed: %v", e.Cause)
}

// Unwrap returns the cause.
func (e ErrProxyStoreLoad) Unwrap() error { return e.Cause }

// ErrProxyPersist is returned when a validated mutation could not be
// written through; the in-memory set is left unchanged.
type ErrProxyPersist struct {
	Kind  string
	ID    string
	Cause error
}

// Error implements the error interface.
func (e ErrProxyPersist) Error() string {
	return fmt.Sprintf("proxy store: persisting %s %q failed: %v", e.Kind, e.ID, e.Cause)
}

// Unwrap returns the cause.
func (e ErrProxyPersist) Unwrap() error { return e.Cause }

// ErrProxySeed is returned when a `proxy:` section entry cannot be seeded.
type ErrProxySeed struct {
	Kind  string
	ID    string
	Cause error
}

// Error implements the error interface.
func (e ErrProxySeed) Error() string {
	return fmt.Sprintf("proxy store: seeding %s %q from the proxy: section failed: %v", e.Kind, e.ID, e.Cause)
}

// Unwrap returns the cause.
func (e ErrProxySeed) Unwrap() error { return e.Cause }
