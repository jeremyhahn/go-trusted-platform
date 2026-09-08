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

package daemon

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/proxy"
)

// =============================================================================
// ProxyStore error types
// =============================================================================

// ErrRouteNotFound indicates the requested proxy route does not exist.
type ErrRouteNotFound struct {
	ID string
}

// Error returns the error message.
func (e ErrRouteNotFound) Error() string {
	return fmt.Sprintf("proxy store: route not found: %s", e.ID)
}

// ErrRouteExists indicates a proxy route with the same ID already exists.
type ErrRouteExists struct {
	ID string
}

// Error returns the error message.
func (e ErrRouteExists) Error() string {
	return fmt.Sprintf("proxy store: route already exists: %s", e.ID)
}

// ErrPoolNotFound indicates the requested backend pool does not exist.
type ErrPoolNotFound struct {
	ID string
}

// Error returns the error message.
func (e ErrPoolNotFound) Error() string {
	return fmt.Sprintf("proxy store: pool not found: %s", e.ID)
}

// ErrPoolExists indicates a backend pool with the same ID already exists.
type ErrPoolExists struct {
	ID string
}

// Error returns the error message.
func (e ErrPoolExists) Error() string {
	return fmt.Sprintf("proxy store: pool already exists: %s", e.ID)
}

// ErrPoolInUse indicates a backend pool cannot be deleted because one or
// more routes reference it.
type ErrPoolInUse struct {
	ID     string
	Routes []string
}

// Error returns the error message.
func (e ErrPoolInUse) Error() string {
	return fmt.Sprintf("proxy store: pool %s in use by routes %v", e.ID, e.Routes)
}

// =============================================================================
// ProxyStore
// =============================================================================

// ProxyStoreStatus is a snapshot of the store's bookkeeping state.
type ProxyStoreStatus struct {
	// Version is the monotonically increasing configuration version.
	Version uint64
	// RouteCount is the number of stored routes.
	RouteCount int
	// PoolCount is the number of stored backend pools.
	PoolCount int
	// UpdatedAt is the time of the last mutation or reload.
	UpdatedAt time.Time
}

// ProxyStore is the platformd-side source of truth for reverse-proxy routes
// and backend pools that gatewayd instances sync. It follows the runtime
// zone-service store pattern: an in-process, mutex-guarded map seeded empty
// (or from config by the daemon wiring) with every mutation re-validated
// through pkg/proxy Config.Validate — the single source of truth for
// configuration rules.
//
// The version counter increases monotonically on every successful mutation
// and on Reload so pollers can detect changes with a single comparison.
type ProxyStore struct {
	mu        sync.RWMutex
	routes    map[string]proxy.RouteConfig
	pools     map[string]proxy.BackendPoolConfig
	version   uint64
	updatedAt time.Time
	// persist, when set, is written through on every successful mutation
	// before the in-memory working set changes, so a restart reloads what
	// the API last accepted (#570). Nil is the in-memory test double.
	persist ProxyPersistence
}

// NewProxyStore creates an empty, in-memory ProxyStore at version 0. It is
// the test double and the fallback when the daemon has no DAO factory.
func NewProxyStore() *ProxyStore {
	return &ProxyStore{
		routes: make(map[string]proxy.RouteConfig),
		pools:  make(map[string]proxy.BackendPoolConfig),
	}
}

// NewPersistentProxyStore creates a ProxyStore whose working set is loaded
// from persist and written through to it. The loaded set is validated as a
// whole; a set the engine would refuse is a startup error, never a store
// that serves half of it. A non-empty load starts at version 1 so pollers
// that remember version 0 re-sync after a restart.
func NewPersistentProxyStore(ctx context.Context, persist ProxyPersistence) (*ProxyStore, error) {
	if persist == nil {
		return nil, ErrProxyPersistenceRequired{}
	}
	routes, pools, err := persist.Load(ctx)
	if err != nil {
		return nil, ErrProxyStoreLoad{Cause: err}
	}
	if err := validateCandidate(routes, pools); err != nil {
		return nil, ErrProxyStoreLoad{Cause: err}
	}
	s := NewProxyStore()
	s.persist = persist
	for _, r := range routes {
		s.routes[r.ID] = cloneRoute(r)
	}
	for _, p := range pools {
		s.pools[p.ID] = clonePool(p)
	}
	if len(routes)+len(pools) > 0 {
		s.bumpLocked()
	}
	return s, nil
}

// SeedFromConfig applies the platformd `proxy:` section as the base layer:
// a pool or route whose ID the store already holds is kept as stored (the
// API-authored record wins), an absent one is created and persisted. Pools
// go first so routes can reference them. It returns how many entries were
// added. A section the engine would refuse is rejected whole.
func (s *ProxyStore) SeedFromConfig(ctx context.Context, cfg *proxy.ControlPlaneConfig) (int, error) {
	if cfg == nil {
		return 0, nil
	}
	if err := cfg.Validate(); err != nil {
		return 0, err
	}
	added := 0
	for _, pool := range cfg.Pools {
		if s.hasPool(pool.ID) {
			continue
		}
		if _, _, err := s.CreatePool(ctx, pool); err != nil {
			return added, ErrProxySeed{Kind: "pool", ID: pool.ID, Cause: err}
		}
		added++
	}
	for _, route := range cfg.Routes {
		if s.hasRoute(route.ID) {
			continue
		}
		if _, _, err := s.CreateRoute(ctx, route); err != nil {
			return added, ErrProxySeed{Kind: "route", ID: route.ID, Cause: err}
		}
		added++
	}
	return added, nil
}

// validationListener is a synthetic listener injected into candidate configs
// so pkg/proxy Config.Validate — which requires at least one listener — can
// validate route/pool state. Listeners are a gatewayd-local concern; the
// platform store only owns routes and pools.
var validationListener = proxy.ListenerConfig{
	ID:      "store-validation",
	Address: "127.0.0.1:0",
}

// validateCandidate assembles the would-be configuration and delegates to
// pkg/proxy Config.Validate. Validate normalizes route Hosts to lowercase in
// place, so callers should store the candidate copies after validation.
func validateCandidate(routes []proxy.RouteConfig, pools []proxy.BackendPoolConfig) error {
	cfg := proxy.Config{
		Listeners: []proxy.ListenerConfig{validationListener},
		Routes:    routes,
		Pools:     pools,
	}
	return cfg.Validate()
}

// cloneRoute deep-copies a route so stored state never aliases caller slices.
func cloneRoute(r proxy.RouteConfig) proxy.RouteConfig {
	out := r
	out.Hosts = append([]string(nil), r.Hosts...)
	out.Auth.AllowedZones = append([]string(nil), r.Auth.AllowedZones...)
	out.Auth.RequiredRoles = append([]string(nil), r.Auth.RequiredRoles...)
	out.Auth.RequiredScopes = append([]string(nil), r.Auth.RequiredScopes...)
	return out
}

// clonePool deep-copies a pool so stored state never aliases caller slices.
func clonePool(p proxy.BackendPoolConfig) proxy.BackendPoolConfig {
	out := p
	out.Backends = append([]proxy.BackendConfig(nil), p.Backends...)
	return out
}

// routesSliceLocked returns all routes sorted by ID. Callers must hold mu.
func (s *ProxyStore) routesSliceLocked() []proxy.RouteConfig {
	out := make([]proxy.RouteConfig, 0, len(s.routes))
	for _, r := range s.routes {
		out = append(out, cloneRoute(r))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// poolsSliceLocked returns all pools sorted by ID. Callers must hold mu.
func (s *ProxyStore) poolsSliceLocked() []proxy.BackendPoolConfig {
	out := make([]proxy.BackendPoolConfig, 0, len(s.pools))
	for _, p := range s.pools {
		out = append(out, clonePool(p))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// bumpLocked advances the version counter and update time. Callers must
// hold mu.
func (s *ProxyStore) bumpLocked() uint64 {
	s.version++
	s.updatedAt = time.Now().UTC()
	return s.version
}

// =============================================================================
// Route CRUD
// =============================================================================

// CreateRoute stores a new route after validating the resulting
// configuration. Returns the stored (host-normalized) route and the new
// config version.
func (s *ProxyStore) CreateRoute(ctx context.Context, route proxy.RouteConfig) (proxy.RouteConfig, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.routes[route.ID]; exists {
		return proxy.RouteConfig{}, 0, ErrRouteExists{ID: route.ID}
	}

	candidate := cloneRoute(route)
	candidateRoutes := append(s.routesSliceLocked(), candidate)
	if err := validateCandidate(candidateRoutes, s.poolsSliceLocked()); err != nil {
		return proxy.RouteConfig{}, 0, err
	}
	// Validate normalized Hosts in place on the last candidate element.
	stored := candidateRoutes[len(candidateRoutes)-1]
	if err := s.persistRoute(ctx, stored); err != nil {
		return proxy.RouteConfig{}, 0, err
	}
	s.routes[stored.ID] = stored
	return cloneRoute(stored), s.bumpLocked(), nil
}

// Route returns the route with the given ID.
func (s *ProxyStore) Route(ctx context.Context, id string) (proxy.RouteConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	route, ok := s.routes[id]
	if !ok {
		return proxy.RouteConfig{}, ErrRouteNotFound{ID: id}
	}
	return cloneRoute(route), nil
}

// UpdateRoute replaces an existing route after validating the resulting
// configuration. Returns the stored route and the new config version.
func (s *ProxyStore) UpdateRoute(ctx context.Context, route proxy.RouteConfig) (proxy.RouteConfig, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.routes[route.ID]; !exists {
		return proxy.RouteConfig{}, 0, ErrRouteNotFound{ID: route.ID}
	}

	candidate := cloneRoute(route)
	candidateRoutes := make([]proxy.RouteConfig, 0, len(s.routes))
	for _, r := range s.routes {
		if r.ID == route.ID {
			continue
		}
		candidateRoutes = append(candidateRoutes, cloneRoute(r))
	}
	candidateRoutes = append(candidateRoutes, candidate)
	if err := validateCandidate(candidateRoutes, s.poolsSliceLocked()); err != nil {
		return proxy.RouteConfig{}, 0, err
	}
	stored := candidateRoutes[len(candidateRoutes)-1]
	if err := s.persistRoute(ctx, stored); err != nil {
		return proxy.RouteConfig{}, 0, err
	}
	s.routes[stored.ID] = stored
	return cloneRoute(stored), s.bumpLocked(), nil
}

// DeleteRoute removes a route and returns the new config version.
func (s *ProxyStore) DeleteRoute(ctx context.Context, id string) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.routes[id]; !exists {
		return 0, ErrRouteNotFound{ID: id}
	}
	if s.persist != nil {
		if err := s.persist.DeleteRoute(ctx, id); err != nil {
			return 0, ErrProxyPersist{Kind: "route", ID: id, Cause: err}
		}
	}
	delete(s.routes, id)
	return s.bumpLocked(), nil
}

// Routes returns all routes sorted by ID plus the current config version.
func (s *ProxyStore) Routes(ctx context.Context) ([]proxy.RouteConfig, uint64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.routesSliceLocked(), s.version, nil
}

// =============================================================================
// Pool CRUD
// =============================================================================

// CreatePool stores a new backend pool after validating the resulting
// configuration. Returns the stored pool and the new config version.
func (s *ProxyStore) CreatePool(ctx context.Context, pool proxy.BackendPoolConfig) (proxy.BackendPoolConfig, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.pools[pool.ID]; exists {
		return proxy.BackendPoolConfig{}, 0, ErrPoolExists{ID: pool.ID}
	}

	candidate := clonePool(pool)
	candidatePools := append(s.poolsSliceLocked(), candidate)
	if err := validateCandidate(s.routesSliceLocked(), candidatePools); err != nil {
		return proxy.BackendPoolConfig{}, 0, err
	}
	if err := s.persistPool(ctx, candidate); err != nil {
		return proxy.BackendPoolConfig{}, 0, err
	}
	s.pools[candidate.ID] = candidate
	return clonePool(candidate), s.bumpLocked(), nil
}

// Pool returns the backend pool with the given ID.
func (s *ProxyStore) Pool(ctx context.Context, id string) (proxy.BackendPoolConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	pool, ok := s.pools[id]
	if !ok {
		return proxy.BackendPoolConfig{}, ErrPoolNotFound{ID: id}
	}
	return clonePool(pool), nil
}

// UpdatePool replaces an existing backend pool after validating the
// resulting configuration. Returns the stored pool and the new config
// version.
func (s *ProxyStore) UpdatePool(ctx context.Context, pool proxy.BackendPoolConfig) (proxy.BackendPoolConfig, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.pools[pool.ID]; !exists {
		return proxy.BackendPoolConfig{}, 0, ErrPoolNotFound{ID: pool.ID}
	}

	candidate := clonePool(pool)
	candidatePools := make([]proxy.BackendPoolConfig, 0, len(s.pools))
	for _, p := range s.pools {
		if p.ID == pool.ID {
			continue
		}
		candidatePools = append(candidatePools, clonePool(p))
	}
	candidatePools = append(candidatePools, candidate)
	if err := validateCandidate(s.routesSliceLocked(), candidatePools); err != nil {
		return proxy.BackendPoolConfig{}, 0, err
	}
	if err := s.persistPool(ctx, candidate); err != nil {
		return proxy.BackendPoolConfig{}, 0, err
	}
	s.pools[candidate.ID] = candidate
	return clonePool(candidate), s.bumpLocked(), nil
}

// DeletePool removes a backend pool and returns the new config version.
// Deletion is denied with ErrPoolInUse while any route references the pool.
func (s *ProxyStore) DeletePool(ctx context.Context, id string) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.pools[id]; !exists {
		return 0, ErrPoolNotFound{ID: id}
	}

	var refs []string
	for _, r := range s.routes {
		if r.PoolID == id {
			refs = append(refs, r.ID)
		}
	}
	if len(refs) > 0 {
		sort.Strings(refs)
		return 0, ErrPoolInUse{ID: id, Routes: refs}
	}
	if s.persist != nil {
		if err := s.persist.DeletePool(ctx, id); err != nil {
			return 0, ErrProxyPersist{Kind: "pool", ID: id, Cause: err}
		}
	}

	delete(s.pools, id)
	return s.bumpLocked(), nil
}

// Pools returns all backend pools sorted by ID plus the current config
// version.
func (s *ProxyStore) Pools(ctx context.Context) ([]proxy.BackendPoolConfig, uint64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.poolsSliceLocked(), s.version, nil
}

// =============================================================================
// Snapshot / status / reload
// =============================================================================

// Snapshot returns the full merged configuration (routes and pools sorted by
// ID) and the current config version.
func (s *ProxyStore) Snapshot(ctx context.Context) ([]proxy.RouteConfig, []proxy.BackendPoolConfig, uint64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.routesSliceLocked(), s.poolsSliceLocked(), s.version, nil
}

// Status reports the store's bookkeeping state.
func (s *ProxyStore) Status(ctx context.Context) (*ProxyStoreStatus, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return &ProxyStoreStatus{
		Version:    s.version,
		RouteCount: len(s.routes),
		PoolCount:  len(s.pools),
		UpdatedAt:  s.updatedAt,
	}, nil
}

// Reload bumps the config version without changing state so syncing
// gatewayd instances re-fetch the current configuration.
func (s *ProxyStore) Reload(ctx context.Context) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bumpLocked(), nil
}

// persistRoute writes a validated route through to the persistence backend
// when one is configured. Called under s.mu so the memory and the backend
// never disagree about which write won.
func (s *ProxyStore) persistRoute(ctx context.Context, route proxy.RouteConfig) error {
	if s.persist == nil {
		return nil
	}
	if err := s.persist.SaveRoute(ctx, route); err != nil {
		return ErrProxyPersist{Kind: "route", ID: route.ID, Cause: err}
	}
	return nil
}

// persistPool is persistRoute for pools.
func (s *ProxyStore) persistPool(ctx context.Context, pool proxy.BackendPoolConfig) error {
	if s.persist == nil {
		return nil
	}
	if err := s.persist.SavePool(ctx, pool); err != nil {
		return ErrProxyPersist{Kind: "pool", ID: pool.ID, Cause: err}
	}
	return nil
}

// hasPool reports whether a pool with id is in the working set.
func (s *ProxyStore) hasPool(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.pools[id]
	return ok
}

// hasRoute reports whether a route with id is in the working set.
func (s *ProxyStore) hasRoute(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.routes[id]
	return ok
}
