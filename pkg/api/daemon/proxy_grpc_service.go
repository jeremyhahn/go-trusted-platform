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
	"errors"
	"sort"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/proxy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// proxyStoreService adapts the daemon ProxyStore (plus an optional zone
// service for the zone matrix) into the grpcapi.ProxyService interface that
// backs the gRPC, REST, QUIC and MCP proxy transports. It translates the
// store's typed errors into the grpc-package typed errors that define the
// ProxyService error contract; pkg/proxy validation errors pass through
// unchanged (they are already the canonical validation vocabulary).
type proxyStoreService struct {
	store   *ProxyStore
	zoneSvc gateway.ZoneService // may be nil; ZoneMatrix degrades to Unavailable
}

// Compile-time check: proxyStoreService implements grpcapi.ProxyService.
var _ grpcapi.ProxyService = (*proxyStoreService)(nil)

// newProxyStoreService wraps a ProxyStore and an optional zone service as a
// grpcapi.ProxyService.
func newProxyStoreService(store *ProxyStore, zoneSvc gateway.ZoneService) *proxyStoreService {
	return &proxyStoreService{store: store, zoneSvc: zoneSvc}
}

// NewProxyGRPCServiceWithStore constructs the shared ProxyGRPCService over
// the given store — the persistent one in the daemon, the in-memory one in
// tests — and the given zone service. The returned service backs every proxy
// transport (gRPC TCP/UDS, REST, QUIC, MCP, embedded SDK).
func NewProxyGRPCServiceWithStore(logger *logging.Logger, store *ProxyStore, zoneSvc gateway.ZoneService) *grpcapi.ProxyGRPCService {
	return grpcapi.NewProxyGRPCService(logger, newProxyStoreService(store, zoneSvc))
}

// mapProxyStoreError translates ProxyStore typed errors into the grpc
// package's typed errors so the ProxyGRPCService assigns the correct status
// codes. Unrecognized errors (including pkg/proxy validation errors) pass
// through unchanged.
func mapProxyStoreError(err error) error {
	if err == nil {
		return nil
	}
	var (
		routeNotFound ErrRouteNotFound
		routeExists   ErrRouteExists
		poolNotFound  ErrPoolNotFound
		poolExists    ErrPoolExists
		poolInUse     ErrPoolInUse
	)
	switch {
	case errors.As(err, &routeNotFound):
		return grpcapi.ErrProxyRouteNotFound{ID: routeNotFound.ID}
	case errors.As(err, &routeExists):
		return grpcapi.ErrProxyRouteExists{ID: routeExists.ID}
	case errors.As(err, &poolNotFound):
		return grpcapi.ErrProxyPoolNotFound{ID: poolNotFound.ID}
	case errors.As(err, &poolExists):
		return grpcapi.ErrProxyPoolExists{ID: poolExists.ID}
	case errors.As(err, &poolInUse):
		return grpcapi.ErrProxyPoolInUse{ID: poolInUse.ID, Routes: poolInUse.Routes}
	}
	return err
}

// CreateRoute stores a new route.
func (s *proxyStoreService) CreateRoute(ctx context.Context, route proxy.RouteConfig) (proxy.RouteConfig, uint64, error) {
	stored, version, err := s.store.CreateRoute(ctx, route)
	if err != nil {
		return proxy.RouteConfig{}, 0, mapProxyStoreError(err)
	}
	return stored, version, nil
}

// Route returns a route by ID.
func (s *proxyStoreService) Route(ctx context.Context, id string) (proxy.RouteConfig, error) {
	route, err := s.store.Route(ctx, id)
	if err != nil {
		return proxy.RouteConfig{}, mapProxyStoreError(err)
	}
	return route, nil
}

// UpdateRoute replaces an existing route.
func (s *proxyStoreService) UpdateRoute(ctx context.Context, route proxy.RouteConfig) (proxy.RouteConfig, uint64, error) {
	stored, version, err := s.store.UpdateRoute(ctx, route)
	if err != nil {
		return proxy.RouteConfig{}, 0, mapProxyStoreError(err)
	}
	return stored, version, nil
}

// DeleteRoute removes a route by ID.
func (s *proxyStoreService) DeleteRoute(ctx context.Context, id string) (uint64, error) {
	version, err := s.store.DeleteRoute(ctx, id)
	if err != nil {
		return 0, mapProxyStoreError(err)
	}
	return version, nil
}

// Routes returns all routes.
func (s *proxyStoreService) Routes(ctx context.Context) ([]proxy.RouteConfig, uint64, error) {
	return s.store.Routes(ctx)
}

// CreatePool stores a new backend pool.
func (s *proxyStoreService) CreatePool(ctx context.Context, pool proxy.BackendPoolConfig) (proxy.BackendPoolConfig, uint64, error) {
	stored, version, err := s.store.CreatePool(ctx, pool)
	if err != nil {
		return proxy.BackendPoolConfig{}, 0, mapProxyStoreError(err)
	}
	return stored, version, nil
}

// Pool returns a backend pool by ID.
func (s *proxyStoreService) Pool(ctx context.Context, id string) (proxy.BackendPoolConfig, error) {
	pool, err := s.store.Pool(ctx, id)
	if err != nil {
		return proxy.BackendPoolConfig{}, mapProxyStoreError(err)
	}
	return pool, nil
}

// UpdatePool replaces an existing backend pool.
func (s *proxyStoreService) UpdatePool(ctx context.Context, pool proxy.BackendPoolConfig) (proxy.BackendPoolConfig, uint64, error) {
	stored, version, err := s.store.UpdatePool(ctx, pool)
	if err != nil {
		return proxy.BackendPoolConfig{}, 0, mapProxyStoreError(err)
	}
	return stored, version, nil
}

// DeletePool removes a backend pool by ID.
func (s *proxyStoreService) DeletePool(ctx context.Context, id string) (uint64, error) {
	version, err := s.store.DeletePool(ctx, id)
	if err != nil {
		return 0, mapProxyStoreError(err)
	}
	return version, nil
}

// Pools returns all backend pools.
func (s *proxyStoreService) Pools(ctx context.Context) ([]proxy.BackendPoolConfig, uint64, error) {
	return s.store.Pools(ctx)
}

// Snapshot returns the merged configuration and version.
func (s *proxyStoreService) Snapshot(ctx context.Context) ([]proxy.RouteConfig, []proxy.BackendPoolConfig, uint64, error) {
	return s.store.Snapshot(ctx)
}

// Status reports the store status.
func (s *proxyStoreService) Status(ctx context.Context) (*grpcapi.ProxyStatusInfo, error) {
	st, err := s.store.Status(ctx)
	if err != nil {
		return nil, mapProxyStoreError(err)
	}
	return &grpcapi.ProxyStatusInfo{
		Version:    st.Version,
		RouteCount: st.RouteCount,
		PoolCount:  st.PoolCount,
		UpdatedAt:  st.UpdatedAt,
	}, nil
}

// Reload bumps the config version.
func (s *proxyStoreService) Reload(ctx context.Context) (uint64, error) {
	return s.store.Reload(ctx)
}

// ZoneMatrix compiles the SDN zone matrix from the runtime zone service.
// The zone names are sorted and the allowed pairs are derived by querying
// the compiled matrix for every (from, to) combination, reusing the
// canonical pkg/sdn/zone compilation rules rather than duplicating them.
func (s *proxyStoreService) ZoneMatrix(ctx context.Context) (*grpcapi.ProxyZoneMatrixInfo, error) {
	if s.zoneSvc == nil {
		return nil, grpcapi.ErrProxyZoneMatrixUnavailable{}
	}

	index := s.zoneSvc.ZoneIndex()
	names := make([]string, 0, len(index))
	configs := make([]zone.ZoneConfig, 0, len(index))
	for name, cfg := range index {
		names = append(names, string(name))
		configs = append(configs, cfg)
	}
	sort.Strings(names)

	matrix := zone.CompileMatrix(configs)
	pairs := make([]grpcapi.ProxyZonePairInfo, 0, len(names))
	for _, from := range names {
		for _, to := range names {
			verdict := matrix.Allowed(zone.Zone(from), zone.Zone(to))
			if !verdict.Allowed {
				continue
			}
			pairs = append(pairs, grpcapi.ProxyZonePairInfo{
				From:     from,
				To:       to,
				Services: verdict.Services,
			})
		}
	}

	return &grpcapi.ProxyZoneMatrixInfo{
		Zones: names,
		Pairs: pairs,
	}, nil
}
