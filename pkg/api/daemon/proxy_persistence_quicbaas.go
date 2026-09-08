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
	"hash/fnv"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/proxy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

// Entity type names the proxy records are stored under. They are part of
// the persisted key layout; renaming one orphans every existing record.
const (
	entityTypeProxyRoute = "ProxyRoute"
	entityTypeProxyPool  = "ProxyPool"
)

// proxyPersistencePageSize bounds one Load page; the whole set is walked.
const proxyPersistencePageSize = 500

// ProxyRouteEntity is a persisted proxy route. The entity ID is derived
// from the route's string ID so the same route always lands on the same
// record; the route itself is stored with its json tags.
type ProxyRouteEntity struct {
	ID    uint64            `json:"id"`
	Route proxy.RouteConfig `json:"route"`

	entities.KeyValueEntity `json:"-"`
}

// EntityID returns the entity's unique identifier.
func (e *ProxyRouteEntity) EntityID() uint64 { return e.ID }

// SetEntityID sets the entity's unique identifier.
func (e *ProxyRouteEntity) SetEntityID(id uint64) { e.ID = id }

// ProxyPoolEntity is a persisted backend pool.
type ProxyPoolEntity struct {
	ID   uint64                  `json:"id"`
	Pool proxy.BackendPoolConfig `json:"pool"`

	entities.KeyValueEntity `json:"-"`
}

// EntityID returns the entity's unique identifier.
func (e *ProxyPoolEntity) EntityID() uint64 { return e.ID }

// SetEntityID sets the entity's unique identifier.
func (e *ProxyPoolEntity) SetEntityID(id uint64) { e.ID = id }

// proxyEntityID maps a route or pool string ID onto the entity keyspace
// deterministically (FNV-1a 64), so Save is an upsert and Delete needs no
// lookup. Zero is reserved by the DAO layer as "unassigned", so it is
// avoided.
func proxyEntityID(id string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(id))
	sum := h.Sum64()
	if sum == 0 {
		return 1
	}
	return sum
}

// QuicBaaSProxyPersistence persists routes and pools through the platform's
// quicbaas DAO adapter — two entity types, one record per ID — the same
// seam every other platform entity (EAB credentials, device profiles,
// registrations) uses. It lives in the daemon, not in pkg/proxy, so the
// gatewayd import closure stays free of the SDK client.
type QuicBaaSProxyPersistence struct {
	routes *quicbaas.GenericDAO[*ProxyRouteEntity]
	pools  *quicbaas.GenericDAO[*ProxyPoolEntity]
}

// NewQuicBaaSProxyPersistence builds the backend over a quicbaas Storage.
func NewQuicBaaSProxyPersistence(storage quicbaas.Storage, logger *logging.Logger, opts ...quicbaas.DAOOption) *QuicBaaSProxyPersistence {
	return &QuicBaaSProxyPersistence{
		routes: quicbaas.NewGenericDAO[*ProxyRouteEntity](storage, entityTypeProxyRoute,
			func() *ProxyRouteEntity { return &ProxyRouteEntity{} }, logger, opts...),
		pools: quicbaas.NewGenericDAO[*ProxyPoolEntity](storage, entityTypeProxyPool,
			func() *ProxyPoolEntity { return &ProxyPoolEntity{} }, logger, opts...),
	}
}

// Load walks both entity types and returns every record.
func (p *QuicBaaSProxyPersistence) Load(ctx context.Context) ([]proxy.RouteConfig, []proxy.BackendPoolConfig, error) {
	var routes []proxy.RouteConfig
	err := p.routes.ForEachPage(ctx, datastore.PageQuery{Page: 1, PageSize: proxyPersistencePageSize},
		func(page datastore.PageResult[*ProxyRouteEntity]) error {
			for _, e := range page.Entities {
				routes = append(routes, e.Route)
			}
			return nil
		})
	if err != nil {
		return nil, nil, err
	}
	var pools []proxy.BackendPoolConfig
	err = p.pools.ForEachPage(ctx, datastore.PageQuery{Page: 1, PageSize: proxyPersistencePageSize},
		func(page datastore.PageResult[*ProxyPoolEntity]) error {
			for _, e := range page.Entities {
				pools = append(pools, e.Pool)
			}
			return nil
		})
	if err != nil {
		return nil, nil, err
	}
	return routes, pools, nil
}

// SaveRoute upserts the route's record.
func (p *QuicBaaSProxyPersistence) SaveRoute(ctx context.Context, route proxy.RouteConfig) error {
	return p.routes.Save(ctx, &ProxyRouteEntity{ID: proxyEntityID(route.ID), Route: route})
}

// DeleteRoute removes the route's record.
func (p *QuicBaaSProxyPersistence) DeleteRoute(ctx context.Context, id string) error {
	return p.routes.Delete(ctx, &ProxyRouteEntity{ID: proxyEntityID(id)})
}

// SavePool upserts the pool's record.
func (p *QuicBaaSProxyPersistence) SavePool(ctx context.Context, pool proxy.BackendPoolConfig) error {
	return p.pools.Save(ctx, &ProxyPoolEntity{ID: proxyEntityID(pool.ID), Pool: pool})
}

// DeletePool removes the pool's record.
func (p *QuicBaaSProxyPersistence) DeletePool(ctx context.Context, id string) error {
	return p.pools.Delete(ctx, &ProxyPoolEntity{ID: proxyEntityID(id)})
}

// Compile-time check that the backend satisfies the seam.
var _ ProxyPersistence = (*QuicBaaSProxyPersistence)(nil)
