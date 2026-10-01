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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/proxy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// fakePersistence records what the store wrote through and can fail on
// demand, so the store's ordering (persist before mutate) is observable.
type fakePersistence struct {
	routes   map[string]proxy.RouteConfig
	pools    map[string]proxy.BackendPoolConfig
	loadErr  error
	saveErr  error
	delErr   error
	saves    int
	deletes  int
	loadOnce int
}

func newFakePersistence() *fakePersistence {
	return &fakePersistence{routes: map[string]proxy.RouteConfig{}, pools: map[string]proxy.BackendPoolConfig{}}
}

func (f *fakePersistence) Load(context.Context) ([]proxy.RouteConfig, []proxy.BackendPoolConfig, error) {
	f.loadOnce++
	if f.loadErr != nil {
		return nil, nil, f.loadErr
	}
	var rs []proxy.RouteConfig
	for _, r := range f.routes {
		rs = append(rs, r)
	}
	var ps []proxy.BackendPoolConfig
	for _, p := range f.pools {
		ps = append(ps, p)
	}
	return rs, ps, nil
}

func (f *fakePersistence) SaveRoute(_ context.Context, r proxy.RouteConfig) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	f.saves++
	f.routes[r.ID] = r
	return nil
}

func (f *fakePersistence) DeleteRoute(_ context.Context, id string) error {
	if f.delErr != nil {
		return f.delErr
	}
	f.deletes++
	delete(f.routes, id)
	return nil
}

func (f *fakePersistence) SavePool(_ context.Context, p proxy.BackendPoolConfig) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	f.saves++
	f.pools[p.ID] = p
	return nil
}

func (f *fakePersistence) DeletePool(_ context.Context, id string) error {
	if f.delErr != nil {
		return f.delErr
	}
	f.deletes++
	delete(f.pools, id)
	return nil
}

func TestNewPersistentProxyStore_RequiresABackend(t *testing.T) {
	_, err := NewPersistentProxyStore(context.Background(), nil)
	var want ErrProxyPersistenceRequired
	assert.True(t, errors.As(err, &want))
}

func TestNewPersistentProxyStore_LoadsAndVersions(t *testing.T) {
	ctx := context.Background()
	p := newFakePersistence()
	p.pools["p"] = testPool("p")
	p.routes["r"] = testRoute("r", "p")

	store, err := NewPersistentProxyStore(ctx, p)
	require.NoError(t, err)
	routes, version, err := store.Routes(ctx)
	require.NoError(t, err)
	assert.Len(t, routes, 1)
	assert.Equal(t, uint64(1), version, "a non-empty load starts at version 1")
	assert.Equal(t, 1, p.loadOnce)

	empty, err := NewPersistentProxyStore(ctx, newFakePersistence())
	require.NoError(t, err)
	_, version, _ = empty.Routes(ctx)
	assert.Equal(t, uint64(0), version)
}

func TestNewPersistentProxyStore_RefusesABadSet(t *testing.T) {
	ctx := context.Background()
	t.Run("load error", func(t *testing.T) {
		p := newFakePersistence()
		p.loadErr = errors.New("db down")
		_, err := NewPersistentProxyStore(ctx, p)
		var want ErrProxyStoreLoad
		require.True(t, errors.As(err, &want))
		assert.ErrorIs(t, err, p.loadErr)
	})
	t.Run("route references a pool that is gone", func(t *testing.T) {
		p := newFakePersistence()
		p.routes["r"] = testRoute("r", "missing")
		_, err := NewPersistentProxyStore(ctx, p)
		var want ErrProxyStoreLoad
		require.True(t, errors.As(err, &want))
		assert.ErrorIs(t, err, proxy.ErrUnknownPoolID)
	})
}

// TestProxyStore_WritesThroughBeforeMutating pins the contract: a mutation
// the backend refuses leaves the working set untouched and the version
// unchanged; an accepted one is in the backend before the caller sees it.
func TestProxyStore_WritesThroughBeforeMutating(t *testing.T) {
	ctx := context.Background()
	p := newFakePersistence()
	store, err := NewPersistentProxyStore(ctx, p)
	require.NoError(t, err)

	_, v1, err := store.CreatePool(ctx, testPool("p"))
	require.NoError(t, err)
	_, v2, err := store.CreateRoute(ctx, testRoute("r", "p"))
	require.NoError(t, err)
	assert.Greater(t, v2, v1)
	assert.Equal(t, 2, p.saves)
	assert.Equal(t, []string{"example.com"}, p.routes["r"].Hosts, "the normalized route is what gets persisted")

	p.saveErr = errors.New("write refused")
	_, _, err = store.UpdateRoute(ctx, testRoute("r", "p"))
	var persistErr ErrProxyPersist
	require.True(t, errors.As(err, &persistErr))
	assert.Equal(t, "route", persistErr.Kind)
	_, _, err = store.CreatePool(ctx, testPool("q"))
	require.True(t, errors.As(err, &persistErr))
	_, _, err = store.UpdatePool(ctx, testPool("p"))
	require.True(t, errors.As(err, &persistErr))
	_, vAfter, _ := store.Routes(ctx)
	assert.Equal(t, v2, vAfter, "a refused write does not bump the version")
	_, err = store.Pool(ctx, "q")
	assert.Error(t, err, "the refused pool never entered the working set")

	p.saveErr = nil
	p.delErr = errors.New("delete refused")
	_, err = store.DeleteRoute(ctx, "r")
	require.True(t, errors.As(err, &persistErr))
	_, err = store.Route(ctx, "r")
	assert.NoError(t, err, "the route stays when the backend refuses the delete")

	p.delErr = nil
	_, err = store.DeleteRoute(ctx, "r")
	require.NoError(t, err)
	_, err = store.DeletePool(ctx, "p")
	require.NoError(t, err)
	assert.Equal(t, 2, p.deletes)
	assert.Empty(t, p.routes)
	assert.Empty(t, p.pools)
}

func TestProxyStore_SeedFromConfig(t *testing.T) {
	ctx := context.Background()
	p := newFakePersistence()
	p.pools["api"] = testPool("api")
	existing := testRoute("console", "api")
	existing.PathPrefix = "/stored"
	p.routes["console"] = existing
	store, err := NewPersistentProxyStore(ctx, p)
	require.NoError(t, err)

	fromFile := testRoute("console", "api")
	fromFile.PathPrefix = "/from-file"
	cfg := &proxy.ControlPlaneConfig{
		Pools:  []proxy.BackendPoolConfig{testPool("api"), testPool("registry")},
		Routes: []proxy.RouteConfig{fromFile, testRoute("registry", "registry")},
	}
	added, err := store.SeedFromConfig(ctx, cfg)
	require.NoError(t, err)
	assert.Equal(t, 2, added, "one new pool and one new route")

	kept, err := store.Route(ctx, "console")
	require.NoError(t, err)
	assert.Equal(t, "/stored", kept.PathPrefix, "an API-authored record wins over the file")
	_, err = store.Route(ctx, "registry")
	assert.NoError(t, err)
	assert.Contains(t, p.pools, "registry")

	again, err := store.SeedFromConfig(ctx, cfg)
	require.NoError(t, err)
	assert.Equal(t, 0, again, "seeding is idempotent")

	added, err = store.SeedFromConfig(ctx, nil)
	require.NoError(t, err)
	assert.Equal(t, 0, added)
}

func TestProxyStore_SeedFromConfig_FailsClosed(t *testing.T) {
	ctx := context.Background()
	store := NewProxyStore()
	bad := &proxy.ControlPlaneConfig{Routes: []proxy.RouteConfig{testRoute("r", "nope")}}
	_, err := store.SeedFromConfig(ctx, bad)
	assert.ErrorIs(t, err, proxy.ErrUnknownPoolID)
	routes, _, _ := store.Routes(ctx)
	assert.Empty(t, routes, "nothing from a refused section is seeded")

	p := newFakePersistence()
	pstore, err := NewPersistentProxyStore(ctx, p)
	require.NoError(t, err)
	p.saveErr = errors.New("write refused")
	_, err = pstore.SeedFromConfig(ctx, &proxy.ControlPlaneConfig{Pools: []proxy.BackendPoolConfig{testPool("p")}})
	var seedErr ErrProxySeed
	require.True(t, errors.As(err, &seedErr))
	assert.Equal(t, "pool", seedErr.Kind)
}

func TestProxyErrors_Messages(t *testing.T) {
	cause := errors.New("cause")
	assert.Contains(t, ErrProxyStoreLoad{Cause: cause}.Error(), "cause")
	assert.ErrorIs(t, ErrProxyStoreLoad{Cause: cause}, cause)
	assert.Contains(t, ErrProxyPersist{Kind: "pool", ID: "p", Cause: cause}.Error(), `pool "p"`)
	assert.ErrorIs(t, ErrProxyPersist{Cause: cause}, cause)
	assert.Contains(t, ErrProxySeed{Kind: "route", ID: "r", Cause: cause}.Error(), `route "r"`)
	assert.ErrorIs(t, ErrProxySeed{Cause: cause}, cause)
	assert.NotEmpty(t, ErrProxyPersistenceRequired{}.Error())
}

// --- quicbaas backend over the mock Storage ---

func newQuicBaaSPersistenceForTest(t *testing.T) (*QuicBaaSProxyPersistence, *quicbaas.MockStorage) {
	t.Helper()
	storage := quicbaas.NewMockStorage()
	require.NoError(t, storage.Start(context.Background()))
	return NewQuicBaaSProxyPersistence(storage, logging.DefaultLogger()), storage
}

func TestQuicBaaSProxyPersistence_RoundTrip(t *testing.T) {
	ctx := context.Background()
	p, storage := newQuicBaaSPersistenceForTest(t)

	require.NoError(t, p.SavePool(ctx, testPool("api")))
	r := testRoute("console", "api")
	r.Auth = proxy.AuthRequirements{Mode: proxy.AuthModeMTLS, AllowedZones: []string{"control-plane"}}
	require.NoError(t, p.SaveRoute(ctx, r))
	assert.Equal(t, 1, storage.Count(entityTypeProxyRoute))
	assert.Equal(t, 1, storage.Count(entityTypeProxyPool))

	// Saving the same ID again is an upsert, not a second record.
	r.PathPrefix = "/v2"
	require.NoError(t, p.SaveRoute(ctx, r))
	assert.Equal(t, 1, storage.Count(entityTypeProxyRoute))

	routes, pools, err := p.Load(ctx)
	require.NoError(t, err)
	require.Len(t, routes, 1)
	require.Len(t, pools, 1)
	assert.Equal(t, "/v2", routes[0].PathPrefix)
	assert.Equal(t, []string{"control-plane"}, routes[0].Auth.AllowedZones)
	assert.Equal(t, "api", pools[0].ID)

	require.NoError(t, p.DeleteRoute(ctx, "console"))
	require.NoError(t, p.DeletePool(ctx, "api"))
	routes, pools, err = p.Load(ctx)
	require.NoError(t, err)
	assert.Empty(t, routes)
	assert.Empty(t, pools)
}

func TestQuicBaaSProxyPersistence_PropagatesStorageErrors(t *testing.T) {
	ctx := context.Background()
	p, storage := newQuicBaaSPersistenceForTest(t)
	storage.PutError = errors.New("put failed")
	assert.Error(t, p.SaveRoute(ctx, testRoute("r", "p")))
	assert.Error(t, p.SavePool(ctx, testPool("p")))
	storage.PutError = nil
	storage.ListError = errors.New("list failed")
	_, _, err := p.Load(ctx)
	assert.Error(t, err)
	storage.ListError = nil
	storage.DeleteError = errors.New("delete failed")
	assert.Error(t, p.DeleteRoute(ctx, "r"))
	assert.Error(t, p.DeletePool(ctx, "p"))
}

func TestProxyEntityID_IsDeterministicAndNeverZero(t *testing.T) {
	assert.Equal(t, proxyEntityID("console"), proxyEntityID("console"))
	assert.NotEqual(t, proxyEntityID("console"), proxyEntityID("registry"))
	assert.NotZero(t, proxyEntityID(""))
	e := &ProxyRouteEntity{}
	e.SetEntityID(7)
	assert.Equal(t, uint64(7), e.EntityID())
	pe := &ProxyPoolEntity{}
	pe.SetEntityID(9)
	assert.Equal(t, uint64(9), pe.EntityID())
}

func TestBuildProxyStore_InMemoryWithoutAFactory(t *testing.T) {
	logger := logging.DefaultLogger()
	store, err := buildProxyStore(nil, logger)
	require.NoError(t, err)
	assert.NotNil(t, store)
	assert.Nil(t, store.persist)

	store, err = buildProxyStore(&Config{}, logger)
	require.NoError(t, err)
	assert.Nil(t, store.persist)
	assert.Nil(t, proxyStorage(nil))
	assert.Nil(t, proxyStorage(&Config{}))
}

func TestBuildProxyStore_SeedsFromTheAppSection(t *testing.T) {
	ctx := context.Background()
	app := &app.App{Proxy: &proxy.ControlPlaneConfig{
		Pools:  []proxy.BackendPoolConfig{testPool("console")},
		Routes: []proxy.RouteConfig{testRoute("console", "console")},
	}}
	store, err := buildProxyStore(&Config{App: app}, logging.DefaultLogger())
	require.NoError(t, err)
	routes, _, err := store.Routes(ctx)
	require.NoError(t, err)
	assert.Len(t, routes, 1)

	app.Proxy = &proxy.ControlPlaneConfig{Routes: []proxy.RouteConfig{testRoute("r", "nope")}}
	_, err = buildProxyStore(&Config{App: app}, logging.DefaultLogger())
	assert.ErrorIs(t, err, proxy.ErrUnknownPoolID, "a refused section is a startup error")
}

// TestNewProxyGRPCServiceWithStore_WritesThrough proves the shared gRPC
// service — the one instance behind gRPC TCP/UDS, REST, QUIC, MCP and the
// embedded SDK — writes every accepted mutation through the persistent
// store, and that a second daemon built over the same backend serves what
// the first accepted.
func TestNewProxyGRPCServiceWithStore_WritesThrough(t *testing.T) {
	ctx := context.Background()
	persist, storage := newQuicBaaSPersistenceForTest(t)
	store, err := NewPersistentProxyStore(ctx, persist)
	require.NoError(t, err)
	svc := NewProxyGRPCServiceWithStore(logging.DefaultLogger(), store, nil)

	_, err = svc.CreatePool(ctx, &platformv1.CreateProxyPoolRequest{Pool: &platformv1.ProxyPool{
		Id: "web-pool", Backends: []*platformv1.ProxyBackend{{Url: "https://10.0.0.10:8443", Weight: 1}},
	}})
	require.NoError(t, err)
	_, err = svc.CreateRoute(ctx, &platformv1.CreateProxyRouteRequest{Route: &platformv1.ProxyRoute{
		Id: "web", PathPrefix: "/", PoolId: "web-pool",
		Auth: &platformv1.ProxyAuthRequirements{Mode: proxy.AuthModeMTLS},
	}})
	require.NoError(t, err)
	assert.Equal(t, 1, storage.Count(entityTypeProxyRoute))
	assert.Equal(t, 1, storage.Count(entityTypeProxyPool))

	// A restart: a new store over the same backend serves the same set.
	restarted, err := NewPersistentProxyStore(ctx, NewQuicBaaSProxyPersistence(storage, logging.DefaultLogger()))
	require.NoError(t, err)
	route, err := restarted.Route(ctx, "web")
	require.NoError(t, err)
	assert.Equal(t, proxy.AuthModeMTLS, route.Auth.Mode)
	_, version, _ := restarted.Routes(ctx)
	assert.Equal(t, uint64(1), version)

	_, err = svc.DeleteRoute(ctx, &platformv1.DeleteProxyRouteRequest{Id: "web"})
	require.NoError(t, err)
	assert.Equal(t, 0, storage.Count(entityTypeProxyRoute))
}
