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
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
)

// proxyStoreLoadTimeout bounds the startup load and seed of the proxy store.
const proxyStoreLoadTimeout = 30 * time.Second

// buildProxyStore selects the proxy store the daemon serves (#570): the
// persistent store over the platform DAO seam when the App carries a
// quicbaas DAO factory with a live client, the in-memory store otherwise
// (announced, because routes authored over the API then die with the
// process). The control plane's proxy: section is then seeded as the base
// layer. Any refusal — an unloadable set, a section the engine would not
// accept, a write the backend refuses — is returned, and the daemon does
// not start.
func buildProxyStore(config *Config, logger *logging.Logger) (*ProxyStore, error) {
	ctx, cancel := context.WithTimeout(context.Background(), proxyStoreLoadTimeout)
	defer cancel()

	store, err := selectProxyStore(ctx, config, logger)
	if err != nil {
		return nil, err
	}
	if config == nil || config.App == nil || config.App.Proxy == nil {
		return store, nil
	}
	added, err := store.SeedFromConfig(ctx, config.App.Proxy)
	if err != nil {
		return nil, err
	}
	logger.Info("proxy store seeded from the proxy: section",
		"added", added,
		"routes", len(config.App.Proxy.Routes),
		"pools", len(config.App.Proxy.Pools))
	return store, nil
}

// selectProxyStore returns the persistent store when a quicbaas storage
// client is available and the in-memory one otherwise.
func selectProxyStore(ctx context.Context, config *Config, logger *logging.Logger) (*ProxyStore, error) {
	storage := platformStorage(config)
	if storage == nil {
		logger.Warn("proxy store is in-memory: no quicbaas DAO factory; routes and pools authored over the API do not survive a restart")
		return NewProxyStore(), nil
	}
	store, err := NewPersistentProxyStore(ctx, NewQuicBaaSProxyPersistence(storage, logger))
	if err != nil {
		return nil, err
	}
	logger.Info("proxy store is persistent through the platform DAO seam")
	return store, nil
}

// platformStorage returns the quicbaas storage client behind the App's DAO
// factory, or nil when the daemon runs without one.
func platformStorage(config *Config) quicbaas.Storage {
	if config == nil || config.App == nil {
		return nil
	}
	factory, ok := config.App.DAOFactory().(*quicbaas.Factory)
	if !ok || factory == nil {
		return nil
	}
	client := factory.Client()
	if client == nil {
		return nil
	}
	return client
}
