//go:build platform_p2p

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

package app

import (
	"context"
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam/backends"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/p2p"
)

func init() {
	// memory: in-process bitmap-based allocator; default when backend is empty.
	ipamBackendFactory["memory"] = func(ctx context.Context, app *App) (ipam.Allocator, error) {
		return backends.NewMemoryBackend(
			ipam.WithLogger(app.Logger.Slog()),
		), nil
	}

	// dht: libp2p Kademlia DHT-backed allocator for decentralised P2P deployments.
	// The factory entry is replaced at startup by RegisterDHTIPAMBackend once a
	// live p2p.Node is available. Until then Allocate returns an unavailable error.
	ipamBackendFactory["dht"] = func(ctx context.Context, app *App) (ipam.Allocator, error) {
		return nil, fmt.Errorf("sdn: ipam backend \"dht\" requires a live p2p node; call RegisterDHTIPAMBackend before initSDN")
	}
}

// RegisterDHTIPAMBackend replaces the "dht" factory entry with one that uses
// the provided p2p node. Call this during the P2P daemon init path, before
// App.initSDN is invoked.
func RegisterDHTIPAMBackend(node *p2p.Node) {
	ipamBackendFactory["dht"] = func(ctx context.Context, app *App) (ipam.Allocator, error) {
		return backends.NewDHTBackend(node, ipam.WithLogger(app.Logger.Slog()))
	}
}
