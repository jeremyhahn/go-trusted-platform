//go:build !platform_p2p

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

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam/backends"
)

func init() {
	// memory: in-process bitmap-based allocator; default when backend is empty.
	ipamBackendFactory["memory"] = func(ctx context.Context, app *App) (ipam.Allocator, error) {
		return backends.NewMemoryBackend(
			ipam.WithLogger(app.Logger.Slog()),
		), nil
	}

	// quicbaas: strongly-consistent Raft-backed allocator via QuicBaaS KV.
	// Requires the platform QuicBaaS SDK client to be configured and started.
	ipamBackendFactory["quicbaas"] = func(ctx context.Context, app *App) (ipam.Allocator, error) {
		sdk := app.QuicBaaSSDKClient()
		if sdk == nil {
			return nil, sdn.ErrIPAMBackendUnconfigured{Backend: "quicbaas"}
		}
		return backends.NewQuicBaaSBackend(
			&sdkIPAMClient{sdk: sdk},
			&backends.QuicBaaSBackendConfig{Logger: app.Logger.Slog()},
		)
	}
}
