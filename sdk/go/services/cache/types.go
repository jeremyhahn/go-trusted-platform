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

package cache

import (
	upstream "github.com/jeremyhahn/go-quicbaas/sdk/go/client/cache"
)

// Client is the cache management client returned by quicbaas.Client.Cache().
type Client = upstream.Client

// Requests and responses of the Client verbs.
type (
	GetCacheStatsRequest      = upstream.GetCacheStatsRequest
	GetCacheStatsResponse     = upstream.GetCacheStatsResponse
	ClearCacheRequest         = upstream.ClearCacheRequest
	ClearCacheResponse        = upstream.ClearCacheResponse
	GetCacheConfigRequest     = upstream.GetCacheConfigRequest
	GetCacheConfigResponse    = upstream.GetCacheConfigResponse
	UpdateCacheConfigRequest  = upstream.UpdateCacheConfigRequest
	UpdateCacheConfigResponse = upstream.UpdateCacheConfigResponse
)
