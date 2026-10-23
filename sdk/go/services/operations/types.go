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

package operations

import (
	upstream "github.com/jeremyhahn/go-quicbaas/sdk/go/client/operations"
)

// Client is the cluster operations client returned by
// quicbaas.Client.Operations().
type Client = upstream.Client

// Requests and responses of the Client verbs.
type (
	MigrateDataRequest           = upstream.MigrateDataRequest
	MigrateDataResponse          = upstream.MigrateDataResponse
	GetMigrationProgressRequest  = upstream.GetMigrationProgressRequest
	GetMigrationProgressResponse = upstream.GetMigrationProgressResponse
	ReplaceNodeRequest           = upstream.ReplaceNodeRequest
	ReplaceNodeResponse          = upstream.ReplaceNodeResponse
	UpgradeNodeRequest           = upstream.UpgradeNodeRequest
	UpgradeNodeResponse          = upstream.UpgradeNodeResponse
	GetUpgradeStatusRequest      = upstream.GetUpgradeStatusRequest
	GetUpgradeStatusResponse     = upstream.GetUpgradeStatusResponse
)
