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

package backup

import (
	upstream "github.com/jeremyhahn/go-quicbaas/sdk/go/client/backup"
)

// Client is the backup and restore client returned by
// quicbaas.Client.Backup().
type Client = upstream.Client

// BackupInfo is a stored backup as the server reports it.
type BackupInfo = upstream.BackupInfo

// Requests and responses of the Client verbs.
type (
	BackupRequest       = upstream.BackupRequest
	BackupResponse      = upstream.BackupResponse
	RestoreRequest      = upstream.RestoreRequest
	RestoreResponse     = upstream.RestoreResponse
	ListBackupsResponse = upstream.ListBackupsResponse
)
