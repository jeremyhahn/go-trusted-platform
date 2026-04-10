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

package entities

type KeyValueEntity interface {
	SetEntityID(id uint64)
	EntityID() uint64
}

type Index interface {
	Name() string
	RefID() uint64
	KeyValueEntity
}

type TimeSeriesIndexer interface {
	KeyValueEntity
	SetTimestamp(timestamp uint64)
	Timestamp() uint64
}
