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

package kv

import (
	upstream "github.com/jeremyhahn/go-quicbaas/sdk/go/client/kv"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"
)

// Client is the key-value client returned by quicbaas.Client.KV().
type Client = upstream.Client

// Requests and responses of the Client verbs.
type (
	PutRequest     = service.PutRequest
	PutResponse    = service.PutResponse
	GetRequest     = service.GetRequest
	GetResponse    = service.GetResponse
	DeleteRequest  = service.DeleteRequest
	DeleteResponse = service.DeleteResponse
	ListRequest    = service.ListRequest
	ListResponse   = service.ListResponse
)

// Entities and the guarantees a read or write asks for.
type (
	// Entity is a stored entity as List returns it.
	Entity = service.Entity
	// ConsistencyLevel is the read or write consistency a request asks for.
	ConsistencyLevel = service.ConsistencyLevel
	// WriteMode is the durability a write asks for.
	WriteMode = service.WriteMode
)

// Watches.
type (
	// Watcher streams the change events of a Watch or WatchPrefix.
	Watcher = upstream.Watcher
	// WatchEvent is one key change.
	WatchEvent = upstream.WatchEvent
	// EventType says whether a WatchEvent is a put or a delete.
	EventType = upstream.EventType
	// WatchOption configures a Watch or WatchPrefix.
	WatchOption = upstream.WatchOption
)

// Consistency levels.
const (
	ConsistencyLevelUnspecified  = service.ConsistencyLevelUnspecified
	ConsistencyLevelEventual     = service.ConsistencyLevelEventual
	ConsistencyLevelLinearizable = service.ConsistencyLevelLinearizable
	ConsistencyLevelStrong       = service.ConsistencyLevelStrong
)

// Write modes.
const (
	WriteModeSync       = service.WriteModeSync
	WriteModeWALDurable = service.WriteModeWALDurable
	WriteModeBatched    = service.WriteModeBatched
)

// Watch event types.
const (
	EventPut    = upstream.EventPut
	EventDelete = upstream.EventDelete
)

// WithStartRevision starts the watch at MVCC revision rev.
func WithStartRevision(rev uint64) WatchOption {
	return upstream.WithStartRevision(rev)
}

// WithPrevKV includes the previous value in each watch event.
func WithPrevKV() WatchOption {
	return upstream.WithPrevKV()
}

// WithProgressNotify asks for periodic progress notifications.
func WithProgressNotify() WatchOption {
	return upstream.WithProgressNotify()
}

// WithFilterPut drops PUT events, so the watch delivers deletes only.
func WithFilterPut() WatchOption {
	return upstream.WithFilterPut()
}

// WithFilterDelete drops DELETE events, so the watch delivers puts only.
func WithFilterDelete() WatchOption {
	return upstream.WithFilterDelete()
}
