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

package jsonfile

// Querier exposes Query / ListServices / Subscribe in the shape the
// REST + gRPC log surfaces expect. It is satisfied by *Handler with
// the dir captured from the active handler so callers don't have to
// thread it themselves.
type Querier struct {
	dir string
	h   *Handler
}

// NewQuerier returns a Querier bound to an existing handler. The
// handler must remain alive for the lifetime of the querier — when
// the handler is closed, Subscribe channels close and Query reads
// continue to function until the underlying files are removed.
func NewQuerier(h *Handler) *Querier {
	return &Querier{dir: h.dir, h: h}
}

// Query scans on-disk JSON-lines logs against the filter and returns
// matching entries newest-first.
func (q *Querier) Query(filter Filter) (QueryResult, error) {
	return Query(q.dir, filter)
}

// ListServices returns the set of service names with at least one
// record on disk.
func (q *Querier) ListServices() ([]string, error) {
	return ListServices(q.dir)
}

// Subscribe registers a live tail. The returned channel emits raw
// JSON-line bytes; the unsubscribe func MUST be called when the
// subscriber is done.
func (q *Querier) Subscribe() (<-chan []byte, func()) {
	return q.h.Subscribe()
}
