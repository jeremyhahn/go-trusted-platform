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

package logging

import (
	"context"
	"errors"
	"log/slog"
)

// MultiHandler fans every slog Record out to two or more child
// handlers. A non-nil error from any child is returned to the caller;
// errors from later children are joined into a single combined error
// so a misbehaving downstream handler does not mask its peers.
//
// MultiHandler exists so platformd can keep the existing
// stderr/JSON-to-file logger working while also feeding records into
// a structured JSON-lines store for the WebUI Logs page (and any
// future cluster-wide forwarder). Without it, wiring observability
// would require replacing the entire boot-time logger or migrating
// every call site to a new abstraction.
type MultiHandler struct {
	handlers []slog.Handler
}

// NewMultiHandler returns a handler that forwards every record to
// each of the supplied children, in order. Nil children are skipped
// silently — callers can therefore mix in an optional sink without
// having to nil-guard at every call site.
func NewMultiHandler(handlers ...slog.Handler) *MultiHandler {
	cleaned := make([]slog.Handler, 0, len(handlers))
	for _, h := range handlers {
		if h != nil {
			cleaned = append(cleaned, h)
		}
	}
	return &MultiHandler{handlers: cleaned}
}

// Enabled returns true if any underlying handler is enabled for the
// supplied level. This matches the "fan-out" semantics: if even one
// downstream wants the record, we emit it; individual handlers can
// still drop their copy via their own Enabled checks.
func (m *MultiHandler) Enabled(ctx context.Context, l slog.Level) bool {
	for _, h := range m.handlers {
		if h.Enabled(ctx, l) {
			return true
		}
	}
	return false
}

// Handle dispatches the record to every child whose Enabled gate
// passes. Errors are accumulated and joined.
func (m *MultiHandler) Handle(ctx context.Context, r slog.Record) error {
	var errs []error
	for _, h := range m.handlers {
		if !h.Enabled(ctx, r.Level) {
			continue
		}
		if err := h.Handle(ctx, r.Clone()); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// WithAttrs returns a MultiHandler whose children each carry the
// supplied attributes. Children that are unaware of WithAttrs are
// passed through unchanged.
func (m *MultiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		out[i] = h.WithAttrs(attrs)
	}
	return &MultiHandler{handlers: out}
}

// WithGroup propagates the group prefix to all children.
func (m *MultiHandler) WithGroup(name string) slog.Handler {
	out := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		out[i] = h.WithGroup(name)
	}
	return &MultiHandler{handlers: out}
}

// WrapHandler returns a *Logger backed by an existing slog.Handler.
// This is the inverse of NewLoggerWithFormat which constructs the
// handler internally — used at platformd boot when a multi-handler
// has been assembled separately. A nil handler is a programming error
// and panics at construction time (previously it produced a logger
// that panicked on first use).
func WrapHandler(h slog.Handler) *Logger {
	return newSharedLogger(h, "trace")
}
