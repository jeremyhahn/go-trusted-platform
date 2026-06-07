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

package platform

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/log/jsonfile"
)

// LogQuerier is the surface PlatformHandlers needs from the daemon's
// log infrastructure. Keeping it small means tests can stand in a
// fake without owning a slog handler.
type LogQuerier interface {
	// Query scans on-disk JSON-lines logs against the filter and
	// returns matching entries newest-first.
	Query(filter jsonfile.Filter) (jsonfile.QueryResult, error)

	// ListServices returns the set of service names with at least
	// one record on disk. Used by the WebUI service-selector.
	ListServices() ([]string, error)

	// Subscribe registers a live tail. The returned channel emits
	// raw JSON-line bytes; the unsubscribe func MUST be called when
	// the subscriber is done.
	Subscribe() (<-chan []byte, func())
}

// SetLogQuerier wires the daemon's log infrastructure into the
// /platform/logs handlers. When unset, /logs endpoints return 503 so
// the surface is honest rather than silently returning empty.
func (h *PlatformHandlers) SetLogQuerier(q LogQuerier) {
	h.logQuerier = q
}

// QueryLogs handles GET /api/v1/platform/logs. Query parameters:
//
//   - service=<name> (repeatable) — narrow to one or more services
//   - level=info|warn|error|debug — minimum severity (default info)
//   - since=<RFC3339> — earliest time (default unset)
//   - until=<RFC3339> — latest time (default unset)
//   - grep=<text> — substring filter on the message (case-insensitive)
//   - limit=<int> — max entries returned (default 200, ceiling 5000)
//
// Response is `{entries: [Entry], next_cursor: string}`. When
// next_cursor is non-empty, pass it back as `until=<cursor>` to fetch
// the next page (older entries).
func (h *PlatformHandlers) QueryLogs(w http.ResponseWriter, r *http.Request) {
	if h.logQuerier == nil {
		h.respWriter.Error500(w, r, ErrLogQuerierUnavailable{})
		return
	}
	filter, err := parseLogFilter(r)
	if err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	res, err := h.logQuerier.Query(filter)
	if err != nil {
		h.respWriter.Error500(w, r, err)
		return
	}
	h.respWriter.Success200(w, r, map[string]interface{}{
		"entries":     res.Entries,
		"next_cursor": res.NextCursor,
	})
}

// ListLogServices handles GET /api/v1/platform/logs/services. Used by
// the WebUI to populate the service-selector pulldown.
func (h *PlatformHandlers) ListLogServices(w http.ResponseWriter, r *http.Request) {
	if h.logQuerier == nil {
		h.respWriter.Error500(w, r, ErrLogQuerierUnavailable{})
		return
	}
	svcs, err := h.logQuerier.ListServices()
	if err != nil {
		h.respWriter.Error500(w, r, err)
		return
	}
	h.respWriter.Success200(w, r, map[string]interface{}{
		"services": svcs,
	})
}

// StreamLogs handles GET /api/v1/platform/logs/stream as a server-
// sent-events stream. Each event payload is a single JSON object —
// the raw JSON-line as written to disk — terminated by the standard
// SSE blank line. The browser EventSource reconnects automatically;
// per-subscription filtering matches QueryLogs.
//
// Connection is kept open until the client disconnects or the daemon
// shuts down. Slow consumers do not block writers — the underlying
// handler uses a bounded channel and drops on overflow.
func (h *PlatformHandlers) StreamLogs(w http.ResponseWriter, r *http.Request) {
	if h.logQuerier == nil {
		http.Error(w, "logs surface not available", http.StatusServiceUnavailable)
		return
	}
	filter, err := parseLogFilter(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported by ResponseWriter", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	ch, unsub := h.logQuerier.Subscribe()
	defer unsub()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case line, alive := <-ch:
			if !alive {
				return
			}
			if !filterMatchesLine(filter, line) {
				continue
			}
			// SSE frame: data: <json>\n\n
			if _, err := w.Write([]byte("data: ")); err != nil {
				return
			}
			// jsonfile already writes a trailing newline; strip it.
			if n := len(line); n > 0 && line[n-1] == '\n' {
				line = line[:n-1]
			}
			if _, err := w.Write(line); err != nil {
				return
			}
			if _, err := w.Write([]byte("\n\n")); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// parseLogFilter extracts a jsonfile.Filter from the request URL.
func parseLogFilter(r *http.Request) (jsonfile.Filter, error) {
	q := r.URL.Query()
	f := jsonfile.Filter{
		Services: q["service"],
		MinLevel: strings.ToUpper(strings.TrimSpace(q.Get("level"))),
		Grep:     q.Get("grep"),
	}
	if v := q.Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return jsonfile.Filter{}, fmt.Errorf("invalid since: %w", err)
		}
		f.Since = t
	}
	if v := q.Get("until"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return jsonfile.Filter{}, fmt.Errorf("invalid until: %w", err)
		}
		f.Until = t
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return jsonfile.Filter{}, fmt.Errorf("invalid limit: %w", err)
		}
		if n > 5000 {
			n = 5000
		}
		if n < 1 {
			n = 1
		}
		f.Limit = n
	}
	return f, nil
}

// filterMatchesLine applies the filter to a raw JSON-line. We parse
// only the fields we need to keep the streaming hot-path cheap;
// payloads always pass unmodified to the client.
func filterMatchesLine(f jsonfile.Filter, line []byte) bool {
	// Fast-path: empty filter accepts everything.
	if len(f.Services) == 0 && f.MinLevel == "" && f.Since.IsZero() && f.Until.IsZero() && f.Grep == "" {
		return true
	}
	var probe struct {
		Time    time.Time `json:"time"`
		Level   string    `json:"level"`
		Msg     string    `json:"msg"`
		Service string    `json:"service"`
	}
	if err := json.Unmarshal(line, &probe); err != nil {
		// Malformed line — surface it to the client rather than
		// silently dropping; the client can decide what to do.
		return true
	}
	entry := jsonfile.Entry{
		Time:    probe.Time,
		Level:   probe.Level,
		Msg:     probe.Msg,
		Service: probe.Service,
	}
	return f.Matches(entry)
}

// ErrLogQuerierUnavailable is returned when /logs endpoints are hit
// before SetLogQuerier has been wired.
type ErrLogQuerierUnavailable struct{}

func (ErrLogQuerierUnavailable) Error() string {
	return "platform: log querier is not configured on this daemon"
}
