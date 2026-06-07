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

// Package jsonfile provides a structured JSON-lines slog handler with size
// rotation, in-memory broadcast for live tail subscribers, and a Query
// helper that scans rotated files. It is intentionally Alpine-friendly:
// no systemd / journald dependency; every event lands on disk as one
// JSON object per line under <log_dir>/<service>.jsonl with rotated
// historical files named <service>.jsonl.<UTC-RFC3339-no-colons>.
package jsonfile

import (
	"strings"
	"time"
)

// Entry is the in-memory shape of a single log line. The on-disk JSON
// layout is whatever Go's stdlib slog.JSONHandler emits — Entry is the
// parsed form consumed by Query / Subscribe.
type Entry struct {
	Time    time.Time      `json:"time"`
	Level   string         `json:"level"`
	Msg     string         `json:"msg"`
	Service string         `json:"service"`
	Source  string         `json:"source,omitempty"`
	Attrs   map[string]any `json:"attrs,omitempty"`
}

// Filter narrows the result set for Query and Subscribe.
//
// Empty fields mean "no constraint". MinLevel is matched
// case-insensitively against the canonical slog level strings (DEBUG,
// INFO, WARN, ERROR). MaxAge caps how far back Query walks files; older
// rotated files are skipped without parsing.
type Filter struct {
	Services []string
	MinLevel string
	Since    time.Time
	Until    time.Time
	Grep     string
	Limit    int
	Cursor   string
}

// Matches reports whether the entry passes the filter. Exported so
// REST stream handlers can apply the same filter logic to raw bytes
// without round-tripping through the on-disk path.
func (f Filter) Matches(e Entry) bool {
	return f.matches(e)
}

// matches reports whether the entry passes the filter.
func (f Filter) matches(e Entry) bool {
	if len(f.Services) > 0 {
		hit := false
		for _, s := range f.Services {
			if strings.EqualFold(s, e.Service) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	if f.MinLevel != "" {
		if levelRank(e.Level) < levelRank(f.MinLevel) {
			return false
		}
	}
	if !f.Since.IsZero() && e.Time.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && e.Time.After(f.Until) {
		return false
	}
	if f.Grep != "" && !strings.Contains(strings.ToLower(e.Msg), strings.ToLower(f.Grep)) {
		return false
	}
	return true
}

// levelRank returns an ordered rank for the canonical slog level
// strings. Unknown values rank as INFO so a typo doesn't accidentally
// hide everything.
func levelRank(s string) int {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "DEBUG":
		return 0
	case "INFO":
		return 1
	case "WARN", "WARNING":
		return 2
	case "ERROR":
		return 3
	case "FATAL", "CRITICAL":
		return 4
	default:
		return 1
	}
}
