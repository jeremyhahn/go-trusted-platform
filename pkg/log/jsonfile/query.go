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

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// QueryResult is the paginated output of a Query call. Entries are
// ordered newest-first. NextCursor is non-empty when more results are
// available; pass it back as Filter.Cursor to fetch the next page.
type QueryResult struct {
	Entries    []Entry
	NextCursor string
}

// Query walks files on disk matching the filter and returns the matching
// entries, newest first. Both the live <service>.jsonl and any rotated
// <service>.jsonl.<ts> files are scanned. Rotations older than
// Filter.Since are skipped without parsing.
//
// The Cursor scheme is opaque; today it encodes the path + line index
// where the next page begins. Callers must treat it as opaque.
func Query(dir string, filter Filter) (QueryResult, error) {
	if dir == "" {
		return QueryResult{}, ErrInvalidConfig{Field: "Dir", Reason: "cannot be empty"}
	}
	files, err := listLogFiles(dir, filter.Services)
	if err != nil {
		return QueryResult{}, err
	}
	if !filter.Since.IsZero() {
		files = pruneOldFiles(files, filter.Since)
	}
	// newest first
	sort.Slice(files, func(i, j int) bool {
		return files[i].mtime.After(files[j].mtime)
	})

	limit := filter.Limit
	if limit <= 0 {
		limit = 200
	}

	var out []Entry
	for _, f := range files {
		entries, err := scanFile(f.path, filter)
		if err != nil {
			return QueryResult{}, err
		}
		out = append(out, entries...)
		if len(out) >= limit*4 {
			break
		}
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].Time.After(out[j].Time)
	})

	if len(out) > limit {
		// Cursor encoding: timestamp of the last returned entry as
		// RFC3339Nano. The next call passes the same filter with
		// Until=that-timestamp.
		next := out[limit-1].Time.UTC().Format(time.RFC3339Nano)
		return QueryResult{Entries: out[:limit], NextCursor: next}, nil
	}
	return QueryResult{Entries: out}, nil
}

// ListServices returns the set of service names with at least one
// JSON-lines file in dir. Used by the WebUI service-selector.
func ListServices(dir string) ([]string, error) {
	if dir == "" {
		return nil, ErrInvalidConfig{Field: "Dir", Reason: "cannot be empty"}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, ErrIO{Op: "readdir", Path: dir, Err: err}
	}
	seen := map[string]struct{}{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".jsonl") &&
			!strings.Contains(name, ".jsonl.") {
			continue
		}
		// active: foo.jsonl   rotated: foo.jsonl.<ts>
		base := name
		if i := strings.Index(base, ".jsonl"); i > 0 {
			base = base[:i]
		}
		if base == "" {
			continue
		}
		seen[base] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out, nil
}

type logFile struct {
	path  string
	mtime time.Time
}

func listLogFiles(dir string, services []string) ([]logFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, ErrIO{Op: "readdir", Path: dir, Err: err}
	}
	wantedSet := map[string]struct{}{}
	for _, s := range services {
		wantedSet[strings.ToLower(s)] = struct{}{}
	}

	var out []logFile
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.Contains(name, ".jsonl") {
			continue
		}
		base := name
		if i := strings.Index(base, ".jsonl"); i > 0 {
			base = base[:i]
		}
		if len(wantedSet) > 0 {
			if _, ok := wantedSet[strings.ToLower(base)]; !ok {
				continue
			}
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, logFile{filepath.Join(dir, name), info.ModTime()})
	}
	return out, nil
}

func pruneOldFiles(files []logFile, since time.Time) []logFile {
	kept := files[:0]
	for _, f := range files {
		if f.mtime.Before(since) {
			continue
		}
		kept = append(kept, f)
	}
	return kept
}

// scanFile reads a JSON-lines file and returns the entries matching
// the filter. The file is closed before returning.
func scanFile(path string, filter Filter) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrIO{Op: "open", Path: path, Err: err}
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	// raise scanner buffer ceiling; default 64KB is too small for
	// stack traces or structured payloads
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	var out []Entry
	for sc.Scan() {
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			continue
		}
		if filter.matches(e) {
			out = append(out, e)
		}
	}
	if err := sc.Err(); err != nil && err != io.EOF {
		return nil, ErrIO{Op: "scan", Path: path, Err: err}
	}
	return out, nil
}
