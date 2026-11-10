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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// readEntries decodes every JSON line of path into a generic map.
func readEntries(t *testing.T, path string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("decode %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

// writeFile writes data to path and sets its modification time.
func writeFile(t *testing.T, path, data string, mod time.Time) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o640); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	if err := os.Chtimes(path, mod, mod); err != nil {
		t.Fatalf("chtimes %s: %v", path, err)
	}
}

func TestErrors_MessagesAndUnwrap(t *testing.T) {
	cfg := ErrInvalidConfig{Field: "Dir", Reason: "cannot be empty"}
	if got, want := cfg.Error(), "jsonfile: Dir: cannot be empty"; got != want {
		t.Fatalf("ErrInvalidConfig.Error() = %q, want %q", got, want)
	}
	ioErr := ErrIO{Op: "open", Path: "/x", Err: fs.ErrPermission}
	if got := ioErr.Error(); !strings.Contains(got, "jsonfile: open /x:") {
		t.Fatalf("ErrIO.Error() = %q", got)
	}
	if !errors.Is(ioErr, fs.ErrPermission) {
		t.Fatal("ErrIO does not unwrap to its cause")
	}
}

func TestNewHandler_IOErrors(t *testing.T) {
	base := t.TempDir()
	plain := filepath.Join(base, "plain")
	writeFile(t, plain, "x", time.Now())

	blocked := filepath.Join(base, "blocked")
	if err := os.MkdirAll(filepath.Join(blocked, "svc.jsonl"), 0o755); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		dir  string
		op   string
	}{
		{"dir under a regular file", filepath.Join(plain, "sub"), "mkdir"},
		{"active path is a directory", blocked, "open"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewHandler(Options{Dir: tc.dir, Service: "svc"})
			var ioErr ErrIO
			if !errors.As(err, &ioErr) {
				t.Fatalf("err = %v, want ErrIO", err)
			}
			if ioErr.Op != tc.op {
				t.Fatalf("Op = %q, want %q", ioErr.Op, tc.op)
			}
		})
	}
}

func TestHandler_WithGroup_PrefixesKeysAndForwardsToInner(t *testing.T) {
	var inner bytes.Buffer
	h, dir := newTestHandler(t, Options{Inner: slog.NewJSONHandler(&inner, nil)})

	logger := slog.New(h).WithGroup("outer").WithGroup("mid")
	logger.Info("grouped", "k", "v", slog.Group("g", slog.String("a", "1")), slog.Any("", "dropped"))

	entries := readEntries(t, filepath.Join(dir, "test.jsonl"))
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	attrs, ok := entries[0]["attrs"].(map[string]any)
	if !ok {
		t.Fatalf("attrs missing: %v", entries[0])
	}
	if attrs["outer.mid.k"] != "v" {
		t.Fatalf("grouped key missing: %v", attrs)
	}
	g, ok := attrs["outer.mid.g"].(map[string]any)
	if !ok || g["outer.mid.g.a"] != "1" {
		t.Fatalf("nested group = %v", attrs["outer.mid.g"])
	}
	if len(attrs) != 2 {
		t.Fatalf("empty-key attr was not dropped: %v", attrs)
	}
	if !strings.Contains(inner.String(), `"outer":{"mid":{"k":"v"`) {
		t.Fatalf("inner handler did not receive the group: %s", inner.String())
	}
}

func TestHandler_WithAttrs_ForwardsToInner(t *testing.T) {
	var inner bytes.Buffer
	h, _ := newTestHandler(t, Options{Inner: slog.NewJSONHandler(&inner, nil)})
	slog.New(h).With("req", "r1").Info("hello")
	if !strings.Contains(inner.String(), `"req":"r1"`) {
		t.Fatalf("inner handler missing attrs: %s", inner.String())
	}
}

func TestHandler_ServiceAndSourceAttrsArePromoted(t *testing.T) {
	h, dir := newTestHandler(t, Options{})
	slog.New(h).Info("m", "service", "other", "source", "file.go:1")

	e := readEntries(t, filepath.Join(dir, "test.jsonl"))[0]
	if e["service"] != "other" {
		t.Fatalf("service = %v, want other", e["service"])
	}
	if e["source"] != "file.go:1" {
		t.Fatalf("source = %v", e["source"])
	}
	if _, ok := e["attrs"]; ok {
		t.Fatalf("promoted attrs left in attrs: %v", e["attrs"])
	}
}

func TestHandler_HandleAfterCloseReturnsWriteError(t *testing.T) {
	h, _ := newTestHandler(t, Options{MaxSize: 1})
	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("second Close = %v, want nil", err)
	}
	err := h.Handle(context.Background(), slog.NewRecord(time.Now(), slog.LevelInfo, "late", 0))
	var ioErr ErrIO
	if !errors.As(err, &ioErr) || ioErr.Op != "write" {
		t.Fatalf("err = %v, want ErrIO write", err)
	}
}

func TestHandler_RotateFailsWhenActiveFileVanished(t *testing.T) {
	h, dir := newTestHandler(t, Options{MaxSize: 150})
	logger := slog.New(h)
	logger.Info("first")
	if err := os.Remove(filepath.Join(dir, "test.jsonl")); err != nil {
		t.Fatal(err)
	}
	err := h.Handle(context.Background(), slog.NewRecord(time.Now(), slog.LevelInfo, strings.Repeat("x", 200), 0))
	var ioErr ErrIO
	if !errors.As(err, &ioErr) || ioErr.Op != "rotate" {
		t.Fatalf("err = %v, want ErrIO rotate", err)
	}
}

func TestHandler_RotationCullsByMaxAge(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "test.jsonl.20000101T000000.000000000Z")
	recent := filepath.Join(dir, "test.jsonl.20990101T000000.000000000Z")
	foreign := filepath.Join(dir, "other.jsonl.20000101T000000.000000000Z")
	writeFile(t, old, "{}\n", time.Now().Add(-2*time.Hour))
	writeFile(t, recent, "{}\n", time.Now().Add(-time.Minute))
	writeFile(t, foreign, "{}\n", time.Now().Add(-2*time.Hour))
	if err := os.Mkdir(filepath.Join(dir, "test.jsonl.dir"), 0o755); err != nil {
		t.Fatal(err)
	}

	h, _ := newTestHandler(t, Options{Dir: dir, MaxSize: 150, MaxAge: time.Hour, MaxFiles: 10})
	logger := slog.New(h)
	logger.Info("first")
	logger.Info(strings.Repeat("y", 200))

	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatalf("file older than MaxAge was kept: %v", err)
	}
	for _, p := range []string{recent, foreign, filepath.Join(dir, "test.jsonl.dir")} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s removed: %v", p, err)
		}
	}
	matches, err := filepath.Glob(filepath.Join(dir, "test.jsonl.2*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 2 {
		t.Fatalf("rotated files = %v, want recent plus the new rotation", matches)
	}
}

func TestHandler_RotationWithoutRetentionKeepsEverything(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "test.jsonl.20000101T000000.000000000Z")
	writeFile(t, old, "{}\n", time.Now().Add(-1000*time.Hour))

	h, _ := newTestHandler(t, Options{Dir: dir, MaxSize: 150})
	logger := slog.New(h)
	logger.Info("first")
	logger.Info(strings.Repeat("z", 200))

	if _, err := os.Stat(old); err != nil {
		t.Fatalf("old file removed without a retention policy: %v", err)
	}
}

func TestFilter_Matches(t *testing.T) {
	now := time.Now()
	e := Entry{Time: now, Level: "WARNING", Msg: "Disk Full", Service: "Storage"}
	cases := []struct {
		name   string
		filter Filter
		want   bool
	}{
		{"empty filter", Filter{}, true},
		{"service case-insensitive", Filter{Services: []string{"storage"}}, true},
		{"other service", Filter{Services: []string{"dns"}}, false},
		{"level at minimum", Filter{MinLevel: "warn"}, true},
		{"level below minimum", Filter{MinLevel: "CRITICAL"}, false},
		{"unknown min level ranks as info", Filter{MinLevel: "bogus"}, true},
		{"since before entry", Filter{Since: now.Add(-time.Second)}, true},
		{"since after entry", Filter{Since: now.Add(time.Second)}, false},
		{"until before entry", Filter{Until: now.Add(-time.Second)}, false},
		{"grep case-insensitive", Filter{Grep: "disk"}, true},
		{"grep miss", Filter{Grep: "network"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.filter.Matches(e); got != tc.want {
				t.Fatalf("Matches = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestQuery_Errors(t *testing.T) {
	plain := filepath.Join(t.TempDir(), "plain")
	writeFile(t, plain, "x", time.Now())

	if _, err := Query("", Filter{}); !errors.As(err, new(ErrInvalidConfig)) {
		t.Fatalf("Query empty dir err = %v, want ErrInvalidConfig", err)
	}
	if _, err := Query(plain, Filter{}); !errors.As(err, new(ErrIO)) {
		t.Fatalf("Query on a file err = %v, want ErrIO", err)
	}
	res, err := Query(plain+"-missing", Filter{})
	if err != nil || len(res.Entries) != 0 {
		t.Fatalf("Query missing dir = %v, %v; want empty, nil", res, err)
	}

	if _, err := ListServices(""); !errors.As(err, new(ErrInvalidConfig)) {
		t.Fatalf("ListServices empty dir err = %v, want ErrInvalidConfig", err)
	}
	if _, err := ListServices(plain); !errors.As(err, new(ErrIO)) {
		t.Fatalf("ListServices on a file err = %v, want ErrIO", err)
	}
	svcs, err := ListServices(plain + "-missing")
	if err != nil || svcs != nil {
		t.Fatalf("ListServices missing dir = %v, %v; want nil, nil", svcs, err)
	}

	if _, err := scanFile(plain+"-missing", Filter{}); !errors.As(err, new(ErrIO)) {
		t.Fatalf("scanFile missing err = %v, want ErrIO", err)
	}
}

func TestQuery_SinceLimitAndCursor(t *testing.T) {
	dir := t.TempDir()
	base := time.Now().UTC().Add(-time.Hour)
	var lines []string
	for i := 0; i < 3; i++ {
		ts := base.Add(time.Duration(i) * time.Minute).Format(time.RFC3339Nano)
		lines = append(lines, `{"time":"`+ts+`","level":"INFO","msg":"m","service":"svc"}`)
	}
	lines = append(lines, "not json")
	writeFile(t, filepath.Join(dir, "svc.jsonl"), strings.Join(lines, "\n")+"\n", time.Now())
	writeFile(t, filepath.Join(dir, "svc.jsonl.old"),
		`{"time":"2000-01-01T00:00:00Z","level":"INFO","msg":"stale","service":"svc"}`+"\n",
		time.Now().Add(-48*time.Hour))
	if err := os.Mkdir(filepath.Join(dir, "x.jsonl"), 0o755); err != nil {
		t.Fatal(err)
	}

	res, err := Query(dir, Filter{Since: base.Add(-time.Hour), Limit: 2})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(res.Entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(res.Entries))
	}
	if !res.Entries[0].Time.Equal(base.Add(2 * time.Minute)) {
		t.Fatalf("first entry not newest: %v", res.Entries[0].Time)
	}
	if want := base.Add(time.Minute).Format(time.RFC3339Nano); res.NextCursor != want {
		t.Fatalf("NextCursor = %q, want %q", res.NextCursor, want)
	}

	all, err := Query(dir, Filter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(all.Entries) != 4 || all.NextCursor != "" {
		t.Fatalf("unfiltered = %d entries, cursor %q; want 4, empty", len(all.Entries), all.NextCursor)
	}
}

func TestQuerier_DelegatesToHandlerDir(t *testing.T) {
	h, _ := newTestHandler(t, Options{Service: "qsvc"})
	q := NewQuerier(h)
	ch, cancel := q.Subscribe()
	defer cancel()

	slog.New(h).Info("via querier")

	select {
	case line := <-ch:
		if !bytes.Contains(line, []byte("via querier")) {
			t.Fatalf("subscriber line = %s", line)
		}
	default:
		t.Fatal("subscriber received nothing")
	}
	res, err := q.Query(Filter{Grep: "querier"})
	if err != nil || len(res.Entries) != 1 {
		t.Fatalf("Query = %v, %v; want one entry", res, err)
	}
	svcs, err := q.ListServices()
	if err != nil || len(svcs) != 1 || svcs[0] != "qsvc" {
		t.Fatalf("ListServices = %v, %v; want [qsvc]", svcs, err)
	}
}
