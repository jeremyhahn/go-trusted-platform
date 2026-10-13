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
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

func newTestHandler(t *testing.T, opts Options) (*Handler, string) {
	t.Helper()
	dir := t.TempDir()
	if opts.Dir == "" {
		opts.Dir = dir
	}
	if opts.Service == "" {
		opts.Service = "test"
	}
	h, err := NewHandler(opts)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })
	return h, opts.Dir
}

func TestNewHandler_InvalidConfig(t *testing.T) {
	if _, err := NewHandler(Options{Service: "x"}); err == nil {
		t.Fatal("expected error when Dir is empty")
	}
	if _, err := NewHandler(Options{Dir: t.TempDir()}); err == nil {
		t.Fatal("expected error when Service is empty")
	}
}

func TestHandler_WritesJSONLines(t *testing.T) {
	h, dir := newTestHandler(t, Options{Service: "ca"})
	l := slog.New(h)
	l.Info("issued certificate", "serial", "AB12", "duration_ms", 42)

	data, err := os.ReadFile(filepath.Join(dir, "ca.jsonl"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}
	var got Entry
	if err := json.Unmarshal([]byte(lines[0]), &got); err != nil {
		t.Fatalf("unmarshal: %v\nline: %s", err, lines[0])
	}
	if got.Service != "ca" {
		t.Errorf("Service = %q, want ca", got.Service)
	}
	if got.Level != "INFO" {
		t.Errorf("Level = %q, want INFO", got.Level)
	}
	if got.Msg != "issued certificate" {
		t.Errorf("Msg = %q", got.Msg)
	}
	if v, _ := got.Attrs["serial"].(string); v != "AB12" {
		t.Errorf("attrs.serial = %v, want AB12", got.Attrs["serial"])
	}
	if v, _ := got.Attrs["duration_ms"].(float64); v != 42 {
		t.Errorf("attrs.duration_ms = %v, want 42", got.Attrs["duration_ms"])
	}
}

func TestHandler_Subscribe_GetsLiveLines(t *testing.T) {
	h, _ := newTestHandler(t, Options{Service: "live"})
	ch, unsub := h.Subscribe()
	defer unsub()

	l := slog.New(h)
	go func() {
		l.Info("hello")
		l.Warn("world", "k", "v")
	}()

	got := 0
	timeout := time.After(500 * time.Millisecond)
	for got < 2 {
		select {
		case line := <-ch:
			if len(line) == 0 {
				t.Fatal("got empty line")
			}
			got++
		case <-timeout:
			t.Fatalf("timed out after %d lines", got)
		}
	}
}

func TestHandler_Rotation(t *testing.T) {
	// MaxSize=1 forces rotation on every record. After three writes
	// we should see at least three files (one active + two rotated).
	h, dir := newTestHandler(t, Options{Service: "rot", MaxSize: 1})
	l := slog.New(h)
	l.Info("a")
	l.Info("b")
	l.Info("c")

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) < 3 {
		t.Fatalf("expected >=3 files, got %d", len(entries))
	}
}

func TestQuery_FiltersByLevelAndService(t *testing.T) {
	h, dir := newTestHandler(t, Options{Service: "filter"})
	l := slog.New(h)
	l.Debug("low")
	l.Info("normal")
	l.Error("boom")

	got, err := Query(dir, Filter{MinLevel: "INFO"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got.Entries) != 2 {
		t.Fatalf("expected 2 entries at INFO+, got %d", len(got.Entries))
	}

	got, err = Query(dir, Filter{Services: []string{"other"}})
	if err != nil {
		t.Fatalf("Query (other): %v", err)
	}
	if len(got.Entries) != 0 {
		t.Fatalf("expected 0 entries for unknown service, got %d", len(got.Entries))
	}

	got, err = Query(dir, Filter{Grep: "boom"})
	if err != nil {
		t.Fatalf("Query (grep): %v", err)
	}
	if len(got.Entries) != 1 || got.Entries[0].Msg != "boom" {
		t.Fatalf("grep result = %+v", got.Entries)
	}
}

// TestHandler_NamesPlatformLevels proves the platform's custom levels land
// on disk under names the level filter ranks. Written as slog's default
// "ERROR+12", a security record ranked as INFO and vanished from an
// ERROR-and-above view.
func TestHandler_NamesPlatformLevels(t *testing.T) {
	h, dir := newTestHandler(t, Options{Service: "levels"})
	l := slog.New(h)
	ctx := context.Background()
	l.Log(ctx, slog.LevelWarn+1, "unregistered")
	l.Log(ctx, logging.LevelFatal, "fatal")
	l.Log(ctx, logging.LevelSecurity, "security_log")

	got, err := Query(dir, Filter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	want := map[string]string{
		"unregistered": "WARN+1",
		"fatal":        "FATAL",
		"security_log": "SECURITY",
	}
	if len(got.Entries) != len(want) {
		t.Fatalf("expected %d entries, got %d", len(want), len(got.Entries))
	}
	for _, e := range got.Entries {
		if e.Level != want[e.Msg] {
			t.Errorf("%s: Level = %q, want %q", e.Msg, e.Level, want[e.Msg])
		}
	}

	got, err = Query(dir, Filter{MinLevel: "ERROR"})
	if err != nil {
		t.Fatalf("Query (ERROR): %v", err)
	}
	if len(got.Entries) != 2 {
		t.Fatalf("expected fatal and security at ERROR+, got %+v", got.Entries)
	}

	got, err = Query(dir, Filter{MinLevel: "security"})
	if err != nil {
		t.Fatalf("Query (security): %v", err)
	}
	if len(got.Entries) != 1 || got.Entries[0].Msg != "security_log" {
		t.Fatalf("expected only the security record, got %+v", got.Entries)
	}
}

func TestLevelRank_OrdersSecurityAboveFatal(t *testing.T) {
	if levelRank("SECURITY") <= levelRank("FATAL") {
		t.Errorf("SECURITY must outrank FATAL so no level filter hides it")
	}
	if levelRank("ERROR+12") != levelRank("INFO") {
		t.Errorf("an unknown level must rank as INFO")
	}
}

func TestListServices(t *testing.T) {
	dir := t.TempDir()
	if _, err := NewHandler(Options{Dir: dir, Service: "alpha"}); err != nil {
		t.Fatalf("alpha: %v", err)
	}
	hb, err := NewHandler(Options{Dir: dir, Service: "beta"})
	if err != nil {
		t.Fatalf("beta: %v", err)
	}
	defer hb.Close()
	// Force at least one write so the file actually appears.
	slog.New(hb).Info("hi")

	svcs, err := ListServices(dir)
	if err != nil {
		t.Fatalf("ListServices: %v", err)
	}
	want := map[string]bool{"alpha": true, "beta": true}
	for _, s := range svcs {
		delete(want, s)
	}
	if len(want) != 0 {
		t.Fatalf("missing services: %v (got %v)", want, svcs)
	}
}

func TestHandler_Enabled(t *testing.T) {
	h, _ := newTestHandler(t, Options{Service: "lvl", Level: slog.LevelWarn})
	if h.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("expected INFO to be disabled at WARN min level")
	}
	if !h.Enabled(context.Background(), slog.LevelError) {
		t.Error("expected ERROR to be enabled at WARN min level")
	}
}

func TestHandler_WithAttrs_Propagates(t *testing.T) {
	h, dir := newTestHandler(t, Options{Service: "wa"})
	l := slog.New(h).With("tenant", "default")
	l.Info("first")

	data, _ := os.ReadFile(filepath.Join(dir, "wa.jsonl"))
	var e Entry
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(data))), &e); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if e.Attrs["tenant"] != "default" {
		t.Errorf("attrs.tenant = %v, want default", e.Attrs["tenant"])
	}
}
