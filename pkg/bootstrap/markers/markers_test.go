package markers

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestNewRejectsEmptyBaseDir(t *testing.T) {
	if _, err := New(""); err == nil {
		t.Fatal("New(\"\") must return an error")
	}
}

func TestNewCreatesDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "markers")
	m, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if m.BaseDir() != dir {
		t.Fatalf("BaseDir = %q, want %q", m.BaseDir(), dir)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("baseDir not created: %v", err)
	}
}

func TestSetThenHas(t *testing.T) {
	m := mustNew(t)
	if has, err := m.Has("bootstrap.test"); err != nil || has {
		t.Fatalf("unexpected pre-state: has=%v err=%v", has, err)
	}
	if err := m.Set("bootstrap.test"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if has, err := m.Has("bootstrap.test"); err != nil || !has {
		t.Fatalf("expected has=true; got has=%v err=%v", has, err)
	}
}

func TestSetIsIdempotentAndPreservesTimestamp(t *testing.T) {
	m := mustNew(t)
	if err := m.Set("bootstrap.idem"); err != nil {
		t.Fatalf("first Set: %v", err)
	}
	first, err := os.ReadFile(filepath.Join(m.BaseDir(), "bootstrap.idem.done"))
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}
	if err := m.Set("bootstrap.idem"); err != nil {
		t.Fatalf("second Set: %v", err)
	}
	second, err := os.ReadFile(filepath.Join(m.BaseDir(), "bootstrap.idem.done"))
	if err != nil {
		t.Fatalf("re-read marker: %v", err)
	}
	if string(first) != string(second) {
		t.Fatalf("Set rewrote timestamp: first=%q second=%q", first, second)
	}
}

func TestDoOnceRunsFnOnce(t *testing.T) {
	m := mustNew(t)
	calls := 0
	fn := func(context.Context) error { calls++; return nil }
	for i := 0; i < 5; i++ {
		if err := m.DoOnce(context.Background(), "bootstrap.dn", fn); err != nil {
			t.Fatalf("DoOnce[%d]: %v", i, err)
		}
	}
	if calls != 1 {
		t.Fatalf("fn ran %d times, want 1", calls)
	}
}

func TestDoOnceErrorDoesNotSetMarker(t *testing.T) {
	m := mustNew(t)
	failErr := errors.New("boom")
	if err := m.DoOnce(context.Background(), "bootstrap.fail", func(context.Context) error { return failErr }); !errors.Is(err, failErr) {
		t.Fatalf("DoOnce: want %v, got %v", failErr, err)
	}
	if has, _ := m.Has("bootstrap.fail"); has {
		t.Fatal("marker set despite fn error")
	}
}

func TestDoOnceRespectsCancelledCtx(t *testing.T) {
	m := mustNew(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	err := m.DoOnce(ctx, "bootstrap.ctx", func(context.Context) error { called = true; return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	if called {
		t.Fatal("fn ran despite cancelled ctx")
	}
}

func TestClearRemovesMarker(t *testing.T) {
	m := mustNew(t)
	if err := m.Set("bootstrap.clear"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := m.Clear("bootstrap.clear"); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if has, _ := m.Has("bootstrap.clear"); has {
		t.Fatal("marker still present after Clear")
	}
	// Clear on missing marker is a no-op.
	if err := m.Clear("bootstrap.clear"); err != nil {
		t.Fatalf("Clear (missing): %v", err)
	}
}

func TestNameValidation(t *testing.T) {
	m := mustNew(t)
	bad := []string{"", "../escape", "with/slash", "with\\backslash", "with..dots"}
	for _, name := range bad {
		if _, err := m.Has(name); err == nil {
			t.Fatalf("Has(%q) accepted invalid name", name)
		}
		if err := m.Set(name); err == nil {
			t.Fatalf("Set(%q) accepted invalid name", name)
		}
	}
}

func mustNew(t *testing.T) *Markers {
	t.Helper()
	m, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m
}
