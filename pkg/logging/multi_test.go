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
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"
)

type captureHandler struct {
	records []slog.Record
	err     error
	level   slog.Level
}

func (c *captureHandler) Enabled(_ context.Context, l slog.Level) bool {
	return l >= c.level
}
func (c *captureHandler) Handle(_ context.Context, r slog.Record) error {
	c.records = append(c.records, r.Clone())
	return c.err
}
func (c *captureHandler) WithAttrs(_ []slog.Attr) slog.Handler { return c }
func (c *captureHandler) WithGroup(_ string) slog.Handler      { return c }

func TestMultiHandler_FansOut(t *testing.T) {
	a := &captureHandler{level: slog.LevelDebug}
	b := &captureHandler{level: slog.LevelDebug}
	m := NewMultiHandler(a, b)
	l := slog.New(m)
	l.Info("hi")
	if len(a.records) != 1 || len(b.records) != 1 {
		t.Fatalf("expected both handlers to receive 1 record, got a=%d b=%d",
			len(a.records), len(b.records))
	}
}

func TestMultiHandler_SkipsDisabled(t *testing.T) {
	a := &captureHandler{level: slog.LevelError}
	b := &captureHandler{level: slog.LevelDebug}
	m := NewMultiHandler(a, b)
	slog.New(m).Info("hi")
	if len(a.records) != 0 {
		t.Errorf("expected ERROR-only handler to skip INFO, got %d", len(a.records))
	}
	if len(b.records) != 1 {
		t.Errorf("expected DEBUG handler to receive INFO, got %d", len(b.records))
	}
}

func TestMultiHandler_JoinsErrors(t *testing.T) {
	errA := errors.New("a failed")
	errB := errors.New("b failed")
	a := &captureHandler{level: slog.LevelDebug, err: errA}
	b := &captureHandler{level: slog.LevelDebug, err: errB}
	m := NewMultiHandler(a, b)
	err := m.Handle(context.Background(), slog.Record{Level: slog.LevelInfo})
	if err == nil {
		t.Fatal("expected joined error")
	}
	if !errors.Is(err, errA) || !errors.Is(err, errB) {
		t.Errorf("expected joined error to contain both children, got %v", err)
	}
}

func TestMultiHandler_NilChildrenIgnored(t *testing.T) {
	a := &captureHandler{level: slog.LevelDebug}
	m := NewMultiHandler(nil, a, nil)
	slog.New(m).Info("hi")
	if len(a.records) != 1 {
		t.Fatalf("expected 1 record on non-nil handler, got %d", len(a.records))
	}
}

func TestMultiHandler_EnabledOR(t *testing.T) {
	a := &captureHandler{level: slog.LevelError}
	b := &captureHandler{level: slog.LevelDebug}
	m := NewMultiHandler(a, b)
	if !m.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("expected Enabled to be true when any child accepts")
	}
}

func TestWrapHandler_LogsThroughHandler(t *testing.T) {
	var buf bytes.Buffer
	h := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	l := WrapHandler(h)
	l.Info("wrapped")
	if buf.Len() == 0 {
		t.Fatal("expected output from wrapped handler")
	}
}
