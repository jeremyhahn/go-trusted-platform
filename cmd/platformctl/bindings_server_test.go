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

package main

import (
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
)

// The config path the GUI passes is the one the daemon reads: a missing
// file fails Start instead of silently falling back to the default search.
func TestEmbeddedServerBinding_StartReadsTheGivenConfig(t *testing.T) {
	t.Cleanup(viper.Reset)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	binding := NewEmbeddedServerBinding(logger, NewConnectionBinding(logger))

	err := binding.Start(filepath.Join(t.TempDir(), "missing.yaml"), false)

	var serverErr *EmbeddedServerError
	if !errors.As(err, &serverErr) || serverErr.Op != "start" {
		t.Fatalf("err = %v, want EmbeddedServerError{Op: start}", err)
	}
	var hostErr daemon.ErrEmbeddedHostFailed
	if !errors.As(err, &hostErr) || hostErr.Op != "init" {
		t.Fatalf("err = %v, want it to wrap ErrEmbeddedHostFailed{Op: init}", err)
	}
	if binding.IsRunning() {
		t.Fatal("binding reports running after a failed start")
	}
}

// Stopping a binding that never started is a no-op.
func TestEmbeddedServerBinding_StopWithoutStartIsANoop(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	binding := NewEmbeddedServerBinding(logger, NewConnectionBinding(logger))

	if err := binding.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}
