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

package swtpm

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeSWTPMOnPath puts a stand-in "swtpm" that idles until signalled first
// on PATH, so Start runs without the real emulator.
func fakeSWTPMOnPath(t *testing.T) {
	t.Helper()
	binDir := t.TempDir()
	script := "#!/bin/sh\nexec sleep 300\n"
	require.NoError(t, os.WriteFile(filepath.Join(binDir, "swtpm"), []byte(script), 0o755))
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// A vTPM started by an API request must outlive the request: the daemon is
// not bound to the start context, so cancelling it never kills swtpm.
func TestStart_DaemonOutlivesStartContext(t *testing.T) {
	fakeSWTPMOnPath(t)
	s := &SWTPM{
		config: &Config{StateDir: t.TempDir(), SocketPath: filepath.Join(t.TempDir(), "swtpm.sock")},
		logger: logging.DefaultLogger(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	require.NoError(t, s.Start(ctx))
	t.Cleanup(func() { assert.NoError(t, s.Stop()) })
	cancel()

	assert.Nil(t, s.cmd.Cancel, "the start context must not own the daemon's lifetime")
	assert.True(t, s.IsRunning(), "swtpm must keep running after the start context ends")
}

func TestStart_CancelledContextRefusesToStart(t *testing.T) {
	fakeSWTPMOnPath(t)
	s := &SWTPM{
		config: &Config{StateDir: t.TempDir(), SocketPath: filepath.Join(t.TempDir(), "swtpm.sock")},
		logger: logging.DefaultLogger(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := s.Start(ctx)
	require.ErrorIs(t, err, context.Canceled)
	assert.False(t, s.IsRunning())
}
