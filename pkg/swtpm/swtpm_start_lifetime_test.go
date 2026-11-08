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
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeSWTPMOnPath puts a stand-in "swtpm" that idles until signalled first
// on PATH, so Start runs without the real emulator.
func fakeSWTPMOnPath(t *testing.T) {
	t.Helper()
	fakeSWTPMScriptOnPath(t, "#!/bin/sh\nexec sleep 300\n")
}

// fakeSWTPMScriptOnPath puts script on PATH as the swtpm binary.
func fakeSWTPMScriptOnPath(t *testing.T, script string) {
	t.Helper()
	binDir := t.TempDir()
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

// A socket path past the Unix limit runs swtpm in a short temp directory.
// Stop removes that directory, so it must hand the configured path back: a
// restart that kept the removed temp socket would bind in a directory that
// no longer exists, and every reboot of a VM would lose its TPM.
func TestStart_RelocatedSocketIsRestoredOnStop(t *testing.T) {
	fakeSWTPMOnPath(t)
	configured := filepath.Join(t.TempDir(), strings.Repeat("s", unixSocketPathMax), "swtpm.sock")
	s := &SWTPM{
		config: &Config{StateDir: t.TempDir(), SocketPath: configured},
		logger: logging.DefaultLogger(),
	}

	require.NoError(t, s.Start(context.Background()))
	first := s.SocketPath()
	assert.NotEqual(t, configured, first, "a socket past the Unix limit must run in a temp directory")
	assert.DirExists(t, filepath.Dir(first))
	require.NoError(t, s.Stop())

	assert.Equal(t, configured, s.SocketPath())
	assert.NoDirExists(t, filepath.Dir(first))

	require.NoError(t, s.Start(context.Background()))
	t.Cleanup(func() { assert.NoError(t, s.Stop()) })
	assert.NotEqual(t, configured, s.SocketPath())
	assert.DirExists(t, filepath.Dir(s.SocketPath()), "a restart must listen in a directory that exists")
}

// A socket within the limit is never relocated, so Stop leaves it alone.
func TestStart_ShortSocketIsKeptAcrossStop(t *testing.T) {
	fakeSWTPMOnPath(t)
	stateDir, err := os.MkdirTemp("/tmp", "swtpm-test-")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, os.RemoveAll(stateDir)) })
	configured := filepath.Join(stateDir, "swtpm.sock")
	s := &SWTPM{
		config: &Config{StateDir: stateDir, SocketPath: configured},
		logger: logging.DefaultLogger(),
	}

	require.NoError(t, s.Start(context.Background()))
	assert.Equal(t, configured, s.SocketPath())
	require.NoError(t, s.Stop())

	assert.Equal(t, configured, s.SocketPath())
}
