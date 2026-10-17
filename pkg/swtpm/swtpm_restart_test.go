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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// longSocketDir returns a directory under the test's temp directory whose
// swtpm.sock path is too long to host a Unix socket.
func longSocketDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for len(filepath.Join(dir, "swtpm.sock")) < unixSocketPathMax {
		dir = filepath.Join(dir, strings.Repeat("d", 16))
	}
	require.NoError(t, os.MkdirAll(dir, 0o755))
	return dir
}

// startStop starts s, checks the socket it reports is the one the daemon
// was given and that its directory exists, then stops s. It returns that
// socket.
func startStop(t *testing.T, s *SWTPM, fake *fakeTools, run int) string {
	t.Helper()
	require.NoError(t, s.Start(context.Background()))
	live := s.SocketPath()
	assert.Equal(t, fake.daemonSocket(t, run), live, "SocketPath is the socket the daemon listens on")
	assert.DirExists(t, filepath.Dir(live))
	require.NoError(t, s.Stop())
	return live
}

// A reboot stops and starts the same SWTPM. A socket moved into a temp
// directory must not outlive that directory: each Start picks a socket
// whose directory exists, and Stop hands back the configured path.
func TestStartAfterStopWithMovedSocket(t *testing.T) {
	stateDir := longSocketDir(t)
	configured := filepath.Join(stateDir, "swtpm.sock")
	fake := &fakeTools{}
	s := newFakeSWTPM(t, &Config{StateDir: stateDir, SocketPath: configured, QEMUMode: true}, fake)

	first := startStop(t, s, fake, 0)
	assert.NotEqual(t, configured, first, "a too-long socket path is moved")
	assert.NoDirExists(t, filepath.Dir(first), "Stop removes the temp directory")
	assert.Equal(t, configured, s.SocketPath(), "a stopped SWTPM reports the configured socket")

	second := startStop(t, s, fake, 1)
	assert.NotEqual(t, first, second, "the restart does not reuse the removed temp directory")
	assert.Equal(t, configured, s.config.SocketPath, "Start leaves the configured socket path alone")
}

func TestStartAfterStopKeepsConfiguredSocket(t *testing.T) {
	stateDir := t.TempDir()
	require.True(t, strings.HasPrefix(stateDir, "/tmp/"), "the test needs a state directory swtpm runs in place: %s", stateDir)
	configured := filepath.Join(stateDir, "swtpm.sock")
	fake := &fakeTools{}
	s := newFakeSWTPM(t, &Config{StateDir: stateDir, SocketPath: configured}, fake)

	assert.Equal(t, configured, startStop(t, s, fake, 0))
	assert.Equal(t, configured, startStop(t, s, fake, 1))
}

func TestStartWhileRunningKeepsSocket(t *testing.T) {
	stateDir := longSocketDir(t)
	fake := &fakeTools{}
	s := newFakeSWTPM(t, &Config{StateDir: stateDir}, fake)
	require.NoError(t, s.Start(context.Background()))
	t.Cleanup(func() { require.NoError(t, s.Stop()) })
	live := s.SocketPath()

	require.ErrorIs(t, s.Start(context.Background()), ErrAlreadyRunning)
	assert.Equal(t, live, s.SocketPath())
	assert.Len(t, fake.daemonArgs, 1)
}
