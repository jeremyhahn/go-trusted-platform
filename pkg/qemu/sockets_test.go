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

package qemu

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// longWorkDir returns a work directory path of at least 120 bytes.
func longWorkDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), strings.Repeat("w", 100))
	require.GreaterOrEqual(t, len(dir), 120)
	return dir
}

func newSocketTestVM(cfg *Config) *VM {
	return &VM{config: cfg, logger: logging.DefaultLogger()}
}

func TestCheckSocketPath(t *testing.T) {
	assert.NoError(t, checkSocketPath("/"+strings.Repeat("a", SocketPathLimit-1)))
	assert.NoError(t, checkSocketPath(""))
}

func TestCheckSocketPath_TooLong(t *testing.T) {
	path := "/" + strings.Repeat("a", SocketPathLimit)

	err := checkSocketPath(path)

	var tooLong ErrSocketPathTooLong
	require.ErrorAs(t, err, &tooLong)
	assert.Equal(t, path, tooLong.Path)
	assert.Equal(t, SocketPathLimit, tooLong.Limit)
	assert.Contains(t, err.Error(), path)
	assert.Contains(t, err.Error(), "107")
}

func TestConfigSocketPath(t *testing.T) {
	cfg := &Config{WorkDir: "/work"}
	assert.Equal(t, "/work/qmp.sock", cfg.GetQMPSocketPath())

	cfg.RuntimeDir = "/run/tp-vm-1"
	assert.Equal(t, "/run/tp-vm-1/qmp.sock", cfg.GetQMPSocketPath())

	cfg.QMPSocketPath = "/pinned/qmp.sock"
	assert.Equal(t, "/pinned/qmp.sock", cfg.GetQMPSocketPath())
}

func TestConfigValidateSocketPaths(t *testing.T) {
	cfg := &Config{WorkDir: "/work", ConsoleSocketPath: "/work/console.sock"}
	assert.NoError(t, cfg.validateSocketPaths())
}

func TestConfigValidateSocketPaths_TooLong(t *testing.T) {
	tests := []struct {
		name string
		cfg  *Config
		want string
	}{
		{
			name: "default qmp path under a long work dir",
			cfg:  &Config{WorkDir: "/" + strings.Repeat("w", 120)},
			want: "/" + strings.Repeat("w", 120) + "/qmp.sock",
		},
		{
			name: "explicit qmp path",
			cfg:  &Config{QMPSocketPath: "/" + strings.Repeat("q", 110)},
			want: "/" + strings.Repeat("q", 110),
		},
		{
			name: "console path",
			cfg:  &Config{WorkDir: "/work", ConsoleSocketPath: "/" + strings.Repeat("c", 110)},
			want: "/" + strings.Repeat("c", 110),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var tooLong ErrSocketPathTooLong
			require.ErrorAs(t, tt.cfg.validateSocketPaths(), &tooLong)
			assert.Equal(t, tt.want, tooLong.Path)
			assert.Equal(t, SocketPathLimit, tooLong.Limit)
		})
	}
}

func TestCreateRuntimeDir_LongWorkDirYieldsShortSocketPath(t *testing.T) {
	cfg := &Config{WorkDir: longWorkDir(t)}
	vm := newSocketTestVM(cfg)

	require.NoError(t, vm.createRuntimeDir())

	qmp := cfg.GetQMPSocketPath()
	assert.LessOrEqual(t, len(qmp), SocketPathLimit)
	assert.NotContains(t, qmp, cfg.WorkDir)
	assert.NoError(t, cfg.validateSocketPaths())
	info, err := os.Stat(cfg.RuntimeDir)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
	assert.Equal(t, os.FileMode(0700), info.Mode().Perm())

	dir := cfg.RuntimeDir
	vm.releaseRuntimeDir()
	assert.NoDirExists(t, dir)
	assert.Empty(t, cfg.RuntimeDir)

	vm.releaseRuntimeDir() // idempotent
}

func TestCreateRuntimeDir_KeepsCallerPinnedSockets(t *testing.T) {
	pinnedDir := t.TempDir()
	tests := []*Config{
		{WorkDir: "/work", QMPSocketPath: "/pinned/qmp.sock"},
		{WorkDir: "/work", RuntimeDir: pinnedDir},
	}
	for _, cfg := range tests {
		vm := newSocketTestVM(cfg)

		require.NoError(t, vm.createRuntimeDir())
		assert.Empty(t, vm.runtimeDir)

		vm.releaseRuntimeDir()
		assert.DirExists(t, pinnedDir, "a caller's directory is never removed")
	}
}

func TestCreateRuntimeDir_TempDirUnusable(t *testing.T) {
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing"))
	cfg := &Config{WorkDir: "/work"}
	vm := newSocketTestVM(cfg)

	err := vm.createRuntimeDir()

	var wrapped *WrappedError
	require.ErrorAs(t, err, &wrapped)
	assert.Empty(t, cfg.RuntimeDir)
}

// startableConfig returns a config whose Start reaches NVRAM initialisation
// and fails there (OVMF_VARS is a directory), so no QEMU process is launched.
func startableConfig(t *testing.T, workDir string) *Config {
	t.Helper()
	tmpDir := t.TempDir()
	ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
	disk := filepath.Join(tmpDir, "test.qcow2")
	require.NoError(t, os.WriteFile(ovmfCode, []byte("mock"), 0644))
	require.NoError(t, os.WriteFile(disk, []byte("mock"), 0644))
	ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")
	require.NoError(t, os.Mkdir(ovmfVars, 0755))

	return &Config{
		DiskPath: disk,
		Memory:   4096,
		CPUs:     2,
		DiskSize: "10G",
		WorkDir:  workDir,
		OVMFCode: ovmfCode,
		OVMFVars: ovmfVars,
	}
}

func TestVMStart_FailureReleasesRuntimeDir(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	cfg := startableConfig(t, longWorkDir(t))
	vm, err := NewVM(cfg, logging.DefaultLogger())
	require.NoError(t, err)

	err = vm.Start(context.Background(), "boot")

	require.Error(t, err)
	var tooLong ErrSocketPathTooLong
	assert.False(t, errors.As(err, &tooLong), "a long work dir must not reach the socket limit")
	entries, readErr := os.ReadDir(tmp)
	require.NoError(t, readErr)
	assert.Empty(t, entries, "the socket directory must not outlive a failed start")
	assert.Empty(t, cfg.RuntimeDir)
}

func TestVMStart_OverLongSocketPathIsTyped(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	cfg := startableConfig(t, t.TempDir())
	cfg.QMPSocketPath = "/" + strings.Repeat("q", 120)
	vm, err := NewVM(cfg, logging.DefaultLogger())
	require.NoError(t, err)

	err = vm.Start(context.Background(), "boot")

	var tooLong ErrSocketPathTooLong
	require.ErrorAs(t, err, &tooLong)
	assert.Equal(t, cfg.QMPSocketPath, tooLong.Path)
	entries, readErr := os.ReadDir(tmp)
	require.NoError(t, readErr)
	assert.Empty(t, entries)
}

func TestVMForceStop_RemovesRuntimeDir(t *testing.T) {
	cfg := &Config{WorkDir: longWorkDir(t)}
	vm := newSocketTestVM(cfg)
	require.NoError(t, vm.createRuntimeDir())
	dir := cfg.RuntimeDir

	vm.cmd = exec.Command("sleep", "30")
	require.NoError(t, vm.cmd.Start())
	vm.running.Store(true)

	require.NoError(t, vm.ForceStop())
	_ = vm.cmd.Wait()

	assert.NoDirExists(t, dir)
}
