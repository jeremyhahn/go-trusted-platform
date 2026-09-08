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

package installer

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

func gatewaydTestLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelError, io.Discard)
}

func stageGatewayd(t *testing.T, isoMount string) string {
	t.Helper()
	dir := filepath.Join(isoMount, "platformd-bin")
	require.NoError(t, os.MkdirAll(dir, 0755))
	src := filepath.Join(dir, "gatewayd")
	require.NoError(t, os.WriteFile(src, []byte("#!/bin/sh\necho gatewayd\n"), 0755))
	return src
}

func TestInstallGatewaydBinary_InstallsBinaryAndSymlink(t *testing.T) {
	iso := t.TempDir()
	root := t.TempDir()
	stageGatewayd(t, iso)

	err := installGatewaydBinaryFrom(context.Background(), gatewaydTestLogger(), []string{filepath.Join(iso, "missing"), iso}, root, true)
	require.NoError(t, err)

	bin := filepath.Join(root, "usr", "bin", "gatewayd")
	stat, err := os.Stat(bin)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0755), stat.Mode().Perm())

	link, err := os.Readlink(filepath.Join(root, "usr", "sbin", "gatewayd"))
	require.NoError(t, err)
	assert.Equal(t, "/usr/bin/gatewayd", link)
}

func TestInstallGatewaydBinary_ReplacesAStaleSymlink(t *testing.T) {
	iso := t.TempDir()
	root := t.TempDir()
	stageGatewayd(t, iso)
	sbin := filepath.Join(root, "usr", "sbin")
	require.NoError(t, os.MkdirAll(sbin, 0755))
	require.NoError(t, os.Symlink("/nowhere", filepath.Join(sbin, "gatewayd")))

	require.NoError(t, installGatewaydBinaryFrom(context.Background(), gatewaydTestLogger(), []string{iso}, root, true))
	link, err := os.Readlink(filepath.Join(sbin, "gatewayd"))
	require.NoError(t, err)
	assert.Equal(t, "/usr/bin/gatewayd", link)
}

func TestInstallGatewaydBinary_GatewayRoleFailsClosedWhenMissing(t *testing.T) {
	iso := t.TempDir()
	root := t.TempDir()

	err := installGatewaydBinaryFrom(context.Background(), gatewaydTestLogger(), []string{iso}, root, true)
	var want *ErrGatewaydBinaryMissing
	require.True(t, errors.As(err, &want), "got %v", err)
	assert.Equal(t, []string{iso}, want.Searched)
	assert.Contains(t, err.Error(), "gateway role")
	_, statErr := os.Stat(filepath.Join(root, "usr", "bin", "gatewayd"))
	assert.True(t, os.IsNotExist(statErr))
}

func TestInstallGatewaydBinary_OtherRolesSkipWhenMissing(t *testing.T) {
	iso := t.TempDir()
	root := t.TempDir()

	require.NoError(t, installGatewaydBinaryFrom(context.Background(), gatewaydTestLogger(), []string{iso}, root, false))
	_, statErr := os.Stat(filepath.Join(root, "usr", "bin", "gatewayd"))
	assert.True(t, os.IsNotExist(statErr))
}

func TestInstallGatewaydBinary_OtherRolesStillInstallWhenPresent(t *testing.T) {
	iso := t.TempDir()
	root := t.TempDir()
	stageGatewayd(t, iso)

	require.NoError(t, installGatewaydBinaryFrom(context.Background(), gatewaydTestLogger(), []string{iso}, root, false))
	_, err := os.Stat(filepath.Join(root, "usr", "bin", "gatewayd"))
	assert.NoError(t, err)
}

func TestInstallGatewaydBinary_UnwritableTargetIsAnError(t *testing.T) {
	iso := t.TempDir()
	stageGatewayd(t, iso)
	root := filepath.Join(t.TempDir(), "file-not-dir")
	require.NoError(t, os.WriteFile(root, []byte("x"), 0644))

	err := installGatewaydBinaryFrom(context.Background(), gatewaydTestLogger(), []string{iso}, root, true)
	var wrapped *WrappedError
	require.True(t, errors.As(err, &wrapped), "got %v", err)
}
