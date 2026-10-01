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

package iso

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

func newGatewaydCustomizer(t *testing.T) *Customizer {
	t.Helper()
	return NewCustomizer(&PlatformISOConfig{
		Directories: DirectoryConfig{
			ISO:     filepath.Join(t.TempDir(), "iso"),
			Overlay: filepath.Join(t.TempDir(), "overlay"),
		},
	}, logging.DefaultLogger())
}

// selfELF returns this test binary: a real ELF file validateBinary accepts.
func selfELF(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	require.NoError(t, err)
	return exe
}

func TestGatewaydBinaryPath_BesidePlatformd(t *testing.T) {
	assert.Equal(t, "/opt/tp/bin/gatewayd", gatewaydBinaryPath("/opt/tp/bin/platformd"))
	assert.Equal(t, "", gatewaydBinaryPath(""))
}

func TestISOTargetsGatewayRole(t *testing.T) {
	dir := t.TempDir()
	gw := filepath.Join(dir, "gateway.yaml")
	require.NoError(t, os.WriteFile(gw, []byte("gateway:\n  enabled: true\n"), 0644))
	cp := filepath.Join(dir, "cp.yaml")
	require.NoError(t, os.WriteFile(cp, []byte("sdn:\n  enabled: true\n"), 0644))
	bad := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(bad, []byte("gateway: [oops"), 0644))

	got, err := isoTargetsGatewayRole(gw)
	require.NoError(t, err)
	assert.True(t, got)

	got, err = isoTargetsGatewayRole(cp)
	require.NoError(t, err)
	assert.False(t, got)

	got, err = isoTargetsGatewayRole("")
	require.NoError(t, err)
	assert.False(t, got)

	_, err = isoTargetsGatewayRole(filepath.Join(dir, "missing.yaml"))
	require.Error(t, err)
	_, err = isoTargetsGatewayRole(bad)
	require.Error(t, err)
}

func TestCopyGatewaydBinary_StagesUnderPlatformdBin(t *testing.T) {
	c := newGatewaydCustomizer(t)
	require.NoError(t, c.CopyGatewaydBinary(context.Background(), selfELF(t), true))

	stat, err := os.Stat(filepath.Join(c.config.Directories.ISO, "platformd-bin", "gatewayd"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0755), stat.Mode().Perm())
}

// TestCopyGatewaydBinary_GatewayRoleAbsenceIsFatal is the #48 rule applied
// to gatewayd: an ISO whose config enables the gateway role must not build
// without the daemon that role runs.
func TestCopyGatewaydBinary_GatewayRoleAbsenceIsFatal(t *testing.T) {
	c := newGatewaydCustomizer(t)
	missing := filepath.Join(t.TempDir(), "bin", "gatewayd")

	err := c.CopyGatewaydBinary(context.Background(), missing, true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gatewayd")
	assert.Contains(t, err.Error(), "gateway role")

	err = c.CopyGatewaydBinary(context.Background(), "", true)
	require.Error(t, err, "a gateway-role ISO with no platformd path has nowhere to find gatewayd")
}

func TestCopyGatewaydBinary_OtherRolesSkipAbsence(t *testing.T) {
	c := newGatewaydCustomizer(t)
	require.NoError(t, c.CopyGatewaydBinary(context.Background(), filepath.Join(t.TempDir(), "gatewayd"), false))
	require.NoError(t, c.CopyGatewaydBinary(context.Background(), "", false))
	_, err := os.Stat(filepath.Join(c.config.Directories.ISO, "platformd-bin", "gatewayd"))
	assert.True(t, os.IsNotExist(err))
}

func TestCopyGatewaydBinary_RejectsANonELF(t *testing.T) {
	c := newGatewaydCustomizer(t)
	notELF := filepath.Join(t.TempDir(), "gatewayd")
	require.NoError(t, os.WriteFile(notELF, []byte("#!/bin/sh\n"), 0755))
	err := c.CopyGatewaydBinary(context.Background(), notELF, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validation failed")
}

// TestAutoinstallScript_PXEPayloadIsListDriven: a PXE node rebuilds its CD
// from the media set's payload list, not a list compiled into the script —
// the hard-coded list once omitted gatewayd and every gateway install over
// PXE aborted after partitioning the disk (mini fleet, 2026-09-13).
func TestAutoinstallScript_PXEPayloadIsListDriven(t *testing.T) {
	script := newGatewaydCustomizer(t).buildAutoinstallScript()
	assert.Contains(t, script, PXEPayloadFunction)
	assert.Contains(t, script, `fetch_install_payload "${PLATFORM_BIN_URL%/}" /media/cdrom`)
	assert.NotContains(t, script, "for _bin in platformctl platformd platform-initrd gatewayd;", "no binary list in the script")
}

// TestAutoinstallScript_StagesTheNodeConfigAfterThePayload: the node's own
// config replaces the payload's baked one, so it must run after the CD is
// rebuilt.
func TestAutoinstallScript_StagesTheNodeConfigAfterThePayload(t *testing.T) {
	script := newGatewaydCustomizer(t).buildAutoinstallScript()
	assert.Contains(t, script, NodeConfigFunction)
	call := strings.Index(script, `stage_node_config "$INSTALLER_CONFIG" /media/cdrom /tmp/ca-bundle.pem`)
	payload := strings.Index(script, `fetch_install_payload "${PLATFORM_BIN_URL%/}" /media/cdrom`)
	require.GreaterOrEqual(t, call, 0)
	require.GreaterOrEqual(t, payload, 0)
	assert.Greater(t, call, payload)
	assert.NotContains(t, script, `[ ! -f /media/cdrom/configs/installer.yaml ]`, "the baked config no longer blocks the node's")
}
