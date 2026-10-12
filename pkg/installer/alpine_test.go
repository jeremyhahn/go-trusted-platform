// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func installInitScripts(t *testing.T, root string, names ...string) {
	t.Helper()
	dir := filepath.Join(root, "etc", "init.d")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	for _, name := range names {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte("#!/sbin/openrc-run\n"), 0o755))
	}
}

// TestInstalledServices_EnablesTheIPsecServices: a node with the IPsec
// -openrc packages gets charon and its module host in the default runlevel,
// so the VICI socket exists after a reboot.
func TestInstalledServices_EnablesTheIPsecServices(t *testing.T) {
	root := t.TempDir()
	installInitScripts(t, root, "charon", "xkms-p11-kit", "ovsdb-server", "networking", "unrelated")

	assert.Equal(t, []openRCService{
		{name: "ovsdb-server", runlevel: "boot"},
		{name: "networking", runlevel: "default"},
		{name: "xkms-p11-kit", runlevel: "default"},
		{name: "charon", runlevel: "default"},
	}, installedServices(root))
}

// TestInstalledServices_SkipsServicesNotInstalled: a node without the
// packages, or without any init scripts, enables nothing it lacks.
func TestInstalledServices_SkipsServicesNotInstalled(t *testing.T) {
	t.Run("no IPsec packages", func(t *testing.T) {
		root := t.TempDir()
		installInitScripts(t, root, "networking", "sshd")
		assert.Equal(t, []openRCService{
			{name: "networking", runlevel: "default"},
			{name: "sshd", runlevel: "default"},
		}, installedServices(root))
	})
	t.Run("no init.d", func(t *testing.T) {
		assert.Empty(t, installedServices(t.TempDir()))
	})
}
