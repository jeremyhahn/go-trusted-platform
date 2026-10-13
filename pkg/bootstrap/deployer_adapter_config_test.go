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

package bootstrap

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/deployer"
)

// TestLinuxDeployerAdapter_DeployConfig: the adapter is the one place the
// deployer section becomes a deployer.DeployConfig, and it carries every
// field the Linux deployer reads.
func TestLinuxDeployerAdapter_DeployConfig(t *testing.T) {
	home, err := os.UserHomeDir()
	require.NoError(t, err)
	cfg := &DeployerConfig{
		Host:               "10.0.0.1",
		User:               "admin",
		SSHKey:             "~/.ssh/id_ed25519",
		KnownHostsPath:     "/etc/pins",
		ContainerRuntime:   "podman",
		ContainerImage:     "platform-pxeboot:1",
		DataDir:            "/srv/bootstrap",
		BootstrapAPKMirror: "http://mirror",
		NetbootMediaDir:    "/srv/netboot-media",
		ProxyDHCP:          true,
		BootstrapHTTPPort:  9000,
		BootstrapBindHost:  "10.0.0.1",
	}
	a := newLinuxDeployerAdapter(cfg, nil, nil)

	dc := a.deployConfig("/tmp/manifest.yaml")
	assert.Equal(t, filepath.Join(home, ".ssh", "id_ed25519"), dc.SSHKeyPath)
	assert.Equal(t, "/etc/pins", dc.KnownHostsPath)
	assert.Equal(t, "podman", dc.ContainerRuntime)
	assert.Equal(t, "/tmp/manifest.yaml", dc.ManifestPath)
	assert.Equal(t, "/srv/bootstrap", dc.DataDir)
	assert.Equal(t, "/srv/netboot-media", dc.NetbootMediaDir)
	assert.True(t, dc.BootstrapProxyDHCP)
	assert.Equal(t, "http://mirror", dc.BootstrapAPKMirror)
	assert.Equal(t, 9000, dc.BootstrapHTTPPort)
	assert.Equal(t, "10.0.0.1", dc.BootstrapBindHost)
	assert.Equal(t, 9001, dc.BootstrapDeviceScriptPort, "the device script port follows the HTTP port")
	assert.Equal(t, 22, dc.Port, "defaults applied")
	require.NoError(t, dc.Validate())

	teardown := newLinuxDeployerAdapter(&DeployerConfig{Host: "h"}, nil, nil).deployConfig("")
	assert.Empty(t, teardown.ManifestPath)
	assert.Equal(t, deployer.DefaultRemoteDataDir, teardown.DataDir)
	var invalid deployer.ErrInvalidDeployConfig
	assert.ErrorAs(t, teardown.Validate(), &invalid, "an incomplete section fails the deployer's validation")
}
