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

package container

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newBindHostContainer builds a container server for an x86-only fleet
// whose HTTP and TFTP servers bind bindHost.
func newBindHostContainer(t *testing.T, bindHost string) (*Server, error) {
	t.Helper()
	dataDir := testDataDir(t, x86Set())
	manifestPath := filepath.Join(t.TempDir(), "manifest.yaml")
	manifest := "nodes:\n  - mac: \"aa:bb:cc:dd:ee:01\"\n    role: worker\n    hostname: x\n"
	require.NoError(t, os.WriteFile(manifestPath, []byte(manifest), 0o644))
	cfg := &ServerConfig{
		Interface:    "lo",
		BindHost:     bindHost,
		ManifestPath: manifestPath,
		DataDir:      dataDir,
		MediaDir:     filepath.Join(dataDir, "media"),
		HTTPPort:     8080,
		DHCPConfig: DHCPConfig{
			ServerIP: "192.168.1.1", RangeStart: "192.168.1.100", RangeEnd: "192.168.1.200", SubnetMask: "255.255.255.0",
		},
	}
	return NewServer(cfg, testLogger())
}

func TestNewServer_BindHostReachesIPXE(t *testing.T) {
	for _, bindHost := range []string{"", "127.0.0.1", "fd00::1"} {
		t.Run(bindHost, func(t *testing.T) {
			_, err := newBindHostContainer(t, bindHost)
			assert.NoError(t, err)
		})
	}
}

// TestNewServer_InvalidBindHost proves the field reaches ipxe.ServerConfig:
// only the iPXE validation knows to refuse a host that is not an address.
func TestNewServer_InvalidBindHost(t *testing.T) {
	_, err := newBindHostContainer(t, "pxe.example.com")
	var startFailed ErrServerStartFailed
	require.ErrorAs(t, err, &startFailed)
	assert.ErrorIs(t, err, ipxe.ErrInvalidBindHost)
}
