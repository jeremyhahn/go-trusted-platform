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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
)

// TestManagedPXEProvision_StagesPerMACConfig: a BMC-managed node booted
// over PXE must find its per-MAC hostname, installer.yaml and trust
// material on the config server exactly as an unmanaged node does — the
// autoinstall reads them before falling back to the ISO-baked defaults,
// so without them the node installs as nobody in particular. Both paths
// are run for otherwise identical workers and must publish the same keys.
func TestManagedPXEProvision_StagesPerMACConfig(t *testing.T) {
	cfg := minimalConfig()
	managed := NodeConfig{Hostname: "w-managed", Role: RoleWorker, MACs: []string{"aa:bb:cc:dd:ee:21"}, BMCAddress: "10.0.0.21", BootMethod: BootMethodPXE}
	unmanaged := NodeConfig{Hostname: "w-unmanaged", Role: RoleWorker, MACs: []string{"aa:bb:cc:dd:ee:22"}}
	cfg.Nodes = append(cfg.Nodes, managed, unmanaged)
	o, rec := newRecordingRunOrchestrator(t, OrchestratorParams{
		Config:        cfg,
		BMCFactory:    &mockBMCFactory{client: bmc.NewMockClient()},
		Logger:        orchTestLogger(),
		HealthChecker: &mockHealthChecker{},
	})

	// Drive the post-install power and health polls instead of waiting
	// for their real intervals.
	o.pollTicker = newFakeHealthTicker(16).New

	require.NoError(t, o.provisionUnmanaged(t.Context(), &DiscoveredNode{NodeConfig: unmanaged, DiscoveredMACs: unmanaged.MACs}))
	require.NoError(t, o.managedPXEProvision(t.Context(), &DiscoveredNode{NodeConfig: managed, DiscoveredMACs: managed.MACs, BMCManaged: true}))

	want := rec.keys(sanitizeMACForPath(unmanaged.MACs[0]))
	require.Contains(t, want, "hostname", "the unmanaged path is the reference and stages at least the hostname")
	assert.Equal(t, want, rec.keys(sanitizeMACForPath(managed.MACs[0])), "the managed PXE node gets the same per-MAC config")
}
