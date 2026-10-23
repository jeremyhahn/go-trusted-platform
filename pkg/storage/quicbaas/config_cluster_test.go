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

package quicbaas

import (
	"fmt"
	"testing"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// threeNodeMembers is the member list every node of the test cluster carries.
var threeNodeMembers = []string{
	"1=10.0.1.1:63000",
	"2=10.0.1.2:63000",
	"3=10.0.1.3:63000",
}

// clusterMemberConfig returns a valid configuration for member id of the
// three-node test cluster.
func clusterMemberConfig(t *testing.T, id uint64) *Config {
	t.Helper()
	cfg := TestConfig(t)
	cfg.NodeID = id
	cfg.RaftAddress = fmt.Sprintf("10.0.1.%d:63000", id)
	cfg.JoinAddresses = append([]string(nil), threeNodeMembers...)
	cfg.DeploymentID = 42
	cfg.RaftTLSCertFile = fmt.Sprintf("/etc/trusted-platform/raft/node%d.crt", id)
	cfg.RaftTLSKeyFile = fmt.Sprintf("/etc/trusted-platform/raft/node%d.key", id)
	cfg.RaftTLSCAFile = "/etc/trusted-platform/raft/ca.crt"
	return cfg
}

func TestToQuicBaaSConfig_ThreeNodeCluster(t *testing.T) {
	for id := uint64(1); id <= 3; id++ {
		t.Run(fmt.Sprintf("node%d", id), func(t *testing.T) {
			c := clusterMemberConfig(t, id)
			require.NoError(t, c.Validate())

			cfg := c.ToQuicBaaSConfig()
			assert.Equal(t, quicbaassdk.ServerModeCluster, cfg.Server.Mode)
			assert.Equal(t, id, cfg.Raft.NodeID)
			assert.Equal(t, c.RaftAddress, cfg.Raft.RaftAddress)
			assert.Equal(t, threeNodeMembers, cfg.Raft.JoinAddresses)
			assert.Equal(t, uint64(42), cfg.Raft.DeploymentID)
			assert.False(t, cfg.Raft.Join, "members bootstrap together; none joins a running cluster")
			assert.Equal(t, c.RaftTLSCertFile, cfg.Raft.TLSCertFile)
			assert.Equal(t, c.RaftTLSKeyFile, cfg.Raft.TLSKeyFile)
			assert.Equal(t, "/etc/trusted-platform/raft/ca.crt", cfg.Raft.TLSCAFile)
		})
	}
}

func TestToQuicBaaSConfig_StandaloneUnchanged(t *testing.T) {
	c := TestConfig(t)
	// Cluster-only fields set on a node with no member list stay unmapped:
	// only JoinAddresses makes a node clustered.
	c.DeploymentID = 42
	c.RaftTLSCertFile = "/etc/trusted-platform/raft/node1.crt"
	require.NoError(t, c.Validate())
	require.False(t, c.IsClustered())

	cfg := c.ToQuicBaaSConfig()
	assert.NotEqual(t, quicbaassdk.ServerModeCluster, cfg.Server.Mode)
	assert.Nil(t, cfg.Raft.JoinAddresses)
	assert.Zero(t, cfg.Raft.DeploymentID)
	assert.Empty(t, cfg.Raft.TLSCertFile)
	assert.Empty(t, cfg.Raft.TLSKeyFile)
	assert.Empty(t, cfg.Raft.TLSCAFile)
	assert.Equal(t, c.NodeID, cfg.Raft.NodeID)
	assert.Equal(t, c.RaftAddress, cfg.Raft.RaftAddress)
}

func TestConfig_Validate_ClusterRequiresRaftTLS(t *testing.T) {
	tests := []struct {
		name    string
		clear   func(c *Config)
		missing []string
	}{
		{"no TLS files", func(c *Config) { c.RaftTLSCertFile, c.RaftTLSKeyFile, c.RaftTLSCAFile = "", "", "" },
			[]string{"quicbaas.raft-tls-cert-file", "quicbaas.raft-tls-key-file", "quicbaas.raft-tls-ca-file"}},
		{"no certificate", func(c *Config) { c.RaftTLSCertFile = "" }, []string{"quicbaas.raft-tls-cert-file"}},
		{"no key", func(c *Config) { c.RaftTLSKeyFile = "" }, []string{"quicbaas.raft-tls-key-file"}},
		{"no CA", func(c *Config) { c.RaftTLSCAFile = "" }, []string{"quicbaas.raft-tls-ca-file"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := clusterMemberConfig(t, 1)
			tt.clear(c)

			err := c.Validate()
			var tlsErr ErrRaftTLSRequired
			require.ErrorAs(t, err, &tlsErr)
			assert.Equal(t, tt.missing, tlsErr.Missing)
			for _, field := range tt.missing {
				assert.Contains(t, err.Error(), field)
			}
		})
	}
}

func TestConfig_Validate_ClusterMalformedJoinAddress(t *testing.T) {
	for _, entry := range []string{
		"10.0.1.2:63000",   // the old seed form, with no member ID
		"0=10.0.1.2:63000", // node IDs start at 1
		"two=10.0.1.2:63000",
		"-2=10.0.1.2:63000",
		"2=10.0.1.2",
		"2=:63000",
		"2=10.0.1.2:0",
		"2=10.0.1.2:70000",
		"2=10.0.1.2:raft",
		"2=",
	} {
		t.Run(entry, func(t *testing.T) {
			c := clusterMemberConfig(t, 1)
			c.JoinAddresses[1] = entry

			err := c.Validate()
			var peerErr ErrRaftPeerAddress
			require.ErrorAs(t, err, &peerErr)
			assert.Equal(t, entry, peerErr.Entry)
			assert.Contains(t, err.Error(), "id=host:port")
		})
	}
}

func TestConfig_Validate_ClusterAcceptsIPv6AndHostnameMembers(t *testing.T) {
	c := clusterMemberConfig(t, 1)
	c.JoinAddresses[1] = "2=[2001:db8::2]:63000"
	c.JoinAddresses[2] = "3=node-3.cluster.internal:63000"
	assert.NoError(t, c.Validate())
}

func TestConfig_Validate_ClusterDuplicateNodeID(t *testing.T) {
	c := clusterMemberConfig(t, 1)
	c.JoinAddresses[2] = "2=10.0.1.3:63000"

	err := c.Validate()
	var dupErr ErrRaftDuplicatePeer
	require.ErrorAs(t, err, &dupErr)
	assert.Equal(t, uint64(2), dupErr.NodeID)
	assert.Contains(t, err.Error(), "node ID 2")
}

func TestConfig_Validate_ClusterSelfMember(t *testing.T) {
	tests := []struct {
		name    string
		members []string
	}{
		{"self missing", []string{"2=10.0.1.2:63000", "3=10.0.1.3:63000"}},
		{"self at another address", []string{"1=10.0.1.9:63000", "2=10.0.1.2:63000", "3=10.0.1.3:63000"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := clusterMemberConfig(t, 1)
			c.JoinAddresses = tt.members

			err := c.Validate()
			var selfErr ErrRaftSelfPeer
			require.ErrorAs(t, err, &selfErr)
			assert.Equal(t, uint64(1), selfErr.NodeID)
			assert.Contains(t, err.Error(), `"1=10.0.1.1:63000"`)
		})
	}
}

func TestConfig_Validate_ClusterRequiredFields(t *testing.T) {
	tests := []struct {
		name  string
		field string
		clear func(c *Config)
	}{
		{"no deployment ID", "deployment-id", func(c *Config) { c.DeploymentID = 0 }},
		{"no node ID", "node-id", func(c *Config) { c.NodeID = 0 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := clusterMemberConfig(t, 1)
			tt.clear(c)

			err := c.Validate()
			var fieldErr ErrRaftClusterField
			require.ErrorAs(t, err, &fieldErr)
			assert.Equal(t, tt.field, fieldErr.Field)
			assert.Contains(t, err.Error(), "quicbaas."+tt.field)
		})
	}
}
