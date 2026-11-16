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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// haTemplateRoot is the x10 high-availability profile: one control-plane
// template per Raft member (#1702).
var haTemplateRoot = filepath.Join("..", "..", "..", "configs", "platform", "templates",
	"high-availability", "supermicro", "x10")

// loadHATemplateQuicBaaS decodes the quicbaas: section of one shipped HA
// control-plane template into Config.
func loadHATemplateQuicBaaS(t *testing.T, path string) *Config {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var doc struct {
		QuicBaaS *Config `yaml:"quicbaas"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &doc), path)
	require.NotNil(t, doc.QuicBaaS, "%s: quicbaas section", path)
	return doc.QuicBaaS
}

// TestShippedHATemplates_FormOneCluster decodes the quicbaas: section of each
// of the three HA control-plane templates and asserts that they form one
// Raft cluster: each validates, node-ids are distinct, the member list and
// deployment-id are identical, every member address is routable and the
// raft-tls files are set.
func TestShippedHATemplates_FormOneCluster(t *testing.T) {
	var first *Config
	seen := map[uint64]string{}
	for i := 1; i <= 3; i++ {
		path := filepath.Join(haTemplateRoot, fmt.Sprintf("cp%d", i), "control-plane.yaml")
		c := loadHATemplateQuicBaaS(t, path)
		require.NoError(t, c.Validate(), path)
		require.True(t, c.IsClustered(), path)

		if prev, dup := seen[c.NodeID]; dup {
			t.Fatalf("%s: node-id %d already used by %s", path, c.NodeID, prev)
		}
		seen[c.NodeID] = path

		assert.Len(t, c.JoinAddresses, 3, path)
		for _, entry := range c.JoinAddresses {
			_, addr, err := parseRaftMember(entry)
			require.NoError(t, err, "%s: member %q", path, entry)
			assert.True(t, IsRoutableRaftAddress(addr), "%s: member %q is not routable", path, entry)
		}
		assert.Contains(t, c.JoinAddresses, fmt.Sprintf("%d=%s", c.NodeID, c.RaftAddress), path)
		assert.NotEmpty(t, c.RaftTLSCertFile, path)
		assert.NotEmpty(t, c.RaftTLSKeyFile, path)
		assert.NotEmpty(t, c.RaftTLSCAFile, path)

		if first == nil {
			first = c
			continue
		}
		assert.Equal(t, first.JoinAddresses, c.JoinAddresses, path)
		assert.Equal(t, first.DeploymentID, c.DeploymentID, path)
		assert.Equal(t, first.RaftTLSCAFile, c.RaftTLSCAFile, path)
	}
	assert.Len(t, seen, 3)
}
