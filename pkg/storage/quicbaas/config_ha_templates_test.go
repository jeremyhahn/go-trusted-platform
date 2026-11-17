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

// haComputeIdentityLeaves are the only leaf keys allowed to differ between
// the two compute templates of the high-availability profile: the node's
// hostname, its addresses and its TPM serial.
var haComputeIdentityLeaves = map[string]bool{
	"hostname":     true,
	"address":      true,
	"ipv4-address": true,
	"serial":       true,
}

// diffYAMLLeaves records in out the path of every leaf where a and b differ,
// together with the name of the key holding it.
func diffYAMLLeaves(path, key string, a, b any, out map[string]string) {
	switch av := a.(type) {
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok || len(av) != len(bv) {
			out[path] = key
			return
		}
		for k, x := range av {
			y, ok := bv[k]
			if !ok {
				out[path+"."+k] = k
				continue
			}
			diffYAMLLeaves(path+"."+k, k, x, y, out)
		}
	case []any:
		bv, ok := b.([]any)
		if !ok || len(av) != len(bv) {
			out[path] = key
			return
		}
		for i := range av {
			diffYAMLLeaves(fmt.Sprintf("%s[%d]", path, i), key, av[i], bv[i], out)
		}
	default:
		if fmt.Sprint(a) != fmt.Sprint(b) {
			out[path] = key
		}
	}
}

// TestShippedHATemplates_ComputePair pins the compute pair of the
// high-availability profile: both templates load and validate, and they
// differ only in node identity (hostname, addresses, TPM serial), each of
// which is distinct between the two nodes.
func TestShippedHATemplates_ComputePair(t *testing.T) {
	docs := make([]map[string]any, 2)
	for i := range docs {
		path := filepath.Join(haTemplateRoot, fmt.Sprintf("compute%d", i+1), "compute.yaml")
		c := loadHATemplateQuicBaaS(t, path)
		require.NoError(t, c.Validate(), path)

		raw, err := os.ReadFile(path)
		require.NoError(t, err)
		require.NoError(t, yaml.Unmarshal(raw, &docs[i]), path)
	}

	diffs := map[string]string{}
	diffYAMLLeaves("", "", docs[0], docs[1], diffs)
	require.NotEmpty(t, diffs, "compute1 and compute2 are identical")
	for path, key := range diffs {
		assert.True(t, haComputeIdentityLeaves[key],
			"compute templates differ at %s, which is not a node identity field", path)
	}
	for _, path := range []string{".os.hostname", ".bmc.address"} {
		_, ok := diffs[path]
		assert.True(t, ok, "compute templates share %s", path)
	}
	serials := 0
	for _, key := range diffs {
		if key == "serial" {
			serials++
		}
	}
	assert.Positive(t, serials, "compute templates share the TPM serial")
}
