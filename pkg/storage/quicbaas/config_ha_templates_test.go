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
	"sort"
	"strings"
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
var haComputeIdentityPaths = map[string]bool{
	".os.hostname":                  true,
	".bmc.address":                  true,
	".tpm.idevid.serial":            true,
	".network.platform-vrf.address": true,
}

// haComputeHostAddressPaths are the node host-address paths: each must
// differ between the pair, so the two nodes never share a host IP.
var haComputeHostAddressPaths = []string{
	".network.platform-vrf.address",
	".network.bonds[0].vlans[0].ipv4-address",
	".network.bonds[0].vlans[1].ipv4-address",
	".network.bonds[0].vlans[2].ipv4-address",
}

func init() {
	for _, p := range haComputeHostAddressPaths {
		haComputeIdentityPaths[p] = true
	}
}

// computePairViolations returns one message per diff path outside the
// identity allow-list and per host-address path the two nodes share.
func computePairViolations(diffs map[string]string) []string {
	var out []string
	for path := range diffs {
		if !haComputeIdentityPaths[path] {
			out = append(out, fmt.Sprintf("compute templates differ at %s, which is not a node identity field", path))
		}
	}
	for _, path := range haComputeHostAddressPaths {
		if _, ok := diffs[path]; !ok {
			out = append(out, fmt.Sprintf("compute templates share the host address at %s", path))
		}
	}
	sort.Strings(out)
	return out
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
	assert.Empty(t, computePairViolations(diffs))
	for _, path := range []string{".os.hostname", ".bmc.address", ".tpm.idevid.serial"} {
		_, ok := diffs[path]
		assert.True(t, ok, "compute templates share %s", path)
	}
}

// TestShippedHATemplates_ComputePairCheck proves the pair check keys on the
// full YAML path: a non-identity field whose leaf name matches an identity
// field (a DNS resolver address, an NTP upstream) is rejected, and so is a
// pair sharing a host address.
func TestShippedHATemplates_ComputePairCheck(t *testing.T) {
	hostAddrs := func(n int) map[string]any {
		return map[string]any{
			"platform-vrf": map[string]any{"address": fmt.Sprintf("10.4.144.%d/32", n)},
			"bonds": []any{map[string]any{"vlans": []any{
				map[string]any{"ipv4-address": fmt.Sprintf("10.4.1.%d/24", n)},
				map[string]any{"ipv4-address": fmt.Sprintf("10.4.3.%d/24", n)},
				map[string]any{"ipv4-address": fmt.Sprintf("10.4.7.%d/24", n)},
			}}},
		}
	}
	node := func(n int, dns, ntp string, net map[string]any) map[string]any {
		return map[string]any{
			"os":  map[string]any{"hostname": fmt.Sprintf("compute-%02d", n)},
			"bmc": map[string]any{"address": fmt.Sprintf("198.51.100.%d", 150+n)},
			"tpm": map[string]any{"idevid": map[string]any{"serial": fmt.Sprintf("sm-compute-%02d", n)}},
			"dns": map[string]any{"resolver": map[string]any{"servers": []any{
				map[string]any{"address": dns},
			}}},
			"ntp":     map[string]any{"upstreams": []any{map[string]any{"address": ntp}}},
			"network": net,
		}
	}
	tests := []struct {
		name   string
		a, b   map[string]any
		reject string
	}{
		{"identity only", node(1, "10.4.1.1", "10.4.1.2", hostAddrs(20)), node(2, "10.4.1.1", "10.4.1.2", hostAddrs(21)), ""},
		{"dns resolver differs", node(1, "10.4.1.1", "10.4.1.2", hostAddrs(20)), node(2, "10.4.1.9", "10.4.1.2", hostAddrs(21)), ".dns.resolver.servers[0].address"},
		{"ntp upstream differs", node(1, "10.4.1.1", "10.4.1.2", hostAddrs(20)), node(2, "10.4.1.1", "10.4.1.9", hostAddrs(21)), ".ntp.upstreams[0].address"},
		{"shared host address", node(1, "10.4.1.1", "10.4.1.2", hostAddrs(20)), node(2, "10.4.1.1", "10.4.1.2", hostAddrs(20)), ".network.platform-vrf.address"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			diffs := map[string]string{}
			diffYAMLLeaves("", "", tc.a, tc.b, diffs)
			got := computePairViolations(diffs)
			if tc.reject == "" {
				assert.Empty(t, got)
				return
			}
			require.NotEmpty(t, got)
			assert.Contains(t, strings.Join(got, "\n"), tc.reject)
		})
	}
}
