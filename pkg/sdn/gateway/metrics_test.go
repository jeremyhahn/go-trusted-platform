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

package gateway

import (
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
)

// staticSnapshot is a SnapshotSource returning a fixed snapshot.
type staticSnapshot struct {
	snap  *gwstate.Snapshot
	calls int
}

func (s *staticSnapshot) Snapshot() *gwstate.Snapshot {
	s.calls++
	return s.snap
}

func metricsSnapshot() *gwstate.Snapshot {
	return &gwstate.Snapshot{
		GatewayID: "node-01-gateway",
		Services: []gwstate.ServiceState{
			{Name: "tunnels", Active: true, Healthy: true},
			{Name: "dhcp", Active: false, Healthy: false, RefusedReason: "no allocator"},
		},
		BGP: gwstate.BGPState{
			Peers: []gwstate.BGPPeerState{{
				Address: "10.255.0.2", ASN: 64512, State: "Established", UptimeSeconds: 3600,
				PrefixesReceived: 120, PrefixesAccepted: 118, PrefixesSent: 2,
				BFD: &gwstate.BFDState{State: "up", FailureTransitions: 4},
			}, {
				Address: "10.255.0.6", ASN: 64512, State: "Active",
			}},
		},
		Tunnels: []gwstate.TunnelState{{
			Name: "gre-pri", Transport: "ipsec", State: "up", Uplink: "isp-a",
			RxBytes: 4096, TxBytes: 2048, RxPackets: 32, TxPackets: 16,
			LastRekey: time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC),
		}, {
			Name: "gre-alt", Transport: "gre", State: "down",
		}},
		Uplinks: []gwstate.UplinkState{{
			Name: "isp-a", Table: 101, RuleCount: 2, Tunnels: []string{"gre-pri"},
		}},
		HostFirewall: &gwstate.HostFirewallState{Active: true, Installed: true, Fingerprint: "sha256:abc", RuleCount: 10},
		Firewall:     &gwstate.FirewallState{Active: true, FlowCount: 26},
		NAT: &gwstate.NATState{Active: true, DNATRules: 3, Uplinks: []gwstate.NATUplinkState{
			{Name: "isp-a", PoolAddresses: 8, Ports: 64512},
		}},
		Pipeline: &gwstate.PipelineState{Installed: true, Bridge: "br-fabric", Terminal: "normal"},
	}
}

func TestCollector_ExportsEverySection(t *testing.T) {
	source := &staticSnapshot{snap: metricsSnapshot()}
	registry := prometheus.NewRegistry()
	require.NoError(t, registry.Register(NewCollector(source)))

	families, err := registry.Gather()
	require.NoError(t, err)
	assert.Equal(t, 1, source.calls, "one scrape takes exactly one snapshot")

	names := make(map[string]bool, len(families))
	for _, f := range families {
		names[f.GetName()] = true
	}
	for _, want := range []string{
		"gatewayd_service_active", "gatewayd_service_healthy",
		"gatewayd_bgp_peer_established", "gatewayd_bgp_peer_prefixes",
		"gatewayd_bfd_session_up", "gatewayd_bfd_failure_transitions_total",
		"gatewayd_tunnel_up", "gatewayd_tunnel_bytes_total",
		"gatewayd_uplink_policy_rules", "gatewayd_hostfw_installed",
		"gatewayd_firewall_flows", "gatewayd_nat_dnat_rules", "gatewayd_pipeline_installed",
	} {
		assert.True(t, names[want], "missing metric %s", want)
	}

	expected := `
# HELP gatewayd_bgp_peer_established 1 when the BGP session is established, 0 otherwise.
# TYPE gatewayd_bgp_peer_established gauge
gatewayd_bgp_peer_established{asn="64512",gateway="node-01-gateway",peer="10.255.0.2"} 1
gatewayd_bgp_peer_established{asn="64512",gateway="node-01-gateway",peer="10.255.0.6"} 0
# HELP gatewayd_tunnel_up 1 when the tunnel link is up, 0 otherwise.
# TYPE gatewayd_tunnel_up gauge
gatewayd_tunnel_up{gateway="node-01-gateway",transport="ipsec",tunnel="gre-pri",uplink="isp-a"} 1
gatewayd_tunnel_up{gateway="node-01-gateway",transport="gre",tunnel="gre-alt",uplink=""} 0
`
	require.NoError(t, testutil.GatherAndCompare(registry, strings.NewReader(expected),
		"gatewayd_bgp_peer_established", "gatewayd_tunnel_up"))

	bfd := `
# HELP gatewayd_bfd_failure_transitions_total BFD session failures since the session was created.
# TYPE gatewayd_bfd_failure_transitions_total counter
gatewayd_bfd_failure_transitions_total{gateway="node-01-gateway",peer="10.255.0.2"} 4
`
	require.NoError(t, testutil.GatherAndCompare(registry, strings.NewReader(bfd),
		"gatewayd_bfd_failure_transitions_total"), "only the peer that runs BFD reports one")
}

func TestCollector_AbsentSectionsEmitNoSeries(t *testing.T) {
	source := &staticSnapshot{snap: &gwstate.Snapshot{GatewayID: "bare"}}
	registry := prometheus.NewRegistry()
	require.NoError(t, registry.Register(NewCollector(source)))

	families, err := registry.Gather()
	require.NoError(t, err)
	assert.Empty(t, families, "a gateway running nothing reports no series, not zeroes")

	t.Run("a peer without BFD emits no BFD series", func(t *testing.T) {
		source.snap = &gwstate.Snapshot{
			GatewayID: "bare",
			BGP:       gwstate.BGPState{Peers: []gwstate.BGPPeerState{{Address: "10.255.0.2", State: "Idle"}}},
		}
		count, err := testutil.GatherAndCount(registry, "gatewayd_bfd_session_up")
		require.NoError(t, err)
		assert.Zero(t, count)
	})

	t.Run("a tunnel never re-keyed emits no rekey timestamp", func(t *testing.T) {
		source.snap = &gwstate.Snapshot{
			GatewayID: "bare",
			Tunnels:   []gwstate.TunnelState{{Name: "gre-alt", State: "up"}},
		}
		count, err := testutil.GatherAndCount(registry, "gatewayd_tunnel_last_rekey_timestamp_seconds")
		require.NoError(t, err)
		assert.Zero(t, count)
	})
}

func TestCollector_NilSnapshotIsNotAScrapeFailure(t *testing.T) {
	registry := prometheus.NewRegistry()
	require.NoError(t, registry.Register(NewCollector(&staticSnapshot{})))
	families, err := registry.Gather()
	require.NoError(t, err)
	assert.Empty(t, families)
}

func TestCollector_DescribesEveryMetricItCollects(t *testing.T) {
	collector := NewCollector(&staticSnapshot{snap: metricsSnapshot()})
	described := make(chan *prometheus.Desc, 64)
	collector.Describe(described)
	close(described)
	assert.Len(t, described, len(collector.descs()))
}

func TestGatewayImplementsSnapshotSource(t *testing.T) {
	var _ SnapshotSource = (*Gateway)(nil)
}
