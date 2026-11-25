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

package sdn

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// `platformctl sdn gateway snapshot` renders the telemetry snapshot section
// by section (#594): what each service programmed, never a bare "healthy".

func cliSnapshot() *platformv1.GatewaySnapshot {
	return &platformv1.GatewaySnapshot{
		GatewayId:  "node-01-gateway",
		Hostname:   "node-01",
		ReportedAt: timestamppb.New(time.Date(2026, 9, 8, 22, 0, 0, 0, time.UTC)),
		Health:     &platformv1.SnapshotHealth{Status: "degraded"},
		Services: []*platformv1.SnapshotService{
			{Name: "tunnels", Active: true, Healthy: true},
			{Name: "dhcp", RefusedReason: "the DHCP service needs an IPAM allocator"},
		},
		Bgp: &platformv1.SnapshotBGP{
			LocalAsn: 64512, RouterId: "203.0.113.4", PeerCount: 1, EstablishedPeers: 1,
			Peers: []*platformv1.SnapshotBGPPeer{{
				Address: "10.255.0.2", Asn: 64512, State: "Established",
				PrefixesReceived: 120, PrefixesAccepted: 118, PrefixesSent: 2,
				Bfd: &platformv1.SnapshotBFD{State: "up", RemoteState: "up", FailureTransitions: 2},
			}},
		},
		Tunnels: []*platformv1.SnapshotTunnel{{
			Name: "gre-pri", Transport: "ipsec", State: "up", Uplink: "isp-a",
			LocalIp: "198.51.100.4", RemoteIp: "198.51.100.100", RxBytes: 4096, TxBytes: 2048,
		}},
		Uplinks: []*platformv1.SnapshotUplink{{
			Name: "isp-a", Interface: "eth6", Table: 101, GatewayV4: "198.51.100.6",
			RuleCount: 1, Tunnels: []string{"gre-pri"},
		}},
		HostFirewall: &platformv1.SnapshotHostFirewall{Installed: true, RuleCount: 10, Fingerprint: "sha256:abc", LastError: "netlink busy"},
		Firewall:     &platformv1.SnapshotFirewall{Active: true, FlowCount: 26},
		Nat: &platformv1.SnapshotNAT{SnatEnabled: true, DnatRules: 2, Uplinks: []*platformv1.SnapshotNATUplink{
			{Name: "isp-a", IsDefault: true, PoolAddresses: 8, Ports: 64512, StaticTranslations: 1},
		}},
		Pipeline: &platformv1.SnapshotPipeline{Installed: true, Bridge: "br-fabric", Owner: "node-01-gateway", Terminal: "normal", FailMode: "secure"},
		Overlay: &platformv1.SnapshotOverlay{
			Running: true, LocalVtep: "192.0.2.10", VniCount: 1, RemoteVtepCount: 1,
			LocalMacCount: 2, RemoteMacCount: 1, PrefixCount: 1, RefusedBindings: 3, RefusedReplays: 4,
			NdCounters: &platformv1.SnapshotOverlayNDCounters{Punted: 11, Answered: 7, MeterDropped: 2, QueueDropped: 1, FellThrough: 3},
			AdmittedVteps: []*platformv1.GatewayAdmittedVTEP{{
				Vtep: "198.51.100.10", DeviceId: 42, HostId: "host-42", Serial: "SERIAL42",
				AllocationId: "alloc-42", BaselineSource: "golden", ProfileId: 9,
			}},
		},
	}
}

func TestPrintGatewaySnapshot_RendersEverySection(t *testing.T) {
	var out bytes.Buffer
	printGatewaySnapshot(&out, cliSnapshot())
	text := out.String()

	for _, want := range []string{
		"Gateway:  node-01-gateway",
		"Health:   degraded",
		"tunnels        active=true  healthy=true",
		"refused: the DHCP service needs an IPAM allocator",
		"BGP  AS 64512  router-id 203.0.113.4  1/1 established",
		"10.255.0.2         AS64512    Established  recv=120 accepted=118 sent=2",
		"bfd up (remote up) failures=2",
		"gre-pri      ipsec      up     uplink=isp-a    198.51.100.4 -> 198.51.100.100  rx=4096 tx=2048",
		"isp-a      eth6     table=101  via 198.51.100.6 rules=1 tunnels=gre-pri",
		"Host filter  installed=true rules=10 fingerprint=sha256:abc",
		"last error: netlink busy",
		"Firewall     active=true flows=26",
		"NAT          snat=true dnat=2",
		"Pipeline     bridge=br-fabric owner=node-01-gateway terminal=normal fail-mode=secure",
		"Overlay      running=true local=192.0.2.10 vnis=1 remote-vteps=1 macs=2/1 prefixes=1 refused=3 refused-replays=4",
		"nd punted=11 answered=7 meter-dropped=2 queue-dropped=1 fell-through=3",
		"198.51.100.10   device=42 host=host-42 serial=SERIAL42 allocation=alloc-42 baseline=golden profile=9",
	} {
		assert.Contains(t, text, want)
	}
}

func TestPrintGatewaySnapshot_SparseAndAbsent(t *testing.T) {
	var out bytes.Buffer
	printGatewaySnapshot(&out, nil)
	assert.Equal(t, "no snapshot\n", out.String(), "a missing snapshot says so instead of printing empty sections")

	out.Reset()
	printGatewaySnapshot(&out, &platformv1.GatewaySnapshot{GatewayId: "bare"})
	text := out.String()
	assert.Contains(t, text, "Gateway:  bare")
	assert.NotContains(t, text, "Tunnels", "a gateway running no tunnels prints no tunnel section")
	assert.NotContains(t, text, "Pipeline")
	assert.NotContains(t, text, "BGP")
}

func TestRunGatewaySnapshot_ContradictoryFlags(t *testing.T) {
	err := runGatewaySnapshot(newGatewaySnapshotCommand(func() *cli.CommonFlags { return nil }), nil, "node-01-gateway", true)
	var args *ErrSnapshotArguments
	require.ErrorAs(t, err, &args)
	assert.Contains(t, err.Error(), "use one")
}

func TestIsStructuredOutput(t *testing.T) {
	assert.False(t, isStructuredOutput(nil))
	assert.False(t, isStructuredOutput(&cli.CommonFlags{OutputFormat: cli.OutputFormatTable}))
	assert.True(t, isStructuredOutput(&cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}))
	assert.True(t, isStructuredOutput(&cli.CommonFlags{OutputFormat: cli.OutputFormatYAML}))
}

func TestGatewaySnapshotCommandIsRegistered(t *testing.T) {
	cmd := NewGatewayCommand(func() *cli.CommonFlags { return nil })
	var found bool
	for _, sub := range cmd.Commands() {
		if sub.Name() == "snapshot" {
			found = true
			assert.NotNil(t, sub.Flags().Lookup("gateway-id"))
			assert.NotNil(t, sub.Flags().Lookup("all"))
		}
	}
	assert.True(t, found, "the snapshot subcommand is registered")
}
