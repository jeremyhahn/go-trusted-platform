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
		GatewayId:  "lab-node-1-gateway",
		Hostname:   "lab-node-1",
		ReportedAt: timestamppb.New(time.Date(2026, 9, 8, 22, 0, 0, 0, time.UTC)),
		Health:     &platformv1.SnapshotHealth{Status: "degraded"},
		Services: []*platformv1.SnapshotService{
			{Name: "tunnels", Active: true, Healthy: true},
			{Name: "dhcp", RefusedReason: "the DHCP service needs an IPAM allocator"},
		},
		Bgp: &platformv1.SnapshotBGP{
			LocalAsn: 401870, RouterId: "23.143.36.4", PeerCount: 1, EstablishedPeers: 1,
			Peers: []*platformv1.SnapshotBGPPeer{{
				Address: "10.255.0.2", Asn: 401870, State: "Established",
				PrefixesReceived: 120, PrefixesAccepted: 118, PrefixesSent: 2,
				Bfd: &platformv1.SnapshotBFD{State: "up", RemoteState: "up", FailureTransitions: 2},
			}},
		},
		Tunnels: []*platformv1.SnapshotTunnel{{
			Name: "gre-mia", Transport: "ipsec", State: "up", Uplink: "att",
			LocalIp: "99.12.246.36", RemoteIp: "45.63.110.165", RxBytes: 4096, TxBytes: 2048,
		}},
		Uplinks: []*platformv1.SnapshotUplink{{
			Name: "att", Interface: "eth6", Table: 101, GatewayV4: "99.12.246.38",
			RuleCount: 1, Tunnels: []string{"gre-mia"},
		}},
		HostFirewall: &platformv1.SnapshotHostFirewall{Installed: true, RuleCount: 10, Fingerprint: "sha256:abc", LastError: "netlink busy"},
		Firewall:     &platformv1.SnapshotFirewall{Active: true, FlowCount: 26},
		Nat: &platformv1.SnapshotNAT{SnatEnabled: true, DnatRules: 2, Uplinks: []*platformv1.SnapshotNATUplink{
			{Name: "att", IsDefault: true, PoolAddresses: 8, Ports: 64512, StaticTranslations: 1},
		}},
		Pipeline: &platformv1.SnapshotPipeline{Installed: true, Bridge: "br-fabric", Owner: "lab-node-1-gateway", Terminal: "normal", FailMode: "secure"},
	}
}

func TestPrintGatewaySnapshot_RendersEverySection(t *testing.T) {
	var out bytes.Buffer
	printGatewaySnapshot(&out, cliSnapshot())
	text := out.String()

	for _, want := range []string{
		"Gateway:  lab-node-1-gateway",
		"Health:   degraded",
		"tunnels        active=true  healthy=true",
		"refused: the DHCP service needs an IPAM allocator",
		"BGP  AS 401870  router-id 23.143.36.4  1/1 established",
		"10.255.0.2         AS401870   Established  recv=120 accepted=118 sent=2",
		"bfd up (remote up) failures=2",
		"gre-mia      ipsec      up     uplink=att      99.12.246.36 -> 45.63.110.165  rx=4096 tx=2048",
		"att        eth6     table=101  via 99.12.246.38 rules=1 tunnels=gre-mia",
		"Host filter  installed=true rules=10 fingerprint=sha256:abc",
		"last error: netlink busy",
		"Firewall     active=true flows=26",
		"NAT          snat=true dnat=2",
		"Pipeline     bridge=br-fabric owner=lab-node-1-gateway terminal=normal fail-mode=secure",
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
	err := runGatewaySnapshot(newGatewaySnapshotCommand(func() *cli.CommonFlags { return nil }), nil, "lab-node-1-gateway", true)
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
