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
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/hostfw"
	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/tunnel"
)

// The telemetry snapshot's datapath sections (#594) are derived from each
// service's own status. A service that is not running contributes nothing,
// so an operator never reads a zero value as "installed and empty".

// observabilityGateway builds a gateway running tunnels, hostfw, NAT,
// firewall and transit against in-memory fakes, and returns it with the
// fakes the test drives.
func observabilityGateway(t *testing.T, peers []*api.Peer) (*Gateway, *fakeTunnelManager, *fakeBGPServer) {
	t.Helper()

	tunnels := &fakeTunnelManager{
		down: map[string]bool{},
		statuses: map[string]tunnel.TunnelStatus{
			"gre-mia": {
				Transport: tunnel.TransportIPsec, Uplink: "att", Bound: true,
				LocalIP: "99.12.246.36", RemoteIP: "45.63.110.165", TunnelIP: "10.255.0.1/30",
				RxBytes: 4096, TxBytes: 2048, RxPackets: 32, TxPackets: 16,
				RekeyInterval: 8 * time.Hour,
				LastRekey:     time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC),
			},
			"gre-atl": {
				Transport: tunnel.TransportGRE,
				LocalIP:   "99.12.246.36", RemoteIP: "66.42.90.190", TunnelIP: "10.255.0.5/30",
			},
		},
		uplinks: []tunnel.UplinkStatus{{
			Name: "att", Interface: "eth6", Table: 101, GatewayV4: "99.12.246.38",
			Addresses: []string{"99.12.246.36/29"}, Priority: 1000, RuleCount: 1,
			Tunnels: []string{"gre-mia"},
		}},
	}
	server := &fakeBGPServer{listPeers: peers}

	cfg := natGatewayConfig()
	cfg.ID = "lab-node-1-gateway"
	cfg.Firewall = &FirewallConfig{Enabled: true, DefaultPolicy: "deny"}
	cfg.HostFW = &hostfw.Config{Enabled: true}
	cfg.Tunnels = []TunnelConfig{
		{Name: "gre-mia", Type: "gre", Local: "99.12.246.36", Remote: "45.63.110.165", TunnelIP: "10.255.0.1/30"},
		{Name: "gre-atl", Type: "gre", Local: "99.12.246.36", Remote: "66.42.90.190", TunnelIP: "10.255.0.5/30"},
	}
	cfg.BGP = &bgp.BGPConfig{
		ASN:      401870,
		RouterID: netip.MustParseAddr("23.143.36.4"),
		Neighbors: []bgp.NeighborConfig{{
			Address:         netip.MustParseAddr("10.255.0.2"),
			ASN:             401870,
			EnabledFamilies: []bgp.AddressFamily{bgp.AFamilyIPv4Unicast},
		}},
	}
	cfg.Host = &HostRuntime{
		TunnelManager: tunnels,
		HostFWApplier: &fakeHostFWApplier{},
		BGPServer:     server,
	}

	gw := startGateway(t, cfg)
	t.Cleanup(func() { _ = gw.Stop(context.Background()) })
	return gw, tunnels, server
}

// establishedPeer is one GoBGP peer with a BFD session up.
func establishedPeer(address string, received, accepted, sent uint64) *api.Peer {
	return &api.Peer{
		Conf: &api.PeerConf{NeighborAddress: address, PeerAsn: 401870, Description: "POP"},
		Bfd:  &api.BfdPeerConfig{Enabled: true, DesiredMinimumTxInterval: 300000, RequiredMinimumReceive: 300000, DetectionMultiplier: 3},
		State: &api.PeerState{
			SessionState: api.PeerState_SESSION_STATE_ESTABLISHED,
			AdminState:   api.PeerState_ADMIN_STATE_UP,
			RouterId:     "23.143.36.1",
			Messages:     &api.Messages{Received: &api.Message{Total: 40}, Sent: &api.Message{Total: 41}},
			BfdState: &api.BfdPeerState{
				SessionState:       api.BfdSessionState_BFD_SESSION_STATE_UP,
				RemoteSessionState: api.BfdSessionState_BFD_SESSION_STATE_UP,
			},
		},
		Timers:    &api.Timers{State: &api.TimersState{NegotiatedHoldTime: 30}},
		Transport: &api.Transport{LocalAddress: "10.255.0.1"},
		AfiSafis: []*api.AfiSafi{{
			Config: &api.AfiSafiConfig{Enabled: true, Family: &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST}},
			State:  &api.AfiSafiState{Received: received, Accepted: accepted, Advertised: sent},
		}},
	}
}

func TestSnapshot_ReportsEveryDatapathSection(t *testing.T) {
	gw, _, _ := observabilityGateway(t, []*api.Peer{
		establishedPeer("10.255.0.6", 60, 59, 2),
		establishedPeer("10.255.0.2", 120, 118, 2),
	})

	snap := gw.Snapshot()

	// Services: one entry per configured section, active and healthy from
	// the service, not from the handler's own bookkeeping.
	byName := make(map[string]gwstate.ServiceState, len(snap.Services))
	for _, svc := range snap.Services {
		byName[svc.Name] = svc
	}
	require.Contains(t, byName, ServiceTunnels)
	assert.True(t, byName[ServiceTunnels].Active)
	assert.True(t, byName[ServiceTunnels].Healthy)
	assert.Empty(t, byName[ServiceTunnels].RefusedReason)

	// BGP: sessions come from the speaker, sorted, with prefix counters and
	// the BFD session.
	require.Len(t, snap.BGP.Peers, 2)
	assert.Equal(t, "10.255.0.2", snap.BGP.Peers[0].Address, "peers are sorted by address")
	assert.Equal(t, uint32(401870), snap.BGP.LocalASN)
	assert.Equal(t, "23.143.36.4", snap.BGP.RouterID)
	assert.Equal(t, 2, snap.BGP.PeerCount)
	assert.Equal(t, 2, snap.BGP.EstablishedPeers)
	assert.Equal(t, 177, snap.BGP.ReceivedPrefixes, "accepted prefixes across the sessions")
	peer := snap.BGP.Peers[0]
	assert.Equal(t, "Established", peer.State)
	assert.Equal(t, int64(120), peer.PrefixesReceived)
	assert.Equal(t, int64(118), peer.PrefixesAccepted)
	assert.Equal(t, int64(2), peer.PrefixesSent)
	assert.Equal(t, []string{"ipv4-unicast"}, peer.Families)
	assert.Equal(t, 30, peer.HoldTimeSeconds)
	require.NotNil(t, peer.BFD)
	assert.Equal(t, "up", peer.BFD.State)
	assert.Equal(t, int64(300), peer.BFD.TxIntervalMS)
	assert.Equal(t, uint8(3), peer.BFD.DetectionMultiplier)

	// Tunnels and the uplink policy routes behind them.
	require.Len(t, snap.Tunnels, 2)
	assert.Equal(t, "gre-atl", snap.Tunnels[0].Name, "tunnels are sorted by name")
	mia := snap.Tunnels[1]
	assert.Equal(t, "gre-mia", mia.Name)
	assert.Equal(t, tunnel.TransportIPsec, mia.Transport)
	assert.Equal(t, "gre", mia.Type)
	assert.Equal(t, "up", mia.State)
	assert.Equal(t, "att", mia.Uplink)
	assert.True(t, mia.Bound)
	assert.Equal(t, uint64(4096), mia.RxBytes)
	assert.Equal(t, int64(28800), mia.RekeySeconds)
	require.Len(t, snap.Uplinks, 1)
	assert.Equal(t, 101, snap.Uplinks[0].Table)
	assert.Equal(t, []string{"gre-mia"}, snap.Uplinks[0].Tunnels)

	// Host filter, firewall, NAT and the base pipeline.
	require.NotNil(t, snap.HostFirewall)
	assert.True(t, snap.HostFirewall.Active)
	assert.True(t, snap.HostFirewall.Installed)
	assert.NotEmpty(t, snap.HostFirewall.Fingerprint)
	assert.Empty(t, snap.HostFirewall.LastError)

	require.NotNil(t, snap.Firewall)
	assert.True(t, snap.Firewall.Active)
	assert.Positive(t, snap.Firewall.FlowCount)

	require.NotNil(t, snap.NAT)
	assert.True(t, snap.NAT.Active)
	assert.True(t, snap.NAT.SNATEnabled)

	require.NotNil(t, snap.Pipeline)
	assert.True(t, snap.Pipeline.Installed)
	assert.Equal(t, "br-test", snap.Pipeline.Bridge)
	assert.Equal(t, "lab-node-1-gateway", snap.Pipeline.Owner)
	assert.Equal(t, string(TerminalNormal), snap.Pipeline.Terminal)
	assert.Equal(t, PipelineFailMode, snap.Pipeline.FailMode)
}

func TestSnapshot_ServicesNotRunningContributeNoSection(t *testing.T) {
	// A gateway that has not started runs nothing: the sections are absent
	// and the refused DHCP section still names its blocker.
	cfg := validConfig()
	cfg.DHCP = &DHCPServiceConfig{Enabled: true, Interface: "eth0"}
	gw, err := NewGateway(cfg)
	require.NoError(t, err)

	snap := gw.Snapshot()
	assert.Nil(t, snap.HostFirewall, "a section the gateway does not run is absent, not zeroed")
	assert.Nil(t, snap.Firewall)
	assert.Nil(t, snap.NAT)
	assert.Empty(t, snap.Tunnels)
	assert.Empty(t, snap.Uplinks)
	assert.Empty(t, snap.BGP.Peers)
	assert.Nil(t, snap.Pipeline, "no datapath service, no pipeline")

	// A refused section still reports itself, with the blocker.
	var dhcp *gwstate.ServiceState
	for i := range snap.Services {
		if snap.Services[i].Name == ServiceDHCP {
			dhcp = &snap.Services[i]
		}
	}
	require.NotNil(t, dhcp, "a refused section is reported, never dropped")
	assert.False(t, dhcp.Active)
	assert.False(t, dhcp.Healthy)
	assert.Contains(t, dhcp.RefusedReason, "IPAM allocator")
}

func TestSnapshot_UnreadableSectionsAreOmittedNotFabricated(t *testing.T) {
	gw, tunnels, server := observabilityGateway(t, nil)

	tunnels.mu.Lock()
	tunnels.listErr = errors.New("netlink: EBUSY")
	tunnels.mu.Unlock()
	server.mu.Lock()
	server.listErr = errors.New("gobgp: unavailable")
	server.mu.Unlock()

	snap := gw.Snapshot()
	assert.Empty(t, snap.Tunnels, "a tunnel list that cannot be read is omitted")
	assert.Empty(t, snap.BGP.Peers, "a session table that cannot be read is omitted")
	assert.Zero(t, snap.BGP.PeerCount, "and no peer count is invented for it")
	assert.Equal(t, uint32(401870), snap.BGP.LocalASN, "the configured identity still reports")
	require.NotNil(t, snap.NAT, "the sections that could be read are unaffected")
}

func TestSnapshot_GoldenJSON(t *testing.T) {
	gw, _, _ := observabilityGateway(t, []*api.Peer{establishedPeer("10.255.0.2", 120, 118, 2)})

	snap := gw.Snapshot()
	// Fields that vary per host or per run are pinned so the golden file
	// documents the shape, not this machine.
	snap.Hostname = "lab-node-1"
	snap.Interfaces = nil
	snap.Annotations = map[string]string{"state": snap.Annotations["state"], "uptime": "1m0s"}
	snap.ReportedAt = time.Date(2026, 9, 8, 22, 30, 0, 0, time.UTC)
	snap.HostFirewall.LastReconcile = time.Date(2026, 9, 8, 22, 29, 0, 0, time.UTC)
	snap.Firewall.LastReconcile = time.Date(2026, 9, 8, 22, 29, 0, 0, time.UTC)

	got, err := json.MarshalIndent(snap, "", "  ")
	require.NoError(t, err)
	got = append(got, '\n')

	golden := filepath.Join("testdata", "snapshot.golden.json")
	if os.Getenv("UPDATE_GOLDEN") != "" {
		require.NoError(t, os.WriteFile(golden, got, 0o600))
	}
	want, err := os.ReadFile(golden)
	require.NoError(t, err, "run with UPDATE_GOLDEN=1 to write the golden file")
	assert.JSONEq(t, string(want), string(got))
}
