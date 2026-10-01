//go:build integration

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

package sdn

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ct"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/loadbalancer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// These tests are the keystone assertion of #567: a real gateway.Gateway,
// started with its datapath services enabled on a live OVS bridge, owns
// the base pipeline itself. Nothing here calls installPipelinePlumbing —
// that helper was the workaround that hid the missing table-0 hand-off.

const (
	gwPipeFWBridge  = "tp-gwpipe-fw"
	gwPipeNATBridge = "tp-gwpipe-nat"
	gwPipeLBBridge  = "tp-gwpipe-lb"

	gwPipeNATInternal = "10.231.1.0/24"
	gwPipeNATClientIP = "10.231.1.5"
	gwPipeNATServerIP = "10.231.2.5"
	gwPipeNATExternal = "10.231.2.250"
	gwPipeNATPort     = 9191
)

// newGatewayRuntime builds the runtime gatewayd's serve command injects,
// against the live OVSDB client.
func newGatewayRuntime(t *testing.T, client *ovs.Client, bridge string,
	zones []zone.ZoneConfig, networks map[zone.Zone]zoneflows.NetworkSummary) *gateway.GatewayRuntime {
	t.Helper()
	controller, err := policy.NewOVSFlowController(client)
	require.NoError(t, err, "create flow controller")
	return &gateway.GatewayRuntime{
		Controller: controller,
		OVS:        client,
		Groups:     client,
		Bridge:     bridge,
		Zones:      func() []zone.ZoneConfig { return zones },
		Networks:   func() map[zone.Zone]zoneflows.NetworkSummary { return networks },
		CTZones:    ct.NewZoneAllocator(nil),
		Logger:     slog.Default(),
	}
}

func baseGatewayConfig(id string, rt *gateway.GatewayRuntime) *gateway.GatewayConfig {
	return &gateway.GatewayConfig{
		Enabled:       true,
		ID:            id,
		MinReputation: gateway.MinReputation,
		MinAgeDays:    gateway.MinAgeDays,
		MinUptimePct:  gateway.MinUptimePct,
		Runtime:       rt,
	}
}

func startGatewayForTest(t *testing.T, ctx context.Context, cfg *gateway.GatewayConfig) *gateway.Gateway {
	t.Helper()
	gw, err := gateway.NewGateway(cfg)
	require.NoError(t, err, "create gateway")
	gw.SetNodeMetrics(1.0, 365*24*time.Hour, 100.0)
	require.NoError(t, gw.Start(ctx), "start gateway")
	t.Cleanup(func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer stopCancel()
		if stopErr := gw.Stop(stopCtx); stopErr != nil {
			t.Logf("gateway stop: %v", stopErr)
		}
	})
	return gw
}

// pipelineFlows returns the base-pipeline flows on the bridge by cookie.
func pipelineFlows(ctx context.Context, t *testing.T, client *ovs.Client, bridge string) []*ovs.Flow {
	t.Helper()
	flows, err := client.GetFlowStats(ctx, bridge, fmt.Sprintf("cookie=0x%x/0x%x", gateway.CookiePipeline, gateway.CookiePipelineMask))
	require.NoError(t, err, "dump pipeline flows")
	return flows
}

// TestGatewayPipeline_FirewallVerdictsReachable proves the firewall's deny
// verdict is reachable through the gateway's own pipeline. The negative
// control comes first: on the bare bridge, NORMAL forwarding connects the
// pair the firewall is about to deny — which is exactly what a gateway
// reporting `firewall: healthy` did before #567.
func TestGatewayPipeline_FirewallVerdictsReachable(t *testing.T) {
	requireOVSForTest(t)

	bridge := setupTestBridge(t, gwPipeFWBridge)
	client := newOVSDBClient(t)

	createNSEndpoint(t, bridge.name, "tpgwf-a", ctFWClientIP+"/24", ctFWVLANAlpha,
		ctFWSubnetBeta, ctFWSubnetGamma)
	createNSEndpoint(t, bridge.name, "tpgwf-b", ctFWAllowedIP+"/24", ctFWVLANAlpha,
		ctFWSubnetAlpha)
	createNSEndpoint(t, bridge.name, "tpgwf-c", ctFWDeniedIP+"/24", ctFWVLANAlpha,
		ctFWSubnetAlpha)

	allowedAddr := fmt.Sprintf("%s:%d", ctFWAllowedIP, ctFWServerPort)
	deniedAddr := fmt.Sprintf("%s:%d", ctFWDeniedIP, ctFWServerPort)
	startEchoServer(t, "tpgwf-b", allowedAddr)
	startEchoServer(t, "tpgwf-c", deniedAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	t.Run("NegativeControl_BareBridgeForwardsTheDeniedPair", func(t *testing.T) {
		require.Empty(t, pipelineFlows(ctx, t, client, bridge.name), "the bridge starts with no pipeline")
		conn, err := nsDial("tpgwf-a", deniedAddr, 5*time.Second)
		require.NoError(t, err, "with no pipeline, NORMAL forwarding connects the pair the firewall will deny")
		conn.Close()
	})

	rt := newGatewayRuntime(t, client, bridge.name, ctFWZones(), ctFWNetworks())
	cfg := baseGatewayConfig("gwpipe-fw", rt)
	cfg.Firewall = &gateway.FirewallConfig{Enabled: true, DefaultPolicy: "deny"}
	gw := startGatewayForTest(t, ctx, cfg)

	t.Run("PipelineIsOwnedAndSecure", func(t *testing.T) {
		require.True(t, rt.PipelineInstalled())
		flows := pipelineFlows(ctx, t, client, bridge.name)
		require.Len(t, flows, 3, "table 0 → 10 → 30 hand-off")
		tables := map[int]bool{}
		for _, f := range flows {
			tables[f.Table] = true
		}
		require.True(t, tables[0] && tables[10] && tables[30], "%+v", flows)

		b, err := client.GetBridge(ctx, bridge.name)
		require.NoError(t, err)
		require.Equal(t, gateway.PipelineFailMode, b.FailMode)
		owner, held, err := gateway.ReadPipelineOwner(ctx, client, bridge.name)
		require.NoError(t, err)
		require.True(t, held)
		require.Equal(t, "gatewayd:gwpipe-fw", owner.Owner)
		require.Equal(t, gateway.TerminalNormal, owner.Terminal)
		require.True(t, gw.HasService(gateway.ServiceFirewall))
	})

	t.Run("AllowedPairConnects", func(t *testing.T) {
		conn, err := nsDial("tpgwf-a", allowedAddr, 5*time.Second)
		require.NoError(t, err, "allowed pair alpha→beta must connect through the pipeline")
		defer conn.Close()
		fmt.Fprintln(conn, "hello")
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
		reply, err := bufio.NewReader(conn).ReadString('\n')
		require.NoError(t, err)
		require.Equal(t, "echo:hello\n", reply)
	})

	t.Run("DeniedPairTimesOut", func(t *testing.T) {
		_, err := nsDial("tpgwf-a", deniedAddr, 2*time.Second)
		require.Error(t, err, "denied pair alpha→gamma must not connect: the verdict is reachable now")
	})

	t.Run("StopRestoresTheBridge", func(t *testing.T) {
		require.NoError(t, gw.Stop(ctx))
		require.Empty(t, pipelineFlows(ctx, t, client, bridge.name))
		_, held, err := gateway.ReadPipelineOwner(ctx, client, bridge.name)
		require.NoError(t, err)
		require.False(t, held)
		b, err := client.GetBridge(ctx, bridge.name)
		require.NoError(t, err)
		require.NotEqual(t, gateway.PipelineFailMode, b.FailMode, "fail_mode is put back")
	})
}

// TestGatewayPipeline_NATTranslatesEgress proves the NAT service's
// commit is reachable: a datagram from the internal subnet arrives at the
// far side carrying the external address as its source. UDP is used
// deliberately — the SNAT rule set translates the forward direction only
// (the reverse un-NAT on replies is Phase 5 work), so a TCP handshake is
// not the right probe for "the table-25 commit ran".
func TestGatewayPipeline_NATTranslatesEgress(t *testing.T) {
	requireOVSForTest(t)

	bridge := setupTestBridge(t, gwPipeNATBridge)
	client := newOVSDBClient(t)

	clientEP := createNSEndpoint(t, bridge.name, "tpgwn-c", gwPipeNATClientIP+"/24", 0, "10.231.2.0/24")
	uplink := createNSEndpoint(t, bridge.name, "tpgwn-u", gwPipeNATServerIP+"/24", 0, gwPipeNATInternal)
	_ = clientEP
	// The server must answer ARP for the external address so the
	// translated datagram has a destination MAC on the far side.
	runCmd(t, "ip", "netns", "exec", "tpgwn-u", "ip", "addr", "add", gwPipeNATExternal+"/24", "dev", uplink.PeerIf)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// A UDP sink in the far namespace reports the source it saw.
	seen := make(chan string, 8)
	var pc net.PacketConn
	require.NoError(t, inNetns("tpgwn-u", func() error {
		var listenErr error
		pc, listenErr = net.ListenPacket("udp", fmt.Sprintf("%s:%d", gwPipeNATServerIP, gwPipeNATPort))
		return listenErr
	}), "listen udp in far namespace")
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 64)
		for {
			_, addr, readErr := pc.ReadFrom(buf)
			if readErr != nil {
				return
			}
			seen <- addr.(*net.UDPAddr).IP.String()
		}
	}()

	rt := newGatewayRuntime(t, client, bridge.name, nil, nil)
	cfg := baseGatewayConfig("gwpipe-nat", rt)
	cfg.Uplinks = []gateway.UplinkConfig{{Name: uplink.HostIf, MTU: 1500}}
	cfg.NAT = &gateway.NATConfig{
		Enabled:        true,
		ExternalIP:     gwPipeNATExternal,
		InternalCIDR:   gwPipeNATInternal,
		PortRangeStart: 1024,
		PortRangeEnd:   65535,
		MaxSessions:    65536,
	}
	gw := startGatewayForTest(t, ctx, cfg)
	require.True(t, gw.HasService(gateway.ServiceNAT))
	require.True(t, rt.PipelineInstalled())

	sendCtx, sendCancel := context.WithTimeout(ctx, 15*time.Second)
	defer sendCancel()
	waitFor(sendCtx, t, "translated datagram", 300*time.Millisecond, 15*time.Second, func() bool {
		require.NoError(t, inNetns("tpgwn-c", func() error {
			conn, dialErr := net.DialTimeout("udp", fmt.Sprintf("%s:%d", gwPipeNATServerIP, gwPipeNATPort), 2*time.Second)
			if dialErr != nil {
				return dialErr
			}
			defer conn.Close()
			_, writeErr := fmt.Fprintln(conn, "probe")
			return writeErr
		}))
		select {
		case src := <-seen:
			if src == gwPipeNATExternal {
				return true
			}
			t.Logf("datagram arrived from %s, not the external address yet", src)
			return false
		default:
			return false
		}
	})
}

// TestGatewayPipeline_LoadBalancerDispatchInstalled proves the load
// balancer's VIP dispatch is reachable through the gateway's pipeline: the
// select group exists and the table-26 dispatch flow is routed from the
// table-10 gate. End-to-end delivery to a backend still needs the MAC
// rewrite the LB service does not program (group_lb_test.go supplies it
// from its harness), which is the LB's own gap, not the pipeline's.
func TestGatewayPipeline_LoadBalancerDispatchInstalled(t *testing.T) {
	requireOVSForTest(t)

	bridge := setupTestBridge(t, gwPipeLBBridge)
	client := newOVSDBClient(t)
	createNSEndpoint(t, bridge.name, "tpgwl-b1", lbBackend1+"/24", 0)
	createNSEndpoint(t, bridge.name, "tpgwl-b2", lbBackend2+"/24", 0)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	rt := newGatewayRuntime(t, client, bridge.name, nil, nil)
	cfg := baseGatewayConfig("gwpipe-lb", rt)
	cfg.LoadBalancer = &gateway.LoadBalancerConfig{
		Enabled:             true,
		Algorithm:           "hash",
		HealthCheckInterval: time.Hour,
		HealthCheckTimeout:  time.Second,
		MaxBackends:         8,
		VIPs: []gateway.VIPConfig{{
			Address:  lbVIPAddr,
			Port:     lbVIPPort,
			Protocol: "tcp",
			Backends: []gateway.BackendConfig{
				{Address: lbBackend1, Port: lbBackPort},
				{Address: lbBackend2, Port: lbBackPort},
			},
		}},
	}
	gw := startGatewayForTest(t, ctx, cfg)
	require.True(t, gw.HasService(gateway.ServiceLoadBalancer))
	require.True(t, rt.PipelineInstalled())

	target := netip.AddrPortFrom(netip.MustParseAddr(lbVIPAddr), lbVIPPort)
	status, err := gw.GetVIP(ctx, "tcp", target)
	require.NoError(t, err, "the VIP the gateway config declared is registered")
	require.NotZero(t, status.CTZone)

	flows, err := client.GetFlowStats(ctx, bridge.name, fmt.Sprintf("table=%d", 26))
	require.NoError(t, err)
	dispatch := false
	for _, f := range flows {
		if strings.Contains(f.Match, lbVIPAddr) && strings.Contains(f.Actions, "group:") {
			dispatch = true
		}
	}
	require.True(t, dispatch, "table 26 carries the VIP's select-group dispatch: %+v", flows)

	gate, err := client.GetFlowStats(ctx, bridge.name, "table=10")
	require.NoError(t, err)
	routed := false
	for _, f := range gate {
		if strings.Contains(f.Actions, "goto_table:20") || strings.Contains(f.Actions, "table=26") {
			routed = true
		}
	}
	require.True(t, routed, "the table-10 gate routes toward the LB dispatch: %+v", gate)
	_ = loadbalancer.CookieLoadBalancer
}
