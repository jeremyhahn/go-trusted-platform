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
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ct"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/firewall"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
)

// Dual-uplink NAT topology (#586): one internal client, two "ISP" uplink
// namespaces on the same bridge. Egress to the default destination is
// translated to the ISP A pool address; egress to a prefix ISP B claims is
// translated to the ISP B pool; a static 1:1 host is reachable from the
// ISP B side on its external address.
const (
	natDUBridge   = "tp-nat-du"
	natDUInternal = "10.232.1.0/24"
	natDUClientIP = "10.232.1.5"
	natDUStaticIP = "10.232.1.10"

	natDUIspANet    = "10.232.2.0/24"
	natDUIspAServer = "10.232.2.5"
	natDUIspAPool   = "10.232.2.250"

	natDUIspBNet    = "10.232.3.0/24"
	natDUIspBServer = "10.232.3.5"
	natDUIspBPool   = "10.232.3.250"
	natDUStaticExt  = "10.232.3.240"

	natDUPort = 9292
)

// udpSourceSink listens in ns on addr:port and reports each datagram's
// source address on the returned channel.
func udpSourceSink(t *testing.T, ns, addr string) <-chan string {
	t.Helper()
	seen := make(chan string, 16)
	var pc net.PacketConn
	require.NoError(t, inNetns(ns, func() error {
		var err error
		pc, err = net.ListenPacket("udp", fmt.Sprintf("%s:%d", addr, natDUPort))
		return err
	}), "listen udp in %s", ns)
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 64)
		for {
			_, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			seen <- from.(*net.UDPAddr).IP.String()
		}
	}()
	return seen
}

// probeUntilSource sends UDP probes from ns to target until the sink sees
// a datagram from wantSrc.
func probeUntilSource(ctx context.Context, t *testing.T, ns, target, wantSrc string, seen <-chan string) {
	t.Helper()
	waitFor(ctx, t, "datagram translated to "+wantSrc, 300*time.Millisecond, 15*time.Second, func() bool {
		require.NoError(t, inNetns(ns, func() error {
			conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", target, natDUPort), 2*time.Second)
			if err != nil {
				return err
			}
			defer conn.Close()
			_, err = fmt.Fprintln(conn, "probe")
			return err
		}))
		select {
		case src := <-seen:
			if src == wantSrc {
				return true
			}
			t.Logf("datagram arrived from %s, want %s", src, wantSrc)
			return false
		default:
			return false
		}
	})
}

func TestNATDualUplink_TranslatesPerUplinkAndStatic(t *testing.T) {
	requireOVSForTest(t)

	bridge := setupTestBridge(t, natDUBridge)
	client := newOVSDBClient(t)

	// The client routes both far networks through the bridge; each uplink
	// namespace routes the internal prefix back and answers for its pool
	// (and, on ISP B, the static external) so translated packets have a
	// destination MAC on the far side.
	createNSEndpoint(t, bridge.name, "tpndu-c", natDUClientIP+"/24", 0, natDUIspANet, natDUIspBNet)
	ispA := createNSEndpoint(t, bridge.name, "tpndu-a", natDUIspAServer+"/24", 0, natDUInternal)
	ispB := createNSEndpoint(t, bridge.name, "tpndu-o", natDUIspBServer+"/24", 0, natDUInternal)
	runCmd(t, "ip", "netns", "exec", "tpndu-a", "ip", "addr", "add", natDUIspAPool+"/24", "dev", ispA.PeerIf)
	runCmd(t, "ip", "netns", "exec", "tpndu-o", "ip", "addr", "add", natDUIspBPool+"/24", "dev", ispB.PeerIf)
	runCmd(t, "ip", "netns", "exec", "tpndu-o", "ip", "addr", "add", natDUStaticExt+"/24", "dev", ispB.PeerIf)
	// The static host lives beside the client.
	runCmd(t, "ip", "netns", "exec", "tpndu-c", "ip", "addr", "add", natDUStaticIP+"/24", "dev", "vep-tpndu-c")

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()

	// The pipeline the gateway runtime normally owns (#567): drive the
	// service directly here, so the runtime's tables come from the fixture.
	rt := newGatewayRuntime(t, client, bridge.name, nil, nil)
	require.NoError(t, rt.EnsurePipeline(ctx, "nat-du", gateway.TerminalNormal))
	t.Cleanup(func() { _ = rt.RemovePipeline(context.Background()) })

	controller, err := policy.NewOVSFlowController(client)
	require.NoError(t, err)
	nat, err := firewall.NewNAT(firewall.Deps{
		Controller: controller,
		OVS:        client,
		Allocator:  ct.NewZoneAllocator(nil),
	}, firewall.NATConfig{
		PortRangeStart: 1024,
		PortRangeEnd:   65535,
		InternalCIDR:   natDUInternal,
		Bridge:         bridge.name,
		Uplinks: []firewall.NATUplink{
			{Name: "isp-a", Port: ispA.HostIf, Addresses: []string{natDUIspAPool}, Default: true},
			{Name: "isp-b", Port: ispB.HostIf, Addresses: []string{natDUIspBPool}, Destinations: []string{natDUIspBNet}},
		},
		Static: []firewall.StaticNAT{{Internal: natDUStaticIP, External: natDUStaticExt, Uplink: "isp-b"}},
	})
	require.NoError(t, err)
	require.NoError(t, nat.Start(ctx))
	t.Cleanup(func() { _ = nat.Stop(context.Background()) })

	ispASeen := udpSourceSink(t, "tpndu-a", natDUIspAServer)
	ispBSeen := udpSourceSink(t, "tpndu-o", natDUIspBServer)

	// Default destination → ISP A pool; ISP B-claimed destination → ISP B pool.
	probeUntilSource(ctx, t, "tpndu-c", natDUIspAServer, natDUIspAPool, ispASeen)
	probeUntilSource(ctx, t, "tpndu-c", natDUIspBServer, natDUIspBPool, ispBSeen)

	// Static 1:1 inbound: a probe from the ISP B side to the external
	// address arrives at the inside host, and the inside host's own egress
	// carries the external address rather than the pool.
	staticSeen := udpSourceSink(t, "tpndu-c", natDUStaticIP)
	waitFor(ctx, t, "static inbound translation", 300*time.Millisecond, 15*time.Second, func() bool {
		require.NoError(t, inNetns("tpndu-o", func() error {
			conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", natDUStaticExt, natDUPort), 2*time.Second)
			if err != nil {
				return err
			}
			defer conn.Close()
			_, err = fmt.Fprintln(conn, "probe")
			return err
		}))
		select {
		case src := <-staticSeen:
			return src == natDUIspBServer
		default:
			return false
		}
	})

	health := nat.Health()
	require.Len(t, health.Uplinks, 2)
	require.Equal(t, 1, health.Uplinks[1].Static)
}
