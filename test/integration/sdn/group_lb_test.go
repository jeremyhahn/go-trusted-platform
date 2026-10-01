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
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ct"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/loadbalancer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
)

const (
	lbBridge = "tp-grouplb"

	// The root namespace attaches through an OVS internal port and acts
	// as both the LB client and the prober's vantage point.
	lbHostIP    = "10.240.0.1"
	lbBackend1  = "10.240.0.11"
	lbBackend2  = "10.240.0.12"
	lbSubnet    = "10.240.0.0/24"
	lbVIPAddr   = "10.240.0.100"
	lbVIPPort   = 8080
	lbBackPort  = 9001
	lbClientNS  = "" // root namespace
	lbBackend1N = "tplb-b1"
	lbBackend2N = "tplb-b2"

	// lbVIPMAC is the locally-administered MAC the client resolves the
	// VIP to (static neighbor entry; no host owns the VIP address). The
	// harness forwarding table also uses it as the gateway's source MAC.
	lbVIPMAC = "0e:1b:00:00:00:aa"

	// The hairpin segment: a client and a backend on one Linux bridge,
	// reaching the OVS bridge through a single port, as hosts on a LAN
	// behind one gateway interface do. The backend answers an on-link
	// client directly, so only source NAT to the VIP brings its reply
	// back through the gateway.
	lbHairpinNet     = "10.241.0.0/24"
	lbHairpinClient  = "10.241.0.2"
	lbHairpinBackend = "10.241.0.12"
	lbHairpinVIP     = "10.241.0.101"
	lbSegmentNS      = "tplb-seg"
	lbHairpinCNS     = "tplb-hc"
	lbHairpinBNS     = "tplb-hb"
)

// lbBackendServer is a TCP server that identifies itself on every line.
type lbBackendServer struct {
	id       string
	listener net.Listener
	wg       sync.WaitGroup

	mu         sync.Mutex
	accepted   int
	lastRemote string
}

// startLBBackend starts an identifying echo server inside the namespace.
func startLBBackend(t *testing.T, ns, addr, id string) *lbBackendServer {
	t.Helper()

	listener, err := nsListen(ns, addr)
	require.NoError(t, err, "listen in %s on %s", ns, addr)

	srv := &lbBackendServer{id: id, listener: listener}
	srv.wg.Add(1)
	go func() {
		defer srv.wg.Done()
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			srv.mu.Lock()
			srv.accepted++
			srv.lastRemote = conn.RemoteAddr().(*net.TCPAddr).IP.String()
			srv.mu.Unlock()
			srv.wg.Add(1)
			go func(c net.Conn) {
				defer srv.wg.Done()
				defer c.Close()
				scanner := bufio.NewScanner(c)
				for scanner.Scan() {
					fmt.Fprintf(c, "%s\n", srv.id)
				}
			}(conn)
		}
	}()

	t.Cleanup(srv.Stop)
	return srv
}

// Stop closes the listener and waits for connection goroutines.
func (s *lbBackendServer) Stop() {
	s.listener.Close()
	s.wg.Wait()
}

// Accepted returns the number of accepted connections.
func (s *lbBackendServer) Accepted() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accepted
}

// LastRemote returns the source address of the last accepted connection.
func (s *lbBackendServer) LastRemote() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastRemote
}

// setupLBHostPort attaches the root namespace to the bridge via an OVS
// internal port carrying lbHostIP and a static neighbor entry for the
// VIP.
func setupLBHostPort(t *testing.T, bridge string) {
	t.Helper()

	hostIf := "tplb-host"
	runCmd(t, "ovs-vsctl", "add-port", bridge, hostIf,
		"--", "set", "Interface", hostIf, "type=internal")
	t.Cleanup(func() {
		runCmdQuiet("ovs-vsctl", "--if-exists", "del-port", bridge, hostIf)
	})
	runCmd(t, "ip", "addr", "add", lbHostIP+"/24", "dev", hostIf)
	runCmd(t, "ip", "link", "set", hostIf, "up")
	// The VIP is virtual: nothing answers ARP for it, so pin a
	// locally-administered MAC. The table 30 harness rules rewrite it to
	// the selected backend's MAC after DNAT.
	runCmd(t, "ip", "neigh", "replace", lbVIPAddr, "lladdr", lbVIPMAC, "dev", hostIf)
}

// segmentHost is a namespace on the hairpin segment.
type segmentHost struct {
	ns  string
	mac string
}

// setupHairpinSegment builds the hairpin segment: a Linux bridge inside its
// own namespace, uplinked to one OVS port, with a client and a backend
// namespace attached to it. It returns the uplink's OpenFlow port.
func setupHairpinSegment(t *testing.T, bridge string) (int, segmentHost, segmentHost) {
	t.Helper()

	uplink, inside := "tplb-sego", "tplb-segu"
	runCmdQuiet("ip", "netns", "del", lbSegmentNS)
	runCmdQuiet("ip", "link", "del", uplink)
	t.Cleanup(func() {
		runCmdQuiet("ovs-vsctl", "--if-exists", "del-port", bridge, uplink)
		runCmdQuiet("ip", "link", "del", uplink)
		runCmdQuiet("ip", "netns", "del", lbSegmentNS)
	})
	runCmd(t, "ip", "netns", "add", lbSegmentNS)
	runCmd(t, "ip", "-n", lbSegmentNS, "link", "add", "sbr", "type", "bridge")
	runCmd(t, "ip", "-n", lbSegmentNS, "link", "set", "sbr", "up")
	runCmd(t, "ip", "link", "add", uplink, "type", "veth", "peer", "name", inside)
	runCmd(t, "ip", "link", "set", inside, "netns", lbSegmentNS)
	runCmd(t, "ip", "-n", lbSegmentNS, "link", "set", inside, "master", "sbr")
	runCmd(t, "ip", "-n", lbSegmentNS, "link", "set", inside, "up")
	runCmd(t, "ovs-vsctl", "add-port", bridge, uplink)
	runCmd(t, "ip", "link", "set", uplink, "up")

	attach := func(ns, cidr, peer string) segmentHost {
		hostIf, segIf := ns+"-i", ns+"-s"
		runCmdQuiet("ip", "netns", "del", ns)
		t.Cleanup(func() { runCmdQuiet("ip", "netns", "del", ns) })
		runCmd(t, "ip", "netns", "add", ns)
		runCmd(t, "ip", "link", "add", hostIf, "type", "veth", "peer", "name", segIf)
		runCmd(t, "ip", "link", "set", hostIf, "netns", ns)
		runCmd(t, "ip", "link", "set", segIf, "netns", lbSegmentNS)
		runCmd(t, "ip", "-n", lbSegmentNS, "link", "set", segIf, "master", "sbr")
		runCmd(t, "ip", "-n", lbSegmentNS, "link", "set", segIf, "up")
		runCmd(t, "ip", "-n", ns, "link", "set", "lo", "up")
		runCmd(t, "ip", "-n", ns, "addr", "add", cidr, "dev", hostIf)
		runCmd(t, "ip", "-n", ns, "link", "set", hostIf, "up")
		// The VIP resolves to the gateway's MAC, as on a LAN where the
		// gateway answers for it.
		runCmd(t, "ip", "-n", ns, "neigh", "replace", lbHairpinVIP, "lladdr", lbVIPMAC, "dev", hostIf)
		if peer != "" {
			runCmd(t, "ip", "-n", ns, "route", "add", peer, "dev", hostIf)
		}
		mac := strings.TrimSpace(runCmd(t, "ip", "netns", "exec", ns, "cat", "/sys/class/net/"+hostIf+"/address"))
		return segmentHost{ns: ns, mac: mac}
	}
	client := attach(lbHairpinCNS, lbHairpinClient+"/24", "")
	// The backend also answers the prober in the root namespace, on-link
	// through the gateway bridge.
	backend := attach(lbHairpinBNS, lbHairpinBackend+"/24", lbSubnet)
	return lookupOFPort(t, uplink), client, backend
}

// installLBHarnessFlows provides the pipeline context the full gateway
// normally supplies around the LB service on a standalone bridge, and
// nothing of the load balancer's own:
//   - table 0 diverts into the table 10 gate;
//   - table 30 plays the forwarding role: a DNATed packet gets the
//     backend's MAC and port, a packet routed back onto the hairpin segment
//     leaves through the port it came in on with the gateway's source MAC,
//     everything else goes NORMAL.
//
// It installs no reply flow. Reverse translation of a backend's reply is
// the load balancer's job (#718); this harness used to supply it, which is
// how a load balancer that never un-NATed replies passed this test.
func installLBHarnessFlows(t *testing.T, client *ovs.Client, bridge string, backends map[string]*nsEndpoint, segmentPort int, hairpinClient, hairpinBackend segmentHost) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	flows := []*ovs.FlowMod{
		{Table: 0, Priority: 1, Actions: "goto_table:10"},
		// Table 20's miss is the gateway pipeline's (#614); the load
		// balancer no longer installs one.
		{Table: 20, Priority: 0, Actions: "goto_table:30"},
		{Table: 30, Priority: 0, Actions: "normal"},
	}
	for ip, endpoint := range backends {
		flows = append(flows, &ovs.FlowMod{
			Table:    30,
			Priority: 10,
			Match:    "dl_type=0x0800,nw_dst=" + ip,
			Actions:  fmt.Sprintf("mod_dl_dst:%s,output:%d", endpoint.MAC, endpoint.OFPort),
		})
	}
	for ip, host := range map[string]segmentHost{lbHairpinBackend: hairpinBackend, lbHairpinClient: hairpinClient} {
		flows = append(flows, &ovs.FlowMod{
			Table:    30,
			Priority: 11,
			Match:    fmt.Sprintf("in_port=%d,dl_type=0x0800,nw_dst=%s", segmentPort, ip),
			Actions:  fmt.Sprintf("mod_dl_src:%s,mod_dl_dst:%s,in_port", lbVIPMAC, host.mac),
		})
	}
	require.NoError(t, client.AddFlows(ctx, bridge, flows), "install LB harness flows")
}

// requireOVSRunning fails the test when Open vSwitch is not usable. This
// suite runs in the devcontainer, where OVS is part of the environment; a
// missing OVS is a broken environment, not a reason to pass silently.
func requireOVSRunning(t *testing.T) {
	t.Helper()
	require.Zero(t, os.Geteuid(), "the load balancer datapath test needs root (run it in the devcontainer)")
	out, err := exec.Command("ovs-vsctl", "list-br").CombinedOutput()
	require.NoError(t, err, "Open vSwitch must be running: %s", out)
}

// dialVIPAndIdentify connects to the VIP from the root namespace and
// returns the backend ID that answered, closing the connection.
func dialVIPAndIdentify(t *testing.T, timeout time.Duration) (string, error) {
	t.Helper()

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", lbVIPAddr, lbVIPPort), timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	fmt.Fprintln(conn, "who")
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return "", err
	}
	id, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(id), nil
}

// TestGroupLoadBalancer drives real TCP traffic through the OVS select
// group + conntrack DNAT datapath: distribution across backends,
// per-connection stickiness, prober-driven group rebuilds on backend
// failure, and fail-closed behavior with zero healthy backends.
func TestGroupLoadBalancer(t *testing.T) {
	requireOVSRunning(t)

	bridge := setupTestBridge(t, lbBridge)
	client := newOVSDBClient(t)

	setupLBHostPort(t, bridge.name)
	b1 := createNSEndpoint(t, bridge.name, lbBackend1N, lbBackend1+"/24", 0)
	b2 := createNSEndpoint(t, bridge.name, lbBackend2N, lbBackend2+"/24", 0)

	segmentPort, hairpinClient, hairpinBackend := setupHairpinSegment(t, bridge.name)
	runCmd(t, "ip", "route", "add", lbHairpinNet, "dev", "tplb-host")

	srv1 := startLBBackend(t, lbBackend1N, fmt.Sprintf("%s:%d", lbBackend1, lbBackPort), "backend-1")
	srv2 := startLBBackend(t, lbBackend2N, fmt.Sprintf("%s:%d", lbBackend2, lbBackPort), "backend-2")
	srvHairpin := startLBBackend(t, lbHairpinBNS, fmt.Sprintf("%s:%d", lbHairpinBackend, lbBackPort), "backend-hairpin")

	controller, err := policy.NewOVSFlowController(client)
	require.NoError(t, err, "create flow controller")

	// Short prober cycle so failure-driven group rebuilds are fast.
	lbService, err := loadbalancer.New(loadbalancer.Deps{
		Controller: controller,
		OVS:        client,
		Groups:     client,
		Config: loadbalancer.Config{
			Bridge:              bridge.name,
			HealthCheckInterval: 300 * time.Millisecond,
			HealthCheckTimeout:  150 * time.Millisecond,
			Rise:                1,
			Fall:                1,
			HairpinPrefixes:     []netip.Prefix{netip.MustParsePrefix(lbHairpinNet)},
		},
		Allocator: ct.NewZoneAllocator(nil),
	})
	require.NoError(t, err, "create load balancer service")

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	require.NoError(t, lbService.Start(ctx), "start load balancer service")
	t.Cleanup(func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer stopCancel()
		if stopErr := lbService.Stop(stopCtx); stopErr != nil {
			t.Logf("load balancer stop: %v", stopErr)
		}
	})

	vip := loadbalancer.VIP{
		Address:  netip.MustParseAddr(lbVIPAddr),
		Port:     lbVIPPort,
		Protocol: "tcp",
		Backends: []loadbalancer.Backend{
			{Address: netip.MustParseAddr(lbBackend1), Port: lbBackPort},
			{Address: netip.MustParseAddr(lbBackend2), Port: lbBackPort},
		},
	}
	require.NoError(t, lbService.AddVIP(ctx, vip), "add VIP")

	target := netip.AddrPortFrom(netip.MustParseAddr(lbVIPAddr), lbVIPPort)
	status, err := lbService.GetVIP("tcp", target)
	require.NoError(t, err, "get VIP status")
	require.NotZero(t, status.CTZone, "VIP conntrack zone")

	hairpinVIP := loadbalancer.VIP{
		Address:  netip.MustParseAddr(lbHairpinVIP),
		Port:     lbVIPPort,
		Protocol: "tcp",
		Backends: []loadbalancer.Backend{{Address: netip.MustParseAddr(lbHairpinBackend), Port: lbBackPort}},
	}
	require.NoError(t, lbService.AddVIP(ctx, hairpinVIP), "add hairpin VIP")

	// On failure, record what the datapath held: the flow tables with
	// their packet counters, the groups and the conntrack entries. A
	// timeout alone says nothing about which stage dropped the packet.
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		for _, args := range [][]string{
			{"ovs-ofctl", "-O", "OpenFlow13", "dump-flows", bridge.name},
			{"ovs-ofctl", "-O", "OpenFlow13", "dump-groups", bridge.name},
			{"ovs-appctl", "dpctl/dump-conntrack"},
			{"ovs-appctl", "dpctl/dump-flows"},
		} {
			out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
			t.Logf("%s (err=%v):\n%s", strings.Join(args, " "), err, out)
		}
	})

	installLBHarnessFlows(t, client, bridge.name, map[string]*nsEndpoint{
		lbBackend1: b1,
		lbBackend2: b2,
	}, segmentPort, hairpinClient, hairpinBackend)

	// Both backends must probe healthy before traffic assertions.
	waitFor(ctx, t, "both backends healthy", 200*time.Millisecond, 20*time.Second, func() bool {
		current, getErr := lbService.GetVIP("tcp", target)
		if getErr != nil {
			return false
		}
		healthy := 0
		for _, backend := range current.Backends {
			if backend.Healthy {
				healthy++
			}
		}
		return healthy == 2
	})

	// #718: the harness supplies no reply flow, so a completed handshake
	// and an answer through the VIP mean the load balancer reversed the
	// backend's reply itself. Before the fix the client's SYN reached the
	// backend and its SYN-ACK came back from 10.240.0.1x:9001, which the
	// client answers with a reset.
	t.Run("RepliesAreReverseTranslated", func(t *testing.T) {
		id, dialErr := dialVIPAndIdentify(t, 5*time.Second)
		require.NoError(t, dialErr, "TCP handshake and exchange through the VIP")
		require.Contains(t, []string{"backend-1", "backend-2"}, id)
	})

	// The reply divert matches a backend's source address:port, so the
	// backend's own traffic from that port passes through it too. It must
	// leave untouched: a client that talks to the backend directly still
	// gets its answers.
	t.Run("BackendStillReachableDirectly", func(t *testing.T) {
		conn, dialErr := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", lbBackend1, lbBackPort), 5*time.Second)
		require.NoError(t, dialErr, "direct connection to a backend")
		defer conn.Close()
		fmt.Fprintln(conn, "who")
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
		id, readErr := bufio.NewReader(conn).ReadString('\n')
		require.NoError(t, readErr)
		require.Equal(t, "backend-1", strings.TrimSpace(id))
	})

	// #718 hairpin: the client and the backend share a segment behind one
	// gateway port. Without source NAT the backend answers the client
	// directly from its own address and the handshake fails; with it the
	// backend sees the VIP and answers through the gateway.
	t.Run("HairpinThroughTheVIP", func(t *testing.T) {
		waitFor(ctx, t, "hairpin backend healthy", 200*time.Millisecond, 20*time.Second, func() bool {
			current, getErr := lbService.GetVIP("tcp", netip.AddrPortFrom(hairpinVIP.Address, hairpinVIP.Port))
			return getErr == nil && len(current.Backends) == 1 && current.Backends[0].Healthy
		})
		for i := 0; i < 3; i++ {
			conn, dialErr := nsDial(lbHairpinCNS, fmt.Sprintf("%s:%d", lbHairpinVIP, lbVIPPort), 5*time.Second)
			require.NoError(t, dialErr, "hairpin TCP handshake %d through the VIP", i)
			fmt.Fprintln(conn, "who")
			require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
			id, readErr := bufio.NewReader(conn).ReadString('\n')
			conn.Close()
			require.NoError(t, readErr, "hairpin exchange %d", i)
			require.Equal(t, "backend-hairpin", strings.TrimSpace(id))
			require.Equal(t, lbHairpinVIP, srvHairpin.LastRemote(),
				"the hairpin backend must see the VIP as the client, so it answers through the gateway")
		}
	})

	t.Run("DistributionAcrossBackends", func(t *testing.T) {
		hits := map[string]int{}
		before := srv1.Accepted() + srv2.Accepted()
		for i := 0; i < 24; i++ {
			id, dialErr := dialVIPAndIdentify(t, 5*time.Second)
			require.NoError(t, dialErr, "VIP connection %d", i)
			hits[id]++
		}
		require.Greater(t, hits["backend-1"], 0, "backend-1 must receive connections: %v", hits)
		require.Greater(t, hits["backend-2"], 0, "backend-2 must receive connections: %v", hits)
		require.Equal(t, 24, srv1.Accepted()+srv2.Accepted()-before, "every connection lands on a real backend")
	})

	t.Run("PerConnectionStickiness", func(t *testing.T) {
		conn, dialErr := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", lbVIPAddr, lbVIPPort), 5*time.Second)
		require.NoError(t, dialErr, "VIP connection")
		defer conn.Close()

		reader := bufio.NewReader(conn)
		var first string
		for i := 0; i < 5; i++ {
			fmt.Fprintln(conn, "who")
			require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
			id, readErr := reader.ReadString('\n')
			require.NoError(t, readErr, "read %d", i)
			id = strings.TrimSpace(id)
			if first == "" {
				first = id
				continue
			}
			require.Equal(t, first, id, "connection must stay on one backend")
		}
	})

	t.Run("ProberRebuildsGroupOnBackendFailure", func(t *testing.T) {
		srv1.Stop()

		waitFor(ctx, t, "backend-1 marked unhealthy", 200*time.Millisecond, 20*time.Second, func() bool {
			current, getErr := lbService.GetVIP("tcp", target)
			if getErr != nil {
				return false
			}
			healthy := 0
			for _, backend := range current.Backends {
				if backend.Healthy {
					healthy++
				}
			}
			return healthy == 1
		})

		for i := 0; i < 8; i++ {
			id, dialErr := dialVIPAndIdentify(t, 5*time.Second)
			require.NoError(t, dialErr, "VIP connection %d after failover", i)
			require.Equal(t, "backend-2", id, "all new connections must land on the survivor")
		}
	})

	t.Run("ZeroBackendsFailClosed", func(t *testing.T) {
		srv2.Stop()

		waitFor(ctx, t, "all backends unhealthy", 200*time.Millisecond, 20*time.Second, func() bool {
			current, getErr := lbService.GetVIP("tcp", target)
			if getErr != nil {
				return false
			}
			for _, backend := range current.Backends {
				if backend.Healthy {
					return false
				}
			}
			return true
		})

		_, dialErr := dialVIPAndIdentify(t, 2*time.Second)
		require.Error(t, dialErr, "new connections must fail with zero healthy backends")
	})
}
