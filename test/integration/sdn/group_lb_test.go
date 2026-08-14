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
	// VIP to (static neighbor entry; no host owns the VIP address).
	lbVIPMAC = "0e:1b:00:00:00:aa"
)

// lbBackendServer is a TCP server that identifies itself on every line.
type lbBackendServer struct {
	id       string
	listener net.Listener
	wg       sync.WaitGroup

	mu       sync.Mutex
	accepted int
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

// installLBHarnessFlows provides the pipeline context the full gateway
// normally supplies around the LB service on a standalone bridge:
//   - table 0 diverts into the table 10 gate
//   - backend-sourced traffic passes ct(nat) in the VIP zone through a
//     harness table (27, above the LB dispatch table 26 and below table 30
//     so its goto_table continuation is legal) so committed DNAT state is
//     reversed on replies without entering the LB's fail-closed dispatch
//     table
//   - table 30 statically plays the MAC-learning/forwarding role: DNATed
//     packets get the backend MAC and port, everything else goes NORMAL
func installLBHarnessFlows(t *testing.T, client *ovs.Client, bridge string, ctZone uint16, backends map[string]*nsEndpoint) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	flows := []*ovs.FlowMod{
		{Table: 0, Priority: 1, Actions: "goto_table:10"},
		{Table: 27, Priority: 0, Actions: "goto_table:30"},
		{Table: 30, Priority: 0, Actions: "normal"},
	}
	for ip, endpoint := range backends {
		flows = append(flows,
			&ovs.FlowMod{
				Table:    20,
				Priority: 240,
				Match:    "dl_type=0x0800,nw_src=" + ip,
				Actions:  fmt.Sprintf("ct(table=27,zone=%d,nat)", ctZone),
			},
			&ovs.FlowMod{
				Table:    30,
				Priority: 10,
				Match:    "dl_type=0x0800,nw_dst=" + ip,
				Actions:  fmt.Sprintf("mod_dl_dst:%s,output:%d", endpoint.MAC, endpoint.OFPort),
			},
		)
	}
	require.NoError(t, client.AddFlows(ctx, bridge, flows), "install LB harness flows")
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
	requireOVSForTest(t)
	SkipIfSDNUnavailable(t)

	bridge := setupTestBridge(t, lbBridge)
	client := newOVSDBClient(t)

	setupLBHostPort(t, bridge.name)
	b1 := createNSEndpoint(t, bridge.name, lbBackend1N, lbBackend1+"/24", 0)
	b2 := createNSEndpoint(t, bridge.name, lbBackend2N, lbBackend2+"/24", 0)

	srv1 := startLBBackend(t, lbBackend1N, fmt.Sprintf("%s:%d", lbBackend1, lbBackPort), "backend-1")
	srv2 := startLBBackend(t, lbBackend2N, fmt.Sprintf("%s:%d", lbBackend2, lbBackPort), "backend-2")

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

	installLBHarnessFlows(t, client, bridge.name, status.CTZone, map[string]*nsEndpoint{
		lbBackend1: b1,
		lbBackend2: b2,
	})

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

	t.Run("DistributionAcrossBackends", func(t *testing.T) {
		hits := map[string]int{}
		for i := 0; i < 24; i++ {
			id, dialErr := dialVIPAndIdentify(t, 5*time.Second)
			require.NoError(t, dialErr, "VIP connection %d", i)
			hits[id]++
		}
		require.Greater(t, hits["backend-1"], 0, "backend-1 must receive connections: %v", hits)
		require.Greater(t, hits["backend-2"], 0, "backend-2 must receive connections: %v", hits)
		require.Equal(t, srv1.Accepted()+srv2.Accepted(), 24, "every connection lands on a real backend")
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
