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
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netns"
)

// nsEndpoint is one network-namespace endpoint attached to an OVS test
// bridge through a veth pair. The host-side veth is added to the bridge
// (as a trunk, so VLAN-tagged sub-interface traffic passes through the
// OpenFlow pipeline tagged); the peer lives inside the namespace.
type nsEndpoint struct {
	// NS is the namespace name.
	NS string

	// HostIf is the bridge-side veth name.
	HostIf string

	// PeerIf is the namespace-side veth name.
	PeerIf string

	// MAC is the MAC address of the in-namespace data interface (the
	// VLAN sub-interface when VLAN != 0, the veth peer otherwise).
	MAC string

	// OFPort is the OpenFlow port number of the host-side veth.
	OFPort int
	// DataIf is the interface that carries addresses: the VLAN
	// sub-interface when a VLAN was requested, else the veth peer.
	DataIf string
}

// runCmd executes a command and fails the test with full output on error.
func runCmd(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

// runCmdQuiet executes a command ignoring failures (cleanup paths).
func runCmdQuiet(name string, args ...string) {
	cmd := exec.Command(name, args...)
	if err := cmd.Run(); err != nil {
		// Best-effort cleanup: the resource may already be gone.
		_ = err
	}
}

// createNSEndpoint creates a namespace, a veth pair, attaches the host
// side to the bridge, and configures the namespace side with the given
// CIDR. When vlan != 0 the address lives on a VLAN sub-interface so all
// traffic leaves the namespace 802.1Q-tagged. extraRoutes are installed
// as on-link routes over the data interface. Every resource is removed
// via t.Cleanup.
func createNSEndpoint(t *testing.T, bridge, ns, cidr string, vlan int, extraRoutes ...string) *nsEndpoint {
	t.Helper()

	hostIf := "veh-" + ns
	peerIf := "vep-" + ns

	// Cleanup from previous failed runs, then register teardown.
	runCmdQuiet("ip", "netns", "del", ns)
	runCmdQuiet("ip", "link", "del", hostIf)
	t.Cleanup(func() {
		runCmdQuiet("ovs-vsctl", "--if-exists", "del-port", bridge, hostIf)
		runCmdQuiet("ip", "link", "del", hostIf)
		runCmdQuiet("ip", "netns", "del", ns)
	})

	runCmd(t, "ip", "netns", "add", ns)
	runCmd(t, "ip", "link", "add", hostIf, "type", "veth", "peer", "name", peerIf)
	runCmd(t, "ip", "link", "set", peerIf, "netns", ns)
	runCmd(t, "ovs-vsctl", "add-port", bridge, hostIf)
	runCmd(t, "ip", "link", "set", hostIf, "up")

	runCmd(t, "ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up")
	runCmd(t, "ip", "netns", "exec", ns, "ip", "link", "set", peerIf, "up")

	dataIf := peerIf
	if vlan != 0 {
		dataIf = fmt.Sprintf("%s.%d", peerIf, vlan)
		runCmd(t, "ip", "netns", "exec", ns, "ip", "link", "add", "link", peerIf,
			"name", dataIf, "type", "vlan", "id", fmt.Sprintf("%d", vlan))
		runCmd(t, "ip", "netns", "exec", ns, "ip", "link", "set", dataIf, "up")
	}
	runCmd(t, "ip", "netns", "exec", ns, "ip", "addr", "add", cidr, "dev", dataIf)
	for _, route := range extraRoutes {
		runCmd(t, "ip", "netns", "exec", ns, "ip", "route", "add", route, "dev", dataIf)
	}

	mac := strings.TrimSpace(runCmd(t, "ip", "netns", "exec", ns, "cat",
		"/sys/class/net/"+dataIf+"/address"))
	ofPort := lookupOFPort(t, hostIf)

	return &nsEndpoint{NS: ns, HostIf: hostIf, PeerIf: peerIf, DataIf: dataIf, MAC: mac, OFPort: ofPort}
}

// addNSAddress adds a second address (typically the IPv6 leg of a dual-stack
// endpoint) to the endpoint's data interface, with on-link routes for the
// extra prefixes so cross-subnet traffic stays L2-adjacent (#554).
func addNSAddress(t *testing.T, ep *nsEndpoint, cidr string, extraRoutes ...string) {
	t.Helper()
	family := "-4"
	if strings.Contains(cidr, ":") {
		family = "-6"
	}
	runCmd(t, "ip", "netns", "exec", ep.NS, "ip", family, "addr", "add", cidr, "dev", ep.DataIf, "nodad")
	for _, route := range extraRoutes {
		runCmd(t, "ip", "netns", "exec", ep.NS, "ip", family, "route", "add", route, "dev", ep.DataIf)
	}
}

// lookupOFPort resolves an interface's OpenFlow port number via OVSDB.
func lookupOFPort(t *testing.T, ifName string) int {
	t.Helper()
	out := strings.TrimSpace(runCmd(t, "ovs-vsctl", "get", "Interface", ifName, "ofport"))
	var port int
	if _, err := fmt.Sscanf(out, "%d", &port); err != nil {
		t.Fatalf("parse ofport %q for %s: %v", out, ifName, err)
	}
	return port
}

// inNetns runs fn with the calling goroutine switched into the named
// namespace. Sockets created inside fn stay bound to that namespace after
// the switch back.
func inNetns(ns string, fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	orig, err := netns.Get()
	if err != nil {
		return fmt.Errorf("get current netns: %w", err)
	}
	defer orig.Close()

	target, err := netns.GetFromName(ns)
	if err != nil {
		return fmt.Errorf("get netns %s: %w", ns, err)
	}
	defer target.Close()

	if err := netns.Set(target); err != nil {
		return fmt.Errorf("enter netns %s: %w", ns, err)
	}
	defer func() {
		// The thread is locked; restoring must succeed or the thread is
		// poisoned — UnlockOSThread with a foreign netns would leak it,
		// so a failed restore terminates the thread instead (the runtime
		// discards locked threads whose goroutine exits).
		if restoreErr := netns.Set(orig); restoreErr != nil {
			runtime.Goexit()
		}
	}()

	return fn()
}

// nsListen creates a TCP listener inside the namespace.
func nsListen(ns, addr string) (net.Listener, error) {
	var listener net.Listener
	err := inNetns(ns, func() error {
		var listenErr error
		listener, listenErr = net.Listen("tcp", addr)
		return listenErr
	})
	return listener, err
}

// nsDial dials a TCP address from inside the namespace with a bounded
// timeout.
func nsDial(ns, addr string, timeout time.Duration) (net.Conn, error) {
	var conn net.Conn
	err := inNetns(ns, func() error {
		var dialErr error
		conn, dialErr = net.DialTimeout("tcp", addr, timeout)
		return dialErr
	})
	return conn, err
}

// waitFor polls condition with a ticker until it reports true or the
// deadline passes (channel-based waiting; no bare sleeps).
func waitFor(ctx context.Context, t *testing.T, what string, interval, timeout time.Duration, condition func() bool) {
	t.Helper()

	deadline, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		if condition() {
			return
		}
		select {
		case <-deadline.Done():
			t.Fatalf("timed out waiting for %s", what)
		case <-ticker.C:
		}
	}
}

// dumpBridgeOnFailure logs the bridge's flow table, with packet counts,
// when the test fails, so a red run shows where the frames stopped.
// Register it after the cleanups that tear the flows down: cleanups run
// last-in first-out, so it runs while the flows are still there.
func dumpBridgeOnFailure(t *testing.T, bridge string) {
	t.Helper()
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		out, err := exec.Command("ovs-ofctl", "-O", "OpenFlow13", "dump-flows", bridge).CombinedOutput()
		t.Logf("flows on %s (err=%v):\n%s", bridge, err, out)
		groups, err := exec.Command("ovs-ofctl", "-O", "OpenFlow13", "dump-groups", bridge).CombinedOutput()
		t.Logf("groups on %s (err=%v):\n%s", bridge, err, groups)
	})
}
