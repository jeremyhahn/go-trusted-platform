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
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/hostfw"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testenv"
)

// The host filter is proven in two network namespaces the test creates
// and destroys (#569): "host" carries the tp_host table and the listeners,
// "peer" is the client on the far end of a veth pair. Nothing in the
// root namespace is touched. The test requires root (NET_ADMIN); it fails
// rather than skips when it lacks it, so an environment that cannot run
// it says so instead of reporting green.
const (
	hostfwHostAddr = "10.99.0.1"
	hostfwPeerAddr = "10.99.0.2"
	hostfwTunHost  = "10.98.0.1"
	hostfwTunPeer  = "10.98.0.2"

	hostfwDeclaredPort   = 18443
	hostfwUndeclaredPort = 19999
	hostfwDialTimeout    = 1500 * time.Millisecond
)

// inNS runs f with the calling OS thread switched into ns and switches
// back afterwards. Sockets and links f creates stay in ns.
func inNS(t *testing.T, ns netns.NsHandle, f func()) {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	orig, err := netns.Get()
	require.NoError(t, err)
	defer orig.Close()
	require.NoError(t, netns.Set(ns))
	defer func() { require.NoError(t, netns.Set(orig)) }()
	f()
}

func newNS(t *testing.T) netns.NsHandle {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	orig, err := netns.Get()
	require.NoError(t, err)
	defer orig.Close()
	ns, err := netns.New()
	require.NoError(t, err)
	require.NoError(t, netns.Set(orig))
	t.Cleanup(func() { ns.Close() })
	return ns
}

func addrUp(t *testing.T, h *netlink.Handle, name, cidr string) {
	t.Helper()
	link, err := h.LinkByName(name)
	require.NoError(t, err)
	addr, err := netlink.ParseAddr(cidr)
	require.NoError(t, err)
	require.NoError(t, h.AddrAdd(link, addr))
	require.NoError(t, h.LinkSetUp(link))
}

func dialWithin(ns netns.NsHandle, t *testing.T, target string) error {
	t.Helper()
	var err error
	inNS(t, ns, func() {
		var c net.Conn
		c, err = net.DialTimeout("tcp", target, hostfwDialTimeout)
		if err == nil {
			c.Close()
		}
	})
	return err
}

// sendWithin sends one UDP datagram to target from inside ns.
func sendWithin(ns netns.NsHandle, t *testing.T, target string) error {
	t.Helper()
	var err error
	inNS(t, ns, func() {
		var c net.Conn
		c, err = net.Dial("udp", target)
		if err != nil {
			return
		}
		_, err = c.Write([]byte{0})
		if cerr := c.Close(); err == nil {
			err = cerr
		}
	})
	return err
}

// listenWithin opens a TCP listener inside ns that accepts and closes
// every connection, and closes it when the test ends.
func listenWithin(ns netns.NsHandle, t *testing.T, addr string) {
	t.Helper()
	var ln net.Listener
	inNS(t, ns, func() {
		var err error
		ln, err = net.Listen("tcp", addr)
		require.NoError(t, err)
	})
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
}

func TestHostFW_NetNS_OnlyDeclaredListenersAnswer(t *testing.T) {
	require.Equal(t, 0, os.Geteuid(), "the host filter test needs root (NET_ADMIN); run it in the devcontainer")

	hostNS := newNS(t)
	peerNS := newNS(t)
	hh, err := netlink.NewHandleAt(hostNS)
	require.NoError(t, err)
	defer hh.Close()
	ph, err := netlink.NewHandleAt(peerNS)
	require.NoError(t, err)
	defer ph.Close()

	// veth pair: hfw0 stays in host, hfw1 moves to peer.
	require.NoError(t, hh.LinkAdd(testenv.NewVeth("hfw0", "hfw1")))
	peerLink, err := hh.LinkByName("hfw1")
	require.NoError(t, err)
	require.NoError(t, hh.LinkSetNsFd(peerLink, int(peerNS)))
	for _, h := range []*netlink.Handle{hh, ph} {
		lo, err := h.LinkByName("lo")
		require.NoError(t, err)
		require.NoError(t, h.LinkSetUp(lo))
	}
	addrUp(t, hh, "hfw0", hostfwHostAddr+"/24")
	addrUp(t, ph, "hfw1", hostfwPeerAddr+"/24")

	// GRE tunnels in both directions, so a declared tunnel interface can
	// be exercised end to end: BGP on the tunnel is allowed only once the
	// outer GRE from the peer's address is allowed.
	require.NoError(t, hh.LinkAdd(&netlink.Gretun{LinkAttrs: netlink.LinkAttrs{Name: "hgre0"},
		Local: net.ParseIP(hostfwHostAddr), Remote: net.ParseIP(hostfwPeerAddr)}))
	require.NoError(t, ph.LinkAdd(&netlink.Gretun{LinkAttrs: netlink.LinkAttrs{Name: "pgre0"},
		Local: net.ParseIP(hostfwPeerAddr), Remote: net.ParseIP(hostfwHostAddr)}))
	addrUp(t, hh, "hgre0", hostfwTunHost+"/30")
	addrUp(t, ph, "pgre0", hostfwTunPeer+"/30")

	listenWithin(hostNS, t, net.JoinHostPort(hostfwHostAddr, strconv.Itoa(hostfwDeclaredPort)))
	listenWithin(hostNS, t, net.JoinHostPort(hostfwHostAddr, strconv.Itoa(hostfwUndeclaredPort)))
	listenWithin(hostNS, t, net.JoinHostPort(hostfwTunHost, strconv.Itoa(int(hostfw.PortBGP))))

	// Before the filter: everything answers.
	require.NoError(t, dialWithin(peerNS, t, net.JoinHostPort(hostfwHostAddr, strconv.Itoa(hostfwUndeclaredPort))),
		"positive control: without the filter the undeclared port answers")

	applier, err := hostfw.NewNetlinkApplier(nftables.WithNetNSFd(int(hostNS)))
	require.NoError(t, err)
	inventory := hostfw.StaticInventory{{Interface: "hfw0", Protocol: hostfw.ProtocolTCP, Port: hostfwDeclaredPort, Comment: "declared"}}
	cfg := hostfw.Config{
		Tunnels: []string{"hgre0"},
		// The peer allowance names the WRONG address first: GRE from the
		// real peer must be dropped until the allowance is corrected.
		Peers: []hostfw.PeerAllowance{{Interface: "hfw0", Protocol: hostfw.PeerProtocolGRE, Addresses: []netip.Addr{netip.MustParseAddr("10.99.0.9")}}},
	}
	svc, err := hostfw.New(hostfw.Deps{Applier: applier, Inventory: inventory, Config: cfg})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	require.NoError(t, svc.Start(ctx))
	t.Cleanup(func() { _ = svc.Stop(context.Background()) })

	t.Run("declared port answers", func(t *testing.T) {
		require.NoError(t, dialWithin(peerNS, t, net.JoinHostPort(hostfwHostAddr, strconv.Itoa(hostfwDeclaredPort))))
	})
	t.Run("undeclared port is dropped", func(t *testing.T) {
		err := dialWithin(peerNS, t, net.JoinHostPort(hostfwHostAddr, strconv.Itoa(hostfwUndeclaredPort)))
		require.Error(t, err)
		var nerr net.Error
		require.True(t, errors.As(err, &nerr) && nerr.Timeout(), "a drop looks like a timeout, not a refusal: %v", err)
	})
	t.Run("gre from an undeclared source is dropped", func(t *testing.T) {
		// The host sends GRE to the peer first, so conntrack holds an entry
		// that makes the peer's GRE a reply. Kernels that send IPv6 MLD or
		// router solicitations over hgre0 create the same entry on their own,
		// and the dial then passed on conntrack alone (#730). Doing it here
		// proves on every kernel that only the peer allowance admits GRE.
		require.NoError(t, sendWithin(hostNS, t, net.JoinHostPort(hostfwTunPeer, "9")))
		err := dialWithin(peerNS, t, net.JoinHostPort(hostfwTunHost, strconv.Itoa(int(hostfw.PortBGP))))
		require.Error(t, err, "the outer GRE from 10.99.0.2 is not in the allowance yet")
	})
	t.Run("correcting the peer allowance admits bgp over the tunnel", func(t *testing.T) {
		cfg.Peers[0].Addresses = []netip.Addr{netip.MustParseAddr(hostfwPeerAddr)}
		svc2, err := hostfw.New(hostfw.Deps{Applier: applier, Inventory: inventory, Config: cfg})
		require.NoError(t, err)
		require.NoError(t, svc.Stop(ctx))
		require.NoError(t, svc2.Start(ctx))
		t.Cleanup(func() { _ = svc2.Stop(context.Background()) })
		require.NoError(t, dialWithin(peerNS, t, net.JoinHostPort(hostfwTunHost, strconv.Itoa(int(hostfw.PortBGP)))))
		// And the undeclared port stays closed.
		require.Error(t, dialWithin(peerNS, t, net.JoinHostPort(hostfwHostAddr, strconv.Itoa(hostfwUndeclaredPort))))
	})
}
