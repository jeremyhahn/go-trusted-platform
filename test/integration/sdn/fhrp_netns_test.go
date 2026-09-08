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
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/fhrp"
)

const (
	fhrpVIP   = "10.77.0.1/24"
	fhrpAAddr = "10.77.0.2"
	fhrpBAddr = "10.77.0.3"
)

// nsProgrammer runs the real netlink programmer with the calling thread in
// the speaker's namespace, because the announcement sockets it opens are
// namespace-bound.
type nsProgrammer struct {
	ns    netns.NsHandle
	inner fhrp.Programmer
}

func (p *nsProgrammer) within(f func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	orig, err := netns.Get()
	if err != nil {
		return err
	}
	defer func() { _ = netns.Set(orig) }()
	if err := netns.Set(p.ns); err != nil {
		return err
	}
	return f()
}

func (p *nsProgrammer) AddAddress(iface string, prefix netip.Prefix, hw net.HardwareAddr) error {
	return p.within(func() error { return p.inner.AddAddress(iface, prefix, hw) })
}

func (p *nsProgrammer) DeleteAddress(iface string, prefix netip.Prefix, hw net.HardwareAddr) error {
	return p.within(func() error { return p.inner.DeleteAddress(iface, prefix, hw) })
}

func (p *nsProgrammer) Announce(iface string, addr netip.Addr, hw net.HardwareAddr) error {
	return p.within(func() error { return p.inner.Announce(iface, addr, hw) })
}

// nsTransport opens the raw VRRP socket inside the speaker's namespace.
type nsTransport struct {
	ns    netns.NsHandle
	inner fhrp.Transport
}

func (t *nsTransport) Open(iface string, family fhrp.Family, source netip.Addr) (fhrp.Conn, error) {
	var conn fhrp.Conn
	err := (&nsProgrammer{ns: t.ns}).within(func() error {
		c, err := t.inner.Open(iface, family, source)
		conn = c
		return err
	})
	return conn, err
}

type fhrpEvents struct{ ch chan fhrp.Event }

func (e *fhrpEvents) GroupEvent(ev fhrp.Event) { e.ch <- ev }

func (e *fhrpEvents) awaitState(t *testing.T, prio uint8, state fhrp.State) {
	t.Helper()
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case ev := <-e.ch:
			if ev.Kind == fhrp.EventTransition && ev.Status.Priority == prio && ev.Status.State == state {
				return
			}
		case <-deadline.C:
			t.Fatalf("speaker with priority %d never reached %s", prio, state)
		}
	}
}

func holdsVIP(t *testing.T, h *netlink.Handle, iface string) bool {
	t.Helper()
	link, err := h.LinkByName(iface)
	require.NoError(t, err)
	addrs, err := h.AddrList(link, netlink.FAMILY_V4)
	require.NoError(t, err)
	want, _ := netlink.ParseAddr(fhrpVIP)
	for _, a := range addrs {
		if a.IP.Equal(want.IP) {
			return true
		}
	}
	return false
}

// TestFHRP_NetNS_TwoSpeakersElectAndFailOver runs two real VRRPv3 speakers
// in two namespaces joined by a veth pair: the higher priority wins the
// election and holds the virtual address; when it stops, the backup takes
// the address over after its skew time.
func TestFHRP_NetNS_TwoSpeakersElectAndFailOver(t *testing.T) {
	require.Equal(t, 0, os.Geteuid(), "the FHRP test needs root (NET_ADMIN, NET_RAW); run it in the devcontainer")

	nsA, nsB := newNS(t), newNS(t)
	ha, err := netlink.NewHandleAt(nsA)
	require.NoError(t, err)
	defer ha.Close()
	hb, err := netlink.NewHandleAt(nsB)
	require.NoError(t, err)
	defer hb.Close()

	require.NoError(t, ha.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "vr0"}, PeerName: "vr1"}))
	peer, err := ha.LinkByName("vr1")
	require.NoError(t, err)
	require.NoError(t, ha.LinkSetNsFd(peer, int(nsB)))
	for _, h := range []*netlink.Handle{ha, hb} {
		lo, err := h.LinkByName("lo")
		require.NoError(t, err)
		require.NoError(t, h.LinkSetUp(lo))
	}
	addrUp(t, ha, "vr0", fhrpAAddr+"/24")
	addrUp(t, hb, "vr1", fhrpBAddr+"/24")

	events := &fhrpEvents{ch: make(chan fhrp.Event, 256)}
	group := func(iface, source string, prio uint8) fhrp.Config {
		return fhrp.Config{Enabled: true, Groups: []fhrp.GroupConfig{{
			VRID: 7, Interface: iface, Priority: prio, AdvertIntervalCentiseconds: 20,
			Addresses: []string{fhrpVIP}, Source: source,
		}}}
	}
	newSpeaker := func(ns netns.NsHandle, h *netlink.Handle, cfg fhrp.Config) *fhrp.Speaker {
		s, err := fhrp.New(cfg, fhrp.Deps{
			Transport:  &nsTransport{ns: ns, inner: fhrp.NewRawTransport()},
			Programmer: &nsProgrammer{ns: ns, inner: fhrp.NewNetlinkProgrammer(fhrp.WithNetlinkHandle(h))},
			Observer:   events,
		})
		require.NoError(t, err)
		return s
	}
	a := newSpeaker(nsA, ha, group("vr0", fhrpAAddr, 200))
	b := newSpeaker(nsB, hb, group("vr1", fhrpBAddr, 100))

	ctx := context.Background()
	require.NoError(t, a.Start(ctx))
	require.NoError(t, b.Start(ctx))
	defer func() { _ = b.Stop(ctx) }()

	// Election: A (200) masters within 3 × 0.2 s + skew; B stays backup.
	events.awaitState(t, 200, fhrp.StateMaster)
	require.True(t, holdsVIP(t, ha, "vr0"), "the master holds the virtual address")
	require.False(t, holdsVIP(t, hb, "vr1"), "the backup does not")
	stB, err := b.GroupState("vr1", 7)
	require.NoError(t, err)
	require.Equal(t, fhrp.StateBackup, stB)

	// Failover: A leaves (priority-0 advertisement); B takes over.
	require.NoError(t, a.Stop(ctx))
	require.False(t, holdsVIP(t, ha, "vr0"), "a stopped master releases the address")
	events.awaitState(t, 100, fhrp.StateMaster)
	require.True(t, holdsVIP(t, hb, "vr1"), "the backup took the address over")
}
