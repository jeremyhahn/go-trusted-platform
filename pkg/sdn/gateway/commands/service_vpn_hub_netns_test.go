//go:build integration && !fips

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

package commands

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

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testenv"
)

// The hub's forward and input enforcement is proven on packets in network
// namespaces the test creates and destroys: "peer" is a VPN client behind a
// veth whose gateway end is named vpn-hub0 (the filter matches the ingress
// name, so a veth stands in for the WireGuard device); "gw" forwards and
// carries the tp_vpn_hub table the production programmer writes; "mgmt",
// "cp" and "storage" sit on the zone subnets of hubForwardNetworks. Nothing
// in the root namespace is touched. The test needs root (NET_ADMIN) and
// fails rather than skips without it.
const (
	hubNSHubAddr   = "10.99.0.1"
	hubNSPeerAddr  = "10.99.0.7"
	hubNSStrayAddr = "10.99.0.9"

	hubNSMgmtGW    = "10.4.10.1"
	hubNSMgmtAddr  = "10.4.10.2"
	hubNSCPGW      = "10.4.20.1"
	hubNSCPAddr    = "10.4.20.2"
	hubNSStoreGW   = "10.4.30.1"
	hubNSStoreAddr = "10.4.30.2"

	hubNSMgmtPort    = 18080
	hubNSCPAcmePort  = 8443
	hubNSCPOtherPort = 19999
	hubNSStorePort   = 18081
	hubNSLocalPort   = 18082

	hubNSDialTimeout = 1500 * time.Millisecond
)

// hubNSIn runs f with the calling OS thread switched into ns and switches
// back afterwards. Sockets f creates stay in ns.
func hubNSIn(t *testing.T, ns netns.NsHandle, f func()) {
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

func hubNSNew(t *testing.T) netns.NsHandle {
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

func hubNSHandle(t *testing.T, ns netns.NsHandle) *netlink.Handle {
	t.Helper()
	h, err := netlink.NewHandleAt(ns)
	require.NoError(t, err)
	t.Cleanup(h.Close)
	lo, err := h.LinkByName("lo")
	require.NoError(t, err)
	require.NoError(t, h.LinkSetUp(lo))
	return h
}

func hubNSAddrUp(t *testing.T, h *netlink.Handle, name, cidr string) {
	t.Helper()
	link, err := h.LinkByName(name)
	require.NoError(t, err)
	addr, err := netlink.ParseAddr(cidr)
	require.NoError(t, err)
	require.NoError(t, h.AddrAdd(link, addr))
	require.NoError(t, h.LinkSetUp(link))
}

// hubNSLink joins gw and far with a veth: gwName stays in gw with gwCIDR,
// farName moves to far with farCIDR and a default route via gwAddr.
func hubNSLink(t *testing.T, gh, fh *netlink.Handle, far netns.NsHandle, gwName, farName, gwCIDR, farCIDR, gwAddr string) {
	t.Helper()
	require.NoError(t, gh.LinkAdd(testenv.NewVeth(gwName, farName)))
	farLink, err := gh.LinkByName(farName)
	require.NoError(t, err)
	require.NoError(t, gh.LinkSetNsFd(farLink, int(far)))
	hubNSAddrUp(t, gh, gwName, gwCIDR)
	hubNSAddrUp(t, fh, farName, farCIDR)
	require.NoError(t, fh.RouteAdd(&netlink.Route{Gw: net.ParseIP(gwAddr)}))
}

// hubNSDial dials target over TCP from inside ns, from the local address
// from when it is not empty.
func hubNSDial(ns netns.NsHandle, t *testing.T, from, target string) error {
	t.Helper()
	var err error
	hubNSIn(t, ns, func() {
		d := net.Dialer{Timeout: hubNSDialTimeout}
		if from != "" {
			d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(from)}
		}
		var c net.Conn
		c, err = d.Dial("tcp", target)
		if err == nil {
			c.Close()
		}
	})
	return err
}

// hubNSListen opens a TCP listener inside ns that accepts and closes every
// connection, and closes it when the test ends.
func hubNSListen(ns netns.NsHandle, t *testing.T, addr string) {
	t.Helper()
	var ln net.Listener
	hubNSIn(t, ns, func() {
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

func hubNSTarget(addr string, port int) string {
	return net.JoinHostPort(addr, strconv.Itoa(port))
}

func hubNSRequireDrop(t *testing.T, err error, msg string) {
	t.Helper()
	require.Error(t, err, msg)
	var nerr net.Error
	require.True(t, errors.As(err, &nerr) && nerr.Timeout(), "%s: a drop looks like a timeout, not a refusal: %v", msg, err)
}

// hubNSZones opens management to the hub and the control plane only for
// the acme service; storage is declared but not opened.
func hubNSZones() []zone.ZoneConfig {
	return []zone.ZoneConfig{
		{Name: vpnHubZone, AllowTo: []zone.ZonePath{
			{Zone: zone.ZoneManagement},
			{Zone: zone.ZoneControlPlane, Services: []string{"acme"}},
		}},
		{Name: zone.ZoneManagement},
		{Name: zone.ZoneControlPlane},
		{Name: zone.ZoneStorage},
	}
}

func TestVPNHubNetNS_ProductionFilterEnforcesLeasesOnPackets(t *testing.T) {
	require.Equal(t, 0, os.Geteuid(), "the vpn hub filter test needs root (NET_ADMIN); run it in the devcontainer")

	gwNS := hubNSNew(t)
	peerNS := hubNSNew(t)
	mgmtNS := hubNSNew(t)
	cpNS := hubNSNew(t)
	storeNS := hubNSNew(t)
	gh := hubNSHandle(t, gwNS)
	ph := hubNSHandle(t, peerNS)
	mh := hubNSHandle(t, mgmtNS)
	ch := hubNSHandle(t, cpNS)
	sh := hubNSHandle(t, storeNS)

	hubNSLink(t, gh, ph, peerNS, vpnHubInterface, "hubp0", hubNSHubAddr+"/24", hubNSPeerAddr+"/24", hubNSHubAddr)
	hubNSAddrUp(t, ph, "hubp0", hubNSStrayAddr+"/24")
	hubNSLink(t, gh, mh, mgmtNS, "hubm0", "hubm1", hubNSMgmtGW+"/24", hubNSMgmtAddr+"/24", hubNSMgmtGW)
	hubNSLink(t, gh, ch, cpNS, "hubc0", "hubc1", hubNSCPGW+"/24", hubNSCPAddr+"/24", hubNSCPGW)
	hubNSLink(t, gh, sh, storeNS, "hubs0", "hubs1", hubNSStoreGW+"/24", hubNSStoreAddr+"/24", hubNSStoreGW)
	hubNSIn(t, gwNS, func() {
		require.NoError(t, os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o644))
	})

	mgmt := hubNSTarget(hubNSMgmtAddr, hubNSMgmtPort)
	cpAcme := hubNSTarget(hubNSCPAddr, hubNSCPAcmePort)
	cpOther := hubNSTarget(hubNSCPAddr, hubNSCPOtherPort)
	storage := hubNSTarget(hubNSStoreAddr, hubNSStorePort)
	local := hubNSTarget(hubNSMgmtGW, hubNSLocalPort)
	hubNSListen(mgmtNS, t, mgmt)
	hubNSListen(cpNS, t, cpAcme)
	hubNSListen(cpNS, t, cpOther)
	hubNSListen(storeNS, t, storage)
	hubNSListen(gwNS, t, local)

	// Before the filter: everything answers, from either source.
	require.NoError(t, hubNSDial(peerNS, t, "", storage), "positive control: without the filter storage answers")
	require.NoError(t, hubNSDial(peerNS, t, "", cpOther), "positive control: without the filter every control-plane port answers")
	require.NoError(t, hubNSDial(peerNS, t, hubNSStrayAddr, local), "positive control: without the filter the gateway answers any source")

	conn, err := nftables.New(nftables.WithNetNSFd(int(gwNS)))
	require.NoError(t, err)
	withHubNFTConn(t, conn)
	zones, err := installVPNHubZones(hubNSZones(), hubForwardNetworks(), discardLogger())
	require.NoError(t, err)
	plane := hubNetworkPlane{
		ManagedDataPlane: &fakeVPNPlane{},
		network:          netip.MustParsePrefix("10.99.0.0/24"),
		hub:              netip.MustParseAddr(hubNSHubAddr),
		zones:            zones,
	}
	t.Cleanup(func() {
		require.NoError(t, plane.Stop(context.Background()))
		tables, err := conn.ListTables()
		require.NoError(t, err)
		for _, tbl := range tables {
			require.NotEqual(t, vpnHubTableName, tbl.Name, "stopping the hub deletes its table")
		}
	})
	host, err := vpn.NewPlaneHost(plane)
	require.NoError(t, err)
	dp, err := vpn.NewDatapathPlane(vpn.DataPlaneMASQUE, wirePeers{host: host})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	t.Run("no lease reaches nothing", func(t *testing.T) {
		hubNSRequireDrop(t, hubNSDial(peerNS, t, "", mgmt), "management before any lease")
		hubNSRequireDrop(t, hubNSDial(peerNS, t, "", cpAcme), "control-plane acme before any lease")
		hubNSRequireDrop(t, hubNSDial(peerNS, t, "", local), "the gateway before any lease")
	})

	lease := hubLease("a", hubNSPeerAddr+"/32")
	lease.Zones = []string{string(zone.ZoneManagement), string(zone.ZoneControlPlane)}
	require.NoError(t, dp.InstallPeer(ctx, lease))

	t.Run("allowed zones and ports answer", func(t *testing.T) {
		require.NoError(t, hubNSDial(peerNS, t, "", mgmt), "the lease opens management")
		require.NoError(t, hubNSDial(peerNS, t, "", cpAcme), "the lease opens the control plane's acme port")
	})
	t.Run("denied zone is dropped", func(t *testing.T) {
		hubNSRequireDrop(t, hubNSDial(peerNS, t, "", storage), "the matrix does not open storage to the hub")
	})
	t.Run("denied port is dropped", func(t *testing.T) {
		hubNSRequireDrop(t, hubNSDial(peerNS, t, "", cpOther), "the control plane opens only the acme ports")
	})
	t.Run("local delivery passes the same rules", func(t *testing.T) {
		require.NoError(t, hubNSDial(peerNS, t, "", local), "the lease reaches the gateway's management address")
		hubNSRequireDrop(t, hubNSDial(peerNS, t, hubNSStrayAddr, local), "a source without a lease is dropped by the input chain")
		hubNSRequireDrop(t, hubNSDial(peerNS, t, hubNSStrayAddr, mgmt), "a source without a lease is dropped by the forward chain")
	})
	t.Run("expiry withdraws the lease", func(t *testing.T) {
		require.NoError(t, host.ExpirePeers(ctx, lease.ExpiresAt))
		hubNSRequireDrop(t, hubNSDial(peerNS, t, "", mgmt), "management after the lease expired")
		hubNSRequireDrop(t, hubNSDial(peerNS, t, "", cpAcme), "control-plane acme after the lease expired")
		hubNSRequireDrop(t, hubNSDial(peerNS, t, "", local), "the gateway after the lease expired")
	})
	t.Run("address reuse carries only the new lease", func(t *testing.T) {
		reuse := hubLease("b", hubNSPeerAddr+"/32")
		reuse.Zones = []string{string(zone.ZoneControlPlane)}
		require.NoError(t, dp.InstallPeer(ctx, reuse))
		require.NoError(t, hubNSDial(peerNS, t, "", cpAcme), "the new lease opens the control plane's acme port")
		hubNSRequireDrop(t, hubNSDial(peerNS, t, "", mgmt), "nothing of the expired lease's management access survives")
		hubNSRequireDrop(t, hubNSDial(peerNS, t, "", local), "the gateway's management address is not the new lease's")
	})
}
