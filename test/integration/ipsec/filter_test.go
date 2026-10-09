//go:build integration

package ipsec

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	sdnipsec "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipsec"
)

// The fail-closed floor on a real kernel: the nftables filter and the XFRM
// block policies of pkg/sdn/ipsec, applied to a node in a network namespace
// with no charon running. The node has a fabric link to a peer and a LAN link
// to a client, and forwards between them, so traffic can reach the fabric in
// every way a node carries it: from the node, to the node, and routed through
// it into and out of the fabric. These tests need no suite inputs.
const (
	floorNodeNS   = "tp-floor-node"
	floorPeerNS   = "tp-floor-peer"
	floorClientNS = "tp-floor-client"

	// The node's interfaces, and the far ends of their veth pairs.
	floorFabric     = "fabric0"
	floorLAN        = "lan0"
	floorPeerLink   = "fabric1"
	floorClientLink = "lan1"

	floorNodeAddr    = "10.77.0.1"
	floorPeerAddr    = "10.77.0.2"
	floorNodeLANAddr = "10.78.0.1"
	floorClientAddr  = "10.78.0.2"
	floorLANNet      = "10.78.0.0/24"

	// floorSpoofNet holds the source addresses the IKE limiter test sends
	// from, which nothing owns: 10.200.0.0/16 fills the meter and
	// 10.201.0.0/16 probes it.
	floorSpoofNet = "10.200.0.0/15"

	// netnsDir is where `ip netns add` pins named namespaces.
	netnsDir = "/run/netns"

	// floorQuiet is how long a probe waits before it decides that nothing
	// got through. Everything here is one veth hop away, so a packet that
	// gets through arrives far sooner.
	floorQuiet = time.Second

	vxlanPort   = 4789
	bgpPort     = 179
	ikePort     = 500
	ikeNATTPort = 4500

	// espNetwork is ESP (IP protocol 50) on a raw IPv4 socket.
	espNetwork = "ip4:50"

	// ikeMeter and ikeMeterSize are the filter's per-source IKE meter and
	// its capacity (setIKEMeter and ikeMeterSize in pkg/sdn/ipsec/filter.go).
	ikeMeter     = "ike_meter"
	ikeMeterSize = 65535
	// meterFillRounds bounds how often the fill resends to sources the
	// kernel has not recorded yet.
	meterFillRounds = 20
)

// floorHost is an address on one of the test network's namespaces.
type floorHost struct {
	ns   netns.NsHandle
	addr netip.Addr
}

// address is the host as a dial or listen address: the address alone for a
// raw IP socket (port 0), with the port otherwise.
func (h floorHost) address(port uint16) string {
	if port == 0 {
		return h.addr.String()
	}
	return netip.AddrPortFrom(h.addr, port).String()
}

// local is the UDP address a sender binds, or nil for any port.
func (h floorHost) local(port uint16) net.Addr {
	if port == 0 {
		return nil
	}
	return &net.UDPAddr{IP: h.addr.AsSlice(), Port: int(port)}
}

// floorNet is the test network. node is the node's fabric address.
type floorNet struct {
	node, peer, client floorHost
}

// newFloorNet builds the test network and tears it down when the test ends.
func newFloorNet(t *testing.T, ctx context.Context) *floorNet {
	t.Helper()
	handles := make(map[string]netns.NsHandle, 3)
	for _, name := range []string{floorNodeNS, floorPeerNS, floorClientNS} {
		if _, err := os.Stat(filepath.Join(netnsDir, name)); err == nil {
			mustRun(t, ctx, "ip", "netns", "del", name) // a previous run's leftovers
		}
		mustRun(t, ctx, "ip", "netns", "add", name)
		t.Cleanup(func() {
			if out, err := run(context.Background(), nil, "ip", "netns", "del", name); err != nil {
				t.Logf("cleanup: %v %s", err, out)
			}
		})
		ns, err := netns.GetFromName(name)
		if err != nil {
			t.Fatalf("namespace %s: %v", name, err)
		}
		t.Cleanup(func() {
			if err := ns.Close(); err != nil {
				t.Logf("cleanup: namespace %s: %v", name, err)
			}
		})
		handles[name] = ns
	}

	for _, args := range [][]string{
		{"link", "add", floorFabric, "netns", floorNodeNS, "type", "veth", "peer", "name", floorPeerLink, "netns", floorPeerNS},
		{"link", "add", floorLAN, "netns", floorNodeNS, "type", "veth", "peer", "name", floorClientLink, "netns", floorClientNS},
		{"-n", floorNodeNS, "addr", "add", floorNodeAddr + "/24", "dev", floorFabric},
		{"-n", floorNodeNS, "addr", "add", floorNodeLANAddr + "/24", "dev", floorLAN},
		{"-n", floorPeerNS, "addr", "add", floorPeerAddr + "/24", "dev", floorPeerLink},
		{"-n", floorClientNS, "addr", "add", floorClientAddr + "/24", "dev", floorClientLink},
		{"-n", floorNodeNS, "link", "set", "lo", "up"},
		{"-n", floorNodeNS, "link", "set", floorFabric, "up"},
		{"-n", floorNodeNS, "link", "set", floorLAN, "up"},
		{"-n", floorPeerNS, "link", "set", "lo", "up"},
		{"-n", floorPeerNS, "link", "set", floorPeerLink, "up"},
		{"-n", floorClientNS, "link", "set", "lo", "up"},
		{"-n", floorClientNS, "link", "set", floorClientLink, "up"},
		{"-n", floorPeerNS, "route", "add", floorLANNet, "via", floorNodeAddr},
		{"-n", floorClientNS, "route", "add", "default", "via", floorNodeLANAddr},
		// The limiter test's sources route back to the fabric, so reverse-path
		// filtering on the node passes them to the filter.
		{"-n", floorNodeNS, "route", "add", floorSpoofNet, "via", floorPeerAddr},
	} {
		mustRun(t, ctx, "ip", args...)
	}
	mustRun(t, ctx, "ip", "netns", "exec", floorNodeNS, "sysctl", "-qw", "net.ipv4.ip_forward=1")

	return &floorNet{
		node:   floorHost{ns: handles[floorNodeNS], addr: netip.MustParseAddr(floorNodeAddr)},
		peer:   floorHost{ns: handles[floorPeerNS], addr: netip.MustParseAddr(floorPeerAddr)},
		client: floorHost{ns: handles[floorClientNS], addr: netip.MustParseAddr(floorClientAddr)},
	}
}

// floorConfig is the node's overlay.ipsec section.
func floorConfig() *sdnipsec.Config {
	return &sdnipsec.Config{
		Enabled:         true,
		FabricInterface: floorFabric,
		LocalAddress:    floorNodeAddr,
		StaticPeers:     []string{floorPeerAddr},
		Token:           sdnipsec.TokenConfig{Handle: "6970736563"},
	}
}

// applyFilter applies the nftables half of the floor on the node and removes
// it when the test ends.
func (n *floorNet) applyFilter(t *testing.T, ctx context.Context) *sdnipsec.Filter {
	t.Helper()
	f, err := sdnipsec.NewFilter(floorConfig(), nftables.WithNetNSFd(int(n.node.ns)))
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}
	if err := f.Apply(ctx); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	t.Cleanup(func() {
		if err := f.Remove(context.Background()); err != nil {
			t.Errorf("filter Remove: %v", err)
		}
	})
	return f
}

// installBlockPolicy installs the XFRM half of the floor on the node and
// removes it when the test ends.
func (n *floorNet) installBlockPolicy(t *testing.T, ctx context.Context) {
	t.Helper()
	b, err := sdnipsec.NewBlockPolicy(floorConfig(), n.node.ns)
	if err != nil {
		t.Fatalf("NewBlockPolicy: %v", err)
	}
	t.Cleanup(b.Close)
	if err := b.Install(ctx); err != nil {
		t.Fatalf("Install: %v", err)
	}
	t.Cleanup(func() {
		if err := b.Remove(context.Background()); err != nil {
			t.Errorf("block policy Remove: %v", err)
		}
	})
}

// inNetns runs fn on a thread in ns; the sockets fn opens stay in ns. The
// thread is never unlocked, so the runtime retires it with the goroutine
// instead of handing a thread in another namespace to other code.
func inNetns(ns netns.NsHandle, fn func() error) error {
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if err := netns.Set(ns); err != nil {
			done <- err
			return
		}
		done <- fn()
	}()
	return <-done
}

func closeConn(t *testing.T, c io.Closer) {
	t.Helper()
	if err := c.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
}

// floorFlow is one way a packet can cross the fabric. network is "udp4",
// "tcp4" or espNetwork.
type floorFlow struct {
	name             string
	network          string
	from, to         floorHost
	srcPort, dstPort uint16
	// outOfFabric marks traffic routed from the fabric to the LAN. The XFRM
	// block covers only what is routed into the fabric; the filter covers
	// both directions.
	outOfFabric bool
}

// floorProbes sends one packet along a flow, or for TCP makes one
// handshake, and reports whether it got through.
var floorProbes = map[string]func(t *testing.T, f floorFlow) bool{
	"udp4":     probeDatagram,
	espNetwork: probeDatagram,
	"tcp4":     probeStream,
}

func (f floorFlow) delivered(t *testing.T) bool {
	t.Helper()
	probe, ok := floorProbes[f.network]
	if !ok {
		t.Fatalf("%s: no probe for %s", f.name, f.network)
	}
	return probe(t, f)
}

func probeDatagram(t *testing.T, f floorFlow) bool {
	t.Helper()
	var rx net.PacketConn
	if err := inNetns(f.to.ns, func() (err error) {
		rx, err = net.ListenPacket(f.network, f.to.address(f.dstPort))
		return err
	}); err != nil {
		t.Fatalf("%s: listen: %v", f.name, err)
	}
	defer closeConn(t, rx)

	payload := []byte("tp-floor " + f.name)
	if err := inNetns(f.from.ns, func() error {
		d := net.Dialer{LocalAddr: f.from.local(f.srcPort)}
		c, err := d.Dial(f.network, f.to.address(f.dstPort))
		if err != nil {
			return err
		}
		_, werr := c.Write(payload)
		return errors.Join(werr, c.Close())
	}); err != nil {
		// The floor can refuse a packet at its sender: an XFRM block and an
		// nftables drop on output both fail the send with EPERM.
		t.Logf("%s: %v", f.name, err)
		return false
	}
	return receives(t, rx, payload)
}

func probeStream(t *testing.T, f floorFlow) bool {
	t.Helper()
	var ln net.Listener
	if err := inNetns(f.to.ns, func() (err error) {
		ln, err = net.Listen(f.network, f.to.address(f.dstPort))
		return err
	}); err != nil {
		t.Fatalf("%s: listen: %v", f.name, err)
	}
	defer closeConn(t, ln)

	if err := inNetns(f.from.ns, func() error {
		d := net.Dialer{Timeout: floorQuiet}
		c, err := d.Dial(f.network, f.to.address(f.dstPort))
		if err != nil {
			return err
		}
		return c.Close()
	}); err != nil {
		t.Logf("%s: %v", f.name, err)
		return false
	}
	return true
}

// receives reads rx until payload arrives, or reports false once floorQuiet
// has passed without it.
func receives(t *testing.T, rx net.PacketConn, payload []byte) bool {
	t.Helper()
	if err := rx.SetReadDeadline(time.Now().Add(floorQuiet)); err != nil {
		t.Fatalf("read deadline: %v", err)
	}
	buf := make([]byte, 2048)
	for {
		n, _, err := rx.ReadFrom(buf)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return false
		}
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if bytes.Equal(buf[:n], payload) {
			return true
		}
	}
}

// requireDelivery fails the test unless every flow gets through.
func requireDelivery(t *testing.T, flows []floorFlow, when string) {
	t.Helper()
	for _, f := range flows {
		if !f.delivered(t) {
			t.Errorf("%s did not get through %s", f.name, when)
		}
	}
	if t.Failed() {
		t.FailNow()
	}
}

// TestFloorLeavesNoCleartextPath sends VXLAN and BGP in cleartext every way
// the fabric carries them while charon is stopped, and ESP routed through
// the node, which is another host's tunnel and not the VTEP's. Each half of
// the floor is applied alone and then both together, as a node runs them,
// so neither half can hide a hole in the other, and the two must agree
// that routed ESP does not pass.
func TestFloorLeavesNoCleartextPath(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	n := newFloorNet(t, ctx)

	var flows []floorFlow
	for _, p := range []struct {
		name, network string
		port          uint16
	}{
		{"VXLAN", "udp4", vxlanPort},
		{"BGP", "tcp4", bgpPort},
	} {
		flows = append(flows,
			floorFlow{name: p.name + " from the node", network: p.network, from: n.node, to: n.peer, dstPort: p.port},
			floorFlow{name: p.name + " to the node", network: p.network, from: n.peer, to: n.node, dstPort: p.port},
			floorFlow{name: p.name + " routed into the fabric", network: p.network, from: n.client, to: n.peer, dstPort: p.port},
			floorFlow{name: p.name + " routed out of the fabric", network: p.network, from: n.peer, to: n.client, dstPort: p.port,
				outOfFabric: true},
		)
	}
	flows = append(flows,
		floorFlow{name: "ESP routed into the fabric", network: espNetwork, from: n.client, to: n.peer},
		floorFlow{name: "ESP routed out of the fabric", network: espNetwork, from: n.peer, to: n.client, outOfFabric: true},
	)

	for _, layer := range []struct {
		name          string
		filter, block bool
	}{
		{"nftables filter", true, false},
		{"XFRM block policies", false, true},
		{"both", true, true},
	} {
		t.Run(layer.name, func(t *testing.T) {
			// Every flow gets through without the floor (and so after the
			// previous layer's removal), so one that does not is stopped by
			// the floor and not by the test network.
			requireDelivery(t, flows, "without the floor")
			if layer.filter {
				n.applyFilter(t, ctx)
			}
			if layer.block {
				n.installBlockPolicy(t, ctx)
			}
			for _, f := range flows {
				if f.outOfFabric && !layer.filter {
					continue
				}
				if f.delivered(t) {
					t.Errorf("%s crossed the floor", f.name)
				}
			}
		})
	}
}

// TestEvictedPeerIsDroppedBeforeESP evicts a peer whose ESP and IKE the
// filter accepts, and checks that the input and output chains drop them
// from then on: the evicted-peer rules must come before the ESP and IKE
// accepts. Routed ESP is never accepted (TestFloorLeavesNoCleartextPath).
func TestEvictedPeerIsDroppedBeforeESP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	n := newFloorNet(t, ctx)
	filter := n.applyFilter(t, ctx)

	flows := []floorFlow{
		{name: "ESP from the peer", network: espNetwork, from: n.peer, to: n.node},
		{name: "ESP to the peer", network: espNetwork, from: n.node, to: n.peer},
		{name: "IKE from the peer", network: "udp4", from: n.peer, to: n.node, srcPort: ikePort, dstPort: ikePort},
	}
	requireDelivery(t, flows, "the filter before the eviction")

	if err := filter.Drop(ctx, n.peer.addr); err != nil {
		t.Fatalf("Drop: %v", err)
	}
	for _, f := range flows {
		if f.delivered(t) {
			t.Errorf("%s got through after the eviction", f.name)
		}
	}

	if err := filter.Undrop(ctx, n.peer.addr); err != nil {
		t.Fatalf("Undrop: %v", err)
	}
	requireDelivery(t, flows, "the filter once the eviction is lifted")
}

// TestIKELimiterHoldsWithAFullMeter fills the filter's IKE meter, one entry
// per source address, then sends IKE from one more source. The meter cannot
// take it, so the update fails and the packet must be dropped: a flood of
// sources cannot open the limiter. A source already in the meter is still
// admitted.
func TestIKELimiterHoldsWithAFullMeter(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	n := newFloorNet(t, ctx)
	n.applyFilter(t, ctx)
	ike := n.newIKESender(t)

	var rx net.PacketConn
	if err := inNetns(n.node.ns, func() (err error) {
		rx, err = net.ListenPacket("udp4", n.node.address(ikePort))
		return err
	}); err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer closeConn(t, rx)

	known := netip.MustParseAddr("10.201.0.1")
	newcomer := netip.MustParseAddr("10.201.0.2")
	if !ike.arrives(t, rx, known) {
		t.Fatal("IKE from a new source was dropped while the meter had room")
	}
	n.fillIKEMeter(t, ike, netip.MustParseAddr("10.200.0.0"), ikeMeterSize-1)

	if ike.arrives(t, rx, newcomer) {
		t.Error("IKE from a new source got through a full meter")
	}
	if !ike.arrives(t, rx, known) {
		t.Error("IKE from a source already in the full meter was dropped")
	}
}

// ikeSender sends IKE to the node from any source address, through a raw
// socket in the peer's namespace.
type ikeSender struct {
	fd int
	to netip.Addr
}

func (n *floorNet) newIKESender(t *testing.T) *ikeSender {
	t.Helper()
	var fd int
	if err := inNetns(n.peer.ns, func() (err error) {
		fd, err = unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
		return err
	}); err != nil {
		t.Fatalf("raw socket: %v", err)
	}
	t.Cleanup(func() {
		if err := unix.Close(fd); err != nil {
			t.Errorf("close raw socket: %v", err)
		}
	})
	return &ikeSender{fd: fd, to: n.node.addr}
}

func (s *ikeSender) send(src netip.Addr, port uint16, payload []byte) error {
	return unix.Sendto(s.fd, ikePacket(src, s.to, port, payload), 0, &unix.SockaddrInet4{Addr: s.to.As4()})
}

// arrives sends IKE from src and reports whether the node received it.
func (s *ikeSender) arrives(t *testing.T, rx net.PacketConn, src netip.Addr) bool {
	t.Helper()
	payload := []byte("tp-floor IKE from " + src.String())
	if err := s.send(src, ikePort, payload); err != nil {
		t.Fatalf("send from %s: %v", src, err)
	}
	return receives(t, rx, payload)
}

// fillIKEMeter sends IKE on the NAT-T port from count sources counted up from
// first, until the node's meter holds every one of them and is full. Sources
// the kernel has not recorded are sent again: a burst this large can overrun
// the veth's receive backlog.
func (n *floorNet) fillIKEMeter(t *testing.T, s *ikeSender, first netip.Addr, count int) {
	t.Helper()
	conn, err := nftables.New(nftables.WithNetNSFd(int(n.node.ns)))
	if err != nil {
		t.Fatalf("nftables: %v", err)
	}
	table := &nftables.Table{Name: sdnipsec.TableName, Family: nftables.TableFamilyINet}
	meter, err := conn.GetSetByName(table, ikeMeter)
	if err != nil {
		t.Fatalf("meter: %v", err)
	}

	missing := make(map[netip.Addr]struct{}, count)
	for src := first; len(missing) < count; src = src.Next() {
		missing[src] = struct{}{}
	}
	held := 0
	for round := 0; len(missing) > 0; round++ {
		if round == meterFillRounds {
			t.Fatalf("the meter still lacks %d of %d sources", len(missing), count)
		}
		for src := range missing {
			if err := s.send(src, ikeNATTPort, nil); err != nil {
				t.Fatalf("send from %s: %v", src, err)
			}
		}
		elems, err := conn.GetSetElements(meter)
		if err != nil {
			t.Fatalf("meter elements: %v", err)
		}
		for _, e := range elems {
			if a, ok := netip.AddrFromSlice(e.Key); ok {
				delete(missing, a)
			}
		}
		held = len(elems)
	}
	if held != ikeMeterSize {
		t.Fatalf("the meter holds %d sources, want it full at %d", held, ikeMeterSize)
	}
}

// ikePacket is an IPv4 UDP datagram from src to dst, port to port, for an
// IPPROTO_RAW socket. The kernel fills in the IPv4 checksum; a zero UDP
// checksum means none (RFC 768).
func ikePacket(src, dst netip.Addr, port uint16, payload []byte) []byte {
	const ipLen, udpLen = 20, 8
	pkt := make([]byte, ipLen+udpLen+len(payload))
	pkt[0] = 0x45 // IPv4, 20-byte header
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64 // TTL
	pkt[9] = unix.IPPROTO_UDP
	s, d := src.As4(), dst.As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])

	udp := pkt[ipLen:]
	binary.BigEndian.PutUint16(udp[0:2], port)
	binary.BigEndian.PutUint16(udp[2:4], port)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen+len(payload)))
	copy(udp[udpLen:], payload)
	return pkt
}
