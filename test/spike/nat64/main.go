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

//go:build spike

// Command nat64 is the #595 spike: a deliberately minimal stateful NAT64
// (RFC 6146 shape, RFC 6052 well-known prefix) over two TUN devices, used
// only to measure the throughput ceiling of a Go userspace translator with
// one goroutine per direction and no per-core fan-out. It handles UDP and TCP without options-aware rewriting, no
// ICMP translation (RFC 7915), no fragments, no timeouts — none of which a
// product needs to be missing. Run inside an unprivileged user namespace:
//
//	unshare -rn go run -tags spike ./test/spike/nat64 -seconds 5 -payload 1200
//
// It is never part of `make test`.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// ErrSpike is the spike's only error type: a step and its cause.
type ErrSpike struct {
	Step  string
	Cause error
}

func (e *ErrSpike) Error() string { return "nat64 spike: " + e.Step + ": " + e.Cause.Error() }

const (
	wkp        = "64:ff9b::"      // RFC 6052 well-known prefix /96
	clientV6   = "2001:db8::2/64" // the IPv6-only client, on tun6
	serverV4   = "192.0.2.1"      // the IPv4-only server, on tun4
	poolV4     = "192.0.2.100"    // the translator's NAT64 pool address
	serverPort = 9000
	mtu6       = 1280
)

func openTUN(name string) (int, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR, 0)
	if err != nil {
		return -1, &ErrSpike{Step: "open /dev/net/tun", Cause: err}
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return -1, &ErrSpike{Step: "ifreq", Cause: err}
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		return -1, &ErrSpike{Step: "TUNSETIFF " + name, Cause: err}
	}
	return fd, nil
}

func ip(args ...string) error {
	cmd := exec.Command("ip", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return &ErrSpike{Step: "ip " + fmt.Sprint(args) + ": " + string(out), Cause: err}
	}
	return nil
}

// binding is one NAT64 session: the client's IPv6 source and port, keyed
// by the pool port the translator handed out.
type binding struct {
	src6 [16]byte
	port uint16
}

// translator holds the binding table. Each direction runs on its own
// goroutine, so the table is guarded: readers take the read lock, the one
// writer (a new binding on the v6→v4 path) takes the write lock.
type translator struct {
	tun6, tun4 int
	pool       [4]byte
	mu         sync.RWMutex
	byKey      map[[18]byte]uint16 // src6+port -> pool port
	byPort     map[uint16]binding
	nextPort   uint16
	pkts6to4   atomic.Uint64
	pkts4to6   atomic.Uint64
}

func csum(sum uint32, b []byte) uint32 {
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return sum
}

func fold(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// l4Checksum recomputes the UDP/TCP checksum over a pseudo-header built
// for the given family; the translator never adjusts incrementally so the
// spike stays obviously correct.
func l4Checksum(src, dst []byte, proto uint8, l4 []byte) uint16 {
	var sum uint32
	sum = csum(sum, src)
	sum = csum(sum, dst)
	if len(src) == 4 {
		sum += uint32(proto)
		sum += uint32(len(l4))
	} else {
		sum += uint32(len(l4))
		sum += uint32(proto)
	}
	sum = csum(sum, l4)
	return fold(sum)
}

func (t *translator) v6to4(pkt []byte) []byte {
	if len(pkt) < 40 || pkt[0]>>4 != 6 {
		return nil
	}
	next := pkt[6]
	if next != unix.IPPROTO_UDP && next != unix.IPPROTO_TCP {
		return nil // ICMPv6 and everything else: out of the spike's scope
	}
	l4 := pkt[40:]
	if len(l4) < 8 {
		return nil
	}
	var key [18]byte
	copy(key[:16], pkt[8:24])
	copy(key[16:], l4[0:2])
	pport, ok := t.lookupOrBind(key, pkt[8:24], binary.BigEndian.Uint16(l4[0:2]))
	if !ok {
		return nil
	}
	out := make([]byte, 20+len(l4))
	out[0] = 0x45
	binary.BigEndian.PutUint16(out[2:], uint16(len(out)))
	out[6] = 0x40 // DF, as RFC 7915 does for atomic translations
	out[8] = pkt[7]
	out[9] = next
	copy(out[12:16], t.pool[:])
	copy(out[16:20], pkt[36:40]) // embedded IPv4 from the /96 prefix
	binary.BigEndian.PutUint16(out[10:], fold(csum(0, out[:20])))
	copy(out[20:], l4)
	binary.BigEndian.PutUint16(out[20:], pport)
	cs := 6
	if next == unix.IPPROTO_TCP {
		cs = 16
	}
	out[20+cs], out[21+cs] = 0, 0
	binary.BigEndian.PutUint16(out[20+cs:], l4Checksum(out[12:16], out[16:20], next, out[20:]))
	return out
}

// lookupOrBind returns the pool port for a client address:port, creating the
// binding on first sight. It reports false only when the pool is exhausted.
func (t *translator) lookupOrBind(key [18]byte, src6 []byte, port uint16) (uint16, bool) {
	t.mu.RLock()
	pport, ok := t.byKey[key]
	t.mu.RUnlock()
	if ok {
		return pport, true
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if pport, ok = t.byKey[key]; ok {
		return pport, true
	}
	if t.nextPort == 65535 {
		return 0, false
	}
	t.nextPort++
	if t.nextPort < 1024 {
		t.nextPort = 1024
	}
	pport = t.nextPort
	t.byKey[key] = pport
	var b binding
	copy(b.src6[:], src6)
	b.port = port
	t.byPort[pport] = b
	return pport, true
}

// lookupPort returns the binding behind a pool port.
func (t *translator) lookupPort(pport uint16) (binding, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	b, ok := t.byPort[pport]
	return b, ok
}

func (t *translator) v4to6(pkt []byte) []byte {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return nil
	}
	ihl := int(pkt[0]&0x0f) * 4
	proto := pkt[9]
	if proto != unix.IPPROTO_UDP && proto != unix.IPPROTO_TCP {
		return nil
	}
	l4 := pkt[ihl:]
	if len(l4) < 8 {
		return nil
	}
	b, ok := t.lookupPort(binary.BigEndian.Uint16(l4[2:4]))
	if !ok {
		return nil
	}
	out := make([]byte, 40+len(l4))
	out[0] = 0x60
	binary.BigEndian.PutUint16(out[4:], uint16(len(l4)))
	out[6] = proto
	out[7] = pkt[8]
	prefix := net.ParseIP(wkp)
	copy(out[8:24], prefix[:16])
	copy(out[20:24], pkt[12:16]) // v4 source embedded into the /96
	copy(out[24:40], b.src6[:])
	copy(out[40:], l4)
	binary.BigEndian.PutUint16(out[42:], b.port)
	cs := 6
	if proto == unix.IPPROTO_TCP {
		cs = 16
	}
	out[40+cs], out[41+cs] = 0, 0
	binary.BigEndian.PutUint16(out[40+cs:], l4Checksum(out[8:24], out[24:40], proto, out[40:]))
	return out
}

func (t *translator) pump(from, to int, fn func([]byte) []byte, counter *atomic.Uint64) {
	buf := make([]byte, 65536)
	for {
		n, err := unix.Read(from, buf)
		if err != nil {
			return
		}
		if out := fn(buf[:n]); out != nil {
			if _, err := unix.Write(to, out); err == nil {
				counter.Add(1)
			}
		}
	}
}

func main() {
	seconds := flag.Int("seconds", 5, "measurement window")
	payload := flag.Int("payload", 1200, "UDP payload bytes (IPv6 MTU 1280 bounds it)")
	flag.Parse()
	if err := run(*seconds, *payload); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(seconds, payload int) error {
	tun6, err := openTUN("nat64v6")
	if err != nil {
		return err
	}
	tun4, err := openTUN("nat64v4")
	if err != nil {
		return err
	}
	steps := [][]string{
		{"link", "set", "lo", "up"},
		{"link", "set", "nat64v6", "up", "mtu", fmt.Sprint(mtu6)},
		{"link", "set", "nat64v4", "up"},
		{"-6", "addr", "add", clientV6, "dev", "nat64v6"},
		{"-6", "route", "add", wkp + "/96", "dev", "nat64v6"},
		{"-4", "addr", "add", serverV4 + "/24", "dev", "nat64v4"},
	}
	for _, s := range steps {
		if err := ip(s...); err != nil {
			return err
		}
	}
	t := &translator{tun6: tun6, tun4: tun4, byKey: map[[18]byte]uint16{}, byPort: map[uint16]binding{}}
	copy(t.pool[:], net.ParseIP(poolV4).To4())
	go t.pump(tun6, tun4, t.v6to4, &t.pkts6to4)
	go t.pump(tun4, tun6, t.v4to6, &t.pkts4to6)

	recv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(serverV4), Port: serverPort})
	if err != nil {
		return &ErrSpike{Step: "listen v4", Cause: err}
	}
	defer recv.Close()
	var received, replied atomic.Uint64
	go func() {
		buf := make([]byte, 65536)
		for {
			n, from, err := recv.ReadFromUDP(buf)
			if err != nil {
				return
			}
			received.Add(uint64(n))
			// Echo one byte back so the v4→v6 path is exercised too.
			if _, err := recv.WriteToUDP(buf[:1], from); err == nil {
				replied.Add(1)
			}
		}
	}()

	// The IPv6-only client talks to the IPv4 server through the prefix.
	embedded := net.ParseIP(wkp)
	copy(embedded[12:16], net.ParseIP(serverV4).To4())
	client, err := net.DialUDP("udp6", &net.UDPAddr{IP: net.ParseIP("2001:db8::2")}, &net.UDPAddr{IP: embedded, Port: serverPort})
	if err != nil {
		return &ErrSpike{Step: "dial v6", Cause: err}
	}
	defer client.Close()
	go func() {
		buf := make([]byte, 64)
		for {
			if _, err := client.Read(buf); err != nil {
				return
			}
		}
	}()

	msg := make([]byte, payload)
	deadline := time.Now().Add(time.Duration(seconds) * time.Second)
	var sent uint64
	for time.Now().Before(deadline) {
		if _, err := client.Write(msg); err == nil {
			sent++
		}
	}
	timer := time.NewTimer(200 * time.Millisecond)
	<-timer.C
	got := received.Load()
	fmt.Printf("nat64 spike: %d s, payload %d B\n", seconds, payload)
	fmt.Printf("  sent      %d datagrams\n", sent)
	fmt.Printf("  received  %d datagrams, %.1f MB, %.0f Mbit/s goodput, %.0f pps\n",
		got/uint64(payload), float64(got)/1e6, float64(got)*8/1e6/float64(seconds), float64(got/uint64(payload))/float64(seconds))
	fmt.Printf("  translated v6->v4 %d, v4->v6 %d (echo replies %d)\n", t.pkts6to4.Load(), t.pkts4to6.Load(), replied.Load())
	return nil
}
