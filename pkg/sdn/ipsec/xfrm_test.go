// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package ipsec

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// fabricIndex is the interface index of the fabric in fakeXFRM.
const fabricIndex = 7

// fakeXFRM is a security policy database. Like the kernel, it keys a
// policy by direction and selector, and a lookup picks the matching policy
// with the lowest priority number. It also resolves interface names.
type fakeXFRM struct {
	spd       map[string]*netlink.XfrmPolicy
	links     map[string]int
	updateErr error
	delErr    error
	updates   int
	closed    bool
}

func newFakeXFRM() *fakeXFRM {
	return &fakeXFRM{
		spd:   make(map[string]*netlink.XfrmPolicy),
		links: map[string]int{"bond0": fabricIndex},
	}
}

func policyKey(p *netlink.XfrmPolicy) string {
	return p.Dir.String() + " " + p.Src.String() + " " + p.Dst.String() + " " +
		p.Proto.String() + " " + strconv.Itoa(p.SrcPort) + " " + strconv.Itoa(p.Ifindex)
}

func (x *fakeXFRM) XfrmPolicyUpdate(p *netlink.XfrmPolicy) error {
	if x.updateErr != nil {
		return x.updateErr
	}
	x.updates++
	x.spd[policyKey(p)] = p
	return nil
}

func (x *fakeXFRM) XfrmPolicyDel(p *netlink.XfrmPolicy) error {
	if x.delErr != nil && p.Action == netlink.XFRM_POLICY_BLOCK {
		return x.delErr
	}
	if _, ok := x.spd[policyKey(p)]; !ok {
		return unix.ENOENT
	}
	delete(x.spd, policyKey(p))
	return nil
}

func (x *fakeXFRM) LinkByName(name string) (netlink.Link, error) {
	index, ok := x.links[name]
	if !ok {
		return nil, unix.ENODEV
	}
	return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name, Index: index}}, nil
}

func (x *fakeXFRM) Close() { x.closed = true }

// flow is what a policy lookup needs of a packet. oif is the output
// interface index, which only the forward direction is checked against.
type flow struct {
	dir      netlink.Dir
	src, dst netip.Addr
	proto    uint8
	icmpType int
	oif      int
}

// lookup returns the policy governing a flow, or nil when none does.
func (x *fakeXFRM) lookup(f flow) *netlink.XfrmPolicy {
	var best *netlink.XfrmPolicy
	for _, p := range x.spd {
		if p.Dir != f.dir || !selects(p.Src, f.src) || !selects(p.Dst, f.dst) ||
			(p.Proto != 0 && uint8(p.Proto) != f.proto) || (p.SrcPort != 0 && p.SrcPort != f.icmpType) ||
			(p.Ifindex != 0 && p.Ifindex != f.oif) {
			continue
		}
		if best == nil || p.Priority < best.Priority {
			best = p
		}
	}
	return best
}

// selects is a selector address match. A nil destination is an IPv4
// wildcard, because the selector family follows the destination.
func selects(n *net.IPNet, a netip.Addr) bool {
	if n == nil {
		return a.Is4()
	}
	return n.Contains(a.AsSlice())
}

func action(p *netlink.XfrmPolicy) string {
	if p == nil {
		return "none"
	}
	return p.Action.String()
}

func testBlockPolicy(t *testing.T, cfg *Config) (*BlockPolicy, *fakeXFRM) {
	t.Helper()
	local, err := enabledLocal(cfg)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	x := newFakeXFRM()
	return &BlockPolicy{local: local, iface: cfg.FabricInterface, slaac: cfg.UnderlaySLAAC, handle: x}, x
}

func installedBlockPolicy(t *testing.T, cfg *Config) (*BlockPolicy, *fakeXFRM) {
	t.Helper()
	b, x := testBlockPolicy(t, cfg)
	if err := b.Install(context.Background()); err != nil {
		t.Fatalf("Install: %v", err)
	}
	return b, x
}

func ipv6Config() *Config {
	cfg := validConfig()
	cfg.LocalAddress = "fd00:20::11"
	cfg.StaticPeers = []string{"fd00:20::1"}
	return cfg
}

func TestBlockPolicyFailsClosed(t *testing.T) {
	_, x := installedBlockPolicy(t, validConfig())
	local, peer, beyond := addr(local4), addr(peer4), addr("10.30.0.5")

	for _, tt := range []struct {
		name string
		f    flow
		want string
	}{
		{"outbound VXLAN", flow{dir: netlink.XFRM_DIR_OUT, src: local, dst: peer, proto: unix.IPPROTO_UDP}, "block"},
		{"inbound BGP", flow{dir: netlink.XFRM_DIR_IN, src: peer, dst: local, proto: unix.IPPROTO_TCP}, "block"},
		{"routed into the fabric", flow{dir: netlink.XFRM_DIR_FWD, src: beyond, dst: peer, proto: unix.IPPROTO_UDP, oif: fabricIndex}, "block"},
		{"routed out of the fabric elsewhere", flow{dir: netlink.XFRM_DIR_FWD, src: peer, dst: beyond, proto: unix.IPPROTO_UDP, oif: 9}, "none"},
		{"from another address", flow{dir: netlink.XFRM_DIR_OUT, src: addr("192.0.2.1"), dst: peer, proto: unix.IPPROTO_UDP}, "none"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := action(x.lookup(tt.f)); got != tt.want {
				t.Fatalf("policy = %s, want %s", got, tt.want)
			}
		})
	}

	// A transport policy as charon installs it for a trapped peer, at its
	// lowest priority, takes precedence.
	host := func(a netip.Addr) *net.IPNet { return &net.IPNet{IP: a.AsSlice(), Mask: net.CIDRMask(32, 32)} }
	charon := &netlink.XfrmPolicy{Src: host(local), Dst: host(peer), Dir: netlink.XFRM_DIR_OUT, Priority: 400000,
		Tmpls: []netlink.XfrmPolicyTmpl{{Proto: netlink.XFRM_PROTO_ESP, Mode: netlink.XFRM_MODE_TRANSPORT}}}
	if err := x.XfrmPolicyUpdate(charon); err != nil {
		t.Fatalf("charon policy: %v", err)
	}
	if got := x.lookup(flow{dir: netlink.XFRM_DIR_OUT, src: local, dst: peer, proto: unix.IPPROTO_UDP}); got != charon {
		t.Fatalf("charon's policy lost to %s", action(got))
	}
}

func TestBlockPolicyIPv6(t *testing.T) {
	slaac := ipv6Config()
	slaac.UnderlaySLAAC = true
	_, plain := installedBlockPolicy(t, ipv6Config())
	_, withSLAAC := installedBlockPolicy(t, slaac)
	local, peer := addr("fd00:20::11"), addr("fd00:20::30")
	icmp := func(dir netlink.Dir, src, dst netip.Addr, typ int) flow {
		return flow{dir: dir, src: src, dst: dst, proto: unix.IPPROTO_ICMPV6, icmpType: typ}
	}

	for _, tt := range []struct {
		name          string
		f             flow
		want, slaacOn string
	}{
		{"neighbour solicitation out", icmp(netlink.XFRM_DIR_OUT, local, addr("ff02::1:ff00:30"), 135), "allow", "allow"},
		{"neighbour advertisement in", icmp(netlink.XFRM_DIR_IN, peer, local, 136), "allow", "allow"},
		{"MLD query in", icmp(netlink.XFRM_DIR_IN, peer, local, 130), "allow", "allow"},
		{"MLDv2 report out", icmp(netlink.XFRM_DIR_OUT, local, addr("ff02::16"), 143), "allow", "allow"},
		{"router solicitation out", icmp(netlink.XFRM_DIR_OUT, local, addr("ff02::2"), 133), "block", "allow"},
		{"router advertisement in", icmp(netlink.XFRM_DIR_IN, peer, local, 134), "block", "allow"},
		{"redirect in", icmp(netlink.XFRM_DIR_IN, peer, local, 137), "block", "block"},
		{"echo request in", icmp(netlink.XFRM_DIR_IN, peer, local, 128), "block", "block"},
		{"VXLAN out", flow{dir: netlink.XFRM_DIR_OUT, src: local, dst: peer, proto: unix.IPPROTO_UDP}, "block", "block"},
		{"BGP in", flow{dir: netlink.XFRM_DIR_IN, src: peer, dst: local, proto: unix.IPPROTO_TCP}, "block", "block"},
		{"routed into the fabric", flow{dir: netlink.XFRM_DIR_FWD, src: addr("fd00:30::5"), dst: peer,
			proto: unix.IPPROTO_UDP, oif: fabricIndex}, "block", "block"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := action(plain.lookup(tt.f)); got != tt.want {
				t.Errorf("policy = %s, want %s", got, tt.want)
			}
			if got := action(withSLAAC.lookup(tt.f)); got != tt.slaacOn {
				t.Errorf("with underlay-slaac: policy = %s, want %s", got, tt.slaacOn)
			}
		})
	}
}

func TestBlockPolicyInstallIsIdempotent(t *testing.T) {
	b, x := installedBlockPolicy(t, validConfig())
	if err := b.Install(context.Background()); err != nil {
		t.Fatalf("second Install: %v", err)
	}
	if len(x.spd) != 3 {
		t.Fatalf("SPD holds %d policies after a second Install, want 3", len(x.spd))
	}
}

func TestBlockPolicyInstallFailures(t *testing.T) {
	b, x := testBlockPolicy(t, validConfig())

	x.updateErr = errInjected
	var opErr *OpError
	if err := b.Install(context.Background()); !errors.As(err, &opErr) || !errors.Is(err, errInjected) {
		t.Fatalf("Install with a failing kernel: err = %v", err)
	}

	x.updateErr = nil
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := b.Install(cancelled); !errors.As(err, &opErr) || !errors.Is(err, context.Canceled) {
		t.Fatalf("Install with a cancelled context: err = %v", err)
	}

	// Without the fabric interface the forward block has nothing to bind
	// to, and Install writes nothing rather than a partial floor.
	delete(x.links, "bond0")
	if err := b.Install(context.Background()); !errors.As(err, &opErr) || !errors.Is(err, unix.ENODEV) {
		t.Fatalf("Install without the fabric interface: err = %v", err)
	}
	if x.updates != 0 {
		t.Fatalf("failed Installs wrote %d policies", x.updates)
	}
}

func TestBlockPolicyRemove(t *testing.T) {
	ctx := context.Background()
	b, x := installedBlockPolicy(t, ipv6Config())

	if err := b.Remove(ctx); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if len(x.spd) != 0 {
		t.Fatalf("SPD still holds %d policies", len(x.spd))
	}
	if err := b.Remove(ctx); err != nil {
		t.Fatalf("Remove of absent policies: %v", err)
	}

	// A block the kernel refuses to delete does not keep the rest.
	if err := b.Install(ctx); err != nil {
		t.Fatalf("Install: %v", err)
	}
	x.delErr = errInjected
	var opErr *OpError
	if err := b.Remove(ctx); !errors.As(err, &opErr) || !errors.Is(err, errInjected) {
		t.Fatalf("Remove with a failing kernel: err = %v", err)
	}
	if len(x.spd) != 3 {
		t.Fatalf("SPD holds %d policies, want only the three blocks left", len(x.spd))
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := b.Remove(cancelled); !errors.As(err, &opErr) || !errors.Is(err, context.Canceled) {
		t.Fatalf("Remove with a cancelled context: err = %v", err)
	}

	b.Close()
	if !x.closed {
		t.Fatal("Close did not close the netlink handle")
	}
}

func TestBlockPolicyRemoveForwardBlock(t *testing.T) {
	ctx := context.Background()

	t.Run("after the fabric interface is gone", func(t *testing.T) {
		b, x := installedBlockPolicy(t, validConfig())
		delete(x.links, "bond0")
		if err := b.Remove(ctx); err != nil {
			t.Fatalf("Remove: %v", err)
		}
		if len(x.spd) != 0 {
			t.Fatalf("SPD still holds %d policies", len(x.spd))
		}
	})
	t.Run("installed by an earlier process", func(t *testing.T) {
		earlier, x := installedBlockPolicy(t, validConfig())
		later := &BlockPolicy{local: earlier.local, iface: earlier.iface, handle: x}
		if err := later.Remove(ctx); err != nil {
			t.Fatalf("Remove: %v", err)
		}
		if len(x.spd) != 0 {
			t.Fatalf("SPD still holds %d policies", len(x.spd))
		}
	})
	t.Run("never installed and no interface", func(t *testing.T) {
		b, x := testBlockPolicy(t, validConfig())
		delete(x.links, "bond0")
		if err := b.Remove(ctx); err != nil {
			t.Fatalf("Remove: %v", err)
		}
	})
}

func TestNewBlockPolicy(t *testing.T) {
	invalid := validConfig()
	invalid.FabricInterface = ""
	for _, tt := range []struct {
		name string
		cfg  *Config
		want error
	}{
		{"absent", nil, ErrNotEnabled},
		{"disabled", &Config{}, ErrNotEnabled},
		{"invalid", invalid, ErrRequired},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewBlockPolicy(tt.cfg, netns.None()); !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}

	// Opening the netlink sockets needs no privilege; nothing is written.
	cfg := validConfig()
	cfg.UnderlaySLAAC = true
	b, err := NewBlockPolicy(cfg, netns.None())
	if err != nil {
		t.Fatalf("NewBlockPolicy: %v", err)
	}
	if b.iface != cfg.FabricInterface || !b.slaac {
		t.Fatalf("BlockPolicy iface %q slaac %v, want the configuration's", b.iface, b.slaac)
	}
	b.Close()
}
