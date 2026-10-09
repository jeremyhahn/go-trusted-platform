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

// fakeXFRM is a security policy database. Like the kernel, it keys a
// policy by direction and selector, and a lookup picks the matching policy
// with the lowest priority number.
type fakeXFRM struct {
	spd       map[string]*netlink.XfrmPolicy
	updateErr error
	delErr    error
	updates   int
	closed    bool
}

func newFakeXFRM() *fakeXFRM {
	return &fakeXFRM{spd: make(map[string]*netlink.XfrmPolicy)}
}

func policyKey(p *netlink.XfrmPolicy) string {
	return p.Dir.String() + " " + p.Src.String() + " " + p.Dst.String() + " " +
		p.Proto.String() + " " + strconv.Itoa(p.SrcPort)
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

func (x *fakeXFRM) Close() { x.closed = true }

// lookup returns the policy governing a packet, or nil when none does.
func (x *fakeXFRM) lookup(dir netlink.Dir, src, dst netip.Addr, proto uint8, icmpType int) *netlink.XfrmPolicy {
	var best *netlink.XfrmPolicy
	for _, p := range x.spd {
		if p.Dir != dir || !selects(p.Src, src) || !selects(p.Dst, dst) ||
			(p.Proto != 0 && uint8(p.Proto) != proto) || (p.SrcPort != 0 && p.SrcPort != icmpType) {
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

func installedBlockPolicy(t *testing.T, cfg *Config) (*BlockPolicy, *fakeXFRM) {
	t.Helper()
	local, err := enabledLocal(cfg)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	x := newFakeXFRM()
	b := &BlockPolicy{local: local, handle: x}
	if err := b.Install(context.Background()); err != nil {
		t.Fatalf("Install: %v", err)
	}
	return b, x
}

func TestBlockPolicyFailsClosed(t *testing.T) {
	_, x := installedBlockPolicy(t, validConfig())
	local, peer := addr(local4), addr(peer4)

	if got := action(x.lookup(netlink.XFRM_DIR_OUT, local, peer, unix.IPPROTO_UDP, 0)); got != "block" {
		t.Fatalf("outbound VXLAN with charon stopped: %s", got)
	}
	if got := action(x.lookup(netlink.XFRM_DIR_IN, peer, local, unix.IPPROTO_TCP, 0)); got != "block" {
		t.Fatalf("inbound BGP with charon stopped: %s", got)
	}
	if got := action(x.lookup(netlink.XFRM_DIR_OUT, addr("192.0.2.1"), peer, unix.IPPROTO_UDP, 0)); got != "none" {
		t.Fatalf("traffic from another address is governed: %s", got)
	}

	// A transport policy as charon installs it for a trapped peer, at its
	// lowest priority, takes precedence.
	host := func(a netip.Addr) *net.IPNet { return &net.IPNet{IP: a.AsSlice(), Mask: net.CIDRMask(32, 32)} }
	charon := &netlink.XfrmPolicy{Src: host(local), Dst: host(peer), Dir: netlink.XFRM_DIR_OUT, Priority: 400000,
		Tmpls: []netlink.XfrmPolicyTmpl{{Proto: netlink.XFRM_PROTO_ESP, Mode: netlink.XFRM_MODE_TRANSPORT}}}
	if err := x.XfrmPolicyUpdate(charon); err != nil {
		t.Fatalf("charon policy: %v", err)
	}
	if got := x.lookup(netlink.XFRM_DIR_OUT, local, peer, unix.IPPROTO_UDP, 0); got != charon {
		t.Fatalf("charon's policy lost to %s", action(got))
	}
}

func TestBlockPolicyIPv6(t *testing.T) {
	cfg := validConfig()
	cfg.LocalAddress = "fd00:20::11"
	cfg.StaticPeers = []string{"fd00:20::1"}
	_, x := installedBlockPolicy(t, cfg)
	local, peer := addr("fd00:20::11"), addr("fd00:20::30")

	for _, tt := range []struct {
		name     string
		dir      netlink.Dir
		src, dst netip.Addr
		proto    uint8
		icmpType int
		want     string
	}{
		{"neighbour solicitation out", netlink.XFRM_DIR_OUT, local, addr("ff02::1:ff00:30"), unix.IPPROTO_ICMPV6, 135, "allow"},
		{"neighbour advertisement in", netlink.XFRM_DIR_IN, peer, local, unix.IPPROTO_ICMPV6, 136, "allow"},
		{"router solicitation out", netlink.XFRM_DIR_OUT, local, addr("ff02::2"), unix.IPPROTO_ICMPV6, 133, "allow"},
		{"redirect in", netlink.XFRM_DIR_IN, peer, local, unix.IPPROTO_ICMPV6, 137, "allow"},
		{"echo request in", netlink.XFRM_DIR_IN, peer, local, unix.IPPROTO_ICMPV6, 128, "block"},
		{"VXLAN out", netlink.XFRM_DIR_OUT, local, peer, unix.IPPROTO_UDP, 0, "block"},
		{"BGP in", netlink.XFRM_DIR_IN, peer, local, unix.IPPROTO_TCP, 0, "block"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := action(x.lookup(tt.dir, tt.src, tt.dst, tt.proto, tt.icmpType)); got != tt.want {
				t.Fatalf("policy = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestBlockPolicyInstallIsIdempotent(t *testing.T) {
	b, x := installedBlockPolicy(t, validConfig())
	if err := b.Install(context.Background()); err != nil {
		t.Fatalf("second Install: %v", err)
	}
	if len(x.spd) != 2 {
		t.Fatalf("SPD holds %d policies after a second Install, want 2", len(x.spd))
	}
}

func TestBlockPolicyInstallFailures(t *testing.T) {
	local := addr(local4)
	x := newFakeXFRM()
	b := &BlockPolicy{local: local, handle: x}

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
	if x.updates != 0 {
		t.Fatalf("a cancelled Install wrote %d policies", x.updates)
	}
}

func TestBlockPolicyRemove(t *testing.T) {
	ctx := context.Background()
	cfg := validConfig()
	cfg.LocalAddress = "fd00:20::11"
	cfg.StaticPeers = []string{"fd00:20::1"}
	b, x := installedBlockPolicy(t, cfg)

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
	if len(x.spd) != 2 {
		t.Fatalf("SPD holds %d policies, want only the two blocks left", len(x.spd))
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

	// Opening the netlink socket needs no privilege; nothing is written.
	b, err := NewBlockPolicy(validConfig(), netns.None())
	if err != nil {
		t.Fatalf("NewBlockPolicy: %v", err)
	}
	b.Close()
}
