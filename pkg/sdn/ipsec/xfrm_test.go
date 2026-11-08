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
	"sync"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipsec/config"
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

func testBlockPolicy(t *testing.T, cfg *config.Config) (*BlockPolicy, *fakeXFRM) {
	t.Helper()
	local, err := config.EnabledLocal(cfg)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	x := newFakeXFRM()
	return &BlockPolicy{local: local, iface: cfg.FabricInterface, slaac: cfg.UnderlaySLAAC, handle: x}, x
}

func installedBlockPolicy(t *testing.T, cfg *config.Config) (*BlockPolicy, *fakeXFRM) {
	t.Helper()
	b, x := testBlockPolicy(t, cfg)
	if err := b.Install(context.Background()); err != nil {
		t.Fatalf("Install: %v", err)
	}
	return b, x
}

func ipv6Config() *config.Config {
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

// TestBlockPolicyLeavesNoCleartextPath runs every flow the floor must stop
// against the block policies alone: VXLAN and BGP to and from the node and
// routed through it into the fabric, and ESP routed into the fabric, which
// is another host's tunnel. What is routed out of the fabric elsewhere is
// the nftables filter's (TestFilterFailsClosed).
func TestBlockPolicyLeavesNoCleartextPath(t *testing.T) {
	_, x := installedBlockPolicy(t, validConfig())
	local, peer, beyond := addr(local4), addr(peer4), addr("10.30.0.5")
	out, in, fwd := netlink.XFRM_DIR_OUT, netlink.XFRM_DIR_IN, netlink.XFRM_DIR_FWD
	udp, tcp, esp := uint8(unix.IPPROTO_UDP), uint8(unix.IPPROTO_TCP), uint8(unix.IPPROTO_ESP)

	for _, tt := range []struct {
		name string
		f    flow
	}{
		{"VXLAN from the node", flow{dir: out, src: local, dst: peer, proto: udp}},
		{"VXLAN to the node", flow{dir: in, src: peer, dst: local, proto: udp}},
		{"VXLAN routed into the fabric", flow{dir: fwd, src: beyond, dst: peer, proto: udp, oif: fabricIndex}},
		{"BGP from the node", flow{dir: out, src: local, dst: peer, proto: tcp}},
		{"BGP to the node", flow{dir: in, src: peer, dst: local, proto: tcp}},
		{"BGP routed into the fabric", flow{dir: fwd, src: beyond, dst: peer, proto: tcp, oif: fabricIndex}},
		{"ESP routed into the fabric", flow{dir: fwd, src: beyond, dst: peer, proto: esp, oif: fabricIndex}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := action(x.lookup(tt.f)); got != "block" {
				t.Fatalf("policy = %s, want block", got)
			}
		})
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

// linkSub is a link subscription the test drives. ch closes when the
// subscriber stops or the test ends the subscription, as netlink's does.
type linkSub struct {
	ch   chan<- netlink.LinkUpdate
	once sync.Once
}

func (s *linkSub) end() { s.once.Do(func() { close(s.ch) }) }

// send hands Watch u and returns once Watch has handled it: Watch receives
// the update that follows only after it handles u.
func (s *linkSub) send(u netlink.LinkUpdate) {
	s.ch <- u
	s.ch <- otherLinkUpdate
}

// otherLinkUpdate is a change to a link that is not the fabric interface.
var otherLinkUpdate = netlink.LinkUpdate{Link: &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "lo", Index: 1}}}

// fabricUpdate is the update the kernel sends when the fabric interface
// changes.
func fabricUpdate(index int) netlink.LinkUpdate {
	return netlink.LinkUpdate{Link: &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "bond0", Index: index}}}
}

// watchRun is Watch running over a fake link subscription.
type watchRun struct {
	*linkSub
	cancel context.CancelFunc
	// result waits for Watch to return and returns its error.
	result func() error
}

// stop ends Watch and returns its error. The test may read the policy
// database again after it.
func (w *watchRun) stop() error {
	w.cancel()
	return w.result()
}

// watching runs Watch on b over a fake link subscription, and returns once
// Watch has made its first move.
func watching(t *testing.T, b *BlockPolicy) *watchRun {
	t.Helper()
	subs := make(chan *linkSub, 1)
	b.subscribe = func(ch chan<- netlink.LinkUpdate, done <-chan struct{}) error {
		s := &linkSub{ch: ch}
		go func() {
			<-done
			s.end()
		}()
		subs <- s
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- b.Watch(ctx) }()
	w := &watchRun{cancel: cancel, result: sync.OnceValue(func() error { return <-errc })}
	t.Cleanup(func() {
		if err := w.stop(); err != nil {
			t.Logf("Watch: %v", err)
		}
	})
	select {
	case w.linkSub = <-subs:
	case err := <-errc:
		t.Fatalf("Watch returned before subscribing: %v", err)
	}
	// Watch receives an update only after its first move.
	w.ch <- otherLinkUpdate
	return w
}

// routedInto is a packet routed into the fabric when its interface has the
// given index.
func routedInto(index int) flow {
	return flow{dir: netlink.XFRM_DIR_FWD, src: addr("10.30.0.5"), dst: addr(peer4), proto: unix.IPPROTO_UDP, oif: index}
}

func TestBlockPolicyWatchFollowsTheFabricInterface(t *testing.T) {
	b, x := installedBlockPolicy(t, validConfig())
	w := watching(t, b)

	// The interface is deleted: the block stays on the old index.
	delete(x.links, "bond0")
	w.send(fabricUpdate(fabricIndex))
	// Another interface changes: nothing moves.
	x.links["eth1"] = 9
	w.send(netlink.LinkUpdate{Link: &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth1", Index: 9}}})
	// The interface is created again under a new index.
	x.links["bond0"] = 8
	w.send(fabricUpdate(8))
	if err := w.stop(); err != nil {
		t.Fatalf("Watch: %v", err)
	}

	for _, tt := range []struct {
		name  string
		index int
		want  string
	}{
		{"out of the re-created interface", 8, "block"},
		{"out of the deleted interface's index", fabricIndex, "none"},
		{"out of the other interface", 9, "none"},
	} {
		if got := action(x.lookup(routedInto(tt.index))); got != tt.want {
			t.Errorf("routed %s: policy = %s, want %s", tt.name, got, tt.want)
		}
	}
	if len(x.spd) != 3 {
		t.Fatalf("SPD holds %d policies, want 3", len(x.spd))
	}

	// Remove deletes the block for the index Watch moved it to.
	if err := b.Remove(context.Background()); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if len(x.spd) != 0 {
		t.Fatalf("SPD still holds %d policies", len(x.spd))
	}
}

func TestBlockPolicyWatchCatchesUpWhenItStarts(t *testing.T) {
	b, x := installedBlockPolicy(t, validConfig())
	// The interface was re-created while nothing watched it.
	x.links["bond0"] = 8
	if err := watching(t, b).stop(); err != nil {
		t.Fatalf("Watch: %v", err)
	}
	if got := action(x.lookup(routedInto(8))); got != "block" {
		t.Fatalf("routed out of the re-created interface: policy = %s, want block", got)
	}
	if got := action(x.lookup(routedInto(fabricIndex))); got != "none" {
		t.Fatalf("routed out of the old index: policy = %s, want none", got)
	}
}

func TestBlockPolicyWatchInstallsNothingWithoutAFloor(t *testing.T) {
	b, x := testBlockPolicy(t, validConfig())
	w := watching(t, b)
	w.send(fabricUpdate(fabricIndex))
	if err := w.stop(); err != nil {
		t.Fatalf("Watch before Install: %v", err)
	}
	if len(x.spd) != 0 {
		t.Fatalf("Watch before Install wrote %d policies", len(x.spd))
	}

	b, x = installedBlockPolicy(t, validConfig())
	if err := b.Remove(context.Background()); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	w = watching(t, b)
	x.links["bond0"] = 8
	w.send(fabricUpdate(8))
	if err := w.stop(); err != nil {
		t.Fatalf("Watch after Remove: %v", err)
	}
	if len(x.spd) != 0 || x.updates != 3 {
		t.Fatalf("Watch wrote policies with no floor installed: SPD holds %d, %d writes", len(x.spd), x.updates)
	}
}

func TestBlockPolicyWatchFailures(t *testing.T) {
	var opErr *OpError

	t.Run("subscription refused", func(t *testing.T) {
		b, _ := installedBlockPolicy(t, validConfig())
		b.subscribe = func(chan<- netlink.LinkUpdate, <-chan struct{}) error { return errInjected }
		if err := b.Watch(context.Background()); !errors.As(err, &opErr) || !errors.Is(err, errInjected) {
			t.Fatalf("err = %v, want the subscription error", err)
		}
	})
	t.Run("subscription ended", func(t *testing.T) {
		b, _ := installedBlockPolicy(t, validConfig())
		w := watching(t, b)
		w.end()
		if err := w.result(); !errors.As(err, &opErr) || !errors.Is(err, ErrLinkWatchEnded) {
			t.Fatalf("err = %v, want ErrLinkWatchEnded", err)
		}
	})
	t.Run("new block refused", func(t *testing.T) {
		b, x := installedBlockPolicy(t, validConfig())
		w := watching(t, b)
		x.updateErr = errInjected
		x.links["bond0"] = 8
		// Watch returns on this update, so it gets no update after it.
		w.ch <- fabricUpdate(8)
		if err := w.result(); !errors.As(err, &opErr) || !errors.Is(err, errInjected) {
			t.Fatalf("err = %v, want the kernel error", err)
		}
		// The old block stays, and a later Watch retries the move.
		if got := action(x.lookup(routedInto(fabricIndex))); got != "block" {
			t.Fatalf("old block: policy = %s, want block", got)
		}
		x.updateErr = nil
		if err := watching(t, b).stop(); err != nil {
			t.Fatalf("second Watch: %v", err)
		}
		if got := action(x.lookup(routedInto(8))); got != "block" {
			t.Fatalf("routed out of the re-created interface: policy = %s, want block", got)
		}
	})
	t.Run("old block not deleted", func(t *testing.T) {
		b, x := installedBlockPolicy(t, validConfig())
		w := watching(t, b)
		x.delErr = errInjected
		x.links["bond0"] = 8
		// Watch returns on this update, so it gets no update after it.
		w.ch <- fabricUpdate(8)
		if err := w.result(); !errors.As(err, &opErr) || !errors.Is(err, errInjected) {
			t.Fatalf("err = %v, want the kernel error", err)
		}
		// The new block went in first, so the floor never had a gap.
		if got := action(x.lookup(routedInto(8))); got != "block" {
			t.Fatalf("routed out of the re-created interface: policy = %s, want block", got)
		}
	})
}

func TestNewBlockPolicy(t *testing.T) {
	invalid := validConfig()
	invalid.FabricInterface = ""
	for _, tt := range []struct {
		name string
		cfg  *config.Config
		want error
	}{
		{"absent", nil, config.ErrNotEnabled},
		{"disabled", &config.Config{}, config.ErrNotEnabled},
		{"invalid", invalid, config.ErrRequired},
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

	// The link subscription needs no privilege either, and closes its
	// channel once the subscriber stops.
	updates := make(chan netlink.LinkUpdate)
	done := make(chan struct{})
	if err := b.subscribe(updates, done); err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	close(done)
	for range updates {
	}
}
