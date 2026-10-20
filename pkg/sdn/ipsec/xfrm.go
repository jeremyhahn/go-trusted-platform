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
	"slices"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const (
	// blockPriority puts the block policies below every policy charon
	// installs: in XFRM a larger number is a lower priority, and charon's
	// policies stay under a million.
	blockPriority = 1 << 30
	// linkPriority puts the link ICMPv6 exemptions just above the block
	// policies.
	linkPriority = blockPriority - 1
)

// xfrmHandle is the slice of *netlink.Handle the block policy uses, so
// tests can substitute a fake.
type xfrmHandle interface {
	XfrmPolicyUpdate(p *netlink.XfrmPolicy) error
	XfrmPolicyDel(p *netlink.XfrmPolicy) error
	LinkByName(name string) (netlink.Link, error)
	Close()
}

// BlockPolicy is the XFRM half of the fail-closed floor: kernel policies
// that block every packet from or to the local fabric address, and every
// packet the node forwards out of the fabric interface. They sit below
// every policy charon installs, so a packet passes only when one of
// charon's policies sends it through an SA, and charon's policies exist
// only while charon runs. charon's IKE sockets carry their own bypass
// policies, which the kernel consults first. On an IPv6 underlay, the
// link ICMPv6 (linkICMPv6) is exempt. Watch keeps the forward block on the
// fabric interface when the interface is created again.
type BlockPolicy struct {
	local     netip.Addr
	iface     string
	slaac     bool
	linkWait  time.Duration
	handle    xfrmHandle
	subscribe linkSubscriber

	// mu serializes Install, Remove and Watch's moves of the forward block.
	mu sync.Mutex
	// ifindex is the fabric interface the forward block is installed for,
	// so Remove deletes the same selector after the link is gone. It is
	// zero while no floor is installed.
	ifindex int
}

// linkSubscriber sends every link change in the policy's network namespace
// on ch until done closes, then closes ch. It closes ch early when the
// subscription fails.
type linkSubscriber func(ch chan<- netlink.LinkUpdate, done <-chan struct{}) error

// NewBlockPolicy opens a netlink XFRM and route connection in network
// namespace ns (netns.None() is the current one) for an enabled
// configuration. Installing policies needs CAP_NET_ADMIN.
func NewBlockPolicy(cfg *Config, ns netns.NsHandle) (*BlockPolicy, error) {
	local, err := enabledLocal(cfg)
	if err != nil {
		return nil, err
	}
	h, err := netlink.NewHandleAt(ns, unix.NETLINK_XFRM, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, &OpError{Op: "xfrm connect", Err: err}
	}
	subscribe := func(ch chan<- netlink.LinkUpdate, done <-chan struct{}) error {
		return netlink.LinkSubscribeWithOptions(ch, done, netlink.LinkSubscribeOptions{Namespace: &ns})
	}
	return &BlockPolicy{local: local, iface: cfg.FabricInterface, slaac: cfg.UnderlaySLAAC, linkWait: cfg.EffectiveFabricLinkWait(), handle: h, subscribe: subscribe}, nil
}

// Install writes the policies. Each one replaces any policy with the same
// selector and direction, so Install is idempotent. Exemptions go in
// before the blocks they exempt from. The fabric interface must exist: the
// forward block is bound to it.
func (b *BlockPolicy) Install(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return &OpError{Op: "xfrm install", Err: err}
	}
	link, err := b.waitForLink(ctx)
	if err != nil {
		return &OpError{Op: "xfrm install", Err: err}
	}
	b.ifindex = link.Attrs().Index
	for _, p := range b.policies() {
		if err := ctx.Err(); err != nil {
			return &OpError{Op: "xfrm install", Err: err}
		}
		if err := b.handle.XfrmPolicyUpdate(p); err != nil {
			return &OpError{Op: "xfrm install", Err: err}
		}
	}
	return nil
}

func (b *BlockPolicy) waitForLink(ctx context.Context) (netlink.Link, error) {
	link, err := b.handle.LinkByName(b.iface)
	if err == nil {
		return link, nil
	}
	if !linkMissing(err) || b.linkWait <= 0 {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	updates := make(chan netlink.LinkUpdate)
	if err := b.subscribe(updates, ctx.Done()); err != nil {
		return nil, err
	}
	defer func() {
		cancel()
		for range updates {
		}
	}()
	timer := time.NewTimer(b.linkWait)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
			return nil, err
		case u, ok := <-updates:
			if !ok {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				return nil, ErrLinkWatchEnded
			}
			if u.Link == nil || u.Attrs().Name != b.iface {
				continue
			}
			link, retryErr := b.handle.LinkByName(b.iface)
			if retryErr == nil {
				return link, nil
			}
			if !linkMissing(retryErr) {
				return nil, retryErr
			}
			err = retryErr
		}
	}
}

// Remove deletes the policies, blocks first. A policy that is already
// gone is not an error, and a failure does not stop the rest from being
// removed. The forward block is removed for the interface it is installed
// for, or, when this BlockPolicy installed nothing, for the fabric
// interface as it is now; with neither, there is no forward block to find.
func (b *BlockPolicy) Remove(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return &OpError{Op: "xfrm remove", Err: err}
	}
	if b.ifindex == 0 {
		if link, err := b.handle.LinkByName(b.iface); err == nil {
			b.ifindex = link.Attrs().Index
		}
	}
	var errs []error
	for _, p := range slices.Backward(b.policies()) {
		if err := b.handle.XfrmPolicyDel(p); err != nil && !errors.Is(err, unix.ENOENT) {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return &OpError{Op: "xfrm remove", Err: errors.Join(errs...)}
	}
	b.ifindex = 0
	return nil
}

// Watch keeps the forward block on the fabric interface until ctx ends.
// The block selects the interface by index, and an interface that is
// deleted and created again, as a bond or VLAN rebuilt by the network
// configuration is, comes back under a new index. Watch subscribes to link
// changes, then moves the block to the interface's current index, and
// moves it again on every change to a link of the fabric interface's name.
// A move installs the new block before it deletes the old one, so the
// floor has no gap. While the interface is gone the block stays on the old
// index. Watch moves nothing while no floor is installed.
//
// Watch returns nil when ctx ends. It returns an error when the
// subscription fails or ends (ErrLinkWatchEnded) or a move fails; calling
// it again resubscribes, and its first move catches up on any change it
// missed.
func (b *BlockPolicy) Watch(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// Unbuffered: the subscription's socket buffer holds what arrives
	// during a move.
	updates := make(chan netlink.LinkUpdate)
	if err := b.subscribe(updates, ctx.Done()); err != nil {
		return &OpError{Op: "xfrm watch", Err: err}
	}
	defer func() {
		// Ending the subscription closes updates; draining it lets the
		// subscription get to the close.
		cancel()
		for range updates {
		}
	}()

	if err := b.rebind(); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case u, ok := <-updates:
			if !ok {
				// The subscription also ends when ctx does.
				if ctx.Err() != nil {
					return nil
				}
				return &OpError{Op: "xfrm watch", Err: ErrLinkWatchEnded}
			}
			if u.Link == nil || u.Attrs().Name != b.iface {
				continue
			}
			if err := b.rebind(); err != nil {
				return err
			}
		}
	}
}

// rebind moves the forward block to the fabric interface's current index.
// When the old block cannot be deleted it stays, on an index that is gone.
func (b *BlockPolicy) rebind() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ifindex == 0 {
		return nil
	}
	link, err := b.handle.LinkByName(b.iface)
	if linkMissing(err) {
		return nil
	}
	if err != nil {
		return &OpError{Op: "xfrm rebind", Err: err}
	}
	index := link.Attrs().Index
	if index == b.ifindex {
		return nil
	}
	if err := b.handle.XfrmPolicyUpdate(b.forwardBlock(index)); err != nil {
		return &OpError{Op: "xfrm rebind", Err: err}
	}
	old := b.ifindex
	b.ifindex = index
	if err := b.handle.XfrmPolicyDel(b.forwardBlock(old)); err != nil && !errors.Is(err, unix.ENOENT) {
		return &OpError{Op: "xfrm rebind", Err: err}
	}
	return nil
}

// linkMissing reports a lookup of an interface that does not exist.
// netlink reports it as LinkNotFoundError, the kernel as ENODEV.
func linkMissing(err error) bool {
	var notFound netlink.LinkNotFoundError
	return errors.As(err, &notFound) || errors.Is(err, unix.ENODEV)
}

// Close releases the netlink connection. Installed policies stay.
func (b *BlockPolicy) Close() {
	b.handle.Close()
}

// policies is the policy set in install order. Both selectors carry an
// explicit destination because the kernel takes a selector's address
// family from it.
func (b *BlockPolicy) policies() []*netlink.XfrmPolicy {
	bits := b.local.BitLen()
	local := &net.IPNet{IP: b.local.AsSlice(), Mask: net.CIDRMask(bits, bits)}
	all := b.everything()

	var out []*netlink.XfrmPolicy
	if b.local.Is6() {
		// An ICMPv6 selector matches the message type in its source port.
		for _, typ := range linkICMPv6(b.slaac) {
			out = append(out,
				&netlink.XfrmPolicy{Src: local, Dst: all, Dir: netlink.XFRM_DIR_OUT, Proto: unix.IPPROTO_ICMPV6,
					SrcPort: int(typ), Priority: linkPriority, Action: netlink.XFRM_POLICY_ALLOW},
				&netlink.XfrmPolicy{Src: all, Dst: local, Dir: netlink.XFRM_DIR_IN, Proto: unix.IPPROTO_ICMPV6,
					SrcPort: int(typ), Priority: linkPriority, Action: netlink.XFRM_POLICY_ALLOW},
			)
		}
	}
	out = append(out,
		&netlink.XfrmPolicy{Src: local, Dst: all, Dir: netlink.XFRM_DIR_OUT,
			Priority: blockPriority, Action: netlink.XFRM_POLICY_BLOCK},
		&netlink.XfrmPolicy{Src: all, Dst: local, Dir: netlink.XFRM_DIR_IN,
			Priority: blockPriority, Action: netlink.XFRM_POLICY_BLOCK},
	)
	if b.ifindex != 0 {
		out = append(out, b.forwardBlock(b.ifindex))
	}
	return out
}

// forwardBlock blocks routing anything out of interface index that no SA
// carries. The kernel checks a forwarded packet against the FWD direction
// with the output interface as the flow's oif, which is what Ifindex
// selects.
func (b *BlockPolicy) forwardBlock(index int) *netlink.XfrmPolicy {
	all := b.everything()
	return &netlink.XfrmPolicy{Src: all, Dst: all, Dir: netlink.XFRM_DIR_FWD, Ifindex: index,
		Priority: blockPriority, Action: netlink.XFRM_POLICY_BLOCK}
}

// everything is the selector address matching every address of the local
// address's family.
func (b *BlockPolicy) everything() *net.IPNet {
	bits := b.local.BitLen()
	return &net.IPNet{IP: make(net.IP, bits/8), Mask: net.CIDRMask(0, bits)}
}
