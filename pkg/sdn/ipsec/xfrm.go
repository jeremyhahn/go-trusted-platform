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
// link ICMPv6 (linkICMPv6) is exempt.
type BlockPolicy struct {
	local  netip.Addr
	iface  string
	slaac  bool
	handle xfrmHandle

	// ifindex is the fabric interface the forward block was installed
	// for, so Remove deletes the same selector after the link is gone.
	ifindex int
}

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
	return &BlockPolicy{local: local, iface: cfg.FabricInterface, slaac: cfg.UnderlaySLAAC, handle: h}, nil
}

// Install writes the policies. Each one replaces any policy with the same
// selector and direction, so Install is idempotent. Exemptions go in
// before the blocks they exempt from. The fabric interface must exist: the
// forward block is bound to it.
func (b *BlockPolicy) Install(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return &OpError{Op: "xfrm install", Err: err}
	}
	link, err := b.handle.LinkByName(b.iface)
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

// Remove deletes the policies, blocks first. A policy that is already
// gone is not an error, and a failure does not stop the rest from being
// removed. The forward block is removed for the interface Install bound it
// to, or, when this BlockPolicy installed nothing, for the fabric
// interface as it is now; with neither, there is no forward block to find.
func (b *BlockPolicy) Remove(ctx context.Context) error {
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
	return nil
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
	all := &net.IPNet{IP: make(net.IP, bits/8), Mask: net.CIDRMask(0, bits)}

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
		// The kernel checks a forwarded packet against the FWD direction with
		// the output interface as the flow's oif, which is what Ifindex
		// selects: this blocks routing anything out of the fabric that no SA
		// carries.
		out = append(out, &netlink.XfrmPolicy{Src: all, Dst: all, Dir: netlink.XFRM_DIR_FWD, Ifindex: b.ifindex,
			Priority: blockPriority, Action: netlink.XFRM_POLICY_BLOCK})
	}
	return out
}
