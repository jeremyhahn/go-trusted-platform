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
	// ndPriority puts the neighbour-discovery exemptions just above the
	// block policies.
	ndPriority = blockPriority - 1
)

// xfrmHandle is the slice of *netlink.Handle the block policy uses, so
// tests can substitute a fake.
type xfrmHandle interface {
	XfrmPolicyUpdate(p *netlink.XfrmPolicy) error
	XfrmPolicyDel(p *netlink.XfrmPolicy) error
	Close()
}

// BlockPolicy is the XFRM half of the fail-closed floor: kernel policies
// that block every packet from or to the local fabric address. They sit
// below every policy charon installs, so a packet passes only when one of
// charon's policies sends it through an SA, and charon's policies exist
// only while charon runs. charon's IKE sockets carry their own bypass
// policies, which the kernel consults first. On an IPv6 underlay,
// neighbour discovery is exempt.
type BlockPolicy struct {
	local  netip.Addr
	handle xfrmHandle
}

// NewBlockPolicy opens a netlink XFRM connection in network namespace ns
// (netns.None() is the current one) for an enabled configuration.
// Installing policies needs CAP_NET_ADMIN.
func NewBlockPolicy(cfg *Config, ns netns.NsHandle) (*BlockPolicy, error) {
	local, err := enabledLocal(cfg)
	if err != nil {
		return nil, err
	}
	h, err := netlink.NewHandleAt(ns, unix.NETLINK_XFRM)
	if err != nil {
		return nil, &OpError{Op: "xfrm connect", Err: err}
	}
	return &BlockPolicy{local: local, handle: h}, nil
}

// Install writes the policies. Each one replaces any policy with the same
// selector and direction, so Install is idempotent. Exemptions go in
// before the blocks they exempt from.
func (b *BlockPolicy) Install(ctx context.Context) error {
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
// removed.
func (b *BlockPolicy) Remove(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return &OpError{Op: "xfrm remove", Err: err}
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
		for typ := icmpv6NDLow; typ <= icmpv6NDHigh; typ++ {
			out = append(out,
				&netlink.XfrmPolicy{Src: local, Dst: all, Dir: netlink.XFRM_DIR_OUT, Proto: unix.IPPROTO_ICMPV6,
					SrcPort: typ, Priority: ndPriority, Action: netlink.XFRM_POLICY_ALLOW},
				&netlink.XfrmPolicy{Src: all, Dst: local, Dir: netlink.XFRM_DIR_IN, Proto: unix.IPPROTO_ICMPV6,
					SrcPort: typ, Priority: ndPriority, Action: netlink.XFRM_POLICY_ALLOW},
			)
		}
	}
	return append(out,
		&netlink.XfrmPolicy{Src: local, Dst: all, Dir: netlink.XFRM_DIR_OUT,
			Priority: blockPriority, Action: netlink.XFRM_POLICY_BLOCK},
		&netlink.XfrmPolicy{Src: all, Dst: local, Dir: netlink.XFRM_DIR_IN,
			Priority: blockPriority, Action: netlink.XFRM_POLICY_BLOCK},
	)
}
