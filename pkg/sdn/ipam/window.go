// Copyright (c) 2025 Jeremy Hahn. All rights reserved.
// Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package ipam

import (
	"crypto/rand"
	"math/big"
	"net/netip"
)

// This file holds the allocation-window rules every backend shares: which
// addresses of a pool are reserved (never allocatable), and which form the
// dynamic window Allocate draws from. Offsets are positions from the
// network address (see IPToOffset).

// gatewayPrefix returns the pool gateway as a single-address prefix, or an
// invalid prefix when the pool has no gateway.
func (p *Pool) gatewayPrefix() netip.Prefix {
	if !p.Gateway.IsValid() {
		return netip.Prefix{}
	}
	return netip.PrefixFrom(p.Gateway, p.Gateway.BitLen())
}

// reservedPrefixes returns the pool's reserved prefixes plus the gateway,
// with every prefix nested inside another removed. CIDR prefixes either
// nest or are disjoint, so the result holds disjoint prefixes.
func (p *Pool) reservedPrefixes() []netip.Prefix {
	all := make([]netip.Prefix, 0, len(p.Reserved)+1)
	for _, r := range p.Reserved {
		if r.IsValid() {
			all = append(all, r.Masked())
		}
	}
	if gw := p.gatewayPrefix(); gw.IsValid() {
		all = append(all, gw)
	}
	out := make([]netip.Prefix, 0, len(all))
	for i, a := range all {
		nested := false
		for j, b := range all {
			if i == j {
				continue
			}
			// a is dropped when b strictly contains it, or when they are
			// equal and b comes first.
			if b.Bits() <= a.Bits() && b.Contains(a.Addr()) && (b.Bits() < a.Bits() || j < i) {
				nested = true
				break
			}
		}
		if !nested {
			out = append(out, a)
		}
	}
	return out
}

// reservedPrefixFor returns the reserved prefix (or gateway) that holds ip.
func (p *Pool) reservedPrefixFor(ip netip.Addr) (netip.Prefix, bool) {
	if !ip.IsValid() {
		return netip.Prefix{}, false
	}
	ip = ip.Unmap()
	if p.Gateway.IsValid() && ip == p.Gateway.Unmap() {
		return p.gatewayPrefix(), true
	}
	for _, r := range p.Reserved {
		if r.IsValid() && r.Contains(ip) {
			return r.Masked(), true
		}
	}
	return netip.Prefix{}, false
}

// IsReserved reports whether ip is never allocatable in this pool: the
// gateway, or an address inside one of the Reserved prefixes.
func (p *Pool) IsReserved(ip netip.Addr) bool {
	_, ok := p.reservedPrefixFor(ip)
	return ok
}

// HasDynamicRange reports whether the pool bounds dynamic allocation with
// RangeStart and RangeEnd.
func (p *Pool) HasDynamicRange() bool {
	return p.RangeStart.IsValid() && p.RangeEnd.IsValid()
}

// InDynamicRange reports whether ip lies in the dynamic window. Without a
// range the whole CIDR is the window.
func (p *Pool) InDynamicRange(ip netip.Addr) bool {
	if !p.HasDynamicRange() {
		return ContainsIP(p.CIDR, ip)
	}
	return ip.Compare(p.RangeStart) >= 0 && ip.Compare(p.RangeEnd) <= 0
}

// CheckSpecific checks that ip may be taken by AllocateSpecific: it lies in
// the CIDR, is neither the network nor the broadcast address, and is not
// reserved. A static address outside the dynamic window is allowed.
func (p *Pool) CheckSpecific(ip netip.Addr) error {
	if !ip.IsValid() {
		return ErrInvalidIP
	}
	if !ContainsIP(p.CIDR, ip) {
		return ErrIPNotInPool
	}
	if IsNetworkAddress(p.CIDR, ip) {
		return ErrNetworkAddress
	}
	if IsBroadcastAddress(p.CIDR, ip) {
		return ErrBroadcastAddress
	}
	if r, ok := p.reservedPrefixFor(ip); ok {
		return &ErrIPReserved{IP: ip, PoolID: p.ID, Reserved: r}
	}
	return nil
}

// usableOffsets returns the first and last usable offsets of the CIDR. ok is
// false when the CIDR has no usable address.
func usableOffsets(cidr netip.Prefix) (first, last uint64, ok bool) {
	size := CalculatePoolSize(cidr)
	if size == 0 {
		return 0, 0, false
	}
	if cidr.Addr().Is4() && cidr.Bits() < 31 {
		return 1, size, true
	}
	return 0, size - 1, true
}

// DynamicOffsets returns the offset window Allocate draws from: the usable
// CIDR, narrowed to [RangeStart, RangeEnd] when the pool sets a range. ok is
// false when the window is empty.
func (p *Pool) DynamicOffsets() (first, last uint64, ok bool) {
	first, last, ok = usableOffsets(p.CIDR)
	if !ok || !p.HasDynamicRange() {
		return first, last, ok
	}
	start, err := IPToOffset(p.CIDR, p.RangeStart)
	if err != nil {
		return 0, 0, false
	}
	end, err := IPToOffset(p.CIDR, p.RangeEnd)
	if err != nil {
		return 0, 0, false
	}
	first = max(first, start)
	last = min(last, end)
	return first, last, first <= last
}

// NextDynamic finds the next address Allocate may hand out. nextFree is the
// backend's view of the allocation state: it returns the first offset at or
// after from that holds no allocation, and false when there is none. Reserved
// addresses are skipped a whole reserved prefix at a time, and the search
// never leaves the dynamic window. It returns ErrPoolExhausted when the
// window has no free, unreserved address.
func (p *Pool) NextDynamic(nextFree func(from uint64) (uint64, bool)) (netip.Addr, uint64, error) {
	first, last, ok := p.DynamicOffsets()
	if !ok {
		return netip.Addr{}, 0, ErrPoolExhausted
	}
	cur := first
	for cur <= last {
		off, found := nextFree(cur)
		if !found || off > last {
			return netip.Addr{}, 0, ErrPoolExhausted
		}
		ip, err := OffsetToIP(p.CIDR, off)
		if err != nil {
			return netip.Addr{}, 0, err
		}
		r, reserved := p.reservedPrefixFor(ip)
		if !reserved {
			return ip, off, nil
		}
		end, err := IPToOffset(p.CIDR, lastAddrOf(r))
		if err != nil || end >= last {
			return netip.Addr{}, 0, ErrPoolExhausted
		}
		cur = end + 1
	}
	return netip.Addr{}, 0, ErrPoolExhausted
}

// RandomDynamic returns a random address inside the dynamic window, or
// ErrIPReserved when the draw lands on a reserved address (the caller
// draws again). It serves backends that spread allocations randomly.
func (p *Pool) RandomDynamic() (netip.Addr, error) {
	first, last, ok := p.DynamicOffsets()
	if !ok {
		return netip.Addr{}, ErrPoolExhausted
	}
	span := new(big.Int).SetUint64(last - first)
	span.Add(span, big.NewInt(1))
	n, err := rand.Int(rand.Reader, span)
	if err != nil {
		return netip.Addr{}, err
	}
	ip, err := OffsetToIP(p.CIDR, first+n.Uint64())
	if err != nil {
		return netip.Addr{}, err
	}
	if r, reserved := p.reservedPrefixFor(ip); reserved {
		return netip.Addr{}, &ErrIPReserved{IP: ip, PoolID: p.ID, Reserved: r}
	}
	return ip, nil
}

// AllocatableIPs returns how many addresses of the pool can ever be
// allocated: the usable addresses of the CIDR less the reserved ones. It
// saturates at the maximum uint64 for very large IPv6 pools.
func (p *Pool) AllocatableIPs() uint64 {
	total := CalculatePoolSize(p.CIDR)
	if total == ^uint64(0) {
		return total
	}
	var reserved uint64
	for _, r := range p.reservedPrefixes() {
		reserved += usableInside(p.CIDR, r)
	}
	if reserved >= total {
		return 0
	}
	return total - reserved
}

// usableInside counts the usable addresses of cidr inside r.
func usableInside(cidr, r netip.Prefix) uint64 {
	if !cidr.Contains(r.Addr()) || r.Bits() < cidr.Bits() {
		return 0
	}
	hostBits := r.Addr().BitLen() - r.Bits()
	if hostBits >= 64 {
		return ^uint64(0)
	}
	n := uint64(1) << hostBits
	if cidr.Addr().Is4() && cidr.Bits() < 31 {
		if r.Contains(cidr.Masked().Addr()) {
			n--
		}
		if r.Contains(GetBroadcastAddress(cidr)) {
			n--
		}
	}
	return n
}

// lastAddrOf returns the last address of prefix r.
func lastAddrOf(r netip.Prefix) netip.Addr {
	r = r.Masked()
	b := r.Addr().AsSlice()
	for i := range b {
		bitStart := i * 8
		switch {
		case bitStart >= r.Bits():
			b[i] = 0xff
		case bitStart+8 > r.Bits():
			b[i] |= byte(0xff >> (r.Bits() - bitStart))
		}
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// validateWindow checks the pool's reserved prefixes and dynamic range
// against its CIDR.
func (p *Pool) validateWindow() error {
	for _, r := range p.Reserved {
		if !r.IsValid() || r.Addr().Is4() != p.CIDR.Addr().Is4() ||
			r.Bits() < p.CIDR.Bits() || !p.CIDR.Contains(r.Addr()) {
			return &ErrInvalidWindow{PoolID: p.ID, Reason: "reserved prefix " + r.String() + " is not inside " + p.CIDR.String()}
		}
	}
	if p.RangeStart.IsValid() != p.RangeEnd.IsValid() {
		return &ErrInvalidWindow{PoolID: p.ID, Reason: "range_start and range_end must be set together"}
	}
	if !p.HasDynamicRange() {
		return nil
	}
	if !ContainsIP(p.CIDR, p.RangeStart) || !ContainsIP(p.CIDR, p.RangeEnd) {
		return &ErrInvalidWindow{PoolID: p.ID, Reason: "range " + p.RangeStart.String() + "-" + p.RangeEnd.String() + " is not inside " + p.CIDR.String()}
	}
	if p.RangeStart.Compare(p.RangeEnd) > 0 {
		return &ErrInvalidWindow{PoolID: p.ID, Reason: "range_start " + p.RangeStart.String() + " is after range_end " + p.RangeEnd.String()}
	}
	return nil
}

// ParseWindow parses the wire form of a pool's allocation window: reserved
// prefixes in CIDR notation and the dynamic range bounds. Empty bounds parse
// to invalid addresses (no range). Every transport converts through it so
// they reject the same input the same way.
func ParseWindow(reserved []string, rangeStart, rangeEnd string) ([]netip.Prefix, netip.Addr, netip.Addr, error) {
	var prefixes []netip.Prefix
	for _, r := range reserved {
		p, err := netip.ParsePrefix(r)
		if err != nil {
			return nil, netip.Addr{}, netip.Addr{}, &ErrInvalidWindow{Reason: "reserved " + r + " is not a prefix"}
		}
		prefixes = append(prefixes, p.Masked())
	}
	start, err := parseOptionalAddr(rangeStart)
	if err != nil {
		return nil, netip.Addr{}, netip.Addr{}, &ErrInvalidWindow{Reason: "range_start " + rangeStart + " is not an address"}
	}
	end, err := parseOptionalAddr(rangeEnd)
	if err != nil {
		return nil, netip.Addr{}, netip.Addr{}, &ErrInvalidWindow{Reason: "range_end " + rangeEnd + " is not an address"}
	}
	return prefixes, start, end, nil
}

// parseOptionalAddr parses s, treating the empty string as no address.
func parseOptionalAddr(s string) (netip.Addr, error) {
	if s == "" {
		return netip.Addr{}, nil
	}
	return netip.ParseAddr(s)
}

// ReservedStrings returns the reserved prefixes in CIDR notation.
func (p *Pool) ReservedStrings() []string {
	if len(p.Reserved) == 0 {
		return nil
	}
	out := make([]string, len(p.Reserved))
	for i, r := range p.Reserved {
		out[i] = r.String()
	}
	return out
}

// AddrString returns a's text form, or "" for an invalid address.
func AddrString(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

// ApplyWindowUpdate applies a partial update of the allocation window to p:
// a non-nil argument replaces the pool's value (an empty list or "" clears
// it), a nil one keeps it. It serves the transports whose update requests
// carry only the fields the caller set.
func (p *Pool) ApplyWindowUpdate(reserved []string, rangeStart, rangeEnd *string) error {
	if reserved == nil && rangeStart == nil && rangeEnd == nil {
		return nil
	}
	if reserved == nil {
		reserved = p.ReservedStrings()
	}
	start := AddrString(p.RangeStart)
	if rangeStart != nil {
		start = *rangeStart
	}
	end := AddrString(p.RangeEnd)
	if rangeEnd != nil {
		end = *rangeEnd
	}
	prefixes, s, e, err := ParseWindow(reserved, start, end)
	if err != nil {
		return err
	}
	p.Reserved = prefixes
	p.RangeStart = s
	p.RangeEnd = e
	return nil
}
