// Copyright (c) 2025 Jeremy Hahn. All rights reserved.
// Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package ipam

import (
	"net/netip"
)

// IsNetworkAddress returns true if the IP is the network address of the CIDR.
// Only applicable for IPv4 networks with prefix length < 31.
func IsNetworkAddress(cidr netip.Prefix, ip netip.Addr) bool {
	if !ip.Is4() {
		return false
	}
	if cidr.Bits() >= 31 {
		// Per RFC 3021, /31 networks don't have network/broadcast
		return false
	}
	return ip == cidr.Masked().Addr()
}

// IsBroadcastAddress returns true if the IP is the broadcast address of the CIDR.
// Only applicable for IPv4 networks with prefix length < 31.
func IsBroadcastAddress(cidr netip.Prefix, ip netip.Addr) bool {
	if !ip.Is4() {
		return false
	}
	if cidr.Bits() >= 31 {
		// Per RFC 3021, /31 networks don't have network/broadcast
		return false
	}
	return ip == GetBroadcastAddress(cidr)
}

// NextUsableIP returns the first usable IP address in a CIDR.
// For IPv4 with prefix < 31, this skips the network address.
func NextUsableIP(cidr netip.Prefix) (netip.Addr, error) {
	return GetFirstUsableIP(cidr)
}

// LastUsableIP returns the last usable IP address in a CIDR.
// For IPv4 with prefix < 31, this excludes the broadcast address.
func LastUsableIP(cidr netip.Prefix) (netip.Addr, error) {
	return GetLastUsableIP(cidr)
}

// CIDROverlaps checks if two CIDRs overlap.
func CIDROverlaps(a, b netip.Prefix) bool {
	// Two prefixes overlap if one contains the base address of the other
	return a.Overlaps(b)
}

// IsUsableOffset returns true if the offset corresponds to a usable IP address.
// For IPv4 with prefix < 31, offsets 0 (network) and last (broadcast) are not usable.
func IsUsableOffset(cidr netip.Prefix, offset uint64) bool {
	if cidr.Addr().Is4() && cidr.Bits() < 31 {
		hostBits := 32 - cidr.Bits()
		maxOffset := uint64(1<<hostBits) - 1
		// Offset 0 is network address, maxOffset is broadcast
		return offset > 0 && offset < maxOffset
	}
	// For IPv6 or /31+, all offsets are usable (within bounds)
	size := CalculatePoolSize(cidr)
	return offset < size
}

// AdjustOffsetForUsable converts a logical "usable IP index" to an actual offset.
// For IPv4 with prefix < 31, this adds 1 to skip the network address.
func AdjustOffsetForUsable(cidr netip.Prefix, usableIndex uint64) uint64 {
	if cidr.Addr().Is4() && cidr.Bits() < 31 {
		// Skip network address
		return usableIndex + 1
	}
	return usableIndex
}
