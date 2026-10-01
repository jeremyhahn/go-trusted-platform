// Copyright (c) 2025 Jeremy Hahn. All rights reserved.
// Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package ipam

import (
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"net/netip"
	"sync"
	"time"
)

const (
	// DefaultInactivityTimeout is the default time before an allocation is
	// considered inactive and eligible for expiration.
	DefaultInactivityTimeout = 30 * 24 * time.Hour // 30 days

	// DefaultLeaseDuration is the default lease duration for allocations.
	// Zero means allocations never expire.
	DefaultLeaseDuration = 0
)

// PoolManager handles pool operations and IP calculations.
// It is safe for concurrent use.
type PoolManager struct {
	mu sync.RWMutex
}

// NewPoolManager creates a new pool manager.
func NewPoolManager() *PoolManager {
	return &PoolManager{}
}

// ValidatePool validates pool configuration.
func (pm *PoolManager) ValidatePool(pool *Pool) error {
	if pool == nil {
		return ErrPoolNotFound
	}
	if pool.ID == "" {
		return ErrInvalidPoolID
	}
	if pool.Name == "" {
		return ErrInvalidPoolName
	}
	if !pool.CIDR.IsValid() {
		return ErrInvalidCIDR
	}

	// Validate gateway is within CIDR if specified
	if pool.Gateway.IsValid() {
		if !ContainsIP(pool.CIDR, pool.Gateway) {
			return ErrInvalidGateway
		}
	}

	return pool.validateWindow()
}

// InitializePool sets default values and calculates pool size.
func (pm *PoolManager) InitializePool(pool *Pool) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	now := time.Now()
	if pool.CreatedAt.IsZero() {
		pool.CreatedAt = now
	}
	pool.UpdatedAt = now

	if pool.InactivityTimeout == 0 {
		pool.InactivityTimeout = DefaultInactivityTimeout
	}

	pool.TotalIPs = pool.AllocatableIPs()
	pool.AvailableIPs = pool.TotalIPs
	pool.AllocatedIPs = 0
}

// CalculatePoolSize returns the number of usable IPs in a CIDR.
// For IPv4, this excludes network and broadcast addresses (size - 2) for /30 and larger.
// For IPv6, all addresses are usable.
func CalculatePoolSize(cidr netip.Prefix) uint64 {
	if !cidr.IsValid() {
		return 0
	}

	bits := cidr.Bits()
	var totalBits int
	if cidr.Addr().Is4() {
		totalBits = 32
	} else {
		totalBits = 128
	}

	hostBits := totalBits - bits

	// Handle edge cases
	if hostBits == 0 {
		return 1 // Single host (/32 or /128)
	}
	if hostBits == 1 {
		return 2 // Point-to-point link (/31 or /127)
	}

	// Calculate total addresses
	if hostBits >= 64 {
		// For very large prefixes, return max uint64
		// This handles /0 through /64 for IPv6
		return ^uint64(0)
	}

	total := uint64(1) << hostBits

	// For IPv4, subtract network and broadcast addresses
	if cidr.Addr().Is4() && hostBits >= 2 {
		return total - 2
	}

	return total
}

// IPToOffset converts an IP to its offset within a CIDR.
// The offset represents the position of the IP within the network range.
func IPToOffset(cidr netip.Prefix, ip netip.Addr) (uint64, error) {
	if !cidr.IsValid() {
		return 0, ErrInvalidCIDR
	}
	if !ip.IsValid() {
		return 0, ErrInvalidIP
	}

	// Check address family match
	if cidr.Addr().Is4() != ip.Is4() {
		return 0, &ErrCIDRMismatch{IP: ip, CIDR: cidr}
	}

	// Check if IP is in CIDR
	if !ContainsIP(cidr, ip) {
		return 0, ErrIPNotInPool
	}

	// Get network base address
	network := cidr.Masked().Addr()

	if ip.Is4() {
		// IPv4: simple subtraction
		ipBytes := ip.As4()
		netBytes := network.As4()

		ipVal := binary.BigEndian.Uint32(ipBytes[:])
		netVal := binary.BigEndian.Uint32(netBytes[:])

		return uint64(ipVal - netVal), nil
	}

	// IPv6: use big.Int for 128-bit arithmetic
	ipBytes := ip.As16()
	netBytes := network.As16()

	ipInt := new(big.Int).SetBytes(ipBytes[:])
	netInt := new(big.Int).SetBytes(netBytes[:])

	offset := new(big.Int).Sub(ipInt, netInt)

	// Check if offset fits in uint64
	if !offset.IsUint64() {
		return 0, ErrInvalidOffset
	}

	return offset.Uint64(), nil
}

// OffsetToIP converts an offset to an IP within a CIDR.
// The offset represents the position within the network range.
func OffsetToIP(cidr netip.Prefix, offset uint64) (netip.Addr, error) {
	if !cidr.IsValid() {
		return netip.Addr{}, ErrInvalidCIDR
	}

	// Get network base address
	network := cidr.Masked().Addr()

	if network.Is4() {
		// IPv4: simple addition
		netBytes := network.As4()
		netVal := binary.BigEndian.Uint32(netBytes[:])

		// Check for overflow
		if offset > uint64(^uint32(0)-netVal) {
			return netip.Addr{}, ErrInvalidOffset
		}

		ipVal := netVal + uint32(offset)
		var ipBytes [4]byte
		binary.BigEndian.PutUint32(ipBytes[:], ipVal)

		ip := netip.AddrFrom4(ipBytes)

		// Verify IP is within CIDR
		if !ContainsIP(cidr, ip) {
			return netip.Addr{}, ErrInvalidOffset
		}

		return ip, nil
	}

	// IPv6: use big.Int for 128-bit arithmetic
	netBytes := network.As16()
	netInt := new(big.Int).SetBytes(netBytes[:])

	offsetInt := new(big.Int).SetUint64(offset)
	ipInt := new(big.Int).Add(netInt, offsetInt)

	// Convert back to 16-byte array
	ipBytesSlice := ipInt.Bytes()
	if len(ipBytesSlice) > 16 {
		return netip.Addr{}, ErrInvalidOffset
	}

	var ipBytes [16]byte
	// Right-align the bytes
	copy(ipBytes[16-len(ipBytesSlice):], ipBytesSlice)

	ip := netip.AddrFrom16(ipBytes)

	// Verify IP is within CIDR
	if !ContainsIP(cidr, ip) {
		return netip.Addr{}, ErrInvalidOffset
	}

	return ip, nil
}

// ContainsIP checks if a CIDR contains an IP address.
func ContainsIP(cidr netip.Prefix, ip netip.Addr) bool {
	if !cidr.IsValid() || !ip.IsValid() {
		return false
	}
	// Check address family match
	if cidr.Addr().Is4() != ip.Is4() {
		return false
	}
	return cidr.Contains(ip)
}

// NextAvailableIP finds the next available IP using a bitmap.
// This is a helper function - actual allocation logic is in backends.
// It skips network and broadcast addresses for IPv4 networks.
func (pm *PoolManager) NextAvailableIP(cidr netip.Prefix, allocated map[netip.Addr]bool) (netip.Addr, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if !cidr.IsValid() {
		return netip.Addr{}, ErrInvalidCIDR
	}

	poolSize := CalculatePoolSize(cidr)
	if poolSize == 0 {
		return netip.Addr{}, ErrPoolExhausted
	}

	// Start offset at 1 to skip network address for IPv4
	startOffset := uint64(0)
	if cidr.Addr().Is4() && cidr.Bits() < 31 {
		startOffset = 1
	}

	// End offset excludes broadcast for IPv4
	endOffset := poolSize
	if cidr.Addr().Is4() && cidr.Bits() < 31 {
		endOffset = poolSize + 1 // +1 because poolSize already excludes network and broadcast
	}

	for offset := startOffset; offset <= endOffset; offset++ {
		ip, err := OffsetToIP(cidr, offset)
		if err != nil {
			continue
		}

		// Skip if network or broadcast
		if IsNetworkOrBroadcast(cidr, ip) {
			continue
		}

		// Check if allocated
		if !allocated[ip] {
			return ip, nil
		}
	}

	return netip.Addr{}, ErrPoolExhausted
}

// RandomIPInCIDR generates a random IP within a CIDR.
// This is useful for DHT-based backends to distribute allocations.
// It avoids network and broadcast addresses for IPv4.
func RandomIPInCIDR(cidr netip.Prefix) (netip.Addr, error) {
	if !cidr.IsValid() {
		return netip.Addr{}, ErrInvalidCIDR
	}

	poolSize := CalculatePoolSize(cidr)
	if poolSize == 0 {
		return netip.Addr{}, ErrPoolExhausted
	}

	// Generate random offset within usable range
	var maxOffset uint64
	var startOffset uint64

	if cidr.Addr().Is4() && cidr.Bits() < 31 {
		// Skip network address, exclude broadcast
		startOffset = 1
		maxOffset = poolSize // poolSize already excludes network and broadcast
	} else {
		startOffset = 0
		maxOffset = poolSize
	}

	// Generate random offset
	randBig, err := rand.Int(rand.Reader, big.NewInt(int64(maxOffset)))
	if err != nil {
		return netip.Addr{}, err
	}

	offset := startOffset + randBig.Uint64()

	ip, err := OffsetToIP(cidr, offset)
	if err != nil {
		return netip.Addr{}, err
	}

	return ip, nil
}

// IsNetworkOrBroadcast checks if an IP is the network or broadcast address.
// For IPv6, this always returns false as all addresses are usable.
func IsNetworkOrBroadcast(cidr netip.Prefix, ip netip.Addr) bool {
	if !cidr.IsValid() || !ip.IsValid() {
		return false
	}

	// IPv6 doesn't have network/broadcast addresses in the traditional sense
	if ip.Is6() {
		return false
	}

	// For /31 and /32, all addresses are usable (point-to-point links)
	if cidr.Bits() >= 31 {
		return false
	}

	// Get network and broadcast addresses
	network := cidr.Masked().Addr()

	// Calculate broadcast address
	netBytes := network.As4()
	hostBits := 32 - cidr.Bits()
	hostMask := uint32((1 << hostBits) - 1)

	netVal := binary.BigEndian.Uint32(netBytes[:])
	broadcastVal := netVal | hostMask

	var broadcastBytes [4]byte
	binary.BigEndian.PutUint32(broadcastBytes[:], broadcastVal)
	broadcast := netip.AddrFrom4(broadcastBytes)

	return ip == network || ip == broadcast
}

// GetNetworkAddress returns the network address for a CIDR.
func GetNetworkAddress(cidr netip.Prefix) netip.Addr {
	if !cidr.IsValid() {
		return netip.Addr{}
	}
	return cidr.Masked().Addr()
}

// GetBroadcastAddress returns the broadcast address for an IPv4 CIDR.
// For IPv6, it returns an invalid address as there's no broadcast.
func GetBroadcastAddress(cidr netip.Prefix) netip.Addr {
	if !cidr.IsValid() || cidr.Addr().Is6() {
		return netip.Addr{}
	}

	network := cidr.Masked().Addr()
	netBytes := network.As4()
	hostBits := 32 - cidr.Bits()
	hostMask := uint32((1 << hostBits) - 1)

	netVal := binary.BigEndian.Uint32(netBytes[:])
	broadcastVal := netVal | hostMask

	var broadcastBytes [4]byte
	binary.BigEndian.PutUint32(broadcastBytes[:], broadcastVal)

	return netip.AddrFrom4(broadcastBytes)
}

// GetFirstUsableIP returns the first usable IP address in a CIDR.
// For IPv4, this is the first address after the network address.
// For IPv6, this is the network address itself.
func GetFirstUsableIP(cidr netip.Prefix) (netip.Addr, error) {
	if !cidr.IsValid() {
		return netip.Addr{}, ErrInvalidCIDR
	}

	if cidr.Addr().Is6() || cidr.Bits() >= 31 {
		return cidr.Masked().Addr(), nil
	}

	// IPv4: skip network address
	return OffsetToIP(cidr, 1)
}

// GetLastUsableIP returns the last usable IP address in a CIDR.
// For IPv4, this is the address before the broadcast address.
// For IPv6, this is the last address in the range.
func GetLastUsableIP(cidr netip.Prefix) (netip.Addr, error) {
	if !cidr.IsValid() {
		return netip.Addr{}, ErrInvalidCIDR
	}

	poolSize := CalculatePoolSize(cidr)
	if poolSize == 0 {
		return netip.Addr{}, ErrPoolExhausted
	}

	if cidr.Addr().Is6() || cidr.Bits() >= 31 {
		// IPv6 or point-to-point: last offset is poolSize - 1
		return OffsetToIP(cidr, poolSize-1)
	}

	// IPv4: poolSize is already excluding network and broadcast
	// So last usable is at offset poolSize (1-indexed from network)
	return OffsetToIP(cidr, poolSize)
}

// SplitCIDR splits a CIDR into two equal halves.
// Returns an error if the CIDR cannot be split (e.g., /32 or /128).
func SplitCIDR(cidr netip.Prefix) (netip.Prefix, netip.Prefix, error) {
	if !cidr.IsValid() {
		return netip.Prefix{}, netip.Prefix{}, ErrInvalidCIDR
	}

	bits := cidr.Bits()
	var maxBits int
	if cidr.Addr().Is4() {
		maxBits = 32
	} else {
		maxBits = 128
	}

	if bits >= maxBits {
		return netip.Prefix{}, netip.Prefix{}, ErrInvalidCIDR
	}

	// First half: same network address, one more bit
	first, err := cidr.Addr().Prefix(bits + 1)
	if err != nil {
		return netip.Prefix{}, netip.Prefix{}, err
	}

	// Second half: calculate the midpoint
	midOffset := uint64(1) << (maxBits - bits - 1)
	midIP, err := OffsetToIP(cidr, midOffset)
	if err != nil {
		return netip.Prefix{}, netip.Prefix{}, err
	}

	second, err := midIP.Prefix(bits + 1)
	if err != nil {
		return netip.Prefix{}, netip.Prefix{}, err
	}

	return first, second, nil
}
