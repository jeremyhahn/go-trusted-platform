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

package vlan

import (
	"sync/atomic"
	"unsafe"
)

// bitset provides efficient storage for tracking used VLANs
// VLANs 1-4094 fit in ~64 uint64 words (512 bytes)
// This implementation is lock-free using atomic operations
type bitset struct {
	bits []uint64
	size int
}

// newBitset creates a new bitset capable of tracking n bits
func newBitset(size int) *bitset {
	if size <= 0 {
		size = int(MaxVLANID) + 1
	}
	// Calculate number of uint64 words needed (64 bits per word)
	words := (size + 63) / 64
	return &bitset{
		bits: make([]uint64, words),
		size: size,
	}
}

// wordIndex returns the word index and bit offset for a given bit position
func (b *bitset) wordIndex(n uint16) (word int, bit uint64) {
	word = int(n) / 64
	bit = uint64(1) << (uint(n) % 64)
	return
}

// Set atomically sets the bit at position n
func (b *bitset) Set(n uint16) {
	if int(n) >= b.size {
		return
	}
	word, bit := b.wordIndex(n)
	addr := (*uint64)(unsafe.Pointer(&b.bits[word]))
	for {
		old := atomic.LoadUint64(addr)
		if old&bit != 0 {
			return // Already set
		}
		if atomic.CompareAndSwapUint64(addr, old, old|bit) {
			return
		}
	}
}

// Clear atomically clears the bit at position n
func (b *bitset) Clear(n uint16) {
	if int(n) >= b.size {
		return
	}
	word, bit := b.wordIndex(n)
	addr := (*uint64)(unsafe.Pointer(&b.bits[word]))
	for {
		old := atomic.LoadUint64(addr)
		if old&bit == 0 {
			return // Already clear
		}
		if atomic.CompareAndSwapUint64(addr, old, old&^bit) {
			return
		}
	}
}

// Test atomically checks if the bit at position n is set
func (b *bitset) Test(n uint16) bool {
	if int(n) >= b.size {
		return false
	}
	word, bit := b.wordIndex(n)
	addr := (*uint64)(unsafe.Pointer(&b.bits[word]))
	return atomic.LoadUint64(addr)&bit != 0
}

// SetRange atomically sets all bits in the range [start, end]
func (b *bitset) SetRange(start, end uint16) {
	for i := start; i <= end; i++ {
		b.Set(i)
		// Prevent overflow if end is at max value
		if i == end {
			break
		}
	}
}

// ClearRange atomically clears all bits in the range [start, end]
func (b *bitset) ClearRange(start, end uint16) {
	for i := start; i <= end; i++ {
		b.Clear(i)
		// Prevent overflow if end is at max value
		if i == end {
			break
		}
	}
}

// FindFirstClear finds the first clear bit in the range [start, end]
// Returns the bit position and true if found, or 0 and false if not found
func (b *bitset) FindFirstClear(start, end uint16) (uint16, bool) {
	if int(start) >= b.size || start > end {
		return 0, false
	}
	if int(end) >= b.size {
		end = uint16(b.size - 1)
	}

	for i := start; i <= end; i++ {
		if !b.Test(i) {
			return i, true
		}
		// Prevent overflow if end is at max value
		if i == end {
			break
		}
	}
	return 0, false
}

// FindClearRange finds a contiguous range of clear bits of the specified size
// within the range [start, end]
// Returns the starting position and true if found, or 0 and false if not found
func (b *bitset) FindClearRange(start, end uint16, size uint16) (uint16, bool) {
	if size == 0 || int(start) >= b.size || start > end {
		return 0, false
	}
	if int(end) >= b.size {
		end = uint16(b.size - 1)
	}

	// Need at least 'size' bits available in the search range
	availableRange := end - start + 1
	if availableRange < size {
		return 0, false
	}

	rangeStart := start
	count := uint16(0)

	for i := start; i <= end; i++ {
		if !b.Test(i) {
			if count == 0 {
				rangeStart = i
			}
			count++
			if count >= size {
				return rangeStart, true
			}
		} else {
			count = 0
		}
		// Prevent overflow if end is at max value
		if i == end {
			break
		}
	}
	return 0, false
}

// CountSet returns the number of set bits
func (b *bitset) CountSet() int {
	count := 0
	for i := 0; i < len(b.bits); i++ {
		addr := (*uint64)(unsafe.Pointer(&b.bits[i]))
		word := atomic.LoadUint64(addr)
		count += popcount(word)
	}
	return count
}

// CountClear returns the number of clear bits within the valid size
func (b *bitset) CountClear() int {
	return b.size - b.CountSet()
}

// CountSetInRange returns the number of set bits in the range [start, end]
func (b *bitset) CountSetInRange(start, end uint16) int {
	if start > end {
		return 0
	}
	count := 0
	for i := start; i <= end; i++ {
		if b.Test(i) {
			count++
		}
		// Prevent overflow if end is at max value
		if i == end {
			break
		}
	}
	return count
}

// TestRange returns true if all bits in the range [start, end] are set
func (b *bitset) TestRange(start, end uint16) bool {
	for i := start; i <= end; i++ {
		if !b.Test(i) {
			return false
		}
		// Prevent overflow if end is at max value
		if i == end {
			break
		}
	}
	return true
}

// TestRangeClear returns true if all bits in the range [start, end] are clear
func (b *bitset) TestRangeClear(start, end uint16) bool {
	for i := start; i <= end; i++ {
		if b.Test(i) {
			return false
		}
		// Prevent overflow if end is at max value
		if i == end {
			break
		}
	}
	return true
}

// Reset clears all bits in the bitset
func (b *bitset) Reset() {
	for i := 0; i < len(b.bits); i++ {
		addr := (*uint64)(unsafe.Pointer(&b.bits[i]))
		atomic.StoreUint64(addr, 0)
	}
}

// Clone returns a copy of the bitset
// Note: This is not atomic across the entire bitset
func (b *bitset) Clone() *bitset {
	newBits := make([]uint64, len(b.bits))
	for i := 0; i < len(b.bits); i++ {
		addr := (*uint64)(unsafe.Pointer(&b.bits[i]))
		newBits[i] = atomic.LoadUint64(addr)
	}
	return &bitset{
		bits: newBits,
		size: b.size,
	}
}

// popcount returns the number of set bits in a uint64 using Brian Kernighan's algorithm
func popcount(x uint64) int {
	count := 0
	for x != 0 {
		x &= x - 1
		count++
	}
	return count
}
