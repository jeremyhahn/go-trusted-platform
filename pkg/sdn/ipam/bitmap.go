// Copyright (c) 2025 Jeremy Hahn. All rights reserved.
// Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package ipam

import (
	"sync/atomic"
)

// Bitmap provides efficient tracking of allocated IP addresses using a bit array.
// It is safe for concurrent use through atomic operations.
type Bitmap struct {
	// words stores the bitmap data as 64-bit words for atomic operations
	words []atomic.Uint64
	// size is the total number of bits in the bitmap
	size uint64
}

// NewBitmap creates a new bitmap with the specified size (number of bits).
// The bitmap is initialized with all bits cleared (available).
func NewBitmap(size uint64) *Bitmap {
	if size == 0 {
		return &Bitmap{
			words: nil,
			size:  0,
		}
	}
	// Calculate number of 64-bit words needed
	numWords := (size + 63) / 64
	return &Bitmap{
		words: make([]atomic.Uint64, numWords),
		size:  size,
	}
}

// Size returns the total number of bits in the bitmap.
func (b *Bitmap) Size() uint64 {
	return b.size
}

// Set marks the bit at the given offset as set (allocated).
// Returns true if the bit was successfully set, false if already set.
// Returns false if offset is out of range.
func (b *Bitmap) Set(offset uint64) bool {
	if offset >= b.size {
		return false
	}
	wordIdx := offset / 64
	bitIdx := offset % 64
	mask := uint64(1) << bitIdx

	for {
		oldVal := b.words[wordIdx].Load()
		if oldVal&mask != 0 {
			// Already set
			return false
		}
		newVal := oldVal | mask
		if b.words[wordIdx].CompareAndSwap(oldVal, newVal) {
			return true
		}
		// CAS failed, retry
	}
}

// Clear marks the bit at the given offset as cleared (available).
// Returns true if the bit was successfully cleared, false if already clear.
// Returns false if offset is out of range.
func (b *Bitmap) Clear(offset uint64) bool {
	if offset >= b.size {
		return false
	}
	wordIdx := offset / 64
	bitIdx := offset % 64
	mask := uint64(1) << bitIdx

	for {
		oldVal := b.words[wordIdx].Load()
		if oldVal&mask == 0 {
			// Already clear
			return false
		}
		newVal := oldVal &^ mask
		if b.words[wordIdx].CompareAndSwap(oldVal, newVal) {
			return true
		}
		// CAS failed, retry
	}
}

// IsSet returns true if the bit at the given offset is set (allocated).
// Returns false if the offset is out of range.
func (b *Bitmap) IsSet(offset uint64) bool {
	if offset >= b.size {
		return false
	}
	wordIdx := offset / 64
	bitIdx := offset % 64
	mask := uint64(1) << bitIdx
	return b.words[wordIdx].Load()&mask != 0
}

// NextClear finds the next clear (available) bit starting from the given offset.
// Returns the offset and true if found, or 0 and false if no clear bit exists.
func (b *Bitmap) NextClear(start uint64) (uint64, bool) {
	if start >= b.size {
		return 0, false
	}

	// Start in the middle of a word
	wordIdx := start / 64
	bitIdx := start % 64

	// Check the first partial word
	word := b.words[wordIdx].Load()
	// Mask off bits before start position
	maskedWord := word | ((1 << bitIdx) - 1)
	if maskedWord != ^uint64(0) {
		// There's a clear bit in this word
		clearBit := findFirstClearBit(maskedWord)
		offset := wordIdx*64 + clearBit
		if offset < b.size {
			return offset, true
		}
	}

	// Scan remaining words
	for i := wordIdx + 1; i < uint64(len(b.words)); i++ {
		word := b.words[i].Load()
		if word != ^uint64(0) {
			// There's a clear bit in this word
			clearBit := findFirstClearBit(word)
			offset := i*64 + clearBit
			if offset < b.size {
				return offset, true
			}
			return 0, false
		}
	}

	return 0, false
}

// NextSet finds the next set (allocated) bit starting from the given offset.
// Returns the offset and true if found, or 0 and false if no set bit exists.
func (b *Bitmap) NextSet(start uint64) (uint64, bool) {
	if start >= b.size {
		return 0, false
	}

	wordIdx := start / 64
	bitIdx := start % 64

	// Check the first partial word
	word := b.words[wordIdx].Load()
	// Mask off bits before start position
	maskedWord := word & (^uint64(0) << bitIdx)
	if maskedWord != 0 {
		setBit := findFirstSetBit(maskedWord)
		offset := wordIdx*64 + setBit
		if offset < b.size {
			return offset, true
		}
	}

	// Scan remaining words
	for i := wordIdx + 1; i < uint64(len(b.words)); i++ {
		word := b.words[i].Load()
		if word != 0 {
			setBit := findFirstSetBit(word)
			offset := i*64 + setBit
			if offset < b.size {
				return offset, true
			}
			return 0, false
		}
	}

	return 0, false
}

// CountSet returns the number of set bits in the bitmap.
func (b *Bitmap) CountSet() uint64 {
	var count uint64
	for i := range b.words {
		count += popcount(b.words[i].Load())
	}
	// Adjust for bits beyond size in the last word
	if b.size > 0 {
		extraBits := (uint64(len(b.words)) * 64) - b.size
		if extraBits > 0 {
			lastWordIdx := len(b.words) - 1
			lastWord := b.words[lastWordIdx].Load()
			// Count any set bits that are beyond our size
			invalidMask := ^uint64(0) << (64 - extraBits)
			count -= popcount(lastWord & invalidMask)
		}
	}
	return count
}

// CountClear returns the number of clear bits in the bitmap.
func (b *Bitmap) CountClear() uint64 {
	return b.size - b.CountSet()
}

// Clone creates a deep copy of the bitmap.
func (b *Bitmap) Clone() *Bitmap {
	if b == nil || b.size == 0 {
		return NewBitmap(0)
	}
	clone := &Bitmap{
		words: make([]atomic.Uint64, len(b.words)),
		size:  b.size,
	}
	for i := range b.words {
		clone.words[i].Store(b.words[i].Load())
	}
	return clone
}

// Reset clears all bits in the bitmap.
func (b *Bitmap) Reset() {
	for i := range b.words {
		b.words[i].Store(0)
	}
}

// findFirstClearBit finds the index of the first clear bit in a word.
// Assumes the word has at least one clear bit.
func findFirstClearBit(word uint64) uint64 {
	// Find first clear bit by finding first set bit in inverted word
	return findFirstSetBit(^word)
}

// findFirstSetBit finds the index of the first set bit in a word.
// Assumes the word has at least one set bit.
// Uses de Bruijn sequence for O(1) lookup.
func findFirstSetBit(word uint64) uint64 {
	// Use trailing zeros count
	// This is the bit-twiddling version of ctz (count trailing zeros)
	if word == 0 {
		return 64
	}

	// De Bruijn sequence for 64-bit
	const debruijn64 = 0x03f79d71b4cb0a89
	var debruijnIndex = [64]uint64{
		0, 1, 48, 2, 57, 49, 28, 3, 61, 58, 50, 42, 38, 29, 17, 4,
		62, 55, 59, 36, 53, 51, 43, 22, 45, 39, 33, 30, 24, 18, 12, 5,
		63, 47, 56, 27, 60, 41, 37, 16, 54, 35, 52, 21, 44, 32, 23, 11,
		46, 26, 40, 15, 34, 20, 31, 10, 25, 14, 19, 9, 13, 8, 7, 6,
	}

	// Isolate the lowest set bit
	isolated := word & (^word + 1)
	return debruijnIndex[(isolated*debruijn64)>>58]
}

// popcount counts the number of set bits in a word.
func popcount(word uint64) uint64 {
	// Standard popcount using parallel bit counting
	word -= (word >> 1) & 0x5555555555555555
	word = (word & 0x3333333333333333) + ((word >> 2) & 0x3333333333333333)
	word = (word + (word >> 4)) & 0x0f0f0f0f0f0f0f0f
	return (word * 0x0101010101010101) >> 56
}
