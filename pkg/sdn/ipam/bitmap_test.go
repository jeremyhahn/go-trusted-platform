// Copyright (c) 2025 Jeremy Hahn. All rights reserved.
// Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package ipam

import (
	"sync"
	"testing"
)

func TestNewBitmap(t *testing.T) {
	tests := []struct {
		name string
		size uint64
	}{
		{"zero size", 0},
		{"small size", 64},
		{"exactly one word", 64},
		{"one and a half words", 96},
		{"two words", 128},
		{"large size", 1024},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := NewBitmap(tt.size)
			if b == nil {
				t.Fatal("NewBitmap() returned nil")
			}
			if b.Size() != tt.size {
				t.Errorf("Size() = %v, want %v", b.Size(), tt.size)
			}
			// All bits should start cleared
			if tt.size > 0 && b.CountSet() != 0 {
				t.Errorf("CountSet() = %v, want 0", b.CountSet())
			}
		})
	}
}

func TestBitmap_Set(t *testing.T) {
	b := NewBitmap(256)

	t.Run("set unset bit returns true", func(t *testing.T) {
		if !b.Set(0) {
			t.Error("Set(0) should return true for unset bit")
		}
		if !b.IsSet(0) {
			t.Error("Bit 0 should be set after Set(0)")
		}
	})

	t.Run("set already set bit returns false", func(t *testing.T) {
		if b.Set(0) {
			t.Error("Set(0) should return false for already set bit")
		}
	})

	t.Run("set out of range returns false", func(t *testing.T) {
		if b.Set(256) {
			t.Error("Set(256) should return false for out of range")
		}
		if b.Set(1000) {
			t.Error("Set(1000) should return false for out of range")
		}
	})

	t.Run("set across word boundary", func(t *testing.T) {
		// Test setting bits at word boundaries
		for _, offset := range []uint64{63, 64, 65, 127, 128, 129} {
			if !b.Set(offset) {
				t.Errorf("Set(%d) should return true", offset)
			}
			if !b.IsSet(offset) {
				t.Errorf("Bit %d should be set", offset)
			}
		}
	})
}

func TestBitmap_Clear(t *testing.T) {
	b := NewBitmap(256)

	t.Run("clear unset bit returns false", func(t *testing.T) {
		if b.Clear(0) {
			t.Error("Clear(0) should return false for unset bit")
		}
	})

	t.Run("clear set bit returns true", func(t *testing.T) {
		b.Set(0)
		if !b.Clear(0) {
			t.Error("Clear(0) should return true for set bit")
		}
		if b.IsSet(0) {
			t.Error("Bit 0 should be clear after Clear(0)")
		}
	})

	t.Run("clear out of range returns false", func(t *testing.T) {
		if b.Clear(256) {
			t.Error("Clear(256) should return false for out of range")
		}
	})
}

func TestBitmap_IsSet(t *testing.T) {
	b := NewBitmap(256)

	t.Run("IsSet returns false for unset bit", func(t *testing.T) {
		if b.IsSet(0) {
			t.Error("IsSet(0) should return false for unset bit")
		}
	})

	t.Run("IsSet returns true for set bit", func(t *testing.T) {
		b.Set(0)
		if !b.IsSet(0) {
			t.Error("IsSet(0) should return true for set bit")
		}
	})

	t.Run("IsSet returns false for out of range", func(t *testing.T) {
		if b.IsSet(256) {
			t.Error("IsSet(256) should return false for out of range")
		}
	})
}

func TestBitmap_NextClear(t *testing.T) {
	b := NewBitmap(256)

	t.Run("finds first clear bit", func(t *testing.T) {
		offset, found := b.NextClear(0)
		if !found {
			t.Fatal("NextClear(0) should find clear bit")
		}
		if offset != 0 {
			t.Errorf("NextClear(0) = %v, want 0", offset)
		}
	})

	t.Run("skips set bits", func(t *testing.T) {
		b.Set(0)
		b.Set(1)
		b.Set(2)
		offset, found := b.NextClear(0)
		if !found {
			t.Fatal("NextClear(0) should find clear bit")
		}
		if offset != 3 {
			t.Errorf("NextClear(0) = %v, want 3", offset)
		}
	})

	t.Run("starts from given offset", func(t *testing.T) {
		b.Clear(0)
		b.Clear(1)
		b.Clear(2)
		b.Set(10)
		offset, found := b.NextClear(10)
		if !found {
			t.Fatal("NextClear(10) should find clear bit")
		}
		if offset != 11 {
			t.Errorf("NextClear(10) = %v, want 11", offset)
		}
	})

	t.Run("returns false when no clear bits from start", func(t *testing.T) {
		// Fill all bits
		full := NewBitmap(64)
		for i := uint64(0); i < 64; i++ {
			full.Set(i)
		}
		_, found := full.NextClear(0)
		if found {
			t.Error("NextClear() should return false when all bits are set")
		}
	})

	t.Run("out of range start returns false", func(t *testing.T) {
		_, found := b.NextClear(256)
		if found {
			t.Error("NextClear(256) should return false for out of range start")
		}
	})
}

func TestBitmap_NextSet(t *testing.T) {
	t.Run("returns false when no bits set", func(t *testing.T) {
		b := NewBitmap(256)
		_, found := b.NextSet(0)
		if found {
			t.Error("NextSet(0) should return false when no bits are set")
		}
	})

	t.Run("finds set bit", func(t *testing.T) {
		b := NewBitmap(256)
		b.Set(10)
		offset, found := b.NextSet(0)
		if !found {
			t.Fatal("NextSet(0) should find set bit")
		}
		if offset != 10 {
			t.Errorf("NextSet(0) = %v, want 10", offset)
		}
	})

	t.Run("starts from given offset", func(t *testing.T) {
		b := NewBitmap(256)
		b.Set(5)
		b.Set(20)
		offset, found := b.NextSet(10)
		if !found {
			t.Fatal("NextSet(10) should find set bit")
		}
		if offset != 20 {
			t.Errorf("NextSet(10) = %v, want 20", offset)
		}
	})

	t.Run("out of range start returns false", func(t *testing.T) {
		b := NewBitmap(256)
		_, found := b.NextSet(256)
		if found {
			t.Error("NextSet(256) should return false for out of range start")
		}
	})
}

func TestBitmap_CountSet(t *testing.T) {
	b := NewBitmap(256)

	t.Run("zero for empty bitmap", func(t *testing.T) {
		if b.CountSet() != 0 {
			t.Errorf("CountSet() = %v, want 0", b.CountSet())
		}
	})

	t.Run("counts set bits", func(t *testing.T) {
		b.Set(0)
		b.Set(50)
		b.Set(100)
		if b.CountSet() != 3 {
			t.Errorf("CountSet() = %v, want 3", b.CountSet())
		}
	})

	t.Run("accounts for cleared bits", func(t *testing.T) {
		b.Clear(50)
		if b.CountSet() != 2 {
			t.Errorf("CountSet() = %v, want 2", b.CountSet())
		}
	})
}

func TestBitmap_CountClear(t *testing.T) {
	b := NewBitmap(256)

	t.Run("full count for empty bitmap", func(t *testing.T) {
		if b.CountClear() != 256 {
			t.Errorf("CountClear() = %v, want 256", b.CountClear())
		}
	})

	t.Run("counts clear bits", func(t *testing.T) {
		b.Set(0)
		b.Set(50)
		b.Set(100)
		if b.CountClear() != 253 {
			t.Errorf("CountClear() = %v, want 253", b.CountClear())
		}
	})
}

func TestBitmap_Clone(t *testing.T) {
	t.Run("clones bitmap", func(t *testing.T) {
		b := NewBitmap(256)
		b.Set(0)
		b.Set(100)
		b.Set(200)

		clone := b.Clone()

		// Verify clone is not same pointer
		if clone == b {
			t.Error("Clone() returned same pointer")
		}

		// Verify values match
		if clone.Size() != b.Size() {
			t.Errorf("Clone().Size() = %v, want %v", clone.Size(), b.Size())
		}
		if clone.CountSet() != b.CountSet() {
			t.Errorf("Clone().CountSet() = %v, want %v", clone.CountSet(), b.CountSet())
		}
		for _, offset := range []uint64{0, 100, 200} {
			if !clone.IsSet(offset) {
				t.Errorf("Clone() missing set bit at %d", offset)
			}
		}

		// Verify independence
		clone.Clear(0)
		if !b.IsSet(0) {
			t.Error("Modifying clone affected original")
		}
	})

	t.Run("clones nil bitmap", func(t *testing.T) {
		var b *Bitmap
		clone := b.Clone()
		if clone == nil {
			t.Fatal("Clone() of nil returned nil")
		}
		if clone.Size() != 0 {
			t.Errorf("Clone() of nil has non-zero size: %v", clone.Size())
		}
	})

	t.Run("clones zero size bitmap", func(t *testing.T) {
		b := NewBitmap(0)
		clone := b.Clone()
		if clone == nil {
			t.Fatal("Clone() returned nil")
		}
		if clone.Size() != 0 {
			t.Errorf("Clone().Size() = %v, want 0", clone.Size())
		}
	})
}

func TestBitmap_Reset(t *testing.T) {
	b := NewBitmap(256)
	b.Set(0)
	b.Set(50)
	b.Set(100)

	b.Reset()

	if b.CountSet() != 0 {
		t.Errorf("CountSet() after Reset() = %v, want 0", b.CountSet())
	}
	for _, offset := range []uint64{0, 50, 100} {
		if b.IsSet(offset) {
			t.Errorf("Bit %d should be clear after Reset()", offset)
		}
	}
}

func TestBitmap_ConcurrentAccess(t *testing.T) {
	b := NewBitmap(1024)
	var wg sync.WaitGroup
	numGoroutines := 100

	// Concurrent sets
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(offset uint64) {
			defer wg.Done()
			b.Set(offset)
		}(uint64(i))
	}
	wg.Wait()

	// Verify all bits were set
	for i := uint64(0); i < uint64(numGoroutines); i++ {
		if !b.IsSet(i) {
			t.Errorf("Bit %d should be set after concurrent Set()", i)
		}
	}

	// Concurrent clears
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(offset uint64) {
			defer wg.Done()
			b.Clear(offset)
		}(uint64(i))
	}
	wg.Wait()

	// Verify all bits were cleared
	for i := uint64(0); i < uint64(numGoroutines); i++ {
		if b.IsSet(i) {
			t.Errorf("Bit %d should be clear after concurrent Clear()", i)
		}
	}
}

func TestBitmap_WordBoundaries(t *testing.T) {
	b := NewBitmap(256)

	// Test bits at word boundaries
	boundaries := []uint64{0, 63, 64, 127, 128, 191, 192, 255}

	for _, offset := range boundaries {
		t.Run("boundary "+string(rune('0'+offset%10)), func(t *testing.T) {
			if !b.Set(offset) {
				t.Errorf("Set(%d) failed", offset)
			}
			if !b.IsSet(offset) {
				t.Errorf("IsSet(%d) = false, want true", offset)
			}
			if !b.Clear(offset) {
				t.Errorf("Clear(%d) failed", offset)
			}
			if b.IsSet(offset) {
				t.Errorf("IsSet(%d) = true after Clear, want false", offset)
			}
		})
	}
}

func TestFindFirstSetBit(t *testing.T) {
	tests := []struct {
		name string
		word uint64
		want uint64
	}{
		{"single bit 0", 1, 0},
		{"single bit 1", 2, 1},
		{"single bit 63", 1 << 63, 63},
		{"multiple bits", 0b11110000, 4},
		{"all bits", ^uint64(0), 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findFirstSetBit(tt.word)
			if got != tt.want {
				t.Errorf("findFirstSetBit(%016x) = %v, want %v", tt.word, got, tt.want)
			}
		})
	}
}

func TestFindFirstClearBit(t *testing.T) {
	tests := []struct {
		name string
		word uint64
		want uint64
	}{
		{"all clear", 0, 0},
		{"first set", 1, 1},
		{"first two set", 3, 2},
		{"all but last set", ^uint64(0) >> 1, 63},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findFirstClearBit(tt.word)
			if got != tt.want {
				t.Errorf("findFirstClearBit(%016x) = %v, want %v", tt.word, got, tt.want)
			}
		})
	}
}

func TestPopcount(t *testing.T) {
	tests := []struct {
		name string
		word uint64
		want uint64
	}{
		{"zero", 0, 0},
		{"one", 1, 1},
		{"all ones", ^uint64(0), 64},
		{"alternating", 0x5555555555555555, 32},
		{"0xF0", 0xF0, 4},
		{"0xFF", 0xFF, 8},
		{"0xFFFF", 0xFFFF, 16},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := popcount(tt.word)
			if got != tt.want {
				t.Errorf("popcount(%016x) = %v, want %v", tt.word, got, tt.want)
			}
		})
	}
}

func BenchmarkBitmap_Set(b *testing.B) {
	bm := NewBitmap(1000000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bm.Set(uint64(i % 1000000))
	}
}

func BenchmarkBitmap_IsSet(b *testing.B) {
	bm := NewBitmap(1000000)
	for i := uint64(0); i < 1000000; i += 2 {
		bm.Set(i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bm.IsSet(uint64(i % 1000000))
	}
}

func BenchmarkBitmap_NextClear(b *testing.B) {
	bm := NewBitmap(1000000)
	// Fill first half
	for i := uint64(0); i < 500000; i++ {
		bm.Set(i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bm.NextClear(0)
	}
}

func BenchmarkBitmap_CountSet(b *testing.B) {
	bm := NewBitmap(1000000)
	for i := uint64(0); i < 1000000; i += 2 {
		bm.Set(i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bm.CountSet()
	}
}
