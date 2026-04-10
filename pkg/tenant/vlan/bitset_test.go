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
	"sync"
	"testing"
)

func TestNewBitset(t *testing.T) {
	t.Run("default size", func(t *testing.T) {
		bs := newBitset(0)
		if bs == nil {
			t.Fatal("newBitset(0) returned nil")
		}
		if bs.size != int(MaxVLANID)+1 {
			t.Errorf("size = %d, want %d", bs.size, int(MaxVLANID)+1)
		}
		expectedWords := (int(MaxVLANID) + 1 + 63) / 64
		if len(bs.bits) != expectedWords {
			t.Errorf("bits length = %d, want %d", len(bs.bits), expectedWords)
		}
	})

	t.Run("negative size uses default", func(t *testing.T) {
		bs := newBitset(-10)
		if bs.size != int(MaxVLANID)+1 {
			t.Errorf("size = %d, want %d", bs.size, int(MaxVLANID)+1)
		}
	})

	t.Run("custom size", func(t *testing.T) {
		bs := newBitset(100)
		if bs.size != 100 {
			t.Errorf("size = %d, want 100", bs.size)
		}
		expectedWords := (100 + 63) / 64
		if len(bs.bits) != expectedWords {
			t.Errorf("bits length = %d, want %d", len(bs.bits), expectedWords)
		}
	})

	t.Run("exact 64 bits", func(t *testing.T) {
		bs := newBitset(64)
		if len(bs.bits) != 1 {
			t.Errorf("bits length = %d, want 1", len(bs.bits))
		}
	})

	t.Run("65 bits requires 2 words", func(t *testing.T) {
		bs := newBitset(65)
		if len(bs.bits) != 2 {
			t.Errorf("bits length = %d, want 2", len(bs.bits))
		}
	})

	t.Run("max VLAN count", func(t *testing.T) {
		bs := newBitset(int(MaxVLANID) + 1)
		if bs.size != int(MaxVLANID)+1 {
			t.Errorf("size = %d, want %d", bs.size, int(MaxVLANID)+1)
		}
	})
}

func TestBitset_Set(t *testing.T) {
	t.Run("set single bit", func(t *testing.T) {
		bs := newBitset(100)
		bs.Set(50)
		if !bs.Test(50) {
			t.Error("bit 50 should be set")
		}
	})

	t.Run("set first bit", func(t *testing.T) {
		bs := newBitset(100)
		bs.Set(0)
		if !bs.Test(0) {
			t.Error("bit 0 should be set")
		}
	})

	t.Run("set last bit", func(t *testing.T) {
		bs := newBitset(100)
		bs.Set(99)
		if !bs.Test(99) {
			t.Error("bit 99 should be set")
		}
	})

	t.Run("set beyond size does nothing", func(t *testing.T) {
		bs := newBitset(100)
		bs.Set(100) // beyond size
		// Should not panic and not affect anything
		if bs.CountSet() != 0 {
			t.Error("no bits should be set")
		}
	})

	t.Run("set already set bit", func(t *testing.T) {
		bs := newBitset(100)
		bs.Set(50)
		bs.Set(50)
		if !bs.Test(50) {
			t.Error("bit 50 should still be set")
		}
	})

	t.Run("set bit at word boundary", func(t *testing.T) {
		bs := newBitset(200)
		bs.Set(63) // last bit of first word
		bs.Set(64) // first bit of second word
		if !bs.Test(63) || !bs.Test(64) {
			t.Error("bits at word boundary should be set")
		}
	})

	t.Run("set VLAN boundaries", func(t *testing.T) {
		bs := newBitset(int(MaxVLANID) + 1)
		bs.Set(MinVLANID)
		bs.Set(MaxVLANID)
		if !bs.Test(MinVLANID) {
			t.Errorf("MinVLANID (%d) should be set", MinVLANID)
		}
		if !bs.Test(MaxVLANID) {
			t.Errorf("MaxVLANID (%d) should be set", MaxVLANID)
		}
	})
}

func TestBitset_Clear(t *testing.T) {
	t.Run("clear set bit", func(t *testing.T) {
		bs := newBitset(100)
		bs.Set(50)
		bs.Clear(50)
		if bs.Test(50) {
			t.Error("bit 50 should be clear")
		}
	})

	t.Run("clear already clear bit", func(t *testing.T) {
		bs := newBitset(100)
		bs.Clear(50)
		if bs.Test(50) {
			t.Error("bit 50 should still be clear")
		}
	})

	t.Run("clear beyond size does nothing", func(t *testing.T) {
		bs := newBitset(100)
		bs.Set(50)
		bs.Clear(100) // beyond size
		if !bs.Test(50) {
			t.Error("bit 50 should still be set")
		}
	})

	t.Run("clear first bit", func(t *testing.T) {
		bs := newBitset(100)
		bs.Set(0)
		bs.Clear(0)
		if bs.Test(0) {
			t.Error("bit 0 should be clear")
		}
	})

	t.Run("clear last bit", func(t *testing.T) {
		bs := newBitset(100)
		bs.Set(99)
		bs.Clear(99)
		if bs.Test(99) {
			t.Error("bit 99 should be clear")
		}
	})
}

func TestBitset_Test(t *testing.T) {
	t.Run("test unset bit", func(t *testing.T) {
		bs := newBitset(100)
		if bs.Test(50) {
			t.Error("bit 50 should be unset")
		}
	})

	t.Run("test set bit", func(t *testing.T) {
		bs := newBitset(100)
		bs.Set(50)
		if !bs.Test(50) {
			t.Error("bit 50 should be set")
		}
	})

	t.Run("test beyond size returns false", func(t *testing.T) {
		bs := newBitset(100)
		if bs.Test(100) {
			t.Error("test beyond size should return false")
		}
		if bs.Test(1000) {
			t.Error("test far beyond size should return false")
		}
	})

	t.Run("test all bits in fresh bitset", func(t *testing.T) {
		bs := newBitset(100)
		for i := uint16(0); i < 100; i++ {
			if bs.Test(i) {
				t.Errorf("bit %d should be unset in fresh bitset", i)
			}
		}
	})
}

func TestBitset_SetRange(t *testing.T) {
	t.Run("set range of bits", func(t *testing.T) {
		bs := newBitset(100)
		bs.SetRange(10, 20)
		for i := uint16(10); i <= 20; i++ {
			if !bs.Test(i) {
				t.Errorf("bit %d should be set", i)
			}
		}
		// Check bits before and after
		if bs.Test(9) {
			t.Error("bit 9 should not be set")
		}
		if bs.Test(21) {
			t.Error("bit 21 should not be set")
		}
	})

	t.Run("set single bit range", func(t *testing.T) {
		bs := newBitset(100)
		bs.SetRange(50, 50)
		if !bs.Test(50) {
			t.Error("bit 50 should be set")
		}
		if bs.CountSet() != 1 {
			t.Errorf("CountSet() = %d, want 1", bs.CountSet())
		}
	})

	t.Run("set range across word boundary", func(t *testing.T) {
		bs := newBitset(200)
		bs.SetRange(60, 70) // Crosses 64-bit boundary
		for i := uint16(60); i <= 70; i++ {
			if !bs.Test(i) {
				t.Errorf("bit %d should be set", i)
			}
		}
	})

	t.Run("set range at max boundary", func(t *testing.T) {
		bs := newBitset(int(MaxVLANID) + 1)
		bs.SetRange(MaxVLANID-10, MaxVLANID)
		for i := MaxVLANID - 10; i <= MaxVLANID; i++ {
			if !bs.Test(i) {
				t.Errorf("bit %d should be set", i)
			}
		}
	})

	t.Run("set full VLAN range", func(t *testing.T) {
		bs := newBitset(int(MaxVLANID) + 1)
		bs.SetRange(MinVLANID, MaxVLANID)
		// Spot check
		if !bs.Test(MinVLANID) || !bs.Test(MaxVLANID) || !bs.Test(2000) {
			t.Error("full range should be set")
		}
	})
}

func TestBitset_ClearRange(t *testing.T) {
	t.Run("clear range of bits", func(t *testing.T) {
		bs := newBitset(100)
		bs.SetRange(0, 99) // Set all bits
		bs.ClearRange(10, 20)
		for i := uint16(10); i <= 20; i++ {
			if bs.Test(i) {
				t.Errorf("bit %d should be clear", i)
			}
		}
		// Surrounding bits should still be set
		if !bs.Test(9) {
			t.Error("bit 9 should still be set")
		}
		if !bs.Test(21) {
			t.Error("bit 21 should still be set")
		}
	})

	t.Run("clear single bit range", func(t *testing.T) {
		bs := newBitset(100)
		bs.SetRange(0, 99)
		bs.ClearRange(50, 50)
		if bs.Test(50) {
			t.Error("bit 50 should be clear")
		}
		if !bs.Test(49) || !bs.Test(51) {
			t.Error("surrounding bits should still be set")
		}
	})

	t.Run("clear range across word boundary", func(t *testing.T) {
		bs := newBitset(200)
		bs.SetRange(0, 199)
		bs.ClearRange(60, 70)
		for i := uint16(60); i <= 70; i++ {
			if bs.Test(i) {
				t.Errorf("bit %d should be clear", i)
			}
		}
	})

	t.Run("clear already clear range", func(t *testing.T) {
		bs := newBitset(100)
		bs.ClearRange(10, 20) // Already clear
		for i := uint16(10); i <= 20; i++ {
			if bs.Test(i) {
				t.Errorf("bit %d should be clear", i)
			}
		}
	})
}

func TestBitset_FindFirstClear(t *testing.T) {
	t.Run("find in empty bitset", func(t *testing.T) {
		bs := newBitset(100)
		pos, found := bs.FindFirstClear(0, 99)
		if !found || pos != 0 {
			t.Errorf("FindFirstClear = (%d, %v), want (0, true)", pos, found)
		}
	})

	t.Run("find first clear with some set", func(t *testing.T) {
		bs := newBitset(100)
		bs.SetRange(0, 9) // Set first 10 bits
		pos, found := bs.FindFirstClear(0, 99)
		if !found || pos != 10 {
			t.Errorf("FindFirstClear = (%d, %v), want (10, true)", pos, found)
		}
	})

	t.Run("find in specific range", func(t *testing.T) {
		bs := newBitset(100)
		bs.SetRange(0, 50)
		pos, found := bs.FindFirstClear(40, 60)
		if !found || pos != 51 {
			t.Errorf("FindFirstClear = (%d, %v), want (51, true)", pos, found)
		}
	})

	t.Run("no clear bit available", func(t *testing.T) {
		bs := newBitset(100)
		bs.SetRange(0, 99)
		pos, found := bs.FindFirstClear(0, 99)
		if found {
			t.Errorf("FindFirstClear should return false when full, got (%d, %v)", pos, found)
		}
	})

	t.Run("start beyond size", func(t *testing.T) {
		bs := newBitset(100)
		pos, found := bs.FindFirstClear(100, 200)
		if found {
			t.Errorf("FindFirstClear should return false when start beyond size, got (%d, %v)", pos, found)
		}
	})

	t.Run("start greater than end", func(t *testing.T) {
		bs := newBitset(100)
		pos, found := bs.FindFirstClear(50, 40)
		if found {
			t.Errorf("FindFirstClear should return false when start > end, got (%d, %v)", pos, found)
		}
	})

	t.Run("end beyond size clamps to size", func(t *testing.T) {
		bs := newBitset(100)
		bs.SetRange(0, 98)
		pos, found := bs.FindFirstClear(0, 200)
		if !found || pos != 99 {
			t.Errorf("FindFirstClear = (%d, %v), want (99, true)", pos, found)
		}
	})

	t.Run("find at max VLAN", func(t *testing.T) {
		bs := newBitset(int(MaxVLANID) + 1)
		bs.SetRange(MinVLANID, MaxVLANID-1)
		pos, found := bs.FindFirstClear(MinVLANID, MaxVLANID)
		if !found || pos != MaxVLANID {
			t.Errorf("FindFirstClear = (%d, %v), want (%d, true)", pos, found, MaxVLANID)
		}
	})
}

func TestBitset_FindClearRange(t *testing.T) {
	t.Run("find range in empty bitset", func(t *testing.T) {
		bs := newBitset(100)
		pos, found := bs.FindClearRange(0, 99, 10)
		if !found || pos != 0 {
			t.Errorf("FindClearRange = (%d, %v), want (0, true)", pos, found)
		}
	})

	t.Run("find contiguous range after set bits", func(t *testing.T) {
		bs := newBitset(100)
		bs.SetRange(0, 19) // First 20 bits set
		pos, found := bs.FindClearRange(0, 99, 10)
		if !found || pos != 20 {
			t.Errorf("FindClearRange = (%d, %v), want (20, true)", pos, found)
		}
	})

	t.Run("find range with gaps", func(t *testing.T) {
		bs := newBitset(100)
		bs.SetRange(0, 9)   // Set 0-9
		bs.Set(15)          // Set single bit at 15
		bs.SetRange(30, 39) // Set 30-39
		// Gaps: 10-14 (5 bits), 16-29 (14 bits)
		pos, found := bs.FindClearRange(0, 99, 10)
		if !found || pos != 16 {
			t.Errorf("FindClearRange = (%d, %v), want (16, true)", pos, found)
		}
	})

	t.Run("no contiguous range available", func(t *testing.T) {
		bs := newBitset(100)
		// Set every other bit
		for i := uint16(0); i < 100; i += 2 {
			bs.Set(i)
		}
		pos, found := bs.FindClearRange(0, 99, 2)
		if found {
			t.Errorf("FindClearRange should return false, got (%d, %v)", pos, found)
		}
	})

	t.Run("size zero", func(t *testing.T) {
		bs := newBitset(100)
		pos, found := bs.FindClearRange(0, 99, 0)
		if found {
			t.Errorf("FindClearRange with size 0 should return false, got (%d, %v)", pos, found)
		}
	})

	t.Run("start beyond size", func(t *testing.T) {
		bs := newBitset(100)
		pos, found := bs.FindClearRange(100, 200, 10)
		if found {
			t.Errorf("FindClearRange should return false when start beyond size, got (%d, %v)", pos, found)
		}
	})

	t.Run("range too small for requested size", func(t *testing.T) {
		bs := newBitset(100)
		pos, found := bs.FindClearRange(0, 9, 20)
		if found {
			t.Errorf("FindClearRange should return false when range < size, got (%d, %v)", pos, found)
		}
	})

	t.Run("exact fit", func(t *testing.T) {
		bs := newBitset(100)
		pos, found := bs.FindClearRange(0, 9, 10)
		if !found || pos != 0 {
			t.Errorf("FindClearRange = (%d, %v), want (0, true)", pos, found)
		}
	})

	t.Run("find VLAN allocation size", func(t *testing.T) {
		bs := newBitset(int(MaxVLANID) + 1)
		bs.SetRange(100, 199) // First tenant
		pos, found := bs.FindClearRange(100, 4000, DefaultRangeSize)
		if !found || pos != 200 {
			t.Errorf("FindClearRange = (%d, %v), want (200, true)", pos, found)
		}
	})

	t.Run("start greater than end", func(t *testing.T) {
		bs := newBitset(100)
		pos, found := bs.FindClearRange(50, 40, 5)
		if found {
			t.Errorf("FindClearRange should return false when start > end, got (%d, %v)", pos, found)
		}
	})
}

func TestBitset_CountSet(t *testing.T) {
	t.Run("empty bitset", func(t *testing.T) {
		bs := newBitset(100)
		if count := bs.CountSet(); count != 0 {
			t.Errorf("CountSet() = %d, want 0", count)
		}
	})

	t.Run("single bit set", func(t *testing.T) {
		bs := newBitset(100)
		bs.Set(50)
		if count := bs.CountSet(); count != 1 {
			t.Errorf("CountSet() = %d, want 1", count)
		}
	})

	t.Run("multiple bits set", func(t *testing.T) {
		bs := newBitset(100)
		bs.SetRange(10, 19) // 10 bits
		if count := bs.CountSet(); count != 10 {
			t.Errorf("CountSet() = %d, want 10", count)
		}
	})

	t.Run("all bits set", func(t *testing.T) {
		bs := newBitset(100)
		bs.SetRange(0, 99)
		if count := bs.CountSet(); count != 100 {
			t.Errorf("CountSet() = %d, want 100", count)
		}
	})

	t.Run("cross word boundary", func(t *testing.T) {
		bs := newBitset(200)
		bs.SetRange(60, 70) // 11 bits across word boundary
		if count := bs.CountSet(); count != 11 {
			t.Errorf("CountSet() = %d, want 11", count)
		}
	})
}

func TestBitset_CountClear(t *testing.T) {
	t.Run("empty bitset", func(t *testing.T) {
		bs := newBitset(100)
		if count := bs.CountClear(); count != 100 {
			t.Errorf("CountClear() = %d, want 100", count)
		}
	})

	t.Run("some bits set", func(t *testing.T) {
		bs := newBitset(100)
		bs.SetRange(0, 9) // 10 bits set
		if count := bs.CountClear(); count != 90 {
			t.Errorf("CountClear() = %d, want 90", count)
		}
	})

	t.Run("all bits set", func(t *testing.T) {
		bs := newBitset(100)
		bs.SetRange(0, 99)
		if count := bs.CountClear(); count != 0 {
			t.Errorf("CountClear() = %d, want 0", count)
		}
	})

	t.Run("count clear plus count set equals size", func(t *testing.T) {
		bs := newBitset(100)
		bs.SetRange(20, 49)
		set := bs.CountSet()
		clear := bs.CountClear()
		if set+clear != 100 {
			t.Errorf("CountSet() + CountClear() = %d, want 100", set+clear)
		}
	})
}

func TestBitset_CountSetInRange(t *testing.T) {
	t.Run("empty range", func(t *testing.T) {
		bs := newBitset(100)
		if count := bs.CountSetInRange(0, 99); count != 0 {
			t.Errorf("CountSetInRange = %d, want 0", count)
		}
	})

	t.Run("partial set", func(t *testing.T) {
		bs := newBitset(100)
		bs.SetRange(10, 19)
		if count := bs.CountSetInRange(0, 99); count != 10 {
			t.Errorf("CountSetInRange = %d, want 10", count)
		}
	})

	t.Run("count only in range", func(t *testing.T) {
		bs := newBitset(100)
		bs.SetRange(0, 99)
		if count := bs.CountSetInRange(10, 19); count != 10 {
			t.Errorf("CountSetInRange = %d, want 10", count)
		}
	})

	t.Run("start greater than end returns 0", func(t *testing.T) {
		bs := newBitset(100)
		bs.SetRange(0, 99)
		if count := bs.CountSetInRange(50, 40); count != 0 {
			t.Errorf("CountSetInRange = %d, want 0", count)
		}
	})

	t.Run("single position", func(t *testing.T) {
		bs := newBitset(100)
		bs.Set(50)
		if count := bs.CountSetInRange(50, 50); count != 1 {
			t.Errorf("CountSetInRange = %d, want 1", count)
		}
	})
}

func TestBitset_TestRange(t *testing.T) {
	t.Run("all set in range", func(t *testing.T) {
		bs := newBitset(100)
		bs.SetRange(10, 20)
		if !bs.TestRange(10, 20) {
			t.Error("TestRange should return true when all bits are set")
		}
	})

	t.Run("not all set in range", func(t *testing.T) {
		bs := newBitset(100)
		bs.SetRange(10, 19)
		if bs.TestRange(10, 20) {
			t.Error("TestRange should return false when not all bits are set")
		}
	})

	t.Run("single bit set", func(t *testing.T) {
		bs := newBitset(100)
		bs.Set(50)
		if !bs.TestRange(50, 50) {
			t.Error("TestRange should return true for single set bit")
		}
	})

	t.Run("single bit not set", func(t *testing.T) {
		bs := newBitset(100)
		if bs.TestRange(50, 50) {
			t.Error("TestRange should return false for single unset bit")
		}
	})

	t.Run("empty bitset", func(t *testing.T) {
		bs := newBitset(100)
		if bs.TestRange(0, 99) {
			t.Error("TestRange should return false for empty bitset")
		}
	})
}

func TestBitset_TestRangeClear(t *testing.T) {
	t.Run("all clear in range", func(t *testing.T) {
		bs := newBitset(100)
		if !bs.TestRangeClear(10, 20) {
			t.Error("TestRangeClear should return true when all bits are clear")
		}
	})

	t.Run("some bits set in range", func(t *testing.T) {
		bs := newBitset(100)
		bs.Set(15)
		if bs.TestRangeClear(10, 20) {
			t.Error("TestRangeClear should return false when some bits are set")
		}
	})

	t.Run("all bits set in range", func(t *testing.T) {
		bs := newBitset(100)
		bs.SetRange(10, 20)
		if bs.TestRangeClear(10, 20) {
			t.Error("TestRangeClear should return false when all bits are set")
		}
	})

	t.Run("single bit clear", func(t *testing.T) {
		bs := newBitset(100)
		if !bs.TestRangeClear(50, 50) {
			t.Error("TestRangeClear should return true for single clear bit")
		}
	})

	t.Run("single bit set", func(t *testing.T) {
		bs := newBitset(100)
		bs.Set(50)
		if bs.TestRangeClear(50, 50) {
			t.Error("TestRangeClear should return false for single set bit")
		}
	})
}

func TestBitset_Reset(t *testing.T) {
	t.Run("reset clears all bits", func(t *testing.T) {
		bs := newBitset(100)
		bs.SetRange(0, 99)
		bs.Reset()
		if count := bs.CountSet(); count != 0 {
			t.Errorf("CountSet after Reset = %d, want 0", count)
		}
	})

	t.Run("reset empty bitset is safe", func(t *testing.T) {
		bs := newBitset(100)
		bs.Reset()
		if count := bs.CountSet(); count != 0 {
			t.Errorf("CountSet after Reset = %d, want 0", count)
		}
	})

	t.Run("reset partial bitset", func(t *testing.T) {
		bs := newBitset(100)
		bs.SetRange(20, 50)
		bs.Reset()
		if count := bs.CountSet(); count != 0 {
			t.Errorf("CountSet after Reset = %d, want 0", count)
		}
	})
}

func TestBitset_Clone(t *testing.T) {
	t.Run("clone copies data", func(t *testing.T) {
		bs := newBitset(100)
		bs.SetRange(10, 20)
		clone := bs.Clone()

		if clone.size != bs.size {
			t.Errorf("clone size = %d, want %d", clone.size, bs.size)
		}
		for i := uint16(10); i <= 20; i++ {
			if !clone.Test(i) {
				t.Errorf("clone bit %d should be set", i)
			}
		}
	})

	t.Run("clone is independent", func(t *testing.T) {
		bs := newBitset(100)
		bs.SetRange(10, 20)
		clone := bs.Clone()

		// Modify original
		bs.Clear(15)
		if !clone.Test(15) {
			t.Error("clone should not be affected by original modification")
		}

		// Modify clone
		clone.Set(50)
		if bs.Test(50) {
			t.Error("original should not be affected by clone modification")
		}
	})

	t.Run("clone empty bitset", func(t *testing.T) {
		bs := newBitset(100)
		clone := bs.Clone()
		if clone.CountSet() != 0 {
			t.Error("clone of empty bitset should have no bits set")
		}
	})
}

func TestBitset_WordIndex(t *testing.T) {
	bs := newBitset(200)

	tests := []struct {
		n            uint16
		expectedWord int
		expectedBit  uint64
	}{
		{0, 0, 1},
		{1, 0, 2},
		{63, 0, 1 << 63},
		{64, 1, 1},
		{65, 1, 2},
		{127, 1, 1 << 63},
		{128, 2, 1},
	}

	for _, tt := range tests {
		word, bit := bs.wordIndex(tt.n)
		if word != tt.expectedWord {
			t.Errorf("wordIndex(%d) word = %d, want %d", tt.n, word, tt.expectedWord)
		}
		if bit != tt.expectedBit {
			t.Errorf("wordIndex(%d) bit = %d, want %d", tt.n, bit, tt.expectedBit)
		}
	}
}

func TestPopcount(t *testing.T) {
	tests := []struct {
		x        uint64
		expected int
	}{
		{0, 0},
		{1, 1},
		{0xFF, 8},
		{0xFFFF, 16},
		{0xFFFFFFFF, 32},
		{0xFFFFFFFFFFFFFFFF, 64},
		{0xAAAAAAAAAAAAAAAA, 32}, // alternating bits
		{0x5555555555555555, 32}, // alternating bits
	}

	for _, tt := range tests {
		got := popcount(tt.x)
		if got != tt.expected {
			t.Errorf("popcount(0x%X) = %d, want %d", tt.x, got, tt.expected)
		}
	}
}

func TestBitset_ConcurrentSetClear(t *testing.T) {
	bs := newBitset(1000)
	var wg sync.WaitGroup
	concurrency := 100

	// Concurrent sets
	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				bit := uint16((idx*10 + j) % 1000)
				bs.Set(bit)
			}
		}(i)
	}
	wg.Wait()

	// Verify some bits are set
	if bs.CountSet() == 0 {
		t.Error("expected some bits to be set after concurrent operations")
	}

	// Concurrent clears
	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				bit := uint16((idx*10 + j) % 1000)
				bs.Clear(bit)
			}
		}(i)
	}
	wg.Wait()

	// After clearing all bits we set, count should be 0
	if count := bs.CountSet(); count != 0 {
		t.Errorf("CountSet after clear = %d, want 0", count)
	}
}

func TestBitset_ConcurrentSetAndTest(t *testing.T) {
	bs := newBitset(1000)
	var wg sync.WaitGroup
	concurrency := 50

	// Set bits
	for i := uint16(0); i < 500; i++ {
		bs.Set(i)
	}

	// Concurrent reads and writes
	wg.Add(concurrency * 2)

	// Writers
	for i := 0; i < concurrency; i++ {
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				bit := uint16((idx*20 + j) % 1000)
				if bit < 500 {
					bs.Clear(bit)
				} else {
					bs.Set(bit)
				}
			}
		}(i)
	}

	// Readers
	for i := 0; i < concurrency; i++ {
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				bit := uint16((idx*20 + j) % 1000)
				bs.Test(bit) // Just read, don't check result due to races
			}
		}(i)
	}

	wg.Wait()

	// Just ensure no panics and basic consistency
	set := bs.CountSet()
	clear := bs.CountClear()
	if set+clear != 1000 {
		t.Errorf("CountSet + CountClear = %d, want 1000", set+clear)
	}
}

func TestBitset_EdgeCases(t *testing.T) {
	t.Run("max VLAN bitset operations", func(t *testing.T) {
		bs := newBitset(int(MaxVLANID) + 1)

		// Set and test at boundaries
		bs.Set(0)
		bs.Set(MinVLANID)
		bs.Set(MaxVLANID)

		if !bs.Test(0) {
			t.Error("bit 0 should be set")
		}
		if !bs.Test(MinVLANID) {
			t.Error("MinVLANID bit should be set")
		}
		if !bs.Test(MaxVLANID) {
			t.Error("MaxVLANID bit should be set")
		}

		// Clear and verify
		bs.Clear(MinVLANID)
		if bs.Test(MinVLANID) {
			t.Error("MinVLANID bit should be clear")
		}
	})

	t.Run("set range at uint16 max prevention", func(t *testing.T) {
		// This tests the overflow prevention in SetRange
		bs := newBitset(100)
		bs.SetRange(90, 99)
		if count := bs.CountSet(); count != 10 {
			t.Errorf("CountSet = %d, want 10", count)
		}
	})

	t.Run("find in range with end at max", func(t *testing.T) {
		bs := newBitset(int(MaxVLANID) + 1)
		bs.SetRange(MinVLANID, MaxVLANID-1)
		pos, found := bs.FindFirstClear(MinVLANID, MaxVLANID)
		if !found || pos != MaxVLANID {
			t.Errorf("FindFirstClear = (%d, %v), want (%d, true)", pos, found, MaxVLANID)
		}
	})

	t.Run("find clear range with exact size remaining", func(t *testing.T) {
		bs := newBitset(100)
		bs.SetRange(0, 89)                         // 90 bits set
		pos, found := bs.FindClearRange(0, 99, 10) // exactly 10 remaining
		if !found || pos != 90 {
			t.Errorf("FindClearRange = (%d, %v), want (90, true)", pos, found)
		}
	})
}

func BenchmarkBitset_Set(b *testing.B) {
	bs := newBitset(int(MaxVLANID) + 1)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bs.Set(uint16(i % int(MaxVLANID)))
	}
}

func BenchmarkBitset_Test(b *testing.B) {
	bs := newBitset(int(MaxVLANID) + 1)
	bs.SetRange(0, MaxVLANID/2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bs.Test(uint16(i % int(MaxVLANID)))
	}
}

func BenchmarkBitset_FindClearRange(b *testing.B) {
	bs := newBitset(int(MaxVLANID) + 1)
	bs.SetRange(100, 199)
	bs.SetRange(300, 399)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bs.FindClearRange(100, 4000, 100)
	}
}

func BenchmarkBitset_CountSet(b *testing.B) {
	bs := newBitset(int(MaxVLANID) + 1)
	bs.SetRange(0, MaxVLANID/2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bs.CountSet()
	}
}
