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

package tpmnv

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckIndex_AcceptsNVRange(t *testing.T) {
	// The TCG EK certificate index sits inside the range; both ends are
	// inclusive.
	for _, index := range []uint32{IndexFirst, 0x01C00002, IndexLast} {
		assert.NoError(t, CheckIndex(index), "0x%08x", index)
	}
}

func TestCheckIndex_RejectsOtherHandleTypes(t *testing.T) {
	// 0 is the missing index; 0x00000017 a PCR; 0x81000001 a persistent
	// key; 0x02000000 a session. None of them is an NV index.
	for _, index := range []uint32{0, 0x00000017, IndexFirst - 1, IndexLast + 1, 0x81000001} {
		err := CheckIndex(index)
		var typed ErrIndexOutOfRange
		require.ErrorAs(t, err, &typed, "0x%08x", index)
		assert.Equal(t, index, typed.Index)
	}
}

func TestCheckSpan_AcceptsUpToMaxSpan(t *testing.T) {
	assert.NoError(t, CheckSpan(0, 0))
	assert.NoError(t, CheckSpan(0, MaxSpan))
	assert.NoError(t, CheckSpan(MaxSpan, 0))
	assert.NoError(t, CheckSpan(100, MaxSpan-100))
}

func TestCheckSpan_RejectsWrap(t *testing.T) {
	// Each of these would wrap the UINT16 offset NVRead/NVWrite carry.
	cases := []struct {
		offset uint32
		size   uint64
	}{
		{0, MaxSpan + 1},
		{MaxSpan, 1},
		{100, MaxSpan - 99},
		{^uint32(0), ^uint64(0) >> 1},
	}
	for _, tc := range cases {
		err := CheckSpan(tc.offset, tc.size)
		var typed ErrSpanTooLarge
		require.ErrorAs(t, err, &typed, "offset %d size %d", tc.offset, tc.size)
		assert.Equal(t, tc.offset, typed.Offset)
		assert.Equal(t, tc.size, typed.Size)
	}
}
