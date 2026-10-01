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

package openflow

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The golden bytes below were decoded by Open vSwitch 3.3's
// `ovs-ofctl parse-actions OpenFlow13` to exactly the grammar each comment
// names.

func TestActionRegLoadEncoding(t *testing.T) {
	tests := []struct {
		name          string
		register      uint8
		offset, nbits uint16
		value         uint64
		golden        string
	}{
		// load:0x1->NXM_NX_REG1[0]
		{"one bit", 1, 0, 1, 1, "ffff00180000232000070000000102040000000000000001"},
		// load:0x5->NXM_NX_REG2[3..6]
		{"a range", 2, 3, 4, 5, "ffff001800002320000700c3000104040000000000000005"},
		// load:0x7->NXM_NX_REG0[]
		{"the whole register", 0, 0, 32, 7, "ffff0018000023200007001f000100040000000000000007"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := NewActionRegLoad(tt.register, tt.offset, tt.nbits, tt.value)
			require.NoError(t, err)
			data, err := a.MarshalBinary()
			require.NoError(t, err)
			assert.Equal(t, tt.golden, hex.EncodeToString(data))
			assert.Equal(t, int(a.Length()), len(data))
		})
	}
}

func TestNewActionRegLoadRefuses(t *testing.T) {
	for name, args := range map[string]struct {
		register      uint8
		offset, nbits uint16
		value         uint64
	}{
		"register 16":           {16, 0, 1, 0},
		"zero bits":             {0, 0, 0, 0},
		"past bit 31":           {0, 30, 4, 0},
		"value wider than bits": {0, 0, 1, 2},
	} {
		_, err := NewActionRegLoad(args.register, args.offset, args.nbits, args.value)
		var msgErr *MessageError
		assert.ErrorAs(t, err, &msgErr, name)
	}
}

func TestActionResubmitEncoding(t *testing.T) {
	// The ovs-ofctl form is "resubmit(,20)".
	data, err := NewActionResubmit(20).MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, "ffff001000002320000efff814000000", hex.EncodeToString(data))

	// The ovs-ofctl form is "resubmit(3,28)": an explicit in_port.
	a := NewActionResubmit(28)
	a.InPort = 3
	data, err = a.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, "ffff001000002320000e00031c000000", hex.EncodeToString(data))
	assert.Equal(t, int(a.Length()), len(data))
}

func TestMatchAddReg(t *testing.T) {
	m := NewMatch()
	m.AddReg(1, 0, 1)
	require.Len(t, m.Fields, 1)
	f := m.Fields[0]
	assert.Equal(t, uint16(OFPXMCNxm1), f.Class)
	assert.Equal(t, uint8(1), f.Field)
	assert.True(t, f.HasMask)
	assert.Equal(t, []byte{0, 0, 0, 1}, f.Mask)

	full := NewMatch()
	full.AddReg(15, 7, 0xffffffff)
	assert.False(t, full.Fields[0].HasMask, "a whole-register match carries no mask")
	assert.Equal(t, uint32(0x00011e04), NXMHeaderReg(15))
}
