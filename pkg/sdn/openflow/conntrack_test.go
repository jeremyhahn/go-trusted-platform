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
	"bytes"
	"encoding/hex"
	"errors"
	"net/netip"
	"testing"
)

// mustHex decodes a hex string, failing the test on error
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	data, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("invalid hex string %q: %v", s, err)
	}
	return data
}

// TestActionCT_GoldenBytes verifies the NXAST_CT wire encoding against
// hand-derived byte sequences cross-checked with ovs-ofctl parse-actions.
func TestActionCT_GoldenBytes(t *testing.T) {
	tests := []struct {
		name   string
		action *ActionCT
		// Expected bytes, struct nx_action_conntrack:
		//   ofs 0:  type = OFPAT_EXPERIMENTER (0xffff)
		//   ofs 2:  len
		//   ofs 4:  vendor = NX_VENDOR_ID (0x00002320)
		//   ofs 8:  subtype = NXAST_CT (35 = 0x0023)
		//   ofs 10: flags
		//   ofs 12: zone_src (0 = immediate zone)
		//   ofs 16: zone_imm
		//   ofs 18: recirc_table
		//   ofs 19: pad[3]
		//   ofs 22: alg
		//   ofs 24: nested actions
		expected string
	}{
		{
			// ovs-ofctl parse-actions: ct(table=21,zone=5)
			name:   "plain ct with recirc table and zone",
			action: NewActionCT(0, 5, 21),
			// ffff | 0018 | 00002320 | 0023 | 0000 | 00000000 | 0005 | 15 | 000000 | 0000
			expected: "ffff0018000023200023000000000000000515000000" + "0000",
		},
		{
			// ovs-ofctl parse-actions: ct(commit,zone=5)
			name:   "ct commit with zone",
			action: NewActionCTCommit(5),
			// ffff | 0018 | 00002320 | 0023 | 0001 | 00000000 | 0005 | ff | 000000 | 0000
			expected: "ffff00180000232000230001000000000005ff000000" + "0000",
		},
		{
			// ovs-ofctl parse-actions: ct(commit,zone=7,nat(src=10.0.0.1:1024-65535))
			name: "ct commit with nested source NAT",
			action: NewActionCTCommit(7,
				NewActionNATSrc(netip.MustParseAddr("10.0.0.1"), netip.Addr{}, 1024, 65535)),
			// CT:  ffff | 0030 | 00002320 | 0023 | 0001 | 00000000 | 0007 | ff | 000000 | 0000
			// NAT: ffff | 0018 | 00002320 | 0024 | 0000(pad) | 0001(src) | 0031(ipv4min|pmin|pmax)
			//      | 0a000001(10.0.0.1) | 0400(1024) | ffff(65535)
			expected: "ffff00300000232000230001000000000007ff000000" + "0000" +
				"ffff0018000023200024" + "0000" + "0001" + "0031" + "0a000001" + "0400" + "ffff",
		},
		{
			// ovs-ofctl parse-actions: ct(commit,nat(dst=192.168.1.10:8080))
			name: "ct commit with nested destination NAT",
			action: NewActionCTCommit(0,
				NewActionNATDst(netip.MustParseAddr("192.168.1.10"), 8080)),
			// CT:  ffff | 0030 | 00002320 | 0023 | 0001 | 00000000 | 0000 | ff | 000000 | 0000
			// NAT: ffff | 0018 | 00002320 | 0024 | 0000(pad) | 0002(dst) | 0011(ipv4min|pmin)
			//      | c0a8010a(192.168.1.10) | 1f90(8080) | 0000(pad to 8)
			expected: "ffff00300000232000230001000000000000ff000000" + "0000" +
				"ffff0018000023200024" + "0000" + "0002" + "0011" + "c0a8010a" + "1f90" + "0000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.action.MarshalBinary()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			expected := mustHex(t, tt.expected)
			if !bytes.Equal(data, expected) {
				t.Errorf("encoding mismatch:\n  got:  %x\n  want: %x", data, expected)
			}

			assertActionAlignment(t, tt.action, data)
		})
	}
}

// TestActionNAT_GoldenBytes verifies the standalone NXAST_NAT wire encoding
func TestActionNAT_GoldenBytes(t *testing.T) {
	tests := []struct {
		name     string
		action   *ActionNAT
		expected string
	}{
		{
			name:   "source NAT single address with port range",
			action: NewActionNATSrc(netip.MustParseAddr("10.0.0.1"), netip.Addr{}, 1024, 65535),
			// ffff | 0018 | 00002320 | 0024 | 0000 | 0001 | 0031 | 0a000001 | 0400 | ffff
			expected: "ffff0018000023200024000000010031" + "0a000001" + "0400" + "ffff",
		},
		{
			name: "source NAT address range without ports",
			action: NewActionNATSrc(netip.MustParseAddr("10.0.0.1"),
				netip.MustParseAddr("10.0.0.9"), 0, 0),
			// range_present = ipv4 min | ipv4 max = 0x0003, 16+8 = 24 bytes, no pad
			expected: "ffff0018000023200024000000010003" + "0a000001" + "0a000009",
		},
		{
			name:   "destination NAT single address and port",
			action: NewActionNATDst(netip.MustParseAddr("192.168.1.10"), 8080),
			// range_present = ipv4 min | proto min = 0x0011, 16+6 = 22, pad to 24
			expected: "ffff0018000023200024000000020011" + "c0a8010a" + "1f90" + "0000",
		},
		{
			name:   "bare NAT with no ranges",
			action: &ActionNAT{Flags: NXNATFSrc},
			// fixed part only, already 8-aligned
			expected: "ffff0010000023200024000000010000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.action.MarshalBinary()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			expected := mustHex(t, tt.expected)
			if !bytes.Equal(data, expected) {
				t.Errorf("encoding mismatch:\n  got:  %x\n  want: %x", data, expected)
			}

			assertActionAlignment(t, tt.action, data)
		})
	}
}

// TestActionCTClear_GoldenBytes verifies the NXAST_CT_CLEAR wire encoding
func TestActionCTClear_GoldenBytes(t *testing.T) {
	action := NewActionCTClear()
	data, err := action.MarshalBinary()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// ovs-ofctl parse-actions: ct_clear
	// ffff | 0010 | 00002320 | 002b | 6 bytes pad
	expected := mustHex(t, "ffff001000002320002b000000000000")
	if !bytes.Equal(data, expected) {
		t.Errorf("encoding mismatch:\n  got:  %x\n  want: %x", data, expected)
	}

	assertActionAlignment(t, action, data)
}

// assertActionAlignment verifies the marshaled action is 8-byte aligned and
// that Length() and the encoded length field agree with the actual size
func assertActionAlignment(t *testing.T, action Action, data []byte) {
	t.Helper()

	if len(data)%8 != 0 {
		t.Errorf("action length %d is not a multiple of 8", len(data))
	}
	if int(action.Length()) != len(data) {
		t.Errorf("Length() = %d, marshaled size = %d", action.Length(), len(data))
	}
	if encoded := ByteOrder.Uint16(data[2:4]); int(encoded) != len(data) {
		t.Errorf("encoded length field = %d, marshaled size = %d", encoded, len(data))
	}
}

// TestActionCT_InvalidNestedAction verifies non-NAT/set-field nested actions are rejected
func TestActionCT_InvalidNestedAction(t *testing.T) {
	action := NewActionCTCommit(5, NewActionOutput(1, 0))
	if _, err := action.MarshalBinary(); !errors.Is(err, ErrInvalidAction) {
		t.Errorf("expected ErrInvalidAction, got %v", err)
	}
}

// TestActionCT_NestedSetField verifies set-field actions are legal inside ct
func TestActionCT_NestedSetField(t *testing.T) {
	markBytes := make([]byte, CTMarkLength)
	ByteOrder.PutUint32(markBytes, 0xaa)
	setMark := NewActionSetField(OFPXMCNxm1, NXMFieldCTMark, markBytes)

	action := NewActionCTCommit(5, setMark)
	data, err := action.MarshalBinary()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertActionAlignment(t, action, data)
}

// TestActionNAT_Invalid verifies NAT marshal error handling for bad inputs
func TestActionNAT_Invalid(t *testing.T) {
	tests := []struct {
		name   string
		action *ActionNAT
	}{
		{
			name:   "IPv6 range bits set",
			action: &ActionNAT{Flags: NXNATFSrc, RangePresent: NXNATRangeIPv6Min},
		},
		{
			name:   "IPv4 min bit with IPv6 address",
			action: NewActionNATSrc(netip.MustParseAddr("2001:db8::1"), netip.Addr{}, 0, 0),
		},
		{
			name: "IPv4 max bit with IPv6 address",
			action: NewActionNATSrc(netip.MustParseAddr("10.0.0.1"),
				netip.MustParseAddr("2001:db8::2"), 0, 0),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tt.action.MarshalBinary(); !errors.Is(err, ErrInvalidAction) {
				t.Errorf("expected ErrInvalidAction, got %v", err)
			}
		})
	}
}

// TestActionCT_NestedMarshalError verifies nested NAT marshal errors propagate
func TestActionCT_NestedMarshalError(t *testing.T) {
	bad := &ActionNAT{Flags: NXNATFSrc, RangePresent: NXNATRangeIPv6Min}
	action := NewActionCTCommit(5, bad)
	if _, err := action.MarshalBinary(); !errors.Is(err, ErrInvalidAction) {
		t.Errorf("expected ErrInvalidAction, got %v", err)
	}
}

// TestMatch_AddCTState verifies the masked ct_state OXM TLV encoding.
// Cross-checked with ovs-ofctl ofp-print: ct_state=+new+trk
func TestMatch_AddCTState(t *testing.T) {
	match := NewMatch()
	match.AddCTState(CTStateNew|CTStateTrk, CTStateNew|CTStateTrk)

	data, err := match.MarshalBinary()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Match header: type=OFPMT_OXM (0001), length=0x0010 (4 + 12)
	// OXM TLV: class=0001, field 105 with mask bit ((105<<1)|1 = 0xd3), len=8
	//          value=00000021 (+new|+trk), mask=00000021
	expected := mustHex(t, "00010010"+"0001d308"+"00000021"+"00000021")
	if !bytes.Equal(data, expected) {
		t.Errorf("encoding mismatch:\n  got:  %x\n  want: %x", data, expected)
	}
}

// TestMatch_AddCTZoneAndCTMark verifies the ct_zone and masked ct_mark OXM
// TLV encodings. Cross-checked with ovs-ofctl ofp-print:
// ct_zone=5,ct_mark=0xaa/0xff
func TestMatch_AddCTZoneAndCTMark(t *testing.T) {
	match := NewMatch()
	match.AddCTZone(5)
	match.AddCTMark(0xaa, 0xff)

	data, err := match.MarshalBinary()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Match header: type=0001, length=0x0016 (4 + 6 + 12), padded to 24
	// ct_zone TLV: class=0001, field 106 no mask (106<<1 = 0xd4), len=2, value=0005
	// ct_mark TLV: class=0001, field 107 with mask ((107<<1)|1 = 0xd7), len=8,
	//              value=000000aa, mask=000000ff
	expected := mustHex(t, "00010016"+"0001d402"+"0005"+"0001d708"+"000000aa"+"000000ff"+"0000")
	if !bytes.Equal(data, expected) {
		t.Errorf("encoding mismatch:\n  got:  %x\n  want: %x", data, expected)
	}
}

// TestFlowModBuilder_Conntrack verifies the builder conntrack match and
// action methods produce a well-formed FlowMod
func TestFlowModBuilder_Conntrack(t *testing.T) {
	flow := NewFlowModBuilder(100).
		SetTableID(20).
		MatchEthType(0x0800).
		MatchCTState(CTStateTrk|CTStateEst, CTStateTrk|CTStateEst).
		MatchCTZone(5).
		MatchCTMark(0xaa, 0xff).
		ActionCT(NewActionCTCommit(5, NewActionNATSrc(netip.MustParseAddr("10.0.0.1"), netip.Addr{}, 0, 0))).
		Build()

	if len(flow.Match.Fields) != 4 {
		t.Errorf("expected 4 match fields, got %d", len(flow.Match.Fields))
	}
	if len(flow.Instructions) != 1 {
		t.Fatalf("expected 1 instruction, got %d", len(flow.Instructions))
	}

	data, err := flow.MarshalBinary()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) != int(flow.Header.Length) {
		t.Errorf("marshaled size %d does not match header length %d", len(data), flow.Header.Length)
	}
}

// TestFlowModBuilder_ActionCTClear verifies the builder ct_clear action method
func TestFlowModBuilder_ActionCTClear(t *testing.T) {
	flow := NewFlowModBuilder(10).
		ActionCTClear().
		ActionOutput(2).
		Build()

	if len(flow.Instructions) != 1 {
		t.Fatalf("expected 1 instruction, got %d", len(flow.Instructions))
	}

	inst, ok := flow.Instructions[0].(*InstructionApplyActions)
	if !ok {
		t.Fatalf("expected apply-actions instruction, got %T", flow.Instructions[0])
	}
	if len(inst.Actions) != 2 {
		t.Fatalf("expected 2 actions, got %d", len(inst.Actions))
	}
	if _, ok := inst.Actions[0].(*ActionCTClear); !ok {
		t.Errorf("expected first action to be *ActionCTClear, got %T", inst.Actions[0])
	}
}

// TestNewActionCTCommit_Fields verifies the commit constructor defaults
func TestNewActionCTCommit_Fields(t *testing.T) {
	action := NewActionCTCommit(9)
	if action.Flags != NXCTFCommit {
		t.Errorf("expected flags %#x, got %#x", NXCTFCommit, action.Flags)
	}
	if action.Zone != 9 {
		t.Errorf("expected zone 9, got %d", action.Zone)
	}
	if action.RecircTable != CTRecircNone {
		t.Errorf("expected recirc table %#x, got %#x", CTRecircNone, action.RecircTable)
	}
}

// TestNATRangePresent verifies the range_present bit derivation edge cases
func TestNATRangePresent(t *testing.T) {
	tests := []struct {
		name     string
		action   *ActionNAT
		expected uint16
	}{
		{
			name:     "single address only min bit",
			action:   NewActionNATSrc(netip.MustParseAddr("10.0.0.1"), netip.Addr{}, 0, 0),
			expected: NXNATRangeIPv4Min,
		},
		{
			name:     "equal min and max collapses to min bit",
			action:   NewActionNATSrc(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.1"), 0, 0),
			expected: NXNATRangeIPv4Min,
		},
		{
			name:     "single port collapses to proto min bit",
			action:   NewActionNATSrc(netip.MustParseAddr("10.0.0.1"), netip.Addr{}, 80, 80),
			expected: NXNATRangeIPv4Min | NXNATRangeProtoMin,
		},
		{
			name:     "destination NAT without port",
			action:   NewActionNATDst(netip.MustParseAddr("10.0.0.2"), 0),
			expected: NXNATRangeIPv4Min,
		},
		{
			name:     "no address no port",
			action:   NewActionNATSrc(netip.Addr{}, netip.Addr{}, 0, 0),
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.action.RangePresent != tt.expected {
				t.Errorf("expected range_present %#x, got %#x", tt.expected, tt.action.RangePresent)
			}
		})
	}
}
