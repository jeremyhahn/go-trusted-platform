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
	"net/netip"
	"testing"
)

// TestTunnelMatch_NewTunnelMatch tests creating a new TunnelMatch
func TestTunnelMatch_NewTunnelMatch(t *testing.T) {
	tm := NewTunnelMatch()
	if tm == nil {
		t.Fatal("NewTunnelMatch returned nil")
	}
	if tm.TunnelID != 0 {
		t.Errorf("Expected TunnelID 0, got %d", tm.TunnelID)
	}
	if tm.TunnelIDMask != nil {
		t.Error("Expected TunnelIDMask to be nil")
	}
	if tm.TunSrc.IsValid() {
		t.Error("Expected TunSrc to be invalid")
	}
	if tm.TunDst.IsValid() {
		t.Error("Expected TunDst to be invalid")
	}
}

// TestTunnelMatch_SetTunnelID tests setting tunnel ID
func TestTunnelMatch_SetTunnelID(t *testing.T) {
	tm := NewTunnelMatch()
	vni := uint64(1000100)

	result := tm.SetTunnelID(vni)

	// Check fluent interface
	if result != tm {
		t.Error("SetTunnelID should return the same TunnelMatch for chaining")
	}

	if tm.TunnelID != vni {
		t.Errorf("Expected TunnelID %d, got %d", vni, tm.TunnelID)
	}
	if tm.TunnelIDMask != nil {
		t.Error("Expected TunnelIDMask to be nil for exact match")
	}
}

// TestTunnelMatch_SetTunnelIDMasked tests setting tunnel ID with mask
func TestTunnelMatch_SetTunnelIDMasked(t *testing.T) {
	tm := NewTunnelMatch()
	vni := uint64(1000100)
	mask := VXLANVNIMask

	result := tm.SetTunnelIDMasked(vni, mask)

	if result != tm {
		t.Error("SetTunnelIDMasked should return the same TunnelMatch for chaining")
	}

	if tm.TunnelID != vni {
		t.Errorf("Expected TunnelID %d, got %d", vni, tm.TunnelID)
	}
	if tm.TunnelIDMask == nil {
		t.Fatal("Expected TunnelIDMask to be set")
	}
	if *tm.TunnelIDMask != mask {
		t.Errorf("Expected mask 0x%x, got 0x%x", mask, *tm.TunnelIDMask)
	}
}

// TestTunnelMatch_SetTunSrc tests setting tunnel source IP
func TestTunnelMatch_SetTunSrc(t *testing.T) {
	tm := NewTunnelMatch()
	src := netip.MustParseAddr("10.0.0.1")

	result := tm.SetTunSrc(src)

	if result != tm {
		t.Error("SetTunSrc should return the same TunnelMatch for chaining")
	}

	if tm.TunSrc != src {
		t.Errorf("Expected TunSrc %v, got %v", src, tm.TunSrc)
	}
}

// TestTunnelMatch_SetTunDst tests setting tunnel destination IP
func TestTunnelMatch_SetTunDst(t *testing.T) {
	tm := NewTunnelMatch()
	dst := netip.MustParseAddr("10.0.0.2")

	result := tm.SetTunDst(dst)

	if result != tm {
		t.Error("SetTunDst should return the same TunnelMatch for chaining")
	}

	if tm.TunDst != dst {
		t.Errorf("Expected TunDst %v, got %v", dst, tm.TunDst)
	}
}

// TestTunnelMatch_Chaining tests fluent interface chaining
func TestTunnelMatch_Chaining(t *testing.T) {
	src := netip.MustParseAddr("10.0.0.1")
	dst := netip.MustParseAddr("10.0.0.2")
	vni := uint64(1000)

	tm := NewTunnelMatch().
		SetTunnelID(vni).
		SetTunSrc(src).
		SetTunDst(dst)

	if tm.TunnelID != vni {
		t.Errorf("Expected TunnelID %d, got %d", vni, tm.TunnelID)
	}
	if tm.TunSrc != src {
		t.Errorf("Expected TunSrc %v, got %v", src, tm.TunSrc)
	}
	if tm.TunDst != dst {
		t.Errorf("Expected TunDst %v, got %v", dst, tm.TunDst)
	}
}

// TestMatch_AddTunnelID tests adding tunnel ID to Match
func TestMatch_AddTunnelID(t *testing.T) {
	m := NewMatch()
	vni := uint64(1000100)

	m.AddTunnelID(vni)

	if len(m.Fields) != 1 {
		t.Fatalf("Expected 1 field, got %d", len(m.Fields))
	}

	field := m.Fields[0]
	if field.Class != OFPXMCNxm1 {
		t.Errorf("Expected class 0x%04x, got 0x%04x", OFPXMCNxm1, field.Class)
	}
	if field.Field != NXMFieldTunID {
		t.Errorf("Expected field %d, got %d", NXMFieldTunID, field.Field)
	}
	if field.HasMask {
		t.Error("Expected no mask for exact match")
	}
	if len(field.Value) != TunnelIDLength {
		t.Errorf("Expected value length %d, got %d", TunnelIDLength, len(field.Value))
	}

	// Verify the value
	decodedVNI := ByteOrder.Uint64(field.Value)
	if decodedVNI != vni {
		t.Errorf("Expected VNI %d, got %d", vni, decodedVNI)
	}
}

// TestMatch_AddTunnelIDMasked tests adding tunnel ID with mask to Match
func TestMatch_AddTunnelIDMasked(t *testing.T) {
	m := NewMatch()
	vni := uint64(1000100)
	mask := VXLANVNIMask

	m.AddTunnelIDMasked(vni, mask)

	if len(m.Fields) != 1 {
		t.Fatalf("Expected 1 field, got %d", len(m.Fields))
	}

	field := m.Fields[0]
	if field.Class != OFPXMCNxm1 {
		t.Errorf("Expected class 0x%04x, got 0x%04x", OFPXMCNxm1, field.Class)
	}
	if field.Field != NXMFieldTunID {
		t.Errorf("Expected field %d, got %d", NXMFieldTunID, field.Field)
	}
	if !field.HasMask {
		t.Error("Expected mask to be set")
	}
	if len(field.Value) != TunnelIDLength {
		t.Errorf("Expected value length %d, got %d", TunnelIDLength, len(field.Value))
	}
	if len(field.Mask) != TunnelIDLength {
		t.Errorf("Expected mask length %d, got %d", TunnelIDLength, len(field.Mask))
	}

	// Verify values
	decodedVNI := ByteOrder.Uint64(field.Value)
	if decodedVNI != vni {
		t.Errorf("Expected VNI %d, got %d", vni, decodedVNI)
	}
	decodedMask := ByteOrder.Uint64(field.Mask)
	if decodedMask != mask {
		t.Errorf("Expected mask 0x%x, got 0x%x", mask, decodedMask)
	}
}

// TestMatch_AddTunIPv4Src tests adding tunnel source IPv4
func TestMatch_AddTunIPv4Src(t *testing.T) {
	m := NewMatch()
	src := netip.MustParseAddr("192.168.1.100")

	m.AddTunIPv4Src(src)

	if len(m.Fields) != 1 {
		t.Fatalf("Expected 1 field, got %d", len(m.Fields))
	}

	field := m.Fields[0]
	if field.Class != OFPXMCNxm1 {
		t.Errorf("Expected class 0x%04x, got 0x%04x", OFPXMCNxm1, field.Class)
	}
	if field.Field != NXMFieldTunIPv4Src {
		t.Errorf("Expected field %d, got %d", NXMFieldTunIPv4Src, field.Field)
	}
	if field.HasMask {
		t.Error("Expected no mask")
	}

	// Verify IP
	expectedIP := src.As4()
	if !bytes.Equal(field.Value, expectedIP[:]) {
		t.Errorf("Expected IP %v, got %v", expectedIP[:], field.Value)
	}
}

// TestMatch_AddTunIPv4Src_InvalidIP tests adding non-IPv4 to tunnel source
func TestMatch_AddTunIPv4Src_InvalidIP(t *testing.T) {
	m := NewMatch()
	// Use IPv6 address which should be rejected
	src := netip.MustParseAddr("::1")

	m.AddTunIPv4Src(src)

	// Should not add any field for non-IPv4
	if len(m.Fields) != 0 {
		t.Errorf("Expected 0 fields for non-IPv4, got %d", len(m.Fields))
	}
}

// TestMatch_AddTunIPv4SrcMasked tests adding tunnel source with mask
func TestMatch_AddTunIPv4SrcMasked(t *testing.T) {
	m := NewMatch()
	src := netip.MustParseAddr("192.168.1.0")
	mask := netip.MustParseAddr("255.255.255.0")

	m.AddTunIPv4SrcMasked(src, mask)

	if len(m.Fields) != 1 {
		t.Fatalf("Expected 1 field, got %d", len(m.Fields))
	}

	field := m.Fields[0]
	if !field.HasMask {
		t.Error("Expected mask to be set")
	}
	if len(field.Mask) != TunnelIPv4Length {
		t.Errorf("Expected mask length %d, got %d", TunnelIPv4Length, len(field.Mask))
	}
}

// TestMatch_AddTunIPv4SrcMasked_InvalidIP tests masked match with invalid IPs
func TestMatch_AddTunIPv4SrcMasked_InvalidIP(t *testing.T) {
	m := NewMatch()
	src := netip.MustParseAddr("192.168.1.0")
	mask := netip.MustParseAddr("::1") // IPv6 mask

	m.AddTunIPv4SrcMasked(src, mask)

	// Should not add field when mask is not IPv4
	if len(m.Fields) != 0 {
		t.Errorf("Expected 0 fields for non-IPv4 mask, got %d", len(m.Fields))
	}
}

// TestMatch_AddTunIPv4Dst tests adding tunnel destination IPv4
func TestMatch_AddTunIPv4Dst(t *testing.T) {
	m := NewMatch()
	dst := netip.MustParseAddr("10.0.0.100")

	m.AddTunIPv4Dst(dst)

	if len(m.Fields) != 1 {
		t.Fatalf("Expected 1 field, got %d", len(m.Fields))
	}

	field := m.Fields[0]
	if field.Class != OFPXMCNxm1 {
		t.Errorf("Expected class 0x%04x, got 0x%04x", OFPXMCNxm1, field.Class)
	}
	if field.Field != NXMFieldTunIPv4Dst {
		t.Errorf("Expected field %d, got %d", NXMFieldTunIPv4Dst, field.Field)
	}
}

// TestMatch_AddTunIPv4Dst_InvalidIP tests adding non-IPv4 to tunnel destination
func TestMatch_AddTunIPv4Dst_InvalidIP(t *testing.T) {
	m := NewMatch()
	dst := netip.MustParseAddr("2001:db8::1")

	m.AddTunIPv4Dst(dst)

	if len(m.Fields) != 0 {
		t.Errorf("Expected 0 fields for non-IPv4, got %d", len(m.Fields))
	}
}

// TestMatch_AddTunIPv4DstMasked tests adding tunnel destination with mask
func TestMatch_AddTunIPv4DstMasked(t *testing.T) {
	m := NewMatch()
	dst := netip.MustParseAddr("10.0.0.0")
	mask := netip.MustParseAddr("255.255.0.0")

	m.AddTunIPv4DstMasked(dst, mask)

	if len(m.Fields) != 1 {
		t.Fatalf("Expected 1 field, got %d", len(m.Fields))
	}

	field := m.Fields[0]
	if !field.HasMask {
		t.Error("Expected mask to be set")
	}
}

// TestMatch_AddTunIPv4DstMasked_InvalidMask tests masked match with invalid mask
func TestMatch_AddTunIPv4DstMasked_InvalidMask(t *testing.T) {
	m := NewMatch()
	dst := netip.MustParseAddr("10.0.0.0")
	mask := netip.MustParseAddr("fe80::1") // IPv6 mask

	m.AddTunIPv4DstMasked(dst, mask)

	if len(m.Fields) != 0 {
		t.Errorf("Expected 0 fields for non-IPv4 mask, got %d", len(m.Fields))
	}
}

// TestActionSetTunnelID_New tests creating a new ActionSetTunnelID
func TestActionSetTunnelID_New(t *testing.T) {
	vni := uint64(1000100)
	action := NewActionSetTunnelID(vni)

	if action == nil {
		t.Fatal("NewActionSetTunnelID returned nil")
	}
	if action.TunnelID != vni {
		t.Errorf("Expected TunnelID %d, got %d", vni, action.TunnelID)
	}
}

// TestActionSetTunnelID_Length tests the action length
func TestActionSetTunnelID_Length(t *testing.T) {
	action := NewActionSetTunnelID(1000)

	length := action.Length()
	if length != 16 {
		t.Errorf("Expected length 16, got %d", length)
	}
}

// TestActionSetTunnelID_MarshalBinary tests encoding the action
func TestActionSetTunnelID_MarshalBinary(t *testing.T) {
	vni := uint64(1000100)
	action := NewActionSetTunnelID(vni)

	data, err := action.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	if len(data) != 16 {
		t.Errorf("Expected length 16, got %d", len(data))
	}

	// Verify action type
	actionType := ByteOrder.Uint16(data[0:2])
	if actionType != OFPATSetField {
		t.Errorf("Expected action type %d, got %d", OFPATSetField, actionType)
	}

	// Verify action length
	actionLen := ByteOrder.Uint16(data[2:4])
	if actionLen != 16 {
		t.Errorf("Expected action length 16, got %d", actionLen)
	}

	// Verify OXM class
	oxmClass := ByteOrder.Uint16(data[4:6])
	if oxmClass != OFPXMCNxm1 {
		t.Errorf("Expected OXM class 0x%04x, got 0x%04x", OFPXMCNxm1, oxmClass)
	}

	// Verify OXM field
	oxmFieldAndMask := data[6]
	expectedField := NXMFieldTunID << 1
	if oxmFieldAndMask != expectedField {
		t.Errorf("Expected OXM field 0x%02x, got 0x%02x", expectedField, oxmFieldAndMask)
	}

	// Verify OXM length
	oxmLen := data[7]
	if oxmLen != TunnelIDLength {
		t.Errorf("Expected OXM length %d, got %d", TunnelIDLength, oxmLen)
	}

	// Verify tunnel ID value
	decodedVNI := ByteOrder.Uint64(data[8:16])
	if decodedVNI != vni {
		t.Errorf("Expected VNI %d, got %d", vni, decodedVNI)
	}
}

// TestActionSetTunDst_New tests creating a new ActionSetTunDst
func TestActionSetTunDst_New(t *testing.T) {
	dst := netip.MustParseAddr("10.0.0.100")
	action := NewActionSetTunDst(dst)

	if action == nil {
		t.Fatal("NewActionSetTunDst returned nil")
	}
	if action.IPv4 != dst {
		t.Errorf("Expected IPv4 %v, got %v", dst, action.IPv4)
	}
}

// TestActionSetTunDst_Length tests the action length
func TestActionSetTunDst_Length(t *testing.T) {
	action := NewActionSetTunDst(netip.MustParseAddr("10.0.0.1"))

	length := action.Length()
	if length != 16 {
		t.Errorf("Expected length 16, got %d", length)
	}
}

// TestActionSetTunDst_MarshalBinary tests encoding the action
func TestActionSetTunDst_MarshalBinary(t *testing.T) {
	dst := netip.MustParseAddr("192.168.1.100")
	action := NewActionSetTunDst(dst)

	data, err := action.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	if len(data) != 16 {
		t.Errorf("Expected length 16, got %d", len(data))
	}

	// Verify action type
	actionType := ByteOrder.Uint16(data[0:2])
	if actionType != OFPATSetField {
		t.Errorf("Expected action type %d, got %d", OFPATSetField, actionType)
	}

	// Verify OXM field
	oxmFieldAndMask := data[6]
	expectedField := NXMFieldTunIPv4Dst << 1
	if oxmFieldAndMask != expectedField {
		t.Errorf("Expected OXM field 0x%02x, got 0x%02x", expectedField, oxmFieldAndMask)
	}

	// Verify IP address
	expectedIP := dst.As4()
	if !bytes.Equal(data[8:12], expectedIP[:]) {
		t.Errorf("Expected IP %v, got %v", expectedIP[:], data[8:12])
	}
}

// TestActionSetTunDst_MarshalBinary_InvalidIP tests encoding with non-IPv4
func TestActionSetTunDst_MarshalBinary_InvalidIP(t *testing.T) {
	dst := netip.MustParseAddr("::1")
	action := NewActionSetTunDst(dst)

	_, err := action.MarshalBinary()
	if err != ErrInvalidAction {
		t.Errorf("Expected ErrInvalidAction, got %v", err)
	}
}

// TestActionSetTunSrc_New tests creating a new ActionSetTunSrc
func TestActionSetTunSrc_New(t *testing.T) {
	src := netip.MustParseAddr("10.0.0.1")
	action := NewActionSetTunSrc(src)

	if action == nil {
		t.Fatal("NewActionSetTunSrc returned nil")
	}
	if action.IPv4 != src {
		t.Errorf("Expected IPv4 %v, got %v", src, action.IPv4)
	}
}

// TestActionSetTunSrc_Length tests the action length
func TestActionSetTunSrc_Length(t *testing.T) {
	action := NewActionSetTunSrc(netip.MustParseAddr("10.0.0.1"))

	length := action.Length()
	if length != 16 {
		t.Errorf("Expected length 16, got %d", length)
	}
}

// TestActionSetTunSrc_MarshalBinary tests encoding the action
func TestActionSetTunSrc_MarshalBinary(t *testing.T) {
	src := netip.MustParseAddr("172.16.0.1")
	action := NewActionSetTunSrc(src)

	data, err := action.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	if len(data) != 16 {
		t.Errorf("Expected length 16, got %d", len(data))
	}

	// Verify OXM field
	oxmFieldAndMask := data[6]
	expectedField := NXMFieldTunIPv4Src << 1
	if oxmFieldAndMask != expectedField {
		t.Errorf("Expected OXM field 0x%02x, got 0x%02x", expectedField, oxmFieldAndMask)
	}

	// Verify IP address
	expectedIP := src.As4()
	if !bytes.Equal(data[8:12], expectedIP[:]) {
		t.Errorf("Expected IP %v, got %v", expectedIP[:], data[8:12])
	}
}

// TestActionSetTunSrc_MarshalBinary_InvalidIP tests encoding with non-IPv4
func TestActionSetTunSrc_MarshalBinary_InvalidIP(t *testing.T) {
	src := netip.MustParseAddr("2001:db8::1")
	action := NewActionSetTunSrc(src)

	_, err := action.MarshalBinary()
	if err != ErrInvalidAction {
		t.Errorf("Expected ErrInvalidAction, got %v", err)
	}
}

// TestFlowModBuilder_Basic tests basic FlowModBuilder usage
func TestFlowModBuilder_Basic(t *testing.T) {
	builder := NewFlowModBuilder(100)

	if builder == nil {
		t.Fatal("NewFlowModBuilder returned nil")
	}

	fm := builder.Build()
	if fm == nil {
		t.Fatal("Build returned nil")
	}
	if fm.Priority != 100 {
		t.Errorf("Expected priority 100, got %d", fm.Priority)
	}
}

// TestFlowModBuilder_SetTableID tests setting table ID
func TestFlowModBuilder_SetTableID(t *testing.T) {
	builder := NewFlowModBuilder(100).SetTableID(5)
	fm := builder.Build()

	if fm.TableID != 5 {
		t.Errorf("Expected TableID 5, got %d", fm.TableID)
	}
}

// TestFlowModBuilder_SetCookie tests setting cookie
func TestFlowModBuilder_SetCookie(t *testing.T) {
	cookie := uint64(0xDEADBEEF)
	builder := NewFlowModBuilder(100).SetCookie(cookie)
	fm := builder.Build()

	if fm.Cookie != cookie {
		t.Errorf("Expected Cookie 0x%x, got 0x%x", cookie, fm.Cookie)
	}
}

// TestFlowModBuilder_SetTimeouts tests setting timeouts
func TestFlowModBuilder_SetTimeouts(t *testing.T) {
	builder := NewFlowModBuilder(100).
		SetIdleTimeout(300).
		SetHardTimeout(600)
	fm := builder.Build()

	if fm.IdleTimeout != 300 {
		t.Errorf("Expected IdleTimeout 300, got %d", fm.IdleTimeout)
	}
	if fm.HardTimeout != 600 {
		t.Errorf("Expected HardTimeout 600, got %d", fm.HardTimeout)
	}
}

// TestFlowModBuilder_SetFlags tests setting flags
func TestFlowModBuilder_SetFlags(t *testing.T) {
	flags := uint16(OFPFFSendFlowRem | OFPFFCheckOverlap)
	builder := NewFlowModBuilder(100).SetFlags(flags)
	fm := builder.Build()

	if fm.Flags != flags {
		t.Errorf("Expected Flags 0x%x, got 0x%x", flags, fm.Flags)
	}
}

// TestFlowModBuilder_MatchInPort tests matching input port
func TestFlowModBuilder_MatchInPort(t *testing.T) {
	builder := NewFlowModBuilder(100).MatchInPort(1)
	fm := builder.Build()

	if len(fm.Match.Fields) != 1 {
		t.Errorf("Expected 1 match field, got %d", len(fm.Match.Fields))
	}
}

// TestFlowModBuilder_MatchTunnelID tests matching tunnel ID
func TestFlowModBuilder_MatchTunnelID(t *testing.T) {
	vni := uint64(1000100)
	builder := NewFlowModBuilder(100).MatchTunnelID(vni)
	fm := builder.Build()

	if len(fm.Match.Fields) != 1 {
		t.Fatalf("Expected 1 match field, got %d", len(fm.Match.Fields))
	}

	field := fm.Match.Fields[0]
	if field.Class != OFPXMCNxm1 {
		t.Errorf("Expected class 0x%04x, got 0x%04x", OFPXMCNxm1, field.Class)
	}
	if field.Field != NXMFieldTunID {
		t.Errorf("Expected field %d, got %d", NXMFieldTunID, field.Field)
	}
}

// TestFlowModBuilder_MatchTunnelIDMasked tests matching tunnel ID with mask
func TestFlowModBuilder_MatchTunnelIDMasked(t *testing.T) {
	vni := uint64(1000000)
	mask := uint64(0xFFFF00)
	builder := NewFlowModBuilder(100).MatchTunnelIDMasked(vni, mask)
	fm := builder.Build()

	if len(fm.Match.Fields) != 1 {
		t.Fatalf("Expected 1 match field, got %d", len(fm.Match.Fields))
	}

	field := fm.Match.Fields[0]
	if !field.HasMask {
		t.Error("Expected mask to be set")
	}
}

// TestFlowModBuilder_MatchTunSrc tests matching tunnel source
func TestFlowModBuilder_MatchTunSrc(t *testing.T) {
	src := netip.MustParseAddr("10.0.0.1")
	builder := NewFlowModBuilder(100).MatchTunSrc(src)
	fm := builder.Build()

	if len(fm.Match.Fields) != 1 {
		t.Fatalf("Expected 1 match field, got %d", len(fm.Match.Fields))
	}

	field := fm.Match.Fields[0]
	if field.Field != NXMFieldTunIPv4Src {
		t.Errorf("Expected field %d, got %d", NXMFieldTunIPv4Src, field.Field)
	}
}

// TestFlowModBuilder_MatchTunDst tests matching tunnel destination
func TestFlowModBuilder_MatchTunDst(t *testing.T) {
	dst := netip.MustParseAddr("10.0.0.2")
	builder := NewFlowModBuilder(100).MatchTunDst(dst)
	fm := builder.Build()

	if len(fm.Match.Fields) != 1 {
		t.Fatalf("Expected 1 match field, got %d", len(fm.Match.Fields))
	}

	field := fm.Match.Fields[0]
	if field.Field != NXMFieldTunIPv4Dst {
		t.Errorf("Expected field %d, got %d", NXMFieldTunIPv4Dst, field.Field)
	}
}

// TestFlowModBuilder_MatchTunSrcMasked tests matching tunnel source with mask
func TestFlowModBuilder_MatchTunSrcMasked(t *testing.T) {
	src := netip.MustParseAddr("10.0.0.0")
	mask := netip.MustParseAddr("255.255.255.0")
	builder := NewFlowModBuilder(100).MatchTunSrcMasked(src, mask)
	fm := builder.Build()

	if len(fm.Match.Fields) != 1 {
		t.Fatalf("Expected 1 match field, got %d", len(fm.Match.Fields))
	}

	field := fm.Match.Fields[0]
	if !field.HasMask {
		t.Error("Expected mask to be set")
	}
}

// TestFlowModBuilder_MatchTunDstMasked tests matching tunnel destination with mask
func TestFlowModBuilder_MatchTunDstMasked(t *testing.T) {
	dst := netip.MustParseAddr("172.16.0.0")
	mask := netip.MustParseAddr("255.255.0.0")
	builder := NewFlowModBuilder(100).MatchTunDstMasked(dst, mask)
	fm := builder.Build()

	if len(fm.Match.Fields) != 1 {
		t.Fatalf("Expected 1 match field, got %d", len(fm.Match.Fields))
	}

	field := fm.Match.Fields[0]
	if !field.HasMask {
		t.Error("Expected mask to be set")
	}
}

// TestFlowModBuilder_MatchEthType tests matching EtherType
func TestFlowModBuilder_MatchEthType(t *testing.T) {
	builder := NewFlowModBuilder(100).MatchEthType(0x0800)
	fm := builder.Build()

	if len(fm.Match.Fields) != 1 {
		t.Errorf("Expected 1 match field, got %d", len(fm.Match.Fields))
	}
}

// TestFlowModBuilder_MatchEthDst tests matching Ethernet destination
func TestFlowModBuilder_MatchEthDst(t *testing.T) {
	mac := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	builder := NewFlowModBuilder(100).MatchEthDst(mac)
	fm := builder.Build()

	if len(fm.Match.Fields) != 1 {
		t.Errorf("Expected 1 match field, got %d", len(fm.Match.Fields))
	}
}

// TestFlowModBuilder_MatchEthSrc tests matching Ethernet source
func TestFlowModBuilder_MatchEthSrc(t *testing.T) {
	mac := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	builder := NewFlowModBuilder(100).MatchEthSrc(mac)
	fm := builder.Build()

	if len(fm.Match.Fields) != 1 {
		t.Errorf("Expected 1 match field, got %d", len(fm.Match.Fields))
	}
}

// TestFlowModBuilder_MatchVLANVid tests matching VLAN ID
func TestFlowModBuilder_MatchVLANVid(t *testing.T) {
	builder := NewFlowModBuilder(100).MatchVLANVid(100)
	fm := builder.Build()

	if len(fm.Match.Fields) != 1 {
		t.Errorf("Expected 1 match field, got %d", len(fm.Match.Fields))
	}
}

// TestFlowModBuilder_MatchIPv4Src tests matching IPv4 source
func TestFlowModBuilder_MatchIPv4Src(t *testing.T) {
	src := netip.MustParseAddr("192.168.1.1")
	builder := NewFlowModBuilder(100).MatchIPv4Src(src)
	fm := builder.Build()

	if len(fm.Match.Fields) != 1 {
		t.Errorf("Expected 1 match field, got %d", len(fm.Match.Fields))
	}
}

// TestFlowModBuilder_MatchIPv4Src_NonIPv4 tests matching with non-IPv4
func TestFlowModBuilder_MatchIPv4Src_NonIPv4(t *testing.T) {
	src := netip.MustParseAddr("::1")
	builder := NewFlowModBuilder(100).MatchIPv4Src(src)
	fm := builder.Build()

	// Should not add field for non-IPv4
	if len(fm.Match.Fields) != 0 {
		t.Errorf("Expected 0 match fields for non-IPv4, got %d", len(fm.Match.Fields))
	}
}

// TestFlowModBuilder_MatchIPv4Dst tests matching IPv4 destination
func TestFlowModBuilder_MatchIPv4Dst(t *testing.T) {
	dst := netip.MustParseAddr("10.0.0.1")
	builder := NewFlowModBuilder(100).MatchIPv4Dst(dst)
	fm := builder.Build()

	if len(fm.Match.Fields) != 1 {
		t.Errorf("Expected 1 match field, got %d", len(fm.Match.Fields))
	}
}

// TestFlowModBuilder_MatchIPv4Dst_NonIPv4 tests matching with non-IPv4
func TestFlowModBuilder_MatchIPv4Dst_NonIPv4(t *testing.T) {
	dst := netip.MustParseAddr("2001:db8::1")
	builder := NewFlowModBuilder(100).MatchIPv4Dst(dst)
	fm := builder.Build()

	if len(fm.Match.Fields) != 0 {
		t.Errorf("Expected 0 match fields for non-IPv4, got %d", len(fm.Match.Fields))
	}
}

// TestFlowModBuilder_ActionSetTunnelID tests adding set tunnel ID action
func TestFlowModBuilder_ActionSetTunnelID(t *testing.T) {
	vni := uint64(1000100)
	builder := NewFlowModBuilder(100).ActionSetTunnelID(vni)
	fm := builder.Build()

	if len(fm.Instructions) != 1 {
		t.Fatalf("Expected 1 instruction, got %d", len(fm.Instructions))
	}

	applyActions, ok := fm.Instructions[0].(*InstructionApplyActions)
	if !ok {
		t.Fatal("Expected InstructionApplyActions")
	}
	if len(applyActions.Actions) != 1 {
		t.Fatalf("Expected 1 action, got %d", len(applyActions.Actions))
	}

	action, ok := applyActions.Actions[0].(*ActionSetTunnelID)
	if !ok {
		t.Fatal("Expected ActionSetTunnelID")
	}
	if action.TunnelID != vni {
		t.Errorf("Expected TunnelID %d, got %d", vni, action.TunnelID)
	}
}

// TestFlowModBuilder_ActionSetTunDst tests adding set tunnel destination action
func TestFlowModBuilder_ActionSetTunDst(t *testing.T) {
	dst := netip.MustParseAddr("10.0.0.100")
	builder := NewFlowModBuilder(100).ActionSetTunDst(dst)
	fm := builder.Build()

	if len(fm.Instructions) != 1 {
		t.Fatalf("Expected 1 instruction, got %d", len(fm.Instructions))
	}

	applyActions, ok := fm.Instructions[0].(*InstructionApplyActions)
	if !ok {
		t.Fatal("Expected InstructionApplyActions")
	}
	if len(applyActions.Actions) != 1 {
		t.Fatalf("Expected 1 action, got %d", len(applyActions.Actions))
	}

	action, ok := applyActions.Actions[0].(*ActionSetTunDst)
	if !ok {
		t.Fatal("Expected ActionSetTunDst")
	}
	if action.IPv4 != dst {
		t.Errorf("Expected IPv4 %v, got %v", dst, action.IPv4)
	}
}

// TestFlowModBuilder_ActionSetTunSrc tests adding set tunnel source action
func TestFlowModBuilder_ActionSetTunSrc(t *testing.T) {
	src := netip.MustParseAddr("10.0.0.1")
	builder := NewFlowModBuilder(100).ActionSetTunSrc(src)
	fm := builder.Build()

	if len(fm.Instructions) != 1 {
		t.Fatalf("Expected 1 instruction, got %d", len(fm.Instructions))
	}

	applyActions, ok := fm.Instructions[0].(*InstructionApplyActions)
	if !ok {
		t.Fatal("Expected InstructionApplyActions")
	}

	action, ok := applyActions.Actions[0].(*ActionSetTunSrc)
	if !ok {
		t.Fatal("Expected ActionSetTunSrc")
	}
	if action.IPv4 != src {
		t.Errorf("Expected IPv4 %v, got %v", src, action.IPv4)
	}
}

// TestFlowModBuilder_ActionOutput tests adding output action
func TestFlowModBuilder_ActionOutput(t *testing.T) {
	builder := NewFlowModBuilder(100).ActionOutput(1)
	fm := builder.Build()

	if len(fm.Instructions) != 1 {
		t.Fatalf("Expected 1 instruction, got %d", len(fm.Instructions))
	}

	applyActions, ok := fm.Instructions[0].(*InstructionApplyActions)
	if !ok {
		t.Fatal("Expected InstructionApplyActions")
	}

	action, ok := applyActions.Actions[0].(*ActionOutput)
	if !ok {
		t.Fatal("Expected ActionOutput")
	}
	if action.Port != 1 {
		t.Errorf("Expected port 1, got %d", action.Port)
	}
}

// TestFlowModBuilder_ActionOutputController tests output to controller
func TestFlowModBuilder_ActionOutputController(t *testing.T) {
	builder := NewFlowModBuilder(100).ActionOutputController(128)
	fm := builder.Build()

	if len(fm.Instructions) != 1 {
		t.Fatalf("Expected 1 instruction, got %d", len(fm.Instructions))
	}

	applyActions, ok := fm.Instructions[0].(*InstructionApplyActions)
	if !ok {
		t.Fatal("Expected InstructionApplyActions")
	}

	action, ok := applyActions.Actions[0].(*ActionOutput)
	if !ok {
		t.Fatal("Expected ActionOutput")
	}
	if action.Port != OFPPController {
		t.Errorf("Expected port %d, got %d", OFPPController, action.Port)
	}
	if action.MaxLen != 128 {
		t.Errorf("Expected MaxLen 128, got %d", action.MaxLen)
	}
}

// TestFlowModBuilder_ActionPushVLAN tests push VLAN action
func TestFlowModBuilder_ActionPushVLAN(t *testing.T) {
	builder := NewFlowModBuilder(100).ActionPushVLAN(0x8100)
	fm := builder.Build()

	if len(fm.Instructions) != 1 {
		t.Fatalf("Expected 1 instruction, got %d", len(fm.Instructions))
	}

	applyActions, ok := fm.Instructions[0].(*InstructionApplyActions)
	if !ok {
		t.Fatal("Expected InstructionApplyActions")
	}

	action, ok := applyActions.Actions[0].(*ActionPushVLAN)
	if !ok {
		t.Fatal("Expected ActionPushVLAN")
	}
	if action.EtherType != 0x8100 {
		t.Errorf("Expected EtherType 0x8100, got 0x%04x", action.EtherType)
	}
}

// TestFlowModBuilder_ActionPopVLAN tests pop VLAN action
func TestFlowModBuilder_ActionPopVLAN(t *testing.T) {
	builder := NewFlowModBuilder(100).ActionPopVLAN()
	fm := builder.Build()

	if len(fm.Instructions) != 1 {
		t.Fatalf("Expected 1 instruction, got %d", len(fm.Instructions))
	}

	applyActions, ok := fm.Instructions[0].(*InstructionApplyActions)
	if !ok {
		t.Fatal("Expected InstructionApplyActions")
	}

	_, ok = applyActions.Actions[0].(*ActionPopVLAN)
	if !ok {
		t.Fatal("Expected ActionPopVLAN")
	}
}

// TestFlowModBuilder_GotoTable tests goto table instruction
func TestFlowModBuilder_GotoTable(t *testing.T) {
	builder := NewFlowModBuilder(100).GotoTable(10)
	fm := builder.Build()

	if len(fm.Instructions) != 1 {
		t.Fatalf("Expected 1 instruction, got %d", len(fm.Instructions))
	}

	gotoTable, ok := fm.Instructions[0].(*InstructionGotoTable)
	if !ok {
		t.Fatal("Expected InstructionGotoTable")
	}
	if gotoTable.TableID != 10 {
		t.Errorf("Expected TableID 10, got %d", gotoTable.TableID)
	}
}

// TestFlowModBuilder_ComplexFlow tests building a complex flow
func TestFlowModBuilder_ComplexFlow(t *testing.T) {
	// Build a VXLAN decap flow
	remoteVTEP := netip.MustParseAddr("10.0.0.100")
	vni := uint64(1000100)

	builder := NewFlowModBuilder(100).
		SetTableID(0).
		SetCookie(0x12345678).
		SetIdleTimeout(300).
		MatchTunnelID(vni).
		MatchTunSrc(remoteVTEP).
		ActionOutput(1)

	fm := builder.Build()

	if fm.Priority != 100 {
		t.Errorf("Expected priority 100, got %d", fm.Priority)
	}
	if fm.TableID != 0 {
		t.Errorf("Expected TableID 0, got %d", fm.TableID)
	}
	if fm.Cookie != 0x12345678 {
		t.Errorf("Expected Cookie 0x12345678, got 0x%x", fm.Cookie)
	}
	if fm.IdleTimeout != 300 {
		t.Errorf("Expected IdleTimeout 300, got %d", fm.IdleTimeout)
	}
	if len(fm.Match.Fields) != 2 {
		t.Errorf("Expected 2 match fields, got %d", len(fm.Match.Fields))
	}
	if len(fm.Instructions) != 1 {
		t.Errorf("Expected 1 instruction, got %d", len(fm.Instructions))
	}
}

// TestFlowModBuilder_VXLANEncap tests building a VXLAN encap flow
func TestFlowModBuilder_VXLANEncap(t *testing.T) {
	remoteVTEP := netip.MustParseAddr("10.0.0.200")
	localVTEP := netip.MustParseAddr("10.0.0.1")
	vni := uint64(1000100)
	remoteMac := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}

	builder := NewFlowModBuilder(100).
		MatchInPort(1).
		MatchEthDst(remoteMac).
		ActionSetTunnelID(vni).
		ActionSetTunSrc(localVTEP).
		ActionSetTunDst(remoteVTEP).
		ActionOutput(100) // tunnel port

	fm := builder.Build()

	// Verify match fields
	if len(fm.Match.Fields) != 2 {
		t.Errorf("Expected 2 match fields, got %d", len(fm.Match.Fields))
	}

	// Verify instructions
	if len(fm.Instructions) != 1 {
		t.Fatalf("Expected 1 instruction, got %d", len(fm.Instructions))
	}

	applyActions, ok := fm.Instructions[0].(*InstructionApplyActions)
	if !ok {
		t.Fatal("Expected InstructionApplyActions")
	}

	// Should have 4 actions: set tunnel ID, set tun src, set tun dst, output
	if len(applyActions.Actions) != 4 {
		t.Errorf("Expected 4 actions, got %d", len(applyActions.Actions))
	}
}

// TestEncodeTunnelIDOXM tests OXM encoding for tunnel ID
func TestEncodeTunnelIDOXM(t *testing.T) {
	vni := uint64(1000100)

	data := encodeTunnelIDOXM(vni, nil)

	// Verify length (4 byte header + 8 byte value)
	if len(data) != 12 {
		t.Errorf("Expected length 12, got %d", len(data))
	}

	// Verify class
	class := ByteOrder.Uint16(data[0:2])
	if class != OFPXMCNxm1 {
		t.Errorf("Expected class 0x%04x, got 0x%04x", OFPXMCNxm1, class)
	}

	// Verify field and hasMask
	if data[2] != (NXMFieldTunID << 1) {
		t.Errorf("Expected field 0x%02x, got 0x%02x", NXMFieldTunID<<1, data[2])
	}

	// Verify length
	if data[3] != TunnelIDLength {
		t.Errorf("Expected OXM length %d, got %d", TunnelIDLength, data[3])
	}

	// Verify value
	decodedVNI := ByteOrder.Uint64(data[4:12])
	if decodedVNI != vni {
		t.Errorf("Expected VNI %d, got %d", vni, decodedVNI)
	}
}

// TestEncodeTunnelIDOXM_WithMask tests OXM encoding for tunnel ID with mask
func TestEncodeTunnelIDOXM_WithMask(t *testing.T) {
	vni := uint64(1000100)
	mask := VXLANVNIMask

	data := encodeTunnelIDOXM(vni, &mask)

	// Verify length (4 byte header + 8 byte value + 8 byte mask)
	if len(data) != 20 {
		t.Errorf("Expected length 20, got %d", len(data))
	}

	// Verify hasMask bit
	if data[2] != ((NXMFieldTunID << 1) | 1) {
		t.Errorf("Expected field with mask 0x%02x, got 0x%02x", (NXMFieldTunID<<1)|1, data[2])
	}

	// Verify length with mask
	if data[3] != TunnelIDLength*2 {
		t.Errorf("Expected OXM length %d, got %d", TunnelIDLength*2, data[3])
	}

	// Verify mask value
	decodedMask := ByteOrder.Uint64(data[12:20])
	if decodedMask != mask {
		t.Errorf("Expected mask 0x%x, got 0x%x", mask, decodedMask)
	}
}

// TestEncodeTunnelIPv4OXM tests OXM encoding for tunnel IPv4
func TestEncodeTunnelIPv4OXM(t *testing.T) {
	ip := netip.MustParseAddr("192.168.1.100")

	data := encodeTunnelIPv4OXM(NXMFieldTunIPv4Dst, ip, nil)

	// Verify length (4 byte header + 4 byte value)
	if len(data) != 8 {
		t.Errorf("Expected length 8, got %d", len(data))
	}

	// Verify field
	if data[2] != (NXMFieldTunIPv4Dst << 1) {
		t.Errorf("Expected field 0x%02x, got 0x%02x", NXMFieldTunIPv4Dst<<1, data[2])
	}

	// Verify IP
	expectedIP := ip.As4()
	if !bytes.Equal(data[4:8], expectedIP[:]) {
		t.Errorf("Expected IP %v, got %v", expectedIP[:], data[4:8])
	}
}

// TestEncodeTunnelIPv4OXM_WithMask tests OXM encoding for tunnel IPv4 with mask
func TestEncodeTunnelIPv4OXM_WithMask(t *testing.T) {
	ip := netip.MustParseAddr("192.168.1.0")
	mask := netip.MustParseAddr("255.255.255.0")

	data := encodeTunnelIPv4OXM(NXMFieldTunIPv4Src, ip, &mask)

	// Verify length (4 byte header + 4 byte value + 4 byte mask)
	if len(data) != 12 {
		t.Errorf("Expected length 12, got %d", len(data))
	}

	// Verify hasMask bit
	if data[2] != ((NXMFieldTunIPv4Src << 1) | 1) {
		t.Errorf("Expected field with mask 0x%02x, got 0x%02x", (NXMFieldTunIPv4Src<<1)|1, data[2])
	}

	// Verify mask
	expectedMask := mask.As4()
	if !bytes.Equal(data[8:12], expectedMask[:]) {
		t.Errorf("Expected mask %v, got %v", expectedMask[:], data[8:12])
	}
}

// TestDecodeTunnelIDOXM tests OXM decoding for tunnel ID
func TestDecodeTunnelIDOXM(t *testing.T) {
	vni := uint64(1000100)
	data := encodeTunnelIDOXM(vni, nil)

	decodedVNI, decodedMask, err := decodeTunnelIDOXM(data)
	if err != nil {
		t.Fatalf("decodeTunnelIDOXM failed: %v", err)
	}

	if decodedVNI != vni {
		t.Errorf("Expected VNI %d, got %d", vni, decodedVNI)
	}
	if decodedMask != nil {
		t.Error("Expected mask to be nil")
	}
}

// TestDecodeTunnelIDOXM_WithMask tests OXM decoding with mask
func TestDecodeTunnelIDOXM_WithMask(t *testing.T) {
	vni := uint64(1000100)
	mask := VXLANVNIMask
	data := encodeTunnelIDOXM(vni, &mask)

	decodedVNI, decodedMask, err := decodeTunnelIDOXM(data)
	if err != nil {
		t.Fatalf("decodeTunnelIDOXM failed: %v", err)
	}

	if decodedVNI != vni {
		t.Errorf("Expected VNI %d, got %d", vni, decodedVNI)
	}
	if decodedMask == nil {
		t.Fatal("Expected mask to be set")
	}
	if *decodedMask != mask {
		t.Errorf("Expected mask 0x%x, got 0x%x", mask, *decodedMask)
	}
}

// TestDecodeTunnelIDOXM_TooShort tests decoding with insufficient data
func TestDecodeTunnelIDOXM_TooShort(t *testing.T) {
	data := make([]byte, 6) // Too short

	_, _, err := decodeTunnelIDOXM(data)
	if err != ErrMessageTooShort {
		t.Errorf("Expected ErrMessageTooShort, got %v", err)
	}
}

// TestDecodeTunnelIDOXM_MaskTooShort tests decoding mask with insufficient data
func TestDecodeTunnelIDOXM_MaskTooShort(t *testing.T) {
	// Create data with hasMask bit but not enough bytes for mask
	data := make([]byte, 12)
	ByteOrder.PutUint16(data[0:2], OFPXMCNxm1)
	data[2] = (NXMFieldTunID << 1) | 1 // hasMask = true
	data[3] = TunnelIDLength * 2

	_, _, err := decodeTunnelIDOXM(data)
	if err != ErrMessageTooShort {
		t.Errorf("Expected ErrMessageTooShort, got %v", err)
	}
}

// TestDecodeTunnelIPv4OXM tests OXM decoding for tunnel IPv4
func TestDecodeTunnelIPv4OXM(t *testing.T) {
	ip := netip.MustParseAddr("10.0.0.100")
	data := encodeTunnelIPv4OXM(NXMFieldTunIPv4Dst, ip, nil)

	decodedIP, decodedMask, err := decodeTunnelIPv4OXM(data)
	if err != nil {
		t.Fatalf("decodeTunnelIPv4OXM failed: %v", err)
	}

	if decodedIP != ip {
		t.Errorf("Expected IP %v, got %v", ip, decodedIP)
	}
	if decodedMask != nil {
		t.Error("Expected mask to be nil")
	}
}

// TestDecodeTunnelIPv4OXM_WithMask tests decoding with mask
func TestDecodeTunnelIPv4OXM_WithMask(t *testing.T) {
	ip := netip.MustParseAddr("192.168.0.0")
	mask := netip.MustParseAddr("255.255.0.0")
	data := encodeTunnelIPv4OXM(NXMFieldTunIPv4Src, ip, &mask)

	decodedIP, decodedMask, err := decodeTunnelIPv4OXM(data)
	if err != nil {
		t.Fatalf("decodeTunnelIPv4OXM failed: %v", err)
	}

	if decodedIP != ip {
		t.Errorf("Expected IP %v, got %v", ip, decodedIP)
	}
	if decodedMask == nil {
		t.Fatal("Expected mask to be set")
	}
	if *decodedMask != mask {
		t.Errorf("Expected mask %v, got %v", mask, *decodedMask)
	}
}

// TestDecodeTunnelIPv4OXM_TooShort tests decoding with insufficient data
func TestDecodeTunnelIPv4OXM_TooShort(t *testing.T) {
	data := make([]byte, 4) // Too short

	_, _, err := decodeTunnelIPv4OXM(data)
	if err != ErrMessageTooShort {
		t.Errorf("Expected ErrMessageTooShort, got %v", err)
	}
}

// TestDecodeTunnelIPv4OXM_MaskTooShort tests decoding mask with insufficient data
func TestDecodeTunnelIPv4OXM_MaskTooShort(t *testing.T) {
	data := make([]byte, 8)
	ByteOrder.PutUint16(data[0:2], OFPXMCNxm1)
	data[2] = (NXMFieldTunIPv4Dst << 1) | 1 // hasMask = true
	data[3] = TunnelIPv4Length * 2

	_, _, err := decodeTunnelIPv4OXM(data)
	if err != ErrMessageTooShort {
		t.Errorf("Expected ErrMessageTooShort, got %v", err)
	}
}

// TestFlowModBuilder_MultipleActions tests building a flow with multiple actions
func TestFlowModBuilder_MultipleActions(t *testing.T) {
	builder := NewFlowModBuilder(100).
		ActionSetTunnelID(1000).
		ActionSetTunDst(netip.MustParseAddr("10.0.0.1")).
		ActionOutput(1)

	fm := builder.Build()

	if len(fm.Instructions) != 1 {
		t.Fatalf("Expected 1 instruction, got %d", len(fm.Instructions))
	}

	applyActions, ok := fm.Instructions[0].(*InstructionApplyActions)
	if !ok {
		t.Fatal("Expected InstructionApplyActions")
	}

	if len(applyActions.Actions) != 3 {
		t.Errorf("Expected 3 actions, got %d", len(applyActions.Actions))
	}
}

// TestFlowModBuilder_ActionsAndGotoTable tests actions with goto table
func TestFlowModBuilder_ActionsAndGotoTable(t *testing.T) {
	builder := NewFlowModBuilder(100).
		GotoTable(10).
		ActionOutput(1)

	fm := builder.Build()

	// Should have 2 instructions: goto table and apply actions
	if len(fm.Instructions) != 2 {
		t.Errorf("Expected 2 instructions, got %d", len(fm.Instructions))
	}

	// First instruction should be goto table (added first)
	_, ok := fm.Instructions[0].(*InstructionGotoTable)
	if !ok {
		t.Error("First instruction should be InstructionGotoTable")
	}

	// Second instruction should be apply actions
	_, ok = fm.Instructions[1].(*InstructionApplyActions)
	if !ok {
		t.Error("Second instruction should be InstructionApplyActions")
	}
}

// TestVXLANVNIMask tests the VXLAN VNI mask constant
func TestVXLANVNIMask(t *testing.T) {
	// VXLAN VNI is 24 bits
	if VXLANVNIMask != 0x00FFFFFF {
		t.Errorf("Expected VXLAN VNI mask 0x00FFFFFF, got 0x%X", VXLANVNIMask)
	}

	// Test that a 24-bit VNI is properly masked
	maxVNI := uint64(0xFFFFFF)
	maskedVNI := maxVNI & VXLANVNIMask
	if maskedVNI != maxVNI {
		t.Errorf("Expected masked VNI %d, got %d", maxVNI, maskedVNI)
	}

	// Test that bits above 24 are masked out
	largeValue := uint64(0xFF000000)
	maskedLarge := largeValue & VXLANVNIMask
	if maskedLarge != 0 {
		t.Errorf("Expected masked value 0, got %d", maskedLarge)
	}
}

// TestFlowModBuilder_NoActions tests building a flow with no actions
func TestFlowModBuilder_NoActions(t *testing.T) {
	builder := NewFlowModBuilder(100).
		MatchTunnelID(1000)

	fm := builder.Build()

	// Should have no instructions when no actions are added
	if len(fm.Instructions) != 0 {
		t.Errorf("Expected 0 instructions, got %d", len(fm.Instructions))
	}
}

// TestMatch_MultipleTunnelFields tests adding multiple tunnel fields
func TestMatch_MultipleTunnelFields(t *testing.T) {
	m := NewMatch()
	vni := uint64(1000)
	src := netip.MustParseAddr("10.0.0.1")
	dst := netip.MustParseAddr("10.0.0.2")

	m.AddTunnelID(vni)
	m.AddTunIPv4Src(src)
	m.AddTunIPv4Dst(dst)

	if len(m.Fields) != 3 {
		t.Errorf("Expected 3 fields, got %d", len(m.Fields))
	}

	// Verify each field
	for i, field := range m.Fields {
		if field.Class != OFPXMCNxm1 {
			t.Errorf("Field %d: Expected class 0x%04x, got 0x%04x", i, OFPXMCNxm1, field.Class)
		}
	}
}

// TestFlowMod_MarshalBinaryWithTunnel tests serializing a FlowMod with tunnel fields
func TestFlowMod_MarshalBinaryWithTunnel(t *testing.T) {
	fm := NewFlowModBuilder(100).
		MatchTunnelID(1000100).
		MatchTunSrc(netip.MustParseAddr("10.0.0.1")).
		ActionSetTunnelID(2000200).
		ActionOutput(1).
		Build()

	data, err := fm.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	// Verify we got data
	if len(data) == 0 {
		t.Error("Expected non-empty data")
	}

	// Verify header
	if data[0] != DefaultVersion {
		t.Errorf("Expected version %d, got %d", DefaultVersion, data[0])
	}
	if data[1] != OFPTFlowMod {
		t.Errorf("Expected type %d, got %d", OFPTFlowMod, data[1])
	}
}

// BenchmarkEncodeTunnelIDOXM benchmarks tunnel ID encoding
func BenchmarkEncodeTunnelIDOXM(b *testing.B) {
	vni := uint64(1000100)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encodeTunnelIDOXM(vni, nil)
	}
}

// BenchmarkEncodeTunnelIDOXM_WithMask benchmarks tunnel ID encoding with mask
func BenchmarkEncodeTunnelIDOXM_WithMask(b *testing.B) {
	vni := uint64(1000100)
	mask := VXLANVNIMask

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encodeTunnelIDOXM(vni, &mask)
	}
}

// BenchmarkDecodeTunnelIDOXM benchmarks tunnel ID decoding
func BenchmarkDecodeTunnelIDOXM(b *testing.B) {
	vni := uint64(1000100)
	data := encodeTunnelIDOXM(vni, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = decodeTunnelIDOXM(data)
	}
}

// BenchmarkFlowModBuilder benchmarks building a flow mod
func BenchmarkFlowModBuilder(b *testing.B) {
	src := netip.MustParseAddr("10.0.0.1")
	dst := netip.MustParseAddr("10.0.0.2")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewFlowModBuilder(100).
			MatchTunnelID(1000100).
			MatchTunSrc(src).
			ActionSetTunnelID(2000200).
			ActionSetTunDst(dst).
			ActionOutput(1).
			Build()
	}
}

// BenchmarkActionSetTunnelID_MarshalBinary benchmarks action encoding
func BenchmarkActionSetTunnelID_MarshalBinary(b *testing.B) {
	action := NewActionSetTunnelID(1000100)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = action.MarshalBinary()
	}
}
