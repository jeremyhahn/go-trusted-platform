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
	"encoding/binary"
	"net"
	"testing"
)

// TestNewHello tests creating a hello message
func TestNewHello(t *testing.T) {
	xid := uint32(12345)
	hello := NewHello(xid)

	if hello == nil {
		t.Fatal("NewHello returned nil")
	}

	if hello.Header.Version != DefaultVersion {
		t.Errorf("Expected version %d, got %d", DefaultVersion, hello.Header.Version)
	}

	if hello.Header.Type != OFPTHello {
		t.Errorf("Expected type %d, got %d", OFPTHello, hello.Header.Type)
	}

	if hello.Header.Length != HeaderSize {
		t.Errorf("Expected length %d, got %d", HeaderSize, hello.Header.Length)
	}

	if hello.Header.Xid != xid {
		t.Errorf("Expected xid %d, got %d", xid, hello.Header.Xid)
	}
}

// TestHello_MarshalBinary tests encoding a hello message
func TestHello_MarshalBinary(t *testing.T) {
	xid := uint32(0x1234)
	hello := NewHello(xid)

	data, err := hello.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	if len(data) != HeaderSize {
		t.Errorf("Expected length %d, got %d", HeaderSize, len(data))
	}

	// Verify header fields
	if data[0] != DefaultVersion {
		t.Errorf("Expected version %d, got %d", DefaultVersion, data[0])
	}

	if data[1] != OFPTHello {
		t.Errorf("Expected type %d, got %d", OFPTHello, data[1])
	}

	length := binary.BigEndian.Uint16(data[2:4])
	if length != HeaderSize {
		t.Errorf("Expected length %d, got %d", HeaderSize, length)
	}

	decodedXid := binary.BigEndian.Uint32(data[4:8])
	if decodedXid != xid {
		t.Errorf("Expected xid 0x%x, got 0x%x", xid, decodedXid)
	}
}

// TestHello_UnmarshalBinary tests decoding a hello message
func TestHello_UnmarshalBinary(t *testing.T) {
	data := make([]byte, HeaderSize)
	data[0] = DefaultVersion
	data[1] = OFPTHello
	binary.BigEndian.PutUint16(data[2:4], HeaderSize)
	binary.BigEndian.PutUint32(data[4:8], 0x9999)

	var hello Hello
	err := hello.UnmarshalBinary(data)
	if err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}

	if hello.Header.Version != DefaultVersion {
		t.Errorf("Expected version %d, got %d", DefaultVersion, hello.Header.Version)
	}

	if hello.Header.Type != OFPTHello {
		t.Errorf("Expected type %d, got %d", OFPTHello, hello.Header.Type)
	}

	if hello.Header.Xid != 0x9999 {
		t.Errorf("Expected xid 0x9999, got 0x%x", hello.Header.Xid)
	}
}

// TestNewEchoRequest tests creating an echo request
func TestNewEchoRequest(t *testing.T) {
	xid := uint32(0x5678)
	testData := []byte("test echo data")

	echo := NewEchoRequest(xid, testData)

	if echo == nil {
		t.Fatal("NewEchoRequest returned nil")
	}

	if echo.Header.Version != DefaultVersion {
		t.Errorf("Expected version %d, got %d", DefaultVersion, echo.Header.Version)
	}

	if echo.Header.Type != OFPTEchoRequest {
		t.Errorf("Expected type %d, got %d", OFPTEchoRequest, echo.Header.Type)
	}

	expectedLen := uint16(HeaderSize + len(testData))
	if echo.Header.Length != expectedLen {
		t.Errorf("Expected length %d, got %d", expectedLen, echo.Header.Length)
	}

	if !bytes.Equal(echo.Data, testData) {
		t.Errorf("Expected data %v, got %v", testData, echo.Data)
	}
}

// TestEchoRequest_MarshalBinary tests encoding echo request with data
func TestEchoRequest_MarshalBinary(t *testing.T) {
	xid := uint32(0x9ABC)
	testData := []byte("echo payload")

	echo := NewEchoRequest(xid, testData)
	data, err := echo.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	expectedLen := HeaderSize + len(testData)
	if len(data) != expectedLen {
		t.Errorf("Expected length %d, got %d", expectedLen, len(data))
	}

	// Verify header
	if data[0] != DefaultVersion {
		t.Errorf("Expected version %d, got %d", DefaultVersion, data[0])
	}

	if data[1] != OFPTEchoRequest {
		t.Errorf("Expected type %d, got %d", OFPTEchoRequest, data[1])
	}

	// Verify payload
	payload := data[HeaderSize:]
	if !bytes.Equal(payload, testData) {
		t.Errorf("Expected payload %v, got %v", testData, payload)
	}
}

// TestEchoRequest_MarshalBinary_EmptyData tests encoding echo request with no data
func TestEchoRequest_MarshalBinary_EmptyData(t *testing.T) {
	xid := uint32(0x1111)
	echo := NewEchoRequest(xid, nil)

	data, err := echo.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	if len(data) != HeaderSize {
		t.Errorf("Expected length %d, got %d", HeaderSize, len(data))
	}
}

// TestNewEchoReply tests creating an echo reply
func TestNewEchoReply(t *testing.T) {
	xid := uint32(0xDEF0)
	testData := []byte("reply data")

	reply := NewEchoReply(xid, testData)

	if reply == nil {
		t.Fatal("NewEchoReply returned nil")
	}

	if reply.Header.Type != OFPTEchoReply {
		t.Errorf("Expected type %d, got %d", OFPTEchoReply, reply.Header.Type)
	}

	if !bytes.Equal(reply.Data, testData) {
		t.Errorf("Expected data %v, got %v", testData, reply.Data)
	}
}

// TestEchoReply_MarshalBinary tests encoding echo reply
func TestEchoReply_MarshalBinary(t *testing.T) {
	xid := uint32(0x2468)
	testData := []byte("reply payload")

	reply := NewEchoReply(xid, testData)
	data, err := reply.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	expectedLen := HeaderSize + len(testData)
	if len(data) != expectedLen {
		t.Errorf("Expected length %d, got %d", expectedLen, len(data))
	}

	// Verify type
	if data[1] != OFPTEchoReply {
		t.Errorf("Expected type %d, got %d", OFPTEchoReply, data[1])
	}

	// Verify payload
	payload := data[HeaderSize:]
	if !bytes.Equal(payload, testData) {
		t.Errorf("Expected payload %v, got %v", testData, payload)
	}
}

// TestNewFeaturesRequest tests creating a features request
func TestNewFeaturesRequest(t *testing.T) {
	xid := uint32(0xABCD)
	req := NewFeaturesRequest(xid)

	if req == nil {
		t.Fatal("NewFeaturesRequest returned nil")
	}

	if req.Header.Version != DefaultVersion {
		t.Errorf("Expected version %d, got %d", DefaultVersion, req.Header.Version)
	}

	if req.Header.Type != OFPTFeaturesRequest {
		t.Errorf("Expected type %d, got %d", OFPTFeaturesRequest, req.Header.Type)
	}

	if req.Header.Length != HeaderSize {
		t.Errorf("Expected length %d, got %d", HeaderSize, req.Header.Length)
	}

	if req.Header.Xid != xid {
		t.Errorf("Expected xid %d, got %d", xid, req.Header.Xid)
	}
}

// TestFeaturesRequest_MarshalBinary tests encoding features request
func TestFeaturesRequest_MarshalBinary(t *testing.T) {
	xid := uint32(0xFEDC)
	req := NewFeaturesRequest(xid)

	data, err := req.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	if len(data) != HeaderSize {
		t.Errorf("Expected length %d, got %d", HeaderSize, len(data))
	}

	// Verify type
	if data[1] != OFPTFeaturesRequest {
		t.Errorf("Expected type %d, got %d", OFPTFeaturesRequest, data[1])
	}

	// Verify xid
	decodedXid := binary.BigEndian.Uint32(data[4:8])
	if decodedXid != xid {
		t.Errorf("Expected xid 0x%x, got 0x%x", xid, decodedXid)
	}
}

// TestFeaturesReply_UnmarshalBinary tests decoding features reply
func TestFeaturesReply_UnmarshalBinary(t *testing.T) {
	// Create test data
	data := make([]byte, 32)

	// Header
	data[0] = DefaultVersion
	data[1] = OFPTFeaturesReply
	binary.BigEndian.PutUint16(data[2:4], 32)
	binary.BigEndian.PutUint32(data[4:8], 0x1234)

	// FeaturesReply fields
	binary.BigEndian.PutUint64(data[8:16], 0xABCDEF0123456789) // DatapathID
	binary.BigEndian.PutUint32(data[16:20], 256)               // NBuffers
	data[20] = 254                                             // NTables
	data[21] = 0                                               // AuxiliaryID
	// 2 bytes padding
	binary.BigEndian.PutUint32(data[24:28], 0xC7) // Capabilities
	binary.BigEndian.PutUint32(data[28:32], 0)    // Reserved

	var reply FeaturesReply
	err := reply.UnmarshalBinary(data)
	if err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}

	if reply.DatapathID != 0xABCDEF0123456789 {
		t.Errorf("Expected DatapathID 0xABCDEF0123456789, got 0x%x", reply.DatapathID)
	}

	if reply.NBuffers != 256 {
		t.Errorf("Expected NBuffers 256, got %d", reply.NBuffers)
	}

	if reply.NTables != 254 {
		t.Errorf("Expected NTables 254, got %d", reply.NTables)
	}

	if reply.Capabilities != 0xC7 {
		t.Errorf("Expected Capabilities 0xC7, got 0x%x", reply.Capabilities)
	}
}

// TestFeaturesReply_UnmarshalBinary_TooShort tests error on short data
func TestFeaturesReply_UnmarshalBinary_TooShort(t *testing.T) {
	data := make([]byte, 20) // Too short

	var reply FeaturesReply
	err := reply.UnmarshalBinary(data)
	if err != ErrMessageTooShort {
		t.Errorf("Expected ErrMessageTooShort, got %v", err)
	}
}

// TestNewBarrierRequest tests creating a barrier request
func TestNewBarrierRequest(t *testing.T) {
	xid := uint32(0x8888)
	req := NewBarrierRequest(xid)

	if req == nil {
		t.Fatal("NewBarrierRequest returned nil")
	}

	if req.Header.Type != OFPTBarrierRequest {
		t.Errorf("Expected type %d, got %d", OFPTBarrierRequest, req.Header.Type)
	}

	if req.Header.Length != HeaderSize {
		t.Errorf("Expected length %d, got %d", HeaderSize, req.Header.Length)
	}

	if req.Header.Xid != xid {
		t.Errorf("Expected xid %d, got %d", xid, req.Header.Xid)
	}
}

// TestBarrierRequest_MarshalBinary tests encoding barrier request
func TestBarrierRequest_MarshalBinary(t *testing.T) {
	xid := uint32(0x9999)
	req := NewBarrierRequest(xid)

	data, err := req.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	if len(data) != HeaderSize {
		t.Errorf("Expected length %d, got %d", HeaderSize, len(data))
	}

	if data[1] != OFPTBarrierRequest {
		t.Errorf("Expected type %d, got %d", OFPTBarrierRequest, data[1])
	}
}

// TestBarrierReply_UnmarshalBinary tests decoding barrier reply
func TestBarrierReply_UnmarshalBinary(t *testing.T) {
	data := make([]byte, HeaderSize)
	data[0] = DefaultVersion
	data[1] = OFPTBarrierReply
	binary.BigEndian.PutUint16(data[2:4], HeaderSize)
	binary.BigEndian.PutUint32(data[4:8], 0x7777)

	var reply BarrierReply
	err := reply.UnmarshalBinary(data)
	if err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}

	if reply.Header.Type != OFPTBarrierReply {
		t.Errorf("Expected type %d, got %d", OFPTBarrierReply, reply.Header.Type)
	}

	if reply.Header.Xid != 0x7777 {
		t.Errorf("Expected xid 0x7777, got 0x%x", reply.Header.Xid)
	}
}

// TestNewMatch tests creating an empty match
func TestNewMatch(t *testing.T) {
	match := NewMatch()

	if match == nil {
		t.Fatal("NewMatch returned nil")
	}

	if match.Type != OFPMTOXM {
		t.Errorf("Expected type %d, got %d", OFPMTOXM, match.Type)
	}

	if match.Length != 4 {
		t.Errorf("Expected length 4, got %d", match.Length)
	}

	if len(match.Fields) != 0 {
		t.Errorf("Expected 0 fields, got %d", len(match.Fields))
	}
}

// TestMatch_AddInPort tests adding input port match
// TestMatch_AddTypedFields checks that each typed Add* helper appends exactly
// one OpenFlow-basic OXM field with the right field code and wire encoding.
func TestMatch_AddTypedFields(t *testing.T) {
	ethDst, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	ethSrc, _ := net.ParseMAC("11:22:33:44:55:66")

	tests := []struct {
		name      string
		add       func(m *Match)
		wantField uint8
		wantValue []byte
	}{
		{"in port", func(m *Match) { m.AddInPort(5) }, OFPXMTOFBInPort, []byte{0, 0, 0, 5}},
		{"eth dst", func(m *Match) { m.AddEthDst(ethDst) }, OFPXMTOFBEthDst, ethDst},
		{"eth src", func(m *Match) { m.AddEthSrc(ethSrc) }, OFPXMTOFBEthSrc, ethSrc},
		{"eth type", func(m *Match) { m.AddEthType(0x0800) }, OFPXMTOFBEthType, []byte{0x08, 0x00}},
		// The VLAN VID carries the OFPVID_PRESENT bit (0x1000).
		{"vlan vid", func(m *Match) { m.AddVLANVid(100) }, OFPXMTOFBVlanVid, []byte{0x10, 0x64}},
		{"ipv4 src", func(m *Match) { m.AddIPv4Src(net.ParseIP("192.168.1.100")) }, OFPXMTOFBIPv4Src, []byte{192, 168, 1, 100}},
		{"ipv4 dst", func(m *Match) { m.AddIPv4Dst(net.ParseIP("10.0.0.1")) }, OFPXMTOFBIPv4Dst, []byte{10, 0, 0, 1}},
		{"ip proto", func(m *Match) { m.AddIPProto(6) }, OFPXMTOFBIPProto, []byte{6}},
		{"tcp src", func(m *Match) { m.AddTCPSrc(8080) }, OFPXMTOFBTCPSrc, []byte{0x1f, 0x90}},
		{"tcp dst", func(m *Match) { m.AddTCPDst(443) }, OFPXMTOFBTCPDst, []byte{0x01, 0xbb}},
		{"udp src", func(m *Match) { m.AddUDPSrc(53) }, OFPXMTOFBUDPSrc, []byte{0, 53}},
		{"udp dst", func(m *Match) { m.AddUDPDst(67) }, OFPXMTOFBUDPDst, []byte{0, 67}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match := NewMatch()
			tt.add(match)

			if len(match.Fields) != 1 {
				t.Fatalf("Expected 1 field, got %d", len(match.Fields))
			}
			field := match.Fields[0]
			if field.Class != OFPXMCOpenflowBasic {
				t.Errorf("Expected class %d, got %d", OFPXMCOpenflowBasic, field.Class)
			}
			if field.Field != tt.wantField {
				t.Errorf("Expected field %d, got %d", tt.wantField, field.Field)
			}
			if !bytes.Equal(field.Value, tt.wantValue) {
				t.Errorf("Expected value %x, got %x", tt.wantValue, field.Value)
			}
		})
	}
}

// TestMatch_MarshalBinary tests full match encoding
func TestMatch_MarshalBinary(t *testing.T) {
	match := NewMatch()
	match.AddInPort(1)

	data, err := match.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	// Check data is padded to 8 bytes
	if len(data)%8 != 0 {
		t.Errorf("Expected data padded to 8 bytes, got length %d", len(data))
	}

	// Verify match type
	matchType := binary.BigEndian.Uint16(data[0:2])
	if matchType != OFPMTOXM {
		t.Errorf("Expected match type %d, got %d", OFPMTOXM, matchType)
	}

	// Verify length field
	matchLen := binary.BigEndian.Uint16(data[2:4])
	if matchLen != match.Length {
		t.Errorf("Expected match length %d, got %d", match.Length, matchLen)
	}
}

// TestMatch_MultipleFields tests match with multiple fields
func TestMatch_MultipleFields(t *testing.T) {
	match := NewMatch()
	match.AddInPort(5)
	match.AddEthType(0x0800)
	match.AddIPProto(6)

	if len(match.Fields) != 3 {
		t.Errorf("Expected 3 fields, got %d", len(match.Fields))
	}

	// Verify length calculation includes all fields
	// Initial 4 bytes + (4 header + 4 value) + (4 header + 2 value) + (4 header + 1 value)
	expectedLen := uint16(4 + 8 + 6 + 5)
	if match.Length != expectedLen {
		t.Errorf("Expected length %d, got %d", expectedLen, match.Length)
	}

	data, err := match.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	// Should be padded to 8-byte boundary
	if len(data)%8 != 0 {
		t.Errorf("Expected data padded to 8 bytes, got length %d", len(data))
	}
}

// TestNewActionOutput tests creating output action
func TestNewActionOutput(t *testing.T) {
	port := uint32(OFPPController)
	maxLen := uint16(128)

	action := NewActionOutput(port, maxLen)

	if action == nil {
		t.Fatal("NewActionOutput returned nil")
	}

	if action.Port != port {
		t.Errorf("Expected port %d, got %d", port, action.Port)
	}

	if action.MaxLen != maxLen {
		t.Errorf("Expected maxLen %d, got %d", maxLen, action.MaxLen)
	}

	if action.Length() != 16 {
		t.Errorf("Expected length 16, got %d", action.Length())
	}
}

// TestActionOutput_MarshalBinary tests encoding output action
func TestActionOutput_MarshalBinary(t *testing.T) {
	port := uint32(7)
	maxLen := uint16(0)

	action := NewActionOutput(port, maxLen)
	data, err := action.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	if len(data) != 16 {
		t.Errorf("Expected length 16, got %d", len(data))
	}

	// Verify action type
	actionType := binary.BigEndian.Uint16(data[0:2])
	if actionType != OFPATOutput {
		t.Errorf("Expected type %d, got %d", OFPATOutput, actionType)
	}

	// Verify action length
	actionLen := binary.BigEndian.Uint16(data[2:4])
	if actionLen != 16 {
		t.Errorf("Expected length 16, got %d", actionLen)
	}

	// Verify port
	decodedPort := binary.BigEndian.Uint32(data[4:8])
	if decodedPort != port {
		t.Errorf("Expected port %d, got %d", port, decodedPort)
	}

	// Verify maxLen
	decodedMaxLen := binary.BigEndian.Uint16(data[8:10])
	if decodedMaxLen != maxLen {
		t.Errorf("Expected maxLen %d, got %d", maxLen, decodedMaxLen)
	}
}

// TestNewActionSetField tests creating set-field action
func TestNewActionSetField(t *testing.T) {
	value := []byte{0x01, 0x02, 0x03, 0x04}
	action := NewActionSetField(OFPXMCOpenflowBasic, OFPXMTOFBIPv4Src, value)

	if action == nil {
		t.Fatal("NewActionSetField returned nil")
	}

	if action.Field.Class != OFPXMCOpenflowBasic {
		t.Errorf("Expected class %d, got %d", OFPXMCOpenflowBasic, action.Field.Class)
	}

	if action.Field.Field != OFPXMTOFBIPv4Src {
		t.Errorf("Expected field %d, got %d", OFPXMTOFBIPv4Src, action.Field.Field)
	}

	if !bytes.Equal(action.Field.Value, value) {
		t.Errorf("Expected value %v, got %v", value, action.Field.Value)
	}
}

// TestActionSetField_MarshalBinary tests encoding set-field action
func TestActionSetField_MarshalBinary(t *testing.T) {
	value := []byte{192, 168, 1, 1}
	action := NewActionSetField(OFPXMCOpenflowBasic, OFPXMTOFBIPv4Src, value)

	data, err := action.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	// Length should be padded to 8 bytes
	if len(data)%8 != 0 {
		t.Errorf("Expected data padded to 8 bytes, got length %d", len(data))
	}

	// Verify action type
	actionType := binary.BigEndian.Uint16(data[0:2])
	if actionType != OFPATSetField {
		t.Errorf("Expected type %d, got %d", OFPATSetField, actionType)
	}

	// Verify OXM class
	oxmClass := binary.BigEndian.Uint16(data[4:6])
	if oxmClass != OFPXMCOpenflowBasic {
		t.Errorf("Expected OXM class %d, got %d", OFPXMCOpenflowBasic, oxmClass)
	}

	// Verify value
	if !bytes.Equal(data[8:12], value) {
		t.Errorf("Expected value %v, got %v", value, data[8:12])
	}
}

// TestNewActionPushVLAN tests creating push VLAN action
func TestNewActionPushVLAN(t *testing.T) {
	etherType := uint16(0x8100)
	action := NewActionPushVLAN(etherType)

	if action == nil {
		t.Fatal("NewActionPushVLAN returned nil")
	}

	if action.EtherType != etherType {
		t.Errorf("Expected etherType 0x%x, got 0x%x", etherType, action.EtherType)
	}

	if action.Length() != 8 {
		t.Errorf("Expected length 8, got %d", action.Length())
	}
}

// TestActionPushVLAN_MarshalBinary tests encoding push VLAN action
func TestActionPushVLAN_MarshalBinary(t *testing.T) {
	etherType := uint16(0x8100)
	action := NewActionPushVLAN(etherType)

	data, err := action.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	if len(data) != 8 {
		t.Errorf("Expected length 8, got %d", len(data))
	}

	// Verify action type
	actionType := binary.BigEndian.Uint16(data[0:2])
	if actionType != OFPATPushVlan {
		t.Errorf("Expected type %d, got %d", OFPATPushVlan, actionType)
	}

	// Verify ethertype
	decodedType := binary.BigEndian.Uint16(data[4:6])
	if decodedType != etherType {
		t.Errorf("Expected ethertype 0x%x, got 0x%x", etherType, decodedType)
	}
}

// TestNewActionPopVLAN tests creating pop VLAN action
func TestNewActionPopVLAN(t *testing.T) {
	action := NewActionPopVLAN()

	if action == nil {
		t.Fatal("NewActionPopVLAN returned nil")
	}

	if action.Length() != 8 {
		t.Errorf("Expected length 8, got %d", action.Length())
	}
}

// TestActionPopVLAN_MarshalBinary tests encoding pop VLAN action
func TestActionPopVLAN_MarshalBinary(t *testing.T) {
	action := NewActionPopVLAN()

	data, err := action.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	if len(data) != 8 {
		t.Errorf("Expected length 8, got %d", len(data))
	}

	// Verify action type
	actionType := binary.BigEndian.Uint16(data[0:2])
	if actionType != OFPATPopVlan {
		t.Errorf("Expected type %d, got %d", OFPATPopVlan, actionType)
	}

	// Verify length
	actionLen := binary.BigEndian.Uint16(data[2:4])
	if actionLen != 8 {
		t.Errorf("Expected length 8, got %d", actionLen)
	}
}

// TestActionDecNwTTL_MarshalBinary pins the OFPAT_DEC_NW_TTL wire form:
// type 24, length 8, four bytes of padding.
func TestActionDecNwTTL_MarshalBinary(t *testing.T) {
	action := NewActionDecNwTTL()
	if action.Length() != 8 {
		t.Fatalf("Length() = %d, want 8", action.Length())
	}

	data, err := action.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}
	want := []byte{0x00, 0x18, 0x00, 0x08, 0, 0, 0, 0}
	if !bytes.Equal(data, want) {
		t.Errorf("MarshalBinary() = %x, want %x", data, want)
	}
}

// TestActionDecNwTTL_InFlowMod checks the action encodes inside an
// apply-actions instruction, where its length must stay 8-aligned.
func TestActionDecNwTTL_InFlowMod(t *testing.T) {
	flow := NewFlowMod(1)
	flow.Instructions = append(flow.Instructions, NewInstructionApplyActions(NewActionDecNwTTL(), NewActionOutput(2, 0)))

	data, err := flow.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}
	if len(data)%8 != 0 {
		t.Errorf("flow mod length %d is not 8-aligned", len(data))
	}
	if !bytes.Contains(data, []byte{0x00, 0x18, 0x00, 0x08}) {
		t.Error("flow mod does not carry the dec_ttl action")
	}
}

// TestNewInstructionApplyActions tests creating apply-actions instruction
func TestNewInstructionApplyActions(t *testing.T) {
	action1 := NewActionOutput(1, 0)
	action2 := NewActionOutput(2, 0)

	inst := NewInstructionApplyActions(action1, action2)

	if inst == nil {
		t.Fatal("NewInstructionApplyActions returned nil")
	}

	if len(inst.Actions) != 2 {
		t.Errorf("Expected 2 actions, got %d", len(inst.Actions))
	}

	// The header and its padding take 8 bytes, and each of the two actions
	// takes another 16.
	expectedLen := uint16(8 + 16 + 16)
	if inst.InstructionLength() != expectedLen {
		t.Errorf("Expected length %d, got %d", expectedLen, inst.InstructionLength())
	}
}

// TestInstructionApplyActions_MarshalBinary tests encoding with actions
func TestInstructionApplyActions_MarshalBinary(t *testing.T) {
	action := NewActionOutput(OFPPController, 128)
	inst := NewInstructionApplyActions(action)

	data, err := inst.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	expectedLen := 8 + 16 // header + action
	if len(data) != expectedLen {
		t.Errorf("Expected length %d, got %d", expectedLen, len(data))
	}

	// Verify instruction type
	instType := binary.BigEndian.Uint16(data[0:2])
	if instType != OFPITApplyActions {
		t.Errorf("Expected type %d, got %d", OFPITApplyActions, instType)
	}

	// Verify instruction length
	instLen := binary.BigEndian.Uint16(data[2:4])
	if instLen != uint16(expectedLen) {
		t.Errorf("Expected length %d, got %d", expectedLen, instLen)
	}

	// Verify action is included (starts at offset 8)
	actionType := binary.BigEndian.Uint16(data[8:10])
	if actionType != OFPATOutput {
		t.Errorf("Expected action type %d, got %d", OFPATOutput, actionType)
	}
}

// TestNewInstructionGotoTable tests creating goto-table instruction
func TestNewInstructionGotoTable(t *testing.T) {
	tableID := uint8(5)
	inst := NewInstructionGotoTable(tableID)

	if inst == nil {
		t.Fatal("NewInstructionGotoTable returned nil")
	}

	if inst.TableID != tableID {
		t.Errorf("Expected tableID %d, got %d", tableID, inst.TableID)
	}

	if inst.InstructionLength() != 8 {
		t.Errorf("Expected length 8, got %d", inst.InstructionLength())
	}
}

// TestInstructionGotoTable_MarshalBinary tests encoding goto-table instruction
func TestInstructionGotoTable_MarshalBinary(t *testing.T) {
	tableID := uint8(10)
	inst := NewInstructionGotoTable(tableID)

	data, err := inst.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	if len(data) != 8 {
		t.Errorf("Expected length 8, got %d", len(data))
	}

	// Verify instruction type
	instType := binary.BigEndian.Uint16(data[0:2])
	if instType != OFPITGotoTable {
		t.Errorf("Expected type %d, got %d", OFPITGotoTable, instType)
	}

	// Verify table ID
	if data[4] != tableID {
		t.Errorf("Expected tableID %d, got %d", tableID, data[4])
	}
}

// TestNewFlowMod tests creating a flow mod message
func TestNewFlowMod(t *testing.T) {
	xid := uint32(0x1111)
	flow := NewFlowMod(xid)

	if flow == nil {
		t.Fatal("NewFlowMod returned nil")
	}

	if flow.Header.Type != OFPTFlowMod {
		t.Errorf("Expected type %d, got %d", OFPTFlowMod, flow.Header.Type)
	}

	if flow.BufferID != 0xffffffff {
		t.Errorf("Expected BufferID 0xffffffff, got 0x%x", flow.BufferID)
	}

	if flow.OutPort != OFPPAny {
		t.Errorf("Expected OutPort %d, got %d", OFPPAny, flow.OutPort)
	}

	if flow.Match == nil {
		t.Error("Expected Match to be initialized")
	}
}

// TestFlowMod_MarshalBinary tests full flow mod encoding
func TestFlowMod_MarshalBinary(t *testing.T) {
	xid := uint32(0x2222)
	flow := NewFlowMod(xid)
	flow.TableID = 0
	flow.Command = OFPFCAdd
	flow.Priority = 100
	flow.IdleTimeout = 30
	flow.HardTimeout = 300

	data, err := flow.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	// Minimum length: 48 (body) + match (8 padded to 8)
	if len(data) < 56 {
		t.Errorf("Expected minimum length 56, got %d", len(data))
	}

	// Verify header
	if data[1] != OFPTFlowMod {
		t.Errorf("Expected type %d, got %d", OFPTFlowMod, data[1])
	}

	// Verify table ID
	if data[24] != 0 {
		t.Errorf("Expected tableID 0, got %d", data[24])
	}

	// Verify command
	if data[25] != OFPFCAdd {
		t.Errorf("Expected command %d, got %d", OFPFCAdd, data[25])
	}

	// Verify priority
	priority := binary.BigEndian.Uint16(data[30:32])
	if priority != 100 {
		t.Errorf("Expected priority 100, got %d", priority)
	}
}

// TestFlowMod_WithMatch tests flow mod with match fields
func TestFlowMod_WithMatch(t *testing.T) {
	xid := uint32(0x3333)
	flow := NewFlowMod(xid)
	flow.Match.AddInPort(5)
	flow.Match.AddEthType(0x0800)

	data, err := flow.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	// Should include match with 2 fields
	if len(data) < 64 {
		t.Errorf("Expected length >= 64 with match, got %d", len(data))
	}
}

// TestFlowMod_WithInstructions tests flow mod with instructions
func TestFlowMod_WithInstructions(t *testing.T) {
	xid := uint32(0x4444)
	flow := NewFlowMod(xid)

	action := NewActionOutput(1, 0)
	inst := NewInstructionApplyActions(action)
	flow.Instructions = []Instruction{inst}

	data, err := flow.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	// Should include instruction (8) + action (16)
	if len(data) < 80 {
		t.Errorf("Expected length >= 80 with instruction, got %d", len(data))
	}
}

// TestNewFlowStatsRequest tests creating flow stats request
func TestNewFlowStatsRequest(t *testing.T) {
	req := NewFlowStatsRequest()

	if req == nil {
		t.Fatal("NewFlowStatsRequest returned nil")
	}

	if req.TableID != OFPTTAll {
		t.Errorf("Expected tableID %d, got %d", OFPTTAll, req.TableID)
	}

	if req.OutPort != OFPPAny {
		t.Errorf("Expected outPort %d, got %d", OFPPAny, req.OutPort)
	}

	if req.Match == nil {
		t.Error("Expected Match to be initialized")
	}
}

// TestFlowStatsRequest_MarshalBinary tests encoding stats request
func TestFlowStatsRequest_MarshalBinary(t *testing.T) {
	req := NewFlowStatsRequest()

	data, err := req.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	// 32 bytes fixed + match (8 padded)
	if len(data) < 40 {
		t.Errorf("Expected length >= 40, got %d", len(data))
	}

	// Verify table ID
	if data[0] != OFPTTAll {
		t.Errorf("Expected tableID %d, got %d", OFPTTAll, data[0])
	}

	// Verify out port
	outPort := binary.BigEndian.Uint32(data[4:8])
	if outPort != OFPPAny {
		t.Errorf("Expected outPort %d, got %d", OFPPAny, outPort)
	}
}

// TestNewMultipartRequest tests creating multipart request
func TestNewMultipartRequest(t *testing.T) {
	xid := uint32(0x5555)
	mpType := uint16(OFPMPFlow)
	body := []byte{0x01, 0x02, 0x03, 0x04}

	req := NewMultipartRequest(xid, mpType, body)

	if req == nil {
		t.Fatal("NewMultipartRequest returned nil")
	}

	if req.Header.Type != OFPTMultipartRequest {
		t.Errorf("Expected type %d, got %d", OFPTMultipartRequest, req.Header.Type)
	}

	if req.Type != mpType {
		t.Errorf("Expected multipart type %d, got %d", mpType, req.Type)
	}

	if !bytes.Equal(req.Body, body) {
		t.Errorf("Expected body %v, got %v", body, req.Body)
	}
}

// TestMultipartRequest_MarshalBinary tests encoding multipart request
func TestMultipartRequest_MarshalBinary(t *testing.T) {
	xid := uint32(0x6666)
	body := []byte{0xAA, 0xBB, 0xCC, 0xDD}

	req := NewMultipartRequest(xid, OFPMPFlow, body)
	data, err := req.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	expectedLen := 16 + len(body)
	if len(data) != expectedLen {
		t.Errorf("Expected length %d, got %d", expectedLen, len(data))
	}

	// Verify header type
	if data[1] != OFPTMultipartRequest {
		t.Errorf("Expected type %d, got %d", OFPTMultipartRequest, data[1])
	}

	// Verify multipart type
	mpType := binary.BigEndian.Uint16(data[8:10])
	if mpType != OFPMPFlow {
		t.Errorf("Expected multipart type %d, got %d", OFPMPFlow, mpType)
	}

	// Verify body
	if !bytes.Equal(data[16:], body) {
		t.Errorf("Expected body %v, got %v", body, data[16:])
	}
}

// TestMultipartRequest_MarshalBinary_EmptyBody tests encoding with no body
func TestMultipartRequest_MarshalBinary_EmptyBody(t *testing.T) {
	xid := uint32(0x7777)
	req := NewMultipartRequest(xid, OFPMPDesc, nil)

	data, err := req.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	if len(data) != 16 {
		t.Errorf("Expected length 16, got %d", len(data))
	}
}

// TestParseFlowStats tests parsing stats response
func TestParseFlowStats(t *testing.T) {
	// Create test data for one flow entry
	data := make([]byte, 56) // Minimum flow stats entry size

	// Flow stats fields
	binary.BigEndian.PutUint16(data[0:2], 56)   // Length
	data[2] = 0                                 // TableID
	data[3] = 0                                 // Pad
	binary.BigEndian.PutUint32(data[4:8], 100)  // DurationSec
	binary.BigEndian.PutUint32(data[8:12], 500) // DurationNsec
	binary.BigEndian.PutUint16(data[12:14], 50) // Priority
	binary.BigEndian.PutUint16(data[14:16], 30) // IdleTimeout
	binary.BigEndian.PutUint16(data[16:18], 0)  // HardTimeout
	binary.BigEndian.PutUint16(data[18:20], 0)  // Flags
	// 4 bytes padding
	binary.BigEndian.PutUint64(data[24:32], 0x1234567890ABCDEF) // Cookie
	binary.BigEndian.PutUint64(data[32:40], 1000)               // PacketCount
	binary.BigEndian.PutUint64(data[40:48], 64000)              // ByteCount
	// 8 bytes minimum match

	stats, err := ParseFlowStats(data)
	if err != nil {
		t.Fatalf("ParseFlowStats failed: %v", err)
	}

	if len(stats) != 1 {
		t.Fatalf("Expected 1 flow stat, got %d", len(stats))
	}

	stat := stats[0]
	if stat.Length != 56 {
		t.Errorf("Expected length 56, got %d", stat.Length)
	}

	if stat.TableID != 0 {
		t.Errorf("Expected tableID 0, got %d", stat.TableID)
	}

	if stat.Priority != 50 {
		t.Errorf("Expected priority 50, got %d", stat.Priority)
	}

	if stat.PacketCount != 1000 {
		t.Errorf("Expected packetCount 1000, got %d", stat.PacketCount)
	}

	if stat.ByteCount != 64000 {
		t.Errorf("Expected byteCount 64000, got %d", stat.ByteCount)
	}
}

// TestParseFlowStats_Empty tests parsing empty response
func TestParseFlowStats_Empty(t *testing.T) {
	data := []byte{}

	stats, err := ParseFlowStats(data)
	if err != nil {
		t.Fatalf("ParseFlowStats failed on empty data: %v", err)
	}

	if len(stats) != 0 {
		t.Errorf("Expected 0 flow stats, got %d", len(stats))
	}
}

// TestParseFlowStats_InvalidLength tests handling bad length
func TestParseFlowStats_InvalidLength(t *testing.T) {
	data := make([]byte, 48)

	// Set length to exceed available data
	binary.BigEndian.PutUint16(data[0:2], 100)

	_, err := ParseFlowStats(data)
	if err == nil {
		t.Error("Expected error for invalid length, got nil")
	}
}

// TestParseFlowStats_TooShort tests handling data too short for header
func TestParseFlowStats_TooShort(t *testing.T) {
	data := make([]byte, 20) // Less than minimum 48 bytes

	stats, err := ParseFlowStats(data)
	if err != nil {
		t.Fatalf("ParseFlowStats failed: %v", err)
	}

	// Should return empty stats when data is too short for a complete entry
	if len(stats) != 0 {
		t.Errorf("Expected 0 stats for short data, got %d", len(stats))
	}
}

// TestMatch_AddField_WithMask tests adding field with mask
func TestMatch_AddField_WithMask(t *testing.T) {
	match := NewMatch()
	value := []byte{192, 168, 1, 0}
	mask := []byte{255, 255, 255, 0}

	match.AddField(OFPXMCOpenflowBasic, OFPXMTOFBIPv4Src, value, mask)

	if len(match.Fields) != 1 {
		t.Fatalf("Expected 1 field, got %d", len(match.Fields))
	}

	field := match.Fields[0]
	if !field.HasMask {
		t.Error("Expected field to have mask")
	}

	if !bytes.Equal(field.Mask, mask) {
		t.Errorf("Expected mask %v, got %v", mask, field.Mask)
	}

	// Length should include both value and mask
	expectedLen := uint8(len(value) * 2)
	if field.Length != expectedLen {
		t.Errorf("Expected length %d, got %d", expectedLen, field.Length)
	}
}

// TestActionOutput_MaxLength tests output action with max length
func TestActionOutput_MaxLength(t *testing.T) {
	action := NewActionOutput(OFPPController, 256)

	data, err := action.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	maxLen := binary.BigEndian.Uint16(data[8:10])
	if maxLen != 256 {
		t.Errorf("Expected maxLen 256, got %d", maxLen)
	}
}

// TestInstructionApplyActions_Empty tests apply-actions with no actions
func TestInstructionApplyActions_Empty(t *testing.T) {
	inst := NewInstructionApplyActions()

	if len(inst.Actions) != 0 {
		t.Errorf("Expected 0 actions, got %d", len(inst.Actions))
	}

	if inst.InstructionLength() != 8 {
		t.Errorf("Expected length 8, got %d", inst.InstructionLength())
	}

	data, err := inst.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	if len(data) != 8 {
		t.Errorf("Expected length 8, got %d", len(data))
	}
}

// TestFlowMod_Cookie tests flow mod cookie handling
func TestFlowMod_Cookie(t *testing.T) {
	xid := uint32(0x7777)
	flow := NewFlowMod(xid)

	cookie := uint64(0xDEADBEEFCAFEBABE)
	cookieMask := uint64(0xFFFFFFFFFFFFFFFF)

	flow.Cookie = cookie
	flow.CookieMask = cookieMask

	data, err := flow.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	// Verify cookie
	decodedCookie := binary.BigEndian.Uint64(data[8:16])
	if decodedCookie != cookie {
		t.Errorf("Expected cookie 0x%x, got 0x%x", cookie, decodedCookie)
	}

	// Verify cookie mask
	decodedMask := binary.BigEndian.Uint64(data[16:24])
	if decodedMask != cookieMask {
		t.Errorf("Expected cookie mask 0x%x, got 0x%x", cookieMask, decodedMask)
	}
}

// TestFlowMod_Flags tests flow mod flags
func TestFlowMod_Flags(t *testing.T) {
	xid := uint32(0x8888)
	flow := NewFlowMod(xid)

	flags := uint16(OFPFFSendFlowRem | OFPFFCheckOverlap)
	flow.Flags = flags

	data, err := flow.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	// Verify flags at offset 44
	decodedFlags := binary.BigEndian.Uint16(data[44:46])
	if decodedFlags != flags {
		t.Errorf("Expected flags 0x%x, got 0x%x", flags, decodedFlags)
	}
}

// TestParseFlowStats_MultipleEntries tests parsing multiple flow entries
func TestParseFlowStats_MultipleEntries(t *testing.T) {
	// Create test data for two flow entries
	entry1 := make([]byte, 56)
	binary.BigEndian.PutUint16(entry1[0:2], 56)
	entry1[2] = 0
	binary.BigEndian.PutUint16(entry1[12:14], 100)  // Priority
	binary.BigEndian.PutUint64(entry1[32:40], 1000) // PacketCount

	entry2 := make([]byte, 56)
	binary.BigEndian.PutUint16(entry2[0:2], 56)
	entry2[2] = 1
	binary.BigEndian.PutUint16(entry2[12:14], 200)  // Priority
	binary.BigEndian.PutUint64(entry2[32:40], 2000) // PacketCount

	data := append(entry1, entry2...)

	stats, err := ParseFlowStats(data)
	if err != nil {
		t.Fatalf("ParseFlowStats failed: %v", err)
	}

	if len(stats) != 2 {
		t.Fatalf("Expected 2 flow stats, got %d", len(stats))
	}

	if stats[0].Priority != 100 {
		t.Errorf("Expected first entry priority 100, got %d", stats[0].Priority)
	}

	if stats[1].Priority != 200 {
		t.Errorf("Expected second entry priority 200, got %d", stats[1].Priority)
	}
}

// TestMatchUnmarshalBinary_RoundTrip verifies that a marshaled match decodes
// back to the same OXM fields, including masked conntrack state.
func TestMatchUnmarshalBinary_RoundTrip(t *testing.T) {
	original := NewMatch()
	original.AddEthType(0x0800)
	original.AddVLANVid(100)
	original.AddCTState(CTStateInv|CTStateTrk, CTStateInv|CTStateTrk)

	data, err := original.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	decoded := NewMatch()
	if err := decoded.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}

	if decoded.Type != OFPMTOXM {
		t.Errorf("Type = %d, want %d", decoded.Type, OFPMTOXM)
	}
	if decoded.Length != original.Length {
		t.Errorf("Length = %d, want %d", decoded.Length, original.Length)
	}
	if len(decoded.Fields) != len(original.Fields) {
		t.Fatalf("Fields = %d, want %d", len(decoded.Fields), len(original.Fields))
	}
	for i, want := range original.Fields {
		got := decoded.Fields[i]
		if got.Class != want.Class || got.Field != want.Field || got.HasMask != want.HasMask {
			t.Errorf("field %d header = %+v, want %+v", i, got, want)
		}
		if !bytes.Equal(got.Value, want.Value) || !bytes.Equal(got.Mask, want.Mask) {
			t.Errorf("field %d payload = %x/%x, want %x/%x", i, got.Value, got.Mask, want.Value, want.Mask)
		}
	}
}

// TestMatchUnmarshalBinary_Errors verifies malformed match encodings are
// rejected.
func TestMatchUnmarshalBinary_Errors(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"too short", []byte{0x00, 0x01}},
		{"length below header", []byte{0x00, 0x01, 0x00, 0x02}},
		{"length beyond data", []byte{0x00, 0x01, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00}},
		{"truncated OXM header", []byte{0x00, 0x01, 0x00, 0x06, 0x80, 0x00}},
		{"truncated OXM payload", []byte{0x00, 0x01, 0x00, 0x0a, 0x80, 0x00, 0x0a, 0x04, 0x00, 0x00}},
		{"odd masked payload", []byte{0x00, 0x01, 0x00, 0x09, 0x80, 0x00, 0x0b, 0x01, 0xff}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMatch()
			if err := m.UnmarshalBinary(tt.data); err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

// TestParseFlowStats_WithMatch verifies the flow's ofp_match and trailing
// instruction bytes are decoded from a stats entry.
func TestParseFlowStats_WithMatch(t *testing.T) {
	match := NewMatch()
	match.AddVLANVid(100)
	match.AddCTState(CTStateInv|CTStateTrk, CTStateInv|CTStateTrk)
	matchData, err := match.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	instructions := []byte{0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00}
	entry := make([]byte, 48+len(matchData)+len(instructions))
	binary.BigEndian.PutUint16(entry[0:2], uint16(len(entry)))
	entry[2] = 21                                 // TableID
	binary.BigEndian.PutUint16(entry[12:14], 400) // Priority
	binary.BigEndian.PutUint64(entry[32:40], 7)   // PacketCount
	copy(entry[48:], matchData)
	copy(entry[48+len(matchData):], instructions)

	stats, err := ParseFlowStats(entry)
	if err != nil {
		t.Fatalf("ParseFlowStats failed: %v", err)
	}
	if len(stats) != 1 {
		t.Fatalf("Expected 1 flow stat, got %d", len(stats))
	}

	stat := stats[0]
	if stat.Match == nil {
		t.Fatal("Match not decoded")
	}
	if len(stat.Match.Fields) != 2 {
		t.Fatalf("Match fields = %d, want 2", len(stat.Match.Fields))
	}
	if stat.Match.Fields[1].Class != OFPXMCNxm1 || stat.Match.Fields[1].Field != NXMFieldCTState {
		t.Errorf("second field = %+v, want ct_state", stat.Match.Fields[1])
	}
	if !bytes.Equal(stat.Instructions, instructions) {
		t.Errorf("Instructions = %x, want %x", stat.Instructions, instructions)
	}
}

// TestParseFlowStats_MalformedMatch verifies a corrupt OXM match in a stats
// entry is rejected instead of silently skipped.
func TestParseFlowStats_MalformedMatch(t *testing.T) {
	entry := make([]byte, 56)
	binary.BigEndian.PutUint16(entry[0:2], 56)
	// OFPMT_OXM header with a length that exceeds the entry.
	binary.BigEndian.PutUint16(entry[48:50], OFPMTOXM)
	binary.BigEndian.PutUint16(entry[50:52], 64)

	if _, err := ParseFlowStats(entry); err == nil {
		t.Error("expected error for malformed match, got nil")
	}
}
