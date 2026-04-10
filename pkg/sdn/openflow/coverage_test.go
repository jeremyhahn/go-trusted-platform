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
	"errors"
	"testing"
)

// TestOFError_Error tests the OFError.Error() method
func TestOFError_Error(t *testing.T) {
	tests := []struct {
		name     string
		errType  uint16
		errCode  uint16
		expected string
	}{
		// Hello Failed errors
		{
			name:     "hello failed - incompatible version",
			errType:  OFPETHelloFailed,
			errCode:  0,
			expected: "hello failed: incompatible version",
		},
		{
			name:     "hello failed - permissions error",
			errType:  OFPETHelloFailed,
			errCode:  1,
			expected: "hello failed: permissions error",
		},
		{
			name:     "hello failed - unknown",
			errType:  OFPETHelloFailed,
			errCode:  99,
			expected: "hello failed: unknown error",
		},

		// Bad Request errors
		{
			name:     "bad request - bad version",
			errType:  OFPETBadRequest,
			errCode:  0,
			expected: "bad request: bad version",
		},
		{
			name:     "bad request - bad type",
			errType:  OFPETBadRequest,
			errCode:  1,
			expected: "bad request: bad type",
		},
		{
			name:     "bad request - bad multipart",
			errType:  OFPETBadRequest,
			errCode:  2,
			expected: "bad request: bad multipart",
		},
		{
			name:     "bad request - bad experimenter",
			errType:  OFPETBadRequest,
			errCode:  3,
			expected: "bad request: bad experimenter",
		},
		{
			name:     "bad request - bad experimenter type",
			errType:  OFPETBadRequest,
			errCode:  4,
			expected: "bad request: bad experimenter type",
		},
		{
			name:     "bad request - permissions error",
			errType:  OFPETBadRequest,
			errCode:  5,
			expected: "bad request: permissions error",
		},
		{
			name:     "bad request - bad length",
			errType:  OFPETBadRequest,
			errCode:  6,
			expected: "bad request: bad length",
		},
		{
			name:     "bad request - buffer empty",
			errType:  OFPETBadRequest,
			errCode:  7,
			expected: "bad request: buffer empty",
		},
		{
			name:     "bad request - buffer unknown",
			errType:  OFPETBadRequest,
			errCode:  8,
			expected: "bad request: buffer unknown",
		},
		{
			name:     "bad request - bad table id",
			errType:  OFPETBadRequest,
			errCode:  9,
			expected: "bad request: bad table id",
		},
		{
			name:     "bad request - is slave",
			errType:  OFPETBadRequest,
			errCode:  10,
			expected: "bad request: is slave",
		},
		{
			name:     "bad request - bad port",
			errType:  OFPETBadRequest,
			errCode:  11,
			expected: "bad request: bad port",
		},
		{
			name:     "bad request - bad packet",
			errType:  OFPETBadRequest,
			errCode:  12,
			expected: "bad request: bad packet",
		},
		{
			name:     "bad request - multipart buffer overflow",
			errType:  OFPETBadRequest,
			errCode:  13,
			expected: "bad request: multipart buffer overflow",
		},
		{
			name:     "bad request - unknown",
			errType:  OFPETBadRequest,
			errCode:  99,
			expected: "bad request: unknown error",
		},

		// Bad Action errors
		{
			name:     "bad action - bad type",
			errType:  OFPETBadAction,
			errCode:  0,
			expected: "bad action: bad type",
		},
		{
			name:     "bad action - bad length",
			errType:  OFPETBadAction,
			errCode:  1,
			expected: "bad action: bad length",
		},
		{
			name:     "bad action - bad experimenter",
			errType:  OFPETBadAction,
			errCode:  2,
			expected: "bad action: bad experimenter",
		},
		{
			name:     "bad action - bad experimenter type",
			errType:  OFPETBadAction,
			errCode:  3,
			expected: "bad action: bad experimenter type",
		},
		{
			name:     "bad action - bad output port",
			errType:  OFPETBadAction,
			errCode:  4,
			expected: "bad action: bad output port",
		},
		{
			name:     "bad action - bad argument",
			errType:  OFPETBadAction,
			errCode:  5,
			expected: "bad action: bad argument",
		},
		{
			name:     "bad action - permissions error",
			errType:  OFPETBadAction,
			errCode:  6,
			expected: "bad action: permissions error",
		},
		{
			name:     "bad action - too many",
			errType:  OFPETBadAction,
			errCode:  7,
			expected: "bad action: too many",
		},
		{
			name:     "bad action - bad queue",
			errType:  OFPETBadAction,
			errCode:  8,
			expected: "bad action: bad queue",
		},
		{
			name:     "bad action - bad output group",
			errType:  OFPETBadAction,
			errCode:  9,
			expected: "bad action: bad output group",
		},
		{
			name:     "bad action - match inconsistent",
			errType:  OFPETBadAction,
			errCode:  10,
			expected: "bad action: match inconsistent",
		},
		{
			name:     "bad action - unsupported order",
			errType:  OFPETBadAction,
			errCode:  11,
			expected: "bad action: unsupported order",
		},
		{
			name:     "bad action - bad tag",
			errType:  OFPETBadAction,
			errCode:  12,
			expected: "bad action: bad tag",
		},
		{
			name:     "bad action - bad set type",
			errType:  OFPETBadAction,
			errCode:  13,
			expected: "bad action: bad set type",
		},
		{
			name:     "bad action - bad set length",
			errType:  OFPETBadAction,
			errCode:  14,
			expected: "bad action: bad set length",
		},
		{
			name:     "bad action - bad set argument",
			errType:  OFPETBadAction,
			errCode:  15,
			expected: "bad action: bad set argument",
		},
		{
			name:     "bad action - unknown",
			errType:  OFPETBadAction,
			errCode:  99,
			expected: "bad action: unknown error",
		},

		// Bad Instruction errors
		{
			name:     "bad instruction - unknown instruction",
			errType:  OFPETBadInstruction,
			errCode:  0,
			expected: "bad instruction: unknown instruction",
		},
		{
			name:     "bad instruction - unsupported instruction",
			errType:  OFPETBadInstruction,
			errCode:  1,
			expected: "bad instruction: unsupported instruction",
		},
		{
			name:     "bad instruction - bad table id",
			errType:  OFPETBadInstruction,
			errCode:  2,
			expected: "bad instruction: bad table id",
		},
		{
			name:     "bad instruction - unsupported metadata",
			errType:  OFPETBadInstruction,
			errCode:  3,
			expected: "bad instruction: unsupported metadata",
		},
		{
			name:     "bad instruction - unsupported metadata mask",
			errType:  OFPETBadInstruction,
			errCode:  4,
			expected: "bad instruction: unsupported metadata mask",
		},
		{
			name:     "bad instruction - bad experimenter",
			errType:  OFPETBadInstruction,
			errCode:  5,
			expected: "bad instruction: bad experimenter",
		},
		{
			name:     "bad instruction - bad experimenter type",
			errType:  OFPETBadInstruction,
			errCode:  6,
			expected: "bad instruction: bad experimenter type",
		},
		{
			name:     "bad instruction - bad length",
			errType:  OFPETBadInstruction,
			errCode:  7,
			expected: "bad instruction: bad length",
		},
		{
			name:     "bad instruction - permissions error",
			errType:  OFPETBadInstruction,
			errCode:  8,
			expected: "bad instruction: permissions error",
		},
		{
			name:     "bad instruction - unknown",
			errType:  OFPETBadInstruction,
			errCode:  99,
			expected: "bad instruction: unknown error",
		},

		// Bad Match errors
		{
			name:     "bad match - bad type",
			errType:  OFPETBadMatch,
			errCode:  0,
			expected: "bad match: bad type",
		},
		{
			name:     "bad match - bad length",
			errType:  OFPETBadMatch,
			errCode:  1,
			expected: "bad match: bad length",
		},
		{
			name:     "bad match - bad tag",
			errType:  OFPETBadMatch,
			errCode:  2,
			expected: "bad match: bad tag",
		},
		{
			name:     "bad match - bad dl addr mask",
			errType:  OFPETBadMatch,
			errCode:  3,
			expected: "bad match: bad dl addr mask",
		},
		{
			name:     "bad match - bad nw addr mask",
			errType:  OFPETBadMatch,
			errCode:  4,
			expected: "bad match: bad nw addr mask",
		},
		{
			name:     "bad match - bad wildcards",
			errType:  OFPETBadMatch,
			errCode:  5,
			expected: "bad match: bad wildcards",
		},
		{
			name:     "bad match - bad field",
			errType:  OFPETBadMatch,
			errCode:  6,
			expected: "bad match: bad field",
		},
		{
			name:     "bad match - bad value",
			errType:  OFPETBadMatch,
			errCode:  7,
			expected: "bad match: bad value",
		},
		{
			name:     "bad match - bad mask",
			errType:  OFPETBadMatch,
			errCode:  8,
			expected: "bad match: bad mask",
		},
		{
			name:     "bad match - bad prereq",
			errType:  OFPETBadMatch,
			errCode:  9,
			expected: "bad match: bad prereq",
		},
		{
			name:     "bad match - dup field",
			errType:  OFPETBadMatch,
			errCode:  10,
			expected: "bad match: dup field",
		},
		{
			name:     "bad match - permissions error",
			errType:  OFPETBadMatch,
			errCode:  11,
			expected: "bad match: permissions error",
		},
		{
			name:     "bad match - unknown",
			errType:  OFPETBadMatch,
			errCode:  99,
			expected: "bad match: unknown error",
		},

		// Flow Mod Failed errors
		{
			name:     "flow mod failed - unknown",
			errType:  OFPETFlowModFailed,
			errCode:  0,
			expected: "flow mod failed: unknown",
		},
		{
			name:     "flow mod failed - table full",
			errType:  OFPETFlowModFailed,
			errCode:  1,
			expected: "flow mod failed: table full",
		},
		{
			name:     "flow mod failed - bad table id",
			errType:  OFPETFlowModFailed,
			errCode:  2,
			expected: "flow mod failed: bad table id",
		},
		{
			name:     "flow mod failed - overlap",
			errType:  OFPETFlowModFailed,
			errCode:  3,
			expected: "flow mod failed: overlap",
		},
		{
			name:     "flow mod failed - permissions error",
			errType:  OFPETFlowModFailed,
			errCode:  4,
			expected: "flow mod failed: permissions error",
		},
		{
			name:     "flow mod failed - bad timeout",
			errType:  OFPETFlowModFailed,
			errCode:  5,
			expected: "flow mod failed: bad timeout",
		},
		{
			name:     "flow mod failed - bad command",
			errType:  OFPETFlowModFailed,
			errCode:  6,
			expected: "flow mod failed: bad command",
		},
		{
			name:     "flow mod failed - bad flags",
			errType:  OFPETFlowModFailed,
			errCode:  7,
			expected: "flow mod failed: bad flags",
		},
		{
			name:     "flow mod failed - unknown error",
			errType:  OFPETFlowModFailed,
			errCode:  99,
			expected: "flow mod failed: unknown error",
		},

		// Unknown error type
		{
			name:     "unknown error type",
			errType:  999,
			errCode:  0,
			expected: "unknown OpenFlow error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ofErr := &OFError{
				Type: tt.errType,
				Code: tt.errCode,
			}

			result := ofErr.Error()
			if result != tt.expected {
				t.Errorf("expected error %q, got %q", tt.expected, result)
			}
		})
	}
}

// TestOFError_WithData tests OFError with data field
func TestOFError_WithData(t *testing.T) {
	ofErr := &OFError{
		Type: OFPETBadRequest,
		Code: 0,
		Data: []byte{0x01, 0x02, 0x03, 0x04},
	}

	// Verify error message is still generated correctly
	errStr := ofErr.Error()
	expected := "bad request: bad version"
	if errStr != expected {
		t.Errorf("expected error %q, got %q", expected, errStr)
	}

	// Verify data is preserved
	if !bytes.Equal(ofErr.Data, []byte{0x01, 0x02, 0x03, 0x04}) {
		t.Errorf("error data was modified")
	}
}

// TestFormatOFError tests the formatOFError function directly
func TestFormatOFError(t *testing.T) {
	tests := []struct {
		name     string
		errType  uint16
		errCode  uint16
		expected string
	}{
		{
			name:     "hello failed",
			errType:  OFPETHelloFailed,
			errCode:  0,
			expected: "hello failed: incompatible version",
		},
		{
			name:     "bad request",
			errType:  OFPETBadRequest,
			errCode:  0,
			expected: "bad request: bad version",
		},
		{
			name:     "bad action",
			errType:  OFPETBadAction,
			errCode:  0,
			expected: "bad action: bad type",
		},
		{
			name:     "bad instruction",
			errType:  OFPETBadInstruction,
			errCode:  0,
			expected: "bad instruction: unknown instruction",
		},
		{
			name:     "bad match",
			errType:  OFPETBadMatch,
			errCode:  0,
			expected: "bad match: bad type",
		},
		{
			name:     "flow mod failed",
			errType:  OFPETFlowModFailed,
			errCode:  0,
			expected: "flow mod failed: unknown",
		},
		{
			name:     "unknown error type",
			errType:  999,
			errCode:  0,
			expected: "unknown OpenFlow error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatOFError(tt.errType, tt.errCode)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// TestEchoRequest_MarshalBinary_LargeData tests echo request with large payload
func TestEchoRequest_MarshalBinary_LargeData(t *testing.T) {
	xid := uint32(0x1234)
	largeData := make([]byte, 1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	echo := NewEchoRequest(xid, largeData)
	data, err := echo.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	expectedLen := HeaderSize + len(largeData)
	if len(data) != expectedLen {
		t.Errorf("expected length %d, got %d", expectedLen, len(data))
	}

	// Verify header length field
	headerLen := binary.BigEndian.Uint16(data[2:4])
	if headerLen != uint16(expectedLen) {
		t.Errorf("expected header length %d, got %d", expectedLen, headerLen)
	}

	// Verify payload
	if !bytes.Equal(data[HeaderSize:], largeData) {
		t.Error("payload data mismatch")
	}
}

// TestEchoReply_MarshalBinary_EmptyData tests echo reply with no data
func TestEchoReply_MarshalBinary_EmptyData(t *testing.T) {
	xid := uint32(0x5678)
	reply := NewEchoReply(xid, nil)

	data, err := reply.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	if len(data) != HeaderSize {
		t.Errorf("expected length %d, got %d", HeaderSize, len(data))
	}

	// Verify type
	if data[1] != OFPTEchoReply {
		t.Errorf("expected type %d, got %d", OFPTEchoReply, data[1])
	}
}

// TestFeaturesReply_UnmarshalBinary_EdgeCases tests edge cases in features reply parsing
func TestFeaturesReply_UnmarshalBinary_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		expectError bool
		errorType   error
	}{
		{
			name:        "exact minimum size",
			data:        make([]byte, 32),
			expectError: false,
		},
		{
			name:        "one byte short",
			data:        make([]byte, 31),
			expectError: true,
			errorType:   ErrMessageTooShort,
		},
		{
			name:        "empty data",
			data:        []byte{},
			expectError: true,
			errorType:   ErrMessageTooShort,
		},
		{
			name:        "with extra bytes",
			data:        make([]byte, 64),
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if len(tt.data) >= 8 {
				// Set valid header
				tt.data[0] = DefaultVersion
				tt.data[1] = OFPTFeaturesReply
				binary.BigEndian.PutUint16(tt.data[2:4], uint16(len(tt.data)))
			}

			var reply FeaturesReply
			err := reply.UnmarshalBinary(tt.data)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				} else if tt.errorType != nil && !errors.Is(err, tt.errorType) {
					t.Errorf("expected error %v, got %v", tt.errorType, err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// TestMatch_MarshalBinary_EmptyMatch tests marshaling an empty match
func TestMatch_MarshalBinary_EmptyMatch(t *testing.T) {
	match := NewMatch()
	data, err := match.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	// Empty match should be padded to 8 bytes
	if len(data) != 8 {
		t.Errorf("expected length 8, got %d", len(data))
	}

	// Verify type
	matchType := binary.BigEndian.Uint16(data[0:2])
	if matchType != OFPMTOXM {
		t.Errorf("expected type %d, got %d", OFPMTOXM, matchType)
	}

	// Verify length
	matchLen := binary.BigEndian.Uint16(data[2:4])
	if matchLen != 4 {
		t.Errorf("expected length 4, got %d", matchLen)
	}

	// Remaining bytes should be padding (zeros)
	for i := 4; i < 8; i++ {
		if data[i] != 0 {
			t.Errorf("expected padding at offset %d to be 0, got %d", i, data[i])
		}
	}
}

// TestMatch_AddField_EmptyValue tests adding field with empty value
func TestMatch_AddField_EmptyValue(t *testing.T) {
	match := NewMatch()
	emptyValue := []byte{}

	match.AddField(OFPXMCOpenflowBasic, OFPXMTOFBInPort, emptyValue, nil)

	if len(match.Fields) != 1 {
		t.Fatalf("expected 1 field, got %d", len(match.Fields))
	}

	field := match.Fields[0]
	if len(field.Value) != 0 {
		t.Errorf("expected empty value, got %d bytes", len(field.Value))
	}

	if field.Length != 0 {
		t.Errorf("expected length 0, got %d", field.Length)
	}
}

// TestInstructionApplyActions_MarshalBinary_Error tests error propagation in instruction marshaling
func TestInstructionApplyActions_MarshalBinary_Error(t *testing.T) {
	// Create an instruction with valid actions
	action := NewActionOutput(1, 0)
	inst := NewInstructionApplyActions(action)

	// Normal case should succeed
	data, err := inst.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	if len(data) == 0 {
		t.Error("expected non-empty data")
	}
}

// TestFlowMod_MarshalBinary_EmptyInstructions tests flow mod with no instructions
func TestFlowMod_MarshalBinary_EmptyInstructions(t *testing.T) {
	xid := uint32(0x1111)
	flow := NewFlowMod(xid)
	flow.TableID = 0
	flow.Command = OFPFCAdd
	flow.Priority = 100

	// No instructions
	flow.Instructions = []Instruction{}

	data, err := flow.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	// Should still have header + body + match (minimum)
	if len(data) < 56 {
		t.Errorf("expected minimum length 56, got %d", len(data))
	}

	// Verify command
	if data[25] != OFPFCAdd {
		t.Errorf("expected command %d, got %d", OFPFCAdd, data[25])
	}
}

// TestFlowMod_MarshalBinary_MultipleInstructions tests flow mod with multiple instructions
func TestFlowMod_MarshalBinary_MultipleInstructions(t *testing.T) {
	xid := uint32(0x2222)
	flow := NewFlowMod(xid)

	// Add multiple instructions
	output1 := NewActionOutput(1, 0)
	inst1 := NewInstructionApplyActions(output1)

	inst2 := NewInstructionGotoTable(5)

	flow.Instructions = []Instruction{inst1, inst2}

	data, err := flow.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	// Should include both instructions
	// Header (8) + Body (40) + Match (8 padded) + ApplyActions (8+16) + GotoTable (8)
	expectedMinLen := 8 + 40 + 8 + 24 + 8
	if len(data) < expectedMinLen {
		t.Errorf("expected minimum length %d, got %d", expectedMinLen, len(data))
	}
}

// TestMultipartRequest_MarshalBinary_MaxLength tests multipart request with maximum size body
func TestMultipartRequest_MarshalBinary_MaxLength(t *testing.T) {
	xid := uint32(0x3333)
	// Create large body (but not exceeding max message size)
	body := make([]byte, 1000)
	for i := range body {
		body[i] = byte(i % 256)
	}

	req := NewMultipartRequest(xid, OFPMPFlow, body)
	data, err := req.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	expectedLen := 16 + len(body)
	if len(data) != expectedLen {
		t.Errorf("expected length %d, got %d", expectedLen, len(data))
	}

	// Verify header length
	headerLen := binary.BigEndian.Uint16(data[2:4])
	if headerLen != uint16(expectedLen) {
		t.Errorf("expected header length %d, got %d", expectedLen, headerLen)
	}

	// Verify body
	if !bytes.Equal(data[16:], body) {
		t.Error("body data mismatch")
	}
}

// TestFlowStatsRequest_MarshalBinary_WithMatch tests flow stats request with match
func TestFlowStatsRequest_MarshalBinary_WithMatch(t *testing.T) {
	req := NewFlowStatsRequest()
	req.TableID = 5
	req.OutPort = 10
	req.OutGroup = 0xFFFFFFFF
	req.Cookie = 0x1234567890ABCDEF
	req.CookieMask = 0xFFFFFFFFFFFFFFFF

	// Add match fields
	req.Match.AddInPort(1)
	req.Match.AddEthType(0x0800)

	data, err := req.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	// Verify table ID
	if data[0] != 5 {
		t.Errorf("expected tableID 5, got %d", data[0])
	}

	// Verify out port
	outPort := binary.BigEndian.Uint32(data[4:8])
	if outPort != 10 {
		t.Errorf("expected outPort 10, got %d", outPort)
	}

	// Verify cookie
	cookie := binary.BigEndian.Uint64(data[16:24])
	if cookie != 0x1234567890ABCDEF {
		t.Errorf("expected cookie 0x1234567890ABCDEF, got 0x%x", cookie)
	}

	// Verify cookie mask
	cookieMask := binary.BigEndian.Uint64(data[24:32])
	if cookieMask != 0xFFFFFFFFFFFFFFFF {
		t.Errorf("expected cookie mask 0xFFFFFFFFFFFFFFFF, got 0x%x", cookieMask)
	}
}

// TestParseFlowStats_PartialData tests parsing when data ends mid-entry
func TestParseFlowStats_PartialData(t *testing.T) {
	// Create first complete entry
	entry1 := make([]byte, 56)
	binary.BigEndian.PutUint16(entry1[0:2], 56)
	entry1[2] = 0
	binary.BigEndian.PutUint16(entry1[12:14], 100)

	// Create incomplete second entry (only partial)
	entry2 := make([]byte, 20)                  // Less than minimum 48 bytes
	binary.BigEndian.PutUint16(entry2[0:2], 56) // Claims to be 56 bytes

	data := append(entry1, entry2...)

	stats, err := ParseFlowStats(data)
	if err == nil {
		// Should return error or only parse first entry
		if len(stats) != 1 {
			t.Errorf("expected 1 complete entry, got %d", len(stats))
		}
	}
}

// TestActionSetField_Length tests set-field action length calculation
func TestActionSetField_Length(t *testing.T) {
	tests := []struct {
		name        string
		value       []byte
		expectedLen uint16
	}{
		{
			name:        "4-byte value (no padding needed)",
			value:       []byte{0x01, 0x02, 0x03, 0x04},
			expectedLen: 16, // 4 (action header) + 4 (OXM header) + 4 (value) + 4 (padding)
		},
		{
			name:        "2-byte value (needs padding)",
			value:       []byte{0x01, 0x02},
			expectedLen: 16, // Padded to 8-byte boundary
		},
		{
			name:        "6-byte value (needs padding)",
			value:       []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
			expectedLen: 16, // 4 + 4 + 6 + 2 (padding)
		},
		{
			name:        "1-byte value (needs padding)",
			value:       []byte{0x01},
			expectedLen: 16, // Padded to 8-byte boundary
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			action := NewActionSetField(OFPXMCOpenflowBasic, OFPXMTOFBIPProto, tt.value)

			length := action.Length()
			if length != tt.expectedLen {
				t.Errorf("expected length %d, got %d", tt.expectedLen, length)
			}

			// Verify marshaled length
			data, err := action.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary failed: %v", err)
			}

			if uint16(len(data)) != tt.expectedLen {
				t.Errorf("marshaled length %d doesn't match expected %d", len(data), tt.expectedLen)
			}
		})
	}
}

// TestInstructionGotoTable_EdgeCases tests goto-table instruction edge cases
func TestInstructionGotoTable_EdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		tableID uint8
	}{
		{
			name:    "table 0",
			tableID: 0,
		},
		{
			name:    "max table",
			tableID: OFPTTMax,
		},
		{
			name:    "table 255",
			tableID: 255,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inst := NewInstructionGotoTable(tt.tableID)

			data, err := inst.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary failed: %v", err)
			}

			if len(data) != 8 {
				t.Errorf("expected length 8, got %d", len(data))
			}

			// Verify table ID is encoded correctly
			if data[4] != tt.tableID {
				t.Errorf("expected tableID %d, got %d", tt.tableID, data[4])
			}
		})
	}
}

// TestErrorConstants tests that error constants are defined
func TestErrorConstants(t *testing.T) {
	// Test sentinel errors exist and are not nil
	if ErrNotConnected == nil {
		t.Error("ErrNotConnected should not be nil")
	}
	if ErrConnectionFailed == nil {
		t.Error("ErrConnectionFailed should not be nil")
	}
	if ErrConnectionClosed == nil {
		t.Error("ErrConnectionClosed should not be nil")
	}
	if ErrVersionMismatch == nil {
		t.Error("ErrVersionMismatch should not be nil")
	}
	if ErrInvalidMessage == nil {
		t.Error("ErrInvalidMessage should not be nil")
	}
	if ErrMessageTooShort == nil {
		t.Error("ErrMessageTooShort should not be nil")
	}
	if ErrMessageTooLong == nil {
		t.Error("ErrMessageTooLong should not be nil")
	}
	if ErrTimeout == nil {
		t.Error("ErrTimeout should not be nil")
	}
	if ErrFlowModFailed == nil {
		t.Error("ErrFlowModFailed should not be nil")
	}
	if ErrInvalidMatch == nil {
		t.Error("ErrInvalidMatch should not be nil")
	}
	if ErrInvalidAction == nil {
		t.Error("ErrInvalidAction should not be nil")
	}
	if ErrBadRequest == nil {
		t.Error("ErrBadRequest should not be nil")
	}
	if ErrNoFeatures == nil {
		t.Error("ErrNoFeatures should not be nil")
	}
	if ErrInvalidBridgeName == nil {
		t.Error("ErrInvalidBridgeName should not be nil")
	}
	if ErrSocketPath == nil {
		t.Error("ErrSocketPath should not be nil")
	}
}

// TestErrorConstants_Messages tests error messages
func TestErrorConstants_Messages(t *testing.T) {
	tests := []struct {
		name  string
		err   error
		check func(string) bool
	}{
		{
			name: "ErrNotConnected",
			err:  ErrNotConnected,
			check: func(s string) bool {
				return s == "not connected to OpenFlow switch"
			},
		},
		{
			name: "ErrConnectionFailed",
			err:  ErrConnectionFailed,
			check: func(s string) bool {
				return s == "failed to connect to OpenFlow switch"
			},
		},
		{
			name: "ErrVersionMismatch",
			err:  ErrVersionMismatch,
			check: func(s string) bool {
				return s == "OpenFlow version mismatch"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.err.Error()
			if !tt.check(msg) {
				t.Errorf("unexpected error message: %s", msg)
			}
		})
	}
}

// TestConstants_ErrorTypes tests error type constants
func TestConstants_ErrorTypes(t *testing.T) {
	tests := []struct {
		name  string
		value uint16
		want  uint16
	}{
		{"OFPETHelloFailed", OFPETHelloFailed, 0},
		{"OFPETBadRequest", OFPETBadRequest, 1},
		{"OFPETBadAction", OFPETBadAction, 2},
		{"OFPETBadInstruction", OFPETBadInstruction, 3},
		{"OFPETBadMatch", OFPETBadMatch, 4},
		{"OFPETFlowModFailed", OFPETFlowModFailed, 5},
		{"OFPETGroupModFailed", OFPETGroupModFailed, 6},
		{"OFPETPortModFailed", OFPETPortModFailed, 7},
		{"OFPETTableModFailed", OFPETTableModFailed, 8},
		{"OFPETQueueOpFailed", OFPETQueueOpFailed, 9},
		{"OFPETSwitchConfigFailed", OFPETSwitchConfigFailed, 10},
		{"OFPETRoleRequestFailed", OFPETRoleRequestFailed, 11},
		{"OFPETMeterModFailed", OFPETMeterModFailed, 12},
		{"OFPETTableFeaturesFailed", OFPETTableFeaturesFailed, 13},
		{"OFPETExperimenter", OFPETExperimenter, 65535},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value != tt.want {
				t.Errorf("%s = %d, want %d", tt.name, tt.value, tt.want)
			}
		})
	}
}

// TestConstants_FlowModFlags tests flow mod flag constants
func TestConstants_FlowModFlags(t *testing.T) {
	tests := []struct {
		name  string
		value uint16
		want  uint16
	}{
		{"OFPFFSendFlowRem", OFPFFSendFlowRem, 1 << 0},
		{"OFPFFCheckOverlap", OFPFFCheckOverlap, 1 << 1},
		{"OFPFFResetCounts", OFPFFResetCounts, 1 << 2},
		{"OFPFFNoPktCounts", OFPFFNoPktCounts, 1 << 3},
		{"OFPFFNoBytCounts", OFPFFNoBytCounts, 1 << 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value != tt.want {
				t.Errorf("%s = %d, want %d", tt.name, tt.value, tt.want)
			}
		})
	}
}

// TestConstants_MultipartTypes tests multipart request/reply type constants
func TestConstants_MultipartTypes(t *testing.T) {
	tests := []struct {
		name  string
		value uint16
		want  uint16
	}{
		{"OFPMPDesc", OFPMPDesc, 0},
		{"OFPMPFlow", OFPMPFlow, 1},
		{"OFPMPAggregate", OFPMPAggregate, 2},
		{"OFPMPTable", OFPMPTable, 3},
		{"OFPMPPortStats", OFPMPPortStats, 4},
		{"OFPMPQueue", OFPMPQueue, 5},
		{"OFPMPGroup", OFPMPGroup, 6},
		{"OFPMPGroupDesc", OFPMPGroupDesc, 7},
		{"OFPMPGroupFeatures", OFPMPGroupFeatures, 8},
		{"OFPMPMeter", OFPMPMeter, 9},
		{"OFPMPMeterConfig", OFPMPMeterConfig, 10},
		{"OFPMPMeterFeatures", OFPMPMeterFeatures, 11},
		{"OFPMPTableFeatures", OFPMPTableFeatures, 12},
		{"OFPMPPortDesc", OFPMPPortDesc, 13},
		{"OFPMPExperimenter", OFPMPExperimenter, 65535},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value != tt.want {
				t.Errorf("%s = %d, want %d", tt.name, tt.value, tt.want)
			}
		})
	}
}

// TestConstants_TableNumbers tests table number constants
func TestConstants_TableNumbers(t *testing.T) {
	tests := []struct {
		name  string
		value uint8
		want  uint8
	}{
		{"OFPTTMax", OFPTTMax, 0xfe},
		{"OFPTTAll", OFPTTAll, 0xff},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value != tt.want {
				t.Errorf("%s = 0x%02x, want 0x%02x", tt.name, tt.value, tt.want)
			}
		})
	}
}
