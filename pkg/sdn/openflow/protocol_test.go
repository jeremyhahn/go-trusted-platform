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
	"testing"
)

// TestHeader_Size verifies that header size is 8 bytes
func TestHeader_Size(t *testing.T) {
	header := &Header{}
	if got := header.Size(); got != 8 {
		t.Errorf("Header.Size() = %d, want 8", got)
	}

	if HeaderSize != 8 {
		t.Errorf("HeaderSize constant = %d, want 8", HeaderSize)
	}
}

// TestHeader_MarshalBinary verifies encoding header to binary
func TestHeader_MarshalBinary(t *testing.T) {
	tests := []struct {
		name    string
		header  Header
		want    []byte
		wantErr bool
	}{
		{
			name: "valid header",
			header: Header{
				Version: OFP13,
				Type:    OFPTHello,
				Length:  8,
				Xid:     12345,
			},
			want: []byte{
				0x04,       // Version
				0x00,       // Type
				0x00, 0x08, // Length
				0x00, 0x00, 0x30, 0x39, // Xid (12345)
			},
			wantErr: false,
		},
		{
			name: "zero values",
			header: Header{
				Version: 0,
				Type:    0,
				Length:  0,
				Xid:     0,
			},
			want: []byte{
				0x00,       // Version
				0x00,       // Type
				0x00, 0x00, // Length
				0x00, 0x00, 0x00, 0x00, // Xid
			},
			wantErr: false,
		},
		{
			name: "max values",
			header: Header{
				Version: 0xFF,
				Type:    0xFF,
				Length:  0xFFFF,
				Xid:     0xFFFFFFFF,
			},
			want: []byte{
				0xFF,       // Version
				0xFF,       // Type
				0xFF, 0xFF, // Length
				0xFF, 0xFF, 0xFF, 0xFF, // Xid
			},
			wantErr: false,
		},
		{
			name: "features request",
			header: Header{
				Version: OFP13,
				Type:    OFPTFeaturesRequest,
				Length:  8,
				Xid:     1,
			},
			want: []byte{
				0x04,       // Version
				0x05,       // Type (OFPT_FEATURES_REQUEST)
				0x00, 0x08, // Length
				0x00, 0x00, 0x00, 0x01, // Xid
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.header.MarshalBinary()
			if (err != nil) != tt.wantErr {
				t.Errorf("Header.MarshalBinary() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("Header.MarshalBinary() = %v, want %v", got, tt.want)
			}
			if len(got) != HeaderSize {
				t.Errorf("Header.MarshalBinary() length = %d, want %d", len(got), HeaderSize)
			}
		})
	}
}

// TestHeader_UnmarshalBinary verifies decoding header from binary
func TestHeader_UnmarshalBinary(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    Header
		wantErr bool
	}{
		{
			name: "valid header",
			data: []byte{
				0x04,       // Version
				0x00,       // Type
				0x00, 0x08, // Length
				0x00, 0x00, 0x30, 0x39, // Xid (12345)
			},
			want: Header{
				Version: OFP13,
				Type:    OFPTHello,
				Length:  8,
				Xid:     12345,
			},
			wantErr: false,
		},
		{
			name: "zero values",
			data: []byte{
				0x00,       // Version
				0x00,       // Type
				0x00, 0x00, // Length
				0x00, 0x00, 0x00, 0x00, // Xid
			},
			want: Header{
				Version: 0,
				Type:    0,
				Length:  0,
				Xid:     0,
			},
			wantErr: false,
		},
		{
			name: "max values",
			data: []byte{
				0xFF,       // Version
				0xFF,       // Type
				0xFF, 0xFF, // Length
				0xFF, 0xFF, 0xFF, 0xFF, // Xid
			},
			want: Header{
				Version: 0xFF,
				Type:    0xFF,
				Length:  0xFFFF,
				Xid:     0xFFFFFFFF,
			},
			wantErr: false,
		},
		{
			name: "features reply",
			data: []byte{
				0x04,       // Version
				0x06,       // Type (OFPT_FEATURES_REPLY)
				0x00, 0x20, // Length (32)
				0x00, 0x00, 0x00, 0x01, // Xid
			},
			want: Header{
				Version: OFP13,
				Type:    OFPTFeaturesReply,
				Length:  32,
				Xid:     1,
			},
			wantErr: false,
		},
		{
			name: "data with extra bytes",
			data: []byte{
				0x04,       // Version
				0x00,       // Type
				0x00, 0x08, // Length
				0x00, 0x00, 0x00, 0x01, // Xid
				0xFF, 0xFF, // Extra bytes (should be ignored)
			},
			want: Header{
				Version: OFP13,
				Type:    OFPTHello,
				Length:  8,
				Xid:     1,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var header Header
			err := header.UnmarshalBinary(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Header.UnmarshalBinary() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if header != tt.want {
					t.Errorf("Header.UnmarshalBinary() = %+v, want %+v", header, tt.want)
				}
			}
		})
	}
}

// TestHeader_UnmarshalBinary_TooShort verifies error on short data
func TestHeader_UnmarshalBinary_TooShort(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "empty data",
			data: []byte{},
		},
		{
			name: "1 byte",
			data: []byte{0x04},
		},
		{
			name: "2 bytes",
			data: []byte{0x04, 0x00},
		},
		{
			name: "4 bytes",
			data: []byte{0x04, 0x00, 0x00, 0x08},
		},
		{
			name: "7 bytes (one short)",
			data: []byte{0x04, 0x00, 0x00, 0x08, 0x00, 0x00, 0x01},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var header Header
			err := header.UnmarshalBinary(tt.data)
			if err == nil {
				t.Errorf("Header.UnmarshalBinary() with %d bytes should return error, got nil", len(tt.data))
			}
		})
	}
}

// TestHeader_Roundtrip verifies marshal then unmarshal
func TestHeader_Roundtrip(t *testing.T) {
	tests := []struct {
		name   string
		header Header
	}{
		{
			name: "hello message",
			header: Header{
				Version: OFP13,
				Type:    OFPTHello,
				Length:  8,
				Xid:     100,
			},
		},
		{
			name: "echo request",
			header: Header{
				Version: OFP13,
				Type:    OFPTEchoRequest,
				Length:  16,
				Xid:     200,
			},
		},
		{
			name: "flow mod",
			header: Header{
				Version: OFP13,
				Type:    OFPTFlowMod,
				Length:  128,
				Xid:     12345,
			},
		},
		{
			name: "zero xid",
			header: Header{
				Version: OFP13,
				Type:    OFPTBarrierRequest,
				Length:  8,
				Xid:     0,
			},
		},
		{
			name: "max xid",
			header: Header{
				Version: OFP13,
				Type:    OFPTPacketOut,
				Length:  MaxMessageSize,
				Xid:     0xFFFFFFFF,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.header.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}

			var decoded Header
			err = decoded.UnmarshalBinary(data)
			if err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}

			if decoded != tt.header {
				t.Errorf("Roundtrip failed: got %+v, want %+v", decoded, tt.header)
			}
		})
	}
}

// TestNewHeader verifies creating header with parameters
func TestNewHeader(t *testing.T) {
	tests := []struct {
		name    string
		msgType uint8
		length  uint16
		xid     uint32
		want    Header
	}{
		{
			name:    "hello",
			msgType: OFPTHello,
			length:  8,
			xid:     1,
			want: Header{
				Version: DefaultVersion,
				Type:    OFPTHello,
				Length:  8,
				Xid:     1,
			},
		},
		{
			name:    "features request",
			msgType: OFPTFeaturesRequest,
			length:  8,
			xid:     100,
			want: Header{
				Version: DefaultVersion,
				Type:    OFPTFeaturesRequest,
				Length:  8,
				Xid:     100,
			},
		},
		{
			name:    "flow mod",
			msgType: OFPTFlowMod,
			length:  256,
			xid:     12345,
			want: Header{
				Version: DefaultVersion,
				Type:    OFPTFlowMod,
				Length:  256,
				Xid:     12345,
			},
		},
		{
			name:    "zero values",
			msgType: 0,
			length:  0,
			xid:     0,
			want: Header{
				Version: DefaultVersion,
				Type:    0,
				Length:  0,
				Xid:     0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewHeader(tt.msgType, tt.length, tt.xid)
			if got == nil {
				t.Fatal("NewHeader() returned nil")
			}
			if *got != tt.want {
				t.Errorf("NewHeader() = %+v, want %+v", *got, tt.want)
			}
		})
	}
}

// TestConstants_Version verifies OpenFlow version constants
func TestConstants_Version(t *testing.T) {
	tests := []struct {
		name  string
		value uint8
		want  uint8
	}{
		{"OFP10", OFP10, 0x01},
		{"OFP11", OFP11, 0x02},
		{"OFP12", OFP12, 0x03},
		{"OFP13", OFP13, 0x04},
		{"OFP14", OFP14, 0x05},
		{"OFP15", OFP15, 0x06},
		{"DefaultVersion", DefaultVersion, 0x04},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value != tt.want {
				t.Errorf("%s = 0x%02x, want 0x%02x", tt.name, tt.value, tt.want)
			}
		})
	}
}

// TestConstants_MessageTypes verifies OFPT message type constants
func TestConstants_MessageTypes(t *testing.T) {
	tests := []struct {
		name  string
		value uint8
		want  uint8
	}{
		// Immutable messages
		{"OFPTHello", OFPTHello, 0},
		{"OFPTError", OFPTError, 1},
		{"OFPTEchoRequest", OFPTEchoRequest, 2},
		{"OFPTEchoReply", OFPTEchoReply, 3},
		{"OFPTExperimenter", OFPTExperimenter, 4},

		// Switch configuration
		{"OFPTFeaturesRequest", OFPTFeaturesRequest, 5},
		{"OFPTFeaturesReply", OFPTFeaturesReply, 6},
		{"OFPTGetConfigRequest", OFPTGetConfigRequest, 7},
		{"OFPTGetConfigReply", OFPTGetConfigReply, 8},
		{"OFPTSetConfig", OFPTSetConfig, 9},

		// Asynchronous messages
		{"OFPTPacketIn", OFPTPacketIn, 10},
		{"OFPTFlowRemoved", OFPTFlowRemoved, 11},
		{"OFPTPortStatus", OFPTPortStatus, 12},

		// Controller commands
		{"OFPTPacketOut", OFPTPacketOut, 13},
		{"OFPTFlowMod", OFPTFlowMod, 14},
		{"OFPTGroupMod", OFPTGroupMod, 15},
		{"OFPTPortMod", OFPTPortMod, 16},
		{"OFPTTableMod", OFPTTableMod, 17},

		// Multipart messages
		{"OFPTMultipartRequest", OFPTMultipartRequest, 18},
		{"OFPTMultipartReply", OFPTMultipartReply, 19},

		// Barrier messages
		{"OFPTBarrierRequest", OFPTBarrierRequest, 20},
		{"OFPTBarrierReply", OFPTBarrierReply, 21},

		// Queue configuration
		{"OFPTQueueGetConfigRequest", OFPTQueueGetConfigRequest, 22},
		{"OFPTQueueGetConfigReply", OFPTQueueGetConfigReply, 23},

		// Controller role
		{"OFPTRoleRequest", OFPTRoleRequest, 24},
		{"OFPTRoleReply", OFPTRoleReply, 25},

		// Async configuration
		{"OFPTGetAsyncRequest", OFPTGetAsyncRequest, 26},
		{"OFPTGetAsyncReply", OFPTGetAsyncReply, 27},
		{"OFPTSetAsync", OFPTSetAsync, 28},

		// Meters
		{"OFPTMeterMod", OFPTMeterMod, 29},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value != tt.want {
				t.Errorf("%s = %d, want %d", tt.name, tt.value, tt.want)
			}
		})
	}
}

// TestConstants_FlowModCommands verifies OFPFC flow mod command constants
func TestConstants_FlowModCommands(t *testing.T) {
	tests := []struct {
		name  string
		value uint8
		want  uint8
	}{
		{"OFPFCAdd", OFPFCAdd, 0},
		{"OFPFCModify", OFPFCModify, 1},
		{"OFPFCModifyStrict", OFPFCModifyStrict, 2},
		{"OFPFCDelete", OFPFCDelete, 3},
		{"OFPFCDeleteStrict", OFPFCDeleteStrict, 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value != tt.want {
				t.Errorf("%s = %d, want %d", tt.name, tt.value, tt.want)
			}
		})
	}
}

// TestConstants_ActionTypes verifies OFPAT action type constants
func TestConstants_ActionTypes(t *testing.T) {
	tests := []struct {
		name  string
		value uint16
		want  uint16
	}{
		{"OFPATOutput", OFPATOutput, 0},
		{"OFPATCopyTTLOut", OFPATCopyTTLOut, 11},
		{"OFPATCopyTTLIn", OFPATCopyTTLIn, 12},
		{"OFPATSetMplsTTL", OFPATSetMplsTTL, 15},
		{"OFPATDecMplsTTL", OFPATDecMplsTTL, 16},
		{"OFPATPushVlan", OFPATPushVlan, 17},
		{"OFPATPopVlan", OFPATPopVlan, 18},
		{"OFPATPushMpls", OFPATPushMpls, 19},
		{"OFPATPopMpls", OFPATPopMpls, 20},
		{"OFPATSetQueue", OFPATSetQueue, 21},
		{"OFPATGroup", OFPATGroup, 22},
		{"OFPATSetNwTTL", OFPATSetNwTTL, 23},
		{"OFPATDecNwTTL", OFPATDecNwTTL, 24},
		{"OFPATSetField", OFPATSetField, 25},
		{"OFPATPushPbb", OFPATPushPbb, 26},
		{"OFPATPopPbb", OFPATPopPbb, 27},
		{"OFPATExperimenter", OFPATExperimenter, 65535},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value != tt.want {
				t.Errorf("%s = %d, want %d", tt.name, tt.value, tt.want)
			}
		})
	}
}

// TestConstants_InstructionTypes verifies OFPIT instruction type constants
func TestConstants_InstructionTypes(t *testing.T) {
	tests := []struct {
		name  string
		value uint16
		want  uint16
	}{
		{"OFPITGotoTable", OFPITGotoTable, 1},
		{"OFPITWriteMetadata", OFPITWriteMetadata, 2},
		{"OFPITWriteActions", OFPITWriteActions, 3},
		{"OFPITApplyActions", OFPITApplyActions, 4},
		{"OFPITClearActions", OFPITClearActions, 5},
		{"OFPITMeter", OFPITMeter, 6},
		{"OFPITExperimenter", OFPITExperimenter, 65535},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value != tt.want {
				t.Errorf("%s = %d, want %d", tt.name, tt.value, tt.want)
			}
		})
	}
}

// TestConstants_SpecialPorts verifies OFPP special port constants
func TestConstants_SpecialPorts(t *testing.T) {
	tests := []struct {
		name  string
		value uint32
		want  uint32
	}{
		{"OFPPMax", OFPPMax, 0xffffff00},
		{"OFPPInPort", OFPPInPort, 0xfffffff8},
		{"OFPPTable", OFPPTable, 0xfffffff9},
		{"OFPPNormal", OFPPNormal, 0xfffffffa},
		{"OFPPFlood", OFPPFlood, 0xfffffffb},
		{"OFPPAll", OFPPAll, 0xfffffffc},
		{"OFPPController", OFPPController, 0xfffffffd},
		{"OFPPLocal", OFPPLocal, 0xfffffffe},
		{"OFPPAny", OFPPAny, 0xffffffff},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value != tt.want {
				t.Errorf("%s = 0x%08x, want 0x%08x", tt.name, tt.value, tt.want)
			}
		})
	}
}

// TestConstants_MatchTypes verifies OFPMT match type constants
func TestConstants_MatchTypes(t *testing.T) {
	tests := []struct {
		name  string
		value uint8
		want  uint8
	}{
		{"OFPMTStandard", OFPMTStandard, 0},
		{"OFPMTOXM", OFPMTOXM, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value != tt.want {
				t.Errorf("%s = %d, want %d", tt.name, tt.value, tt.want)
			}
		})
	}
}

// TestConstants_OXMClasses verifies OFPXMC OXM class constants
func TestConstants_OXMClasses(t *testing.T) {
	tests := []struct {
		name  string
		value uint16
		want  uint16
	}{
		{"OFPXMCNxm0", OFPXMCNxm0, 0x0000},
		{"OFPXMCNxm1", OFPXMCNxm1, 0x0001},
		{"OFPXMCOpenflowBasic", OFPXMCOpenflowBasic, 0x8000},
		{"OFPXMCExperimenter", OFPXMCExperimenter, 0xFFFF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value != tt.want {
				t.Errorf("%s = 0x%04x, want 0x%04x", tt.name, tt.value, tt.want)
			}
		})
	}
}

// TestConstants_OXMFields verifies OFPXMT OXM field constants
func TestConstants_OXMFields(t *testing.T) {
	tests := []struct {
		name  string
		value uint8
		want  uint8
	}{
		{"OFPXMTOFBInPort", OFPXMTOFBInPort, 0},
		{"OFPXMTOFBInPhyPort", OFPXMTOFBInPhyPort, 1},
		{"OFPXMTOFBMetadata", OFPXMTOFBMetadata, 2},
		{"OFPXMTOFBEthDst", OFPXMTOFBEthDst, 3},
		{"OFPXMTOFBEthSrc", OFPXMTOFBEthSrc, 4},
		{"OFPXMTOFBEthType", OFPXMTOFBEthType, 5},
		{"OFPXMTOFBVlanVid", OFPXMTOFBVlanVid, 6},
		{"OFPXMTOFBVlanPcp", OFPXMTOFBVlanPcp, 7},
		{"OFPXMTOFBIPDscp", OFPXMTOFBIPDscp, 8},
		{"OFPXMTOFBIPEcn", OFPXMTOFBIPEcn, 9},
		{"OFPXMTOFBIPProto", OFPXMTOFBIPProto, 10},
		{"OFPXMTOFBIPv4Src", OFPXMTOFBIPv4Src, 11},
		{"OFPXMTOFBIPv4Dst", OFPXMTOFBIPv4Dst, 12},
		{"OFPXMTOFBTCPSrc", OFPXMTOFBTCPSrc, 13},
		{"OFPXMTOFBTCPDst", OFPXMTOFBTCPDst, 14},
		{"OFPXMTOFBUDPSrc", OFPXMTOFBUDPSrc, 15},
		{"OFPXMTOFBUDPDst", OFPXMTOFBUDPDst, 16},
		{"OFPXMTOFBSCTPSrc", OFPXMTOFBSCTPSrc, 17},
		{"OFPXMTOFBSCTPDst", OFPXMTOFBSCTPDst, 18},
		{"OFPXMTOFBICMPv4Type", OFPXMTOFBICMPv4Type, 19},
		{"OFPXMTOFBICMPv4Code", OFPXMTOFBICMPv4Code, 20},
		{"OFPXMTOFBArpOp", OFPXMTOFBArpOp, 21},
		{"OFPXMTOFBArpSpa", OFPXMTOFBArpSpa, 22},
		{"OFPXMTOFBArpTpa", OFPXMTOFBArpTpa, 23},
		{"OFPXMTOFBArpSha", OFPXMTOFBArpSha, 24},
		{"OFPXMTOFBArpTha", OFPXMTOFBArpTha, 25},
		{"OFPXMTOFBIPv6Src", OFPXMTOFBIPv6Src, 26},
		{"OFPXMTOFBIPv6Dst", OFPXMTOFBIPv6Dst, 27},
		{"OFPXMTOFBIPv6Flabel", OFPXMTOFBIPv6Flabel, 28},
		{"OFPXMTOFBICMPv6Type", OFPXMTOFBICMPv6Type, 29},
		{"OFPXMTOFBICMPv6Code", OFPXMTOFBICMPv6Code, 30},
		{"OFPXMTOFBIPv6NdTarget", OFPXMTOFBIPv6NdTarget, 31},
		{"OFPXMTOFBIPv6NdSll", OFPXMTOFBIPv6NdSll, 32},
		{"OFPXMTOFBIPv6NdTll", OFPXMTOFBIPv6NdTll, 33},
		{"OFPXMTOFBMplsLabel", OFPXMTOFBMplsLabel, 34},
		{"OFPXMTOFBMplsTc", OFPXMTOFBMplsTc, 35},
		{"OFPXMTOFBMplsBos", OFPXMTOFBMplsBos, 36},
		{"OFPXMTOFBPbbIsid", OFPXMTOFBPbbIsid, 37},
		{"OFPXMTOFBTunnelId", OFPXMTOFBTunnelId, 38},
		{"OFPXMTOFBIPv6Exthdr", OFPXMTOFBIPv6Exthdr, 39},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value != tt.want {
				t.Errorf("%s = %d, want %d", tt.name, tt.value, tt.want)
			}
		})
	}
}

// TestByteOrder_BigEndian verifies BigEndian encoding
func TestByteOrder_BigEndian(t *testing.T) {
	if ByteOrder != binary.BigEndian {
		t.Error("ByteOrder should be binary.BigEndian")
	}
}

// TestByteOrder_Uint16 verifies encoding/decoding uint16
func TestByteOrder_Uint16(t *testing.T) {
	tests := []struct {
		name  string
		value uint16
		want  []byte
	}{
		{
			name:  "zero",
			value: 0,
			want:  []byte{0x00, 0x00},
		},
		{
			name:  "small value",
			value: 8,
			want:  []byte{0x00, 0x08},
		},
		{
			name:  "medium value",
			value: 12345,
			want:  []byte{0x30, 0x39},
		},
		{
			name:  "max value",
			value: 0xFFFF,
			want:  []byte{0xFF, 0xFF},
		},
		{
			name:  "network byte order test",
			value: 0x1234,
			want:  []byte{0x12, 0x34},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode
			buf := make([]byte, 2)
			ByteOrder.PutUint16(buf, tt.value)
			if !bytes.Equal(buf, tt.want) {
				t.Errorf("PutUint16(%d) = %v, want %v", tt.value, buf, tt.want)
			}

			// Decode
			decoded := ByteOrder.Uint16(tt.want)
			if decoded != tt.value {
				t.Errorf("Uint16(%v) = %d, want %d", tt.want, decoded, tt.value)
			}
		})
	}
}

// TestByteOrder_Uint32 verifies encoding/decoding uint32
func TestByteOrder_Uint32(t *testing.T) {
	tests := []struct {
		name  string
		value uint32
		want  []byte
	}{
		{
			name:  "zero",
			value: 0,
			want:  []byte{0x00, 0x00, 0x00, 0x00},
		},
		{
			name:  "small value",
			value: 1,
			want:  []byte{0x00, 0x00, 0x00, 0x01},
		},
		{
			name:  "medium value",
			value: 12345,
			want:  []byte{0x00, 0x00, 0x30, 0x39},
		},
		{
			name:  "large value",
			value: 0x12345678,
			want:  []byte{0x12, 0x34, 0x56, 0x78},
		},
		{
			name:  "max value",
			value: 0xFFFFFFFF,
			want:  []byte{0xFF, 0xFF, 0xFF, 0xFF},
		},
		{
			name:  "special port OFPP_CONTROLLER",
			value: OFPPController,
			want:  []byte{0xFF, 0xFF, 0xFF, 0xFD},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode
			buf := make([]byte, 4)
			ByteOrder.PutUint32(buf, tt.value)
			if !bytes.Equal(buf, tt.want) {
				t.Errorf("PutUint32(%d) = %v, want %v", tt.value, buf, tt.want)
			}

			// Decode
			decoded := ByteOrder.Uint32(tt.want)
			if decoded != tt.value {
				t.Errorf("Uint32(%v) = %d, want %d", tt.want, decoded, tt.value)
			}
		})
	}
}

// TestByteOrder_Uint64 verifies encoding/decoding uint64
func TestByteOrder_Uint64(t *testing.T) {
	tests := []struct {
		name  string
		value uint64
		want  []byte
	}{
		{
			name:  "zero",
			value: 0,
			want:  []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:  "small value",
			value: 1,
			want:  []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		},
		{
			name:  "medium value",
			value: 12345,
			want:  []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x39},
		},
		{
			name:  "large value",
			value: 0x123456789ABCDEF0,
			want:  []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0},
		},
		{
			name:  "max value",
			value: 0xFFFFFFFFFFFFFFFF,
			want:  []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode
			buf := make([]byte, 8)
			ByteOrder.PutUint64(buf, tt.value)
			if !bytes.Equal(buf, tt.want) {
				t.Errorf("PutUint64(%d) = %v, want %v", tt.value, buf, tt.want)
			}

			// Decode
			decoded := ByteOrder.Uint64(tt.want)
			if decoded != tt.value {
				t.Errorf("Uint64(%v) = %d, want %d", tt.want, decoded, tt.value)
			}
		})
	}
}
