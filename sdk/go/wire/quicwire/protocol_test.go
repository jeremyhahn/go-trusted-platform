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

//go:build codec_msgpack

package quicwire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-codec"
)

func init() {
	// Set the default codec to MsgPack for encoding/decoding payloads
	_ = SetDefaultCodecType(codec.MsgPack)
}

func TestProtocolConstants(t *testing.T) {
	// Verify protocol version
	if ProtocolVersion != 0x01 {
		t.Errorf("expected ProtocolVersion 0x01, got 0x%02X", ProtocolVersion)
	}

	// Verify max payload size (16MB)
	if MaxPayloadSize != 16*1024*1024 {
		t.Errorf("expected MaxPayloadSize 16MB, got %d", MaxPayloadSize)
	}

	// Verify max token size (8KB)
	if MaxTokenSize != 8*1024 {
		t.Errorf("expected MaxTokenSize 8KB, got %d", MaxTokenSize)
	}
}

func TestStatusCodes(t *testing.T) {
	statusCodes := []struct {
		code     byte
		expected byte
	}{
		{StatusOK, 0x00},
		{StatusInvalidRequest, 0x01},
		{StatusNotFound, 0x02},
		{StatusUnauthorized, 0x03},
		{StatusInternalError, 0x04},
		{StatusTimeout, 0x05},
		{StatusAlreadyExists, 0x06},
		{StatusPermissionDenied, 0x07},
		{StatusResourceExhausted, 0x08},
		{StatusInvalidArgument, 0x09},
		{StatusUnavailable, 0x0A},
		{StatusNotImplemented, 0x0B},
		{StatusFailedPrecondition, 0x0C},
	}

	for _, tt := range statusCodes {
		if tt.code != tt.expected {
			t.Errorf("expected status code 0x%02X, got 0x%02X", tt.expected, tt.code)
		}
	}
}

func TestWriteRequest(t *testing.T) {
	tests := []struct {
		name        string
		request     *Request
		expectError bool
		errorSubstr string
	}{
		{
			name: "valid request without payload",
			request: &Request{
				Opcode:  OpHealth,
				Token:   "",
				Payload: nil,
			},
			expectError: false,
		},
		{
			name: "valid request with payload",
			request: &Request{
				Opcode:  OpVTPMCreate,
				Token:   "test-token",
				Payload: []byte("test payload"),
			},
			expectError: false,
		},
		{
			name: "valid request with large payload",
			request: &Request{
				Opcode:  OpDeviceRegister,
				Token:   "auth-token",
				Payload: make([]byte, 1024),
			},
			expectError: false,
		},
		{
			name:        "nil request",
			request:     nil,
			expectError: true,
			errorSubstr: "nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := WriteRequest(&buf, tt.request)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				if !strings.Contains(strings.ToLower(err.Error()), tt.errorSubstr) {
					t.Errorf("expected error containing '%s', got '%s'", tt.errorSubstr, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}

				// Verify the buffer has content
				if buf.Len() == 0 {
					t.Error("expected non-empty buffer")
				}
			}
		})
	}
}

func TestWriteRequestPayloadTooLarge(t *testing.T) {
	req := &Request{
		Opcode:  OpHealth,
		Token:   "",
		Payload: make([]byte, MaxPayloadSize+1),
	}

	var buf bytes.Buffer
	err := WriteRequest(&buf, req)

	if err == nil {
		t.Error("expected error for payload too large")
		return
	}

	if !strings.Contains(err.Error(), "exceeds maximum") {
		t.Errorf("expected error about exceeding maximum, got: %s", err.Error())
	}
}

func TestWriteRequestTokenTooLarge(t *testing.T) {
	req := &Request{
		Opcode:  OpHealth,
		Token:   string(make([]byte, MaxTokenSize+1)),
		Payload: nil,
	}

	var buf bytes.Buffer
	err := WriteRequest(&buf, req)

	if err == nil {
		t.Error("expected error for token too large")
		return
	}

	if !strings.Contains(err.Error(), "exceeds maximum") {
		t.Errorf("expected error about exceeding maximum, got: %s", err.Error())
	}
}

func TestReadRequest(t *testing.T) {
	tests := []struct {
		name        string
		request     *Request
		expectError bool
	}{
		{
			name: "valid request without token and payload",
			request: &Request{
				Opcode:  OpHealth,
				Token:   "",
				Payload: nil,
			},
			expectError: false,
		},
		{
			name: "valid request with token",
			request: &Request{
				Opcode:  OpAuthLogin,
				Token:   "bearer-token-123",
				Payload: nil,
			},
			expectError: false,
		},
		{
			name: "valid request with payload",
			request: &Request{
				Opcode:  OpVTPMCreate,
				Token:   "",
				Payload: []byte("create vtpm payload"),
			},
			expectError: false,
		},
		{
			name: "valid request with token and payload",
			request: &Request{
				Opcode:  OpDeviceRegister,
				Token:   "auth-token-xyz",
				Payload: []byte(`{"device": "test"}`),
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Write the request to a buffer
			var buf bytes.Buffer
			err := WriteRequest(&buf, tt.request)
			if err != nil {
				t.Fatalf("failed to write request: %v", err)
			}

			// Read it back
			readReq, err := ReadRequest(&buf)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}

				if readReq.Opcode != tt.request.Opcode {
					t.Errorf("expected opcode 0x%02X, got 0x%02X", tt.request.Opcode, readReq.Opcode)
				}

				if readReq.Token != tt.request.Token {
					t.Errorf("expected token '%s', got '%s'", tt.request.Token, readReq.Token)
				}

				if !bytes.Equal(readReq.Payload, tt.request.Payload) {
					t.Errorf("expected payload %v, got %v", tt.request.Payload, readReq.Payload)
				}
			}
		})
	}
}

func TestReadRequestFromEmptyReader(t *testing.T) {
	var buf bytes.Buffer
	_, err := ReadRequest(&buf)

	if err == nil {
		t.Error("expected error for empty reader")
	}
}

func TestReadRequestTokenTooLarge(t *testing.T) {
	// Manually construct a message with token length exceeding max
	var buf bytes.Buffer

	// Write opcode
	buf.WriteByte(OpHealth)

	// Write token length (exceeds MaxTokenSize)
	tokenLen := make([]byte, 2)
	binary.BigEndian.PutUint16(tokenLen, MaxTokenSize+1)
	buf.Write(tokenLen)

	_, err := ReadRequest(&buf)

	if err == nil {
		t.Error("expected error for token too large")
		return
	}

	if !strings.Contains(err.Error(), "exceeds maximum") {
		t.Errorf("expected error about exceeding maximum, got: %s", err.Error())
	}
}

func TestReadRequestPayloadTooLarge(t *testing.T) {
	// Manually construct a message with payload length exceeding max
	var buf bytes.Buffer

	// Write opcode
	buf.WriteByte(OpHealth)

	// Write token length (0)
	tokenLen := make([]byte, 2)
	binary.BigEndian.PutUint16(tokenLen, 0)
	buf.Write(tokenLen)

	// Write payload length (exceeds MaxPayloadSize)
	payloadLen := make([]byte, 4)
	binary.BigEndian.PutUint32(payloadLen, MaxPayloadSize+1)
	buf.Write(payloadLen)

	_, err := ReadRequest(&buf)

	if err == nil {
		t.Error("expected error for payload too large")
		return
	}

	if !strings.Contains(err.Error(), "exceeds maximum") {
		t.Errorf("expected error about exceeding maximum, got: %s", err.Error())
	}
}

func TestWriteResponse(t *testing.T) {
	tests := []struct {
		name        string
		response    *Response
		expectError bool
		errorSubstr string
	}{
		{
			name: "valid response without payload",
			response: &Response{
				Status:  StatusOK,
				Payload: nil,
			},
			expectError: false,
		},
		{
			name: "valid response with payload",
			response: &Response{
				Status:  StatusOK,
				Payload: []byte("response data"),
			},
			expectError: false,
		},
		{
			name: "error response",
			response: &Response{
				Status:  StatusNotFound,
				Payload: []byte("resource not found"),
			},
			expectError: false,
		},
		{
			name:        "nil response",
			response:    nil,
			expectError: true,
			errorSubstr: "nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := WriteResponse(&buf, tt.response)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				if !strings.Contains(strings.ToLower(err.Error()), tt.errorSubstr) {
					t.Errorf("expected error containing '%s', got '%s'", tt.errorSubstr, err.Error())
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestWriteResponsePayloadTooLarge(t *testing.T) {
	resp := &Response{
		Status:  StatusOK,
		Payload: make([]byte, MaxPayloadSize+1),
	}

	var buf bytes.Buffer
	err := WriteResponse(&buf, resp)

	if err == nil {
		t.Error("expected error for payload too large")
		return
	}

	if !strings.Contains(err.Error(), "exceeds maximum") {
		t.Errorf("expected error about exceeding maximum, got: %s", err.Error())
	}
}

func TestReadResponse(t *testing.T) {
	tests := []struct {
		name     string
		response *Response
	}{
		{
			name: "success response without payload",
			response: &Response{
				Status:  StatusOK,
				Payload: nil,
			},
		},
		{
			name: "success response with payload",
			response: &Response{
				Status:  StatusOK,
				Payload: []byte("success data"),
			},
		},
		{
			name: "error response",
			response: &Response{
				Status:  StatusInternalError,
				Payload: []byte("internal error occurred"),
			},
		},
		{
			name: "not found response",
			response: &Response{
				Status:  StatusNotFound,
				Payload: []byte("resource not found"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Write the response to a buffer
			var buf bytes.Buffer
			err := WriteResponse(&buf, tt.response)
			if err != nil {
				t.Fatalf("failed to write response: %v", err)
			}

			// Read it back
			readResp, err := ReadResponse(&buf)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if readResp.Status != tt.response.Status {
				t.Errorf("expected status 0x%02X, got 0x%02X", tt.response.Status, readResp.Status)
			}

			if !bytes.Equal(readResp.Payload, tt.response.Payload) {
				t.Errorf("expected payload %v, got %v", tt.response.Payload, readResp.Payload)
			}
		})
	}
}

func TestReadResponseFromEmptyReader(t *testing.T) {
	var buf bytes.Buffer
	_, err := ReadResponse(&buf)

	if err == nil {
		t.Error("expected error for empty reader")
	}
}

func TestReadResponsePayloadTooLarge(t *testing.T) {
	// Manually construct a response with payload length exceeding max
	var buf bytes.Buffer

	// Write status
	buf.WriteByte(StatusOK)

	// Write payload length (exceeds MaxPayloadSize)
	payloadLen := make([]byte, 4)
	binary.BigEndian.PutUint32(payloadLen, MaxPayloadSize+1)
	buf.Write(payloadLen)

	_, err := ReadResponse(&buf)

	if err == nil {
		t.Error("expected error for payload too large")
		return
	}

	if !strings.Contains(err.Error(), "exceeds maximum") {
		t.Errorf("expected error about exceeding maximum, got: %s", err.Error())
	}
}

func TestEncodePayload(t *testing.T) {
	tests := []struct {
		name        string
		entity      interface{}
		expectError bool
		expectNil   bool
	}{
		{
			name:        "nil entity returns nil",
			entity:      nil,
			expectError: false,
			expectNil:   true,
		},
		{
			name:        "string entity",
			entity:      "test string",
			expectError: false,
			expectNil:   false,
		},
		{
			name:        "int entity",
			entity:      42,
			expectError: false,
			expectNil:   false,
		},
		{
			name:        "map entity",
			entity:      map[string]string{"key": "value"},
			expectError: false,
			expectNil:   false,
		},
		{
			name: "struct entity",
			entity: struct {
				Name  string
				Value int
			}{Name: "test", Value: 123},
			expectError: false,
			expectNil:   false,
		},
		{
			name:        "slice entity",
			entity:      []int{1, 2, 3},
			expectError: false,
			expectNil:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := EncodePayload(tt.entity)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}

				if tt.expectNil {
					if result != nil {
						t.Errorf("expected nil result, got %v", result)
					}
				} else if len(result) == 0 {
					t.Error("expected non-empty result")
				}
			}
		})
	}
}

func TestDecodePayload(t *testing.T) {
	tests := []struct {
		name        string
		entity      interface{}
		expectError bool
	}{
		{
			name:        "string entity",
			entity:      "test string",
			expectError: false,
		},
		{
			name:        "int entity",
			entity:      42,
			expectError: false,
		},
		{
			name:        "map entity",
			entity:      map[string]string{"key": "value"},
			expectError: false,
		},
		{
			name: "struct entity",
			entity: struct {
				Name  string
				Value int
			}{Name: "test", Value: 123},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode first
			encoded, err := EncodePayload(tt.entity)
			if err != nil {
				t.Fatalf("failed to encode: %v", err)
			}

			// Decode back - use pointer for struct
			var decoded interface{}
			err = DecodePayload(encoded, &decoded)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestDecodePayloadEmptyData(t *testing.T) {
	var result string
	err := DecodePayload([]byte{}, &result)

	if err != nil {
		t.Errorf("expected no error for empty data, got: %v", err)
	}
}

func TestDecodePayloadNilEntity(t *testing.T) {
	encoded, err := EncodePayload("test")
	if err != nil {
		t.Fatalf("failed to encode: %v", err)
	}

	err = DecodePayload(encoded, nil)

	if err == nil {
		t.Error("expected error for nil entity")
		return
	}

	if !strings.Contains(err.Error(), "nil") {
		t.Errorf("expected error about nil entity, got: %s", err.Error())
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	type TestStruct struct {
		Name    string
		Age     int
		Active  bool
		Tags    []string
		Mapping map[string]int
	}

	original := TestStruct{
		Name:    "John Doe",
		Age:     30,
		Active:  true,
		Tags:    []string{"tag1", "tag2"},
		Mapping: map[string]int{"a": 1, "b": 2},
	}

	encoded, err := EncodePayload(original)
	if err != nil {
		t.Fatalf("failed to encode: %v", err)
	}

	var decoded TestStruct
	err = DecodePayload(encoded, &decoded)
	if err != nil {
		t.Fatalf("failed to decode: %v", err)
	}

	if decoded.Name != original.Name {
		t.Errorf("expected Name '%s', got '%s'", original.Name, decoded.Name)
	}

	if decoded.Age != original.Age {
		t.Errorf("expected Age %d, got %d", original.Age, decoded.Age)
	}

	if decoded.Active != original.Active {
		t.Errorf("expected Active %v, got %v", original.Active, decoded.Active)
	}

	if len(decoded.Tags) != len(original.Tags) {
		t.Errorf("expected %d tags, got %d", len(original.Tags), len(decoded.Tags))
	}

	if len(decoded.Mapping) != len(original.Mapping) {
		t.Errorf("expected %d mappings, got %d", len(original.Mapping), len(decoded.Mapping))
	}
}

func TestOpcodeToString(t *testing.T) {
	tests := []struct {
		opcode   byte
		expected string
	}{
		// Health Operations
		{OpHealth, "Health"},
		{OpLiveness, "Liveness"},
		{OpReadiness, "Readiness"},

		// vTPM Operations
		{OpVTPMCreate, "VTPMCreate"},
		{OpVTPMDelete, "VTPMDelete"},
		{OpVTPMStart, "VTPMStart"},
		{OpVTPMStop, "VTPMStop"},
		{OpVTPMGetState, "VTPMGetState"},
		{OpVTPMList, "VTPMList"},
		{OpVTPMGetEK, "VTPMGetEK"},
		{OpVTPMGetAK, "VTPMGetAK"},
		{OpVTPMCreateAK, "VTPMCreateAK"},
		{OpVTPMQuote, "VTPMQuote"},
		{OpVTPMVerifyQuote, "VTPMVerifyQuote"},
		{OpVTPMExtendPCR, "VTPMExtendPCR"},
		{OpVTPMReadPCR, "VTPMReadPCR"},
		{OpVTPMSeal, "VTPMSeal"},
		{OpVTPMUnseal, "VTPMUnseal"},
		{OpVTPMGetRandom, "VTPMGetRandom"},

		// DNS Operations
		{OpDNSAddRecord, "DNSAddRecord"},
		{OpDNSDeleteRecord, "DNSDeleteRecord"},
		{OpDNSUpdateRecord, "DNSUpdateRecord"},
		{OpDNSGetRecord, "DNSGetRecord"},
		{OpDNSListRecords, "DNSListRecords"},
		{OpDNSAddZone, "DNSAddZone"},
		{OpDNSDeleteZone, "DNSDeleteZone"},
		{OpDNSGetZone, "DNSGetZone"},
		{OpDNSListZones, "DNSListZones"},
		{OpDNSResolve, "DNSResolve"},
		{OpDNSGetConfig, "DNSGetConfig"},
		{OpDNSGetMetrics, "DNSGetMetrics"},

		// Device Operations
		{OpDeviceRegister, "DeviceRegister"},
		{OpDeviceUnregister, "DeviceUnregister"},
		{OpDeviceGet, "DeviceGet"},
		{OpDeviceList, "DeviceList"},
		{OpDeviceUpdate, "DeviceUpdate"},
		{OpDeviceGetProfile, "DeviceGetProfile"},
		{OpDeviceSetProfile, "DeviceSetProfile"},
		{OpDeviceListProfiles, "DeviceListProfiles"},
		{OpDeviceCreateProfile, "DeviceCreateProfile"},
		{OpDeviceDeleteProfile, "DeviceDeleteProfile"},
		{OpDeviceAttest, "DeviceAttest"},
		{OpDeviceActivate, "DeviceActivate"},
		{OpDeviceGetState, "DeviceGetState"},

		// SDN Operations
		{OpSDNGetPortState, "SDNGetPortState"},
		{OpSDNSetPortState, "SDNSetPortState"},
		{OpSDNListPorts, "SDNListPorts"},
		{OpSDNGetFlow, "SDNGetFlow"},
		{OpSDNAddFlow, "SDNAddFlow"},
		{OpSDNDeleteFlow, "SDNDeleteFlow"},
		{OpSDNListFlows, "SDNListFlows"},
		{OpSDNApplyPolicy, "SDNApplyPolicy"},
		{OpSDNGetPolicy, "SDNGetPolicy"},
		{OpSDNListPolicies, "SDNListPolicies"},
		{OpSDNGetBridge, "SDNGetBridge"},
		{OpSDNListBridges, "SDNListBridges"},
		{OpSDNGetMetrics, "SDNGetMetrics"},
		{OpSDNSetVLAN, "SDNSetVLAN"},
		{OpSDNGetVLAN, "SDNGetVLAN"},

		// NTP (time synchronization) category opcode
		{OpNTPCategory, "NTPCategory"},

		// IAM tenant-record category opcode
		{OpIAMCategory, "IAMCategory"},
		{OpVPNCategory, "VPNCategory"},
		{OpCacheCategory, "CacheCategory"},
		{OpSchedulerCategory, "SchedulerCategory"},
		{OpMessagingCategory, "MessagingCategory"},
		{OpObjectStorageCategory, "ObjectStorageCategory"},

		// VM Operations
		{OpVMExtendedCategory, "VMExtendedCategory"},

		// Attestation Operations
		{OpAttestQuote, "AttestQuote"},
		{OpAttestVerify, "AttestVerify"},
		{OpAttestCollectHost, "AttestCollectHost"},
		{OpAttestGetAK, "AttestGetAK"},
		{OpAttestChallenge, "AttestChallenge"},
		{OpAttestPollVerdicts, "AttestPollVerdicts"},
		{OpAttestGetReport, "AttestGetReport"},
		{OpAttestGetPCRs, "AttestGetPCRs"},

		// Certificate Operations
		{OpCertIssue, "CertIssue"},
		{OpCertRevoke, "CertRevoke"},
		{OpCertRenew, "CertRenew"},
		{OpCertGet, "CertGet"},
		{OpCertList, "CertList"},
		{OpCertVerify, "CertVerify"},
		{OpCertGetChain, "CertGetChain"},
		{OpCertGetCRL, "CertGetCRL"},
		{OpCertGetOCSP, "CertGetOCSP"},

		// Cluster category opcode
		{OpClusterCategory, "ClusterCategory"},

		// JWT/Auth Operations
		{OpJWTVerify, "JWTVerify"},
		{OpJWTRefresh, "JWTRefresh"},
		{OpJWTRevoke, "JWTRevoke"},
		{OpJWTGetKeys, "JWTGetKeys"},
		{OpAuthLogin, "AuthLogin"},
		{OpAuthLogout, "AuthLogout"},
		{OpAuthCheck, "AuthCheck"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := OpcodeToString(tt.opcode)
			if result != tt.expected {
				t.Errorf("expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

// TestOpcodeToString_RetiredBytes pins the DNS and device bytes retired
// unimplemented in #317: none of them names an operation any more.
func TestOpcodeToString_RetiredBytes(t *testing.T) {
	for _, opcode := range []byte{0x2B, 0x2D, 0x3C, 0x3E} {
		want := fmt.Sprintf("Unknown(0x%02X)", opcode)
		if got := OpcodeToString(opcode); got != want {
			t.Errorf("OpcodeToString(0x%02X) = %q, want %q", opcode, got, want)
		}
	}
}

func TestOpcodeDaemonListProtocols(t *testing.T) {
	// Verify 0x98 is now defined as OpDaemonListProtocols
	// All 256 opcodes are assigned, so there are no "unknown" opcodes.
	opcode := byte(0x98)
	result := OpcodeToString(opcode)

	if result != "DaemonListProtocols" {
		t.Errorf("expected 'DaemonListProtocols', got '%s'", result)
	}
}

func TestStatusToString(t *testing.T) {
	tests := []struct {
		status   byte
		expected string
	}{
		{StatusOK, "OK"},
		{StatusInvalidRequest, "InvalidRequest"},
		{StatusNotFound, "NotFound"},
		{StatusUnauthorized, "Unauthorized"},
		{StatusInternalError, "InternalError"},
		{StatusTimeout, "Timeout"},
		{StatusAlreadyExists, "AlreadyExists"},
		{StatusPermissionDenied, "PermissionDenied"},
		{StatusResourceExhausted, "ResourceExhausted"},
		{StatusInvalidArgument, "InvalidArgument"},
		{StatusUnavailable, "Unavailable"},
		{StatusNotImplemented, "NotImplemented"},
		{StatusFailedPrecondition, "FailedPrecondition"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := StatusToString(tt.status)
			if result != tt.expected {
				t.Errorf("expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestStatusToStringUnknown(t *testing.T) {
	unknownStatus := byte(0xFF)
	result := StatusToString(unknownStatus)

	if !strings.HasPrefix(result, "Unknown") {
		t.Errorf("expected 'Unknown(...)', got '%s'", result)
	}

	if !strings.Contains(result, "0xFF") {
		t.Errorf("expected result to contain '0xFF', got '%s'", result)
	}
}

func TestRequestResponseWireFormat(t *testing.T) {
	// Test that the wire format matches the documented format
	// Request: [opcode:1][tokenLen:2][token:N][payloadLen:4][payload:M]

	req := &Request{
		Opcode:  OpVTPMCreate,
		Token:   "token123",
		Payload: []byte("payload-data"),
	}

	var buf bytes.Buffer
	err := WriteRequest(&buf, req)
	if err != nil {
		t.Fatalf("failed to write request: %v", err)
	}

	data := buf.Bytes()

	// Verify opcode is first byte
	if data[0] != OpVTPMCreate {
		t.Errorf("expected opcode 0x%02X at position 0, got 0x%02X", OpVTPMCreate, data[0])
	}

	// Verify token length (big-endian 2 bytes)
	tokenLen := binary.BigEndian.Uint16(data[1:3])
	if tokenLen != uint16(len(req.Token)) {
		t.Errorf("expected token length %d, got %d", len(req.Token), tokenLen)
	}

	// Verify payload length (big-endian 4 bytes)
	payloadLenOffset := 3 + len(req.Token)
	payloadLen := binary.BigEndian.Uint32(data[payloadLenOffset : payloadLenOffset+4])
	if payloadLen != uint32(len(req.Payload)) {
		t.Errorf("expected payload length %d, got %d", len(req.Payload), payloadLen)
	}
}

func TestResponseWireFormat(t *testing.T) {
	// Test that the wire format matches the documented format
	// Response: [status:1][payloadLen:4][payload:N]

	resp := &Response{
		Status:  StatusOK,
		Payload: []byte("response-data"),
	}

	var buf bytes.Buffer
	err := WriteResponse(&buf, resp)
	if err != nil {
		t.Fatalf("failed to write response: %v", err)
	}

	data := buf.Bytes()

	// Verify status is first byte
	if data[0] != StatusOK {
		t.Errorf("expected status 0x%02X at position 0, got 0x%02X", StatusOK, data[0])
	}

	// Verify payload length (big-endian 4 bytes)
	payloadLen := binary.BigEndian.Uint32(data[1:5])
	if payloadLen != uint32(len(resp.Payload)) {
		t.Errorf("expected payload length %d, got %d", len(resp.Payload), payloadLen)
	}
}

// errWriter is a test helper that always returns an error
type errWriter struct {
	failAfter int
	written   int
}

func (w *errWriter) Write(p []byte) (int, error) {
	if w.written >= w.failAfter {
		return 0, errors.New("write error")
	}
	w.written += len(p)
	return len(p), nil
}

func TestWriteRequestWriteErrors(t *testing.T) {
	tests := []struct {
		name        string
		failAfter   int
		errorSubstr string
	}{
		{
			name:        "fail on opcode write",
			failAfter:   0,
			errorSubstr: "opcode",
		},
		{
			name:        "fail on token length write",
			failAfter:   1,
			errorSubstr: "token length",
		},
		{
			name:        "fail on token write",
			failAfter:   3,
			errorSubstr: "token",
		},
		{
			name:        "fail on payload length write",
			failAfter:   13, // 1 (opcode) + 2 (token len) + 10 (token)
			errorSubstr: "payload length",
		},
		{
			name:        "fail on payload write",
			failAfter:   17, // 1 (opcode) + 2 (token len) + 10 (token) + 4 (payload len)
			errorSubstr: "payload",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &errWriter{failAfter: tt.failAfter}
			req := &Request{
				Opcode:  OpHealth,
				Token:   "1234567890",
				Payload: []byte("test-payload"),
			}

			err := WriteRequest(w, req)

			if err == nil {
				t.Error("expected error, got nil")
				return
			}

			if !strings.Contains(strings.ToLower(err.Error()), tt.errorSubstr) {
				t.Errorf("expected error containing '%s', got '%s'", tt.errorSubstr, err.Error())
			}
		})
	}
}

func TestWriteResponseWriteErrors(t *testing.T) {
	// WriteResponse assembles the entire frame into a single buffer and
	// performs exactly one Write call. The only write-error case is when
	// that single Write fails (failAfter=0 on the errWriter).
	resp := &Response{
		Status:  StatusOK,
		Payload: []byte("test-payload"),
	}

	w := &errWriter{failAfter: 0}
	err := WriteResponse(w, resp)
	if err == nil {
		t.Error("expected error when Write fails immediately, got nil")
		return
	}
	if !strings.Contains(strings.ToLower(err.Error()), "response") {
		t.Errorf("expected error containing 'response', got '%s'", err.Error())
	}
}

func TestReadRequestPartialData(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		errorSubstr string
	}{
		{
			name:        "truncated after opcode",
			data:        []byte{OpHealth},
			errorSubstr: "token length",
		},
		{
			name:        "truncated after token length",
			data:        []byte{OpHealth, 0x00, 0x05},
			errorSubstr: "token",
		},
		{
			name:        "truncated after token",
			data:        []byte{OpHealth, 0x00, 0x05, 't', 'o', 'k', 'e', 'n'},
			errorSubstr: "payload length",
		},
		{
			name:        "truncated after payload length",
			data:        []byte{OpHealth, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05},
			errorSubstr: "payload",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := bytes.NewReader(tt.data)
			_, err := ReadRequest(buf)

			if err == nil {
				t.Error("expected error, got nil")
				return
			}

			if !strings.Contains(strings.ToLower(err.Error()), tt.errorSubstr) {
				t.Errorf("expected error containing '%s', got '%s'", tt.errorSubstr, err.Error())
			}
		})
	}
}

func TestReadResponsePartialData(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		errorSubstr string
	}{
		{
			name:        "truncated after status",
			data:        []byte{StatusOK},
			errorSubstr: "payload length",
		},
		{
			name:        "truncated after payload length",
			data:        []byte{StatusOK, 0x00, 0x00, 0x00, 0x05},
			errorSubstr: "payload",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := bytes.NewReader(tt.data)
			_, err := ReadResponse(buf)

			if err == nil {
				t.Error("expected error, got nil")
				return
			}

			if !strings.Contains(strings.ToLower(err.Error()), tt.errorSubstr) {
				t.Errorf("expected error containing '%s', got '%s'", tt.errorSubstr, err.Error())
			}
		})
	}
}

func TestEncodePayloadInvalidType(t *testing.T) {
	// Channels cannot be encoded by msgpack
	ch := make(chan int)
	_, err := EncodePayload(ch)

	if err == nil {
		t.Error("expected error for channel type, got nil")
	}
}

func TestDecodePayloadInvalidData(t *testing.T) {
	// Invalid msgpack data
	invalidData := []byte{0xFF, 0xFF, 0xFF}
	var result string
	err := DecodePayload(invalidData, &result)

	if err == nil {
		t.Error("expected error for invalid msgpack data, got nil")
	}
}

func TestDecodePayloadTypeMismatch(t *testing.T) {
	// Encode a string
	encoded, err := EncodePayload("test string")
	if err != nil {
		t.Fatalf("failed to encode: %v", err)
	}

	// Try to decode into a struct - may cause issues
	var result struct {
		Name string
	}
	// This should either succeed with empty values or fail
	// Depends on msgpack implementation
	_ = DecodePayload(encoded, &result)
}

func TestWriteRequestEmptyPayloadNoToken(t *testing.T) {
	req := &Request{
		Opcode:  OpHealth,
		Token:   "",
		Payload: nil,
	}

	var buf bytes.Buffer
	err := WriteRequest(&buf, req)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Read it back
	readReq, err := ReadRequest(&buf)
	if err != nil {
		t.Errorf("unexpected error reading request: %v", err)
	}

	if readReq.Opcode != OpHealth {
		t.Errorf("expected opcode Health, got 0x%02X", readReq.Opcode)
	}

	if readReq.Token != "" {
		t.Errorf("expected empty token, got '%s'", readReq.Token)
	}

	if len(readReq.Payload) != 0 {
		t.Errorf("expected empty payload, got %v", readReq.Payload)
	}
}

func TestWriteResponseEmptyPayload(t *testing.T) {
	resp := &Response{
		Status:  StatusOK,
		Payload: nil,
	}

	var buf bytes.Buffer
	err := WriteResponse(&buf, resp)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Read it back
	readResp, err := ReadResponse(&buf)
	if err != nil {
		t.Errorf("unexpected error reading response: %v", err)
	}

	if readResp.Status != StatusOK {
		t.Errorf("expected status OK, got 0x%02X", readResp.Status)
	}

	if len(readResp.Payload) != 0 {
		t.Errorf("expected empty payload, got %v", readResp.Payload)
	}
}

func TestRequestStructFields(t *testing.T) {
	req := Request{
		Opcode:  OpVTPMCreate,
		Token:   "bearer-token",
		Payload: []byte("data"),
	}

	if req.Opcode != OpVTPMCreate {
		t.Errorf("expected opcode VTPMCreate, got 0x%02X", req.Opcode)
	}

	if req.Token != "bearer-token" {
		t.Errorf("expected token 'bearer-token', got '%s'", req.Token)
	}

	if string(req.Payload) != "data" {
		t.Errorf("expected payload 'data', got '%s'", string(req.Payload))
	}
}

func TestResponseStructFields(t *testing.T) {
	resp := Response{
		Status:  StatusNotFound,
		Payload: []byte("not found"),
	}

	if resp.Status != StatusNotFound {
		t.Errorf("expected status NotFound, got 0x%02X", resp.Status)
	}

	if string(resp.Payload) != "not found" {
		t.Errorf("expected payload 'not found', got '%s'", string(resp.Payload))
	}
}

func TestOpcodeValues(t *testing.T) {
	// Verify opcode ranges are distinct
	healthOps := []byte{OpHealth, OpLiveness, OpReadiness}
	vtpmOps := []byte{OpVTPMCreate, OpVTPMDelete, OpVTPMStart, OpVTPMStop}
	dnsOps := []byte{OpDNSAddRecord, OpDNSDeleteRecord, OpDNSGetRecord}

	// Health ops should be 0x00-0x02
	for _, op := range healthOps {
		if op > 0x0F {
			t.Errorf("health opcode 0x%02X outside expected range", op)
		}
	}

	// VTPM ops should be 0x10-0x1F
	for _, op := range vtpmOps {
		if op < 0x10 || op > 0x1F {
			t.Errorf("vtpm opcode 0x%02X outside expected range", op)
		}
	}

	// DNS ops should be 0x20-0x2F
	for _, op := range dnsOps {
		if op < 0x20 || op > 0x2F {
			t.Errorf("dns opcode 0x%02X outside expected range", op)
		}
	}
}

func TestStatusCodeValues(t *testing.T) {
	// Verify all status codes are unique
	statusCodes := map[byte]string{
		StatusOK:                 "OK",
		StatusInvalidRequest:     "InvalidRequest",
		StatusNotFound:           "NotFound",
		StatusUnauthorized:       "Unauthorized",
		StatusInternalError:      "InternalError",
		StatusTimeout:            "Timeout",
		StatusAlreadyExists:      "AlreadyExists",
		StatusPermissionDenied:   "PermissionDenied",
		StatusResourceExhausted:  "ResourceExhausted",
		StatusInvalidArgument:    "InvalidArgument",
		StatusUnavailable:        "Unavailable",
		StatusNotImplemented:     "NotImplemented",
		StatusFailedPrecondition: "FailedPrecondition",
	}

	if len(statusCodes) != 13 {
		t.Errorf("expected 13 unique status codes, got %d", len(statusCodes))
	}
}

func TestMaxPayloadSizeBoundary(t *testing.T) {
	// Test exactly at boundary
	req := &Request{
		Opcode:  OpHealth,
		Token:   "",
		Payload: make([]byte, MaxPayloadSize),
	}

	var buf bytes.Buffer
	err := WriteRequest(&buf, req)

	if err != nil {
		t.Errorf("expected no error for max payload size, got: %v", err)
	}
}

func TestMaxTokenSizeBoundary(t *testing.T) {
	// Test exactly at boundary
	req := &Request{
		Opcode:  OpHealth,
		Token:   string(make([]byte, MaxTokenSize)),
		Payload: nil,
	}

	var buf bytes.Buffer
	err := WriteRequest(&buf, req)

	if err != nil {
		t.Errorf("expected no error for max token size, got: %v", err)
	}
}

func TestOpcodeToStringExtended(t *testing.T) {
	tests := []struct {
		opcode   byte
		expected string
	}{
		// vTPM Extended Operations (0x03-0x0F)
		{OpVTPMCreateTemplate, "VTPMCreateTemplate"},
		{OpVTPMGetTemplate, "VTPMGetTemplate"},
		{OpVTPMDeleteTemplate, "VTPMDeleteTemplate"},
		{OpVTPMListTemplates, "VTPMListTemplates"},
		{OpVTPMCloneTemplate, "VTPMCloneTemplate"},
		{OpVTPMExportBundle, "VTPMExportBundle"},
		{OpVTPMImportBundle, "VTPMImportBundle"},
		{OpVTPMValidateBundle, "VTPMValidateBundle"},
		{OpVTPMGetBundlePath, "VTPMGetBundlePath"},
		{OpVTPMGetSocketPath, "VTPMGetSocketPath"},
		{OpVTPMGetNVRAMPath, "VTPMGetNVRAMPath"},
		{OpVTPMGetBundle, "VTPMGetBundle"},
		{OpVTPMIsRunning, "VTPMIsRunning"},

		// CA Operations (0xA0-0xA8)
		{OpCAInfo, "CAInfo"},
		{OpCAIssue, "CAIssue"},
		{OpCARevoke, "CARevoke"},
		{OpCARenew, "CARenew"},
		{OpCAGet, "CAGet"},
		{OpCAList, "CAList"},
		{OpCAVerify, "CAVerify"},
		{OpCACRL, "CACRL"},
		{OpCABundle, "CABundle"},

		// IAM User Operations (0xA9-0xAD)
		{OpIAMUserCreate, "IAMUserCreate"},
		{OpIAMUserDelete, "IAMUserDelete"},
		{OpIAMUserGet, "IAMUserGet"},
		{OpIAMUserList, "IAMUserList"},
		{OpIAMUserUpdate, "IAMUserUpdate"},

		// SDN Extended Operations (0xB0-0xB4)
		{OpSDNCreateBridge, "SDNCreateBridge"},
		{OpSDNDeleteBridge, "SDNDeleteBridge"},
		{OpSDNCreatePort, "SDNCreatePort"},
		{OpSDNDeletePort, "SDNDeletePort"},
		{OpSDNDeletePolicy, "SDNDeletePolicy"},

		// IAM Role Operations (0xB5-0xBA)
		{OpIAMRoleCreate, "IAMRoleCreate"},
		{OpIAMRoleDelete, "IAMRoleDelete"},
		{OpIAMRoleGet, "IAMRoleGet"},
		{OpIAMRoleList, "IAMRoleList"},
		{OpIAMRoleAssign, "IAMRoleAssign"},
		{OpIAMRoleRevoke, "IAMRoleRevoke"},

		// IAM Group Operations (0xBB-0xBF)
		{OpIAMGroupCreate, "IAMGroupCreate"},
		{OpIAMGroupDelete, "IAMGroupDelete"},
		{OpIAMGroupGet, "IAMGroupGet"},
		{OpIAMGroupList, "IAMGroupList"},
		{OpIAMGroupAddMember, "IAMGroupAddMember"},

		// KMS Key Management Operations (0xC0-0xC9)
		{OpKMSGenerateKey, "KMSGenerateKey"},
		{OpKMSImportKey, "KMSImportKey"},
		{OpKMSGetKey, "KMSGetKey"},
		{OpKMSListKeys, "KMSListKeys"},
		{OpKMSDeleteKey, "KMSDeleteKey"},
		{OpKMSRotateKey, "KMSRotateKey"},
		{OpKMSUpdateKeyStatus, "KMSUpdateKeyStatus"},
		{OpKMSExportKey, "KMSExportKey"},
		{OpKMSGetKeyVersions, "KMSGetKeyVersions"},
		{OpKMSBackendStatus, "KMSBackendStatus"},

		// KMS Crypto Operations (0xD0-0xD8)
		{OpKMSEncrypt, "KMSEncrypt"},
		{OpKMSDecrypt, "KMSDecrypt"},
		{OpKMSSign, "KMSSign"},
		{OpKMSVerify, "KMSVerify"},
		{OpKMSGenerateRandom, "KMSGenerateRandom"},
		{OpKMSHash, "KMSHash"},
		{OpKMSHMAC, "KMSHMAC"},
		{OpKMSVerifyHMAC, "KMSVerifyHMAC"},
		{OpKMSRewrap, "KMSRewrap"},

		// DEK Management Operations (0xF0-0xF5)
		{OpDEKCreate, "DEKCreate"},
		{OpDEKGet, "DEKGet"},
		{OpDEKList, "DEKList"},
		{OpDEKDelete, "DEKDelete"},
		{OpDEKRotate, "DEKRotate"},
		{OpDEKGetStatus, "DEKGetStatus"},

		// IAM Extended Operations (0xF6-0xFB)
		{OpIAMGroupRemoveMember, "IAMGroupRemoveMember"},
		{OpIAMCheckPermission, "IAMCheckPermission"},
		{OpIAMAuthenticate, "IAMAuthenticate"},
		{OpIAMTokenCreate, "IAMTokenCreate"},
		{OpIAMTokenRevoke, "IAMTokenRevoke"},
		{OpIAMTokenVerify, "IAMTokenVerify"},

		// SDN Extended Operations (0x4F)
		{OpSDNGetPort, "SDNGetPort"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := OpcodeToString(tt.opcode)
			if result != tt.expected {
				t.Errorf("expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

// TestOpcodeToStringDeviceIdentity tests IDevID/IAK device identity operation opcodes
func TestOpcodeToStringDeviceIdentity(t *testing.T) {
	tests := []struct {
		opcode   byte
		expected string
	}{
		// IDevID Operations (0x56-0x5B)
		{OpIDevIDGenerate, "IDevIDGenerate"},
		{OpIDevIDInfo, "IDevIDInfo"},
		{OpIDevIDDelete, "IDevIDDelete"},
		{OpIDevIDCSR, "IDevIDCSR"},
		{OpIDevIDInstallCert, "IDevIDInstallCert"},
		{OpIDevIDGetCert, "IDevIDGetCert"},

		// IAK Operations (0x5C-0x5F, 0x6B-0x6C)
		{OpIAKGenerate, "IAKGenerate"},
		{OpIAKInfo, "IAKInfo"},
		{OpIAKDelete, "IAKDelete"},
		{OpIAKCSR, "IAKCSR"},
		{OpIAKInstallCert, "IAKInstallCert"},
		{OpIAKGetCert, "IAKGetCert"},

		// Device Attributes and Credential Operations (0x6D-0x6E)
		{OpDeviceAttributes, "DeviceAttributes"},
		{OpActivateCredential, "ActivateCredential"},

		// IDevID/IAK Extended Operations (0x78-0x7B)
		{OpHasIDevID, "HasIDevID"},
		{OpHasIAK, "HasIAK"},
		{OpIDevIDDeleteCert, "IDevIDDeleteCert"},
		{OpIAKDeleteCert, "IAKDeleteCert"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := OpcodeToString(tt.opcode)
			if result != tt.expected {
				t.Errorf("expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

// TestOpcodeToStringPXE tests PXE provisioning operation opcodes
func TestOpcodeToStringPXE(t *testing.T) {
	tests := []struct {
		opcode   byte
		expected string
	}{
		{OpPXEListDevices, "PXEListDevices"},
		{OpPXEGetDevice, "PXEGetDevice"},
		{OpPXERegisterDevice, "PXERegisterDevice"},
		{OpPXEUpdateState, "PXEUpdateState"},
		{OpPXEAuthorize, "PXEAuthorize"},
		{OpPXEQuarantine, "PXEQuarantine"},
		{OpPXERetry, "PXERetry"},
		{OpPXERemoveDevice, "PXERemoveDevice"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := OpcodeToString(tt.opcode)
			if result != tt.expected {
				t.Errorf("expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

// TestOpcodeToStringKMSDataKey tests KMS data key operation opcodes
func TestOpcodeToStringKMSDataKey(t *testing.T) {
	tests := []struct {
		opcode   byte
		expected string
	}{
		{OpKMSBatchEncrypt, "KMSBatchEncrypt"},
		{OpKMSBatchDecrypt, "KMSBatchDecrypt"},
		{OpKMSGenerateDataKey, "KMSGenerateDataKey"},
		{OpKMSGenerateWrappedDataKey, "KMSGenerateWrappedDataKey"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := OpcodeToString(tt.opcode)
			if result != tt.expected {
				t.Errorf("expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestGetDefaultCodecType(t *testing.T) {
	// Save the original codec type to restore after test
	original := GetDefaultCodecType()
	defer func() {
		_ = SetDefaultCodecType(original)
	}()

	// Test that GetDefaultCodecType returns the expected value
	codecType := GetDefaultCodecType()
	if codecType == "" {
		t.Error("expected non-empty codec type")
	}

	// Set to a known value and verify
	err := SetDefaultCodecType(codec.JSON)
	if err != nil {
		t.Fatalf("failed to set codec type: %v", err)
	}

	codecType = GetDefaultCodecType()
	if codecType != codec.JSON {
		t.Errorf("expected codec type %s, got %s", codec.JSON, codecType)
	}
}

func TestSetDefaultCodecTypeUnsupported(t *testing.T) {
	// Save the original codec type to restore after test
	original := GetDefaultCodecType()
	defer func() {
		_ = SetDefaultCodecType(original)
	}()

	// Try to set an unsupported codec type
	err := SetDefaultCodecType("invalid-codec-type")
	if err == nil {
		t.Error("expected error for unsupported codec type")
	}
}

func TestSupportedCodecs(t *testing.T) {
	codecs := SupportedCodecs()

	// Should return at least one codec
	if len(codecs) == 0 {
		t.Error("expected at least one supported codec")
	}

	// JSON should always be supported
	hasJSON := false
	for _, c := range codecs {
		if c == codec.JSON {
			hasJSON = true
			break
		}
	}

	if !hasJSON {
		t.Error("expected JSON to be in supported codecs")
	}
}

func TestIsCodecSupported(t *testing.T) {
	tests := []struct {
		name      string
		codecType codec.Type
		expected  bool
	}{
		{
			name:      "JSON is supported",
			codecType: codec.JSON,
			expected:  true,
		},
		{
			name:      "MsgPack is supported with build tag",
			codecType: codec.MsgPack,
			expected:  true, // Assuming build tag is included
		},
		{
			name:      "Invalid codec is not supported",
			codecType: "invalid-codec",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsCodecSupported(tt.codecType)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestEncodePayloadWithCodec(t *testing.T) {
	tests := []struct {
		name        string
		entity      interface{}
		codecType   codec.Type
		expectError bool
		expectNil   bool
	}{
		{
			name:        "nil entity returns nil",
			entity:      nil,
			codecType:   codec.JSON,
			expectError: false,
			expectNil:   true,
		},
		{
			name:        "string entity with JSON",
			entity:      "test string",
			codecType:   codec.JSON,
			expectError: false,
			expectNil:   false,
		},
		{
			name:        "map entity with JSON",
			entity:      map[string]string{"key": "value"},
			codecType:   codec.JSON,
			expectError: false,
			expectNil:   false,
		},
		{
			name:        "string entity with MsgPack",
			entity:      "test string",
			codecType:   codec.MsgPack,
			expectError: false,
			expectNil:   false,
		},
		{
			name:        "invalid codec type",
			entity:      "test",
			codecType:   "invalid-codec",
			expectError: true,
			expectNil:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := EncodePayloadWithCodec(tt.entity, tt.codecType)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}

				if tt.expectNil {
					if result != nil {
						t.Errorf("expected nil result, got %v", result)
					}
				} else if len(result) == 0 {
					t.Error("expected non-empty result")
				}
			}
		})
	}
}

func TestDecodePayloadWithCodec(t *testing.T) {
	tests := []struct {
		name        string
		entity      interface{}
		codecType   codec.Type
		expectError bool
	}{
		{
			name:        "string entity with JSON",
			entity:      "test string",
			codecType:   codec.JSON,
			expectError: false,
		},
		{
			name:        "map entity with JSON",
			entity:      map[string]string{"key": "value"},
			codecType:   codec.JSON,
			expectError: false,
		},
		{
			name:        "string entity with MsgPack",
			entity:      "test string",
			codecType:   codec.MsgPack,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode first
			encoded, err := EncodePayloadWithCodec(tt.entity, tt.codecType)
			if err != nil {
				t.Fatalf("failed to encode: %v", err)
			}

			// Decode back
			var decoded interface{}
			err = DecodePayloadWithCodec(encoded, &decoded, tt.codecType)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestDecodePayloadWithCodecEmptyData(t *testing.T) {
	var result string
	err := DecodePayloadWithCodec([]byte{}, &result, codec.JSON)

	if err != nil {
		t.Errorf("expected no error for empty data, got: %v", err)
	}
}

func TestDecodePayloadWithCodecNilEntity(t *testing.T) {
	encoded, err := EncodePayloadWithCodec("test", codec.JSON)
	if err != nil {
		t.Fatalf("failed to encode: %v", err)
	}

	err = DecodePayloadWithCodec(encoded, nil, codec.JSON)

	if err == nil {
		t.Error("expected error for nil entity")
		return
	}

	if !strings.Contains(err.Error(), "nil") {
		t.Errorf("expected error about nil entity, got: %s", err.Error())
	}
}

func TestDecodePayloadWithCodecInvalidCodec(t *testing.T) {
	var result string
	err := DecodePayloadWithCodec([]byte(`"test"`), &result, "invalid-codec")

	if err == nil {
		t.Error("expected error for invalid codec type")
	}
}

func TestEncodeDecodePayloadWithCodecRoundTrip(t *testing.T) {
	type TestStruct struct {
		Name   string `json:"name"`
		Age    int    `json:"age"`
		Active bool   `json:"active"`
	}

	original := TestStruct{
		Name:   "John",
		Age:    30,
		Active: true,
	}

	// Test with JSON
	encoded, err := EncodePayloadWithCodec(original, codec.JSON)
	if err != nil {
		t.Fatalf("failed to encode with JSON: %v", err)
	}

	var decoded TestStruct
	err = DecodePayloadWithCodec(encoded, &decoded, codec.JSON)
	if err != nil {
		t.Fatalf("failed to decode with JSON: %v", err)
	}

	if decoded.Name != original.Name {
		t.Errorf("expected Name '%s', got '%s'", original.Name, decoded.Name)
	}

	if decoded.Age != original.Age {
		t.Errorf("expected Age %d, got %d", original.Age, decoded.Age)
	}

	if decoded.Active != original.Active {
		t.Errorf("expected Active %v, got %v", original.Active, decoded.Active)
	}
}

func TestTenantOpcodeToString(t *testing.T) {
	tests := []struct {
		opcode   byte
		expected string
	}{
		{OpTenantList, "TenantList"},
		{OpTenantGet, "TenantGet"},
		{OpTenantGetByName, "TenantGetByName"},
		{OpTenantCreate, "TenantCreate"},
		{OpTenantUpdate, "TenantUpdate"},
		{OpTenantDelete, "TenantDelete"},
		{OpTenantSuspend, "TenantSuspend"},
		{OpTenantResume, "TenantResume"},
		{OpTenantGetQuotas, "TenantGetQuotas"},
		{OpTenantUpdateQuotas, "TenantUpdateQuotas"},
		{OpTenantGetUsage, "TenantGetUsage"},
		{OpTenantCheckQuota, "TenantCheckQuota"},
		{OpTenantSync, "TenantSync"},
		{OpTenantRotateDEK, "TenantRotateDEK"},
		{OpTenantGetDEKStatus, "TenantGetDEKStatus"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := TenantOpcodeToString(tt.opcode)
			if result != tt.expected {
				t.Errorf("expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestTenantOpcodeToStringUnknown(t *testing.T) {
	// Use an opcode outside the tenant range
	unknownOpcode := byte(0x00) // Not a tenant opcode
	result := TenantOpcodeToString(unknownOpcode)

	if !strings.HasPrefix(result, "UnknownTenantOp") {
		t.Errorf("expected 'UnknownTenantOp(...)', got '%s'", result)
	}
}

func TestIsTenantOpcode(t *testing.T) {
	tests := []struct {
		name     string
		opcode   byte
		expected bool
	}{
		{
			name:     "OpTenantList is tenant opcode",
			opcode:   OpTenantList,
			expected: true,
		},
		{
			name:     "OpTenantGetDEKStatus is tenant opcode",
			opcode:   OpTenantGetDEKStatus,
			expected: true,
		},
		{
			name:     "OpTenantCreate is tenant opcode",
			opcode:   OpTenantCreate,
			expected: true,
		},
		{
			name:     "OpHealth is not tenant opcode",
			opcode:   OpHealth,
			expected: false,
		},
		{
			name:     "OpVTPMCreate is not tenant opcode",
			opcode:   OpVTPMCreate,
			expected: false,
		},
		{
			name:     "0xFF is not tenant opcode",
			opcode:   0xFF,
			expected: false,
		},
		{
			name:     "0x00 is not tenant opcode",
			opcode:   0x00,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsTenantOpcode(tt.opcode)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}
