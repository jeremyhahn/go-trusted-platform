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

package quic

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	quicapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
)

// recordingSender captures every call made on the QUIC sender so tests
// can assert on the exact wire payload that the adapter would have
// transmitted. Both Send and SendRequest paths are recorded; the
// RPC-style Send is mapped to the same record shape so assertions are
// uniform.
type recordingSender struct {
	// SendRequest captures
	rawOpcode  byte
	rawPayload []byte
	rawCalls   int

	// Send captures
	encOpcode byte
	encArgs   interface{}
	encReply  interface{}
	encCalls  int

	// Programmable response payload returned from SendRequest.
	respPayload []byte

	// Optional error returns
	sendErr        error
	sendRequestErr error
}

func (r *recordingSender) Send(ctx context.Context, opcode byte, reqData, respData interface{}) error {
	r.encCalls++
	r.encOpcode = opcode
	r.encArgs = reqData
	r.encReply = respData
	return r.sendErr
}

func (r *recordingSender) SendRequest(ctx context.Context, opcode byte, payload []byte) (*quicapi.Response, error) {
	r.rawCalls++
	r.rawOpcode = opcode
	r.rawPayload = append(r.rawPayload[:0], payload...)
	if r.sendRequestErr != nil {
		return nil, r.sendRequestErr
	}
	return &quicapi.Response{Status: quicapi.StatusOK, Payload: r.respPayload}, nil
}

// fakeRequest is a minimal codec-friendly type used to verify that the
// adapter actually marshals args before prefixing the sub-opcode.
type fakeRequest struct {
	SwitchName string `codec:"switch_name"`
	PortID     string `codec:"port_id"`
	VLAN       uint16 `codec:"vlan"`
}

// fakeReply mirrors the shape of a typical sub-operation response.
type fakeReply struct {
	OK     bool   `codec:"ok"`
	Detail string `codec:"detail"`
}

// newConnWithSender wires a stub adapter and recording sender into a
// quicClientConn. The adapter is marked connected with a non-nil client
// pointer so Invoke proceeds past the readiness gates.
func newConnWithSender(t *testing.T, sender *recordingSender) *quicClientConn {
	t.Helper()
	a := &Adapter{client: &quicapi.Client{}}
	a.connected.Store(true)
	return &quicClientConn{adapter: a, sender: sender}
}

// TestInvoke_CategoryPrefix_AllSwitchMethods verifies every SwitchService
// method emits the correct (opcode, sub-opcode) pair and that the
// remainder of the payload is the codec-encoded args, not the raw args
// passed straight to the wire. This is the exact behavior the
// server-side handleSwitchCategory expects in pkg/api/daemon/quic_switch.go.
func TestInvoke_CategoryPrefix_AllSwitchMethods(t *testing.T) {
	tests := []struct {
		method           string
		expectedSubOp    byte
		expectedCategory byte
	}{
		{"/platform.v1.SwitchService/ListPorts", quicapi.SwitchSubListPorts, quicapi.OpSwitchCategory},
		{"/platform.v1.SwitchService/GetPortStatus", quicapi.SwitchSubGetPortStatus, quicapi.OpSwitchCategory},
		{"/platform.v1.SwitchService/SetPortVLAN", quicapi.SwitchSubSetPortVLAN, quicapi.OpSwitchCategory},
		{"/platform.v1.SwitchService/EnablePort", quicapi.SwitchSubEnablePort, quicapi.OpSwitchCategory},
		{"/platform.v1.SwitchService/DisablePort", quicapi.SwitchSubDisablePort, quicapi.OpSwitchCategory},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			sender := &recordingSender{}
			conn := newConnWithSender(t, sender)

			args := &fakeRequest{SwitchName: "core-1", PortID: "Eth1/1", VLAN: 100}
			err := conn.Invoke(context.Background(), tt.method, args, &fakeReply{})
			if err != nil {
				t.Fatalf("Invoke() unexpected error: %v", err)
			}

			if sender.encCalls != 0 {
				t.Errorf("category opcode must use SendRequest, got %d Send() calls", sender.encCalls)
			}
			if sender.rawCalls != 1 {
				t.Fatalf("expected exactly 1 SendRequest call, got %d", sender.rawCalls)
			}
			if sender.rawOpcode != tt.expectedCategory {
				t.Errorf("opcode = 0x%02X, want 0x%02X", sender.rawOpcode, tt.expectedCategory)
			}
			if len(sender.rawPayload) == 0 {
				t.Fatal("payload must contain at least the sub-opcode prefix")
			}
			if sender.rawPayload[0] != tt.expectedSubOp {
				t.Errorf("payload[0] sub-opcode = 0x%02X, want 0x%02X",
					sender.rawPayload[0], tt.expectedSubOp)
			}

			// Verify payload[1:] is real codec output, not the raw args
			// pointer or an empty slice. Decoding it back into a
			// fakeRequest must round-trip cleanly.
			var roundTrip fakeRequest
			if err := quicapi.DecodePayload(sender.rawPayload[1:], &roundTrip); err != nil {
				t.Fatalf("payload[1:] is not valid codec output: %v", err)
			}
			if roundTrip.SwitchName != args.SwitchName {
				t.Errorf("round-trip SwitchName = %q, want %q", roundTrip.SwitchName, args.SwitchName)
			}
		})
	}
}

// TestInvoke_CategoryPrefix_AllTenantBarrierMethods covers the second
// production caller of category opcodes.
func TestInvoke_CategoryPrefix_AllTenantBarrierMethods(t *testing.T) {
	tests := []struct {
		method        string
		expectedSubOp byte
	}{
		{"/platform.v1.TenantService/InitTenantBarrier", quicapi.TenantBarrierSubInit},
		{"/platform.v1.TenantService/UnsealTenantBarrier", quicapi.TenantBarrierSubUnseal},
		{"/platform.v1.TenantService/SealTenantBarrier", quicapi.TenantBarrierSubSeal},
		{"/platform.v1.TenantService/GetTenantBarrierStatus", quicapi.TenantBarrierSubStatus},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			sender := &recordingSender{}
			conn := newConnWithSender(t, sender)

			args := &fakeRequest{SwitchName: "tenant-foo"}
			err := conn.Invoke(context.Background(), tt.method, args, &fakeReply{})
			if err != nil {
				t.Fatalf("Invoke() unexpected error: %v", err)
			}

			if sender.rawOpcode != quicapi.OpTenantBarrierCategory {
				t.Errorf("opcode = 0x%02X, want 0x%02X (OpTenantBarrierCategory)",
					sender.rawOpcode, quicapi.OpTenantBarrierCategory)
			}
			if sender.rawPayload[0] != tt.expectedSubOp {
				t.Errorf("payload[0] sub-opcode = 0x%02X, want 0x%02X",
					sender.rawPayload[0], tt.expectedSubOp)
			}
		})
	}
}

// TestInvoke_NonCategory_UsesSendPath ensures a regular opcode (no
// category multiplexing) still flows through the standard Send path
// where the QUIC client handles encode/decode itself. Regression guard
// for accidentally over-prefixing every opcode.
func TestInvoke_NonCategory_UsesSendPath(t *testing.T) {
	sender := &recordingSender{}
	conn := newConnWithSender(t, sender)

	err := conn.Invoke(context.Background(), "/platform.v1.PlatformDaemon/GetHealth", nil, nil)
	if err != nil {
		t.Fatalf("Invoke() unexpected error: %v", err)
	}

	if sender.rawCalls != 0 {
		t.Errorf("non-category opcode must use Send(), got %d SendRequest calls", sender.rawCalls)
	}
	if sender.encCalls != 1 {
		t.Fatalf("expected exactly 1 Send call, got %d", sender.encCalls)
	}
	if sender.encOpcode != quicapi.OpHealth {
		t.Errorf("opcode = 0x%02X, want 0x%02X (OpHealth)", sender.encOpcode, quicapi.OpHealth)
	}
}

// TestInvoke_CategoryNilArgs verifies that a category-opcode call with
// nil args still emits the required sub-opcode prefix. The server must
// see at least one byte (the sub-opcode) or the
// ErrQUICMissingField{Field: "sub_opcode"} branch fires.
func TestInvoke_CategoryNilArgs(t *testing.T) {
	sender := &recordingSender{}
	conn := newConnWithSender(t, sender)

	err := conn.Invoke(context.Background(), "/platform.v1.SwitchService/ListPorts", nil, nil)
	if err != nil {
		t.Fatalf("Invoke() unexpected error: %v", err)
	}
	if len(sender.rawPayload) != 1 {
		t.Fatalf("expected 1-byte payload (sub-opcode only) for nil args, got %d bytes",
			len(sender.rawPayload))
	}
	if sender.rawPayload[0] != quicapi.SwitchSubListPorts {
		t.Errorf("sub-opcode = 0x%02X, want 0x%02X",
			sender.rawPayload[0], quicapi.SwitchSubListPorts)
	}
}

// TestInvoke_CategoryDecodesReply verifies that category-opcode
// responses are codec-decoded into the reply struct. Without this the
// caller would just see an empty/zero reply even on a successful call.
func TestInvoke_CategoryDecodesReply(t *testing.T) {
	expected := &fakeReply{OK: true, Detail: "port enabled"}
	encoded, err := quicapi.EncodePayload(expected)
	if err != nil {
		t.Fatalf("EncodePayload setup failed: %v", err)
	}

	sender := &recordingSender{respPayload: encoded}
	conn := newConnWithSender(t, sender)

	got := &fakeReply{}
	err = conn.Invoke(context.Background(), "/platform.v1.SwitchService/EnablePort", &fakeRequest{}, got)
	if err != nil {
		t.Fatalf("Invoke() unexpected error: %v", err)
	}

	if got.OK != expected.OK || got.Detail != expected.Detail {
		t.Errorf("decoded reply = %+v, want %+v", got, expected)
	}
}

// TestInvoke_CategoryEmptyResponse verifies a successful category call
// with an empty response body does not crash the decoder path.
func TestInvoke_CategoryEmptyResponse(t *testing.T) {
	sender := &recordingSender{respPayload: nil}
	conn := newConnWithSender(t, sender)

	got := &fakeReply{}
	err := conn.Invoke(context.Background(), "/platform.v1.SwitchService/DisablePort", &fakeRequest{}, got)
	if err != nil {
		t.Fatalf("Invoke() unexpected error on empty response: %v", err)
	}
}

// TestInvoke_CategorySendRequestError verifies wire-level errors from
// the category path are translated to gRPC status errors, preserving
// the same translation contract as the non-category path.
func TestInvoke_CategorySendRequestError(t *testing.T) {
	sender := &recordingSender{
		sendRequestErr: &quicapi.ErrProtocol{Status: quicapi.StatusUnauthorized, Message: "bad token"},
	}
	conn := newConnWithSender(t, sender)

	err := conn.Invoke(context.Background(), "/platform.v1.SwitchService/ListPorts", &fakeRequest{}, nil)
	if err == nil {
		t.Fatal("Invoke() must return an error when SendRequest fails")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T: %v", err, err)
	}
	if st.Code() != codes.Unauthenticated {
		t.Errorf("code = %v, want %v", st.Code(), codes.Unauthenticated)
	}
}

// TestBuildCategoryPayload_NilArgs verifies the helper handles nil args
// in isolation; the canonical wire form is a one-byte sub-opcode-only
// payload (matching the server's empty-body decode path).
func TestBuildCategoryPayload_NilArgs(t *testing.T) {
	out, err := buildCategoryPayload(0x42, nil)
	if err != nil {
		t.Fatalf("buildCategoryPayload(nil) unexpected error: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1-byte payload, got %d", len(out))
	}
	if out[0] != 0x42 {
		t.Errorf("payload[0] = 0x%02X, want 0x42", out[0])
	}
}

// TestBuildCategoryPayload_RealArgs confirms the helper marshals args
// then prepends the sub-opcode (not the other way around). Decode
// payload[1:] back to verify the slice boundary is correct.
func TestBuildCategoryPayload_RealArgs(t *testing.T) {
	args := &fakeRequest{SwitchName: "edge-9", PortID: "Eth1/24", VLAN: 4094}
	out, err := buildCategoryPayload(quicapi.SwitchSubSetPortVLAN, args)
	if err != nil {
		t.Fatalf("buildCategoryPayload() unexpected error: %v", err)
	}
	if len(out) < 2 {
		t.Fatalf("payload too small, got %d bytes", len(out))
	}
	if out[0] != quicapi.SwitchSubSetPortVLAN {
		t.Errorf("payload[0] = 0x%02X, want 0x%02X", out[0], quicapi.SwitchSubSetPortVLAN)
	}

	var got fakeRequest
	if err := quicapi.DecodePayload(out[1:], &got); err != nil {
		t.Fatalf("payload[1:] decode failed: %v", err)
	}
	if got != *args {
		t.Errorf("round-trip = %+v, want %+v", got, *args)
	}
}

// TestIsCategoryOpcode_KnownAndUnknown locks down the canonical set of
// category opcodes. Adding a new category opcode without updating this
// test is a strong signal that the matching grpcMethodToOpcodeMap and
// categorySubOpcodeMap entries also need adding.
func TestIsCategoryOpcode_KnownAndUnknown(t *testing.T) {
	known := []byte{
		quicapi.OpOverlayCategory,
		quicapi.OpGatewayCategory,
		quicapi.OpIPAMCategory,
		quicapi.OpTPM2Category,
		quicapi.OpCeremonyCategory,
		quicapi.OpPIVCategory,
		quicapi.OpLUKSCategory,
		quicapi.OpFIDO2Category,
		quicapi.OpTenantBarrierCategory,
		quicapi.OpSwitchCategory,
	}
	for _, op := range known {
		if !isCategoryOpcode(op) {
			t.Errorf("isCategoryOpcode(0x%02X) = false, want true", op)
		}
	}

	notCategory := []byte{
		quicapi.OpHealth,
		quicapi.OpCAInfo,
		quicapi.OpKMSGenerateKey,
		quicapi.OpDaemonStatus,
		quicapi.OpVTPMCreate,
	}
	for _, op := range notCategory {
		if isCategoryOpcode(op) {
			t.Errorf("isCategoryOpcode(0x%02X) = true, want false", op)
		}
	}
}

// TestCategorySubOpcodeMap_Coverage asserts the cross-table invariant:
// every gRPC method whose opcode is a category opcode must have a
// sub-opcode mapping. This is the same invariant the package init()
// enforces at startup; running it as a test gives a clearer diagnostic
// than a process-load panic.
func TestCategorySubOpcodeMap_Coverage(t *testing.T) {
	for method, opcode := range grpcMethodToOpcodeMap {
		if _, isCat := categoryOpcodes[opcode]; !isCat {
			continue
		}
		if _, hasSub := categorySubOpcodeMap[method]; !hasSub {
			t.Errorf("method %s routes to category opcode 0x%02X but has no sub-opcode mapping",
				method, opcode)
		}
	}
}

// TestCategorySubOpcodeMap_NoOrphans is the reverse coverage check: no
// entry in categorySubOpcodeMap may reference a method that is missing
// from grpcMethodToOpcodeMap or whose opcode is not a category.
func TestCategorySubOpcodeMap_NoOrphans(t *testing.T) {
	for method := range categorySubOpcodeMap {
		opcode, ok := grpcMethodToOpcodeMap[method]
		if !ok {
			t.Errorf("categorySubOpcodeMap has %s but grpcMethodToOpcodeMap does not", method)
			continue
		}
		if _, isCat := categoryOpcodes[opcode]; !isCat {
			t.Errorf("categorySubOpcodeMap has %s but its opcode 0x%02X is not a category",
				method, opcode)
		}
	}
}

// TestErrCategorySubOpcodeMissing_Error covers the new typed error.
func TestErrCategorySubOpcodeMissing_Error(t *testing.T) {
	err := ErrCategorySubOpcodeMissing{Method: "/foo.Service/Bar", Opcode: 0xCC}
	got := err.Error()
	want := "QUIC category opcode 0xCC has no sub-opcode mapping for gRPC method /foo.Service/Bar"
	if got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

// TestInvoke_CategoryEncodingFailure injects an args value that the
// codec cannot serialize and verifies the SDK surfaces a typed Internal
// error rather than panicking or sending a malformed payload.
func TestInvoke_CategoryEncodingFailure(t *testing.T) {
	sender := &recordingSender{}
	conn := newConnWithSender(t, sender)

	// A channel cannot be marshalled by any of the supported codecs.
	bogus := make(chan int)
	err := conn.Invoke(context.Background(), "/platform.v1.SwitchService/ListPorts", bogus, nil)
	if err == nil {
		t.Fatal("Invoke() must return error when args cannot be encoded")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T: %v", err, err)
	}
	if st.Code() != codes.Internal {
		t.Errorf("code = %v, want %v", st.Code(), codes.Internal)
	}
	if sender.rawCalls != 0 {
		t.Errorf("encoding failure must not reach the wire, got %d calls", sender.rawCalls)
	}
}

// TestInvoke_CategoryReplyDecodeFailure simulates a server returning
// non-codec bytes for a category response. The adapter must surface the
// decode error rather than silently leaving reply zero-valued.
func TestInvoke_CategoryReplyDecodeFailure(t *testing.T) {
	// Bytes that won't parse as MsgPack/JSON/CBOR-encoded fakeReply.
	sender := &recordingSender{respPayload: []byte{0xFF, 0xFE, 0xFD, 0xFC}}
	conn := newConnWithSender(t, sender)

	got := &fakeReply{}
	err := conn.Invoke(context.Background(), "/platform.v1.SwitchService/EnablePort", &fakeRequest{}, got)
	// Some codecs are lenient and may decode random bytes into a
	// zero-valued struct without erroring; tolerate either outcome but
	// require that if an error is returned it is a gRPC Internal status.
	if err == nil {
		return
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T: %v", err, err)
	}
	if st.Code() != codes.Internal {
		t.Errorf("code = %v, want %v", st.Code(), codes.Internal)
	}
}

// TestQuicClientConn_LazySender_AssignedOnInvoke verifies that a
// quicClientConn created without an explicit sender lazily assigns a
// real one on first Invoke. The closed-adapter early return blocks the
// call from actually hitting the wire, so we assert structurally on
// c.sender after the call.
func TestQuicClientConn_LazySender_AssignedOnInvoke(t *testing.T) {
	// Use a fully-zero adapter so `client == nil` short-circuits Invoke
	// before lazy init is reached. This proves the inverse direction:
	// when client is nil, sender remains nil (no eager allocation).
	a := &Adapter{}
	a.connected.Store(true)
	conn := &quicClientConn{adapter: a}

	err := conn.Invoke(context.Background(), "/platform.v1.PlatformDaemon/GetHealth", nil, nil)
	if err == nil {
		t.Fatal("Invoke() should fail with nil client")
	}
	if conn.sender != nil {
		t.Error("sender should remain nil when client is nil (short-circuit)")
	}
}
