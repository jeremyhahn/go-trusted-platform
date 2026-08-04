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

package quic

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	quicapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
)

func TestConnect_NilOptions(t *testing.T) {
	ctx := context.Background()

	_, err := Connect(ctx, nil)
	if !errors.Is(err, platform.ErrNilOptions) {
		t.Errorf("Connect(nil) error = %v, want %v", err, platform.ErrNilOptions)
	}
}

func TestConnect_EmptyAddress(t *testing.T) {
	ctx := context.Background()
	opts := platform.NewOptions()
	opts.QUICAddr = ""

	_, err := Connect(ctx, opts)
	if !errors.Is(err, platform.ErrEmptyAddress) {
		t.Errorf("Connect() error = %v, want %v", err, platform.ErrEmptyAddress)
	}
}

func TestConnect_InvalidServer(t *testing.T) {
	ctx := context.Background()
	opts := platform.NewOptions(
		platform.WithQUICAddr("localhost:19444"), // Non-existent server
	)

	_, err := Connect(ctx, opts)
	if err == nil {
		t.Fatal("Connect() should return error for invalid server")
	}

	var connErr platform.ErrConnectionFailed
	if !errors.As(err, &connErr) {
		t.Errorf("expected ErrConnectionFailed, got %T: %v", err, err)
	}
	if connErr.Protocol != platform.ProtocolQUIC {
		t.Errorf("Protocol = %v, want %v", connErr.Protocol, platform.ProtocolQUIC)
	}
}

func TestAdapter_Target(t *testing.T) {
	a := &Adapter{
		address: "localhost:9444",
	}

	if got := a.Target(); got != "localhost:9444" {
		t.Errorf("Target() = %q, want %q", got, "localhost:9444")
	}
}

func TestAdapter_IsConnected(t *testing.T) {
	a := &Adapter{}

	// Initially not connected
	if a.IsConnected() {
		t.Error("IsConnected() should return false initially")
	}

	// After storing true but no client
	a.connected.Store(true)
	if a.IsConnected() {
		t.Error("IsConnected() should return false without client")
	}

	// After storing closed
	a.closed.Store(true)
	if a.IsConnected() {
		t.Error("IsConnected() should return false when closed")
	}
}

func TestAdapter_Close_NotConnected(t *testing.T) {
	a := &Adapter{}
	a.connected.Store(false)

	err := a.Close()
	if err != nil {
		t.Errorf("Close() on disconnected adapter should not return error, got %v", err)
	}
}

func TestAdapter_Close_NilClient(t *testing.T) {
	a := &Adapter{
		client: nil,
	}
	a.connected.Store(true)

	err := a.Close()
	if err != nil {
		t.Errorf("Close() with nil client should not return error, got %v", err)
	}
	if a.IsConnected() {
		t.Error("IsConnected() should return false after Close()")
	}
}

func TestAdapter_Close_Idempotent(t *testing.T) {
	a := &Adapter{}
	a.connected.Store(true)

	// First close
	err := a.Close()
	if err != nil {
		t.Errorf("first Close() returned error: %v", err)
	}

	// Second close should be safe
	err = a.Close()
	if err != nil {
		t.Errorf("second Close() returned error: %v", err)
	}
}

func TestAdapter_Connection(t *testing.T) {
	a := &Adapter{}
	a.connected.Store(true)

	conn := a.Connection()
	if conn == nil {
		t.Error("Connection() should not return nil")
	}

	// Verify it's the right type
	_, ok := conn.(*quicClientConn)
	if !ok {
		t.Errorf("Connection() returned %T, want *quicClientConn", conn)
	}
}

func TestAdapter_Client(t *testing.T) {
	a := &Adapter{
		client: nil,
	}

	// With nil client
	if a.Client() != nil {
		t.Error("Client() should return nil when no client is set")
	}
}

func TestAdapter_SetToken(t *testing.T) {
	// With nil client - should not panic
	a := &Adapter{
		client: nil,
	}
	a.SetToken("test-token")
	// If we get here without panic, the test passes
}

func TestQuicClientConn_Invoke_Closed(t *testing.T) {
	a := &Adapter{}
	a.closed.Store(true)

	conn := &quicClientConn{adapter: a}

	err := conn.Invoke(context.Background(), "/platform.v1.PlatformDaemon/GetHealth", nil, nil)
	if err == nil {
		t.Fatal("Invoke() should return error when closed")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T: %v", err, err)
	}
	if st.Code() != codes.Unavailable {
		t.Errorf("status code = %v, want %v", st.Code(), codes.Unavailable)
	}
}

func TestQuicClientConn_Invoke_NilClient(t *testing.T) {
	a := &Adapter{
		client: nil,
	}
	a.connected.Store(true)

	conn := &quicClientConn{adapter: a}

	err := conn.Invoke(context.Background(), "/platform.v1.PlatformDaemon/GetHealth", nil, nil)
	if err == nil {
		t.Fatal("Invoke() should return error with nil client")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T: %v", err, err)
	}
	if st.Code() != codes.Unavailable {
		t.Errorf("status code = %v, want %v", st.Code(), codes.Unavailable)
	}
}

func TestQuicClientConn_Invoke_UnmappedMethod(t *testing.T) {
	a := &Adapter{}
	a.connected.Store(true)

	conn := &quicClientConn{adapter: a}

	err := conn.Invoke(context.Background(), "/unknown.Service/UnknownMethod", nil, nil)
	if err == nil {
		t.Fatal("Invoke() should return error for unmapped method")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T: %v", err, err)
	}
	if st.Code() != codes.Unimplemented {
		t.Errorf("status code = %v, want %v", st.Code(), codes.Unimplemented)
	}
}

func TestQuicClientConn_NewStream(t *testing.T) {
	a := &Adapter{}
	a.connected.Store(true)

	conn := &quicClientConn{adapter: a}

	_, err := conn.NewStream(context.Background(), nil, "/test/method")
	if err == nil {
		t.Fatal("NewStream() should return error")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T: %v", err, err)
	}
	if st.Code() != codes.Unimplemented {
		t.Errorf("status code = %v, want %v", st.Code(), codes.Unimplemented)
	}
}

func TestGRPCMethodToOpcodeMap_Health(t *testing.T) {
	tests := []struct {
		method   string
		expected byte
	}{
		{"/platform.v1.PlatformDaemon/GetHealth", quicapi.OpHealth},
		{"/platform.v1.PlatformDaemon/GetStatus", quicapi.OpDaemonStatus},
		{"/platform.v1.PlatformDaemon/GetVersion", quicapi.OpDaemonVersion},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			opcode, ok := grpcMethodToOpcodeMap[tt.method]
			if !ok {
				t.Fatalf("method %s not found in map", tt.method)
			}
			if opcode != tt.expected {
				t.Errorf("opcode = 0x%02X, want 0x%02X", opcode, tt.expected)
			}
		})
	}
}

func TestGRPCMethodToOpcodeMap_CA(t *testing.T) {
	tests := []struct {
		method   string
		expected byte
	}{
		{"/platform.v1.CAService/GetCAInfo", quicapi.OpCAInfo},
		{"/platform.v1.CAService/IssueCertificate", quicapi.OpCAIssue},
		{"/platform.v1.CAService/RevokeCertificate", quicapi.OpCARevoke},
		{"/platform.v1.CAService/RenewCertificate", quicapi.OpCARenew},
		{"/platform.v1.CAService/VerifyCertificate", quicapi.OpCAVerify},
		{"/platform.v1.CAService/GetCRL", quicapi.OpCACRL},
		{"/platform.v1.CAService/GetCABundle", quicapi.OpCABundle},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			opcode, ok := grpcMethodToOpcodeMap[tt.method]
			if !ok {
				t.Fatalf("method %s not found in map", tt.method)
			}
			if opcode != tt.expected {
				t.Errorf("opcode = 0x%02X, want 0x%02X", opcode, tt.expected)
			}
		})
	}
}

func TestGRPCMethodToOpcodeMap_KMS(t *testing.T) {
	tests := []struct {
		method   string
		expected byte
	}{
		{"/platform.v1.KeyManagementService/GenerateKey", quicapi.OpKMSGenerateKey},
		{"/platform.v1.KeyManagementService/UpdateKeyStatus", quicapi.OpKMSUpdateKeyStatus},
		{"/platform.v1.KeyManagementService/BackendStatus", quicapi.OpKMSBackendStatus},
		{"/platform.v1.KeyManagementService/Encrypt", quicapi.OpKMSEncrypt},
		{"/platform.v1.KeyManagementService/Decrypt", quicapi.OpKMSDecrypt},
		{"/platform.v1.KeyManagementService/BatchEncrypt", quicapi.OpKMSBatchEncrypt},
		{"/platform.v1.KeyManagementService/BatchDecrypt", quicapi.OpKMSBatchDecrypt},
		{"/platform.v1.KeyManagementService/Rewrap", quicapi.OpKMSRewrap},
		{"/platform.v1.KeyManagementService/Sign", quicapi.OpKMSSign},
		{"/platform.v1.KeyManagementService/Verify", quicapi.OpKMSVerify},
		{"/platform.v1.KeyManagementService/HMAC", quicapi.OpKMSHMAC},
		{"/platform.v1.KeyManagementService/VerifyHMAC", quicapi.OpKMSVerifyHMAC},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			opcode, ok := grpcMethodToOpcodeMap[tt.method]
			if !ok {
				t.Fatalf("method %s not found in map", tt.method)
			}
			if opcode != tt.expected {
				t.Errorf("opcode = 0x%02X, want 0x%02X", opcode, tt.expected)
			}
		})
	}
}

func TestGRPCMethodToOpcodeMap_VTPM(t *testing.T) {
	tests := []struct {
		method   string
		expected byte
	}{
		{"/platform.v1.VTPMService/QuoteVTPM", quicapi.OpVTPMQuote},
		{"/platform.v1.VTPMService/SealVTPM", quicapi.OpVTPMSeal},
		{"/platform.v1.VTPMService/UnsealVTPM", quicapi.OpVTPMUnseal},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			opcode, ok := grpcMethodToOpcodeMap[tt.method]
			if !ok {
				t.Fatalf("method %s not found in map", tt.method)
			}
			if opcode != tt.expected {
				t.Errorf("opcode = 0x%02X, want 0x%02X", opcode, tt.expected)
			}
		})
	}
}

func TestTranslateQUICErrorToGRPC(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		expectedCode codes.Code
	}{
		{
			name:         "nil error",
			err:          nil,
			expectedCode: codes.OK,
		},
		{
			name:         "client closed",
			err:          quicapi.ErrClientClosed,
			expectedCode: codes.Unavailable,
		},
		{
			name:         "stream failed",
			err:          quicapi.ErrStreamFailed,
			expectedCode: codes.Unavailable,
		},
		{
			name:         "protocol error - not found",
			err:          &quicapi.ErrProtocol{Status: quicapi.StatusNotFound, Message: "resource not found"},
			expectedCode: codes.NotFound,
		},
		{
			name:         "protocol error - unauthorized",
			err:          &quicapi.ErrProtocol{Status: quicapi.StatusUnauthorized, Message: "authentication required"},
			expectedCode: codes.Unauthenticated,
		},
		{
			name:         "protocol error - permission denied",
			err:          &quicapi.ErrProtocol{Status: quicapi.StatusPermissionDenied, Message: "access denied"},
			expectedCode: codes.PermissionDenied,
		},
		{
			name:         "protocol error - internal",
			err:          &quicapi.ErrProtocol{Status: quicapi.StatusInternalError, Message: "internal error"},
			expectedCode: codes.Internal,
		},
		{
			name:         "protocol error - invalid request",
			err:          &quicapi.ErrProtocol{Status: quicapi.StatusInvalidRequest, Message: "bad request"},
			expectedCode: codes.InvalidArgument,
		},
		{
			name:         "protocol error - already exists",
			err:          &quicapi.ErrProtocol{Status: quicapi.StatusAlreadyExists, Message: "already exists"},
			expectedCode: codes.AlreadyExists,
		},
		{
			name:         "protocol error - timeout",
			err:          &quicapi.ErrProtocol{Status: quicapi.StatusTimeout, Message: "timed out"},
			expectedCode: codes.DeadlineExceeded,
		},
		{
			name:         "protocol error - unavailable",
			err:          &quicapi.ErrProtocol{Status: quicapi.StatusUnavailable, Message: "service unavailable"},
			expectedCode: codes.Unavailable,
		},
		{
			name:         "protocol error - not implemented",
			err:          &quicapi.ErrProtocol{Status: quicapi.StatusNotImplemented, Message: "not implemented"},
			expectedCode: codes.Unimplemented,
		},
		{
			name:         "protocol error - unknown status",
			err:          &quicapi.ErrProtocol{Status: 0xFF, Message: "unknown status"},
			expectedCode: codes.Unknown,
		},
		{
			name:         "unknown error",
			err:          errors.New("unknown error"),
			expectedCode: codes.Unavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			grpcErr := translateQUICErrorToGRPC(tt.err)
			if tt.err == nil {
				if grpcErr != nil {
					t.Errorf("translateQUICErrorToGRPC(nil) = %v, want nil", grpcErr)
				}
				return
			}

			st, ok := status.FromError(grpcErr)
			if !ok {
				t.Fatalf("expected gRPC status error, got %T: %v", grpcErr, grpcErr)
			}
			if st.Code() != tt.expectedCode {
				t.Errorf("code = %v, want %v", st.Code(), tt.expectedCode)
			}
		})
	}
}

func TestQUICStatusToGRPCMap_Coverage(t *testing.T) {
	// Verify all QUIC status codes are mapped
	expectedStatuses := []byte{
		quicapi.StatusOK,
		quicapi.StatusInvalidRequest,
		quicapi.StatusNotFound,
		quicapi.StatusUnauthorized,
		quicapi.StatusInternalError,
		quicapi.StatusTimeout,
		quicapi.StatusAlreadyExists,
		quicapi.StatusPermissionDenied,
		quicapi.StatusResourceExhausted,
		quicapi.StatusInvalidArgument,
		quicapi.StatusUnavailable,
		quicapi.StatusNotImplemented,
	}

	for _, s := range expectedStatuses {
		if _, ok := quicStatusToGRPCMap[s]; !ok {
			t.Errorf("QUIC status 0x%02X not mapped to gRPC code", s)
		}
	}
}

func TestErrClientClosed_Error(t *testing.T) {
	err := ErrClientClosed{}
	expected := "QUIC client is closed"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrStreamFailed_Error(t *testing.T) {
	innerErr := errors.New("network error")
	err := ErrStreamFailed{Operation: "read", Err: innerErr}

	expected := "QUIC stream read failed: network error"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrStreamFailed_Unwrap(t *testing.T) {
	innerErr := errors.New("network error")
	err := ErrStreamFailed{Operation: "write", Err: innerErr}

	if !errors.Is(err, innerErr) {
		t.Error("Unwrap() should return the inner error")
	}
}

func TestErrProtocolError_Error(t *testing.T) {
	err := ErrProtocolError{Status: 0x02, Message: "not found"}
	expected := "QUIC protocol error (status 0x02): not found"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrEncodingFailed_Error(t *testing.T) {
	innerErr := errors.New("invalid type")
	err := ErrEncodingFailed{Err: innerErr}

	expected := "failed to encode payload: invalid type"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrEncodingFailed_Unwrap(t *testing.T) {
	innerErr := errors.New("invalid type")
	err := ErrEncodingFailed{Err: innerErr}

	if !errors.Is(err, innerErr) {
		t.Error("Unwrap() should return the inner error")
	}
}

func TestErrDecodingFailed_Error(t *testing.T) {
	innerErr := errors.New("invalid response")
	err := ErrDecodingFailed{Err: innerErr}

	expected := "failed to decode payload: invalid response"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrDecodingFailed_Unwrap(t *testing.T) {
	innerErr := errors.New("invalid response")
	err := ErrDecodingFailed{Err: innerErr}

	if !errors.Is(err, innerErr) {
		t.Error("Unwrap() should return the inner error")
	}
}

func TestErrMethodNotMapped_Error(t *testing.T) {
	err := ErrMethodNotMapped{Method: "/test.Service/Method"}
	expected := "gRPC method not mapped to QUIC opcode: /test.Service/Method"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}
