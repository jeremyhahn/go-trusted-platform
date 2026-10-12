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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	quicgo "github.com/quic-go/quic-go"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
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
		// UDP gives no connection refused; bound the handshake wait.
		platform.WithTimeout(250*time.Millisecond),
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

// TestConnect_HandshakeTimeoutIsErrTimeout pins that a QUIC peer that never
// answers the handshake is reported as ErrTimeout inside ErrConnectionFailed.
func TestConnect_HandshakeTimeoutIsErrTimeout(t *testing.T) {
	// A bound UDP socket that reads nothing: the handshake can only time out.
	silent, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() {
		if err := silent.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	})

	_, err = Connect(context.Background(), platform.NewOptions(
		platform.WithQUICAddr(silent.LocalAddr().String()),
		platform.WithTimeout(50*time.Millisecond),
	))

	var connErr platform.ErrConnectionFailed
	if !errors.As(err, &connErr) {
		t.Fatalf("err = %v, want ErrConnectionFailed", err)
	}
	var timeout platform.ErrTimeout
	if !errors.As(err, &timeout) {
		t.Fatalf("err = %v, want it to carry ErrTimeout", err)
	}
	if timeout.Operation != "QUIC handshake" {
		t.Errorf("Operation = %q, want %q", timeout.Operation, "QUIC handshake")
	}
}

// quicTestServer is an in-process QUIC listener on loopback that answers
// every framed request with StatusOK and reports the token it carried.
type quicTestServer struct {
	addr   string
	roots  *x509.CertPool
	tokens chan string
}

// startQUICTestServer serves the platform QUIC framing with a self-signed
// certificate valid for "platform.test" and 127.0.0.1.
func startQUICTestServer(t *testing.T) *quicTestServer {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "platform.test"},
		DNSNames:              []string{"platform.test"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)

	listener, err := quicgo.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{"platform-quic"},
		MinVersion:   tls.VersionTLS13,
	}, nil)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		if err := listener.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	})

	srv := &quicTestServer{
		addr:   listener.Addr().String(),
		roots:  roots,
		tokens: make(chan string, 8),
	}
	go srv.serve(ctx, listener)
	return srv
}

func (s *quicTestServer) serve(ctx context.Context, listener *quicgo.Listener) {
	for {
		conn, err := listener.Accept(ctx)
		if err != nil {
			return
		}
		go s.serveConn(ctx, conn)
	}
}

func (s *quicTestServer) serveConn(ctx context.Context, conn *quicgo.Conn) {
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		req, err := quicwire.ReadRequest(stream)
		if err != nil {
			stream.CancelRead(0)
			return
		}
		s.tokens <- req.Token
		if err := quicwire.WriteResponse(stream, &quicwire.Response{Status: quicwire.StatusOK}); err != nil {
			return
		}
		if err := stream.Close(); err != nil {
			return
		}
	}
}

func TestConnect_SendsBearerToken(t *testing.T) {
	srv := startQUICTestServer(t)

	adapter, err := Connect(context.Background(), platform.NewOptions(
		platform.WithQUICAddr(srv.addr),
		platform.WithTLSConfig(&tls.Config{RootCAs: srv.roots}),
		platform.WithBearerToken("secret"),
	))
	if err != nil {
		t.Fatalf("Connect() returned error: %v", err)
	}
	defer func() {
		if err := adapter.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	if err := adapter.(*Adapter).Client().Health(context.Background()); err != nil {
		t.Fatalf("Health() returned error: %v", err)
	}
	if got := <-srv.tokens; got != "secret" {
		t.Errorf("request token = %q, want %q", got, "secret")
	}
}

func TestConnect_HonoursTLSServerName(t *testing.T) {
	srv := startQUICTestServer(t)

	t.Run("matching name connects", func(t *testing.T) {
		adapter, err := Connect(context.Background(), platform.NewOptions(
			platform.WithQUICAddr(srv.addr),
			platform.WithTLSConfig(&tls.Config{RootCAs: srv.roots}),
			platform.WithTLSServerName("platform.test"),
		))
		if err != nil {
			t.Fatalf("Connect() returned error: %v", err)
		}
		if err := adapter.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	})

	t.Run("mismatched name is rejected", func(t *testing.T) {
		_, err := Connect(context.Background(), platform.NewOptions(
			platform.WithQUICAddr(srv.addr),
			platform.WithTLSConfig(&tls.Config{RootCAs: srv.roots}),
			platform.WithTLSServerName("wrong.test"),
		))
		var connErr platform.ErrConnectionFailed
		if !errors.As(err, &connErr) {
			t.Fatalf("Connect() error = %T: %v, want platform.ErrConnectionFailed", err, err)
		}
	})
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
		{"/platform.v1.PlatformDaemon/GetHealth", quicwire.OpHealth},
		{"/platform.v1.PlatformDaemon/GetStatus", quicwire.OpDaemonStatus},
		{"/platform.v1.PlatformDaemon/GetVersion", quicwire.OpDaemonVersion},
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
		{"/platform.v1.CAService/GetCAInfo", quicwire.OpCAInfo},
		{"/platform.v1.CAService/IssueCertificate", quicwire.OpCAIssue},
		{"/platform.v1.CAService/RevokeCertificate", quicwire.OpCARevoke},
		{"/platform.v1.CAService/RenewCertificate", quicwire.OpCARenew},
		{"/platform.v1.CAService/VerifyCertificate", quicwire.OpCAVerify},
		{"/platform.v1.CAService/GetCRL", quicwire.OpCACRL},
		{"/platform.v1.CAService/GetCABundle", quicwire.OpCABundle},
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
		{"/platform.v1.KeyManagementService/GenerateKey", quicwire.OpKMSGenerateKey},
		{"/platform.v1.KeyManagementService/UpdateKeyStatus", quicwire.OpKMSUpdateKeyStatus},
		{"/platform.v1.KeyManagementService/BackendStatus", quicwire.OpKMSBackendStatus},
		{"/platform.v1.KeyManagementService/Encrypt", quicwire.OpKMSEncrypt},
		{"/platform.v1.KeyManagementService/Decrypt", quicwire.OpKMSDecrypt},
		{"/platform.v1.KeyManagementService/BatchEncrypt", quicwire.OpKMSBatchEncrypt},
		{"/platform.v1.KeyManagementService/BatchDecrypt", quicwire.OpKMSBatchDecrypt},
		{"/platform.v1.KeyManagementService/Rewrap", quicwire.OpKMSRewrap},
		{"/platform.v1.KeyManagementService/Sign", quicwire.OpKMSSign},
		{"/platform.v1.KeyManagementService/Verify", quicwire.OpKMSVerify},
		{"/platform.v1.KeyManagementService/HMAC", quicwire.OpKMSHMAC},
		{"/platform.v1.KeyManagementService/VerifyHMAC", quicwire.OpKMSVerifyHMAC},
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
		{"/platform.v1.VTPMService/QuoteVTPM", quicwire.OpVTPMQuote},
		{"/platform.v1.VTPMService/SealVTPM", quicwire.OpVTPMSeal},
		{"/platform.v1.VTPMService/UnsealVTPM", quicwire.OpVTPMUnseal},
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
			err:          quicwire.ErrClientClosed,
			expectedCode: codes.Unavailable,
		},
		{
			name:         "stream failed",
			err:          quicwire.ErrStreamFailed,
			expectedCode: codes.Unavailable,
		},
		{
			name:         "protocol error - not found",
			err:          &quicwire.ErrProtocol{Status: quicwire.StatusNotFound, Message: "resource not found"},
			expectedCode: codes.NotFound,
		},
		{
			name:         "protocol error - unauthorized",
			err:          &quicwire.ErrProtocol{Status: quicwire.StatusUnauthorized, Message: "authentication required"},
			expectedCode: codes.Unauthenticated,
		},
		{
			name:         "protocol error - permission denied",
			err:          &quicwire.ErrProtocol{Status: quicwire.StatusPermissionDenied, Message: "access denied"},
			expectedCode: codes.PermissionDenied,
		},
		{
			name:         "protocol error - internal",
			err:          &quicwire.ErrProtocol{Status: quicwire.StatusInternalError, Message: "internal error"},
			expectedCode: codes.Internal,
		},
		{
			name:         "protocol error - invalid request",
			err:          &quicwire.ErrProtocol{Status: quicwire.StatusInvalidRequest, Message: "bad request"},
			expectedCode: codes.InvalidArgument,
		},
		{
			name:         "protocol error - already exists",
			err:          &quicwire.ErrProtocol{Status: quicwire.StatusAlreadyExists, Message: "already exists"},
			expectedCode: codes.AlreadyExists,
		},
		{
			name:         "protocol error - timeout",
			err:          &quicwire.ErrProtocol{Status: quicwire.StatusTimeout, Message: "timed out"},
			expectedCode: codes.DeadlineExceeded,
		},
		{
			name:         "protocol error - unavailable",
			err:          &quicwire.ErrProtocol{Status: quicwire.StatusUnavailable, Message: "service unavailable"},
			expectedCode: codes.Unavailable,
		},
		{
			name:         "protocol error - not implemented",
			err:          &quicwire.ErrProtocol{Status: quicwire.StatusNotImplemented, Message: "not implemented"},
			expectedCode: codes.Unimplemented,
		},
		{
			name:         "protocol error - unknown status",
			err:          &quicwire.ErrProtocol{Status: 0xFF, Message: "unknown status"},
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
		quicwire.StatusOK,
		quicwire.StatusInvalidRequest,
		quicwire.StatusNotFound,
		quicwire.StatusUnauthorized,
		quicwire.StatusInternalError,
		quicwire.StatusTimeout,
		quicwire.StatusAlreadyExists,
		quicwire.StatusPermissionDenied,
		quicwire.StatusResourceExhausted,
		quicwire.StatusInvalidArgument,
		quicwire.StatusUnavailable,
		quicwire.StatusNotImplemented,
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
