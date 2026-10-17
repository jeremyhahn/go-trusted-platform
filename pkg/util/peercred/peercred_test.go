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

//go:build linux

package peercred

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// contextKey is a typed key for context values to satisfy SA1029.
type unixContextKey string

// =============================================================================
// Error Type Tests
// =============================================================================

func TestErrUnixCredentialsUnavailable_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrUnixCredentialsUnavailable
		expected string
	}{
		{
			name:     "with reason",
			err:      ErrUnixCredentialsUnavailable{Reason: "connection closed"},
			expected: "unix credentials unavailable: connection closed",
		},
		{
			name:     "empty reason",
			err:      ErrUnixCredentialsUnavailable{Reason: ""},
			expected: "unix credentials unavailable: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestErrNilConnection_Error(t *testing.T) {
	err := ErrNilConnection{}
	expected := "connection is nil"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrNotUnixConnection_Error(t *testing.T) {
	err := ErrNotUnixConnection{}
	expected := "connection is not a Unix socket"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrPeerNotAvailable_Error(t *testing.T) {
	err := ErrPeerNotAvailable{}
	expected := "peer information not available in context"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrCredentialsNotInContext_Error(t *testing.T) {
	err := ErrCredentialsNotInContext{}
	expected := "unix credentials not found in context"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrSyscallFailed_Error(t *testing.T) {
	baseErr := errors.New("permission denied")
	err := ErrSyscallFailed{Operation: "GetsockoptUcred", Err: baseErr}

	expected := "syscall GetsockoptUcred failed: permission denied"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}

	// Test Unwrap
	if unwrapped := err.Unwrap(); unwrapped != baseErr {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, baseErr)
	}
}

// =============================================================================
// UnixCredentials Tests
// =============================================================================

func TestUnixCredentials_IsRoot(t *testing.T) {
	tests := []struct {
		name     string
		creds    UnixCredentials
		expected bool
	}{
		{
			name:     "root user",
			creds:    UnixCredentials{PID: 1, UID: 0, GID: 0},
			expected: true,
		},
		{
			name:     "non-root user",
			creds:    UnixCredentials{PID: 1000, UID: 1000, GID: 1000},
			expected: false,
		},
		{
			name:     "root group but not root user",
			creds:    UnixCredentials{PID: 1000, UID: 1000, GID: 0},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.creds.IsRoot(); got != tt.expected {
				t.Errorf("IsRoot() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestUnixCredentials_String(t *testing.T) {
	creds := UnixCredentials{PID: 1234, UID: 1000, GID: 100}
	expected := "UnixCredentials{PID:1234, UID:1000, GID:100}"
	if got := creds.String(); got != expected {
		t.Errorf("String() = %q, want %q", got, expected)
	}
}

// =============================================================================
// Context Helper Tests
// =============================================================================

func TestContextWithUnixCredentials(t *testing.T) {
	ctx := context.Background()
	creds := UnixCredentials{PID: 1234, UID: 1000, GID: 100}

	newCtx := ContextWithUnixCredentials(ctx, creds)

	// Verify credentials can be retrieved
	retrieved, ok := UnixCredentialsFromContext(newCtx)
	if !ok {
		t.Fatal("expected credentials to be found in context")
	}

	if retrieved.PID != creds.PID || retrieved.UID != creds.UID || retrieved.GID != creds.GID {
		t.Errorf("retrieved credentials = %+v, want %+v", retrieved, creds)
	}
}

// An in-process caller is this process: the identity is the one the kernel
// would report for it over SO_PEERCRED.
func TestContextWithProcessCredentials_IsThisProcess(t *testing.T) {
	got, ok := UnixCredentialsFromContext(ContextWithProcessCredentials(context.Background()))
	if !ok {
		t.Fatal("expected credentials to be found in context")
	}
	want := UnixCredentials{PID: int32(os.Getpid()), UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
	if got != want {
		t.Errorf("credentials = %+v, want %+v", got, want)
	}
}

// Credentials already on the caller's context do not survive: the process
// identity replaces them.
func TestContextWithProcessCredentials_ReplacesTheCallersClaim(t *testing.T) {
	claimed := ContextWithUnixCredentials(context.Background(), UnixCredentials{PID: 1, UID: uint32(os.Geteuid()) + 1, GID: 0})

	got, ok := UnixCredentialsFromContext(ContextWithProcessCredentials(claimed))
	if !ok {
		t.Fatal("expected credentials to be found in context")
	}
	if got.UID != uint32(os.Geteuid()) || got.PID != int32(os.Getpid()) {
		t.Errorf("credentials = %+v, want this process's", got)
	}
}

func TestUnixCredentialsFromContext_NotFound(t *testing.T) {
	ctx := context.Background()

	_, ok := UnixCredentialsFromContext(ctx)
	if ok {
		t.Error("expected credentials to not be found in empty context")
	}
}

func TestIsCertificatePrincipal_Marked(t *testing.T) {
	ctx := ContextWithCertificatePrincipal(context.Background())
	if !IsCertificatePrincipal(ctx) {
		t.Error("a marked context does not report a certificate principal")
	}
}

func TestIsCertificatePrincipal_Unmarked(t *testing.T) {
	// Unix peer credentials are a different credential: they do not mark
	// the principal as certificate-authenticated.
	ctx := ContextWithUnixCredentials(context.Background(), UnixCredentials{UID: 0})
	if IsCertificatePrincipal(ctx) {
		t.Error("an unmarked context reports a certificate principal")
	}
}

func TestMustUnixCredentialsFromContext_Success(t *testing.T) {
	creds := UnixCredentials{PID: 1234, UID: 1000, GID: 100}
	ctx := ContextWithUnixCredentials(context.Background(), creds)

	// Should not panic
	retrieved := MustUnixCredentialsFromContext(ctx)
	if retrieved.PID != creds.PID {
		t.Errorf("retrieved PID = %d, want %d", retrieved.PID, creds.PID)
	}
}

func TestMustUnixCredentialsFromContext_Panics(t *testing.T) {
	ctx := context.Background()

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic when credentials not in context")
		}
		if _, ok := r.(ErrCredentialsNotInContext); !ok {
			t.Errorf("expected ErrCredentialsNotInContext, got %T", r)
		}
	}()

	MustUnixCredentialsFromContext(ctx)
}

// =============================================================================
// ExtractUnixCredentials Tests
// =============================================================================

func TestExtractUnixCredentials_NilConnection(t *testing.T) {
	_, err := ExtractUnixCredentials(nil)
	if err == nil {
		t.Fatal("expected error for nil connection")
	}

	var nilErr ErrNilConnection
	if !errors.As(err, &nilErr) {
		t.Errorf("expected ErrNilConnection, got %T: %v", err, err)
	}
}

func TestExtractUnixCredentials_NotUnixConnection(t *testing.T) {
	// Create a TCP connection (not Unix socket)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	done := make(chan struct{})
	go func() {
		conn, _ := listener.Accept()
		if conn != nil {
			conn.Close()
		}
		close(done)
	}()

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	_, extractErr := ExtractUnixCredentials(conn)
	if extractErr == nil {
		t.Fatal("expected error for non-Unix connection")
	}

	var notUnixErr ErrNotUnixConnection
	if !errors.As(extractErr, &notUnixErr) {
		t.Errorf("expected ErrNotUnixConnection, got %T: %v", extractErr, extractErr)
	}

	<-done
}

func TestExtractUnixCredentials_ValidUnixSocket(t *testing.T) {
	// Create a temporary Unix socket
	tmpDir := t.TempDir()
	socketPath := tmpDir + "/test.sock"

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to create Unix listener: %v", err)
	}
	defer listener.Close()
	defer os.Remove(socketPath)

	var serverConn net.Conn
	done := make(chan struct{})
	go func() {
		serverConn, _ = listener.Accept()
		close(done)
	}()

	clientConn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to dial Unix socket: %v", err)
	}
	defer clientConn.Close()

	<-done
	if serverConn != nil {
		defer serverConn.Close()
	}

	// Extract credentials from server-side connection
	creds, err := ExtractUnixCredentials(serverConn)
	if err != nil {
		t.Fatalf("failed to extract credentials: %v", err)
	}

	// Verify we got our own credentials (since we connected)
	currentPID := int32(os.Getpid())
	currentUID := uint32(os.Getuid())
	currentGID := uint32(os.Getgid())

	if creds.PID != currentPID {
		t.Errorf("PID = %d, want %d", creds.PID, currentPID)
	}
	if creds.UID != currentUID {
		t.Errorf("UID = %d, want %d", creds.UID, currentUID)
	}
	if creds.GID != currentGID {
		t.Errorf("GID = %d, want %d", creds.GID, currentGID)
	}
}

// =============================================================================
// Transport Credentials Tests
// =============================================================================

func TestUnixTransportCredentials_Info(t *testing.T) {
	creds := NewUnixTransportCredentials()
	info := creds.Info()

	if info.SecurityProtocol != "unix_peercred" {
		t.Errorf("SecurityProtocol = %q, want %q", info.SecurityProtocol, "unix_peercred")
	}
	if info.SecurityVersion != "1.0" { //nolint:staticcheck // SA1019: testing deprecated field
		t.Errorf("SecurityVersion = %q, want %q", info.SecurityVersion, "1.0") //nolint:staticcheck // SA1019: testing deprecated field
	}
}

func TestUnixTransportCredentials_Clone(t *testing.T) {
	original := NewUnixTransportCredentials(WithRequireCredentials(true))
	cloned := original.Clone()

	if cloned == original {
		t.Error("Clone() should return a different instance")
	}

	// Verify both have same info
	if original.Info().SecurityProtocol != cloned.Info().SecurityProtocol {
		t.Error("cloned credentials should have same protocol info")
	}
}

func TestUnixTransportCredentials_OverrideServerName(t *testing.T) {
	creds := NewUnixTransportCredentials()
	err := creds.OverrideServerName("test.example.com") //nolint:staticcheck // SA1019: testing deprecated method
	if err != nil {
		t.Errorf("OverrideServerName() returned unexpected error: %v", err)
	}
}

func TestUnixTransportCredentials_ClientHandshake(t *testing.T) {
	creds := NewUnixTransportCredentials()

	// Create a temporary Unix socket
	tmpDir := t.TempDir()
	socketPath := tmpDir + "/test.sock"

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	done := make(chan struct{})
	go func() {
		conn, _ := listener.Accept()
		if conn != nil {
			conn.Close()
		}
		close(done)
	}()

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	// Client handshake should succeed
	retConn, authInfo, err := creds.ClientHandshake(context.Background(), "", conn)
	if err != nil {
		t.Fatalf("ClientHandshake() error = %v", err)
	}
	if retConn != conn {
		t.Error("ClientHandshake() should return same connection")
	}
	if authInfo != nil {
		t.Error("ClientHandshake() should return nil authInfo")
	}

	<-done
}

func TestUnixTransportCredentials_ServerHandshake(t *testing.T) {
	creds := NewUnixTransportCredentials()

	// Create a temporary Unix socket
	tmpDir := t.TempDir()
	socketPath := tmpDir + "/test.sock"

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	var serverConn net.Conn
	done := make(chan struct{})
	go func() {
		serverConn, _ = listener.Accept()
		close(done)
	}()

	clientConn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer clientConn.Close()

	<-done
	if serverConn != nil {
		defer serverConn.Close()
	}

	// Server handshake should extract credentials
	retConn, authInfo, err := creds.ServerHandshake(serverConn)
	if err != nil {
		t.Fatalf("ServerHandshake() error = %v", err)
	}
	if retConn != serverConn {
		t.Error("ServerHandshake() should return same connection")
	}
	if authInfo == nil {
		t.Fatal("ServerHandshake() should return authInfo")
	}

	uai, ok := authInfo.(unixAuthInfo)
	if !ok {
		t.Fatalf("authInfo type = %T, want unixAuthInfo", authInfo)
	}

	if uai.AuthType() != "unix_peercred" {
		t.Errorf("AuthType() = %q, want %q", uai.AuthType(), "unix_peercred")
	}

	creds_extracted := uai.Credentials()
	if creds_extracted.PID != int32(os.Getpid()) {
		t.Errorf("extracted PID = %d, want %d", creds_extracted.PID, os.Getpid())
	}
}

func TestUnixTransportCredentials_ServerHandshake_RequireCredentials(t *testing.T) {
	creds := NewUnixTransportCredentials(WithRequireCredentials(true))

	// Test with a non-Unix connection (TCP)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	var serverConn net.Conn
	done := make(chan struct{})
	go func() {
		serverConn, _ = listener.Accept()
		close(done)
	}()

	clientConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer clientConn.Close()

	<-done
	if serverConn != nil {
		defer serverConn.Close()
	}

	// Server handshake should fail for non-Unix connection when required
	_, _, err = creds.ServerHandshake(serverConn)
	if err == nil {
		t.Error("ServerHandshake() should fail for non-Unix connection when credentials required")
	}
}

func TestUnixTransportCredentials_ServerHandshake_NotRequired(t *testing.T) {
	// Test that non-Unix connections proceed when credentials are NOT required
	creds := NewUnixTransportCredentials(WithRequireCredentials(false))

	// Test with a non-Unix connection (TCP)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	var serverConn net.Conn
	done := make(chan struct{})
	go func() {
		serverConn, _ = listener.Accept()
		close(done)
	}()

	clientConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer clientConn.Close()

	<-done
	if serverConn != nil {
		defer serverConn.Close()
	}

	// Server handshake should succeed but return nil authInfo for non-Unix
	retConn, authInfo, err := creds.ServerHandshake(serverConn)
	if err != nil {
		t.Errorf("ServerHandshake() should not fail when credentials not required: %v", err)
	}
	if retConn != serverConn {
		t.Error("ServerHandshake() should return same connection")
	}
	if authInfo != nil {
		t.Error("ServerHandshake() should return nil authInfo for non-Unix connection")
	}
}

// =============================================================================
// Interceptor Tests
// =============================================================================

func TestUnixCredentialsUnaryInterceptor_WithCredentials(t *testing.T) {
	interceptor := UnixCredentialsUnaryInterceptor()

	// Create context with peer info containing Unix credentials
	creds := UnixCredentials{PID: 1234, UID: 1000, GID: 100}
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: unixAuthInfo{creds: creds},
	})

	var capturedCtx context.Context
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		capturedCtx = ctx
		return "response", nil
	}

	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}
	resp, err := interceptor(ctx, "request", info, handler)

	if err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}
	if resp != "response" {
		t.Errorf("response = %v, want %q", resp, "response")
	}

	// Verify credentials were injected into context
	extractedCreds, ok := UnixCredentialsFromContext(capturedCtx)
	if !ok {
		t.Fatal("credentials should be in handler context")
	}
	if extractedCreds.PID != creds.PID {
		t.Errorf("extracted PID = %d, want %d", extractedCreds.PID, creds.PID)
	}
}

func TestUnixCredentialsUnaryInterceptor_WithoutCredentials(t *testing.T) {
	interceptor := UnixCredentialsUnaryInterceptor()

	// Create context without peer info
	ctx := context.Background()

	var capturedCtx context.Context
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		capturedCtx = ctx
		return "response", nil
	}

	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}
	resp, err := interceptor(ctx, "request", info, handler)

	if err != nil {
		t.Fatalf("interceptor should not fail without credentials: %v", err)
	}
	if resp != "response" {
		t.Errorf("response = %v, want %q", resp, "response")
	}

	// Credentials should not be in context
	_, ok := UnixCredentialsFromContext(capturedCtx)
	if ok {
		t.Error("credentials should not be in context when not available")
	}
}

func TestUnixCredentialsUnaryInterceptorRequired_WithCredentials(t *testing.T) {
	interceptor := UnixCredentialsUnaryInterceptorRequired()

	creds := UnixCredentials{PID: 1234, UID: 1000, GID: 100}
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: unixAuthInfo{creds: creds},
	})

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "response", nil
	}

	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}
	_, err := interceptor(ctx, "request", info, handler)

	if err != nil {
		t.Fatalf("interceptor should succeed with credentials: %v", err)
	}
}

func TestUnixCredentialsUnaryInterceptorRequired_WithoutCredentials(t *testing.T) {
	interceptor := UnixCredentialsUnaryInterceptorRequired()

	ctx := context.Background()

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "response", nil
	}

	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}
	_, err := interceptor(ctx, "request", info, handler)

	if err == nil {
		t.Fatal("interceptor should fail without credentials")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("error should be gRPC status, got %T", err)
	}
	if st.Code() != codes.PermissionDenied {
		t.Errorf("error code = %v, want %v", st.Code(), codes.PermissionDenied)
	}
}

// mockServerStream implements grpc.ServerStream for testing
type mockServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (m *mockServerStream) Context() context.Context {
	return m.ctx
}

func TestUnixCredentialsStreamInterceptor_WithCredentials(t *testing.T) {
	interceptor := UnixCredentialsStreamInterceptor()

	creds := UnixCredentials{PID: 1234, UID: 1000, GID: 100}
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: unixAuthInfo{creds: creds},
	})

	stream := &mockServerStream{ctx: ctx}

	var capturedCtx context.Context
	handler := func(srv interface{}, ss grpc.ServerStream) error {
		capturedCtx = ss.Context()
		return nil
	}

	info := &grpc.StreamServerInfo{FullMethod: "/test.Service/StreamMethod"}
	err := interceptor(nil, stream, info, handler)

	if err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}

	// Verify credentials were injected
	extractedCreds, ok := UnixCredentialsFromContext(capturedCtx)
	if !ok {
		t.Fatal("credentials should be in handler context")
	}
	if extractedCreds.PID != creds.PID {
		t.Errorf("extracted PID = %d, want %d", extractedCreds.PID, creds.PID)
	}
}

func TestUnixCredentialsStreamInterceptor_WithoutCredentials(t *testing.T) {
	interceptor := UnixCredentialsStreamInterceptor()

	ctx := context.Background()
	stream := &mockServerStream{ctx: ctx}

	handler := func(srv interface{}, ss grpc.ServerStream) error {
		return nil
	}

	info := &grpc.StreamServerInfo{FullMethod: "/test.Service/StreamMethod"}
	err := interceptor(nil, stream, info, handler)

	if err != nil {
		t.Fatalf("interceptor should not fail without credentials: %v", err)
	}
}

func TestUnixCredentialsStreamInterceptorRequired_WithCredentials(t *testing.T) {
	interceptor := UnixCredentialsStreamInterceptorRequired()

	creds := UnixCredentials{PID: 1234, UID: 1000, GID: 100}
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: unixAuthInfo{creds: creds},
	})

	stream := &mockServerStream{ctx: ctx}

	var capturedCtx context.Context
	handler := func(srv interface{}, ss grpc.ServerStream) error {
		capturedCtx = ss.Context()
		return nil
	}

	info := &grpc.StreamServerInfo{FullMethod: "/test.Service/StreamMethod"}
	err := interceptor(nil, stream, info, handler)

	if err != nil {
		t.Fatalf("interceptor should succeed with credentials: %v", err)
	}

	// Verify credentials were injected
	extractedCreds, ok := UnixCredentialsFromContext(capturedCtx)
	if !ok {
		t.Fatal("credentials should be in handler context")
	}
	if extractedCreds.PID != creds.PID {
		t.Errorf("extracted PID = %d, want %d", extractedCreds.PID, creds.PID)
	}
}

func TestUnixCredentialsStreamInterceptorRequired_WithoutCredentials(t *testing.T) {
	interceptor := UnixCredentialsStreamInterceptorRequired()

	ctx := context.Background()
	stream := &mockServerStream{ctx: ctx}

	handler := func(srv interface{}, ss grpc.ServerStream) error {
		return nil
	}

	info := &grpc.StreamServerInfo{FullMethod: "/test.Service/StreamMethod"}
	err := interceptor(nil, stream, info, handler)

	if err == nil {
		t.Fatal("interceptor should fail without credentials")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("error should be gRPC status, got %T", err)
	}
	if st.Code() != codes.PermissionDenied {
		t.Errorf("error code = %v, want %v", st.Code(), codes.PermissionDenied)
	}
}

// =============================================================================
// extractCredentialsFromPeer Tests
// =============================================================================

func TestExtractCredentialsFromPeer_PeerWithDifferentAuthInfo(t *testing.T) {
	// Test with peer that has non-Unix auth info
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: nil, // No auth info
		Addr:     &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080},
	})

	_, err := extractCredentialsFromPeer(ctx)
	if err == nil {
		t.Error("expected error when peer has non-Unix address")
	}

	var unavailErr ErrUnixCredentialsUnavailable
	if !errors.As(err, &unavailErr) {
		t.Errorf("expected ErrUnixCredentialsUnavailable, got %T: %v", err, err)
	}
}

func TestExtractCredentialsFromPeer_UnixAddrWithoutAuthInfo(t *testing.T) {
	// Test with peer that has Unix address but no auth info
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: nil,
		Addr:     &net.UnixAddr{Name: "/tmp/test.sock", Net: "unix"},
	})

	_, err := extractCredentialsFromPeer(ctx)
	if err == nil {
		t.Error("expected error when peer has Unix address but no auth info")
	}

	var unavailErr ErrUnixCredentialsUnavailable
	if !errors.As(err, &unavailErr) {
		t.Errorf("expected ErrUnixCredentialsUnavailable, got %T: %v", err, err)
	}
}

// =============================================================================
// Authorization Helper Tests
// =============================================================================

func TestRequireRoot_Success(t *testing.T) {
	creds := UnixCredentials{PID: 1, UID: 0, GID: 0}
	ctx := ContextWithUnixCredentials(context.Background(), creds)

	err := RequireRoot(ctx)
	if err != nil {
		t.Errorf("RequireRoot() should succeed for root, got error: %v", err)
	}
}

func TestRequireRoot_NotRoot(t *testing.T) {
	creds := UnixCredentials{PID: 1000, UID: 1000, GID: 1000}
	ctx := ContextWithUnixCredentials(context.Background(), creds)

	err := RequireRoot(ctx)
	if err == nil {
		t.Fatal("RequireRoot() should fail for non-root")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("error should be gRPC status, got %T", err)
	}
	if st.Code() != codes.PermissionDenied {
		t.Errorf("error code = %v, want %v", st.Code(), codes.PermissionDenied)
	}
}

func TestRequireRoot_NoCredentials(t *testing.T) {
	ctx := context.Background()

	err := RequireRoot(ctx)
	if err == nil {
		t.Fatal("RequireRoot() should fail without credentials")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("error should be gRPC status, got %T", err)
	}
	if st.Code() != codes.Unauthenticated {
		t.Errorf("error code = %v, want %v", st.Code(), codes.Unauthenticated)
	}
}

func TestRequireUID_Success(t *testing.T) {
	creds := UnixCredentials{PID: 1000, UID: 1000, GID: 1000}
	ctx := ContextWithUnixCredentials(context.Background(), creds)

	err := RequireUID(ctx, 1000)
	if err != nil {
		t.Errorf("RequireUID() should succeed for matching UID, got error: %v", err)
	}
}

func TestRequireUID_Mismatch(t *testing.T) {
	creds := UnixCredentials{PID: 1000, UID: 1000, GID: 1000}
	ctx := ContextWithUnixCredentials(context.Background(), creds)

	err := RequireUID(ctx, 2000)
	if err == nil {
		t.Fatal("RequireUID() should fail for mismatched UID")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("error should be gRPC status, got %T", err)
	}
	if st.Code() != codes.PermissionDenied {
		t.Errorf("error code = %v, want %v", st.Code(), codes.PermissionDenied)
	}
}

func TestRequireUID_NoCredentials(t *testing.T) {
	ctx := context.Background()

	err := RequireUID(ctx, 1000)
	if err == nil {
		t.Fatal("RequireUID() should fail without credentials")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("error should be gRPC status, got %T", err)
	}
	if st.Code() != codes.Unauthenticated {
		t.Errorf("error code = %v, want %v", st.Code(), codes.Unauthenticated)
	}
}

func TestRequireGID_Success(t *testing.T) {
	creds := UnixCredentials{PID: 1000, UID: 1000, GID: 100}
	ctx := ContextWithUnixCredentials(context.Background(), creds)

	err := RequireGID(ctx, 100)
	if err != nil {
		t.Errorf("RequireGID() should succeed for matching GID, got error: %v", err)
	}
}

func TestRequireGID_Mismatch(t *testing.T) {
	creds := UnixCredentials{PID: 1000, UID: 1000, GID: 100}
	ctx := ContextWithUnixCredentials(context.Background(), creds)

	err := RequireGID(ctx, 200)
	if err == nil {
		t.Fatal("RequireGID() should fail for mismatched GID")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("error should be gRPC status, got %T", err)
	}
	if st.Code() != codes.PermissionDenied {
		t.Errorf("error code = %v, want %v", st.Code(), codes.PermissionDenied)
	}
}

func TestRequireGID_NoCredentials(t *testing.T) {
	ctx := context.Background()

	err := RequireGID(ctx, 100)
	if err == nil {
		t.Fatal("RequireGID() should fail without credentials")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("error should be gRPC status, got %T", err)
	}
	if st.Code() != codes.Unauthenticated {
		t.Errorf("error code = %v, want %v", st.Code(), codes.Unauthenticated)
	}
}

func TestRequireUIDOrRoot_MatchingUID(t *testing.T) {
	creds := UnixCredentials{PID: 1000, UID: 1000, GID: 1000}
	ctx := ContextWithUnixCredentials(context.Background(), creds)

	err := RequireUIDOrRoot(ctx, 1000)
	if err != nil {
		t.Errorf("RequireUIDOrRoot() should succeed for matching UID, got error: %v", err)
	}
}

func TestRequireUIDOrRoot_Root(t *testing.T) {
	creds := UnixCredentials{PID: 1, UID: 0, GID: 0}
	ctx := ContextWithUnixCredentials(context.Background(), creds)

	// Even with different required UID, root should pass
	err := RequireUIDOrRoot(ctx, 1000)
	if err != nil {
		t.Errorf("RequireUIDOrRoot() should succeed for root, got error: %v", err)
	}
}

func TestRequireUIDOrRoot_Neither(t *testing.T) {
	creds := UnixCredentials{PID: 1000, UID: 1000, GID: 1000}
	ctx := ContextWithUnixCredentials(context.Background(), creds)

	err := RequireUIDOrRoot(ctx, 2000)
	if err == nil {
		t.Fatal("RequireUIDOrRoot() should fail when neither matching UID nor root")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("error should be gRPC status, got %T", err)
	}
	if st.Code() != codes.PermissionDenied {
		t.Errorf("error code = %v, want %v", st.Code(), codes.PermissionDenied)
	}
}

func TestRequireUIDOrRoot_NoCredentials(t *testing.T) {
	ctx := context.Background()

	err := RequireUIDOrRoot(ctx, 1000)
	if err == nil {
		t.Fatal("RequireUIDOrRoot() should fail without credentials")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("error should be gRPC status, got %T", err)
	}
	if st.Code() != codes.Unauthenticated {
		t.Errorf("error code = %v, want %v", st.Code(), codes.Unauthenticated)
	}
}

// =============================================================================
// AuthInfo Tests
// =============================================================================

func TestUnixAuthInfo_AuthType(t *testing.T) {
	ai := unixAuthInfo{creds: UnixCredentials{PID: 1234, UID: 1000, GID: 100}}

	if got := ai.AuthType(); got != "unix_peercred" {
		t.Errorf("AuthType() = %q, want %q", got, "unix_peercred")
	}
}

func TestUnixAuthInfo_ImplementsAuthInfo(t *testing.T) {
	var _ credentials.AuthInfo = unixAuthInfo{}
}

// =============================================================================
// Wrapped Server Stream Tests
// =============================================================================

func TestWrappedServerStream_Context(t *testing.T) {
	originalCtx := context.Background()
	newCtx := context.WithValue(context.Background(), unixContextKey("test"), "value")

	wrapped := &wrappedServerStream{
		ServerStream: &mockServerStream{ctx: originalCtx},
		ctx:          newCtx,
	}

	if got := wrapped.Context(); got != newCtx {
		t.Error("Context() should return the wrapped context")
	}
}
