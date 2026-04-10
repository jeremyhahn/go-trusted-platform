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

package grpc

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"syscall"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// =============================================================================
// Error Types
// =============================================================================

// ErrUnixCredentialsUnavailable is returned when Unix socket credentials
// cannot be retrieved from the connection.
type ErrUnixCredentialsUnavailable struct {
	Reason string
}

func (e ErrUnixCredentialsUnavailable) Error() string {
	return fmt.Sprintf("unix credentials unavailable: %s", e.Reason)
}

// ErrNilConnection is returned when a nil connection is provided.
type ErrNilConnection struct{}

func (e ErrNilConnection) Error() string {
	return "connection is nil"
}

// ErrNotUnixConnection is returned when the connection is not a Unix socket.
type ErrNotUnixConnection struct{}

func (e ErrNotUnixConnection) Error() string {
	return "connection is not a Unix socket"
}

// ErrPeerNotAvailable is returned when peer information is not available
// in the context.
type ErrPeerNotAvailable struct{}

func (e ErrPeerNotAvailable) Error() string {
	return "peer information not available in context"
}

// ErrCredentialsNotInContext is returned when Unix credentials are not
// present in the context.
type ErrCredentialsNotInContext struct{}

func (e ErrCredentialsNotInContext) Error() string {
	return "unix credentials not found in context"
}

// ErrSyscallFailed is returned when a syscall operation fails.
type ErrSyscallFailed struct {
	Operation string
	Err       error
}

func (e ErrSyscallFailed) Error() string {
	return fmt.Sprintf("syscall %s failed: %v", e.Operation, e.Err)
}

func (e ErrSyscallFailed) Unwrap() error {
	return e.Err
}

// =============================================================================
// Unix Credentials Structure
// =============================================================================

// UnixCredentials contains Unix socket peer credentials extracted via SO_PEERCRED.
// These credentials are kernel-verified and cannot be forged by userspace processes.
type UnixCredentials struct {
	PID int32  // Process ID of peer
	UID uint32 // User ID of peer
	GID uint32 // Group ID of peer
}

// IsRoot returns true if the credentials indicate root user (UID 0).
func (c UnixCredentials) IsRoot() bool {
	return c.UID == 0
}

// String returns a string representation of the credentials.
func (c UnixCredentials) String() string {
	return fmt.Sprintf("UnixCredentials{PID:%d, UID:%d, GID:%d}", c.PID, c.UID, c.GID)
}

// =============================================================================
// Context Key and Helpers
// =============================================================================

// unixCredentialsKey is the context key for Unix socket credentials.
type unixCredentialsKey struct{}

// ContextWithUnixCredentials adds Unix credentials to a context.
func ContextWithUnixCredentials(ctx context.Context, creds UnixCredentials) context.Context {
	return context.WithValue(ctx, unixCredentialsKey{}, creds)
}

// UnixCredentialsFromContext extracts Unix credentials from a context.
// Returns the credentials and a boolean indicating if they were found.
func UnixCredentialsFromContext(ctx context.Context) (UnixCredentials, bool) {
	creds, ok := ctx.Value(unixCredentialsKey{}).(UnixCredentials)
	return creds, ok
}

// MustUnixCredentialsFromContext extracts Unix credentials from a context
// and panics if they are not found. Use this only when credentials are
// guaranteed to be present (e.g., after the interceptor has run).
func MustUnixCredentialsFromContext(ctx context.Context) UnixCredentials {
	creds, ok := UnixCredentialsFromContext(ctx)
	if !ok {
		panic(ErrCredentialsNotInContext{})
	}
	return creds
}

// =============================================================================
// SO_PEERCRED Extraction
// =============================================================================

// ExtractUnixCredentials extracts peer credentials from a Unix socket connection
// using SO_PEERCRED. This is kernel-verified and cannot be forged.
func ExtractUnixCredentials(conn net.Conn) (UnixCredentials, error) {
	if conn == nil {
		return UnixCredentials{}, ErrNilConnection{}
	}

	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return UnixCredentials{}, ErrNotUnixConnection{}
	}

	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return UnixCredentials{}, ErrUnixCredentialsUnavailable{Reason: err.Error()}
	}

	var creds UnixCredentials
	var credErr error

	err = rawConn.Control(func(fd uintptr) {
		ucred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if err != nil {
			credErr = ErrSyscallFailed{Operation: "GetsockoptUcred", Err: err}
			return
		}

		creds = UnixCredentials{
			PID: ucred.Pid,
			UID: ucred.Uid,
			GID: ucred.Gid,
		}
	})

	if err != nil {
		return UnixCredentials{}, ErrUnixCredentialsUnavailable{Reason: err.Error()}
	}

	if credErr != nil {
		return UnixCredentials{}, credErr
	}

	return creds, nil
}

// =============================================================================
// gRPC Transport Credentials Implementation
// =============================================================================

// unixAuthInfo implements credentials.AuthInfo for Unix socket credentials.
type unixAuthInfo struct {
	creds UnixCredentials
}

// AuthType returns the authentication type identifier.
func (u unixAuthInfo) AuthType() string {
	return "unix_peercred"
}

// Credentials returns the Unix credentials.
func (u unixAuthInfo) Credentials() UnixCredentials {
	return u.creds
}

// unixTransportCredentials implements credentials.TransportCredentials
// for Unix domain sockets with SO_PEERCRED extraction.
type unixTransportCredentials struct {
	// requireCredentials determines if connections without valid credentials
	// should be rejected.
	requireCredentials atomic.Bool
}

// UnixTransportOption configures the Unix transport credentials.
type UnixTransportOption func(*unixTransportCredentials)

// WithRequireCredentials configures whether credentials extraction is mandatory.
// If true, connections where credentials cannot be extracted will be rejected.
func WithRequireCredentials(require bool) UnixTransportOption {
	return func(c *unixTransportCredentials) {
		c.requireCredentials.Store(require)
	}
}

// NewUnixTransportCredentials creates new transport credentials for Unix sockets
// that extract peer credentials via SO_PEERCRED during the server handshake.
func NewUnixTransportCredentials(opts ...UnixTransportOption) credentials.TransportCredentials {
	c := &unixTransportCredentials{}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// ClientHandshake implements credentials.TransportCredentials.
// For Unix sockets, the client side doesn't need special handling.
func (c *unixTransportCredentials) ClientHandshake(
	ctx context.Context,
	authority string,
	rawConn net.Conn,
) (net.Conn, credentials.AuthInfo, error) {
	// Client side: just return the connection, no special auth needed
	return rawConn, nil, nil
}

// ServerHandshake implements credentials.TransportCredentials.
// This extracts SO_PEERCRED during the connection handshake.
func (c *unixTransportCredentials) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	creds, err := ExtractUnixCredentials(rawConn)
	if err != nil {
		if c.requireCredentials.Load() {
			return nil, nil, err
		}
		// If credentials aren't required, proceed without them
		return rawConn, nil, nil
	}

	return rawConn, unixAuthInfo{creds: creds}, nil
}

// Info returns protocol information for Unix transport.
func (c *unixTransportCredentials) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{
		SecurityProtocol: "unix_peercred",
		SecurityVersion:  "1.0",
		ServerName:       "",
	}
}

// Clone creates a copy of the transport credentials.
func (c *unixTransportCredentials) Clone() credentials.TransportCredentials {
	cloned := &unixTransportCredentials{}
	cloned.requireCredentials.Store(c.requireCredentials.Load())
	return cloned
}

// OverrideServerName is not supported for Unix transport.
func (c *unixTransportCredentials) OverrideServerName(serverName string) error {
	// Server name override is not applicable to Unix sockets
	return nil
}

// =============================================================================
// gRPC Interceptors
// =============================================================================

// UnixCredentialsUnaryInterceptor creates a unary server interceptor that extracts
// Unix socket credentials from the peer connection and injects them into the context.
//
// This interceptor should be used in conjunction with NewUnixTransportCredentials
// to extract credentials during the handshake, or it can extract credentials from
// the peer info if transport credentials were not used.
//
// Usage:
//
//	server := grpc.NewServer(
//	    grpc.Creds(grpc.NewUnixTransportCredentials()),
//	    grpc.UnaryInterceptor(grpc.UnixCredentialsUnaryInterceptor()),
//	)
func UnixCredentialsUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Try to extract credentials from peer auth info (set by transport credentials)
		creds, err := extractCredentialsFromPeer(ctx)
		if err != nil {
			// Log but don't fail - credentials may be optional
			// The application can check UnixCredentialsFromContext to verify
			return handler(ctx, req)
		}

		// Inject credentials into context
		ctx = ContextWithUnixCredentials(ctx, creds)
		return handler(ctx, req)
	}
}

// UnixCredentialsUnaryInterceptorRequired creates a unary server interceptor
// that requires Unix socket credentials. If credentials cannot be extracted,
// the RPC will fail with PermissionDenied.
func UnixCredentialsUnaryInterceptorRequired() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		creds, err := extractCredentialsFromPeer(ctx)
		if err != nil {
			return nil, status.Errorf(codes.PermissionDenied,
				"unix credentials required: %v", err)
		}

		ctx = ContextWithUnixCredentials(ctx, creds)
		return handler(ctx, req)
	}
}

// UnixCredentialsStreamInterceptor creates a stream server interceptor that extracts
// Unix socket credentials from the peer connection and injects them into the context.
//
// Usage:
//
//	server := grpc.NewServer(
//	    grpc.Creds(grpc.NewUnixTransportCredentials()),
//	    grpc.StreamInterceptor(grpc.UnixCredentialsStreamInterceptor()),
//	)
func UnixCredentialsStreamInterceptor() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		ctx := ss.Context()

		// Try to extract credentials from peer auth info
		creds, err := extractCredentialsFromPeer(ctx)
		if err != nil {
			// Proceed without credentials - application can check
			return handler(srv, ss)
		}

		// Wrap the stream with updated context containing credentials
		wrapped := &wrappedServerStream{
			ServerStream: ss,
			ctx:          ContextWithUnixCredentials(ctx, creds),
		}
		return handler(srv, wrapped)
	}
}

// UnixCredentialsStreamInterceptorRequired creates a stream server interceptor
// that requires Unix socket credentials. If credentials cannot be extracted,
// the stream will fail with PermissionDenied.
func UnixCredentialsStreamInterceptorRequired() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		ctx := ss.Context()

		creds, err := extractCredentialsFromPeer(ctx)
		if err != nil {
			return status.Errorf(codes.PermissionDenied,
				"unix credentials required: %v", err)
		}

		wrapped := &wrappedServerStream{
			ServerStream: ss,
			ctx:          ContextWithUnixCredentials(ctx, creds),
		}
		return handler(srv, wrapped)
	}
}

// =============================================================================
// Helper Types and Functions
// =============================================================================

// wrappedServerStream wraps grpc.ServerStream to provide a modified context.
type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context returns the wrapped context with Unix credentials.
func (w *wrappedServerStream) Context() context.Context {
	return w.ctx
}

// extractCredentialsFromPeer extracts Unix credentials from peer auth info.
func extractCredentialsFromPeer(ctx context.Context) (UnixCredentials, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return UnixCredentials{}, ErrPeerNotAvailable{}
	}

	// Check if auth info contains Unix credentials
	if p.AuthInfo != nil {
		if uai, ok := p.AuthInfo.(unixAuthInfo); ok {
			return uai.Credentials(), nil
		}
	}

	// If no auth info, try to extract from the peer address if it's a Unix socket
	// This handles the case where transport credentials weren't used
	if p.Addr != nil {
		if unixAddr, ok := p.Addr.(*net.UnixAddr); ok {
			return UnixCredentials{}, ErrUnixCredentialsUnavailable{
				Reason: fmt.Sprintf("credentials not available for address %s (use NewUnixTransportCredentials)",
					unixAddr.String()),
			}
		}
	}

	return UnixCredentials{}, ErrUnixCredentialsUnavailable{Reason: "peer is not a Unix socket"}
}

// =============================================================================
// Convenience Functions for Authorization
// =============================================================================

// RequireRoot is a helper that checks if the Unix credentials indicate root user.
// Returns an error suitable for gRPC status if not root.
func RequireRoot(ctx context.Context) error {
	creds, ok := UnixCredentialsFromContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "unix credentials not available")
	}
	if !creds.IsRoot() {
		return status.Errorf(codes.PermissionDenied,
			"root required, got uid=%d", creds.UID)
	}
	return nil
}

// RequireUID is a helper that checks if the Unix credentials match the specified UID.
// Returns an error suitable for gRPC status if the UID doesn't match.
func RequireUID(ctx context.Context, uid uint32) error {
	creds, ok := UnixCredentialsFromContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "unix credentials not available")
	}
	if creds.UID != uid {
		return status.Errorf(codes.PermissionDenied,
			"uid %d required, got %d", uid, creds.UID)
	}
	return nil
}

// RequireGID is a helper that checks if the Unix credentials match the specified GID.
// Returns an error suitable for gRPC status if the GID doesn't match.
func RequireGID(ctx context.Context, gid uint32) error {
	creds, ok := UnixCredentialsFromContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "unix credentials not available")
	}
	if creds.GID != gid {
		return status.Errorf(codes.PermissionDenied,
			"gid %d required, got %d", gid, creds.GID)
	}
	return nil
}

// RequireUIDOrRoot is a helper that checks if the Unix credentials match the
// specified UID or are root. Returns an error suitable for gRPC status if neither.
func RequireUIDOrRoot(ctx context.Context, uid uint32) error {
	creds, ok := UnixCredentialsFromContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "unix credentials not available")
	}
	if creds.UID != uid && !creds.IsRoot() {
		return status.Errorf(codes.PermissionDenied,
			"uid %d or root required, got uid=%d", uid, creds.UID)
	}
	return nil
}
