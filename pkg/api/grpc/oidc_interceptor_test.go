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

package grpc

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// contextKey is a typed key for context values to satisfy SA1029.
type contextKey string

// =============================================================================
// Error Type Tests
// =============================================================================

func TestErrTokenValidatorNotConfigured_Error(t *testing.T) {
	err := ErrTokenValidatorNotConfigured{}
	expected := "OIDC token validator not configured"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrMissingAuthorizationHeader_Error(t *testing.T) {
	err := ErrMissingAuthorizationHeader{}
	expected := "missing authorization header"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrInvalidAuthorizationHeader_Error(t *testing.T) {
	err := ErrInvalidAuthorizationHeader{}
	expected := "invalid authorization header format"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrTokenValidationFailed_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrTokenValidationFailed
		expected string
	}{
		{
			name:     "with cause",
			err:      ErrTokenValidationFailed{Cause: errors.New("token expired")},
			expected: "token validation failed: token expired",
		},
		{
			name:     "without cause",
			err:      ErrTokenValidationFailed{Cause: nil},
			expected: "token validation failed",
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

func TestErrTokenValidationFailed_Unwrap(t *testing.T) {
	cause := errors.New("token expired")
	err := ErrTokenValidationFailed{Cause: cause}

	if unwrapped := err.Unwrap(); unwrapped != cause {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
	}
}

// =============================================================================
// Mock Token Validator
// =============================================================================

type mockTokenValidator struct {
	valid bool
	err   error
}

func (m *mockTokenValidator) ValidateToken(ctx context.Context, token string) (bool, error) {
	return m.valid, m.err
}

// =============================================================================
// Context Helper Tests
// =============================================================================

func TestContextWithToken_TokenFromContext(t *testing.T) {
	ctx := context.Background()
	token := "test-bearer-token"

	newCtx := ContextWithToken(ctx, token)

	retrieved, ok := TokenFromContext(newCtx)
	if !ok {
		t.Fatal("expected token to be found in context")
	}

	if retrieved != token {
		t.Errorf("TokenFromContext() = %q, want %q", retrieved, token)
	}
}

func TestTokenFromContext_NotFound(t *testing.T) {
	ctx := context.Background()

	_, ok := TokenFromContext(ctx)
	if ok {
		t.Error("expected token to not be found in empty context")
	}
}

// =============================================================================
// Configuration Tests
// =============================================================================

func TestOIDCInterceptorConfig_Options(t *testing.T) {
	validator := &mockTokenValidator{}
	methods := []string{"/health.Service/Check", "/grpc.health.v1.Health/Check"}

	config := &OIDCInterceptorConfig{
		RequireAuth: true,
	}

	WithTokenValidator(validator)(config)
	WithSkipMethods(methods...)(config)
	WithRequireAuth(false)(config)

	if config.TokenValidator != validator {
		t.Error("WithTokenValidator did not set token validator")
	}

	if len(config.SkipMethods) != len(methods) {
		t.Errorf("WithSkipMethods set %d methods, want %d", len(config.SkipMethods), len(methods))
	}

	if config.RequireAuth {
		t.Error("WithRequireAuth(false) did not set RequireAuth to false")
	}
}

// =============================================================================
// Extract Bearer Token Tests
// =============================================================================

func TestExtractBearerToken_Valid(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		expected string
	}{
		{
			name:     "standard bearer token",
			header:   "Bearer eyJhbGciOiJSUzI1NiJ9.test",
			expected: "eyJhbGciOiJSUzI1NiJ9.test",
		},
		{
			name:     "lowercase bearer",
			header:   "bearer test-token",
			expected: "test-token",
		},
		{
			name:     "with whitespace",
			header:   "Bearer   token-with-spaces  ",
			expected: "token-with-spaces",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			md := metadata.Pairs("authorization", tt.header)
			ctx := metadata.NewIncomingContext(context.Background(), md)

			token, err := extractBearerToken(ctx)
			if err != nil {
				t.Fatalf("extractBearerToken() error = %v", err)
			}

			if token != tt.expected {
				t.Errorf("extractBearerToken() = %q, want %q", token, tt.expected)
			}
		})
	}
}

func TestExtractBearerToken_MissingMetadata(t *testing.T) {
	ctx := context.Background()

	_, err := extractBearerToken(ctx)
	if err == nil {
		t.Fatal("expected error for missing metadata")
	}

	var missingErr ErrMissingAuthorizationHeader
	if !errors.As(err, &missingErr) {
		t.Errorf("expected ErrMissingAuthorizationHeader, got %T", err)
	}
}

func TestExtractBearerToken_MissingHeader(t *testing.T) {
	md := metadata.Pairs("other-header", "value")
	ctx := metadata.NewIncomingContext(context.Background(), md)

	_, err := extractBearerToken(ctx)
	if err == nil {
		t.Fatal("expected error for missing authorization header")
	}

	var missingErr ErrMissingAuthorizationHeader
	if !errors.As(err, &missingErr) {
		t.Errorf("expected ErrMissingAuthorizationHeader, got %T", err)
	}
}

func TestExtractBearerToken_InvalidFormat(t *testing.T) {
	tests := []struct {
		name   string
		header string
	}{
		{
			name:   "basic auth",
			header: "Basic dXNlcjpwYXNz",
		},
		{
			name:   "no prefix",
			header: "just-a-token",
		},
		{
			name:   "empty bearer",
			header: "Bearer ",
		},
		{
			name:   "bearer with only spaces",
			header: "Bearer    ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			md := metadata.Pairs("authorization", tt.header)
			ctx := metadata.NewIncomingContext(context.Background(), md)

			_, err := extractBearerToken(ctx)
			if err == nil {
				t.Fatal("expected error for invalid header format")
			}

			var invalidErr ErrInvalidAuthorizationHeader
			if !errors.As(err, &invalidErr) {
				t.Errorf("expected ErrInvalidAuthorizationHeader, got %T", err)
			}
		})
	}
}

// =============================================================================
// AddBearerToken Tests
// =============================================================================

func TestAddBearerToken(t *testing.T) {
	ctx := context.Background()
	token := "test-token"

	newCtx := AddBearerToken(ctx, token)

	md, ok := metadata.FromOutgoingContext(newCtx)
	if !ok {
		t.Fatal("expected outgoing metadata")
	}

	authHeaders := md.Get("authorization")
	if len(authHeaders) == 0 {
		t.Fatal("expected authorization header in outgoing metadata")
	}

	expected := "Bearer test-token"
	if authHeaders[0] != expected {
		t.Errorf("authorization header = %q, want %q", authHeaders[0], expected)
	}
}

// =============================================================================
// Unary Interceptor Tests
// =============================================================================

func TestOIDCUnaryInterceptor_SkipMethod(t *testing.T) {
	interceptor := OIDCUnaryInterceptor(
		WithSkipMethods("/health.Service/Check"),
	)

	ctx := context.Background()
	handlerCalled := false

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		return "response", nil
	}

	info := &grpc.UnaryServerInfo{FullMethod: "/health.Service/Check"}
	resp, err := interceptor(ctx, "request", info, handler)

	if err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}

	if !handlerCalled {
		t.Error("handler was not called for skipped method")
	}

	if resp != "response" {
		t.Errorf("response = %v, want %q", resp, "response")
	}
}

func TestOIDCUnaryInterceptor_NoValidator_RequireAuth(t *testing.T) {
	interceptor := OIDCUnaryInterceptor(
		WithRequireAuth(true),
	)

	ctx := context.Background()

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "response", nil
	}

	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}
	_, err := interceptor(ctx, "request", info, handler)

	if err == nil {
		t.Fatal("expected error when no validator configured and auth required")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T", err)
	}

	if st.Code() != codes.Unavailable {
		t.Errorf("error code = %v, want %v", st.Code(), codes.Unavailable)
	}
}

func TestOIDCUnaryInterceptor_NoValidator_AuthNotRequired(t *testing.T) {
	interceptor := OIDCUnaryInterceptor(
		WithRequireAuth(false),
	)

	ctx := context.Background()
	handlerCalled := false

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		return "response", nil
	}

	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}
	resp, err := interceptor(ctx, "request", info, handler)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !handlerCalled {
		t.Error("handler was not called")
	}

	if resp != "response" {
		t.Errorf("response = %v, want %q", resp, "response")
	}
}

func TestOIDCUnaryInterceptor_MissingToken(t *testing.T) {
	validator := &mockTokenValidator{valid: true}
	interceptor := OIDCUnaryInterceptor(
		WithTokenValidator(validator),
	)

	ctx := context.Background()

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "response", nil
	}

	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}
	_, err := interceptor(ctx, "request", info, handler)

	if err == nil {
		t.Fatal("expected error for missing token")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T", err)
	}

	if st.Code() != codes.Unauthenticated {
		t.Errorf("error code = %v, want %v", st.Code(), codes.Unauthenticated)
	}
}

func TestOIDCUnaryInterceptor_ValidationFails(t *testing.T) {
	validator := &mockTokenValidator{valid: false, err: errors.New("token expired")}
	interceptor := OIDCUnaryInterceptor(
		WithTokenValidator(validator),
	)

	md := metadata.Pairs("authorization", "Bearer test-token")
	ctx := metadata.NewIncomingContext(context.Background(), md)

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "response", nil
	}

	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}
	_, err := interceptor(ctx, "request", info, handler)

	if err == nil {
		t.Fatal("expected error for failed validation")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T", err)
	}

	if st.Code() != codes.Unauthenticated {
		t.Errorf("error code = %v, want %v", st.Code(), codes.Unauthenticated)
	}
}

func TestOIDCUnaryInterceptor_InvalidToken(t *testing.T) {
	validator := &mockTokenValidator{valid: false, err: nil}
	interceptor := OIDCUnaryInterceptor(
		WithTokenValidator(validator),
	)

	md := metadata.Pairs("authorization", "Bearer invalid-token")
	ctx := metadata.NewIncomingContext(context.Background(), md)

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "response", nil
	}

	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}
	_, err := interceptor(ctx, "request", info, handler)

	if err == nil {
		t.Fatal("expected error for invalid token")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T", err)
	}

	if st.Code() != codes.Unauthenticated {
		t.Errorf("error code = %v, want %v", st.Code(), codes.Unauthenticated)
	}
}

func TestOIDCUnaryInterceptor_ValidToken(t *testing.T) {
	validator := &mockTokenValidator{valid: true}
	interceptor := OIDCUnaryInterceptor(
		WithTokenValidator(validator),
	)

	md := metadata.Pairs("authorization", "Bearer valid-token")
	ctx := metadata.NewIncomingContext(context.Background(), md)

	var capturedCtx context.Context
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		capturedCtx = ctx
		return "response", nil
	}

	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}
	resp, err := interceptor(ctx, "request", info, handler)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp != "response" {
		t.Errorf("response = %v, want %q", resp, "response")
	}

	// Verify token was added to context
	token, ok := TokenFromContext(capturedCtx)
	if !ok {
		t.Error("expected token in context after successful validation")
	}

	if token != "valid-token" {
		t.Errorf("token in context = %q, want %q", token, "valid-token")
	}
}

// =============================================================================
// Stream Interceptor Tests
// =============================================================================

// mockOIDCServerStream implements grpc.ServerStream for testing
type mockOIDCServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (m *mockOIDCServerStream) Context() context.Context {
	return m.ctx
}

func TestOIDCStreamInterceptor_SkipMethod(t *testing.T) {
	interceptor := OIDCStreamInterceptor(
		WithSkipMethods("/health.Service/Watch"),
	)

	ctx := context.Background()
	stream := &mockOIDCServerStream{ctx: ctx}
	handlerCalled := false

	handler := func(srv interface{}, ss grpc.ServerStream) error {
		handlerCalled = true
		return nil
	}

	info := &grpc.StreamServerInfo{FullMethod: "/health.Service/Watch"}
	err := interceptor(nil, stream, info, handler)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !handlerCalled {
		t.Error("handler was not called for skipped method")
	}
}

func TestOIDCStreamInterceptor_NoValidator_RequireAuth(t *testing.T) {
	interceptor := OIDCStreamInterceptor(
		WithRequireAuth(true),
	)

	ctx := context.Background()
	stream := &mockOIDCServerStream{ctx: ctx}

	handler := func(srv interface{}, ss grpc.ServerStream) error {
		return nil
	}

	info := &grpc.StreamServerInfo{FullMethod: "/test.Service/StreamMethod"}
	err := interceptor(nil, stream, info, handler)

	if err == nil {
		t.Fatal("expected error when no validator configured and auth required")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T", err)
	}

	if st.Code() != codes.Unavailable {
		t.Errorf("error code = %v, want %v", st.Code(), codes.Unavailable)
	}
}

func TestOIDCStreamInterceptor_NoValidator_AuthNotRequired(t *testing.T) {
	interceptor := OIDCStreamInterceptor(
		WithRequireAuth(false),
	)

	ctx := context.Background()
	stream := &mockOIDCServerStream{ctx: ctx}
	handlerCalled := false

	handler := func(srv interface{}, ss grpc.ServerStream) error {
		handlerCalled = true
		return nil
	}

	info := &grpc.StreamServerInfo{FullMethod: "/test.Service/StreamMethod"}
	err := interceptor(nil, stream, info, handler)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !handlerCalled {
		t.Error("handler was not called")
	}
}

func TestOIDCStreamInterceptor_MissingToken(t *testing.T) {
	validator := &mockTokenValidator{valid: true}
	interceptor := OIDCStreamInterceptor(
		WithTokenValidator(validator),
	)

	ctx := context.Background()
	stream := &mockOIDCServerStream{ctx: ctx}

	handler := func(srv interface{}, ss grpc.ServerStream) error {
		return nil
	}

	info := &grpc.StreamServerInfo{FullMethod: "/test.Service/StreamMethod"}
	err := interceptor(nil, stream, info, handler)

	if err == nil {
		t.Fatal("expected error for missing token")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T", err)
	}

	if st.Code() != codes.Unauthenticated {
		t.Errorf("error code = %v, want %v", st.Code(), codes.Unauthenticated)
	}
}

func TestOIDCStreamInterceptor_ValidationFails(t *testing.T) {
	validator := &mockTokenValidator{valid: false, err: errors.New("token revoked")}
	interceptor := OIDCStreamInterceptor(
		WithTokenValidator(validator),
	)

	md := metadata.Pairs("authorization", "Bearer test-token")
	ctx := metadata.NewIncomingContext(context.Background(), md)
	stream := &mockOIDCServerStream{ctx: ctx}

	handler := func(srv interface{}, ss grpc.ServerStream) error {
		return nil
	}

	info := &grpc.StreamServerInfo{FullMethod: "/test.Service/StreamMethod"}
	err := interceptor(nil, stream, info, handler)

	if err == nil {
		t.Fatal("expected error for failed validation")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T", err)
	}

	if st.Code() != codes.Unauthenticated {
		t.Errorf("error code = %v, want %v", st.Code(), codes.Unauthenticated)
	}
}

func TestOIDCStreamInterceptor_InvalidToken(t *testing.T) {
	validator := &mockTokenValidator{valid: false, err: nil}
	interceptor := OIDCStreamInterceptor(
		WithTokenValidator(validator),
	)

	md := metadata.Pairs("authorization", "Bearer invalid-token")
	ctx := metadata.NewIncomingContext(context.Background(), md)
	stream := &mockOIDCServerStream{ctx: ctx}

	handler := func(srv interface{}, ss grpc.ServerStream) error {
		return nil
	}

	info := &grpc.StreamServerInfo{FullMethod: "/test.Service/StreamMethod"}
	err := interceptor(nil, stream, info, handler)

	if err == nil {
		t.Fatal("expected error for invalid token")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T", err)
	}

	if st.Code() != codes.Unauthenticated {
		t.Errorf("error code = %v, want %v", st.Code(), codes.Unauthenticated)
	}
}

func TestOIDCStreamInterceptor_ValidToken(t *testing.T) {
	validator := &mockTokenValidator{valid: true}
	interceptor := OIDCStreamInterceptor(
		WithTokenValidator(validator),
	)

	md := metadata.Pairs("authorization", "Bearer valid-stream-token")
	ctx := metadata.NewIncomingContext(context.Background(), md)
	stream := &mockOIDCServerStream{ctx: ctx}

	var capturedStream grpc.ServerStream
	handler := func(srv interface{}, ss grpc.ServerStream) error {
		capturedStream = ss
		return nil
	}

	info := &grpc.StreamServerInfo{FullMethod: "/test.Service/StreamMethod"}
	err := interceptor(nil, stream, info, handler)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify token was added to stream context
	token, ok := TokenFromContext(capturedStream.Context())
	if !ok {
		t.Error("expected token in stream context after successful validation")
	}

	if token != "valid-stream-token" {
		t.Errorf("token in context = %q, want %q", token, "valid-stream-token")
	}
}

// =============================================================================
// Wrapped Server Stream Tests
// =============================================================================

func TestWrappedServerStream_Context_OIDC(t *testing.T) {
	originalCtx := context.Background()
	newCtx := context.WithValue(context.Background(), contextKey("key"), "value")

	wrapped := &wrappedServerStream{
		ServerStream: &mockOIDCServerStream{ctx: originalCtx},
		ctx:          newCtx,
	}

	if got := wrapped.Context(); got != newCtx {
		t.Error("Context() should return the wrapped context, not the original")
	}
}

// =============================================================================
// Multiple Skip Methods Tests
// =============================================================================

func TestOIDCUnaryInterceptor_MultipleSkipMethods(t *testing.T) {
	skipMethods := []string{
		"/health.Service/Check",
		"/grpc.health.v1.Health/Check",
		"/reflection.ServerReflection/ServerReflectionInfo",
	}

	interceptor := OIDCUnaryInterceptor(
		WithSkipMethods(skipMethods...),
	)

	ctx := context.Background()

	for _, method := range skipMethods {
		t.Run(method, func(t *testing.T) {
			handlerCalled := false
			handler := func(ctx context.Context, req interface{}) (interface{}, error) {
				handlerCalled = true
				return "response", nil
			}

			info := &grpc.UnaryServerInfo{FullMethod: method}
			_, err := interceptor(ctx, "request", info, handler)

			if err != nil {
				t.Fatalf("unexpected error for skip method %s: %v", method, err)
			}

			if !handlerCalled {
				t.Errorf("handler was not called for skip method %s", method)
			}
		})
	}
}

// =============================================================================
// Default Configuration Tests
// =============================================================================

func TestOIDCUnaryInterceptor_DefaultRequireAuth(t *testing.T) {
	// Default should require auth
	interceptor := OIDCUnaryInterceptor()

	ctx := context.Background()

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "response", nil
	}

	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}
	_, err := interceptor(ctx, "request", info, handler)

	if err == nil {
		t.Fatal("expected error when no validator configured with default RequireAuth=true")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T", err)
	}

	if st.Code() != codes.Unavailable {
		t.Errorf("error code = %v, want %v", st.Code(), codes.Unavailable)
	}
}

func TestOIDCStreamInterceptor_DefaultRequireAuth(t *testing.T) {
	// Default should require auth
	interceptor := OIDCStreamInterceptor()

	ctx := context.Background()
	stream := &mockOIDCServerStream{ctx: ctx}

	handler := func(srv interface{}, ss grpc.ServerStream) error {
		return nil
	}

	info := &grpc.StreamServerInfo{FullMethod: "/test.Service/StreamMethod"}
	err := interceptor(nil, stream, info, handler)

	if err == nil {
		t.Fatal("expected error when no validator configured with default RequireAuth=true")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T", err)
	}

	if st.Code() != codes.Unavailable {
		t.Errorf("error code = %v, want %v", st.Code(), codes.Unavailable)
	}
}
