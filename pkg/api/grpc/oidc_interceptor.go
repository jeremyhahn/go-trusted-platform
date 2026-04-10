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
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// =============================================================================
// Error Types
// =============================================================================

// ErrTokenValidatorNotConfigured is returned when no token validator is available.
type ErrTokenValidatorNotConfigured struct{}

func (e ErrTokenValidatorNotConfigured) Error() string {
	return "OIDC token validator not configured"
}

// ErrMissingAuthorizationHeader is returned when no Authorization header is present.
type ErrMissingAuthorizationHeader struct{}

func (e ErrMissingAuthorizationHeader) Error() string {
	return "missing authorization header"
}

// ErrInvalidAuthorizationHeader is returned when the Authorization header format is invalid.
type ErrInvalidAuthorizationHeader struct{}

func (e ErrInvalidAuthorizationHeader) Error() string {
	return "invalid authorization header format"
}

// ErrTokenValidationFailed is returned when token validation fails.
type ErrTokenValidationFailed struct {
	Cause error
}

func (e ErrTokenValidationFailed) Error() string {
	if e.Cause != nil {
		return "token validation failed: " + e.Cause.Error()
	}
	return "token validation failed"
}

func (e ErrTokenValidationFailed) Unwrap() error {
	return e.Cause
}

// =============================================================================
// Token Validator Interface
// =============================================================================

// TokenValidator validates authentication tokens.
// This interface allows for different token validation implementations
// (e.g., QuicBaaS OIDC provider, local JWT validation, etc.).
type TokenValidator interface {
	// ValidateToken validates a token and returns whether it's valid.
	ValidateToken(ctx context.Context, token string) (bool, error)
}

// AuthorizationChecker checks if an authenticated user has permission for an action.
type AuthorizationChecker interface {
	// CheckPermission checks if the subject has permission for the given resource and action.
	CheckPermission(ctx context.Context, subject, resource, action string) (bool, error)
}

// =============================================================================
// Token Context Key
// =============================================================================

// tokenContextKey is the context key for the validated token.
type tokenContextKey struct{}

// ContextWithToken adds a validated token to the context.
func ContextWithToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, tokenContextKey{}, token)
}

// TokenFromContext extracts the validated token from the context.
func TokenFromContext(ctx context.Context) (string, bool) {
	token, ok := ctx.Value(tokenContextKey{}).(string)
	return token, ok
}

// =============================================================================
// OIDC Interceptor Configuration
// =============================================================================

// OIDCInterceptorConfig configures the OIDC interceptor behavior.
type OIDCInterceptorConfig struct {
	// TokenValidator validates authentication tokens.
	TokenValidator TokenValidator

	// SkipMethods is a list of method names that don't require authentication.
	// Method names should be in the format "/package.Service/Method".
	SkipMethods []string

	// RequireAuth determines behavior when no token validator is configured.
	// If true, unauthenticated requests fail. If false, they're allowed through.
	RequireAuth bool
}

// OIDCInterceptorOption configures the OIDC interceptor.
type OIDCInterceptorOption func(*OIDCInterceptorConfig)

// WithTokenValidator sets the token validator.
func WithTokenValidator(v TokenValidator) OIDCInterceptorOption {
	return func(c *OIDCInterceptorConfig) {
		c.TokenValidator = v
	}
}

// WithSkipMethods sets methods that don't require authentication.
func WithSkipMethods(methods ...string) OIDCInterceptorOption {
	return func(c *OIDCInterceptorConfig) {
		c.SkipMethods = methods
	}
}

// WithRequireAuth sets whether authentication is required.
func WithRequireAuth(require bool) OIDCInterceptorOption {
	return func(c *OIDCInterceptorConfig) {
		c.RequireAuth = require
	}
}

// =============================================================================
// OIDC Unary Interceptor
// =============================================================================

// OIDCUnaryInterceptor creates a unary server interceptor that validates
// OIDC/JWT tokens from the Authorization header.
//
// Usage:
//
//	server := grpc.NewServer(
//	    grpc.UnaryInterceptor(grpc.OIDCUnaryInterceptor(
//	        grpc.WithTokenValidator(myValidator),
//	        grpc.WithSkipMethods("/health.HealthService/Check"),
//	    )),
//	)
func OIDCUnaryInterceptor(opts ...OIDCInterceptorOption) grpc.UnaryServerInterceptor {
	config := &OIDCInterceptorConfig{
		RequireAuth: true, // Default to requiring auth
	}
	for _, opt := range opts {
		opt(config)
	}

	skipMethodsMap := make(map[string]bool)
	for _, m := range config.SkipMethods {
		skipMethodsMap[m] = true
	}

	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Check if this method should skip authentication
		if skipMethodsMap[info.FullMethod] {
			return handler(ctx, req)
		}

		// If no validator configured, handle based on RequireAuth setting
		if config.TokenValidator == nil {
			if config.RequireAuth {
				return nil, status.Error(codes.Unavailable, ErrTokenValidatorNotConfigured{}.Error())
			}
			return handler(ctx, req)
		}

		// Extract token from metadata
		token, err := extractBearerToken(ctx)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}

		// Validate the token
		valid, err := config.TokenValidator.ValidateToken(ctx, token)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, ErrTokenValidationFailed{Cause: err}.Error())
		}
		if !valid {
			return nil, status.Error(codes.Unauthenticated, "invalid token")
		}

		// Add validated token to context and continue
		ctx = ContextWithToken(ctx, token)
		return handler(ctx, req)
	}
}

// =============================================================================
// OIDC Stream Interceptor
// =============================================================================

// OIDCStreamInterceptor creates a stream server interceptor that validates
// OIDC/JWT tokens from the Authorization header.
//
// Usage:
//
//	server := grpc.NewServer(
//	    grpc.StreamInterceptor(grpc.OIDCStreamInterceptor(
//	        grpc.WithTokenValidator(myValidator),
//	    )),
//	)
func OIDCStreamInterceptor(opts ...OIDCInterceptorOption) grpc.StreamServerInterceptor {
	config := &OIDCInterceptorConfig{
		RequireAuth: true,
	}
	for _, opt := range opts {
		opt(config)
	}

	skipMethodsMap := make(map[string]bool)
	for _, m := range config.SkipMethods {
		skipMethodsMap[m] = true
	}

	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		ctx := ss.Context()

		// Check if this method should skip authentication
		if skipMethodsMap[info.FullMethod] {
			return handler(srv, ss)
		}

		// If no validator configured, handle based on RequireAuth setting
		if config.TokenValidator == nil {
			if config.RequireAuth {
				return status.Error(codes.Unavailable, ErrTokenValidatorNotConfigured{}.Error())
			}
			return handler(srv, ss)
		}

		// Extract token from metadata
		token, err := extractBearerToken(ctx)
		if err != nil {
			return status.Error(codes.Unauthenticated, err.Error())
		}

		// Validate the token
		valid, err := config.TokenValidator.ValidateToken(ctx, token)
		if err != nil {
			return status.Error(codes.Unauthenticated, ErrTokenValidationFailed{Cause: err}.Error())
		}
		if !valid {
			return status.Error(codes.Unauthenticated, "invalid token")
		}

		// Wrap stream with token in context
		// Note: wrappedServerStream is defined in unix_credentials.go
		wrapped := &wrappedServerStream{
			ServerStream: ss,
			ctx:          ContextWithToken(ctx, token),
		}
		return handler(srv, wrapped)
	}
}

// =============================================================================
// Helper Functions
// =============================================================================

// extractBearerToken extracts the Bearer token from the Authorization metadata.
func extractBearerToken(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", ErrMissingAuthorizationHeader{}
	}

	authHeaders := md.Get("authorization")
	if len(authHeaders) == 0 {
		return "", ErrMissingAuthorizationHeader{}
	}

	authHeader := authHeaders[0]
	if !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		return "", ErrInvalidAuthorizationHeader{}
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	token = strings.TrimPrefix(token, "bearer ")
	token = strings.TrimSpace(token)

	if token == "" {
		return "", ErrInvalidAuthorizationHeader{}
	}

	return token, nil
}

// AddBearerToken adds a Bearer token to outgoing context metadata.
// Use this on the client side to add authentication.
func AddBearerToken(ctx context.Context, token string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
}
