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

package daemon

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	sdkiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	quicbaaserrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	grpccreds "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/auth"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// contextKey is a private type for context keys to avoid collisions.
type contextKey string

const (
	// ContextKeyIdentity is the context key for the authenticated mTLS identity.
	ContextKeyIdentity contextKey = "mtls-identity"
)

// MTLSInterceptorConfig holds configuration for the mTLS interceptor.
type MTLSInterceptorConfig struct {
	// Authenticator performs certificate validation and identity extraction.
	Authenticator auth.Authenticator

	// Logger for interceptor operations.
	Logger *logging.Logger

	// SkipMethods lists gRPC method names that bypass mTLS authentication
	// and the permission check. Health check endpoints are typically skipped.
	SkipMethods []string

	// PEP is the IAM policy enforcement point that decides every other call
	// for the certificate's IAM user, with that user's role assignments, and
	// the method's catalog permission (grpc.ScopeForMethod). A nil PEP fails
	// each such call closed with codes.Unavailable (#1989).
	PEP quicbaassdk.IAMPEPClient

	// Users resolves the IAM user a certificate names (email SAN first, else
	// the identity ID as the tenant-scoped username) and its role IDs, which
	// the PEP check carries. A nil Users fails each checked call closed with
	// codes.Unavailable; an unknown user is codes.PermissionDenied (#1989).
	Users mtlsUserLookup
}

// mtlsUserLookup is the part of the SDK IAM UserClient the mTLS interceptor
// needs to resolve a certificate's IAM user; sdkiam.UserClient satisfies it.
type mtlsUserLookup interface {
	GetByEmail(ctx context.Context, tenantID, email string) (*sdkiam.User, error)
	FindByUsername(ctx context.Context, tenantID, username string) (*sdkiam.User, error)
}

// ErrMTLSNoPeerInfo indicates no peer info was found in the gRPC context.
type ErrMTLSNoPeerInfo struct{}

func (e ErrMTLSNoPeerInfo) Error() string {
	return "mtls: no peer info in context"
}

// ErrMTLSNoTLSInfo indicates TLS info was not available in peer state.
type ErrMTLSNoTLSInfo struct{}

func (e ErrMTLSNoTLSInfo) Error() string {
	return "mtls: no TLS info in peer state"
}

// ErrMTLSNoCertificates indicates no client certificates were presented.
type ErrMTLSNoCertificates struct{}

func (e ErrMTLSNoCertificates) Error() string {
	return "mtls: no client certificates presented"
}

// MTLSUnaryInterceptor returns a gRPC unary server interceptor that validates
// client certificates via mTLS, attaches the extracted identity to the context
// and lets the call through only when cfg.PEP allows the certificate principal
// the method's catalog permission (see authorizeMTLSCall).
func MTLSUnaryInterceptor(cfg *MTLSInterceptorConfig) grpc.UnaryServerInterceptor {
	skipMap := buildSkipMap(cfg.SkipMethods)

	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Skip authentication for exempt methods
		if _, ok := skipMap[info.FullMethod]; ok {
			return handler(ctx, req)
		}

		// Extract and validate client certificate
		enrichedCtx, err := authenticateFromPeer(ctx, cfg)
		if err != nil {
			return nil, err
		}
		if err := authorizeMTLSCall(enrichedCtx, cfg, info.FullMethod); err != nil {
			return nil, err
		}

		return handler(enrichedCtx, req)
	}
}

// MTLSStreamInterceptor returns a gRPC stream server interceptor that validates
// client certificates via mTLS, attaches the extracted identity to the context
// and lets the stream through only when cfg.PEP allows the certificate
// principal the method's catalog permission (see authorizeMTLSCall).
func MTLSStreamInterceptor(cfg *MTLSInterceptorConfig) grpc.StreamServerInterceptor {
	skipMap := buildSkipMap(cfg.SkipMethods)

	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		// Skip authentication for exempt methods
		if _, ok := skipMap[info.FullMethod]; ok {
			return handler(srv, ss)
		}

		// Extract and validate client certificate
		enrichedCtx, err := authenticateFromPeer(ss.Context(), cfg)
		if err != nil {
			return err
		}
		if err := authorizeMTLSCall(enrichedCtx, cfg, info.FullMethod); err != nil {
			return err
		}

		// Wrap the stream with the enriched context
		wrappedStream := &mtlsServerStream{
			ServerStream: ss,
			ctx:          enrichedCtx,
		}

		return handler(srv, wrappedStream)
	}
}

// authenticateFromPeer extracts the client certificate from the gRPC peer state,
// validates it using the Authenticator, and returns an enriched context with the identity.
func authenticateFromPeer(ctx context.Context, cfg *MTLSInterceptorConfig) (context.Context, error) {
	// Extract peer from context
	p, ok := peer.FromContext(ctx)
	if !ok {
		if cfg.Logger != nil {
			cfg.Logger.Debug("mtls: no peer info in context")
		}
		return nil, status.Error(codes.Unauthenticated, ErrMTLSNoPeerInfo{}.Error())
	}

	// Extract TLS info from peer
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		if cfg.Logger != nil {
			cfg.Logger.Debug("mtls: peer auth info is not TLS")
		}
		return nil, status.Error(codes.Unauthenticated, ErrMTLSNoTLSInfo{}.Error())
	}

	// Get verified client certificates
	certs := extractClientCerts(tlsInfo.State)
	if len(certs) == 0 {
		if cfg.Logger != nil {
			cfg.Logger.Debug("mtls: no client certificates in TLS state")
		}
		return nil, status.Error(codes.Unauthenticated, ErrMTLSNoCertificates{}.Error())
	}

	// Authenticate the leaf certificate
	identity, err := cfg.Authenticator.Authenticate(ctx, certs[0])
	if err != nil {
		if cfg.Logger != nil {
			cfg.Logger.Debug("mtls: authentication failed", "error", err)
		}
		return nil, status.Errorf(codes.Unauthenticated, "mtls: %v", err)
	}

	if cfg.Logger != nil {
		cfg.Logger.Debugf("mtls: authenticated %s (tenant: %s)", identity.ID, identity.TenantID)
	}

	// Attach identity to context
	return context.WithValue(ctx, ContextKeyIdentity, identity), nil
}

// authorizeMTLSCall decides an authenticated mTLS call with the IAM policy
// enforcement point. A certificate is no longer a grant for every method
// (#1989): the call needs the "resource:action" permission the gRPC method
// catalog names for it, checked for the certificate's IAM user and that
// user's role assignments (resolveMTLSPrincipal). A method absent from the
// catalog, a malformed permission, a certificate that names no IAM user or a
// denial is codes.PermissionDenied; a nil PEP or Users, a user lookup that
// fails or a check that fails is codes.Unavailable, so a PEP or directory
// that cannot answer never lets a call through.
func authorizeMTLSCall(ctx context.Context, cfg *MTLSInterceptorConfig, fullMethod string) error {
	// Pre-auth methods are served without a token on the token path; the
	// certificate has already been authenticated, so they skip the PEP here too.
	if grpccreds.IsPreAuthMethod(fullMethod) {
		return nil
	}
	resource, action, ok := strings.Cut(grpccreds.ScopeForMethod(fullMethod), ":")
	if !ok || strings.TrimSpace(resource) == "" || strings.TrimSpace(action) == "" {
		return status.Error(codes.PermissionDenied, grpccreds.ErrMethodNotClassified{Method: fullMethod}.Error())
	}
	identity := IdentityFromContext(ctx)
	if identity == nil {
		return status.Error(codes.Unauthenticated, ErrMTLSNoCertificates{}.Error())
	}
	principal, err := resolveMTLSPrincipal(ctx, cfg.Users, identity)
	if err != nil {
		if cfg.Logger != nil {
			cfg.Logger.Debug("mtls: certificate user not resolved", "method", fullMethod, "error", err)
		}
		var notFound ErrMTLSUserNotFound
		if errors.As(err, &notFound) {
			return status.Error(codes.PermissionDenied, err.Error())
		}
		return status.Errorf(codes.Unavailable, "mtls: %v", err)
	}
	allowed, err := checkPrincipalPermission(ctx, cfg.PEP, principal, resource, action)
	if err != nil {
		if cfg.Logger != nil {
			cfg.Logger.Debug("mtls: permission check failed", "method", fullMethod, "error", err)
		}
		return status.Errorf(codes.Unavailable, "mtls: %v", err)
	}
	if !allowed {
		return status.Errorf(codes.PermissionDenied, "mtls: %s may not %s %s", identity.ID, action, resource)
	}
	return nil
}

// resolveMTLSPrincipal looks up the IAM user a verified certificate names:
// by its email SAN when it has one, else (or when no user has that email) by
// the identity ID as the tenant-scoped username. The principal carries the
// user's ID and role IDs so the PEP decides on the user's role assignments.
// No user under either key, or a user of another tenant, is
// ErrMTLSUserNotFound; a nil users or any other lookup error is returned as
// is, for the caller to fail the call closed.
func resolveMTLSPrincipal(ctx context.Context, users mtlsUserLookup, identity *auth.Identity) (*tokenPrincipal, error) {
	if users == nil {
		return nil, fmt.Errorf("no IAM user lookup is configured to resolve the certificate user")
	}
	notFound := ErrMTLSUserNotFound{Subject: identity.ID, TenantID: identity.TenantID}
	var user *sdkiam.User
	if identity.Email != "" {
		u, err := users.GetByEmail(ctx, identity.TenantID, identity.Email)
		switch {
		case err == nil:
			user = u
		case !quicbaaserrors.IsNotFound(err):
			return nil, fmt.Errorf("look up the certificate user by email: %w", err)
		}
	}
	if user == nil {
		u, err := users.FindByUsername(ctx, identity.TenantID, identity.ID)
		switch {
		case err == nil:
			user = u
		case quicbaaserrors.IsNotFound(err):
			return nil, notFound
		default:
			return nil, fmt.Errorf("look up the certificate user by username: %w", err)
		}
	}
	if user == nil || user.ID == "" || user.TenantID != identity.TenantID {
		return nil, notFound
	}
	return &tokenPrincipal{Subject: user.ID, TenantID: identity.TenantID, Roles: user.Roles}, nil
}

// extractClientCerts returns client certificates from TLS connection state.
// It first checks VerifiedChains (populated when ClientAuth includes verification),
// then falls back to PeerCertificates.
func extractClientCerts(state tls.ConnectionState) []*x509.Certificate {
	// Prefer verified chains (set when RequireAndVerifyClientCert is used)
	if len(state.VerifiedChains) > 0 && len(state.VerifiedChains[0]) > 0 {
		return state.VerifiedChains[0]
	}
	// Fall back to peer certificates
	return state.PeerCertificates
}

// IdentityFromContext extracts the mTLS identity from the context.
// Returns nil if no identity is present.
func IdentityFromContext(ctx context.Context) *auth.Identity {
	val := ctx.Value(ContextKeyIdentity)
	if val == nil {
		return nil
	}
	identity, ok := val.(*auth.Identity)
	if !ok {
		return nil
	}
	return identity
}

// buildSkipMap converts a slice of method names to a map for O(1) lookup.
func buildSkipMap(methods []string) map[string]struct{} {
	m := make(map[string]struct{}, len(methods))
	for _, method := range methods {
		m[method] = struct{}{}
	}
	return m
}

// mtlsServerStream wraps grpc.ServerStream to override Context() with the
// enriched context containing the mTLS identity.
type mtlsServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context returns the enriched context with the mTLS identity.
func (s *mtlsServerStream) Context() context.Context {
	return s.ctx
}
