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

package iam

import (
	"context"
	"crypto/x509"
	"net/http"
	"strings"
	"time"

	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// AuthMiddleware combines mTLS and JWT authentication to create IAM sessions.
type AuthMiddleware struct {
	logger              *logging.Logger
	responseWriter      response.HttpWriter
	config              AuthConfig
	iamService          IAMServiceClient
	jwtMiddleware       *JWTMiddleware
	trustedRoots        *x509.CertPool
	attestationVerifier AttestationVerifier
}

// AuthMiddlewareOption is a functional option for configuring AuthMiddleware.
type AuthMiddlewareOption func(*AuthMiddleware)

// NewAuthMiddleware creates a new authentication middleware instance.
func NewAuthMiddleware(
	logger *logging.Logger,
	responseWriter response.HttpWriter,
	config AuthConfig,
	iamService IAMServiceClient,
	jwtMiddleware *JWTMiddleware,
	trustedRoots *x509.CertPool,
	attestationVerifier AttestationVerifier,
	opts ...AuthMiddlewareOption,
) (*AuthMiddleware, error) {

	if logger == nil {
		return nil, ErrInvalidConfig{Field: "logger", Reason: "logger is required"}
	}
	if responseWriter == nil {
		return nil, ErrInvalidConfig{Field: "responseWriter", Reason: "response writer is required"}
	}
	if iamService == nil {
		return nil, ErrInvalidConfig{Field: "iamService", Reason: "IAM service client is required"}
	}

	m := &AuthMiddleware{
		logger:              logger,
		responseWriter:      responseWriter,
		config:              config,
		iamService:          iamService,
		jwtMiddleware:       jwtMiddleware,
		trustedRoots:        trustedRoots,
		attestationVerifier: attestationVerifier,
	}

	for _, opt := range opts {
		opt(m)
	}

	return m, nil
}

// Handler returns an http.Handler middleware for authentication.
func (m *AuthMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.Authenticate(w, r, next.ServeHTTP)
	})
}

// Authenticate performs authentication via mTLS certificate or JWT token.
func (m *AuthMiddleware) Authenticate(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	// Check TLS requirement
	if m.config.RequireTLS && r.TLS == nil {
		m.logger.Debugf("auth: TLS required but not present")
		m.responseWriter.Error401(w, r, ErrTLSRequired{})
		return
	}

	// Try mTLS authentication first
	session, err := m.authenticateWithMTLS(r)
	if err == nil && session != nil {
		ctx := SetSessionInContext(r.Context(), session)
		next(w, r.WithContext(ctx))
		return
	}

	// If mTLS is required and failed, return error
	if m.config.RequireMTLS && session == nil {
		m.logger.Debugf("auth: mTLS required but authentication failed: %v", err)
		m.responseWriter.Error401(w, r, ErrMTLSRequired{})
		return
	}

	// Try JWT authentication
	session, err = m.authenticateWithJWT(r)
	if err == nil && session != nil {
		ctx := SetSessionInContext(r.Context(), session)
		next(w, r.WithContext(ctx))
		return
	}

	// If JWT is required and failed, return error
	if m.config.RequireJWT {
		m.logger.Debugf("auth: JWT required but authentication failed: %v", err)
		m.responseWriter.Error401(w, r, err)
		return
	}

	// No valid authentication method succeeded - authentication is always required
	m.logger.Debugf("auth: all authentication methods failed")
	m.responseWriter.Error401(w, r, ErrUnauthorized{Reason: "authentication required"})
}

// authenticateWithMTLS attempts to authenticate using a client certificate.
func (m *AuthMiddleware) authenticateWithMTLS(r *http.Request) (IAMSession, error) {
	if r.TLS == nil {
		return nil, ErrTLSRequired{}
	}

	if len(r.TLS.PeerCertificates) == 0 {
		return nil, ErrMTLSRequired{}
	}

	clientCert := r.TLS.PeerCertificates[0]

	// Verify certificate chain if trusted roots are configured
	if m.trustedRoots != nil {
		opts := x509.VerifyOptions{
			Roots:         m.trustedRoots,
			Intermediates: x509.NewCertPool(),
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}

		// Add intermediate certificates
		for _, cert := range r.TLS.PeerCertificates[1:] {
			opts.Intermediates.AddCert(cert)
		}

		if _, err := clientCert.Verify(opts); err != nil {
			m.logger.Debugf("auth: certificate verification failed: %v", err)
			return nil, ErrCertificateInvalid{Reason: err.Error()}
		}
	}

	// Verify TPM attestation if required
	var attestationVerified bool
	var attestationTime time.Time
	var deviceID string

	if m.attestationVerifier != nil && m.config.RequireTPMAttestation {
		// Check if this is an IDevID certificate
		if m.attestationVerifier.IsIDevIDCertificate(clientCert) {
			if m.config.ValidateIDevID {
				if err := m.attestationVerifier.VerifyIDevID(r.Context(), clientCert); err != nil {
					m.logger.Debugf("auth: IDevID verification failed: %v", err)
					return nil, err
				}
			}
			attestationVerified = true
			attestationTime = time.Now()
			// Extract device ID from certificate CN or serial
			deviceID = clientCert.Subject.CommonName
			if deviceID == "" && clientCert.Subject.SerialNumber != "" {
				deviceID = clientCert.Subject.SerialNumber
			}
		} else if m.config.RequireTPMAttestation {
			// TPM attestation required but certificate is not IDevID
			return nil, ErrCertificateInvalid{Reason: "TPM attestation required but certificate is not IDevID"}
		}
	}

	// Extract tenant ID from certificate
	tenantID := m.extractTenantFromCert(clientCert)
	if tenantID == "" && m.config.DefaultTenantID != "" {
		tenantID = m.config.DefaultTenantID
	}
	if tenantID == "" {
		return nil, ErrMissingTenantID{}
	}

	// Extract identity from certificate (email or CN)
	identity := m.extractIdentityFromCert(clientCert)
	if identity == "" {
		return nil, ErrCertificateInvalid{Reason: "no identity in certificate"}
	}

	// Look up user in IAM service
	user, err := m.lookupUserByEmail(r.Context(), tenantID, identity)
	if err != nil {
		m.logger.Debugf("auth: failed to look up user %s: %v", identity, err)
		return nil, err
	}

	return NewIAMSessionWithAttestation(user, false, time.Time{}, attestationVerified, attestationTime, deviceID), nil
}

// authenticateWithJWT attempts to authenticate using a JWT token.
func (m *AuthMiddleware) authenticateWithJWT(r *http.Request) (IAMSession, error) {
	if m.jwtMiddleware == nil {
		return nil, ErrTokenInvalid{Reason: "JWT authentication not configured"}
	}

	// Extract and validate token
	tokenString, err := m.jwtMiddleware.extractToken(r)
	if err != nil {
		return nil, err
	}

	claims, err := m.jwtMiddleware.validateToken(tokenString)
	if err != nil {
		return nil, err
	}

	// Get tenant ID from claims or header
	tenantID := claims.TenantID
	if tenantID == "" {
		tenantID = r.Header.Get(TenantIDHeader)
	}
	if tenantID == "" && m.config.DefaultTenantID != "" {
		tenantID = m.config.DefaultTenantID
	}
	if tenantID == "" {
		return nil, ErrMissingTenantID{}
	}

	// Look up user in IAM service to get current user data
	user, err := m.lookupUserByID(r.Context(), tenantID, claims.Subject)
	if err != nil {
		// If user lookup fails, create session from claims
		m.logger.Debugf("auth: user lookup failed, using claims: %v", err)
		return m.createSessionFromClaims(claims, tenantID), nil
	}

	// Create session with MFA status from token
	return NewIAMSessionWithMFA(user, claims.MFAVerified, claims.MFATimestamp), nil
}

// extractTenantFromCert extracts the tenant ID from a certificate based on configuration.
func (m *AuthMiddleware) extractTenantFromCert(cert *x509.Certificate) string {
	if !m.config.ExtractTenantFromCert {
		return ""
	}

	switch m.config.TenantCertField {
	case "cn":
		return cert.Subject.CommonName
	case "ou":
		if len(cert.Subject.OrganizationalUnit) > 0 {
			return cert.Subject.OrganizationalUnit[0]
		}
	case "o":
		if len(cert.Subject.Organization) > 0 {
			return cert.Subject.Organization[0]
		}
	case "san_email":
		if len(cert.EmailAddresses) > 0 {
			// Extract domain from email as tenant ID
			email := cert.EmailAddresses[0]
			parts := strings.Split(email, "@")
			if len(parts) == 2 {
				return parts[1]
			}
		}
	case "san_dns":
		if len(cert.DNSNames) > 0 {
			return cert.DNSNames[0]
		}
	}

	return ""
}

// extractIdentityFromCert extracts the user identity from a certificate.
func (m *AuthMiddleware) extractIdentityFromCert(cert *x509.Certificate) string {
	// Prefer email addresses
	if len(cert.EmailAddresses) > 0 {
		return cert.EmailAddresses[0]
	}

	// Fall back to Common Name
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}

	// Check serial number
	if cert.Subject.SerialNumber != "" {
		return cert.Subject.SerialNumber
	}

	return ""
}

// lookupUserByEmail looks up a user by email in the IAM service.
func (m *AuthMiddleware) lookupUserByEmail(ctx context.Context, tenantID, email string) (*iamsdk.User, error) {
	users, err := m.iamService.ListUsersByEmail(ctx, tenantID, email)
	if err != nil {
		return nil, ErrServiceUnavailable{Service: "IAM", Reason: err.Error()}
	}

	if len(users) == 0 {
		return nil, ErrUserNotFound{Identifier: email}
	}

	return &users[0], nil
}

// lookupUserByID looks up a user by ID in the IAM service.
func (m *AuthMiddleware) lookupUserByID(ctx context.Context, tenantID, userID string) (*iamsdk.User, error) {
	user, err := m.iamService.GetUser(ctx, tenantID, userID)
	if err != nil {
		return nil, ErrServiceUnavailable{Service: "IAM", Reason: err.Error()}
	}

	if user == nil {
		return nil, ErrUserNotFound{Identifier: userID}
	}

	return user, nil
}

// createSessionFromClaims creates an IAM session from JWT claims when user lookup fails.
func (m *AuthMiddleware) createSessionFromClaims(claims *JWTClaims, tenantID string) IAMSession {
	// Create a synthetic user from claims
	user := &iamsdk.User{
		ID:          claims.Subject,
		TenantID:    tenantID,
		Email:       claims.Email,
		DisplayName: claims.Name,
		Roles:       claims.Roles,
		Groups:      claims.Groups,
		MFAEnabled:  claims.MFAVerified,
	}

	return NewIAMSessionWithMFA(user, claims.MFAVerified, claims.MFATimestamp)
}

// CreateSession creates a session from the current request context.
// This is useful for handlers that need to manually create sessions.
func (m *AuthMiddleware) CreateSession(w http.ResponseWriter, r *http.Request) (IAMSession, error) {
	// Try mTLS first
	session, err := m.authenticateWithMTLS(r)
	if err == nil && session != nil {
		return session, nil
	}

	// Try JWT
	session, err = m.authenticateWithJWT(r)
	if err == nil && session != nil {
		return session, nil
	}

	if err != nil {
		return nil, err
	}

	return nil, ErrUnauthorized{Reason: "no valid authentication method"}
}

// RequireRoles returns a middleware that requires specific roles.
func (m *AuthMiddleware) RequireRoles(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, ok := GetSessionFromContext(r.Context())
			if !ok {
				m.responseWriter.Error401(w, r, ErrUnauthorized{Reason: "session required"})
				return
			}

			if !session.HasAnyRole(roles...) {
				m.responseWriter.Error403(w, r, ErrForbidden{
					Reason: "required role not present",
				}, nil)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAllRoles returns a middleware that requires all specified roles.
func (m *AuthMiddleware) RequireAllRoles(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, ok := GetSessionFromContext(r.Context())
			if !ok {
				m.responseWriter.Error401(w, r, ErrUnauthorized{Reason: "session required"})
				return
			}

			if !session.HasAllRoles(roles...) {
				m.responseWriter.Error403(w, r, ErrForbidden{
					Reason: "all required roles not present",
				}, nil)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireGroups returns a middleware that requires membership in specific groups.
func (m *AuthMiddleware) RequireGroups(groups ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, ok := GetSessionFromContext(r.Context())
			if !ok {
				m.responseWriter.Error401(w, r, ErrUnauthorized{Reason: "session required"})
				return
			}

			hasGroup := false
			for _, group := range groups {
				if session.HasGroup(group) {
					hasGroup = true
					break
				}
			}

			if !hasGroup {
				m.responseWriter.Error403(w, r, ErrForbidden{
					Reason: "required group membership not present",
				}, nil)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireMFA returns a middleware that requires MFA verification.
func (m *AuthMiddleware) RequireMFA() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, ok := GetSessionFromContext(r.Context())
			if !ok {
				m.responseWriter.Error401(w, r, ErrUnauthorized{Reason: "session required"})
				return
			}

			if !session.IsMFAVerified() {
				m.responseWriter.Error401(w, r, ErrMFARequired{})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireTPMAttestation returns a middleware that requires verified TPM attestation.
func (m *AuthMiddleware) RequireTPMAttestation() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, ok := GetSessionFromContext(r.Context())
			if !ok {
				m.responseWriter.Error401(w, r, ErrUnauthorized{Reason: "session required"})
				return
			}

			if !session.IsAttestationVerified() {
				m.responseWriter.Error403(w, r, ErrForbidden{
					Reason: "TPM attestation verification required",
				}, nil)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
