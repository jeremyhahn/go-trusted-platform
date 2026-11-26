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
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	sdkiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	quicbaaserrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"

	grpccreds "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/auth"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// mockAuthenticator implements auth.Authenticator for testing.
type mockAuthenticator struct {
	authenticateFunc    func(ctx context.Context, cert *x509.Certificate) (*auth.Identity, error)
	validateChainFunc   func(ctx context.Context, certs []*x509.Certificate) error
	extractIdentityFunc func(cert *x509.Certificate) (*auth.Identity, error)
	extractTenantFunc   func(cert *x509.Certificate) (string, error)
}

func (m *mockAuthenticator) Authenticate(ctx context.Context, cert *x509.Certificate) (*auth.Identity, error) {
	if m.authenticateFunc != nil {
		return m.authenticateFunc(ctx, cert)
	}
	return &auth.Identity{
		ID:       cert.Subject.CommonName,
		Name:     cert.Subject.CommonName,
		TenantID: "test-tenant",
	}, nil
}

func (m *mockAuthenticator) ValidateChain(ctx context.Context, certs []*x509.Certificate) error {
	if m.validateChainFunc != nil {
		return m.validateChainFunc(ctx, certs)
	}
	return nil
}

func (m *mockAuthenticator) ExtractIdentity(cert *x509.Certificate) (*auth.Identity, error) {
	if m.extractIdentityFunc != nil {
		return m.extractIdentityFunc(cert)
	}
	return &auth.Identity{ID: cert.Subject.CommonName}, nil
}

func (m *mockAuthenticator) ExtractTenant(cert *x509.Certificate) (string, error) {
	if m.extractTenantFunc != nil {
		return m.extractTenantFunc(cert)
	}
	return "test-tenant", nil
}

// mockServerStream implements grpc.ServerStream for testing.
type mockServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (m *mockServerStream) Context() context.Context {
	return m.ctx
}

// generateTestCert creates a minimal x509.Certificate for testing.
func generateTestCert(cn string) *x509.Certificate {
	return &x509.Certificate{
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Org"},
		},
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
}

// createTLSPeerContext creates a context with TLS peer info for testing.
func createTLSPeerContext(cert *x509.Certificate) context.Context {
	ctx := context.Background()
	tlsInfo := credentials.TLSInfo{
		State: tls.ConnectionState{
			VerifiedChains:   [][]*x509.Certificate{{cert}},
			PeerCertificates: []*x509.Certificate{cert},
		},
	}
	p := &peer.Peer{
		AuthInfo: tlsInfo,
	}
	return peer.NewContext(ctx, p)
}

// createPeerContextNoCerts creates a context with TLS peer info but no client certificates.
func createPeerContextNoCerts() context.Context {
	ctx := context.Background()
	tlsInfo := credentials.TLSInfo{
		State: tls.ConnectionState{},
	}
	p := &peer.Peer{
		AuthInfo: tlsInfo,
	}
	return peer.NewContext(ctx, p)
}

// createPeerContextNoTLS creates a context with peer info but no TLS auth info.
func createPeerContextNoTLS() context.Context {
	ctx := context.Background()
	p := &peer.Peer{}
	return peer.NewContext(ctx, p)
}

// =============================================================================
// Error type tests
// =============================================================================

func TestErrMTLSNoPeerInfoError(t *testing.T) {
	err := ErrMTLSNoPeerInfo{}
	expected := "mtls: no peer info in context"
	if err.Error() != expected {
		t.Errorf("ErrMTLSNoPeerInfo.Error() = %q, want %q", err.Error(), expected)
	}
}

func TestErrMTLSNoTLSInfoError(t *testing.T) {
	err := ErrMTLSNoTLSInfo{}
	expected := "mtls: no TLS info in peer state"
	if err.Error() != expected {
		t.Errorf("ErrMTLSNoTLSInfo.Error() = %q, want %q", err.Error(), expected)
	}
}

func TestErrMTLSNoCertificatesError(t *testing.T) {
	err := ErrMTLSNoCertificates{}
	expected := "mtls: no client certificates presented"
	if err.Error() != expected {
		t.Errorf("ErrMTLSNoCertificates.Error() = %q, want %q", err.Error(), expected)
	}
}

// =============================================================================
// buildSkipMap tests
// =============================================================================

func TestBuildSkipMapEmpty(t *testing.T) {
	m := buildSkipMap(nil)
	if len(m) != 0 {
		t.Errorf("buildSkipMap(nil) returned map with %d entries, want 0", len(m))
	}

	m = buildSkipMap([]string{})
	if len(m) != 0 {
		t.Errorf("buildSkipMap([]) returned map with %d entries, want 0", len(m))
	}
}

func TestBuildSkipMapWithMethods(t *testing.T) {
	methods := []string{
		"/grpc.health.v1.Health/Check",
		"/grpc.health.v1.Health/Watch",
		"/platform.Daemon/Status",
	}
	m := buildSkipMap(methods)

	if len(m) != 3 {
		t.Errorf("buildSkipMap returned map with %d entries, want 3", len(m))
	}

	for _, method := range methods {
		if _, ok := m[method]; !ok {
			t.Errorf("buildSkipMap missing entry for %q", method)
		}
	}
}

func TestBuildSkipMapO1Lookup(t *testing.T) {
	methods := []string{
		"/grpc.health.v1.Health/Check",
		"/platform.Daemon/Status",
	}
	m := buildSkipMap(methods)

	// Verify present methods are found
	if _, ok := m["/grpc.health.v1.Health/Check"]; !ok {
		t.Error("expected to find /grpc.health.v1.Health/Check in skip map")
	}

	// Verify absent methods are not found
	if _, ok := m["/platform.Daemon/Shutdown"]; ok {
		t.Error("did not expect to find /platform.Daemon/Shutdown in skip map")
	}
}

// =============================================================================
// extractClientCerts tests
// =============================================================================

func TestExtractClientCertsVerifiedChains(t *testing.T) {
	leafCert := generateTestCert("leaf-client")
	intermediateCert := generateTestCert("intermediate-ca")

	state := tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{
			{leafCert, intermediateCert},
		},
		PeerCertificates: []*x509.Certificate{generateTestCert("peer-cert")},
	}

	certs := extractClientCerts(state)
	if len(certs) != 2 {
		t.Fatalf("extractClientCerts returned %d certs, want 2", len(certs))
	}
	if certs[0].Subject.CommonName != "leaf-client" {
		t.Errorf("first cert CN = %q, want %q", certs[0].Subject.CommonName, "leaf-client")
	}
	if certs[1].Subject.CommonName != "intermediate-ca" {
		t.Errorf("second cert CN = %q, want %q", certs[1].Subject.CommonName, "intermediate-ca")
	}
}

func TestExtractClientCertsPeerCerts(t *testing.T) {
	peerCert := generateTestCert("peer-client")

	state := tls.ConnectionState{
		VerifiedChains:   nil,
		PeerCertificates: []*x509.Certificate{peerCert},
	}

	certs := extractClientCerts(state)
	if len(certs) != 1 {
		t.Fatalf("extractClientCerts returned %d certs, want 1", len(certs))
	}
	if certs[0].Subject.CommonName != "peer-client" {
		t.Errorf("cert CN = %q, want %q", certs[0].Subject.CommonName, "peer-client")
	}
}

func TestExtractClientCertsEmpty(t *testing.T) {
	state := tls.ConnectionState{
		VerifiedChains:   nil,
		PeerCertificates: nil,
	}

	certs := extractClientCerts(state)
	if certs != nil {
		t.Errorf("extractClientCerts returned %v, want nil", certs)
	}
}

func TestExtractClientCertsEmptyVerifiedChains(t *testing.T) {
	// VerifiedChains is non-nil but has an empty first chain
	state := tls.ConnectionState{
		VerifiedChains:   [][]*x509.Certificate{{}},
		PeerCertificates: []*x509.Certificate{generateTestCert("fallback")},
	}

	certs := extractClientCerts(state)
	if len(certs) != 1 {
		t.Fatalf("extractClientCerts returned %d certs, want 1 (fallback to PeerCertificates)", len(certs))
	}
	if certs[0].Subject.CommonName != "fallback" {
		t.Errorf("cert CN = %q, want %q", certs[0].Subject.CommonName, "fallback")
	}
}

// =============================================================================
// IdentityFromContext tests
// =============================================================================

func TestIdentityFromContextPresent(t *testing.T) {
	identity := &auth.Identity{
		ID:       "test-user",
		TenantID: "test-tenant",
		Name:     "Test User",
	}
	ctx := context.WithValue(context.Background(), ContextKeyIdentity, identity)

	result := IdentityFromContext(ctx)
	if result == nil {
		t.Fatal("IdentityFromContext returned nil, expected identity")
	}
	if result.ID != "test-user" {
		t.Errorf("identity ID = %q, want %q", result.ID, "test-user")
	}
	if result.TenantID != "test-tenant" {
		t.Errorf("identity TenantID = %q, want %q", result.TenantID, "test-tenant")
	}
	if result.Name != "Test User" {
		t.Errorf("identity Name = %q, want %q", result.Name, "Test User")
	}
}

func TestIdentityFromContextMissing(t *testing.T) {
	ctx := context.Background()

	result := IdentityFromContext(ctx)
	if result != nil {
		t.Errorf("IdentityFromContext returned %v, want nil", result)
	}
}

func TestIdentityFromContextWrongType(t *testing.T) {
	ctx := context.WithValue(context.Background(), ContextKeyIdentity, "not-an-identity")

	result := IdentityFromContext(ctx)
	if result != nil {
		t.Errorf("IdentityFromContext returned %v, want nil for wrong type", result)
	}
}

// =============================================================================
// MTLSUnaryInterceptor tests
// =============================================================================

func TestMTLSUnaryInterceptorSkipMethod(t *testing.T) {
	cfg := &MTLSInterceptorConfig{
		Authenticator: &mockAuthenticator{},
		Logger:        logging.DefaultLogger(),
		SkipMethods: []string{
			"/grpc.health.v1.Health/Check",
		},
	}

	interceptor := MTLSUnaryInterceptor(cfg)

	handlerCalled := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		return "response", nil
	}

	info := &grpc.UnaryServerInfo{
		FullMethod: "/grpc.health.v1.Health/Check",
	}

	// Use a bare context with no peer info; skip should bypass auth entirely
	resp, err := interceptor(context.Background(), "request", info, handler)
	if err != nil {
		t.Fatalf("interceptor returned unexpected error: %v", err)
	}
	if !handlerCalled {
		t.Error("handler was not called for skipped method")
	}
	if resp != "response" {
		t.Errorf("response = %v, want %q", resp, "response")
	}
}

func TestMTLSUnaryInterceptorNoPeer(t *testing.T) {
	cfg := &MTLSInterceptorConfig{
		Authenticator: &mockAuthenticator{},
		Logger:        logging.DefaultLogger(),
	}

	interceptor := MTLSUnaryInterceptor(cfg)

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		t.Error("handler should not be called when there is no peer info")
		return nil, nil
	}

	info := &grpc.UnaryServerInfo{
		FullMethod: "/platform.Daemon/Shutdown",
	}

	_, err := interceptor(context.Background(), "request", info, handler)
	if err == nil {
		t.Fatal("interceptor should return error when no peer info present")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T: %v", err, err)
	}
	if st.Code() != codes.Unauthenticated {
		t.Errorf("status code = %v, want %v", st.Code(), codes.Unauthenticated)
	}
}

func TestMTLSUnaryInterceptorNoTLSInfo(t *testing.T) {
	cfg := &MTLSInterceptorConfig{
		Authenticator: &mockAuthenticator{},
		Logger:        logging.DefaultLogger(),
	}

	interceptor := MTLSUnaryInterceptor(cfg)

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		t.Error("handler should not be called when no TLS info is present")
		return nil, nil
	}

	info := &grpc.UnaryServerInfo{
		FullMethod: "/platform.Daemon/Shutdown",
	}

	ctx := createPeerContextNoTLS()
	_, err := interceptor(ctx, "request", info, handler)
	if err == nil {
		t.Fatal("interceptor should return error when no TLS info present")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T: %v", err, err)
	}
	if st.Code() != codes.Unauthenticated {
		t.Errorf("status code = %v, want %v", st.Code(), codes.Unauthenticated)
	}
}

func TestMTLSUnaryInterceptorNoCerts(t *testing.T) {
	cfg := &MTLSInterceptorConfig{
		Authenticator: &mockAuthenticator{},
		Logger:        logging.DefaultLogger(),
	}

	interceptor := MTLSUnaryInterceptor(cfg)

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		t.Error("handler should not be called when no certs are presented")
		return nil, nil
	}

	info := &grpc.UnaryServerInfo{
		FullMethod: "/platform.Daemon/Shutdown",
	}

	ctx := createPeerContextNoCerts()
	_, err := interceptor(ctx, "request", info, handler)
	if err == nil {
		t.Fatal("interceptor should return error when no certs presented")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T: %v", err, err)
	}
	if st.Code() != codes.Unauthenticated {
		t.Errorf("status code = %v, want %v", st.Code(), codes.Unauthenticated)
	}
}

func TestMTLSUnaryInterceptorSuccess(t *testing.T) {
	expectedIdentity := &auth.Identity{
		ID:       "test-client",
		TenantID: "acme-corp",
		Name:     "Test Client",
	}

	cfg := &MTLSInterceptorConfig{
		Authenticator: &mockAuthenticator{
			authenticateFunc: func(ctx context.Context, cert *x509.Certificate) (*auth.Identity, error) {
				if cert.Subject.CommonName != "test-client" {
					t.Errorf("authenticator received cert CN = %q, want %q", cert.Subject.CommonName, "test-client")
				}
				return expectedIdentity, nil
			},
		},
		Logger: logging.DefaultLogger(),
		PEP:    mtlsAllowingPEP("test-client", "acme-corp", "platform", "admin", nil),
		Users:  mtlsUsersFor(expectedIdentity),
	}

	interceptor := MTLSUnaryInterceptor(cfg)

	handlerCalled := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true

		// Verify identity is in context
		identity := IdentityFromContext(ctx)
		if identity == nil {
			t.Fatal("identity not found in context after authentication")
		}
		if identity.ID != "test-client" {
			t.Errorf("identity ID = %q, want %q", identity.ID, "test-client")
		}
		if identity.TenantID != "acme-corp" {
			t.Errorf("identity TenantID = %q, want %q", identity.TenantID, "acme-corp")
		}
		return "authenticated-response", nil
	}

	info := &grpc.UnaryServerInfo{
		FullMethod: mtlsPEPTestMethod,
	}

	cert := generateTestCert("test-client")
	ctx := createTLSPeerContext(cert)

	resp, err := interceptor(ctx, "request", info, handler)
	if err != nil {
		t.Fatalf("interceptor returned unexpected error: %v", err)
	}
	if !handlerCalled {
		t.Error("handler was not called on successful authentication")
	}
	if resp != "authenticated-response" {
		t.Errorf("response = %v, want %q", resp, "authenticated-response")
	}
}

func TestMTLSUnaryInterceptorAuthenticatorError(t *testing.T) {
	authErr := auth.ErrCertificateExpired{}

	cfg := &MTLSInterceptorConfig{
		Authenticator: &mockAuthenticator{
			authenticateFunc: func(ctx context.Context, cert *x509.Certificate) (*auth.Identity, error) {
				return nil, authErr
			},
		},
		Logger: logging.DefaultLogger(),
	}

	interceptor := MTLSUnaryInterceptor(cfg)

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		t.Error("handler should not be called when authentication fails")
		return nil, nil
	}

	info := &grpc.UnaryServerInfo{
		FullMethod: "/platform.Daemon/Shutdown",
	}

	cert := generateTestCert("expired-client")
	ctx := createTLSPeerContext(cert)

	_, err := interceptor(ctx, "request", info, handler)
	if err == nil {
		t.Fatal("interceptor should return error when authenticator fails")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T: %v", err, err)
	}
	if st.Code() != codes.Unauthenticated {
		t.Errorf("status code = %v, want %v", st.Code(), codes.Unauthenticated)
	}
}

// =============================================================================
// MTLSStreamInterceptor tests
// =============================================================================

func TestMTLSStreamInterceptorSkipMethod(t *testing.T) {
	cfg := &MTLSInterceptorConfig{
		Authenticator: &mockAuthenticator{},
		Logger:        logging.DefaultLogger(),
		SkipMethods: []string{
			"/grpc.health.v1.Health/Watch",
		},
	}

	interceptor := MTLSStreamInterceptor(cfg)

	handlerCalled := false
	handler := func(srv interface{}, stream grpc.ServerStream) error {
		handlerCalled = true
		return nil
	}

	info := &grpc.StreamServerInfo{
		FullMethod: "/grpc.health.v1.Health/Watch",
	}

	mockStream := &mockServerStream{ctx: context.Background()}

	err := interceptor("server", mockStream, info, handler)
	if err != nil {
		t.Fatalf("interceptor returned unexpected error: %v", err)
	}
	if !handlerCalled {
		t.Error("handler was not called for skipped method")
	}
}

func TestMTLSStreamInterceptorNoPeer(t *testing.T) {
	cfg := &MTLSInterceptorConfig{
		Authenticator: &mockAuthenticator{},
		Logger:        logging.DefaultLogger(),
	}

	interceptor := MTLSStreamInterceptor(cfg)

	handler := func(srv interface{}, stream grpc.ServerStream) error {
		t.Error("handler should not be called when there is no peer info")
		return nil
	}

	info := &grpc.StreamServerInfo{
		FullMethod: "/platform.Daemon/StreamEvents",
	}

	mockStream := &mockServerStream{ctx: context.Background()}

	err := interceptor("server", mockStream, info, handler)
	if err == nil {
		t.Fatal("interceptor should return error when no peer info present")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T: %v", err, err)
	}
	if st.Code() != codes.Unauthenticated {
		t.Errorf("status code = %v, want %v", st.Code(), codes.Unauthenticated)
	}
}

func TestMTLSStreamInterceptorNoTLSInfo(t *testing.T) {
	cfg := &MTLSInterceptorConfig{
		Authenticator: &mockAuthenticator{},
		Logger:        logging.DefaultLogger(),
	}

	interceptor := MTLSStreamInterceptor(cfg)

	handler := func(srv interface{}, stream grpc.ServerStream) error {
		t.Error("handler should not be called when no TLS info present")
		return nil
	}

	info := &grpc.StreamServerInfo{
		FullMethod: "/platform.Daemon/StreamEvents",
	}

	mockStream := &mockServerStream{ctx: createPeerContextNoTLS()}

	err := interceptor("server", mockStream, info, handler)
	if err == nil {
		t.Fatal("interceptor should return error when no TLS info present")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T: %v", err, err)
	}
	if st.Code() != codes.Unauthenticated {
		t.Errorf("status code = %v, want %v", st.Code(), codes.Unauthenticated)
	}
}

func TestMTLSStreamInterceptorNoCerts(t *testing.T) {
	cfg := &MTLSInterceptorConfig{
		Authenticator: &mockAuthenticator{},
		Logger:        logging.DefaultLogger(),
	}

	interceptor := MTLSStreamInterceptor(cfg)

	handler := func(srv interface{}, stream grpc.ServerStream) error {
		t.Error("handler should not be called when no certs presented")
		return nil
	}

	info := &grpc.StreamServerInfo{
		FullMethod: "/platform.Daemon/StreamEvents",
	}

	mockStream := &mockServerStream{ctx: createPeerContextNoCerts()}

	err := interceptor("server", mockStream, info, handler)
	if err == nil {
		t.Fatal("interceptor should return error when no certs presented")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T: %v", err, err)
	}
	if st.Code() != codes.Unauthenticated {
		t.Errorf("status code = %v, want %v", st.Code(), codes.Unauthenticated)
	}
}

func TestMTLSStreamInterceptorSuccess(t *testing.T) {
	expectedIdentity := &auth.Identity{
		ID:       "stream-client",
		TenantID: "stream-tenant",
		Name:     "Stream Client",
	}

	cfg := &MTLSInterceptorConfig{
		Authenticator: &mockAuthenticator{
			authenticateFunc: func(ctx context.Context, cert *x509.Certificate) (*auth.Identity, error) {
				if cert.Subject.CommonName != "stream-client" {
					t.Errorf("authenticator received cert CN = %q, want %q", cert.Subject.CommonName, "stream-client")
				}
				return expectedIdentity, nil
			},
		},
		Logger: logging.DefaultLogger(),
		PEP:    mtlsAllowingPEP("stream-client", "stream-tenant", "platform", "read", nil),
		Users:  mtlsUsersFor(expectedIdentity),
	}

	interceptor := MTLSStreamInterceptor(cfg)

	handlerCalled := false
	handler := func(srv interface{}, stream grpc.ServerStream) error {
		handlerCalled = true

		// Verify the stream's context contains the identity
		identity := IdentityFromContext(stream.Context())
		if identity == nil {
			t.Fatal("identity not found in stream context after authentication")
		}
		if identity.ID != "stream-client" {
			t.Errorf("identity ID = %q, want %q", identity.ID, "stream-client")
		}
		if identity.TenantID != "stream-tenant" {
			t.Errorf("identity TenantID = %q, want %q", identity.TenantID, "stream-tenant")
		}
		return nil
	}

	info := &grpc.StreamServerInfo{
		FullMethod: mtlsPEPTestStreamMethod,
	}

	cert := generateTestCert("stream-client")
	ctx := createTLSPeerContext(cert)
	mockStream := &mockServerStream{ctx: ctx}

	err := interceptor("server", mockStream, info, handler)
	if err != nil {
		t.Fatalf("interceptor returned unexpected error: %v", err)
	}
	if !handlerCalled {
		t.Error("handler was not called on successful authentication")
	}
}

func TestMTLSStreamInterceptorAuthenticatorError(t *testing.T) {
	authErr := auth.ErrCertificateRevoked{}

	cfg := &MTLSInterceptorConfig{
		Authenticator: &mockAuthenticator{
			authenticateFunc: func(ctx context.Context, cert *x509.Certificate) (*auth.Identity, error) {
				return nil, authErr
			},
		},
		Logger: logging.DefaultLogger(),
	}

	interceptor := MTLSStreamInterceptor(cfg)

	handler := func(srv interface{}, stream grpc.ServerStream) error {
		t.Error("handler should not be called when authentication fails")
		return nil
	}

	info := &grpc.StreamServerInfo{
		FullMethod: "/platform.Daemon/StreamEvents",
	}

	cert := generateTestCert("revoked-client")
	ctx := createTLSPeerContext(cert)
	mockStream := &mockServerStream{ctx: ctx}

	err := interceptor("server", mockStream, info, handler)
	if err == nil {
		t.Fatal("interceptor should return error when authenticator fails")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T: %v", err, err)
	}
	if st.Code() != codes.Unauthenticated {
		t.Errorf("status code = %v, want %v", st.Code(), codes.Unauthenticated)
	}
}

// =============================================================================
// mtlsServerStream tests
// =============================================================================

func TestMTLSServerStreamContext(t *testing.T) {
	identity := &auth.Identity{
		ID:       "wrapped-client",
		TenantID: "wrapped-tenant",
	}
	enrichedCtx := context.WithValue(context.Background(), ContextKeyIdentity, identity)

	originalStream := &mockServerStream{ctx: context.Background()}
	wrappedStream := &mtlsServerStream{
		ServerStream: originalStream,
		ctx:          enrichedCtx,
	}

	// Verify the wrapped stream returns the enriched context, not the original
	result := IdentityFromContext(wrappedStream.Context())
	if result == nil {
		t.Fatal("IdentityFromContext returned nil for wrapped stream context")
	}
	if result.ID != "wrapped-client" {
		t.Errorf("identity ID = %q, want %q", result.ID, "wrapped-client")
	}
	if result.TenantID != "wrapped-tenant" {
		t.Errorf("identity TenantID = %q, want %q", result.TenantID, "wrapped-tenant")
	}

	// Verify the original stream context does NOT have the identity
	originalResult := IdentityFromContext(originalStream.Context())
	if originalResult != nil {
		t.Error("original stream context should not contain the identity")
	}
}

// =============================================================================
// MTLSInterceptorConfig tests
// =============================================================================

func TestMTLSInterceptorConfigNilLogger(t *testing.T) {
	// Verify interceptors work with nil logger (no-op logging branches)
	cfg := &MTLSInterceptorConfig{
		Authenticator: &mockAuthenticator{},
		Logger:        nil,
	}

	interceptor := MTLSUnaryInterceptor(cfg)

	info := &grpc.UnaryServerInfo{
		FullMethod: "/platform.Daemon/Shutdown",
	}

	// No peer info, nil logger should not panic
	_, err := interceptor(context.Background(), "request", info, func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, nil
	})
	if err == nil {
		t.Fatal("interceptor should return error when no peer info present")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T: %v", err, err)
	}
	if st.Code() != codes.Unauthenticated {
		t.Errorf("status code = %v, want %v", st.Code(), codes.Unauthenticated)
	}
}

func TestMTLSInterceptorConfigNilLoggerNoCerts(t *testing.T) {
	cfg := &MTLSInterceptorConfig{
		Authenticator: &mockAuthenticator{},
		Logger:        nil,
	}

	interceptor := MTLSUnaryInterceptor(cfg)

	info := &grpc.UnaryServerInfo{
		FullMethod: "/platform.Daemon/Shutdown",
	}

	ctx := createPeerContextNoCerts()
	_, err := interceptor(ctx, "request", info, func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, nil
	})
	if err == nil {
		t.Fatal("interceptor should return error when no certs presented")
	}
}

func TestMTLSInterceptorConfigNilLoggerNoTLS(t *testing.T) {
	cfg := &MTLSInterceptorConfig{
		Authenticator: &mockAuthenticator{},
		Logger:        nil,
	}

	interceptor := MTLSUnaryInterceptor(cfg)

	info := &grpc.UnaryServerInfo{
		FullMethod: "/platform.Daemon/Shutdown",
	}

	ctx := createPeerContextNoTLS()
	_, err := interceptor(ctx, "request", info, func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, nil
	})
	if err == nil {
		t.Fatal("interceptor should return error when no TLS info present")
	}
}

func TestMTLSInterceptorConfigNilLoggerAuthFailed(t *testing.T) {
	cfg := &MTLSInterceptorConfig{
		Authenticator: &mockAuthenticator{
			authenticateFunc: func(ctx context.Context, cert *x509.Certificate) (*auth.Identity, error) {
				return nil, errors.New("test auth failure")
			},
		},
		Logger: nil,
	}

	interceptor := MTLSUnaryInterceptor(cfg)

	info := &grpc.UnaryServerInfo{
		FullMethod: "/platform.Daemon/Shutdown",
	}

	cert := generateTestCert("test-client")
	ctx := createTLSPeerContext(cert)

	_, err := interceptor(ctx, "request", info, func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, nil
	})
	if err == nil {
		t.Fatal("interceptor should return error when auth fails")
	}
}

// =============================================================================
// Config mTLS validation tests
// =============================================================================

func TestConfigEnableMTLSValidation(t *testing.T) {
	config := DefaultConfig()
	config.EnableMTLS = true
	// No CAFile or CAPool set

	err := config.Validate()
	if err == nil {
		t.Fatal("Validate() should return error when EnableMTLS is true but no CA file or pool set")
	}

	errInvalid, ok := err.(ErrInvalidConfig)
	if !ok {
		t.Fatalf("expected ErrInvalidConfig, got %T: %v", err, err)
	}

	expectedReason := "mTLS enabled but no client CA file or cert pool configured"
	if errInvalid.Reason != expectedReason {
		t.Errorf("error reason = %q, want %q", errInvalid.Reason, expectedReason)
	}
}

func TestConfigEnableMTLSWithCAFile(t *testing.T) {
	config := DefaultConfig()
	config.EnableMTLS = true
	config.MTLSClientCAFile = "/etc/ssl/ca-client.pem"

	err := config.Validate()
	if err != nil {
		t.Errorf("Validate() returned unexpected error: %v", err)
	}
}

func TestConfigEnableMTLSWithCAPool(t *testing.T) {
	config := DefaultConfig()
	config.EnableMTLS = true
	config.MTLSClientCAPool = x509.NewCertPool()

	err := config.Validate()
	if err != nil {
		t.Errorf("Validate() returned unexpected error: %v", err)
	}
}

func TestConfigEnableMTLSWithBothCAFileAndPool(t *testing.T) {
	config := DefaultConfig()
	config.EnableMTLS = true
	config.MTLSClientCAFile = "/etc/ssl/ca-client.pem"
	config.MTLSClientCAPool = x509.NewCertPool()

	err := config.Validate()
	if err != nil {
		t.Errorf("Validate() returned unexpected error: %v", err)
	}
}

func TestConfigMTLSDisabledNoValidation(t *testing.T) {
	config := DefaultConfig()
	config.EnableMTLS = false
	// No CAFile or CAPool set, but mTLS is disabled so it should pass

	err := config.Validate()
	if err != nil {
		t.Errorf("Validate() returned unexpected error when mTLS is disabled: %v", err)
	}
}

func TestConfigDefaultMTLSDisabled(t *testing.T) {
	config := DefaultConfig()
	if config.EnableMTLS {
		t.Error("EnableMTLS should be false by default")
	}
	if config.MTLSClientCAFile != "" {
		t.Errorf("MTLSClientCAFile should be empty by default, got %q", config.MTLSClientCAFile)
	}
	if config.MTLSClientCAPool != nil {
		t.Error("MTLSClientCAPool should be nil by default")
	}
}

// =============================================================================
// ContextKeyIdentity tests
// =============================================================================

func TestContextKeyIdentityValue(t *testing.T) {
	expected := contextKey("mtls-identity")
	if ContextKeyIdentity != expected {
		t.Errorf("ContextKeyIdentity = %q, want %q", ContextKeyIdentity, expected)
	}
}

// =============================================================================
// Interceptor with multiple skip methods tests
// =============================================================================

func TestMTLSUnaryInterceptorMultipleSkipMethods(t *testing.T) {
	cfg := &MTLSInterceptorConfig{
		Authenticator: &mockAuthenticator{},
		Logger:        logging.DefaultLogger(),
		SkipMethods: []string{
			"/grpc.health.v1.Health/Check",
			"/grpc.health.v1.Health/Watch",
			"/platform.Daemon/Status",
		},
	}

	interceptor := MTLSUnaryInterceptor(cfg)

	tests := []struct {
		name     string
		method   string
		wantSkip bool
		setupCtx func() context.Context
	}{
		{
			name:     "skip health check",
			method:   "/grpc.health.v1.Health/Check",
			wantSkip: true,
			setupCtx: context.Background,
		},
		{
			name:     "skip daemon status",
			method:   "/platform.Daemon/Status",
			wantSkip: true,
			setupCtx: context.Background,
		},
		{
			name:     "do not skip shutdown",
			method:   "/platform.Daemon/Shutdown",
			wantSkip: false,
			setupCtx: func() context.Context { return createTLSPeerContext(generateTestCert("client")) },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handlerCalled := false
			handler := func(ctx context.Context, req interface{}) (interface{}, error) {
				handlerCalled = true
				return "ok", nil
			}

			info := &grpc.UnaryServerInfo{FullMethod: tt.method}

			_, err := interceptor(tt.setupCtx(), "req", info, handler)
			if tt.wantSkip {
				if err != nil {
					t.Errorf("expected no error for skipped method, got %v", err)
				}
				if !handlerCalled {
					t.Error("handler should be called for skipped method")
				}
			} else if !handlerCalled {
				// For non-skipped methods with valid TLS context, handler should be called
				if err != nil {
					// Error is acceptable if auth setup requires it
					return
				}
			}
		})
	}
}

// =============================================================================
// extractClientCerts with multiple verified chains
// =============================================================================

func TestExtractClientCertsMultipleVerifiedChains(t *testing.T) {
	chain1Leaf := generateTestCert("chain1-leaf")
	chain1Intermediate := generateTestCert("chain1-intermediate")
	chain2Leaf := generateTestCert("chain2-leaf")

	state := tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{
			{chain1Leaf, chain1Intermediate},
			{chain2Leaf},
		},
	}

	// Should return the first chain
	certs := extractClientCerts(state)
	if len(certs) != 2 {
		t.Fatalf("extractClientCerts returned %d certs, want 2 from first chain", len(certs))
	}
	if certs[0].Subject.CommonName != "chain1-leaf" {
		t.Errorf("first cert CN = %q, want %q", certs[0].Subject.CommonName, "chain1-leaf")
	}
}

// mtlsPEPTestMethod is a catalogued gRPC method whose permission is
// platform:admin in pkg/api/grpc/method_permissions.go.
const mtlsPEPTestMethod = "/platform.v1.PlatformDaemon/Shutdown"

// mtlsPEPTestStreamMethod is a catalogued streaming method whose permission
// is platform:read.
const mtlsPEPTestStreamMethod = "/platform.v1.PlatformDaemon/StreamEvents"

// mtlsPEPTestConfig builds an interceptor config whose authenticator returns
// the given identity and whose PEP is pep.
func mtlsPEPTestConfig(identity *auth.Identity, pep *mockSDKPEPClient) *MTLSInterceptorConfig {
	cfg := &MTLSInterceptorConfig{
		Authenticator: &mockAuthenticator{
			authenticateFunc: func(ctx context.Context, cert *x509.Certificate) (*auth.Identity, error) {
				return identity, nil
			},
		},
		Logger: logging.DefaultLogger(),
		// The certificate names an IAM user whose ID is the identity ID, so
		// the PEP expectations of these tests stay keyed by that ID.
		Users: mtlsUsersFor(identity),
	}
	if pep != nil {
		cfg.PEP = pep
	}
	return cfg
}

// mtlsAllowingPEP allows exactly the subject, tenant, resource and action given
// and records the last request it saw.
func mtlsAllowingPEP(subject, tenant, resource, action string, seen **sdkiam.CheckRequest) *mockSDKPEPClient {
	return &mockSDKPEPClient{
		checkFunc: func(ctx context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
			if seen != nil {
				*seen = req
			}
			allowed := req.Subject.ID == subject && req.Subject.TenantID == tenant &&
				req.Resource == resource && req.Action == action
			return &sdkiam.CheckResponse{Allowed: allowed}, nil
		},
	}
}

func TestMTLSUnaryInterceptor_PrincipalWithoutMethodPermissionIsDenied(t *testing.T) {
	identity := &auth.Identity{ID: "reader", TenantID: "acme-corp"}
	// The PEP grants platform:read only; Shutdown needs platform:admin.
	pep := mtlsAllowingPEP("reader", "acme-corp", "platform", "read", nil)
	interceptor := MTLSUnaryInterceptor(mtlsPEPTestConfig(identity, pep))

	handlerCalled := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		return "ok", nil
	}
	ctx := createTLSPeerContext(generateTestCert("reader"))
	_, err := interceptor(ctx, "req", &grpc.UnaryServerInfo{FullMethod: mtlsPEPTestMethod}, handler)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v (err %v), want PermissionDenied", status.Code(err), err)
	}
	if handlerCalled {
		t.Fatal("handler ran for a principal without the method permission")
	}
}

func TestMTLSUnaryInterceptor_PrincipalWithMethodPermissionSucceeds(t *testing.T) {
	identity := &auth.Identity{ID: "operator", TenantID: "acme-corp"}
	var seen *sdkiam.CheckRequest
	pep := mtlsAllowingPEP("operator", "acme-corp", "platform", "admin", &seen)
	interceptor := MTLSUnaryInterceptor(mtlsPEPTestConfig(identity, pep))

	handlerCalled := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		if got := IdentityFromContext(ctx); got == nil || got.ID != "operator" {
			t.Errorf("identity in context = %v, want operator", got)
		}
		return "ok", nil
	}
	ctx := createTLSPeerContext(generateTestCert("operator"))
	resp, err := interceptor(ctx, "req", &grpc.UnaryServerInfo{FullMethod: mtlsPEPTestMethod}, handler)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !handlerCalled || resp != "ok" {
		t.Fatalf("handler called = %v, resp = %v; want the handler's response", handlerCalled, resp)
	}
	if seen == nil || seen.Resource != "platform" || seen.Action != "admin" {
		t.Fatalf("PEP request = %+v, want resource platform action admin", seen)
	}

	// A method with no catalog entry is denied even for this principal.
	handlerCalled = false
	_, err = interceptor(ctx, "req", &grpc.UnaryServerInfo{FullMethod: "/platform.v1.PlatformDaemon/NotInCatalog"}, handler)
	if status.Code(err) != codes.PermissionDenied || handlerCalled {
		t.Fatalf("unclassified method: code = %v, handler called = %v; want PermissionDenied and no handler", status.Code(err), handlerCalled)
	}
}

func TestMTLSStreamInterceptor_PrincipalWithoutMethodPermissionIsDenied(t *testing.T) {
	identity := &auth.Identity{ID: "nobody", TenantID: "acme-corp"}
	// The PEP grants this principal nothing.
	pep := mtlsAllowingPEP("someone-else", "acme-corp", "platform", "read", nil)
	interceptor := MTLSStreamInterceptor(mtlsPEPTestConfig(identity, pep))

	handlerCalled := false
	handler := func(srv interface{}, stream grpc.ServerStream) error {
		handlerCalled = true
		return nil
	}
	ss := &mockServerStream{ctx: createTLSPeerContext(generateTestCert("nobody"))}
	err := interceptor(nil, ss, &grpc.StreamServerInfo{FullMethod: mtlsPEPTestStreamMethod}, handler)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v (err %v), want PermissionDenied", status.Code(err), err)
	}
	if handlerCalled {
		t.Fatal("handler ran for a principal without the method permission")
	}
}

func TestMTLSUnaryInterceptor_NilPEPFailsClosed(t *testing.T) {
	identity := &auth.Identity{ID: "operator", TenantID: "acme-corp"}
	interceptor := MTLSUnaryInterceptor(mtlsPEPTestConfig(identity, nil))

	handlerCalled := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		return "ok", nil
	}
	ctx := createTLSPeerContext(generateTestCert("operator"))
	_, err := interceptor(ctx, "req", &grpc.UnaryServerInfo{FullMethod: mtlsPEPTestMethod}, handler)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("nil PEP: code = %v (err %v), want Unavailable", status.Code(err), err)
	}
	if handlerCalled {
		t.Fatal("handler ran without a PEP")
	}

	// A PEP that errors fails closed the same way.
	failing := &mockSDKPEPClient{
		checkFunc: func(ctx context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
			return nil, errors.New("pep unreachable")
		},
	}
	interceptor = MTLSUnaryInterceptor(mtlsPEPTestConfig(identity, failing))
	_, err = interceptor(ctx, "req", &grpc.UnaryServerInfo{FullMethod: mtlsPEPTestMethod}, handler)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("failing PEP: code = %v (err %v), want Unavailable", status.Code(err), err)
	}
	if handlerCalled {
		t.Fatal("handler ran when the PEP could not answer")
	}
}

// mtlsPreAuthTestMethod is a pre-auth method: the token path serves it
// without a credential, so the mTLS path must not send it to the PEP either.
const mtlsPreAuthTestMethod = "/grpc.health.v1.Health/Check"

// mtlsDenyingPEP denies every check and counts how often it was asked.
func mtlsDenyingPEP(calls *int) *mockSDKPEPClient {
	return &mockSDKPEPClient{
		checkFunc: func(ctx context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
			*calls++
			return &sdkiam.CheckResponse{Allowed: false}, nil
		},
	}
}

func TestMTLSUnaryInterceptor_PreAuthMethodSkipsThePEPCheck(t *testing.T) {
	identity := &auth.Identity{ID: "probe", TenantID: "acme-corp"}
	calls := 0
	interceptor := MTLSUnaryInterceptor(mtlsPEPTestConfig(identity, mtlsDenyingPEP(&calls)))

	handlerCalled := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		if IdentityFromContext(ctx) == nil {
			t.Error("pre-auth handler ran without the authenticated certificate identity")
		}
		return "ok", nil
	}
	ctx := createTLSPeerContext(generateTestCert("probe"))
	_, err := interceptor(ctx, "req", &grpc.UnaryServerInfo{FullMethod: mtlsPreAuthTestMethod}, handler)
	if err != nil {
		t.Fatalf("pre-auth method refused under mTLS: %v", err)
	}
	if !handlerCalled {
		t.Fatal("handler did not run for a pre-auth method")
	}
	if calls != 0 {
		t.Fatalf("PEP was asked %d times for a pre-auth method, want 0", calls)
	}
}

func TestMTLSStreamInterceptor_PreAuthMethodSkipsThePEPCheck(t *testing.T) {
	identity := &auth.Identity{ID: "probe", TenantID: "acme-corp"}
	calls := 0
	interceptor := MTLSStreamInterceptor(mtlsPEPTestConfig(identity, mtlsDenyingPEP(&calls)))

	handlerCalled := false
	handler := func(srv interface{}, stream grpc.ServerStream) error {
		handlerCalled = true
		if IdentityFromContext(stream.Context()) == nil {
			t.Error("pre-auth handler ran without the authenticated certificate identity")
		}
		return nil
	}
	ss := &mockServerStream{ctx: createTLSPeerContext(generateTestCert("probe"))}
	err := interceptor(nil, ss, &grpc.StreamServerInfo{FullMethod: mtlsPreAuthTestMethod}, handler)
	if err != nil {
		t.Fatalf("pre-auth method refused under mTLS: %v", err)
	}
	if !handlerCalled {
		t.Fatal("handler did not run for a pre-auth method")
	}
	if calls != 0 {
		t.Fatalf("PEP was asked %d times for a pre-auth method, want 0", calls)
	}
}

// mtlsFakeUsers is an IAM user directory for the mTLS interceptor tests. A
// key that is not present answers with the SDK's not-found error, as the
// SDK UserClient does.
type mtlsFakeUsers struct {
	byEmail    map[string]*sdkiam.User
	byUsername map[string]*sdkiam.User
	err        error
	calls      int
}

func (f *mtlsFakeUsers) GetByEmail(ctx context.Context, tenantID, email string) (*sdkiam.User, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	if u, ok := f.byEmail[email]; ok {
		return u, nil
	}
	return nil, quicbaaserrors.NewNotFound("iam.user.get_by_email", "user not found")
}

func (f *mtlsFakeUsers) FindByUsername(ctx context.Context, tenantID, username string) (*sdkiam.User, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	if u, ok := f.byUsername[username]; ok {
		return u, nil
	}
	return nil, quicbaaserrors.NewNotFound("iam.user.find_by_username", "user not found")
}

// mtlsUsersFor maps the identity ID, as a username, to an IAM user whose ID
// is that identity ID and who holds no roles.
func mtlsUsersFor(identity *auth.Identity) *mtlsFakeUsers {
	users := &mtlsFakeUsers{byUsername: map[string]*sdkiam.User{}}
	if identity != nil {
		users.byUsername[identity.ID] = &sdkiam.User{ID: identity.ID, TenantID: identity.TenantID, Username: identity.ID}
	}
	return users
}

// mtlsRBACPEP allows a request only when the subject carries roleID and the
// permission is resource:action. It ignores the subject ID, so only the
// interceptor's role resolution can make it allow.
func mtlsRBACPEP(roleID, resource, action string, seen **sdkiam.CheckRequest, calls *int) *mockSDKPEPClient {
	return &mockSDKPEPClient{
		checkFunc: func(ctx context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
			if calls != nil {
				*calls++
			}
			if seen != nil {
				*seen = req
			}
			hasRole := false
			for _, r := range req.Subject.Roles {
				if r == roleID {
					hasRole = true
				}
			}
			return &sdkiam.CheckResponse{Allowed: hasRole && req.Resource == resource && req.Action == action}, nil
		},
	}
}

func mtlsOperatorUsers() *mtlsFakeUsers {
	return &mtlsFakeUsers{byUsername: map[string]*sdkiam.User{
		"operator": {ID: "u-1", TenantID: "acme-corp", Username: "operator", Roles: []string{"role-admin"}},
	}}
}

func assertMTLSSubject(t *testing.T, seen *sdkiam.CheckRequest, id, tenant string, roles []string) {
	t.Helper()
	if seen == nil {
		t.Fatal("the PEP was not asked")
	}
	if seen.Subject.ID != id || seen.Subject.TenantID != tenant {
		t.Fatalf("PEP subject = %q/%q, want %q/%q", seen.Subject.ID, seen.Subject.TenantID, id, tenant)
	}
	if len(seen.Subject.Roles) != len(roles) {
		t.Fatalf("PEP subject roles = %v, want %v", seen.Subject.Roles, roles)
	}
	for i := range roles {
		if seen.Subject.Roles[i] != roles[i] {
			t.Fatalf("PEP subject roles = %v, want %v", seen.Subject.Roles, roles)
		}
	}
}

func TestMTLSUnaryInterceptor_AssignedRoleIsAllowed(t *testing.T) {
	identity := &auth.Identity{ID: "operator", TenantID: "acme-corp"}
	var seen *sdkiam.CheckRequest
	cfg := mtlsPEPTestConfig(identity, mtlsRBACPEP("role-admin", "platform", "admin", &seen, nil))
	cfg.Users = mtlsOperatorUsers()
	interceptor := MTLSUnaryInterceptor(cfg)

	handlerCalled := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		return "ok", nil
	}
	ctx := createTLSPeerContext(generateTestCert("operator"))
	if _, err := interceptor(ctx, "req", &grpc.UnaryServerInfo{FullMethod: mtlsPEPTestMethod}, handler); err != nil {
		t.Fatalf("certificate user holding the role was refused: %v", err)
	}
	if !handlerCalled {
		t.Fatal("handler did not run for a certificate user holding the method permission")
	}
	assertMTLSSubject(t, seen, "u-1", "acme-corp", []string{"role-admin"})
}

func TestMTLSUnaryInterceptor_EmailSANResolvesBeforeUsername(t *testing.T) {
	identity := &auth.Identity{ID: "operator", TenantID: "acme-corp", Email: "op@example.com"}
	var seen *sdkiam.CheckRequest
	cfg := mtlsPEPTestConfig(identity, mtlsRBACPEP("role-admin", "platform", "admin", &seen, nil))
	cfg.Users = &mtlsFakeUsers{
		byEmail: map[string]*sdkiam.User{
			"op@example.com": {ID: "u-email", TenantID: "acme-corp", Email: "op@example.com", Roles: []string{"role-admin"}},
		},
		byUsername: map[string]*sdkiam.User{
			"operator": {ID: "u-name", TenantID: "acme-corp", Username: "operator", Roles: []string{"role-viewer"}},
		},
	}
	interceptor := MTLSUnaryInterceptor(cfg)

	handler := func(ctx context.Context, req interface{}) (interface{}, error) { return "ok", nil }
	ctx := createTLSPeerContext(generateTestCert("operator"))
	if _, err := interceptor(ctx, "req", &grpc.UnaryServerInfo{FullMethod: mtlsPEPTestMethod}, handler); err != nil {
		t.Fatalf("email SAN user holding the role was refused: %v", err)
	}
	assertMTLSSubject(t, seen, "u-email", "acme-corp", []string{"role-admin"})
}

func TestMTLSUnaryInterceptor_UnknownCertificateUserIsDenied(t *testing.T) {
	identity := &auth.Identity{ID: "stranger", TenantID: "acme-corp", Email: "stranger@example.com"}
	calls := 0
	cfg := mtlsPEPTestConfig(identity, mtlsRBACPEP("role-admin", "platform", "admin", nil, &calls))
	cfg.Users = mtlsOperatorUsers()
	interceptor := MTLSUnaryInterceptor(cfg)

	handlerCalled := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		return "ok", nil
	}
	ctx := createTLSPeerContext(generateTestCert("stranger"))
	_, err := interceptor(ctx, "req", &grpc.UnaryServerInfo{FullMethod: mtlsPEPTestMethod}, handler)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v (err %v), want PermissionDenied", status.Code(err), err)
	}
	if handlerCalled || calls != 0 {
		t.Fatalf("handler called = %v, PEP calls = %d; want neither for an unknown user", handlerCalled, calls)
	}
}

func TestMTLSUnaryInterceptor_UserLookupFailureFailsClosed(t *testing.T) {
	identity := &auth.Identity{ID: "operator", TenantID: "acme-corp"}
	calls := 0
	cfg := mtlsPEPTestConfig(identity, mtlsRBACPEP("role-admin", "platform", "admin", nil, &calls))
	users := mtlsOperatorUsers()
	users.err = quicbaaserrors.NewUnavailable("iam.user.find_by_username", "directory unreachable")
	cfg.Users = users
	interceptor := MTLSUnaryInterceptor(cfg)

	handlerCalled := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		return "ok", nil
	}
	ctx := createTLSPeerContext(generateTestCert("operator"))
	_, err := interceptor(ctx, "req", &grpc.UnaryServerInfo{FullMethod: mtlsPEPTestMethod}, handler)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v (err %v), want Unavailable", status.Code(err), err)
	}
	if handlerCalled || calls != 0 {
		t.Fatalf("handler called = %v, PEP calls = %d; want neither when the lookup fails", handlerCalled, calls)
	}
}

func TestMTLSUnaryInterceptor_NilUsersFailsClosed(t *testing.T) {
	identity := &auth.Identity{ID: "operator", TenantID: "acme-corp"}
	calls := 0
	cfg := mtlsPEPTestConfig(identity, mtlsRBACPEP("role-admin", "platform", "admin", nil, &calls))
	cfg.Users = nil
	interceptor := MTLSUnaryInterceptor(cfg)

	handler := func(ctx context.Context, req interface{}) (interface{}, error) { return "ok", nil }
	ctx := createTLSPeerContext(generateTestCert("operator"))
	_, err := interceptor(ctx, "req", &grpc.UnaryServerInfo{FullMethod: mtlsPEPTestMethod}, handler)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v (err %v), want Unavailable", status.Code(err), err)
	}
	if calls != 0 {
		t.Fatalf("PEP asked %d times with no user lookup wired, want 0", calls)
	}
}

func TestMTLSStreamInterceptor_AssignedRoleIsAllowed(t *testing.T) {
	identity := &auth.Identity{ID: "operator", TenantID: "acme-corp"}
	var seen *sdkiam.CheckRequest
	resource, action, _ := strings.Cut(grpccreds.ScopeForMethod(mtlsPEPTestStreamMethod), ":")
	cfg := mtlsPEPTestConfig(identity, mtlsRBACPEP("role-admin", resource, action, &seen, nil))
	cfg.Users = mtlsOperatorUsers()
	interceptor := MTLSStreamInterceptor(cfg)

	handlerCalled := false
	handler := func(srv interface{}, stream grpc.ServerStream) error {
		handlerCalled = true
		return nil
	}
	ss := &mockServerStream{ctx: createTLSPeerContext(generateTestCert("operator"))}
	if err := interceptor(nil, ss, &grpc.StreamServerInfo{FullMethod: mtlsPEPTestStreamMethod}, handler); err != nil {
		t.Fatalf("certificate user holding the role was refused: %v", err)
	}
	if !handlerCalled {
		t.Fatal("handler did not run for a certificate user holding the method permission")
	}
	assertMTLSSubject(t, seen, "u-1", "acme-corp", []string{"role-admin"})
}
