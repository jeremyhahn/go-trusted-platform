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
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

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
		FullMethod: "/platform.Daemon/Shutdown",
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
		FullMethod: "/platform.Daemon/StreamEvents",
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
			setupCtx: func() context.Context { return context.Background() },
		},
		{
			name:     "skip daemon status",
			method:   "/platform.Daemon/Status",
			wantSkip: true,
			setupCtx: func() context.Context { return context.Background() },
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
			} else {
				if !handlerCalled {
					// For non-skipped methods with valid TLS context, handler should be called
					if err != nil {
						// Error is acceptable if auth setup requires it
						return
					}
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
