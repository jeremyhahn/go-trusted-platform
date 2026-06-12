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

package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"log/slog"
	"math/big"
	"testing"
	"time"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme/transport"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme/workflow"
	xkmsca "github.com/jeremyhahn/go-xkms/pkg/ca"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// mockCertificateAuthority implements the CertificateAuthority interface for testing.
type mockCertificateAuthority struct {
	baseMockCA
	signCSRFunc             func(csrPEM []byte, opts *xkmsca.SignOptions) (*x509.Certificate, error)
	caBundleFunc            func(storeType xkmssdk.StoreType, keyAlgorithm x509.PublicKeyAlgorithm) ([]byte, error)
	importCertificateFunc   func(certificate *x509.Certificate) error
	certificateFunc         func(attrs *xkmssdk.KeyAttributes) (*x509.Certificate, error)
	verifyFunc              func(certificate *x509.Certificate, xsigner ...crypto.Signer) ([][]*x509.Certificate, error)
	signerFunc              func() (crypto.Signer, error)
	trustedRootFunc         func() (*x509.Certificate, error)
	trustedIntermediateFunc func() (*x509.Certificate, error)
	issueCertificateFunc    func(request *xkmsca.CertificateRequest) (*xkmsca.IssuedCertificate, error)
	revokeFunc              func(certificate *x509.Certificate, opts xkmsca.RevokeOptions) error
}

func (m *mockCertificateAuthority) SignCSR(_ context.Context, csrPEM []byte, opts *xkmsca.SignOptions) (*x509.Certificate, error) {
	if m.signCSRFunc != nil {
		return m.signCSRFunc(csrPEM, opts)
	}
	return nil, nil
}
func (m *mockCertificateAuthority) CABundle() ([]byte, error) {
	if m.caBundleFunc != nil {
		return m.caBundleFunc("", 0)
	}
	return nil, nil
}
func (m *mockCertificateAuthority) CABundleFiltered(storeType xkmssdk.StoreType, keyAlgorithm x509.PublicKeyAlgorithm) ([]byte, error) {
	if m.caBundleFunc != nil {
		return m.caBundleFunc(storeType, keyAlgorithm)
	}
	return nil, nil
}
func (m *mockCertificateAuthority) ImportCertificate(_ context.Context, certificate *x509.Certificate) error {
	if m.importCertificateFunc != nil {
		return m.importCertificateFunc(certificate)
	}
	return nil
}
func (m *mockCertificateAuthority) Certificate(_ context.Context, attrs *xkmssdk.KeyAttributes) (*x509.Certificate, error) {
	if m.certificateFunc != nil {
		return m.certificateFunc(attrs)
	}
	return nil, nil
}
func (m *mockCertificateAuthority) Verify(certificate *x509.Certificate, xsigner ...crypto.Signer) ([][]*x509.Certificate, error) {
	if m.verifyFunc != nil {
		return m.verifyFunc(certificate, xsigner...)
	}
	return nil, nil
}
func (m *mockCertificateAuthority) Signer(_ context.Context) (crypto.Signer, error) {
	if m.signerFunc != nil {
		return m.signerFunc()
	}
	return nil, nil
}
func (m *mockCertificateAuthority) TrustedRoot() (*x509.Certificate, error) {
	if m.trustedRootFunc != nil {
		return m.trustedRootFunc()
	}
	return nil, nil
}
func (m *mockCertificateAuthority) TrustedIntermediate() (*x509.Certificate, error) {
	if m.trustedIntermediateFunc != nil {
		return m.trustedIntermediateFunc()
	}
	return nil, nil
}
func (m *mockCertificateAuthority) IssueCertificate(_ context.Context, request *xkmsca.CertificateRequest) (*xkmsca.IssuedCertificate, error) {
	if m.issueCertificateFunc != nil {
		return m.issueCertificateFunc(request)
	}
	return nil, nil
}
func (m *mockCertificateAuthority) RevokeCert(_ context.Context, cert *x509.Certificate, opts xkmsca.RevokeOptions) error {
	if m.revokeFunc != nil {
		return m.revokeFunc(cert, opts)
	}
	return nil
}
func (m *mockCertificateAuthority) IsInitialized() bool                          { return true }
func (m *mockCertificateAuthority) Identity() string                             { return "test-ca" }
func (m *mockCertificateAuthority) DefaultKeyAlgorithm() x509.PublicKeyAlgorithm { return x509.ECDSA }
func (m *mockCertificateAuthority) DefaultSignatureAlgorithm() x509.SignatureAlgorithm {
	return x509.ECDSAWithSHA256
}
func (m *mockCertificateAuthority) DefaultValidityPeriod() int { return 365 }

// mockTransport implements the transport.Transport interface for testing.
type mockTransport struct{}

func (m *mockTransport) Request(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
	return nil, nil
}
func (m *mockTransport) RequestStream(ctx context.Context, service, method string, req interface{}) (transport.Stream, error) {
	return nil, nil
}
func (m *mockTransport) Conn() interface{} { return nil }
func (m *mockTransport) Close() error      { return nil }
func (m *mockTransport) Healthy() bool     { return true }

// mockClient implements the trustedca.Client interface for testing.
type mockClient struct {
	accountFunc       func() trustedca.AccountClient
	orderFunc         func() trustedca.OrderClient
	authorizationFunc func() trustedca.AuthorizationClient
	challengeFunc     func() trustedca.ChallengeClient
	certificateFunc   func() trustedca.CertificateClient
	directoryFunc     func() trustedca.DirectoryClient
	nonceFunc         func() trustedca.NonceClient
	transportFunc     func() transport.Transport
	closeFunc         func() error
}

func (m *mockClient) Account() trustedca.AccountClient {
	if m.accountFunc != nil {
		return m.accountFunc()
	}
	return nil
}

func (m *mockClient) Order() trustedca.OrderClient {
	if m.orderFunc != nil {
		return m.orderFunc()
	}
	return nil
}

func (m *mockClient) Authorization() trustedca.AuthorizationClient {
	if m.authorizationFunc != nil {
		return m.authorizationFunc()
	}
	return nil
}

func (m *mockClient) Challenge() trustedca.ChallengeClient {
	if m.challengeFunc != nil {
		return m.challengeFunc()
	}
	return nil
}

func (m *mockClient) Certificate() trustedca.CertificateClient {
	if m.certificateFunc != nil {
		return m.certificateFunc()
	}
	return nil
}

func (m *mockClient) Directory() trustedca.DirectoryClient {
	if m.directoryFunc != nil {
		return m.directoryFunc()
	}
	return nil
}

func (m *mockClient) Nonce() trustedca.NonceClient {
	if m.nonceFunc != nil {
		return m.nonceFunc()
	}
	return nil
}

func (m *mockClient) Transport() transport.Transport {
	if m.transportFunc != nil {
		return m.transportFunc()
	}
	return &mockTransport{}
}

func (m *mockClient) Close() error {
	if m.closeFunc != nil {
		return m.closeFunc()
	}
	return nil
}

func (m *mockClient) Admin() trustedca.AdminClient {
	return nil
}

func (m *mockClient) Workflow(opts ...workflow.Option) workflow.Workflow {
	return nil
}

// createTestCertificate creates a self-signed test certificate.
func createTestCertificate() *x509.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)
	return cert
}

// createTestSigner creates a test ECDSA signer.
func createTestSigner() crypto.Signer {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return key
}

func TestNewAdapter(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	t.Run("valid_config", func(t *testing.T) {
		cfg := &Config{
			Transport:      TransportEmbedded,
			RequestTimeout: 30 * time.Second,
		}

		adapter, err := NewAdapter(cfg, logger)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if adapter == nil {
			t.Fatal("expected adapter, got nil")
		}
		if adapter.IsStarted() {
			t.Error("expected adapter to not be started")
		}
		if adapter.IsClosed() {
			t.Error("expected adapter to not be closed")
		}
	})

	t.Run("nil_config", func(t *testing.T) {
		adapter, err := NewAdapter(nil, logger)
		if err != ErrNilConfig {
			t.Errorf("expected ErrNilConfig, got %v", err)
		}
		if adapter != nil {
			t.Error("expected nil adapter")
		}
	})

	t.Run("nil_logger", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportEmbedded,
		}

		adapter, err := NewAdapter(cfg, nil)
		if err != ErrNilLogger {
			t.Errorf("expected ErrNilLogger, got %v", err)
		}
		if adapter != nil {
			t.Error("expected nil adapter")
		}
	})

	t.Run("invalid_config", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportGRPC,
			// Missing Address
		}

		adapter, err := NewAdapter(cfg, logger)
		if err == nil {
			t.Error("expected error for invalid config")
		}
		if adapter != nil {
			t.Error("expected nil adapter")
		}
	})
}

func TestConfig_Validate(t *testing.T) {
	t.Run("embedded_mode_defaults", func(t *testing.T) {
		cfg := &Config{}
		err := cfg.Validate()
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if cfg.Transport != TransportEmbedded {
			t.Errorf("expected transport to be embedded, got %s", cfg.Transport)
		}
		if cfg.RequestTimeout != DefaultRequestTimeout {
			t.Errorf("expected timeout %v, got %v", DefaultRequestTimeout, cfg.RequestTimeout)
		}
	})

	t.Run("remote_mode_inferred", func(t *testing.T) {
		cfg := &Config{
			Backend: "ca-cluster",
			Address: "localhost:8443",
			TLS:     testTLSConfig(),
		}
		err := cfg.Validate()
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if cfg.Transport != TransportGRPC {
			t.Errorf("expected transport to be grpc, got %s", cfg.Transport)
		}
	})

	t.Run("unix_missing_socket", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportUnix,
		}
		err := cfg.Validate()
		if err != ErrMissingUnixSocket {
			t.Errorf("expected ErrMissingUnixSocket, got %v", err)
		}
	})

	t.Run("unix_with_socket", func(t *testing.T) {
		cfg := &Config{
			Transport:  TransportUnix,
			UnixSocket: "/tmp/ca.sock",
		}
		err := cfg.Validate()
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})

	t.Run("grpc_missing_address", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportGRPC,
		}
		err := cfg.Validate()
		if err != ErrMissingAddress {
			t.Errorf("expected ErrMissingAddress, got %v", err)
		}
	})

	t.Run("grpc_with_address", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportGRPC,
			Address:   "localhost:10443",
			TLS:       testTLSConfig(),
		}
		err := cfg.Validate()
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})

	t.Run("rest_missing_address", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportREST,
		}
		err := cfg.Validate()
		if err != ErrMissingAddress {
			t.Errorf("expected ErrMissingAddress, got %v", err)
		}
	})

	t.Run("rest_with_address", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportREST,
			Address:   "https://localhost:8443",
			TLS:       testTLSConfig(),
		}
		err := cfg.Validate()
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})

	t.Run("quic_missing_address", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportQUIC,
		}
		err := cfg.Validate()
		if err != ErrMissingAddress {
			t.Errorf("expected ErrMissingAddress, got %v", err)
		}
	})

	t.Run("quic_with_address", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportQUIC,
			Address:   "localhost:9444",
			TLS:       testTLSConfig(),
		}
		err := cfg.Validate()
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})

	t.Run("mcp_missing_address", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportMCP,
		}
		err := cfg.Validate()
		if err != ErrMissingAddress {
			t.Errorf("expected ErrMissingAddress, got %v", err)
		}
	})

	t.Run("mcp_with_address", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportMCP,
			Address:   "localhost:9445",
			TLS:       testTLSConfig(),
		}
		err := cfg.Validate()
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})

	t.Run("unsupported_transport", func(t *testing.T) {
		cfg := &Config{
			Transport: "invalid",
		}
		err := cfg.Validate()
		if err == nil {
			t.Error("expected error for unsupported transport")
		}
		_, ok := err.(ErrUnsupportedTransport)
		if !ok {
			t.Errorf("expected ErrUnsupportedTransport, got %T", err)
		}
	})
}

func TestConfig_IsEmbedded(t *testing.T) {
	t.Run("empty_config_is_embedded", func(t *testing.T) {
		cfg := &Config{}
		if !cfg.IsEmbedded() {
			t.Error("expected empty config to be embedded")
		}
	})

	t.Run("explicit_embedded", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportEmbedded,
		}
		if !cfg.IsEmbedded() {
			t.Error("expected explicit embedded transport to be embedded")
		}
	})

	t.Run("with_backend_is_remote", func(t *testing.T) {
		cfg := &Config{
			Backend: "ca-cluster",
		}
		if cfg.IsEmbedded() {
			t.Error("expected config with backend to be remote")
		}
		if !cfg.IsRemote() {
			t.Error("expected config with backend to be remote")
		}
	})

	t.Run("grpc_is_remote", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportGRPC,
			Address:   "localhost:10443",
		}
		if cfg.IsEmbedded() {
			t.Error("expected gRPC transport to be remote")
		}
	})
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Transport != TransportEmbedded {
		t.Errorf("expected embedded transport, got %s", cfg.Transport)
	}
	if cfg.RequestTimeout != DefaultRequestTimeout {
		t.Errorf("expected timeout %v, got %v", DefaultRequestTimeout, cfg.RequestTimeout)
	}
}

func TestRemoteConfig(t *testing.T) {
	cfg := RemoteConfig("localhost:8443", TransportREST)
	if cfg.Address != "localhost:8443" {
		t.Errorf("expected address localhost:8443, got %s", cfg.Address)
	}
	if cfg.Transport != TransportREST {
		t.Errorf("expected REST transport, got %s", cfg.Transport)
	}
	if cfg.RequestTimeout != DefaultRequestTimeout {
		t.Errorf("expected timeout %v, got %v", DefaultRequestTimeout, cfg.RequestTimeout)
	}
}

func TestAdapter_NotStarted(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	cfg := &Config{
		Transport: TransportEmbedded,
	}

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// All service accessors should return nil when not started
	if adapter.CA() != nil {
		t.Error("expected CA() to return nil when not started")
	}
	if adapter.Client() != nil {
		t.Error("expected Client() to return nil when not started")
	}
	if adapter.Account() != nil {
		t.Error("expected Account() to return nil when not started")
	}
	if adapter.Order() != nil {
		t.Error("expected Order() to return nil when not started")
	}
	if adapter.Authorization() != nil {
		t.Error("expected Authorization() to return nil when not started")
	}
	if adapter.Challenge() != nil {
		t.Error("expected Challenge() to return nil when not started")
	}
	if adapter.CertificateClient() != nil {
		t.Error("expected CertificateClient() to return nil when not started")
	}
	if adapter.Directory() != nil {
		t.Error("expected Directory() to return nil when not started")
	}
	if adapter.Nonce() != nil {
		t.Error("expected Nonce() to return nil when not started")
	}
}

func TestAdapter_EmbeddedRequiresService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	cfg := &Config{
		Transport: TransportEmbedded,
	}

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Starting embedded without a CA should fail
	err = adapter.Start(context.TODO(), nil)
	if err != ErrEmbeddedServiceRequired {
		t.Errorf("expected ErrEmbeddedServiceRequired, got %v", err)
	}
}

func TestAdapter_Operations_NotStarted(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	cfg := &Config{
		Transport: TransportEmbedded,
	}

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Operations should fail when not started
	_, err = adapter.SignCSR(context.Background(), nil, nil)
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted, got %v", err)
	}

	_, err = adapter.IssueCertificate(context.Background(), nil)
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted for IssueCertificate, got %v", err)
	}

	err = adapter.Revoke(context.Background(), nil, nil)
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted for Revoke, got %v", err)
	}

	_, err = adapter.Verify(nil, nil)
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted for Verify, got %v", err)
	}

	_, err = adapter.CABundle("", 0)
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted for CABundle, got %v", err)
	}

	_, err = adapter.TrustedRoot()
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted for TrustedRoot, got %v", err)
	}

	_, err = adapter.TrustedIntermediate()
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted for TrustedIntermediate, got %v", err)
	}

	_, err = adapter.Signer(context.Background())
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted for Signer, got %v", err)
	}

	_, err = adapter.Certificate(context.Background(), nil)
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted for Certificate, got %v", err)
	}

	err = adapter.ImportCertificate(context.Background(), nil)
	if err != ErrAdapterNotStarted {
		t.Errorf("expected ErrAdapterNotStarted for ImportCertificate, got %v", err)
	}
}

func TestAdapterError(t *testing.T) {
	t.Run("without_cause", func(t *testing.T) {
		err := &AdapterError{
			Op:  "test",
			Msg: "test error",
		}
		expected := "ca adapter test: test error"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("with_cause", func(t *testing.T) {
		cause := &AdapterError{Op: "cause", Msg: "underlying error"}
		err := &AdapterError{
			Op:    "test",
			Msg:   "test error",
			Cause: cause,
		}
		expected := "ca adapter test: test error: ca adapter cause: underlying error"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
		if err.Unwrap() != cause {
			t.Error("expected Unwrap() to return cause")
		}
	})

	t.Run("with_cause_method", func(t *testing.T) {
		base := &AdapterError{
			Op:  "test",
			Msg: "test error",
		}
		cause := &AdapterError{Op: "cause", Msg: "underlying error"}
		err := base.WithCause(cause)
		if err.Cause != cause {
			t.Error("expected WithCause to set cause")
		}
		if err.Op != base.Op {
			t.Error("expected WithCause to preserve Op")
		}
		if err.Msg != base.Msg {
			t.Error("expected WithCause to preserve Msg")
		}
	})
}

func TestErrUnsupportedTransport(t *testing.T) {
	err := ErrUnsupportedTransport{Transport: "invalid"}
	expected := "ca adapter: unsupported transport: invalid"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrConnectionFailed(t *testing.T) {
	t.Run("without_cause", func(t *testing.T) {
		err := ErrConnectionFailed{
			Address:   "localhost:8443",
			Transport: TransportREST,
		}
		expected := "ca adapter: connection failed to localhost:8443 via rest"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("with_cause", func(t *testing.T) {
		cause := &AdapterError{Op: "dial", Msg: "connection refused"}
		err := ErrConnectionFailed{
			Address:   "localhost:8443",
			Transport: TransportREST,
			Cause:     cause,
		}
		expected := "ca adapter: connection failed to localhost:8443 via rest: ca adapter dial: connection refused"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
		if err.Unwrap() != cause {
			t.Error("expected Unwrap() to return cause")
		}
	})
}

func TestErrServiceUnavailable(t *testing.T) {
	err := ErrServiceUnavailable{Service: "CA"}
	expected := "ca adapter: service unavailable: CA"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrBackendNotFound(t *testing.T) {
	err := ErrBackendNotFound{Backend: "ca-cluster"}
	expected := "ca adapter: backend not found: ca-cluster"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrCertificateNotFound(t *testing.T) {
	err := ErrCertificateNotFound{CN: "example.com"}
	expected := "ca adapter: certificate not found: example.com"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrSigningFailed(t *testing.T) {
	t.Run("without_cause", func(t *testing.T) {
		err := ErrSigningFailed{}
		expected := "ca adapter: signing failed"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("with_cause", func(t *testing.T) {
		cause := &AdapterError{Op: "sign", Msg: "key not found"}
		err := ErrSigningFailed{Cause: cause}
		if err.Unwrap() != cause {
			t.Error("expected Unwrap() to return cause")
		}
	})
}

func TestErrRevocationFailed(t *testing.T) {
	t.Run("without_cause", func(t *testing.T) {
		err := ErrRevocationFailed{}
		expected := "ca adapter: revocation failed"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("with_cause", func(t *testing.T) {
		cause := &AdapterError{Op: "revoke", Msg: "certificate not found"}
		err := ErrRevocationFailed{Cause: cause}
		if err.Unwrap() != cause {
			t.Error("expected Unwrap() to return cause")
		}
	})
}

func TestErrVerificationFailed(t *testing.T) {
	t.Run("without_cause", func(t *testing.T) {
		err := ErrVerificationFailed{}
		expected := "ca adapter: verification failed"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("with_cause", func(t *testing.T) {
		cause := &AdapterError{Op: "verify", Msg: "invalid signature"}
		err := ErrVerificationFailed{Cause: cause}
		if err.Unwrap() != cause {
			t.Error("expected Unwrap() to return cause")
		}
	})
}

func TestAdapter_TransportAccessor(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	testCases := []struct {
		name      string
		transport Transport
	}{
		{"embedded", TransportEmbedded},
		{"grpc", TransportGRPC},
		{"rest", TransportREST},
		{"quic", TransportQUIC},
		{"unix", TransportUnix},
		{"mcp", TransportMCP},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var cfg *Config
			switch tc.transport {
			case TransportEmbedded:
				cfg = &Config{Transport: tc.transport}
			case TransportUnix:
				cfg = &Config{Transport: tc.transport, UnixSocket: "/tmp/ca.sock"}
			default:
				cfg = &Config{Transport: tc.transport, Address: "localhost:8443", TLS: testTLSConfig()}
			}

			adapter, err := NewAdapter(cfg, logger)
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			if adapter.Transport() != tc.transport {
				t.Errorf("expected transport %s, got %s", tc.transport, adapter.Transport())
			}
		})
	}
}

func TestAdapter_ConfigAccessor(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	cfg := &Config{
		Transport:      TransportEmbedded,
		RequestTimeout: 60 * time.Second,
		DataDir:        "/var/lib/ca",
	}

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if adapter.Config() != cfg {
		t.Error("expected Config() to return the same config")
	}
}

func TestAdapter_IsEmbedded_IsRemote(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	t.Run("embedded", func(t *testing.T) {
		cfg := &Config{Transport: TransportEmbedded}
		adapter, err := NewAdapter(cfg, logger)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if !adapter.IsEmbedded() {
			t.Error("expected IsEmbedded() to be true")
		}
		if adapter.IsRemote() {
			t.Error("expected IsRemote() to be false")
		}
	})

	t.Run("remote_grpc", func(t *testing.T) {
		cfg := &Config{Transport: TransportGRPC, Address: "localhost:10443", TLS: testTLSConfig()}
		adapter, err := NewAdapter(cfg, logger)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if adapter.IsEmbedded() {
			t.Error("expected IsEmbedded() to be false")
		}
		if !adapter.IsRemote() {
			t.Error("expected IsRemote() to be true")
		}
	})
}

func TestConfig_ACMEConfig(t *testing.T) {
	cfg := &Config{
		Transport: TransportEmbedded,
		ACME: &ACMEConfig{
			ExternalURL:    "https://ca.example.com",
			HTTPSAddr:      ":8443",
			TermsOfService: "https://ca.example.com/tos",
			CAIdentifiers:  []string{"example.com", "ca.example.com"},
		},
	}

	err := cfg.Validate()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if cfg.ACME.ExternalURL != "https://ca.example.com" {
		t.Errorf("expected external URL https://ca.example.com, got %s", cfg.ACME.ExternalURL)
	}
	if cfg.ACME.HTTPSAddr != ":8443" {
		t.Errorf("expected HTTPS addr :8443, got %s", cfg.ACME.HTTPSAddr)
	}
	if len(cfg.ACME.CAIdentifiers) != 2 {
		t.Errorf("expected 2 CA identifiers, got %d", len(cfg.ACME.CAIdentifiers))
	}
}

func TestConfig_TLSConfig(t *testing.T) {
	cfg := &Config{
		Transport: TransportGRPC,
		Address:   "localhost:10443",
		TLS: &TLSConfig{
			CACert:     "/etc/ssl/ca.crt",
			ClientCert: "/etc/ssl/client.crt",
			ClientKey:  "/etc/ssl/client.key",
		},
	}

	err := cfg.Validate()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if cfg.TLS.CACert != "/etc/ssl/ca.crt" {
		t.Errorf("expected CA cert path, got %s", cfg.TLS.CACert)
	}
}

// Test embedded mode start and stop lifecycle
func TestAdapter_EmbeddedLifecycle(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	ctx := context.Background()

	cfg := &Config{
		Transport: TransportEmbedded,
	}

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	mockCA := &mockCertificateAuthority{}

	// Start the adapter
	err = adapter.Start(ctx, mockCA)
	if err != nil {
		t.Fatalf("expected no error on start, got %v", err)
	}

	if !adapter.IsStarted() {
		t.Error("expected adapter to be started")
	}
	if adapter.IsClosed() {
		t.Error("expected adapter to not be closed")
	}

	// Double start should be idempotent
	err = adapter.Start(ctx, mockCA)
	if err != nil {
		t.Fatalf("expected no error on double start, got %v", err)
	}

	// Stop the adapter
	err = adapter.Stop(ctx)
	if err != nil {
		t.Fatalf("expected no error on stop, got %v", err)
	}

	if !adapter.IsClosed() {
		t.Error("expected adapter to be closed")
	}

	// Double stop should be idempotent
	err = adapter.Stop(ctx)
	if err != nil {
		t.Fatalf("expected no error on double stop, got %v", err)
	}

	// Start after close should fail
	err = adapter.Start(ctx, mockCA)
	if err != ErrAdapterClosed {
		t.Errorf("expected ErrAdapterClosed, got %v", err)
	}
}

// Test stop when not started
func TestAdapter_StopNotStarted(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	ctx := context.Background()

	cfg := &Config{
		Transport: TransportEmbedded,
	}

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Stop without start should be no-op
	err = adapter.Stop(ctx)
	if err != nil {
		t.Fatalf("expected no error on stop when not started, got %v", err)
	}
}

// Test embedded CA operations
func TestAdapter_EmbeddedOperations(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	ctx := context.Background()

	testCert := createTestCertificate()
	testSigner := createTestSigner()
	testBundle := []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----")

	cfg := &Config{
		Transport: TransportEmbedded,
	}

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	mockCA := &mockCertificateAuthority{
		signCSRFunc: func(csrPEM []byte, opts *xkmsca.SignOptions) (*x509.Certificate, error) {
			return testCert, nil
		},
		issueCertificateFunc: func(request *xkmsca.CertificateRequest) (*xkmsca.IssuedCertificate, error) {
			return &xkmsca.IssuedCertificate{Certificate: testCert}, nil
		},
		revokeFunc: func(_ *x509.Certificate, _ xkmsca.RevokeOptions) error {
			return nil
		},
		verifyFunc: func(certificate *x509.Certificate, _ ...crypto.Signer) ([][]*x509.Certificate, error) {
			return [][]*x509.Certificate{{testCert}}, nil
		},
		caBundleFunc: func(storeType xkmssdk.StoreType, keyAlgorithm x509.PublicKeyAlgorithm) ([]byte, error) {
			return testBundle, nil
		},
		trustedRootFunc: func() (*x509.Certificate, error) {
			return testCert, nil
		},
		trustedIntermediateFunc: func() (*x509.Certificate, error) {
			return testCert, nil
		},
		signerFunc: func() (crypto.Signer, error) {
			return testSigner, nil
		},
		certificateFunc: func(attrs *xkmssdk.KeyAttributes) (*x509.Certificate, error) {
			return testCert, nil
		},
		importCertificateFunc: func(certificate *x509.Certificate) error {
			return nil
		},
	}

	err = adapter.Start(ctx, mockCA)
	if err != nil {
		t.Fatalf("expected no error on start, got %v", err)
	}

	t.Run("SignCSR", func(t *testing.T) {
		cert, err := adapter.SignCSR(ctx, []byte("csr"), &CertificateRequest{})
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if cert != testCert {
			t.Error("expected test cert to be returned")
		}
	})

	t.Run("SignCSR_nil_request", func(t *testing.T) {
		// Guards against the nil-deref regression at adapter.go:312.
		_, err := adapter.SignCSR(ctx, []byte("csr"), nil)
		if err != ErrNilRequest {
			t.Errorf("expected ErrNilRequest, got %v", err)
		}
	})

	t.Run("IssueCertificate", func(t *testing.T) {
		cert, err := adapter.IssueCertificate(ctx, &CertificateRequest{})
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if cert != testCert {
			t.Error("expected test cert to be returned")
		}
	})

	t.Run("IssueCertificate_nil_request", func(t *testing.T) {
		_, err := adapter.IssueCertificate(ctx, nil)
		if err != ErrNilRequest {
			t.Errorf("expected ErrNilRequest, got %v", err)
		}
	})

	t.Run("Revoke", func(t *testing.T) {
		err := adapter.Revoke(ctx, testCert, nil)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})

	t.Run("Verify", func(t *testing.T) {
		chains, err := adapter.Verify(testCert, nil)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if len(chains) != 1 {
			t.Errorf("expected 1 chain, got %d", len(chains))
		}
	})

	t.Run("CABundle", func(t *testing.T) {
		bundle, err := adapter.CABundle("", 0)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if string(bundle) != string(testBundle) {
			t.Error("expected test bundle to be returned")
		}
	})

	t.Run("TrustedRoot", func(t *testing.T) {
		cert, err := adapter.TrustedRoot()
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if cert != testCert {
			t.Error("expected test cert to be returned")
		}
	})

	t.Run("TrustedIntermediate", func(t *testing.T) {
		cert, err := adapter.TrustedIntermediate()
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if cert != testCert {
			t.Error("expected test cert to be returned")
		}
	})

	t.Run("Signer", func(t *testing.T) {
		signer, err := adapter.Signer(ctx)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if signer != testSigner {
			t.Error("expected test signer to be returned")
		}
	})

	t.Run("Certificate", func(t *testing.T) {
		cert, err := adapter.Certificate(context.Background(), nil)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if cert != testCert {
			t.Error("expected test cert to be returned")
		}
	})

	t.Run("ImportCertificate", func(t *testing.T) {
		err := adapter.ImportCertificate(context.Background(), testCert)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})

	t.Run("CA", func(t *testing.T) {
		ca := adapter.CA()
		if ca == nil {
			t.Error("expected CA to be returned")
		}
	})
}

// Test embedded operations with nil embedded CA (edge case)
func TestAdapter_EmbeddedOperations_NilCA(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	cfg := &Config{
		Transport: TransportEmbedded,
	}

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Manually set started without embedded CA to test nil checks
	adapter.started.Store(true)

	t.Run("SignCSR_nil_embedded", func(t *testing.T) {
		_, err := adapter.SignCSR(context.Background(), nil, nil)
		if err != ErrCANotInitialized {
			t.Errorf("expected ErrCANotInitialized, got %v", err)
		}
	})

	t.Run("IssueCertificate_nil_embedded", func(t *testing.T) {
		_, err := adapter.IssueCertificate(context.Background(), nil)
		if err != ErrCANotInitialized {
			t.Errorf("expected ErrCANotInitialized, got %v", err)
		}
	})

	t.Run("Revoke_nil_embedded", func(t *testing.T) {
		err := adapter.Revoke(context.Background(), nil, nil)
		if err != ErrCANotInitialized {
			t.Errorf("expected ErrCANotInitialized, got %v", err)
		}
	})

	t.Run("Verify_nil_embedded", func(t *testing.T) {
		_, err := adapter.Verify(nil, nil)
		if err != ErrCANotInitialized {
			t.Errorf("expected ErrCANotInitialized, got %v", err)
		}
	})

	t.Run("CABundle_nil_embedded", func(t *testing.T) {
		_, err := adapter.CABundle("", 0)
		if err != ErrCANotInitialized {
			t.Errorf("expected ErrCANotInitialized, got %v", err)
		}
	})

	t.Run("TrustedRoot_nil_embedded", func(t *testing.T) {
		_, err := adapter.TrustedRoot()
		if err != ErrCANotInitialized {
			t.Errorf("expected ErrCANotInitialized, got %v", err)
		}
	})

	t.Run("TrustedIntermediate_nil_embedded", func(t *testing.T) {
		_, err := adapter.TrustedIntermediate()
		if err != ErrCANotInitialized {
			t.Errorf("expected ErrCANotInitialized, got %v", err)
		}
	})

	t.Run("Signer_nil_embedded", func(t *testing.T) {
		_, err := adapter.Signer(context.Background())
		if err != ErrCANotInitialized {
			t.Errorf("expected ErrCANotInitialized, got %v", err)
		}
	})

	t.Run("Certificate_nil_embedded", func(t *testing.T) {
		_, err := adapter.Certificate(context.Background(), nil)
		if err != ErrCANotInitialized {
			t.Errorf("expected ErrCANotInitialized, got %v", err)
		}
	})

	t.Run("ImportCertificate_nil_embedded", func(t *testing.T) {
		err := adapter.ImportCertificate(context.Background(), nil)
		if err != ErrCANotInitialized {
			t.Errorf("expected ErrCANotInitialized, got %v", err)
		}
	})
}

// Test operations on closed adapter
func TestAdapter_Operations_Closed(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	ctx := context.Background()

	cfg := &Config{
		Transport: TransportEmbedded,
	}

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	mockCA := &mockCertificateAuthority{}
	err = adapter.Start(ctx, mockCA)
	if err != nil {
		t.Fatalf("expected no error on start, got %v", err)
	}

	err = adapter.Stop(ctx)
	if err != nil {
		t.Fatalf("expected no error on stop, got %v", err)
	}

	// All operations should fail when closed
	_, err = adapter.SignCSR(ctx, nil, nil)
	if err != ErrAdapterClosed {
		t.Errorf("expected ErrAdapterClosed for SignCSR, got %v", err)
	}

	_, err = adapter.IssueCertificate(ctx, nil)
	if err != ErrAdapterClosed {
		t.Errorf("expected ErrAdapterClosed for IssueCertificate, got %v", err)
	}

	err = adapter.Revoke(ctx, nil, nil)
	if err != ErrAdapterClosed {
		t.Errorf("expected ErrAdapterClosed for Revoke, got %v", err)
	}

	_, err = adapter.Verify(nil, nil)
	if err != ErrAdapterClosed {
		t.Errorf("expected ErrAdapterClosed for Verify, got %v", err)
	}

	_, err = adapter.CABundle("", 0)
	if err != ErrAdapterClosed {
		t.Errorf("expected ErrAdapterClosed for CABundle, got %v", err)
	}

	_, err = adapter.TrustedRoot()
	if err != ErrAdapterClosed {
		t.Errorf("expected ErrAdapterClosed for TrustedRoot, got %v", err)
	}

	_, err = adapter.TrustedIntermediate()
	if err != ErrAdapterClosed {
		t.Errorf("expected ErrAdapterClosed for TrustedIntermediate, got %v", err)
	}

	_, err = adapter.Signer(ctx)
	if err != ErrAdapterClosed {
		t.Errorf("expected ErrAdapterClosed for Signer, got %v", err)
	}

	_, err = adapter.Certificate(ctx, nil)
	if err != ErrAdapterClosed {
		t.Errorf("expected ErrAdapterClosed for Certificate, got %v", err)
	}

	err = adapter.ImportCertificate(ctx, nil)
	if err != ErrAdapterClosed {
		t.Errorf("expected ErrAdapterClosed for ImportCertificate, got %v", err)
	}

	// Accessors should return nil when closed
	if adapter.CA() != nil {
		t.Error("expected CA() to return nil when closed")
	}
	if adapter.Client() != nil {
		t.Error("expected Client() to return nil when closed")
	}
}

// Test remote mode operations return appropriate errors
func TestAdapter_RemoteOperations_NotSupported(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	cfg := &Config{
		Transport: TransportGRPC,
		Address:   "localhost:10443",
		TLS:       testTLSConfig(),
	}

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Manually set started and client to test remote mode operations
	adapter.started.Store(true)
	adapter.client = &mockClient{}

	t.Run("SignCSR_remote", func(t *testing.T) {
		_, err := adapter.SignCSR(context.Background(), nil, nil)
		if err == nil {
			t.Error("expected error for SignCSR in remote mode")
		}
		adapterErr, ok := err.(*AdapterError)
		if !ok {
			t.Errorf("expected *AdapterError, got %T", err)
		}
		if adapterErr.Op != "SignCSR" {
			t.Errorf("expected op SignCSR, got %s", adapterErr.Op)
		}
	})

	t.Run("IssueCertificate_remote", func(t *testing.T) {
		_, err := adapter.IssueCertificate(context.Background(), nil)
		if err == nil {
			t.Error("expected error for IssueCertificate in remote mode")
		}
		adapterErr, ok := err.(*AdapterError)
		if !ok {
			t.Errorf("expected *AdapterError, got %T", err)
		}
		if adapterErr.Op != "IssueCertificate" {
			t.Errorf("expected op IssueCertificate, got %s", adapterErr.Op)
		}
	})

	t.Run("Revoke_remote", func(t *testing.T) {
		err := adapter.Revoke(context.Background(), nil, nil)
		if err == nil {
			t.Error("expected error for Revoke in remote mode")
		}
		adapterErr, ok := err.(*AdapterError)
		if !ok {
			t.Errorf("expected *AdapterError, got %T", err)
		}
		if adapterErr.Op != "Revoke" {
			t.Errorf("expected op Revoke, got %s", adapterErr.Op)
		}
	})

	t.Run("Verify_remote", func(t *testing.T) {
		_, err := adapter.Verify(nil, nil)
		if err == nil {
			t.Error("expected error for Verify in remote mode")
		}
		adapterErr, ok := err.(*AdapterError)
		if !ok {
			t.Errorf("expected *AdapterError, got %T", err)
		}
		if adapterErr.Op != "Verify" {
			t.Errorf("expected op Verify, got %s", adapterErr.Op)
		}
	})

	t.Run("CABundle_remote", func(t *testing.T) {
		_, err := adapter.CABundle("", 0)
		if err == nil {
			t.Error("expected error for CABundle in remote mode")
		}
		adapterErr, ok := err.(*AdapterError)
		if !ok {
			t.Errorf("expected *AdapterError, got %T", err)
		}
		if adapterErr.Op != "CABundle" {
			t.Errorf("expected op CABundle, got %s", adapterErr.Op)
		}
	})

	t.Run("TrustedRoot_remote", func(t *testing.T) {
		_, err := adapter.TrustedRoot()
		if err == nil {
			t.Error("expected error for TrustedRoot in remote mode")
		}
		adapterErr, ok := err.(*AdapterError)
		if !ok {
			t.Errorf("expected *AdapterError, got %T", err)
		}
		if adapterErr.Op != "TrustedRoot" {
			t.Errorf("expected op TrustedRoot, got %s", adapterErr.Op)
		}
	})

	t.Run("TrustedIntermediate_remote", func(t *testing.T) {
		_, err := adapter.TrustedIntermediate()
		if err == nil {
			t.Error("expected error for TrustedIntermediate in remote mode")
		}
		adapterErr, ok := err.(*AdapterError)
		if !ok {
			t.Errorf("expected *AdapterError, got %T", err)
		}
		if adapterErr.Op != "TrustedIntermediate" {
			t.Errorf("expected op TrustedIntermediate, got %s", adapterErr.Op)
		}
	})

	t.Run("Signer_remote", func(t *testing.T) {
		_, err := adapter.Signer(context.Background())
		if err == nil {
			t.Error("expected error for Signer in remote mode")
		}
		adapterErr, ok := err.(*AdapterError)
		if !ok {
			t.Errorf("expected *AdapterError, got %T", err)
		}
		if adapterErr.Op != "Signer" {
			t.Errorf("expected op Signer, got %s", adapterErr.Op)
		}
	})

	t.Run("Certificate_remote", func(t *testing.T) {
		_, err := adapter.Certificate(context.Background(), nil)
		if err == nil {
			t.Error("expected error for Certificate in remote mode")
		}
		adapterErr, ok := err.(*AdapterError)
		if !ok {
			t.Errorf("expected *AdapterError, got %T", err)
		}
		if adapterErr.Op != "Certificate" {
			t.Errorf("expected op Certificate, got %s", adapterErr.Op)
		}
	})

	t.Run("ImportCertificate_remote", func(t *testing.T) {
		err := adapter.ImportCertificate(context.Background(), nil)
		if err == nil {
			t.Error("expected error for ImportCertificate in remote mode")
		}
		adapterErr, ok := err.(*AdapterError)
		if !ok {
			t.Errorf("expected *AdapterError, got %T", err)
		}
		if adapterErr.Op != "ImportCertificate" {
			t.Errorf("expected op ImportCertificate, got %s", adapterErr.Op)
		}
	})
}

// Test ACME client accessors with mock client
func TestAdapter_ACMEClientAccessors(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	cfg := &Config{
		Transport: TransportGRPC,
		Address:   "localhost:10443",
		TLS:       testTLSConfig(),
	}

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Set up mock client
	mockAccountClient := struct{ trustedca.AccountClient }{}
	mockOrderClient := struct{ trustedca.OrderClient }{}
	mockAuthorizationClient := struct{ trustedca.AuthorizationClient }{}
	mockChallengeClient := struct{ trustedca.ChallengeClient }{}
	mockCertificateClient := struct{ trustedca.CertificateClient }{}
	mockDirectoryClient := struct{ trustedca.DirectoryClient }{}
	mockNonceClient := struct{ trustedca.NonceClient }{}

	mc := &mockClient{
		accountFunc:       func() trustedca.AccountClient { return mockAccountClient },
		orderFunc:         func() trustedca.OrderClient { return mockOrderClient },
		authorizationFunc: func() trustedca.AuthorizationClient { return mockAuthorizationClient },
		challengeFunc:     func() trustedca.ChallengeClient { return mockChallengeClient },
		certificateFunc:   func() trustedca.CertificateClient { return mockCertificateClient },
		directoryFunc:     func() trustedca.DirectoryClient { return mockDirectoryClient },
		nonceFunc:         func() trustedca.NonceClient { return mockNonceClient },
	}

	adapter.started.Store(true)
	adapter.client = mc

	t.Run("Account", func(t *testing.T) {
		if adapter.Account() != mockAccountClient {
			t.Error("expected mock account client")
		}
	})

	t.Run("Order", func(t *testing.T) {
		if adapter.Order() != mockOrderClient {
			t.Error("expected mock order client")
		}
	})

	t.Run("Authorization", func(t *testing.T) {
		if adapter.Authorization() != mockAuthorizationClient {
			t.Error("expected mock authorization client")
		}
	})

	t.Run("Challenge", func(t *testing.T) {
		if adapter.Challenge() != mockChallengeClient {
			t.Error("expected mock challenge client")
		}
	})

	t.Run("CertificateClient", func(t *testing.T) {
		if adapter.CertificateClient() != mockCertificateClient {
			t.Error("expected mock certificate client")
		}
	})

	t.Run("Directory", func(t *testing.T) {
		if adapter.Directory() != mockDirectoryClient {
			t.Error("expected mock directory client")
		}
	})

	t.Run("Nonce", func(t *testing.T) {
		if adapter.Nonce() != mockNonceClient {
			t.Error("expected mock nonce client")
		}
	})

	t.Run("Client", func(t *testing.T) {
		if adapter.Client() != mc {
			t.Error("expected mock client")
		}
	})
}

// Test stop with client close error
func TestAdapter_Stop_ClientCloseError(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	ctx := context.Background()

	cfg := &Config{
		Transport: TransportGRPC,
		Address:   "localhost:10443",
		TLS:       testTLSConfig(),
	}

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	closeErr := &AdapterError{Op: "close", Msg: "connection reset"}
	mc := &mockClient{
		closeFunc: func() error { return closeErr },
	}

	adapter.started.Store(true)
	adapter.client = mc

	err = adapter.Stop(ctx)
	if err != closeErr {
		t.Errorf("expected close error, got %v", err)
	}
}

// Test concurrent start calls
func TestAdapter_ConcurrentStart(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	ctx := context.Background()

	cfg := &Config{
		Transport: TransportEmbedded,
	}

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	mockCA := &mockCertificateAuthority{}

	done := make(chan struct{})
	errors := make(chan error, 10)

	// Start multiple goroutines that all try to start the adapter
	for i := 0; i < 10; i++ {
		go func() {
			err := adapter.Start(ctx, mockCA)
			if err != nil {
				errors <- err
			}
			done <- struct{}{}
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
	close(errors)

	// Check for any errors
	for err := range errors {
		t.Errorf("unexpected error during concurrent start: %v", err)
	}

	if !adapter.IsStarted() {
		t.Error("expected adapter to be started")
	}
}

// Test createClient with various transport configurations
func TestAdapter_CreateClient_MissingSocket(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	// Test Unix transport missing socket (validation catches this, but test createUnixClient directly)
	cfg := &Config{
		Transport:  TransportUnix,
		UnixSocket: "/tmp/ca.sock",
	}
	cfg.Validate()

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Clear socket to test error path in createUnixClient
	adapter.config.UnixSocket = ""

	_, err = adapter.createUnixClient(nil)
	if err != ErrMissingUnixSocket {
		t.Errorf("expected ErrMissingUnixSocket, got %v", err)
	}
}

func TestAdapter_CreateClient_MissingAddress(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	transports := []Transport{TransportGRPC, TransportREST, TransportQUIC, TransportMCP}

	for _, transport := range transports {
		t.Run(string(transport), func(t *testing.T) {
			cfg := &Config{
				Transport: transport,
				Address:   "localhost:8443",
				TLS:       testTLSConfig(),
			}
			cfg.Validate()

			adapter, err := NewAdapter(cfg, logger)
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			// Clear address to test error path
			adapter.config.Address = ""

			var createErr error
			switch transport {
			case TransportGRPC:
				_, createErr = adapter.createGRPCClient(nil)
			case TransportREST:
				_, createErr = adapter.createRESTClient(nil)
			case TransportQUIC:
				_, createErr = adapter.createQUICClient(nil)
			case TransportMCP:
				_, createErr = adapter.createMCPClient(nil)
			}

			if createErr != ErrMissingAddress {
				t.Errorf("expected ErrMissingAddress, got %v", createErr)
			}
		})
	}
}

func TestAdapter_CreateClient_UnsupportedTransport(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	cfg := &Config{
		Transport: TransportEmbedded,
	}
	cfg.Validate()

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Set unsupported transport
	adapter.config.Transport = "invalid"

	_, err = adapter.createClient()
	if err == nil {
		t.Error("expected error for unsupported transport")
	}
	_, ok := err.(ErrUnsupportedTransport)
	if !ok {
		t.Errorf("expected ErrUnsupportedTransport, got %T", err)
	}
}

// Test createClient with TLS config
func TestAdapter_CreateClient_WithTLS(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	t.Run("with_tls_config", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportGRPC,
			Address:   "localhost:10443",
			TLS: &TLSConfig{
				CACert:     "/etc/ssl/ca.crt",
				ClientCert: "/etc/ssl/client.crt",
				ClientKey:  "/etc/ssl/client.key",
			},
		}

		adapter, err := NewAdapter(cfg, logger)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		// createClient will fail because files don't exist, but we're testing
		// that the TLS config path is exercised
		_, err = adapter.createClient()
		// Error expected because cert files don't exist
		if err == nil {
			t.Log("Note: createClient succeeded despite missing cert files")
		}
	})

	t.Run("with_timeout", func(t *testing.T) {
		cfg := &Config{
			Transport:      TransportGRPC,
			Address:        "localhost:10443",
			RequestTimeout: 5 * time.Second,
			TLS:            testTLSConfig(),
		}

		adapter, err := NewAdapter(cfg, logger)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		// createClient will try to connect
		_, err = adapter.createClient()
		// Error expected because no server is listening
		if err == nil {
			t.Log("Note: createClient succeeded despite no server")
		}
	})
}
