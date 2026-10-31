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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"net/url"
	"os"
	"testing"
	"time"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	xkmsca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca/issuance"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func createTestLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelError, os.Stderr)
}

// testCA holds certificate and key for testing
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// Helper to create a self-signed CA certificate with key
func createTestCAWithKey(t *testing.T, cn string) *testCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %v", err)
	}

	return &testCA{cert: cert, key: key}
}

// createIntermediateCAWithKey creates an intermediate CA signed by the parent CA
func createIntermediateCAWithKey(t *testing.T, cn string, parent *testCA) *testCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, parent.cert, &key.PublicKey, parent.key)
	if err != nil {
		t.Fatalf("failed to create intermediate CA certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse intermediate CA certificate: %v", err)
	}

	return &testCA{cert: cert, key: key}
}

// createCertSignedByCA creates a certificate signed by the given CA
func createCertSignedByCA(t *testing.T, cn string, ca *testCA) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:         cn,
			Organization:       []string{"Test Org"},
			OrganizationalUnit: []string{"Test Unit"},
			Country:            []string{"US"},
			Province:           []string{"CA"},
			Locality:           []string{"San Francisco"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{cn, "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("192.168.1.1")},
		EmailAddresses:        []string{"test@example.com"},
	}

	// Add URI SANs
	uri, _ := url.Parse("https://example.com/test")
	template.URIs = []*url.URL{uri}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}

// createExpiredCertSignedByCA creates an expired certificate signed by the given CA
func createExpiredCertSignedByCA(t *testing.T, ca *testCA) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   "expired.example.com",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}

// createFutureCertSignedByCA creates a not-yet-valid certificate signed by the given CA
func createFutureCertSignedByCA(t *testing.T, ca *testCA) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   "future.example.com",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(24 * time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}

func assertGRPCError(t *testing.T, err error, expectedCode codes.Code) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T: %v", err, err)
	}

	if st.Code() != expectedCode {
		t.Errorf("expected code %v, got %v: %s", expectedCode, st.Code(), st.Message())
	}
}

// mockCertStore is a simple mock for the cert store interface
type mockCertStore struct {
	certs    map[string]*x509.Certificate
	listErr  error
	getError error
}

func newMockCertStore() *mockCertStore {
	return &mockCertStore{
		certs: make(map[string]*x509.Certificate),
	}
}

func (m *mockCertStore) GetCertificate(id string) (*x509.Certificate, error) {
	if m.getError != nil {
		return nil, m.getError
	}
	if cert, ok := m.certs[id]; ok {
		return cert, nil
	}
	return nil, errors.New("certificate not found")
}

func (m *mockCertStore) StoreCertificate(cert *x509.Certificate) error {
	return nil
}

func (m *mockCertStore) DeleteCertificate(id string) error {
	return nil
}

func (m *mockCertStore) ListCertificates() ([]*x509.Certificate, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	var certs []*x509.Certificate
	for _, cert := range m.certs {
		certs = append(certs, cert)
	}
	return certs, nil
}

func (m *mockCertStore) StoreCertificateChain(chain []*x509.Certificate) error {
	return nil
}

func (m *mockCertStore) GetCertificateChain(cn string) ([]*x509.Certificate, error) {
	return nil, errors.New("chain not found")
}

func (m *mockCertStore) StoreCRL(crl *x509.RevocationList) error {
	return nil
}

func (m *mockCertStore) GetCRL(issuer string) (*x509.RevocationList, error) {
	return nil, errors.New("CRL not found")
}

func (m *mockCertStore) VerifyCertificate(cert *x509.Certificate, roots *x509.CertPool) error {
	return nil
}

func (m *mockCertStore) IsRevoked(cert *x509.Certificate) (bool, error) {
	return false, nil
}

func (m *mockCertStore) Close() error {
	return nil
}

// configurableMockCA is a mock CA with configurable responses.
// It implements ca.TCGCA by embedding baseMockCA and overriding only
// the methods each test case exercises.
type configurableMockCA struct {
	baseMockCA
	// issuedProfile is the profile the last IssueCertificateWithProfile got.
	issuedProfile   string
	isInitialized   bool
	identity        string
	defaultKeyAlg   x509.PublicKeyAlgorithm
	defaultValidity int
	trustedRoot     *x509.Certificate
	trustedInter    *x509.Certificate
	issuedCert      *x509.Certificate
	issueCertErr    error
	revokeErr       error
	bundleErr       error
	bundle          []byte
	parsedBundle    []*x509.Certificate
	certStore       xkmssdk.CertStore
	// caCertificate, when set, is the issuing CA certificate a subordinate
	// CA request is checked against; otherwise the base mock's unconstrained
	// CA answers.
	caCertificate *x509.Certificate
}

func (m *configurableMockCA) CACertificate() (*x509.Certificate, error) {
	if m.caCertificate != nil {
		return m.caCertificate, nil
	}
	return m.baseMockCA.CACertificate()
}

func (m *configurableMockCA) IsInitialized() bool { return m.isInitialized }
func (m *configurableMockCA) Identity() string    { return m.identity }
func (m *configurableMockCA) DefaultKeyAlgorithm() x509.PublicKeyAlgorithm {
	return m.defaultKeyAlg
}
func (m *configurableMockCA) DefaultValidityPeriod() int { return m.defaultValidity }
func (m *configurableMockCA) TrustedRoot() (*x509.Certificate, error) {
	return m.trustedRoot, nil
}
func (m *configurableMockCA) TrustedIntermediate() (*x509.Certificate, error) {
	return m.trustedInter, nil
}
func (m *configurableMockCA) CABundle() ([]byte, error) {
	if m.bundleErr != nil {
		return nil, m.bundleErr
	}
	return m.bundle, nil
}
func (m *configurableMockCA) CABundleFiltered(_ xkmssdk.StoreType, _ x509.PublicKeyAlgorithm) ([]byte, error) {
	if m.bundleErr != nil {
		return nil, m.bundleErr
	}
	return m.bundle, nil
}
func (m *configurableMockCA) ParseBundle(_ []byte) ([]*x509.Certificate, error) {
	return m.parsedBundle, nil
}
func (m *configurableMockCA) IssueCertificate(_ context.Context, _ *xkmsca.CACertificateRequest) (*xkmsca.IssuedCertificate, error) {
	if m.issueCertErr != nil {
		return nil, m.issueCertErr
	}
	if m.issuedCert == nil {
		return nil, nil
	}
	return &xkmsca.IssuedCertificate{Certificate: m.issuedCert}, nil
}

// IssueCertificateWithProfile records the profile and issues as IssueCertificate.
func (m *configurableMockCA) IssueCertificateWithProfile(ctx context.Context, req *xkmsca.CACertificateRequest, profile string) (*xkmsca.IssuedCertificate, error) {
	m.issuedProfile = profile
	return m.IssueCertificate(ctx, req)
}
func (m *configurableMockCA) RevokeCert(_ context.Context, _ *x509.Certificate, _ xkmsca.RevokeOptions) error {
	return m.revokeErr
}
func (m *configurableMockCA) CertStore() xkmssdk.CertStore { return m.certStore }

// Test cases

func TestNewCAGRPCService(t *testing.T) {
	t.Parallel()

	logger := createTestLogger()
	mockCA := &configurableMockCA{}

	service := NewCAGRPCService(logger, mockCA, nil)

	if service == nil {
		t.Fatal("expected non-nil service")
	}
}

func TestGetCAInfo_NilCA(t *testing.T) {
	t.Parallel()

	logger := createTestLogger()
	service := NewCAGRPCService(logger, nil, nil)
	ctx := context.Background()

	_, err := service.GetCAInfo(ctx, &platformv1.GetCAInfoRequest{})
	assertGRPCError(t, err, codes.FailedPrecondition)
}

func TestGetCAInfo_Success(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test Root CA")
	intermediateCA := createIntermediateCAWithKey(t, "Test Intermediate CA", rootCA)

	mockCA := &configurableMockCA{
		isInitialized:   true,
		identity:        "test-ca",
		defaultKeyAlg:   x509.ECDSA,
		defaultValidity: 365,
		trustedRoot:     rootCA.cert,
		trustedInter:    intermediateCA.cert,
	}

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA, nil)
	ctx := context.Background()

	resp, err := svc.GetCAInfo(ctx, &platformv1.GetCAInfoRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if !resp.CaInfo.IsInitialized {
		t.Error("expected CA to be initialized")
	}
	if resp.CaInfo.CommonName != "test-ca" {
		t.Errorf("expected CN 'test-ca', got %q", resp.CaInfo.CommonName)
	}
	if resp.CaInfo.DefaultAlgorithm != "ECDSA" {
		t.Errorf("expected algorithm ECDSA, got %q", resp.CaInfo.DefaultAlgorithm)
	}
	if !resp.CaInfo.IsIntermediate {
		t.Error("expected IsIntermediate to be true")
	}
}

func TestGetCAInfo_NotInitialized(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{
		isInitialized: false,
	}

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA, nil)
	ctx := context.Background()

	resp, err := svc.GetCAInfo(ctx, &platformv1.GetCAInfoRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.CaInfo.IsInitialized {
		t.Error("expected CA not to be initialized")
	}
}

func TestIssueCertificate_NilCA(t *testing.T) {
	t.Parallel()

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, nil, nil)
	ctx := context.Background()

	_, err := svc.IssueCertificate(ctx, &platformv1.IssueCertificateRequest{})
	assertGRPCError(t, err, codes.FailedPrecondition)
}

func TestIssueCertificate_MissingRequest(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{}
	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA, nil)
	ctx := context.Background()

	_, err := svc.IssueCertificate(ctx, &platformv1.IssueCertificateRequest{})
	assertGRPCError(t, err, codes.InvalidArgument)
}

func TestIssueCertificate_MissingSubject(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{}
	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA, nil)
	ctx := context.Background()

	_, err := svc.IssueCertificate(ctx, &platformv1.IssueCertificateRequest{
		Request: &platformv1.CertificateRequest{},
	})
	assertGRPCError(t, err, codes.InvalidArgument)
}

func TestIssueCertificate_MissingCommonName(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{}
	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA, nil)
	ctx := context.Background()

	_, err := svc.IssueCertificate(ctx, &platformv1.IssueCertificateRequest{
		Request: &platformv1.CertificateRequest{
			Subject: &platformv1.Subject{},
		},
	})
	assertGRPCError(t, err, codes.InvalidArgument)
}

func TestIssueCertificate_Success(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test Root CA")
	issuedCert := createCertSignedByCA(t, "test.example.com", rootCA)

	mockCA := &configurableMockCA{
		issuedCert: issuedCert,
	}

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA, nil)
	ctx := context.Background()

	resp, err := svc.IssueCertificate(ctx, &platformv1.IssueCertificateRequest{
		Request: &platformv1.CertificateRequest{
			Subject: &platformv1.Subject{
				CommonName:   "test.example.com",
				Organization: "Test Org",
				Country:      "US",
			},
			KeyAlgorithm: platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256,
			ValidDays:    365,
			KeyUsage:     []string{"DIGITAL_SIGNATURE", "KEY_ENCIPHERMENT"},
			ExtKeyUsage:  []string{"SERVER_AUTH", "CLIENT_AUTH"},
			Sans: &platformv1.SubjectAlternativeNames{
				DnsNames:    []string{"test.example.com", "www.example.com"},
				IpAddresses: []string{"192.168.1.1"},
			},
			StoreType: "software",
		},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Status.Success {
		t.Error("expected success status")
	}
	if resp.Certificate == nil {
		t.Error("expected certificate in response")
	}
}

// TestIssueCertificate_CARequestUsesCAProfile checks an is_ca request is
// signed with the go-xkms CA profile, not the default leaf profile.
func TestIssueCertificate_CARequestUsesCAProfile(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test Root CA")
	mockCA := &configurableMockCA{issuedCert: createCertSignedByCA(t, "sub-ca.example.com", rootCA)}
	svc := NewCAGRPCService(createTestLogger(), mockCA, nil)

	resp, err := svc.IssueCertificate(context.Background(), &platformv1.IssueCertificateRequest{
		Request: &platformv1.CertificateRequest{
			Subject:      &platformv1.Subject{CommonName: "sub-ca.example.com"},
			KeyAlgorithm: platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256,
			IsCa:         true,
			MaxPathLen:   1,
			StoreType:    "software",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Status.Success {
		t.Error("expected success status")
	}
	if mockCA.issuedProfile != "ca" {
		t.Errorf("issued with profile %q, want the CA profile %q", mockCA.issuedProfile, "ca")
	}
}

func TestIssueCertificate_Error(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{
		issueCertErr: errors.New("failed to issue"),
	}

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA, nil)
	ctx := context.Background()

	_, err := svc.IssueCertificate(ctx, &platformv1.IssueCertificateRequest{
		Request: &platformv1.CertificateRequest{
			Subject: &platformv1.Subject{
				CommonName: "test.example.com",
			},
		},
	})
	assertGRPCError(t, err, codes.Internal)
}

// subCARequest asks for a subordinate CA certificate with pathLen 0.
func subCARequest() *platformv1.IssueCertificateRequest {
	return &platformv1.IssueCertificateRequest{Request: &platformv1.CertificateRequest{
		Subject:      &platformv1.Subject{CommonName: "sub-ca.example.com"},
		KeyAlgorithm: platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256,
		StoreType:    "software",
		IsCa:         true,
	}}
}

// A subordinate CA beneath a pathLen-0 issuer is the caller's error:
// InvalidArgument with the refusal's message, and the CA is never asked.
func TestIssueCertificate_PathLenRefusalIsInvalidArgument(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{caCertificate: &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Issuing CA"},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}}
	svc := NewCAGRPCService(createTestLogger(), mockCA, nil)

	_, err := svc.IssueCertificate(context.Background(), subCARequest())

	assertGRPCError(t, err, codes.InvalidArgument)
	want := (&issuance.IssuerPathLenExhaustedError{Issuer: "CN=Issuing CA"}).Error()
	if got := status.Convert(err).Message(); got != want {
		t.Errorf("message = %q, want %q", got, want)
	}
	if mockCA.issuedProfile != "" {
		t.Errorf("the CA was asked to issue with profile %q", mockCA.issuedProfile)
	}
}

// A CA fault on a subordinate CA request stays a server error.
func TestIssueCertificate_CAFaultIsInternal(t *testing.T) {
	t.Parallel()

	svc := NewCAGRPCService(createTestLogger(), &configurableMockCA{issueCertErr: errors.New("hsm offline")}, nil)

	_, err := svc.IssueCertificate(context.Background(), subCARequest())

	assertGRPCError(t, err, codes.Internal)
}

func TestGetCertificate_NilCA(t *testing.T) {
	t.Parallel()

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, nil, nil)
	ctx := context.Background()

	_, err := svc.GetCertificate(ctx, &platformv1.GetCertificateRequest{Serial: "test"})
	assertGRPCError(t, err, codes.FailedPrecondition)
}

func TestGetCertificate_MissingSerial(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{}
	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA, nil)
	ctx := context.Background()

	_, err := svc.GetCertificate(ctx, &platformv1.GetCertificateRequest{})
	assertGRPCError(t, err, codes.InvalidArgument)
}

func TestGetCertificate_FromRoot(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test Root CA")
	serial := hex.EncodeToString(rootCA.cert.SerialNumber.Bytes())

	mockCA := &configurableMockCA{
		trustedRoot: rootCA.cert,
	}

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA, nil)
	ctx := context.Background()

	resp, err := svc.GetCertificate(ctx, &platformv1.GetCertificateRequest{
		Serial:     serial,
		IncludePem: true,
		IncludeDer: true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Certificate == nil {
		t.Error("expected certificate")
	}
	if len(resp.Certificate.Pem) == 0 {
		t.Error("expected PEM to be included")
	}
	if len(resp.Certificate.Der) == 0 {
		t.Error("expected DER to be included")
	}
}

func TestGetCertificate_FromIntermediate(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test Root CA")
	intermediateCA := createIntermediateCAWithKey(t, "Test Intermediate CA", rootCA)
	serial := hex.EncodeToString(intermediateCA.cert.SerialNumber.Bytes())

	mockCA := &configurableMockCA{
		trustedInter: intermediateCA.cert,
	}

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA, nil)
	ctx := context.Background()

	resp, err := svc.GetCertificate(ctx, &platformv1.GetCertificateRequest{
		Serial: serial,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Certificate.Subject.CommonName != "Test Intermediate CA" {
		t.Errorf("expected 'Test Intermediate CA', got %s", resp.Certificate.Subject.CommonName)
	}
}

func TestGetCertificate_FromCertStore(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test Root CA")
	cert := createCertSignedByCA(t, "test.example.com", rootCA)
	serial := hex.EncodeToString(cert.SerialNumber.Bytes())

	certStore := newMockCertStore()
	certStore.certs[serial] = cert

	mockCA := &configurableMockCA{
		certStore: certStore,
	}

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA, nil)
	ctx := context.Background()

	resp, err := svc.GetCertificate(ctx, &platformv1.GetCertificateRequest{
		Serial: serial,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Certificate.Subject.CommonName != "test.example.com" {
		t.Errorf("expected 'test.example.com', got %s", resp.Certificate.Subject.CommonName)
	}
}

func TestGetCertificate_NotFound(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{}
	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA, nil)
	ctx := context.Background()

	_, err := svc.GetCertificate(ctx, &platformv1.GetCertificateRequest{
		Serial: "nonexistent",
	})
	assertGRPCError(t, err, codes.NotFound)
}

func TestListCertificates_NilCA(t *testing.T) {
	t.Parallel()

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, nil, nil)
	ctx := context.Background()

	_, err := svc.ListCertificates(ctx, &platformv1.ListCertificatesRequest{})
	assertGRPCError(t, err, codes.FailedPrecondition)
}

func TestListCertificates_Success(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test Root CA")
	cert1 := createCertSignedByCA(t, "cert1.example.com", rootCA)
	serial1 := hex.EncodeToString(cert1.SerialNumber.Bytes())

	certStore := newMockCertStore()
	certStore.certs[serial1] = cert1

	mockCA := &configurableMockCA{
		trustedRoot: rootCA.cert,
		certStore:   certStore,
	}

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA, nil)
	ctx := context.Background()

	resp, err := svc.ListCertificates(ctx, &platformv1.ListCertificatesRequest{
		Pagination: &platformv1.PaginationRequest{
			Page:     1,
			PageSize: 10,
		},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Certificates) == 0 {
		t.Error("expected certificates to be returned")
	}
	if resp.Pagination.Page != 1 {
		t.Error("expected page 1")
	}
}

func TestListCertificates_WithFilters(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test Root CA")

	mockCA := &configurableMockCA{
		trustedRoot: rootCA.cert,
	}

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA, nil)
	ctx := context.Background()

	resp, err := svc.ListCertificates(ctx, &platformv1.ListCertificatesRequest{
		TypeFilter: platformv1.CertificateType_CERTIFICATE_TYPE_CA,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Certificates) == 0 {
		t.Error("expected CA certificates")
	}
}

func TestListCertificates_PaginationBeyondTotal(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{}
	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA, nil)
	ctx := context.Background()

	resp, err := svc.ListCertificates(ctx, &platformv1.ListCertificatesRequest{
		Pagination: &platformv1.PaginationRequest{
			Page:     100,
			PageSize: 10,
		},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Certificates) != 0 {
		t.Error("expected empty list for page beyond total")
	}
}

func TestListCertificates_MaxPageSize(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{}
	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA, nil)
	ctx := context.Background()

	resp, err := svc.ListCertificates(ctx, &platformv1.ListCertificatesRequest{
		Pagination: &platformv1.PaginationRequest{
			Page:     1,
			PageSize: 10000, // Over max
		},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Pagination.PageSize > caGRPCMaxPageSize {
		t.Error("page size should be capped at max")
	}
}

func TestRevokeCertificate_NilCA(t *testing.T) {
	t.Parallel()

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, nil, nil)
	ctx := context.Background()

	_, err := svc.RevokeCertificate(ctx, &platformv1.RevokeCertificateRequest{Serial: "test"})
	assertGRPCError(t, err, codes.FailedPrecondition)
}

func TestRevokeCertificate_MissingSerial(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{}
	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA, nil)
	ctx := context.Background()

	_, err := svc.RevokeCertificate(ctx, &platformv1.RevokeCertificateRequest{})
	assertGRPCError(t, err, codes.InvalidArgument)
}

func TestRevokeCertificate_NotFound(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{}
	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA, nil)
	ctx := context.Background()

	_, err := svc.RevokeCertificate(ctx, &platformv1.RevokeCertificateRequest{
		Serial: "nonexistent",
	})
	assertGRPCError(t, err, codes.NotFound)
}

func TestRevokeCertificate_Success(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test Root CA")
	cert := createCertSignedByCA(t, "test.example.com", rootCA)
	serial := hex.EncodeToString(cert.SerialNumber.Bytes())

	certStore := newMockCertStore()
	certStore.certs[serial] = cert

	mockCA := &configurableMockCA{
		certStore: certStore,
	}

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA, nil)
	ctx := context.Background()

	resp, err := svc.RevokeCertificate(ctx, &platformv1.RevokeCertificateRequest{
		Serial:     serial,
		Reason:     platformv1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE,
		DeleteKeys: true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Status.Success {
		t.Error("expected success")
	}
	if resp.CertificateStatus != platformv1.CertificateStatus_CERTIFICATE_STATUS_REVOKED {
		t.Error("expected revoked status")
	}
}

// errTestCARevokeCalled is what the CA fake answers if a revoke reaches it.
type testCARevokeCalledError struct{}

func (testCARevokeCalledError) Error() string { return "the CA was asked to revoke" }

var errTestCARevokeCalled error = testCARevokeCalledError{}

// A reason outside RFC 5280 §5.3.1 (7 is unassigned) is InvalidArgument and
// never reaches the CA, which would publish it in the CRL.
func TestRevokeCertificate_RejectsUndefinedReason(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test Root CA")
	for _, reason := range []int32{7, 8, -1, 99} {
		cert := createCertSignedByCA(t, "test.example.com", rootCA)
		serial := hex.EncodeToString(cert.SerialNumber.Bytes())
		certStore := newMockCertStore()
		certStore.certs[serial] = cert
		// A CA call would fail Internal; InvalidArgument proves it never ran.
		mockCA := &configurableMockCA{
			certStore: certStore,
			revokeErr: errTestCARevokeCalled,
		}
		svc := NewCAGRPCService(createTestLogger(), mockCA, nil)

		_, err := svc.RevokeCertificate(context.Background(), &platformv1.RevokeCertificateRequest{
			Serial: serial,
			Reason: platformv1.RevocationReason(reason),
		})
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("reason %d: expected InvalidArgument, got %v", reason, err)
		}
	}
}

func TestRevokeCertificate_Error(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test Root CA")
	cert := createCertSignedByCA(t, "test.example.com", rootCA)
	serial := hex.EncodeToString(cert.SerialNumber.Bytes())

	certStore := newMockCertStore()
	certStore.certs[serial] = cert

	mockCA := &configurableMockCA{
		certStore: certStore,
		revokeErr: errors.New("revoke failed"),
	}

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA, nil)
	ctx := context.Background()

	_, err := svc.RevokeCertificate(ctx, &platformv1.RevokeCertificateRequest{
		Serial: serial,
	})
	assertGRPCError(t, err, codes.Internal)
}

func TestRenewCertificate_NilCA(t *testing.T) {
	t.Parallel()

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, nil, nil)
	ctx := context.Background()

	_, err := svc.RenewCertificate(ctx, &platformv1.RenewCertificateRequest{Serial: "test", ValidDays: 365})
	assertGRPCError(t, err, codes.FailedPrecondition)
}

func TestRenewCertificate_MissingSerial(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{}
	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA, nil)
	ctx := context.Background()

	_, err := svc.RenewCertificate(ctx, &platformv1.RenewCertificateRequest{ValidDays: 365})
	assertGRPCError(t, err, codes.InvalidArgument)
}

func TestRenewCertificate_MissingValidDays(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{}
	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA, nil)
	ctx := context.Background()

	_, err := svc.RenewCertificate(ctx, &platformv1.RenewCertificateRequest{Serial: "test"})
	assertGRPCError(t, err, codes.InvalidArgument)
}

func TestRenewCertificate_NotFound(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{}
	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA, nil)
	ctx := context.Background()

	_, err := svc.RenewCertificate(ctx, &platformv1.RenewCertificateRequest{
		Serial:    "nonexistent",
		ValidDays: 365,
	})
	assertGRPCError(t, err, codes.NotFound)
}

func TestRenewCertificate_Success(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test Root CA")
	existingCert := createCertSignedByCA(t, "test.example.com", rootCA)
	serial := hex.EncodeToString(existingCert.SerialNumber.Bytes())
	newCert := createCertSignedByCA(t, "test.example.com", rootCA)

	certStore := newMockCertStore()
	certStore.certs[serial] = existingCert

	mockCA := &configurableMockCA{
		certStore:  certStore,
		issuedCert: newCert,
	}

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA, nil)
	ctx := context.Background()

	resp, err := svc.RenewCertificate(ctx, &platformv1.RenewCertificateRequest{
		Serial:       serial,
		ValidDays:    365,
		PreserveSans: true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Status.Success {
		t.Error("expected success")
	}
	if resp.OldCertificate == nil {
		t.Error("expected old certificate")
	}
	if resp.NewCertificate == nil {
		t.Error("expected new certificate")
	}
}

func TestRenewCertificate_WithNewSans(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test Root CA")
	existingCert := createCertSignedByCA(t, "test.example.com", rootCA)
	serial := hex.EncodeToString(existingCert.SerialNumber.Bytes())
	newCert := createCertSignedByCA(t, "test.example.com", rootCA)

	certStore := newMockCertStore()
	certStore.certs[serial] = existingCert

	mockCA := &configurableMockCA{
		certStore:  certStore,
		issuedCert: newCert,
	}

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA, nil)
	ctx := context.Background()

	resp, err := svc.RenewCertificate(ctx, &platformv1.RenewCertificateRequest{
		Serial:    serial,
		ValidDays: 365,
		NewSans: &platformv1.SubjectAlternativeNames{
			DnsNames:    []string{"new.example.com"},
			IpAddresses: []string{"10.0.0.1"},
		},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Status.Success {
		t.Error("expected success")
	}
}

func TestRenewCertificate_Error(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test Root CA")
	existingCert := createCertSignedByCA(t, "test.example.com", rootCA)
	serial := hex.EncodeToString(existingCert.SerialNumber.Bytes())

	certStore := newMockCertStore()
	certStore.certs[serial] = existingCert

	mockCA := &configurableMockCA{
		certStore:    certStore,
		issueCertErr: errors.New("failed to renew"),
	}

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA, nil)
	ctx := context.Background()

	_, err := svc.RenewCertificate(ctx, &platformv1.RenewCertificateRequest{
		Serial:    serial,
		ValidDays: 365,
	})
	assertGRPCError(t, err, codes.Internal)
}

func TestVerifyCertificate_NilCA(t *testing.T) {
	t.Parallel()

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, nil, nil)
	ctx := context.Background()

	_, err := svc.VerifyCertificate(ctx, &platformv1.VerifyCertificateRequest{CertificatePem: []byte("test")})
	assertGRPCError(t, err, codes.FailedPrecondition)
}

func TestVerifyCertificate_MissingCertificate(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{}
	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA, nil)
	ctx := context.Background()

	_, err := svc.VerifyCertificate(ctx, &platformv1.VerifyCertificateRequest{})
	assertGRPCError(t, err, codes.InvalidArgument)
}

func TestVerifyCertificate_InvalidPEM(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{}
	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA, nil)
	ctx := context.Background()

	resp, err := svc.VerifyCertificate(ctx, &platformv1.VerifyCertificateRequest{
		CertificatePem: []byte("not a valid PEM"),
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Valid {
		t.Error("expected invalid certificate")
	}
	if len(resp.Errors) == 0 {
		t.Error("expected errors")
	}
}

func TestVerifyCertificate_InvalidDER(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{}
	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA, nil)
	ctx := context.Background()

	resp, err := svc.VerifyCertificate(ctx, &platformv1.VerifyCertificateRequest{
		CertificateDer: []byte("not valid DER"),
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Valid {
		t.Error("expected invalid certificate")
	}
}

func TestVerifyCertificate_ValidWithPEM(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test Root CA")
	leafCert := createCertSignedByCA(t, "test.example.com", rootCA)

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: leafCert.Raw,
	})

	mockCA := &configurableMockCA{
		trustedRoot: rootCA.cert,
	}

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA, nil)
	ctx := context.Background()

	resp, err := svc.VerifyCertificate(ctx, &platformv1.VerifyCertificateRequest{
		CertificatePem:   pemBlock,
		VerifyExpiration: true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Valid {
		t.Errorf("expected valid certificate, errors: %v", resp.Errors)
	}
}

func TestVerifyCertificate_ValidWithDER(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test Root CA")
	leafCert := createCertSignedByCA(t, "test.example.com", rootCA)

	mockCA := &configurableMockCA{
		trustedRoot: rootCA.cert,
	}

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA, nil)
	ctx := context.Background()

	resp, err := svc.VerifyCertificate(ctx, &platformv1.VerifyCertificateRequest{
		CertificateDer: leafCert.Raw,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Valid {
		t.Errorf("expected valid certificate, errors: %v", resp.Errors)
	}
}

func TestVerifyCertificate_Expired(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test Root CA")
	expiredCert := createExpiredCertSignedByCA(t, rootCA)

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: expiredCert.Raw,
	})

	mockCA := &configurableMockCA{
		trustedRoot: rootCA.cert,
	}

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA, nil)
	ctx := context.Background()

	resp, err := svc.VerifyCertificate(ctx, &platformv1.VerifyCertificateRequest{
		CertificatePem:   pemBlock,
		VerifyExpiration: true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Valid {
		t.Error("expected invalid certificate for expired cert")
	}
}

func TestVerifyCertificate_NotYetValid(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test Root CA")
	futureCert := createFutureCertSignedByCA(t, rootCA)

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: futureCert.Raw,
	})

	mockCA := &configurableMockCA{
		trustedRoot: rootCA.cert,
	}

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA, nil)
	ctx := context.Background()

	resp, err := svc.VerifyCertificate(ctx, &platformv1.VerifyCertificateRequest{
		CertificatePem:   pemBlock,
		VerifyExpiration: true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Warnings) == 0 {
		t.Error("expected warnings for not yet valid cert")
	}
}

func TestVerifyCertificate_WithTrustedRoots(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "External Root CA")
	leafCert := createCertSignedByCA(t, "test.example.com", rootCA)

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: leafCert.Raw,
	})

	mockCA := &configurableMockCA{}

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA, nil)
	ctx := context.Background()

	resp, err := svc.VerifyCertificate(ctx, &platformv1.VerifyCertificateRequest{
		CertificatePem: pemBlock,
		TrustedRoots:   [][]byte{rootCA.cert.Raw},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Valid {
		t.Errorf("expected valid certificate with trusted root, errors: %v", resp.Errors)
	}
}

func TestGetCRL_NilCA(t *testing.T) {
	t.Parallel()

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, nil, nil)
	ctx := context.Background()

	_, err := svc.GetCRL(ctx, &platformv1.GetCRLRequest{})
	assertGRPCError(t, err, codes.FailedPrecondition)
}

func TestGetCRL_NoCRLSupport(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{}
	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA, nil)
	ctx := context.Background()

	resp, err := svc.GetCRL(ctx, &platformv1.GetCRLRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Crl == nil {
		t.Error("expected CRL response")
	}
	if resp.Crl.RevokedCount != 0 {
		t.Error("expected empty CRL")
	}
}

func TestGetCABundle_NilCA(t *testing.T) {
	t.Parallel()

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, nil, nil)
	ctx := context.Background()

	_, err := svc.GetCABundle(ctx, &platformv1.GetCABundleRequest{})
	assertGRPCError(t, err, codes.FailedPrecondition)
}

func TestGetCABundle_Error(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{
		bundleErr: errors.New("bundle error"),
	}

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA, nil)
	ctx := context.Background()

	_, err := svc.GetCABundle(ctx, &platformv1.GetCABundleRequest{})
	assertGRPCError(t, err, codes.Internal)
}

func TestGetCABundle_Empty(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{
		bundle: []byte{},
	}

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA, nil)
	ctx := context.Background()

	_, err := svc.GetCABundle(ctx, &platformv1.GetCABundleRequest{})
	assertGRPCError(t, err, codes.NotFound)
}

func TestGetCABundle_Success(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test Root CA")
	intermediateCA := createIntermediateCAWithKey(t, "Test Intermediate CA", rootCA)

	var bundlePEM []byte
	bundlePEM = append(bundlePEM, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: rootCA.cert.Raw,
	})...)
	bundlePEM = append(bundlePEM, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: intermediateCA.cert.Raw,
	})...)

	mockCA := &configurableMockCA{
		bundle:       bundlePEM,
		parsedBundle: []*x509.Certificate{rootCA.cert, intermediateCA.cert},
	}

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA, nil)
	ctx := context.Background()

	resp, err := svc.GetCABundle(ctx, &platformv1.GetCABundleRequest{
		IncludeIntermediates: true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Bundle.Pem) == 0 {
		t.Error("expected PEM bundle")
	}
	if resp.Bundle.CertCount == 0 {
		t.Error("expected certificates in bundle")
	}
}

// Helper function tests

func TestKeyUsageToStrings(t *testing.T) {
	t.Parallel()

	service := &CAGRPCService{}

	usage := x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	result := service.keyUsageToStrings(usage)

	expected := []string{"DIGITAL_SIGNATURE", "CERT_SIGN", "CRL_SIGN"}
	if len(result) != len(expected) {
		t.Errorf("expected %d usages, got %d", len(expected), len(result))
	}
}

func TestExtKeyUsageToStrings(t *testing.T) {
	t.Parallel()

	service := &CAGRPCService{}

	usages := []x509.ExtKeyUsage{
		x509.ExtKeyUsageServerAuth,
		x509.ExtKeyUsageClientAuth,
		x509.ExtKeyUsageCodeSigning,
	}
	result := service.extKeyUsageToStrings(usages)

	if len(result) != 3 {
		t.Errorf("expected 3 usages, got %d", len(result))
	}
}

func TestKeyAlgorithmConversions(t *testing.T) {
	t.Parallel()

	service := &CAGRPCService{}

	// Test x509 to string
	if service.keyAlgorithmToString(x509.RSA) != "RSA" {
		t.Error("expected RSA")
	}
	if service.keyAlgorithmToString(x509.ECDSA) != "ECDSA" {
		t.Error("expected ECDSA")
	}
	if service.keyAlgorithmToString(x509.Ed25519) != "ED25519" {
		t.Error("expected ED25519")
	}
	if service.keyAlgorithmToString(x509.DSA) != "UNKNOWN" {
		t.Error("expected UNKNOWN")
	}
}

// TestCertConvertersReportIssuedKeyAlgorithm pins that both certificate
// converters report the issued key's real size and curve (Codex 8232): an
// RSA-4096 or ECDSA-P384 certificate was reported as RSA-2048 or ECDSA-P256.
func TestCertConvertersReportIssuedKeyAlgorithm(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-384 key: %v", err)
	}
	// A 4096-bit modulus; the converters read only its size, so no key is generated.
	rsa4096 := &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 4095), E: 65537}

	tests := []struct {
		name string
		pub  crypto.PublicKey
		alg  x509.PublicKeyAlgorithm
		want platformv1.KeyAlgorithm
	}{
		{"RSA-4096", rsa4096, x509.RSA, platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_4096},
		{"ECDSA-P384", &ecKey.PublicKey, x509.ECDSA, platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P384},
		{"unsupported key type", struct{}{}, x509.DSA, platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED},
		{"no public key", nil, x509.RSA, platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED},
	}

	service := &CAGRPCService{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &x509.Certificate{
				SerialNumber:       big.NewInt(1),
				PublicKey:          tt.pub,
				PublicKeyAlgorithm: tt.alg,
				NotBefore:          time.Now().Add(-time.Hour),
				NotAfter:           time.Now().Add(time.Hour),
			}
			if got := service.certToSummary(cert).GetKeyAlgorithm(); got != tt.want {
				t.Errorf("certToSummary key algorithm = %v, want %v", got, tt.want)
			}
			if got := service.certToProto(cert, false, false).GetKeyAlgorithm(); got != tt.want {
				t.Errorf("certToProto key algorithm = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRevocationReasonToProto(t *testing.T) {
	t.Parallel()

	service := &CAGRPCService{}

	testCases := []struct {
		reason   int
		expected platformv1.RevocationReason
	}{
		{1, platformv1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE},
		{2, platformv1.RevocationReason_REVOCATION_REASON_CA_COMPROMISE},
		{3, platformv1.RevocationReason_REVOCATION_REASON_AFFILIATION_CHANGED},
		{4, platformv1.RevocationReason_REVOCATION_REASON_SUPERSEDED},
		{5, platformv1.RevocationReason_REVOCATION_REASON_CESSATION_OF_OPERATION},
		{6, platformv1.RevocationReason_REVOCATION_REASON_CERTIFICATE_HOLD},
		{8, platformv1.RevocationReason_REVOCATION_REASON_REMOVE_FROM_CRL},
		{9, platformv1.RevocationReason_REVOCATION_REASON_PRIVILEGE_WITHDRAWN},
		{10, platformv1.RevocationReason_REVOCATION_REASON_AA_COMPROMISE},
		{99, platformv1.RevocationReason_REVOCATION_REASON_UNSPECIFIED},
	}

	for _, tc := range testCases {
		result := service.revocationReasonToProto(tc.reason)
		if result != tc.expected {
			t.Errorf("for reason %d, expected %v, got %v", tc.reason, tc.expected, result)
		}
	}
}

func TestGetCertificateStatus(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test CA")
	service := &CAGRPCService{}

	// Valid cert
	validCert := createCertSignedByCA(t, "valid.example.com", rootCA)
	if service.getCertificateStatus(validCert) != platformv1.CertificateStatus_CERTIFICATE_STATUS_VALID {
		t.Error("expected valid status")
	}

	// Expired cert
	expiredCert := createExpiredCertSignedByCA(t, rootCA)
	if service.getCertificateStatus(expiredCert) != platformv1.CertificateStatus_CERTIFICATE_STATUS_EXPIRED {
		t.Error("expected expired status")
	}

	// Future cert
	futureCert := createFutureCertSignedByCA(t, rootCA)
	if service.getCertificateStatus(futureCert) != platformv1.CertificateStatus_CERTIFICATE_STATUS_PENDING {
		t.Error("expected pending status")
	}
}

func TestGetCertificateType(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test CA")
	service := &CAGRPCService{}

	// CA cert
	if service.getCertificateType(rootCA.cert) != platformv1.CertificateType_CERTIFICATE_TYPE_CA {
		t.Error("expected CA type")
	}

	// Server cert (has ServerAuth)
	serverCert := createCertSignedByCA(t, "server.example.com", rootCA)
	certType := service.getCertificateType(serverCert)
	if certType != platformv1.CertificateType_CERTIFICATE_TYPE_SERVER {
		t.Errorf("expected SERVER type, got %v", certType)
	}
}

func TestCertToSummary_Nil(t *testing.T) {
	t.Parallel()

	service := &CAGRPCService{}
	if service.certToSummary(nil) != nil {
		t.Error("expected nil for nil certificate")
	}
}

func TestCertToProto_Nil(t *testing.T) {
	t.Parallel()

	service := &CAGRPCService{}
	if service.certToProto(nil, true, true) != nil {
		t.Error("expected nil for nil certificate")
	}
}

func TestFirstOrEmptyGRPC(t *testing.T) {
	t.Parallel()

	if firstOrEmptyGRPC([]string{"first", "second"}) != "first" {
		t.Error("expected first element")
	}
	if firstOrEmptyGRPC([]string{}) != "" {
		t.Error("expected empty string")
	}
	if firstOrEmptyGRPC(nil) != "" {
		t.Error("expected empty string for nil")
	}
}

func TestCASuccessStatusGRPC(t *testing.T) {
	t.Parallel()

	status := caSuccessStatusGRPC("test message")
	if !status.Success {
		t.Error("expected success")
	}
	if status.Message != "test message" {
		t.Error("wrong message")
	}
}

func TestCAFailureStatusGRPC(t *testing.T) {
	t.Parallel()

	status := caFailureStatusGRPC("error message")
	if status.Success {
		t.Error("expected failure")
	}
	if status.Message != "error message" {
		t.Error("wrong message")
	}
}

// Error type tests

func TestErrNilCAService(t *testing.T) {
	t.Parallel()

	err := ErrNilCAService{}
	if err.Error() != "ca service is nil" {
		t.Error("wrong error message")
	}
}

func TestErrMissingSerial(t *testing.T) {
	t.Parallel()

	err := ErrMissingSerial{}
	if err.Error() != "serial number is required" {
		t.Error("wrong error message")
	}
}

func TestErrMissingCertificateRequest(t *testing.T) {
	t.Parallel()

	err := ErrMissingCertificateRequest{}
	if err.Error() != "certificate request is required" {
		t.Error("wrong error message")
	}
}

func TestErrMissingSubject(t *testing.T) {
	t.Parallel()

	err := ErrMissingSubject{}
	if err.Error() != "subject is required" {
		t.Error("wrong error message")
	}
}

func TestErrMissingCommonName(t *testing.T) {
	t.Parallel()

	err := ErrMissingCommonName{}
	if err.Error() != "common name is required" {
		t.Error("wrong error message")
	}
}

func TestErrMissingCertificate(t *testing.T) {
	t.Parallel()

	err := ErrMissingCertificate{}
	if err.Error() != "certificate (PEM or DER) is required" {
		t.Error("wrong error message")
	}
}

func TestErrMissingValidDays(t *testing.T) {
	t.Parallel()

	err := ErrMissingValidDays{}
	if err.Error() != "valid_days must be positive" {
		t.Error("wrong error message")
	}
}

func TestErrCAOperationFailed(t *testing.T) {
	t.Parallel()

	err := ErrCAOperationFailed{Operation: "test", Reason: "failed"}
	expected := "CA operation test failed: failed"
	if err.Error() != expected {
		t.Errorf("expected %s, got %s", expected, err.Error())
	}
}

func TestErrCertificateNotFoundGRPC(t *testing.T) {
	t.Parallel()

	err := ErrCertificateNotFoundGRPC{Serial: "123"}
	expected := "certificate not found: 123"
	if err.Error() != expected {
		t.Errorf("expected %s, got %s", expected, err.Error())
	}
}

func TestMatchesCertFilter(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Root CA")
	service := &CAGRPCService{}

	// Match status filter
	req := &platformv1.ListCertificatesRequest{
		StatusFilter: platformv1.CertificateStatus_CERTIFICATE_STATUS_VALID,
	}
	if !service.matchesCertFilter(rootCA.cert, req) {
		t.Error("expected match for valid status")
	}

	// Non-match status filter
	req = &platformv1.ListCertificatesRequest{
		StatusFilter: platformv1.CertificateStatus_CERTIFICATE_STATUS_EXPIRED,
	}
	if service.matchesCertFilter(rootCA.cert, req) {
		t.Error("expected no match for expired status")
	}

	// Match type filter
	req = &platformv1.ListCertificatesRequest{
		TypeFilter: platformv1.CertificateType_CERTIFICATE_TYPE_CA,
	}
	if !service.matchesCertFilter(rootCA.cert, req) {
		t.Error("expected match for CA type")
	}

	// Non-match type filter
	req = &platformv1.ListCertificatesRequest{
		TypeFilter: platformv1.CertificateType_CERTIFICATE_TYPE_SERVER,
	}
	if service.matchesCertFilter(rootCA.cert, req) {
		t.Error("expected no match for server type")
	}

	// Match issuer filter
	req = &platformv1.ListCertificatesRequest{
		IssuerFilter: "Root CA",
	}
	if !service.matchesCertFilter(rootCA.cert, req) {
		t.Error("expected match for issuer")
	}

	// Non-match issuer filter
	req = &platformv1.ListCertificatesRequest{
		IssuerFilter: "Other CA",
	}
	if service.matchesCertFilter(rootCA.cert, req) {
		t.Error("expected no match for different issuer")
	}
}

// Additional tests for parseKeyUsage and parseExtKeyUsage

func TestCAGRPCService_keyUsageToStrings_AllTypes(t *testing.T) {
	logger := createTestLogger()
	mockCA := &configurableMockCA{}
	service := NewCAGRPCService(logger, mockCA, nil)

	tests := []struct {
		input    x509.KeyUsage
		expected []string
	}{
		{x509.KeyUsageDigitalSignature, []string{"DIGITAL_SIGNATURE"}},
		{x509.KeyUsageContentCommitment, []string{"CONTENT_COMMITMENT"}},
		{x509.KeyUsageKeyEncipherment, []string{"KEY_ENCIPHERMENT"}},
		{x509.KeyUsageDataEncipherment, []string{"DATA_ENCIPHERMENT"}},
		{x509.KeyUsageKeyAgreement, []string{"KEY_AGREEMENT"}},
		{x509.KeyUsageCertSign, []string{"CERT_SIGN"}},
		{x509.KeyUsageCRLSign, []string{"CRL_SIGN"}},
		{x509.KeyUsageEncipherOnly, []string{"ENCIPHER_ONLY"}},
		{x509.KeyUsageDecipherOnly, []string{"DECIPHER_ONLY"}},
		{0, nil},
	}

	for _, tc := range tests {
		result := service.keyUsageToStrings(tc.input)
		if len(result) != len(tc.expected) {
			t.Errorf("keyUsageToStrings(%v) returned %d items, expected %d", tc.input, len(result), len(tc.expected))
			continue
		}
		for i, r := range result {
			if r != tc.expected[i] {
				t.Errorf("keyUsageToStrings(%v)[%d] = '%s', expected '%s'", tc.input, i, r, tc.expected[i])
			}
		}
	}
}

func TestCAGRPCService_extKeyUsageToStrings_AllTypes(t *testing.T) {
	logger := createTestLogger()
	mockCA := &configurableMockCA{}
	service := NewCAGRPCService(logger, mockCA, nil)

	tests := []struct {
		input    []x509.ExtKeyUsage
		expected []string
	}{
		{[]x509.ExtKeyUsage{x509.ExtKeyUsageAny}, []string{"ANY"}},
		{[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []string{"SERVER_AUTH"}},
		{[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, []string{"CLIENT_AUTH"}},
		{[]x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, []string{"CODE_SIGNING"}},
		{[]x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}, []string{"EMAIL_PROTECTION"}},
		{[]x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}, []string{"TIME_STAMPING"}},
		{[]x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}, []string{"OCSP_SIGNING"}},
		// Unmapped types return empty
		{[]x509.ExtKeyUsage{x509.ExtKeyUsageIPSECEndSystem}, nil},
		{[]x509.ExtKeyUsage{x509.ExtKeyUsageIPSECTunnel}, nil},
		{[]x509.ExtKeyUsage{x509.ExtKeyUsageIPSECUser}, nil},
		{nil, nil},
	}

	for _, tc := range tests {
		result := service.extKeyUsageToStrings(tc.input)
		if len(result) != len(tc.expected) {
			t.Errorf("extKeyUsageToStrings(%v) returned %d items, expected %d", tc.input, len(result), len(tc.expected))
			continue
		}
		for i, r := range result {
			if r != tc.expected[i] {
				t.Errorf("extKeyUsageToStrings(%v)[%d] = '%s', expected '%s'", tc.input, i, r, tc.expected[i])
			}
		}
	}
}
