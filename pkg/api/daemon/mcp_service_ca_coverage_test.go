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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"testing"
	"time"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	xkmsca "github.com/jeremyhahn/go-xkms/pkg/ca"
)

// =============================================================================
// Mock CertStore for testing MCP service provider success paths
// =============================================================================

// mockCertStoreForMCPCoverage implements xkmssdk.CertStore for testing
type mockCertStoreForMCPCoverage struct {
	certs  map[string]*x509.Certificate
	chains map[string][]*x509.Certificate
	crls   map[string]*x509.RevocationList
}

func newMockCertStoreForMCPCoverage() *mockCertStoreForMCPCoverage {
	return &mockCertStoreForMCPCoverage{
		certs:  make(map[string]*x509.Certificate),
		chains: make(map[string][]*x509.Certificate),
		crls:   make(map[string]*x509.RevocationList),
	}
}

func (s *mockCertStoreForMCPCoverage) StoreCertificate(cert *x509.Certificate) error {
	serial := hex.EncodeToString(cert.SerialNumber.Bytes())
	s.certs[serial] = cert
	return nil
}

func (s *mockCertStoreForMCPCoverage) GetCertificate(serial string) (*x509.Certificate, error) {
	if cert, ok := s.certs[serial]; ok {
		return cert, nil
	}
	return nil, errors.New("certificate not found")
}

func (s *mockCertStoreForMCPCoverage) ListCertificates() ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for _, cert := range s.certs {
		certs = append(certs, cert)
	}
	return certs, nil
}

func (s *mockCertStoreForMCPCoverage) DeleteCertificate(serial string) error {
	delete(s.certs, serial)
	return nil
}

func (s *mockCertStoreForMCPCoverage) StoreCertificateChain(chain []*x509.Certificate) error {
	return nil
}

func (s *mockCertStoreForMCPCoverage) GetCertificateChain(cn string) ([]*x509.Certificate, error) {
	if chain, ok := s.chains[cn]; ok {
		return chain, nil
	}
	return nil, errors.New("chain not found")
}

func (s *mockCertStoreForMCPCoverage) StoreCRL(crl *x509.RevocationList) error {
	return nil
}

func (s *mockCertStoreForMCPCoverage) GetCRL(issuer string) (*x509.RevocationList, error) {
	if crl, ok := s.crls[issuer]; ok {
		return crl, nil
	}
	return nil, errors.New("CRL not found")
}

func (s *mockCertStoreForMCPCoverage) VerifyCertificate(cert *x509.Certificate, roots *x509.CertPool) error {
	return nil
}

func (s *mockCertStoreForMCPCoverage) IsRevoked(cert *x509.Certificate) (bool, error) {
	return false, nil
}

func (s *mockCertStoreForMCPCoverage) Close() error {
	return nil
}

// =============================================================================
// Mock CA for testing MCP service provider success paths
// =============================================================================

// mockCAForMCPCoverage implements ca.TCGCA for testing success paths.
type mockCAForMCPCoverage struct {
	baseMockCA
	initialized      bool
	identity         string
	rootCert         *x509.Certificate
	intermCert       *x509.Certificate
	defaultKeyAlg    x509.PublicKeyAlgorithm
	defaultSigAlg    x509.SignatureAlgorithm
	validity         int
	privateKey       *ecdsa.PrivateKey
	certStore        xkmssdk.CertStore
	issuedCerts      []*x509.Certificate
	revokedCerts     []*x509.Certificate
	generateCRLErr   error
	crlData          []byte
	bundleData       []byte
	bundleErr        error
	issueCertErr     error
	revokeErr        error
	verifyChainsResp [][]*x509.Certificate
	verifyChainsErr  error
}

func newMockCAForMCPCoverage() *mockCAForMCPCoverage {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootCert := generateTestCertificateForMCPCoverage("Test Root CA", true, nil, privateKey)
	intermCert := generateTestCertificateForMCPCoverage("Test Intermediate CA", true, rootCert, privateKey)

	return &mockCAForMCPCoverage{
		initialized:   true,
		identity:      "Test CA",
		rootCert:      rootCert,
		intermCert:    intermCert,
		defaultKeyAlg: x509.ECDSA,
		defaultSigAlg: x509.ECDSAWithSHA256,
		validity:      365,
		privateKey:    privateKey,
		certStore:     newMockCertStoreForMCPCoverage(),
	}
}

func generateTestCertificateForMCPCoverage(cn string, isCA bool, parent *x509.Certificate, key *ecdsa.PrivateKey) *x509.Certificate {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}

	if isCA {
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}

	parentCert := template
	if parent != nil {
		parentCert = parent
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, parentCert, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)
	return cert
}

// Implement crypto.Signer interface
func (m *mockCAForMCPCoverage) Public() crypto.PublicKey { return &m.privateKey.PublicKey }
func (m *mockCAForMCPCoverage) Sign(r io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	return ecdsa.SignASN1(r, m.privateKey, digest)
}

func (m *mockCAForMCPCoverage) IsInitialized() bool                          { return m.initialized }
func (m *mockCAForMCPCoverage) Identity() string                             { return m.identity }
func (m *mockCAForMCPCoverage) DefaultKeyAlgorithm() x509.PublicKeyAlgorithm { return m.defaultKeyAlg }
func (m *mockCAForMCPCoverage) DefaultSignatureAlgorithm() x509.SignatureAlgorithm {
	return m.defaultSigAlg
}
func (m *mockCAForMCPCoverage) DefaultValidityPeriod() int              { return m.validity }
func (m *mockCAForMCPCoverage) TrustedRoot() (*x509.Certificate, error) { return m.rootCert, nil }
func (m *mockCAForMCPCoverage) TrustedIntermediate() (*x509.Certificate, error) {
	return m.intermCert, nil
}
func (m *mockCAForMCPCoverage) CertStore() xkmssdk.CertStore   { return m.certStore }
func (m *mockCAForMCPCoverage) Signer() (crypto.Signer, error) { return m, nil }
func (m *mockCAForMCPCoverage) CASigner(_ xkmssdk.StoreType, _ x509.PublicKeyAlgorithm) (crypto.Signer, error) {
	return m, nil
}
func (m *mockCAForMCPCoverage) IssueCertificate(req *xkmsca.CertificateRequest) (*xkmsca.IssuedCertificate, error) {
	if m.issueCertErr != nil {
		return nil, m.issueCertErr
	}
	cert := generateTestCertificateForMCPCoverage(req.Subject.CommonName, req.IsCA, m.intermCert, m.privateKey)
	m.issuedCerts = append(m.issuedCerts, cert)
	if m.certStore != nil {
		m.certStore.StoreCertificate(cert)
	}
	return &xkmsca.IssuedCertificate{Certificate: cert}, nil
}
func (m *mockCAForMCPCoverage) RevokeCert(cert *x509.Certificate, _ xkmsca.RevokeOptions) error {
	if m.revokeErr != nil {
		return m.revokeErr
	}
	m.revokedCerts = append(m.revokedCerts, cert)
	return nil
}
func (m *mockCAForMCPCoverage) Verify(certificate *x509.Certificate, _ ...crypto.Signer) ([][]*x509.Certificate, error) {
	if m.verifyChainsErr != nil {
		return nil, m.verifyChainsErr
	}
	if m.verifyChainsResp != nil {
		return m.verifyChainsResp, nil
	}
	return [][]*x509.Certificate{{certificate, m.intermCert, m.rootCert}}, nil
}
func (m *mockCAForMCPCoverage) CABundle() ([]byte, error) {
	if m.bundleErr != nil {
		return nil, m.bundleErr
	}
	if m.bundleData != nil {
		return m.bundleData, nil
	}
	return m.rootCert.Raw, nil
}
func (m *mockCAForMCPCoverage) CABundleFiltered(_ xkmssdk.StoreType, _ x509.PublicKeyAlgorithm) ([]byte, error) {
	if m.bundleErr != nil {
		return nil, m.bundleErr
	}
	if m.bundleData != nil {
		return m.bundleData, nil
	}
	return m.rootCert.Raw, nil
}
func (m *mockCAForMCPCoverage) ParseBundle(bundle []byte) ([]*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(bundle)
	if err != nil {
		return nil, err
	}
	return []*x509.Certificate{cert}, nil
}
func (m *mockCAForMCPCoverage) RootCertificate(_ *x509.Certificate) (*x509.Certificate, error) {
	return m.rootCert, nil
}
func (m *mockCAForMCPCoverage) GenerateCRL() ([]byte, error) {
	if m.generateCRLErr != nil {
		return nil, m.generateCRLErr
	}
	if m.crlData != nil {
		return m.crlData, nil
	}
	template := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(24 * time.Hour),
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, template, m.rootCert, m.privateKey)
	if err != nil {
		return nil, err
	}
	return crlDER, nil
}

// =============================================================================
// Helper to create CAGRPCService with mock CA
// =============================================================================

func createCAGRPCServiceForMCPCoverage(mockCA *mockCAForMCPCoverage) *CAGRPCService {
	logger := logging.DefaultLogger()
	return NewCAGRPCService(logger, mockCA, nil)
}

// =============================================================================
// CAInfo Tests - Success Paths
// =============================================================================

func TestMCPServiceProvider_CAInfo_SuccessCoverage(t *testing.T) {
	ctx := context.Background()
	mockCA := newMockCAForMCPCoverage()
	caService := createCAGRPCServiceForMCPCoverage(mockCA)

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CAService: caService,
		Logger:    slog.Default(),
	})

	result, err := provider.CAInfo(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resp, ok := result.(*platformv1.GetCAInfoResponse)
	if !ok {
		t.Fatalf("expected *platformv1.GetCAInfoResponse, got %T", result)
	}

	if resp.CaInfo == nil {
		t.Fatal("expected non-nil CaInfo")
	}

	if !resp.CaInfo.IsInitialized {
		t.Error("expected IsInitialized to be true")
	}

	if resp.CaInfo.CommonName != "Test CA" {
		t.Errorf("expected CommonName 'Test CA', got %q", resp.CaInfo.CommonName)
	}
}

func TestMCPServiceProvider_CAInfo_UninitializedCACoverage(t *testing.T) {
	ctx := context.Background()
	mockCA := newMockCAForMCPCoverage()
	mockCA.initialized = false
	caService := createCAGRPCServiceForMCPCoverage(mockCA)

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CAService: caService,
		Logger:    slog.Default(),
	})

	result, err := provider.CAInfo(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resp, ok := result.(*platformv1.GetCAInfoResponse)
	if !ok {
		t.Fatalf("expected *platformv1.GetCAInfoResponse, got %T", result)
	}

	if resp.CaInfo.IsInitialized {
		t.Error("expected IsInitialized to be false")
	}
}

// =============================================================================
// CAIssue Tests - Success Paths
// =============================================================================

func TestMCPServiceProvider_CAIssue_SuccessCoverage(t *testing.T) {
	ctx := context.Background()
	mockCA := newMockCAForMCPCoverage()
	caService := createCAGRPCServiceForMCPCoverage(mockCA)

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CAService: caService,
		Logger:    slog.Default(),
	})

	req := &mcp.CAIssueRequest{
		CommonName:   "test.example.com",
		Organization: "Test Org",
		Country:      "US",
		ValidDays:    365,
		Algorithm:    "ECDSA-P256",
		StoreType:    "software",
	}

	result, err := provider.CAIssue(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resp, ok := result.(*platformv1.IssueCertificateResponse)
	if !ok {
		t.Fatalf("expected *platformv1.IssueCertificateResponse, got %T", result)
	}

	if resp.Status == nil || !resp.Status.Success {
		t.Error("expected successful status")
	}

	if resp.Certificate == nil {
		t.Error("expected certificate in response")
	}

	// Verify the certificate was stored in the mock
	if len(mockCA.issuedCerts) != 1 {
		t.Errorf("expected 1 issued cert, got %d", len(mockCA.issuedCerts))
	}
}

func TestMCPServiceProvider_CAIssue_WithSANsCoverage(t *testing.T) {
	ctx := context.Background()
	mockCA := newMockCAForMCPCoverage()
	caService := createCAGRPCServiceForMCPCoverage(mockCA)

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CAService: caService,
		Logger:    slog.Default(),
	})

	req := &mcp.CAIssueRequest{
		CommonName:     "test.example.com",
		DNSNames:       []string{"www.example.com", "api.example.com"},
		IPAddresses:    []string{"192.168.1.1"},
		EmailAddresses: []string{"admin@example.com"},
		URIs:           []string{"spiffe://cluster.local/ns/default/sa/myservice"},
		ValidDays:      365,
	}

	result, err := provider.CAIssue(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resp, ok := result.(*platformv1.IssueCertificateResponse)
	if !ok {
		t.Fatalf("expected *platformv1.IssueCertificateResponse, got %T", result)
	}

	if resp.Status == nil || !resp.Status.Success {
		t.Error("expected successful status")
	}
}

func TestMCPServiceProvider_CAIssue_CACertificateCoverage(t *testing.T) {
	ctx := context.Background()
	mockCA := newMockCAForMCPCoverage()
	caService := createCAGRPCServiceForMCPCoverage(mockCA)

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CAService: caService,
		Logger:    slog.Default(),
	})

	req := &mcp.CAIssueRequest{
		CommonName:   "Intermediate CA",
		Organization: "Test Org",
		IsCA:         true,
		MaxPathLen:   1,
		KeyUsage:     []string{"certSign", "crlSign"},
		ValidDays:    3650,
	}

	result, err := provider.CAIssue(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resp, ok := result.(*platformv1.IssueCertificateResponse)
	if !ok {
		t.Fatalf("expected *platformv1.IssueCertificateResponse, got %T", result)
	}

	if resp.Status == nil || !resp.Status.Success {
		t.Error("expected successful status")
	}
}

func TestMCPServiceProvider_CAIssue_ErrorCoverage(t *testing.T) {
	ctx := context.Background()
	mockCA := newMockCAForMCPCoverage()
	mockCA.issueCertErr = errors.New("failed to issue certificate")
	caService := createCAGRPCServiceForMCPCoverage(mockCA)

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CAService: caService,
		Logger:    slog.Default(),
	})

	req := &mcp.CAIssueRequest{
		CommonName: "test.example.com",
		ValidDays:  365,
	}

	_, err := provider.CAIssue(ctx, req)
	if err == nil {
		t.Fatal("expected error from CA service")
	}
}

// =============================================================================
// CAGet Tests - Success Paths
// =============================================================================

func TestMCPServiceProvider_CAGet_SuccessRootCertCoverage(t *testing.T) {
	ctx := context.Background()
	mockCA := newMockCAForMCPCoverage()
	caService := createCAGRPCServiceForMCPCoverage(mockCA)

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CAService: caService,
		Logger:    slog.Default(),
	})

	serial := hex.EncodeToString(mockCA.rootCert.SerialNumber.Bytes())

	result, err := provider.CAGet(ctx, serial, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resp, ok := result.(*platformv1.GetCertificateResponse)
	if !ok {
		t.Fatalf("expected *platformv1.GetCertificateResponse, got %T", result)
	}

	if resp.Certificate == nil {
		t.Error("expected certificate in response")
	}
}

func TestMCPServiceProvider_CAGet_SuccessIntermediateCertCoverage(t *testing.T) {
	ctx := context.Background()
	mockCA := newMockCAForMCPCoverage()
	caService := createCAGRPCServiceForMCPCoverage(mockCA)

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CAService: caService,
		Logger:    slog.Default(),
	})

	serial := hex.EncodeToString(mockCA.intermCert.SerialNumber.Bytes())

	result, err := provider.CAGet(ctx, serial, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resp, ok := result.(*platformv1.GetCertificateResponse)
	if !ok {
		t.Fatalf("expected *platformv1.GetCertificateResponse, got %T", result)
	}

	if resp.Certificate == nil {
		t.Error("expected certificate in response")
	}
}

func TestMCPServiceProvider_CAGet_SuccessStoredCertCoverage(t *testing.T) {
	ctx := context.Background()
	mockCA := newMockCAForMCPCoverage()

	// Issue and store a certificate
	cert := generateTestCertificateForMCPCoverage("stored.example.com", false, mockCA.intermCert, mockCA.privateKey)
	mockCA.certStore.StoreCertificate(cert)

	caService := createCAGRPCServiceForMCPCoverage(mockCA)

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CAService: caService,
		Logger:    slog.Default(),
	})

	serial := hex.EncodeToString(cert.SerialNumber.Bytes())

	result, err := provider.CAGet(ctx, serial, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resp, ok := result.(*platformv1.GetCertificateResponse)
	if !ok {
		t.Fatalf("expected *platformv1.GetCertificateResponse, got %T", result)
	}

	if resp.Certificate == nil {
		t.Error("expected certificate in response")
	}
}

func TestMCPServiceProvider_CAGet_NotFoundCoverage(t *testing.T) {
	ctx := context.Background()
	mockCA := newMockCAForMCPCoverage()
	caService := createCAGRPCServiceForMCPCoverage(mockCA)

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CAService: caService,
		Logger:    slog.Default(),
	})

	_, err := provider.CAGet(ctx, "nonexistent-serial", true)
	if err == nil {
		t.Fatal("expected error for nonexistent certificate")
	}
}

// =============================================================================
// CAList Tests - Success Paths
// =============================================================================

func TestMCPServiceProvider_CAList_SuccessCoverage(t *testing.T) {
	ctx := context.Background()
	mockCA := newMockCAForMCPCoverage()
	caService := createCAGRPCServiceForMCPCoverage(mockCA)

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CAService: caService,
		Logger:    slog.Default(),
	})

	result, err := provider.CAList(ctx, 50, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resp, ok := result.(*platformv1.ListCertificatesResponse)
	if !ok {
		t.Fatalf("expected *platformv1.ListCertificatesResponse, got %T", result)
	}

	// Should include root and intermediate certificates
	if len(resp.Certificates) < 2 {
		t.Errorf("expected at least 2 certificates (root + intermediate), got %d", len(resp.Certificates))
	}

	if resp.Pagination == nil {
		t.Error("expected pagination info")
	}
}

func TestMCPServiceProvider_CAList_WithDefaultPageSizeCoverage(t *testing.T) {
	ctx := context.Background()
	mockCA := newMockCAForMCPCoverage()
	caService := createCAGRPCServiceForMCPCoverage(mockCA)

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CAService: caService,
		Logger:    slog.Default(),
	})

	// Test with limit=0 which should use default page size
	result, err := provider.CAList(ctx, 0, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resp, ok := result.(*platformv1.ListCertificatesResponse)
	if !ok {
		t.Fatalf("expected *platformv1.ListCertificatesResponse, got %T", result)
	}

	if resp.Pagination.PageSize != 50 {
		t.Errorf("expected default page size 50, got %d", resp.Pagination.PageSize)
	}
}

func TestMCPServiceProvider_CAList_WithCustomPageSizeCoverage(t *testing.T) {
	ctx := context.Background()
	mockCA := newMockCAForMCPCoverage()
	caService := createCAGRPCServiceForMCPCoverage(mockCA)

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CAService: caService,
		Logger:    slog.Default(),
	})

	result, err := provider.CAList(ctx, 10, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resp, ok := result.(*platformv1.ListCertificatesResponse)
	if !ok {
		t.Fatalf("expected *platformv1.ListCertificatesResponse, got %T", result)
	}

	if resp.Pagination.PageSize != 10 {
		t.Errorf("expected page size 10, got %d", resp.Pagination.PageSize)
	}
}

// =============================================================================
// CARevoke Tests - Success Paths
// =============================================================================

func TestMCPServiceProvider_CARevoke_SuccessCoverage(t *testing.T) {
	ctx := context.Background()
	mockCA := newMockCAForMCPCoverage()

	// Issue and store a certificate to revoke
	cert := generateTestCertificateForMCPCoverage("revoke.example.com", false, mockCA.intermCert, mockCA.privateKey)
	mockCA.certStore.StoreCertificate(cert)

	caService := createCAGRPCServiceForMCPCoverage(mockCA)

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CAService: caService,
		Logger:    slog.Default(),
	})

	serial := hex.EncodeToString(cert.SerialNumber.Bytes())

	result, err := provider.CARevoke(ctx, serial, 1, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resp, ok := result.(*platformv1.RevokeCertificateResponse)
	if !ok {
		t.Fatalf("expected *platformv1.RevokeCertificateResponse, got %T", result)
	}

	if resp.Status == nil || !resp.Status.Success {
		t.Error("expected successful status")
	}

	if resp.CertificateStatus != platformv1.CertificateStatus_CERTIFICATE_STATUS_REVOKED {
		t.Errorf("expected REVOKED status, got %v", resp.CertificateStatus)
	}

	// Verify the certificate was revoked in the mock
	if len(mockCA.revokedCerts) != 1 {
		t.Errorf("expected 1 revoked cert, got %d", len(mockCA.revokedCerts))
	}
}

func TestMCPServiceProvider_CARevoke_WithDeleteKeysCoverage(t *testing.T) {
	ctx := context.Background()
	mockCA := newMockCAForMCPCoverage()

	cert := generateTestCertificateForMCPCoverage("revoke-with-keys.example.com", false, mockCA.intermCert, mockCA.privateKey)
	mockCA.certStore.StoreCertificate(cert)

	caService := createCAGRPCServiceForMCPCoverage(mockCA)

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CAService: caService,
		Logger:    slog.Default(),
	})

	serial := hex.EncodeToString(cert.SerialNumber.Bytes())

	result, err := provider.CARevoke(ctx, serial, 2, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resp, ok := result.(*platformv1.RevokeCertificateResponse)
	if !ok {
		t.Fatalf("expected *platformv1.RevokeCertificateResponse, got %T", result)
	}

	if resp.Status == nil || !resp.Status.Success {
		t.Error("expected successful status")
	}
}

func TestMCPServiceProvider_CARevoke_ErrorCoverage(t *testing.T) {
	ctx := context.Background()
	mockCA := newMockCAForMCPCoverage()
	mockCA.revokeErr = errors.New("revocation failed")

	cert := generateTestCertificateForMCPCoverage("revoke-error.example.com", false, mockCA.intermCert, mockCA.privateKey)
	mockCA.certStore.StoreCertificate(cert)

	caService := createCAGRPCServiceForMCPCoverage(mockCA)

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CAService: caService,
		Logger:    slog.Default(),
	})

	serial := hex.EncodeToString(cert.SerialNumber.Bytes())

	_, err := provider.CARevoke(ctx, serial, 1, false)
	if err == nil {
		t.Fatal("expected error from CA service")
	}
}

func TestMCPServiceProvider_CARevoke_NotFoundCoverage(t *testing.T) {
	ctx := context.Background()
	mockCA := newMockCAForMCPCoverage()
	caService := createCAGRPCServiceForMCPCoverage(mockCA)

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CAService: caService,
		Logger:    slog.Default(),
	})

	_, err := provider.CARevoke(ctx, "nonexistent-serial", 1, false)
	if err == nil {
		t.Fatal("expected error for nonexistent certificate")
	}
}

// =============================================================================
// CARenew Tests - Success Paths
// =============================================================================

func TestMCPServiceProvider_CARenew_SuccessCoverage(t *testing.T) {
	ctx := context.Background()
	mockCA := newMockCAForMCPCoverage()

	// Issue and store a certificate to renew
	cert := generateTestCertificateForMCPCoverage("renew.example.com", false, mockCA.intermCert, mockCA.privateKey)
	mockCA.certStore.StoreCertificate(cert)

	caService := createCAGRPCServiceForMCPCoverage(mockCA)

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CAService: caService,
		Logger:    slog.Default(),
	})

	serial := hex.EncodeToString(cert.SerialNumber.Bytes())

	result, err := provider.CARenew(ctx, serial, 365, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resp, ok := result.(*platformv1.RenewCertificateResponse)
	if !ok {
		t.Fatalf("expected *platformv1.RenewCertificateResponse, got %T", result)
	}

	if resp.Status == nil || !resp.Status.Success {
		t.Error("expected successful status")
	}

	if resp.NewCertificate == nil {
		t.Error("expected new certificate in response")
	}
}

func TestMCPServiceProvider_CARenew_NotFoundCoverage(t *testing.T) {
	ctx := context.Background()
	mockCA := newMockCAForMCPCoverage()
	caService := createCAGRPCServiceForMCPCoverage(mockCA)

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CAService: caService,
		Logger:    slog.Default(),
	})

	_, err := provider.CARenew(ctx, "nonexistent-serial", 365, true)
	if err == nil {
		t.Fatal("expected error for nonexistent certificate")
	}
}

func TestMCPServiceProvider_CARenew_ErrorCoverage(t *testing.T) {
	ctx := context.Background()
	mockCA := newMockCAForMCPCoverage()
	mockCA.issueCertErr = errors.New("failed to renew certificate")

	cert := generateTestCertificateForMCPCoverage("renew-error.example.com", false, mockCA.intermCert, mockCA.privateKey)
	mockCA.certStore.StoreCertificate(cert)

	caService := createCAGRPCServiceForMCPCoverage(mockCA)

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CAService: caService,
		Logger:    slog.Default(),
	})

	serial := hex.EncodeToString(cert.SerialNumber.Bytes())

	_, err := provider.CARenew(ctx, serial, 365, false)
	if err == nil {
		t.Fatal("expected error from CA service")
	}
}

// =============================================================================
// CAVerify Tests - Success Paths
// =============================================================================

func TestMCPServiceProvider_CAVerify_SuccessDERCoverage(t *testing.T) {
	ctx := context.Background()
	mockCA := newMockCAForMCPCoverage()
	caService := createCAGRPCServiceForMCPCoverage(mockCA)

	// Create a certificate to verify
	cert := generateTestCertificateForMCPCoverage("verify.example.com", false, mockCA.rootCert, mockCA.privateKey)

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CAService: caService,
		Logger:    slog.Default(),
	})

	result, err := provider.CAVerify(ctx, "", cert.Raw, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resp, ok := result.(*platformv1.VerifyCertificateResponse)
	if !ok {
		t.Fatalf("expected *platformv1.VerifyCertificateResponse, got %T", result)
	}

	if !resp.Valid {
		t.Error("expected valid certificate")
	}
}

func TestMCPServiceProvider_CAVerify_WithRevocationCheckCoverage(t *testing.T) {
	ctx := context.Background()
	mockCA := newMockCAForMCPCoverage()
	caService := createCAGRPCServiceForMCPCoverage(mockCA)

	cert := generateTestCertificateForMCPCoverage("verify-revocation.example.com", false, mockCA.rootCert, mockCA.privateKey)

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CAService: caService,
		Logger:    slog.Default(),
	})

	result, err := provider.CAVerify(ctx, "", cert.Raw, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resp, ok := result.(*platformv1.VerifyCertificateResponse)
	if !ok {
		t.Fatalf("expected *platformv1.VerifyCertificateResponse, got %T", result)
	}

	_ = resp // Response structure validation
}

// =============================================================================
// CACRL Tests - Success Paths
// =============================================================================

func TestMCPServiceProvider_CACRL_SuccessCoverage(t *testing.T) {
	ctx := context.Background()
	mockCA := newMockCAForMCPCoverage()
	caService := createCAGRPCServiceForMCPCoverage(mockCA)

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CAService: caService,
		Logger:    slog.Default(),
	})

	result, err := provider.CACRL(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resp, ok := result.(*platformv1.GetCRLResponse)
	if !ok {
		t.Fatalf("expected *platformv1.GetCRLResponse, got %T", result)
	}

	if resp.Crl == nil || len(resp.Crl.Data) == 0 {
		t.Error("expected CRL data in response")
	}
}

func TestMCPServiceProvider_CACRL_ErrorCoverage(t *testing.T) {
	ctx := context.Background()
	mockCA := newMockCAForMCPCoverage()
	mockCA.generateCRLErr = errors.New("CRL generation failed")
	caService := createCAGRPCServiceForMCPCoverage(mockCA)

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CAService: caService,
		Logger:    slog.Default(),
	})

	_, err := provider.CACRL(ctx)
	if err == nil {
		t.Fatal("expected error from CA service")
	}
}

// =============================================================================
// CABundle Tests - Success Paths
// =============================================================================

func TestMCPServiceProvider_CABundle_SuccessCoverage(t *testing.T) {
	ctx := context.Background()
	mockCA := newMockCAForMCPCoverage()
	caService := createCAGRPCServiceForMCPCoverage(mockCA)

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CAService: caService,
		Logger:    slog.Default(),
	})

	result, err := provider.CABundle(ctx, "software", "RSA")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resp, ok := result.(*platformv1.GetCABundleResponse)
	if !ok {
		t.Fatalf("expected *platformv1.GetCABundleResponse, got %T", result)
	}

	if resp.Bundle == nil || len(resp.Bundle.Pem) == 0 {
		t.Error("expected bundle PEM in response")
	}
}

func TestMCPServiceProvider_CABundle_ErrorCoverage(t *testing.T) {
	ctx := context.Background()
	mockCA := newMockCAForMCPCoverage()
	mockCA.bundleErr = errors.New("bundle error")
	caService := createCAGRPCServiceForMCPCoverage(mockCA)

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CAService: caService,
		Logger:    slog.Default(),
	})

	_, err := provider.CABundle(ctx, "software", "RSA")
	if err == nil {
		t.Fatal("expected error from CA service")
	}
}

func TestMCPServiceProvider_CABundle_VariousStoreTypesCoverage(t *testing.T) {
	ctx := context.Background()
	mockCA := newMockCAForMCPCoverage()
	caService := createCAGRPCServiceForMCPCoverage(mockCA)

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CAService: caService,
		Logger:    slog.Default(),
	})

	storeTypes := []string{"software", "tpm", "hsm", "pkcs11", ""}
	algorithms := []string{"RSA", "ECC", "ED25519", ""}

	for _, storeType := range storeTypes {
		for _, algorithm := range algorithms {
			t.Run(storeType+"_"+algorithm, func(t *testing.T) {
				result, err := provider.CABundle(ctx, storeType, algorithm)
				if err != nil {
					t.Fatalf("unexpected error for storeType=%q algorithm=%q: %v", storeType, algorithm, err)
				}

				resp, ok := result.(*platformv1.GetCABundleResponse)
				if !ok {
					t.Fatalf("expected *platformv1.GetCABundleResponse, got %T", result)
				}

				if resp.Bundle == nil || len(resp.Bundle.Pem) == 0 {
					t.Error("expected bundle PEM in response")
				}
			})
		}
	}
}

// =============================================================================
// Nil Service Tests (ensure error paths still work)
// =============================================================================

func TestMCPServiceProvider_CA_NilServiceCoverage(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	tests := []struct {
		name string
		fn   func() error
	}{
		{"CAInfo", func() error {
			_, err := provider.CAInfo(ctx)
			return err
		}},
		{"CAIssue", func() error {
			_, err := provider.CAIssue(ctx, &mcp.CAIssueRequest{CommonName: "test"})
			return err
		}},
		{"CAGet", func() error {
			_, err := provider.CAGet(ctx, "serial", true)
			return err
		}},
		{"CAList", func() error {
			_, err := provider.CAList(ctx, 10, "", "")
			return err
		}},
		{"CARevoke", func() error {
			_, err := provider.CARevoke(ctx, "serial", 1, false)
			return err
		}},
		{"CARenew", func() error {
			_, err := provider.CARenew(ctx, "serial", 365, true)
			return err
		}},
		{"CAVerify", func() error {
			_, err := provider.CAVerify(ctx, "pem", nil, false)
			return err
		}},
		{"CACRL", func() error {
			_, err := provider.CACRL(ctx)
			return err
		}},
		{"CABundle", func() error {
			_, err := provider.CABundle(ctx, "software", "RSA")
			return err
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			if err == nil {
				t.Fatalf("%s: expected error for nil CA service", tt.name)
			}

			svcErr, ok := err.(ErrServiceNotAvailable)
			if !ok {
				t.Fatalf("%s: expected ErrServiceNotAvailable, got %T: %v", tt.name, err, err)
			}
			if svcErr.Service != "ca" {
				t.Errorf("%s: expected service='ca', got %q", tt.name, svcErr.Service)
			}
		})
	}
}

// =============================================================================
// Health Service Tests with CA Integration
// =============================================================================

func TestMCPServiceProvider_Health_WithCAServiceCoverage(t *testing.T) {
	ctx := context.Background()

	healthConfig := DefaultConfig()
	healthService, err := NewService(healthConfig)
	if err != nil {
		t.Skipf("cannot create health service: %v", err)
	}
	healthService.MarkReady()

	mockCA := newMockCAForMCPCoverage()
	caService := createCAGRPCServiceForMCPCoverage(mockCA)

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CAService:     caService,
		HealthService: healthService,
		Logger:        slog.Default(),
	})

	// Test Health
	result, err := provider.Health(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resp, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}

	status, _ := resp["status"].(string)
	if status == "" || status == "unspecified" {
		t.Error("expected specific health status")
	}

	// Test Liveness
	livenessResult, err := provider.Liveness(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	livenessMap, ok := livenessResult.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", livenessResult)
	}

	if _, exists := livenessMap["live"]; !exists {
		t.Error("expected 'live' key in liveness result")
	}

	// Test Readiness
	readinessResult, err := provider.Readiness(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	readinessMap, ok := readinessResult.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", readinessResult)
	}

	if _, exists := readinessMap["ready"]; !exists {
		t.Error("expected 'ready' key in readiness result")
	}
}

// =============================================================================
// Edge Case Tests
// =============================================================================

func TestMCPServiceProvider_CAIssue_AllAlgorithmsCoverage(t *testing.T) {
	ctx := context.Background()
	mockCA := newMockCAForMCPCoverage()
	caService := createCAGRPCServiceForMCPCoverage(mockCA)

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CAService: caService,
		Logger:    slog.Default(),
	})

	algorithms := []string{
		"RSA",
		"RSA2048",
		"RSA-2048",
		"RSA3072",
		"RSA-3072",
		"RSA4096",
		"RSA-4096",
		"ECDSA",
		"EC",
		"ECDSA-P256",
		"P256",
		"ECDSA-P384",
		"P384",
		"ECDSA-P521",
		"P521",
		"ED25519",
	}

	for _, alg := range algorithms {
		t.Run(alg, func(t *testing.T) {
			req := &mcp.CAIssueRequest{
				CommonName: "test-" + alg + ".example.com",
				Algorithm:  alg,
				ValidDays:  365,
			}

			result, err := provider.CAIssue(ctx, req)
			if err != nil {
				t.Fatalf("unexpected error for algorithm %s: %v", alg, err)
			}

			resp, ok := result.(*platformv1.IssueCertificateResponse)
			if !ok {
				t.Fatalf("expected *platformv1.IssueCertificateResponse, got %T", result)
			}

			if resp.Status == nil || !resp.Status.Success {
				t.Errorf("expected successful status for algorithm %s", alg)
			}
		})
	}
}

func TestMCPServiceProvider_CARevoke_MultipleReasonsCoverage(t *testing.T) {
	ctx := context.Background()
	mockCA := newMockCAForMCPCoverage()
	caService := createCAGRPCServiceForMCPCoverage(mockCA)

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CAService: caService,
		Logger:    slog.Default(),
	})

	reasons := []int{0, 1, 2, 3, 4, 5, 6}

	for _, reason := range reasons {
		t.Run("reason_"+string(rune('0'+reason)), func(t *testing.T) {
			// Create a new certificate for each test
			cert := generateTestCertificateForMCPCoverage("revoke-reason.example.com", false, mockCA.intermCert, mockCA.privateKey)
			mockCA.certStore.StoreCertificate(cert)
			serial := hex.EncodeToString(cert.SerialNumber.Bytes())

			result, err := provider.CARevoke(ctx, serial, reason, false)
			if err != nil {
				t.Fatalf("unexpected error for reason %d: %v", reason, err)
			}

			resp, ok := result.(*platformv1.RevokeCertificateResponse)
			if !ok {
				t.Fatalf("expected *platformv1.RevokeCertificateResponse, got %T", result)
			}

			if resp.Status == nil || !resp.Status.Success {
				t.Errorf("expected successful status for reason %d", reason)
			}
		})
	}
}

func TestMCPServiceProvider_CARenew_VariousValidityPeriodsCoverage(t *testing.T) {
	ctx := context.Background()
	mockCA := newMockCAForMCPCoverage()
	caService := createCAGRPCServiceForMCPCoverage(mockCA)

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CAService: caService,
		Logger:    slog.Default(),
	})

	validityDays := []int{30, 90, 180, 365, 730, 1095}

	for _, days := range validityDays {
		t.Run("days_"+string(rune('0'+days/100))+string(rune('0'+(days%100)/10))+string(rune('0'+days%10)), func(t *testing.T) {
			// Create a new certificate for each test
			cert := generateTestCertificateForMCPCoverage("renew-validity.example.com", false, mockCA.intermCert, mockCA.privateKey)
			mockCA.certStore.StoreCertificate(cert)
			serial := hex.EncodeToString(cert.SerialNumber.Bytes())

			result, err := provider.CARenew(ctx, serial, days, true)
			if err != nil {
				t.Fatalf("unexpected error for %d days: %v", days, err)
			}

			resp, ok := result.(*platformv1.RenewCertificateResponse)
			if !ok {
				t.Fatalf("expected *platformv1.RenewCertificateResponse, got %T", result)
			}

			if resp.Status == nil || !resp.Status.Success {
				t.Errorf("expected successful status for %d days", days)
			}
		})
	}
}

// =============================================================================
// Timestamp Verification Tests
// =============================================================================

func TestMCPServiceProvider_CA_TimestampsPresentCoverage(t *testing.T) {
	ctx := context.Background()
	mockCA := newMockCAForMCPCoverage()
	caService := createCAGRPCServiceForMCPCoverage(mockCA)

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CAService: caService,
		Logger:    slog.Default(),
	})

	// Test CAInfo timestamp
	t.Run("CAInfo", func(t *testing.T) {
		result, err := provider.CAInfo(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		resp := result.(*platformv1.GetCAInfoResponse)
		if resp.Timestamp == nil {
			t.Error("expected timestamp in CAInfo response")
		}
	})

	// Test CAIssue timestamp
	t.Run("CAIssue", func(t *testing.T) {
		result, err := provider.CAIssue(ctx, &mcp.CAIssueRequest{
			CommonName: "timestamp-test.example.com",
			ValidDays:  365,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		resp := result.(*platformv1.IssueCertificateResponse)
		if resp.Timestamp == nil {
			t.Error("expected timestamp in CAIssue response")
		}
	})

	// Test CAList timestamp
	t.Run("CAList", func(t *testing.T) {
		result, err := provider.CAList(ctx, 10, "", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		resp := result.(*platformv1.ListCertificatesResponse)
		if resp.Timestamp == nil {
			t.Error("expected timestamp in CAList response")
		}
	})

	// Test CACRL timestamp
	t.Run("CACRL", func(t *testing.T) {
		result, err := provider.CACRL(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		resp := result.(*platformv1.GetCRLResponse)
		if resp.Timestamp == nil {
			t.Error("expected timestamp in CACRL response")
		}
	})

	// Test CABundle timestamp
	t.Run("CABundle", func(t *testing.T) {
		result, err := provider.CABundle(ctx, "software", "RSA")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		resp := result.(*platformv1.GetCABundleResponse)
		if resp.Timestamp == nil {
			t.Error("expected timestamp in CABundle response")
		}
	})
}
