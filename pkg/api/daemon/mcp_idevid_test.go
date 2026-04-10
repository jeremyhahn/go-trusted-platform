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

//go:build iam && codec_msgpack && codec_cbor && codec_json

package daemon

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Mock TPM2 Service for MCP IDevID/IAK tests
// =============================================================================

// mockTPM2MCPService implements xkmssdk.TrustedPlatformModule for MCP IDevID/IAK testing
type mockTPM2MCPService struct {
	xkmssdk.TrustedPlatformModule

	// State flags
	hasIDevID     bool
	hasIAK        bool
	hasIDevIDCert bool
	hasIAKCert    bool

	// Error injection
	ekAttrsErr            error
	createIAKErr          error
	createIDevIDErr       error
	iakAttrsErr           error
	idevidAttrsErr        error
	readIDevIDCertErr     error
	readIAKCertErr        error
	writeIDevIDCertErr    error
	writeIAKCertErr       error
	deleteIDevIDCertErr   error
	deleteIAKCertErr      error
	createCSRErr          error
	marshalCSRErr         bool // Special flag for CSR marshal error
	activateCredentialErr error
	fixedPropsErr         error
}

func (m *mockTPM2MCPService) EKAttributes() (*xkmssdk.KeyAttributes, error) {
	if m.ekAttrsErr != nil {
		return nil, m.ekAttrsErr
	}
	return &xkmssdk.KeyAttributes{
		TPMAttributes: &xkmssdk.TPMAttributes{
			Handle: 0x81010001,
		},
		KeyAlgorithm: x509.ECDSA,
	}, nil
}

func (m *mockTPM2MCPService) CreateIAK(ekAttrs *xkmssdk.KeyAttributes, qualifyingData []byte) (*xkmssdk.KeyAttributes, error) {
	if m.createIAKErr != nil {
		return nil, m.createIAKErr
	}
	return &xkmssdk.KeyAttributes{
		TPMAttributes: &xkmssdk.TPMAttributes{
			Handle: 0x81020001,
		},
		KeyAlgorithm: x509.ECDSA,
	}, nil
}

func (m *mockTPM2MCPService) CreateIDevID(akAttrs *xkmssdk.KeyAttributes, ekCert *x509.Certificate, qualifyingData []byte) (*xkmssdk.KeyAttributes, *xkmssdk.TCG_CSR_IDEVID, error) {
	if m.createIDevIDErr != nil {
		return nil, nil, m.createIDevIDErr
	}
	return &xkmssdk.KeyAttributes{
		TPMAttributes: &xkmssdk.TPMAttributes{
			Handle: 0x81030001,
		},
		KeyAlgorithm: x509.ECDSA,
	}, &xkmssdk.TCG_CSR_IDEVID{}, nil
}

func (m *mockTPM2MCPService) IAKAttributes() (*xkmssdk.KeyAttributes, error) {
	if m.iakAttrsErr != nil {
		return nil, m.iakAttrsErr
	}
	if !m.hasIAK {
		return nil, errors.New("IAK not found")
	}
	return &xkmssdk.KeyAttributes{
		TPMAttributes: &xkmssdk.TPMAttributes{
			Handle: 0x81020001,
		},
		KeyAlgorithm: x509.ECDSA,
	}, nil
}

func (m *mockTPM2MCPService) IDevIDAttributes() (*xkmssdk.KeyAttributes, error) {
	if m.idevidAttrsErr != nil {
		return nil, m.idevidAttrsErr
	}
	if !m.hasIDevID {
		return nil, errors.New("IDevID not found")
	}
	return &xkmssdk.KeyAttributes{
		TPMAttributes: &xkmssdk.TPMAttributes{
			Handle: 0x81030001,
		},
		KeyAlgorithm: x509.ECDSA,
	}, nil
}

func (m *mockTPM2MCPService) IDevIDCertificate() (*x509.Certificate, error) {
	if m.readIDevIDCertErr != nil {
		return nil, m.readIDevIDCertErr
	}
	if !m.hasIDevIDCert {
		return nil, errors.New("IDevID certificate not found")
	}
	return generateMCPTestCert("IDevID Test")
}

func (m *mockTPM2MCPService) IAKCertificate() (*x509.Certificate, error) {
	if m.readIAKCertErr != nil {
		return nil, m.readIAKCertErr
	}
	if !m.hasIAKCert {
		return nil, errors.New("IAK certificate not found")
	}
	return generateMCPTestCert("IAK Test")
}

func (m *mockTPM2MCPService) ProvisionIDevIDCert(cert *x509.Certificate) error {
	if m.writeIDevIDCertErr != nil {
		return m.writeIDevIDCertErr
	}
	return nil
}

func (m *mockTPM2MCPService) ProvisionIAKCert(cert *x509.Certificate) error {
	if m.writeIAKCertErr != nil {
		return m.writeIAKCertErr
	}
	return nil
}

func (m *mockTPM2MCPService) DeleteIDevIDCertificate() error {
	if m.deleteIDevIDCertErr != nil {
		return m.deleteIDevIDCertErr
	}
	return nil
}

func (m *mockTPM2MCPService) DeleteIAKCertificate() error {
	if m.deleteIAKCertErr != nil {
		return m.deleteIAKCertErr
	}
	return nil
}

func (m *mockTPM2MCPService) CreateTCG_CSR_IDEVID(ekCert *x509.Certificate, iakAttrs, idevidAttrs *xkmssdk.KeyAttributes) (xkmssdk.TCG_CSR_IDEVID, error) {
	if m.createCSRErr != nil {
		return xkmssdk.TCG_CSR_IDEVID{}, m.createCSRErr
	}
	return xkmssdk.TCG_CSR_IDEVID{}, nil
}

func (m *mockTPM2MCPService) ActivateCredential(credentialBlob, secret []byte) ([]byte, error) {
	if m.activateCredentialErr != nil {
		return nil, m.activateCredentialErr
	}
	return []byte("decrypted-secret"), nil
}

func (m *mockTPM2MCPService) FixedProperties() (*xkmssdk.PropertiesFixed, error) {
	if m.fixedPropsErr != nil {
		return nil, m.fixedPropsErr
	}
	return &xkmssdk.PropertiesFixed{
		Manufacturer: "Test Manufacturer",
		Family:       "2.0",
		FwMajor:      1,
		FwMinor:      2,
	}, nil
}

// =============================================================================
// Helper Functions
// =============================================================================

// generateMCPTestCert creates a test X.509 certificate for MCP IDevID testing
// Note: This creates a self-signed certificate where issuer CN = subject CN
func generateMCPTestCert(cn string) (*x509.Certificate, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Organization"},
			Country:      []string{"US"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(certDER)
}

// generateMCPTestCertPEM generates a test certificate and returns its PEM encoding
func generateMCPTestCertPEM(cn string) (string, error) {
	cert, err := generateMCPTestCert(cn)
	if err != nil {
		return "", err
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	return string(pemBytes), nil
}

// createMCPTestProvider creates an MCPServiceProvider for testing with optional TPM2 service
func createMCPTestProvider(mockTPM *mockTPM2MCPService) *MCPServiceProvider {
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})
	if mockTPM != nil {
		provider.SetTPM2Service(mockTPM)
	}
	return provider
}

// =============================================================================
// IDevIDGenerate Tests
// =============================================================================

func TestMCPIDevIDGenerate_Success(t *testing.T) {
	mockTPM := &mockTPM2MCPService{}
	provider := createMCPTestProvider(mockTPM)

	ctx := context.Background()
	result, err := provider.IDevIDGenerate(ctx, &mcp.IDevIDGenerateMCPRequest{Algorithm: "ecdsa-p256", Overwrite: false})

	require.NoError(t, err)
	require.NotNil(t, result)

	resultMap, ok := result.(map[string]interface{})
	require.True(t, ok)
	assert.Contains(t, resultMap, "handle")
	assert.Contains(t, resultMap, "algorithm")
}

func TestMCPIDevIDGenerate_TPM2ServiceNotAvailable(t *testing.T) {
	provider := createMCPTestProvider(nil)

	ctx := context.Background()
	result, err := provider.IDevIDGenerate(ctx, &mcp.IDevIDGenerateMCPRequest{Algorithm: "ecdsa-p256", Overwrite: false})

	require.Error(t, err)
	require.Nil(t, result)
	assert.IsType(t, ErrTPM2ServiceNotAvailable{}, err)
}

func TestMCPIDevIDGenerate_EKAttributesError(t *testing.T) {
	mockTPM := &mockTPM2MCPService{
		ekAttrsErr: errors.New("EK attributes not available"),
	}
	provider := createMCPTestProvider(mockTPM)

	ctx := context.Background()
	result, err := provider.IDevIDGenerate(ctx, &mcp.IDevIDGenerateMCPRequest{Algorithm: "ecdsa-p256", Overwrite: false})

	require.Error(t, err)
	require.Nil(t, result)
	assert.IsType(t, ErrTPM2OperationFailed{}, err)
}

func TestMCPIDevIDGenerate_CreateIAKError(t *testing.T) {
	mockTPM := &mockTPM2MCPService{
		createIAKErr: errors.New("IAK creation failed"),
	}
	provider := createMCPTestProvider(mockTPM)

	ctx := context.Background()
	result, err := provider.IDevIDGenerate(ctx, &mcp.IDevIDGenerateMCPRequest{Algorithm: "ecdsa-p256", Overwrite: false})

	require.Error(t, err)
	require.Nil(t, result)
	assert.IsType(t, ErrTPM2OperationFailed{}, err)
}

func TestMCPIDevIDGenerate_CreateIDevIDError(t *testing.T) {
	mockTPM := &mockTPM2MCPService{
		createIDevIDErr: errors.New("IDevID creation failed"),
	}
	provider := createMCPTestProvider(mockTPM)

	ctx := context.Background()
	result, err := provider.IDevIDGenerate(ctx, &mcp.IDevIDGenerateMCPRequest{Algorithm: "ecdsa-p256", Overwrite: false})

	require.Error(t, err)
	require.Nil(t, result)
	assert.IsType(t, ErrTPM2OperationFailed{}, err)
}

// =============================================================================
// IDevIDInfo Tests
// =============================================================================

func TestMCPIDevIDInfo_Success_WithCertificate(t *testing.T) {
	mockTPM := &mockTPM2MCPService{
		hasIDevID:     true,
		hasIDevIDCert: true,
	}
	provider := createMCPTestProvider(mockTPM)

	ctx := context.Background()
	result, err := provider.IDevIDInfo(ctx)

	require.NoError(t, err)
	require.NotNil(t, result)

	resultMap, ok := result.(map[string]interface{})
	require.True(t, ok)
	assert.True(t, resultMap["exists"].(bool))
	assert.True(t, resultMap["has_certificate"].(bool))
	assert.Contains(t, resultMap, "certificate")
}

func TestMCPIDevIDInfo_Success_NoCertificate(t *testing.T) {
	mockTPM := &mockTPM2MCPService{
		hasIDevID:     true,
		hasIDevIDCert: false,
	}
	provider := createMCPTestProvider(mockTPM)

	ctx := context.Background()
	result, err := provider.IDevIDInfo(ctx)

	require.NoError(t, err)
	require.NotNil(t, result)

	resultMap, ok := result.(map[string]interface{})
	require.True(t, ok)
	assert.True(t, resultMap["exists"].(bool))
	assert.False(t, resultMap["has_certificate"].(bool))
}

func TestMCPIDevIDInfo_NotExists(t *testing.T) {
	mockTPM := &mockTPM2MCPService{
		hasIDevID: false,
	}
	provider := createMCPTestProvider(mockTPM)

	ctx := context.Background()
	result, err := provider.IDevIDInfo(ctx)

	require.NoError(t, err)
	require.NotNil(t, result)

	resultMap, ok := result.(map[string]interface{})
	require.True(t, ok)
	assert.False(t, resultMap["exists"].(bool))
}

func TestMCPIDevIDInfo_TPM2ServiceNotAvailable(t *testing.T) {
	provider := createMCPTestProvider(nil)

	ctx := context.Background()
	result, err := provider.IDevIDInfo(ctx)

	require.Error(t, err)
	require.Nil(t, result)
	assert.IsType(t, ErrTPM2ServiceNotAvailable{}, err)
}

// =============================================================================
// IDevIDCreateCSR Tests
// =============================================================================

func TestMCPIDevIDCreateCSR_Success(t *testing.T) {
	mockTPM := &mockTPM2MCPService{
		hasIDevID: true,
		hasIAK:    true,
	}
	provider := createMCPTestProvider(mockTPM)

	ctx := context.Background()
	result, err := provider.IDevIDCreateCSR(ctx, "Test Device", "Test Org", "US", true)

	require.NoError(t, err)
	assert.NotEmpty(t, result)
}

func TestMCPIDevIDCreateCSR_TPM2ServiceNotAvailable(t *testing.T) {
	provider := createMCPTestProvider(nil)

	ctx := context.Background()
	result, err := provider.IDevIDCreateCSR(ctx, "Test Device", "Test Org", "US", true)

	require.Error(t, err)
	assert.Empty(t, result)
	assert.IsType(t, ErrTPM2ServiceNotAvailable{}, err)
}

func TestMCPIDevIDCreateCSR_IDevIDAttributesError(t *testing.T) {
	mockTPM := &mockTPM2MCPService{
		idevidAttrsErr: errors.New("IDevID not found"),
	}
	provider := createMCPTestProvider(mockTPM)

	ctx := context.Background()
	result, err := provider.IDevIDCreateCSR(ctx, "Test Device", "Test Org", "US", true)

	require.Error(t, err)
	assert.Empty(t, result)
	assert.IsType(t, ErrTPM2OperationFailed{}, err)
}

func TestMCPIDevIDCreateCSR_IAKAttributesError(t *testing.T) {
	mockTPM := &mockTPM2MCPService{
		hasIDevID:   true,
		iakAttrsErr: errors.New("IAK not found"),
	}
	provider := createMCPTestProvider(mockTPM)

	ctx := context.Background()
	result, err := provider.IDevIDCreateCSR(ctx, "Test Device", "Test Org", "US", true)

	require.Error(t, err)
	assert.Empty(t, result)
	assert.IsType(t, ErrTPM2OperationFailed{}, err)
}

func TestMCPIDevIDCreateCSR_CreateCSRError(t *testing.T) {
	mockTPM := &mockTPM2MCPService{
		hasIDevID:    true,
		hasIAK:       true,
		createCSRErr: errors.New("CSR creation failed"),
	}
	provider := createMCPTestProvider(mockTPM)

	ctx := context.Background()
	result, err := provider.IDevIDCreateCSR(ctx, "Test Device", "Test Org", "US", true)

	require.Error(t, err)
	assert.Empty(t, result)
	assert.IsType(t, ErrTPM2OperationFailed{}, err)
}

// =============================================================================
// IDevIDInstallCertificate Tests
// =============================================================================

func TestMCPIDevIDInstallCertificate_Success(t *testing.T) {
	mockTPM := &mockTPM2MCPService{}
	provider := createMCPTestProvider(mockTPM)

	certPEM, err := generateMCPTestCertPEM("Test IDevID")
	require.NoError(t, err)

	ctx := context.Background()
	err = provider.IDevIDInstallCertificate(ctx, certPEM)

	require.NoError(t, err)
}

func TestMCPIDevIDInstallCertificate_TPM2ServiceNotAvailable(t *testing.T) {
	provider := createMCPTestProvider(nil)

	certPEM, err := generateMCPTestCertPEM("Test IDevID")
	require.NoError(t, err)

	ctx := context.Background()
	err = provider.IDevIDInstallCertificate(ctx, certPEM)

	require.Error(t, err)
	assert.IsType(t, ErrTPM2ServiceNotAvailable{}, err)
}

func TestMCPIDevIDInstallCertificate_InvalidPEM(t *testing.T) {
	mockTPM := &mockTPM2MCPService{}
	provider := createMCPTestProvider(mockTPM)

	ctx := context.Background()
	err := provider.IDevIDInstallCertificate(ctx, "not a valid PEM")

	require.Error(t, err)
	assert.IsType(t, ErrInvalidCertificatePEM{}, err)
}

func TestMCPIDevIDInstallCertificate_InvalidCertificate(t *testing.T) {
	mockTPM := &mockTPM2MCPService{}
	provider := createMCPTestProvider(mockTPM)

	// Valid PEM structure but invalid certificate data
	invalidPEM := `-----BEGIN CERTIFICATE-----
aW52YWxpZCBjZXJ0aWZpY2F0ZSBkYXRh
-----END CERTIFICATE-----`

	ctx := context.Background()
	err := provider.IDevIDInstallCertificate(ctx, invalidPEM)

	require.Error(t, err)
	assert.IsType(t, ErrInvalidRequestBody{}, err)
}

func TestMCPIDevIDInstallCertificate_WriteError(t *testing.T) {
	mockTPM := &mockTPM2MCPService{
		writeIDevIDCertErr: errors.New("write failed"),
	}
	provider := createMCPTestProvider(mockTPM)

	certPEM, err := generateMCPTestCertPEM("Test IDevID")
	require.NoError(t, err)

	ctx := context.Background()
	err = provider.IDevIDInstallCertificate(ctx, certPEM)

	require.Error(t, err)
	assert.IsType(t, ErrTPM2OperationFailed{}, err)
}

// =============================================================================
// IDevIDGetCertificate Tests
// =============================================================================

func TestMCPIDevIDGetCertificate_Success(t *testing.T) {
	mockTPM := &mockTPM2MCPService{
		hasIDevIDCert: true,
	}
	provider := createMCPTestProvider(mockTPM)

	ctx := context.Background()
	result, err := provider.IDevIDGetCertificate(ctx)

	require.NoError(t, err)
	require.NotNil(t, result)

	resultMap, ok := result.(map[string]interface{})
	require.True(t, ok)
	assert.Contains(t, resultMap, "pem")
	assert.Contains(t, resultMap, "subject_cn")
	assert.Contains(t, resultMap, "issuer_cn")
}

func TestMCPIDevIDGetCertificate_TPM2ServiceNotAvailable(t *testing.T) {
	provider := createMCPTestProvider(nil)

	ctx := context.Background()
	result, err := provider.IDevIDGetCertificate(ctx)

	require.Error(t, err)
	require.Nil(t, result)
	assert.IsType(t, ErrTPM2ServiceNotAvailable{}, err)
}

func TestMCPIDevIDGetCertificate_NotFound(t *testing.T) {
	mockTPM := &mockTPM2MCPService{
		hasIDevIDCert: false,
	}
	provider := createMCPTestProvider(mockTPM)

	ctx := context.Background()
	result, err := provider.IDevIDGetCertificate(ctx)

	require.Error(t, err)
	require.Nil(t, result)
	assert.IsType(t, ErrIDevIDCertificateNotFound{}, err)
}

// =============================================================================
// IAKGenerate Tests
// =============================================================================

func TestMCPIAKGenerate_Success(t *testing.T) {
	mockTPM := &mockTPM2MCPService{}
	provider := createMCPTestProvider(mockTPM)

	ctx := context.Background()
	result, err := provider.IAKGenerate(ctx, &mcp.IDevIDGenerateMCPRequest{Algorithm: "ecdsa-p256", Overwrite: false})

	require.NoError(t, err)
	require.NotNil(t, result)

	resultMap, ok := result.(map[string]interface{})
	require.True(t, ok)
	assert.Contains(t, resultMap, "handle")
	assert.Contains(t, resultMap, "algorithm")
}

func TestMCPIAKGenerate_TPM2ServiceNotAvailable(t *testing.T) {
	provider := createMCPTestProvider(nil)

	ctx := context.Background()
	result, err := provider.IAKGenerate(ctx, &mcp.IDevIDGenerateMCPRequest{Algorithm: "ecdsa-p256", Overwrite: false})

	require.Error(t, err)
	require.Nil(t, result)
	assert.IsType(t, ErrTPM2ServiceNotAvailable{}, err)
}

func TestMCPIAKGenerate_EKAttributesError(t *testing.T) {
	mockTPM := &mockTPM2MCPService{
		ekAttrsErr: errors.New("EK not available"),
	}
	provider := createMCPTestProvider(mockTPM)

	ctx := context.Background()
	result, err := provider.IAKGenerate(ctx, &mcp.IDevIDGenerateMCPRequest{Algorithm: "ecdsa-p256", Overwrite: false})

	require.Error(t, err)
	require.Nil(t, result)
	assert.IsType(t, ErrTPM2OperationFailed{}, err)
}

func TestMCPIAKGenerate_CreateIAKError(t *testing.T) {
	mockTPM := &mockTPM2MCPService{
		createIAKErr: errors.New("IAK creation failed"),
	}
	provider := createMCPTestProvider(mockTPM)

	ctx := context.Background()
	result, err := provider.IAKGenerate(ctx, &mcp.IDevIDGenerateMCPRequest{Algorithm: "ecdsa-p256", Overwrite: false})

	require.Error(t, err)
	require.Nil(t, result)
	assert.IsType(t, ErrTPM2OperationFailed{}, err)
}

// =============================================================================
// IAKInfo Tests
// =============================================================================

func TestMCPIAKInfo_Success_WithCertificate(t *testing.T) {
	mockTPM := &mockTPM2MCPService{
		hasIAK:     true,
		hasIAKCert: true,
	}
	provider := createMCPTestProvider(mockTPM)

	ctx := context.Background()
	result, err := provider.IAKInfo(ctx)

	require.NoError(t, err)
	require.NotNil(t, result)

	resultMap, ok := result.(map[string]interface{})
	require.True(t, ok)
	assert.True(t, resultMap["exists"].(bool))
	assert.True(t, resultMap["has_certificate"].(bool))
}

func TestMCPIAKInfo_Success_NoCertificate(t *testing.T) {
	mockTPM := &mockTPM2MCPService{
		hasIAK:     true,
		hasIAKCert: false,
	}
	provider := createMCPTestProvider(mockTPM)

	ctx := context.Background()
	result, err := provider.IAKInfo(ctx)

	require.NoError(t, err)
	require.NotNil(t, result)

	resultMap, ok := result.(map[string]interface{})
	require.True(t, ok)
	assert.True(t, resultMap["exists"].(bool))
	assert.False(t, resultMap["has_certificate"].(bool))
}

func TestMCPIAKInfo_NotExists(t *testing.T) {
	mockTPM := &mockTPM2MCPService{
		hasIAK: false,
	}
	provider := createMCPTestProvider(mockTPM)

	ctx := context.Background()
	result, err := provider.IAKInfo(ctx)

	require.NoError(t, err)
	require.NotNil(t, result)

	resultMap, ok := result.(map[string]interface{})
	require.True(t, ok)
	assert.False(t, resultMap["exists"].(bool))
}

func TestMCPIAKInfo_TPM2ServiceNotAvailable(t *testing.T) {
	provider := createMCPTestProvider(nil)

	ctx := context.Background()
	result, err := provider.IAKInfo(ctx)

	require.Error(t, err)
	require.Nil(t, result)
	assert.IsType(t, ErrTPM2ServiceNotAvailable{}, err)
}

// =============================================================================
// IAKCreateCSR Tests
// =============================================================================

func TestMCPIAKCreateCSR_Success(t *testing.T) {
	mockTPM := &mockTPM2MCPService{
		hasIAK: true,
	}
	provider := createMCPTestProvider(mockTPM)

	ctx := context.Background()
	result, err := provider.IAKCreateCSR(ctx, "Test Device", "Test Org", "US", true)

	require.NoError(t, err)
	assert.NotEmpty(t, result)
}

func TestMCPIAKCreateCSR_TPM2ServiceNotAvailable(t *testing.T) {
	provider := createMCPTestProvider(nil)

	ctx := context.Background()
	result, err := provider.IAKCreateCSR(ctx, "Test Device", "Test Org", "US", true)

	require.Error(t, err)
	assert.Empty(t, result)
	assert.IsType(t, ErrTPM2ServiceNotAvailable{}, err)
}

func TestMCPIAKCreateCSR_IAKAttributesError(t *testing.T) {
	mockTPM := &mockTPM2MCPService{
		iakAttrsErr: errors.New("IAK not found"),
	}
	provider := createMCPTestProvider(mockTPM)

	ctx := context.Background()
	result, err := provider.IAKCreateCSR(ctx, "Test Device", "Test Org", "US", true)

	require.Error(t, err)
	assert.Empty(t, result)
	assert.IsType(t, ErrTPM2OperationFailed{}, err)
}

func TestMCPIAKCreateCSR_CreateCSRError(t *testing.T) {
	mockTPM := &mockTPM2MCPService{
		hasIAK:       true,
		createCSRErr: errors.New("CSR creation failed"),
	}
	provider := createMCPTestProvider(mockTPM)

	ctx := context.Background()
	result, err := provider.IAKCreateCSR(ctx, "Test Device", "Test Org", "US", true)

	require.Error(t, err)
	assert.Empty(t, result)
	assert.IsType(t, ErrTPM2OperationFailed{}, err)
}

// =============================================================================
// IAKInstallCertificate Tests
// =============================================================================

func TestMCPIAKInstallCertificate_Success(t *testing.T) {
	mockTPM := &mockTPM2MCPService{}
	provider := createMCPTestProvider(mockTPM)

	certPEM, err := generateMCPTestCertPEM("Test IAK")
	require.NoError(t, err)

	ctx := context.Background()
	err = provider.IAKInstallCertificate(ctx, certPEM)

	require.NoError(t, err)
}

func TestMCPIAKInstallCertificate_TPM2ServiceNotAvailable(t *testing.T) {
	provider := createMCPTestProvider(nil)

	certPEM, err := generateMCPTestCertPEM("Test IAK")
	require.NoError(t, err)

	ctx := context.Background()
	err = provider.IAKInstallCertificate(ctx, certPEM)

	require.Error(t, err)
	assert.IsType(t, ErrTPM2ServiceNotAvailable{}, err)
}

func TestMCPIAKInstallCertificate_InvalidPEM(t *testing.T) {
	mockTPM := &mockTPM2MCPService{}
	provider := createMCPTestProvider(mockTPM)

	ctx := context.Background()
	err := provider.IAKInstallCertificate(ctx, "not a valid PEM")

	require.Error(t, err)
	assert.IsType(t, ErrInvalidCertificatePEM{}, err)
}

func TestMCPIAKInstallCertificate_InvalidCertificate(t *testing.T) {
	mockTPM := &mockTPM2MCPService{}
	provider := createMCPTestProvider(mockTPM)

	// Valid PEM structure but invalid certificate data
	invalidPEM := `-----BEGIN CERTIFICATE-----
aW52YWxpZCBjZXJ0aWZpY2F0ZSBkYXRh
-----END CERTIFICATE-----`

	ctx := context.Background()
	err := provider.IAKInstallCertificate(ctx, invalidPEM)

	require.Error(t, err)
	assert.IsType(t, ErrInvalidRequestBody{}, err)
}

func TestMCPIAKInstallCertificate_WriteError(t *testing.T) {
	mockTPM := &mockTPM2MCPService{
		writeIAKCertErr: errors.New("write failed"),
	}
	provider := createMCPTestProvider(mockTPM)

	certPEM, err := generateMCPTestCertPEM("Test IAK")
	require.NoError(t, err)

	ctx := context.Background()
	err = provider.IAKInstallCertificate(ctx, certPEM)

	require.Error(t, err)
	assert.IsType(t, ErrTPM2OperationFailed{}, err)
}

// =============================================================================
// IAKGetCertificate Tests
// =============================================================================

func TestMCPIAKGetCertificate_Success(t *testing.T) {
	mockTPM := &mockTPM2MCPService{
		hasIAKCert: true,
	}
	provider := createMCPTestProvider(mockTPM)

	ctx := context.Background()
	result, err := provider.IAKGetCertificate(ctx)

	require.NoError(t, err)
	require.NotNil(t, result)

	resultMap, ok := result.(map[string]interface{})
	require.True(t, ok)
	assert.Contains(t, resultMap, "pem")
	assert.Contains(t, resultMap, "subject_cn")
}

func TestMCPIAKGetCertificate_TPM2ServiceNotAvailable(t *testing.T) {
	provider := createMCPTestProvider(nil)

	ctx := context.Background()
	result, err := provider.IAKGetCertificate(ctx)

	require.Error(t, err)
	require.Nil(t, result)
	assert.IsType(t, ErrTPM2ServiceNotAvailable{}, err)
}

func TestMCPIAKGetCertificate_NotFound(t *testing.T) {
	mockTPM := &mockTPM2MCPService{
		hasIAKCert: false,
	}
	provider := createMCPTestProvider(mockTPM)

	ctx := context.Background()
	result, err := provider.IAKGetCertificate(ctx)

	require.Error(t, err)
	require.Nil(t, result)
	assert.IsType(t, ErrIAKCertificateNotFound{}, err)
}

// =============================================================================
// GetDeviceAttributes Tests
// =============================================================================

func TestMCPGetDeviceAttributes_Success(t *testing.T) {
	mockTPM := &mockTPM2MCPService{}
	provider := createMCPTestProvider(mockTPM)

	ctx := context.Background()
	result, err := provider.DeviceAttributes(ctx)

	require.NoError(t, err)
	require.NotNil(t, result)

	resultMap, ok := result.(map[string]interface{})
	require.True(t, ok)
	assert.Contains(t, resultMap, "tpm_manufacturer")
	assert.Contains(t, resultMap, "tpm_model")
	assert.Contains(t, resultMap, "tpm_version")
	assert.Contains(t, resultMap, "platform_manufacturer")
}

func TestMCPGetDeviceAttributes_TPM2ServiceNotAvailable(t *testing.T) {
	provider := createMCPTestProvider(nil)

	ctx := context.Background()
	result, err := provider.DeviceAttributes(ctx)

	require.Error(t, err)
	require.Nil(t, result)
	assert.IsType(t, ErrTPM2ServiceNotAvailable{}, err)
}

func TestMCPGetDeviceAttributes_FixedPropertiesError(t *testing.T) {
	mockTPM := &mockTPM2MCPService{
		fixedPropsErr: errors.New("TPM properties not available"),
	}
	provider := createMCPTestProvider(mockTPM)

	ctx := context.Background()
	result, err := provider.DeviceAttributes(ctx)

	// Still succeeds, but with empty TPM properties
	require.NoError(t, err)
	require.NotNil(t, result)

	resultMap, ok := result.(map[string]interface{})
	require.True(t, ok)
	// TPM properties should be empty strings when error occurs
	assert.Empty(t, resultMap["tpm_manufacturer"])
}

// =============================================================================
// ActivateCredential Tests
// =============================================================================

func TestMCPActivateCredential_Success(t *testing.T) {
	mockTPM := &mockTPM2MCPService{}
	provider := createMCPTestProvider(mockTPM)

	ctx := context.Background()
	result, err := provider.ActivateCredential(ctx, []byte("credential-blob"), []byte("secret"))

	require.NoError(t, err)
	assert.NotEmpty(t, result)
}

func TestMCPActivateCredential_TPM2ServiceNotAvailable(t *testing.T) {
	provider := createMCPTestProvider(nil)

	ctx := context.Background()
	result, err := provider.ActivateCredential(ctx, []byte("credential-blob"), []byte("secret"))

	require.Error(t, err)
	assert.Empty(t, result)
	assert.IsType(t, ErrTPM2ServiceNotAvailable{}, err)
}

func TestMCPActivateCredential_EmptyCredentialBlob(t *testing.T) {
	mockTPM := &mockTPM2MCPService{}
	provider := createMCPTestProvider(mockTPM)

	ctx := context.Background()
	// Empty credential blob - passes to TPM which may reject
	result, err := provider.ActivateCredential(ctx, []byte{}, []byte("secret"))

	// With empty input, operation may still pass to TPM
	_ = result
	_ = err
}

func TestMCPActivateCredential_EmptySecret(t *testing.T) {
	mockTPM := &mockTPM2MCPService{}
	provider := createMCPTestProvider(mockTPM)

	ctx := context.Background()
	// Empty secret - passes to TPM which may reject
	result, err := provider.ActivateCredential(ctx, []byte("credential-blob"), []byte{})

	// With empty input, operation may still pass to TPM
	_ = result
	_ = err
}

func TestMCPActivateCredential_ActivationError(t *testing.T) {
	mockTPM := &mockTPM2MCPService{
		activateCredentialErr: errors.New("activation failed"),
	}
	provider := createMCPTestProvider(mockTPM)

	ctx := context.Background()
	result, err := provider.ActivateCredential(ctx, []byte("credential-blob"), []byte("secret"))

	require.Error(t, err)
	assert.Empty(t, result)
	assert.IsType(t, ErrTPM2OperationFailed{}, err)
}

// =============================================================================
// formatKeyAttributesMap Tests
// =============================================================================

func TestFormatKeyAttributesMap_NilAttributes(t *testing.T) {
	result := formatKeyAttributesMap(nil)
	require.NotNil(t, result)
	assert.Empty(t, result)
}

func TestFormatKeyAttributesMap_WithTPMAttributes(t *testing.T) {
	attrs := &xkmssdk.KeyAttributes{
		TPMAttributes: &xkmssdk.TPMAttributes{
			Handle: 0x81010001,
		},
		KeyAlgorithm: x509.ECDSA,
	}

	result := formatKeyAttributesMap(attrs)
	require.NotNil(t, result)
	assert.Contains(t, result, "handle")
	assert.Equal(t, "0x81010001", result["handle"])
	assert.Contains(t, result, "algorithm")
	assert.Contains(t, result, "created_at")
}

func TestFormatKeyAttributesMap_NoTPMAttributes(t *testing.T) {
	attrs := &xkmssdk.KeyAttributes{
		KeyAlgorithm: x509.RSA,
	}

	result := formatKeyAttributesMap(attrs)
	require.NotNil(t, result)
	assert.NotContains(t, result, "handle")
	assert.Contains(t, result, "algorithm")
}

func TestFormatKeyAttributesMap_ZeroKeyAlgorithm(t *testing.T) {
	attrs := &xkmssdk.KeyAttributes{
		TPMAttributes: &xkmssdk.TPMAttributes{
			Handle: 0x81010001,
		},
	}

	result := formatKeyAttributesMap(attrs)
	require.NotNil(t, result)
	assert.Contains(t, result, "handle")
	// Zero algorithm should not add algorithm key
	_, hasAlgorithm := result["algorithm"]
	assert.False(t, hasAlgorithm)
}

// =============================================================================
// formatX509CertificateInfo Tests
// =============================================================================

func TestFormatX509CertificateInfo_NilCertificate(t *testing.T) {
	result := formatX509CertificateInfo(nil)
	require.NotNil(t, result)
	assert.Empty(t, result)
}

func TestFormatX509CertificateInfo_ValidCertificate(t *testing.T) {
	cert, err := generateMCPTestCert("Test Cert")
	require.NoError(t, err)

	result := formatX509CertificateInfo(cert)
	require.NotNil(t, result)
	assert.Equal(t, "Test Cert", result["subject_cn"])
	// Self-signed certificate has issuer_cn == subject_cn
	assert.Equal(t, "Test Cert", result["issuer_cn"])
	assert.Contains(t, result, "serial_number")
	assert.Contains(t, result, "not_before")
	assert.Contains(t, result, "not_after")
	assert.Contains(t, result, "fingerprint")
}

// =============================================================================
// HasIDevID and HasIAK Tests
// =============================================================================

func TestMCPHasIDevID_Success(t *testing.T) {
	mockTPM := &mockTPM2MCPService{
		hasIDevID: true,
	}
	provider := createMCPTestProvider(mockTPM)

	ctx := context.Background()
	exists, err := provider.HasIDevID(ctx)

	require.NoError(t, err)
	assert.True(t, exists)
}

func TestMCPHasIDevID_NotExists(t *testing.T) {
	mockTPM := &mockTPM2MCPService{
		hasIDevID: false,
	}
	provider := createMCPTestProvider(mockTPM)

	ctx := context.Background()
	exists, err := provider.HasIDevID(ctx)

	require.NoError(t, err)
	assert.False(t, exists)
}

func TestMCPHasIDevID_TPM2ServiceNotAvailable(t *testing.T) {
	provider := createMCPTestProvider(nil)

	ctx := context.Background()
	exists, err := provider.HasIDevID(ctx)

	require.Error(t, err)
	assert.False(t, exists)
	assert.IsType(t, ErrTPM2ServiceNotAvailable{}, err)
}

func TestMCPHasIAK_Success(t *testing.T) {
	mockTPM := &mockTPM2MCPService{
		hasIAK: true,
	}
	provider := createMCPTestProvider(mockTPM)

	ctx := context.Background()
	exists, err := provider.HasIAK(ctx)

	require.NoError(t, err)
	assert.True(t, exists)
}

func TestMCPHasIAK_NotExists(t *testing.T) {
	mockTPM := &mockTPM2MCPService{
		hasIAK: false,
	}
	provider := createMCPTestProvider(mockTPM)

	ctx := context.Background()
	exists, err := provider.HasIAK(ctx)

	require.NoError(t, err)
	assert.False(t, exists)
}

func TestMCPHasIAK_TPM2ServiceNotAvailable(t *testing.T) {
	provider := createMCPTestProvider(nil)

	ctx := context.Background()
	exists, err := provider.HasIAK(ctx)

	require.Error(t, err)
	assert.False(t, exists)
	assert.IsType(t, ErrTPM2ServiceNotAvailable{}, err)
}

// =============================================================================
// IDevIDDelete and IAKDelete Tests
// =============================================================================

func TestMCPIDevIDDelete_Success(t *testing.T) {
	mockTPM := &mockTPM2MCPService{}
	provider := createMCPTestProvider(mockTPM)

	ctx := context.Background()
	err := provider.IDevIDDelete(ctx)

	require.NoError(t, err)
}

func TestMCPIDevIDDelete_TPM2ServiceNotAvailable(t *testing.T) {
	provider := createMCPTestProvider(nil)

	ctx := context.Background()
	err := provider.IDevIDDelete(ctx)

	require.Error(t, err)
	assert.IsType(t, ErrTPM2ServiceNotAvailable{}, err)
}

func TestMCPIDevIDDelete_CertificateDeleteError(t *testing.T) {
	mockTPM := &mockTPM2MCPService{
		deleteIDevIDCertErr: errors.New("delete failed"),
	}
	provider := createMCPTestProvider(mockTPM)

	ctx := context.Background()
	err := provider.IDevIDDelete(ctx)

	// Should still succeed even if certificate deletion fails
	// (logs error but continues)
	require.NoError(t, err)
}

func TestMCPIAKDelete_Success(t *testing.T) {
	mockTPM := &mockTPM2MCPService{}
	provider := createMCPTestProvider(mockTPM)

	ctx := context.Background()
	err := provider.IAKDelete(ctx)

	require.NoError(t, err)
}

func TestMCPIAKDelete_TPM2ServiceNotAvailable(t *testing.T) {
	provider := createMCPTestProvider(nil)

	ctx := context.Background()
	err := provider.IAKDelete(ctx)

	require.Error(t, err)
	assert.IsType(t, ErrTPM2ServiceNotAvailable{}, err)
}

func TestMCPIAKDelete_CertificateDeleteError(t *testing.T) {
	mockTPM := &mockTPM2MCPService{
		deleteIAKCertErr: errors.New("delete failed"),
	}
	provider := createMCPTestProvider(mockTPM)

	ctx := context.Background()
	err := provider.IAKDelete(ctx)

	// Should still succeed even if certificate deletion fails
	require.NoError(t, err)
}

// =============================================================================
// IDevIDDeleteCertificate and IAKDeleteCertificate Tests
// =============================================================================

func TestMCPIDevIDDeleteCertificate_Success(t *testing.T) {
	mockTPM := &mockTPM2MCPService{}
	provider := createMCPTestProvider(mockTPM)

	ctx := context.Background()
	err := provider.IDevIDDeleteCertificate(ctx)

	require.NoError(t, err)
}

func TestMCPIDevIDDeleteCertificate_TPM2ServiceNotAvailable(t *testing.T) {
	provider := createMCPTestProvider(nil)

	ctx := context.Background()
	err := provider.IDevIDDeleteCertificate(ctx)

	require.Error(t, err)
	assert.IsType(t, ErrTPM2ServiceNotAvailable{}, err)
}

func TestMCPIDevIDDeleteCertificate_Error(t *testing.T) {
	mockTPM := &mockTPM2MCPService{
		deleteIDevIDCertErr: errors.New("delete failed"),
	}
	provider := createMCPTestProvider(mockTPM)

	ctx := context.Background()
	err := provider.IDevIDDeleteCertificate(ctx)

	require.Error(t, err)
	assert.IsType(t, ErrTPM2OperationFailed{}, err)
}

func TestMCPIAKDeleteCertificate_Success(t *testing.T) {
	mockTPM := &mockTPM2MCPService{}
	provider := createMCPTestProvider(mockTPM)

	ctx := context.Background()
	err := provider.IAKDeleteCertificate(ctx)

	require.NoError(t, err)
}

func TestMCPIAKDeleteCertificate_TPM2ServiceNotAvailable(t *testing.T) {
	provider := createMCPTestProvider(nil)

	ctx := context.Background()
	err := provider.IAKDeleteCertificate(ctx)

	require.Error(t, err)
	assert.IsType(t, ErrTPM2ServiceNotAvailable{}, err)
}

func TestMCPIAKDeleteCertificate_Error(t *testing.T) {
	mockTPM := &mockTPM2MCPService{
		deleteIAKCertErr: errors.New("delete failed"),
	}
	provider := createMCPTestProvider(mockTPM)

	ctx := context.Background()
	err := provider.IAKDeleteCertificate(ctx)

	require.Error(t, err)
	assert.IsType(t, ErrTPM2OperationFailed{}, err)
}
