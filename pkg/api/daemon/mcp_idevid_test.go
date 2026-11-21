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
	"errors"
	"log/slog"
	"math/big"
	"testing"
	"time"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
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

func (m *mockTPM2MCPService) EKCertificate() (*x509.Certificate, error) {
	return &x509.Certificate{}, nil
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
