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
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

// mockTPM2IDevIDService implements xkmssdk.TrustedPlatformModule for IDevID/IAK testing
type mockTPM2IDevIDService struct {
	xkmssdk.TrustedPlatformModule

	// Configuration for behavior
	hasIDevID             bool
	hasIAK                bool
	hasIDevIDCert         bool
	hasIAKCert            bool
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

func (m *mockTPM2IDevIDService) EKAttributes() (*xkmssdk.KeyAttributes, error) {
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

func (m *mockTPM2IDevIDService) CreateIAK(ekAttrs *xkmssdk.KeyAttributes, qualifyingData []byte) (*xkmssdk.KeyAttributes, error) {
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

func (m *mockTPM2IDevIDService) CreateIDevID(akAttrs *xkmssdk.KeyAttributes, ekCert *x509.Certificate, qualifyingData []byte) (*xkmssdk.KeyAttributes, *xkmssdk.TCG_CSR_IDEVID, error) {
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

func (m *mockTPM2IDevIDService) IAKAttributes() (*xkmssdk.KeyAttributes, error) {
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

func (m *mockTPM2IDevIDService) IDevIDAttributes() (*xkmssdk.KeyAttributes, error) {
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

func (m *mockTPM2IDevIDService) IDevIDCertificate() (*x509.Certificate, error) {
	if m.readIDevIDCertErr != nil {
		return nil, m.readIDevIDCertErr
	}
	if !m.hasIDevIDCert {
		return nil, errors.New("IDevID certificate not found")
	}
	return createIDevIDTestCert("IDevID Test")
}

func (m *mockTPM2IDevIDService) IAKCertificate() (*x509.Certificate, error) {
	if m.readIAKCertErr != nil {
		return nil, m.readIAKCertErr
	}
	if !m.hasIAKCert {
		return nil, errors.New("IAK certificate not found")
	}
	return createIDevIDTestCert("IAK Test")
}

func (m *mockTPM2IDevIDService) ProvisionIDevIDCert(cert *x509.Certificate) error {
	if m.writeIDevIDCertErr != nil {
		return m.writeIDevIDCertErr
	}
	return nil
}

func (m *mockTPM2IDevIDService) ProvisionIAKCert(cert *x509.Certificate) error {
	if m.writeIAKCertErr != nil {
		return m.writeIAKCertErr
	}
	return nil
}

func (m *mockTPM2IDevIDService) DeleteIDevIDCertificate() error {
	if m.deleteIDevIDCertErr != nil {
		return m.deleteIDevIDCertErr
	}
	return nil
}

func (m *mockTPM2IDevIDService) DeleteIAKCertificate() error {
	if m.deleteIAKCertErr != nil {
		return m.deleteIAKCertErr
	}
	return nil
}

func (m *mockTPM2IDevIDService) CreateTCG_CSR_IDEVID(ekCert *x509.Certificate, iakAttrs, idevidAttrs *xkmssdk.KeyAttributes) (xkmssdk.TCG_CSR_IDEVID, error) {
	if m.createCSRErr != nil {
		return xkmssdk.TCG_CSR_IDEVID{}, m.createCSRErr
	}
	return xkmssdk.TCG_CSR_IDEVID{}, nil
}

func (m *mockTPM2IDevIDService) ActivateCredential(credentialBlob, secret []byte) ([]byte, error) {
	if m.activateCredentialErr != nil {
		return nil, m.activateCredentialErr
	}
	return []byte("decrypted-secret"), nil
}

func (m *mockTPM2IDevIDService) FixedProperties() (*xkmssdk.PropertiesFixed, error) {
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

// createIDevIDTestCert creates a test X.509 certificate for IDevID testing
func createIDevIDTestCert(cn string) (*x509.Certificate, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Organization"},
		},
		Issuer: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test CA Organization"},
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

// createIDevIDTestCertPEM generates a test certificate and returns its PEM encoding
func createIDevIDTestCertPEM(cn string) (string, error) {
	cert, err := createIDevIDTestCert(cn)
	if err != nil {
		return "", err
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	return string(pemBytes), nil
}

// =============================================================================
// QUIC IDevID Handler Tests
// =============================================================================

func TestQUICIDevID_ServiceNotAvailable(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	testCases := []struct {
		name   string
		opcode byte
	}{
		{"IDevIDGenerate", quic.OpIDevIDGenerate},
		{"IDevIDInfo", quic.OpIDevIDInfo},
		{"IDevIDDelete", quic.OpIDevIDDelete},
		{"IDevIDCSR", quic.OpIDevIDCSR},
		{"IDevIDInstallCert", quic.OpIDevIDInstallCert},
		{"IDevIDGetCert", quic.OpIDevIDGetCert},
		{"IAKGenerate", quic.OpIAKGenerate},
		{"IAKInfo", quic.OpIAKInfo},
		{"IAKDelete", quic.OpIAKDelete},
		{"IAKCSR", quic.OpIAKCSR},
		{"IAKInstallCert", quic.OpIAKInstallCert},
		{"IAKGetCert", quic.OpIAKGetCert},
		{"DeviceAttributes", quic.OpDeviceAttributes},
		{"ActivateCredential", quic.OpActivateCredential},
		{"HasIDevID", quic.OpHasIDevID},
		{"HasIAK", quic.OpHasIAK},
		{"IDevIDDeleteCert", quic.OpIDevIDDeleteCert},
		{"IAKDeleteCert", quic.OpIAKDeleteCert},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &quic.Request{
				Opcode:  tc.opcode,
				Payload: []byte{},
			}
			resp := handler.HandleRequest(ctx, req)
			assert.Equal(t, quic.StatusUnavailable, resp.Status)
		})
	}
}

func TestQUICIDevIDOperation_Routing(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{hasIDevID: true, hasIAK: true}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	// Test that various opcodes are routed correctly
	opcodes := []byte{
		quic.OpIDevIDGenerate,
		quic.OpIDevIDInfo,
		quic.OpIDevIDDelete,
		quic.OpIAKGenerate,
		quic.OpIAKInfo,
		quic.OpIAKDelete,
		quic.OpHasIDevID,
		quic.OpHasIAK,
		quic.OpDeviceAttributes,
	}

	for _, opcode := range opcodes {
		req := &quic.Request{
			Opcode:  opcode,
			Payload: []byte{},
		}
		resp := handler.HandleRequest(ctx, req)
		// Should not return unavailable since TPM2 service is set
		assert.NotEqual(t, quic.StatusUnavailable, resp.Status, "opcode 0x%02X should be routed", opcode)
	}
}

func TestQUICIDevIDGenerate_Success(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	genReq := &IDevIDGenerateRequest{
		Algorithm: "ecdsa-p256",
		Overwrite: false,
	}
	payload, err := quic.EncodePayload(genReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpIDevIDGenerate,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)

	var genResp IDevIDGenerateResponse
	err = quic.DecodePayload(resp.Payload, &genResp)
	require.NoError(t, err)
	assert.NotZero(t, genResp.Handle)
	assert.NotZero(t, genResp.Timestamp)
}

func TestQUICIDevIDGenerate_EKAttributesError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{
		ekAttrsErr: errors.New("TPM not available"),
	}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpIDevIDGenerate,
		Payload: []byte{},
	}

	resp := handler.HandleRequest(ctx, req)
	assert.NotEqual(t, quic.StatusOK, resp.Status)
}

func TestQUICIDevIDGenerate_CreateIAKError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{
		createIAKErr: errors.New("failed to create IAK"),
	}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpIDevIDGenerate,
		Payload: []byte{},
	}

	resp := handler.HandleRequest(ctx, req)
	assert.NotEqual(t, quic.StatusOK, resp.Status)
}

func TestQUICIDevIDGenerate_CreateIDevIDError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{
		createIDevIDErr: errors.New("failed to create IDevID"),
	}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpIDevIDGenerate,
		Payload: []byte{},
	}

	resp := handler.HandleRequest(ctx, req)
	assert.NotEqual(t, quic.StatusOK, resp.Status)
}

func TestQUICIDevIDGenerate_InvalidPayload(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpIDevIDGenerate,
		Payload: []byte{0xFF, 0xFF, 0xFF}, // Invalid payload
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusInvalidRequest, resp.Status)
}

func TestQUICIDevIDInfo_Exists(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{hasIDevID: true}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpIDevIDInfo,
		Payload: []byte{},
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)

	var infoResp IDevIDInfoResponse
	err := quic.DecodePayload(resp.Payload, &infoResp)
	require.NoError(t, err)
	assert.True(t, infoResp.Exists)
	assert.NotZero(t, infoResp.Handle)
}

func TestQUICIDevIDInfo_NotExists(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{hasIDevID: false}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpIDevIDInfo,
		Payload: []byte{},
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)

	var infoResp IDevIDInfoResponse
	err := quic.DecodePayload(resp.Payload, &infoResp)
	require.NoError(t, err)
	assert.False(t, infoResp.Exists)
}

func TestQUICIDevIDInfo_WithCertificate(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{hasIDevID: true, hasIDevIDCert: true}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpIDevIDInfo,
		Payload: []byte{},
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)

	var infoResp IDevIDInfoResponse
	err := quic.DecodePayload(resp.Payload, &infoResp)
	require.NoError(t, err)
	assert.True(t, infoResp.Exists)
	assert.True(t, infoResp.HasCertificate)
	assert.NotNil(t, infoResp.Certificate)
}

func TestQUICIDevIDDelete_Success(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{hasIDevID: true}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpIDevIDDelete,
		Payload: []byte{},
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)

	var deleteResp IDevIDDeleteResponse
	err := quic.DecodePayload(resp.Payload, &deleteResp)
	require.NoError(t, err)
	assert.True(t, deleteResp.Deleted)
}

func TestQUICIDevIDCSR_Success(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{hasIDevID: true, hasIAK: true}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	csrReq := &IDevIDCSRRequest{
		CommonName:   "test-device",
		Organization: "Test Org",
	}
	payload, err := quic.EncodePayload(csrReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpIDevIDCSR,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)

	var csrResp IDevIDCSRResponse
	err = quic.DecodePayload(resp.Payload, &csrResp)
	require.NoError(t, err)
	assert.NotEmpty(t, csrResp.CSR)
}

func TestQUICIDevIDCSR_NoIDevID(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{hasIDevID: false, hasIAK: true}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpIDevIDCSR,
		Payload: []byte{},
	}

	resp := handler.HandleRequest(ctx, req)
	assert.NotEqual(t, quic.StatusOK, resp.Status)
}

func TestQUICIDevIDCSR_NoIAK(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{hasIDevID: true, hasIAK: false}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpIDevIDCSR,
		Payload: []byte{},
	}

	resp := handler.HandleRequest(ctx, req)
	assert.NotEqual(t, quic.StatusOK, resp.Status)
}

func TestQUICIDevIDCSR_CreateCSRError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{
		hasIDevID:    true,
		hasIAK:       true,
		createCSRErr: errors.New("CSR creation failed"),
	}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpIDevIDCSR,
		Payload: []byte{},
	}

	resp := handler.HandleRequest(ctx, req)
	assert.NotEqual(t, quic.StatusOK, resp.Status)
}

func TestQUICIDevIDInstallCert_Success(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{hasIDevID: true}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	certPEM, err := createIDevIDTestCertPEM("Test IDevID")
	require.NoError(t, err)

	installReq := &IDevIDInstallCertRequest{
		CertificatePEM: certPEM,
	}
	payload, err := quic.EncodePayload(installReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpIDevIDInstallCert,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)

	var installResp IDevIDInstallCertResponse
	err = quic.DecodePayload(resp.Payload, &installResp)
	require.NoError(t, err)
	assert.True(t, installResp.Installed)
}

func TestQUICIDevIDInstallCert_MissingPEM(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{hasIDevID: true}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	installReq := &IDevIDInstallCertRequest{
		CertificatePEM: "",
	}
	payload, err := quic.EncodePayload(installReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpIDevIDInstallCert,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
}

func TestQUICIDevIDInstallCert_InvalidPEM(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{hasIDevID: true}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	installReq := &IDevIDInstallCertRequest{
		CertificatePEM: "not-a-valid-pem",
	}
	payload, err := quic.EncodePayload(installReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpIDevIDInstallCert,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
}

func TestQUICIDevIDInstallCert_WriteError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{
		hasIDevID:          true,
		writeIDevIDCertErr: errors.New("write failed"),
	}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	certPEM, err := createIDevIDTestCertPEM("Test IDevID")
	require.NoError(t, err)

	installReq := &IDevIDInstallCertRequest{
		CertificatePEM: certPEM,
	}
	payload, err := quic.EncodePayload(installReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpIDevIDInstallCert,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	assert.NotEqual(t, quic.StatusOK, resp.Status)
}

func TestQUICIDevIDGetCert_Success(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{hasIDevID: true, hasIDevIDCert: true}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	getCertReq := &IDevIDGetCertRequest{
		IncludePEM: true,
	}
	payload, err := quic.EncodePayload(getCertReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpIDevIDGetCert,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)

	var certResp IDevIDGetCertResponse
	err = quic.DecodePayload(resp.Payload, &certResp)
	require.NoError(t, err)
	assert.NotNil(t, certResp.Certificate)
	assert.NotEmpty(t, certResp.Certificate.PEM)
}

func TestQUICIDevIDGetCert_NoPEM(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{hasIDevID: true, hasIDevIDCert: true}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	getCertReq := &IDevIDGetCertRequest{
		IncludePEM: false,
	}
	payload, err := quic.EncodePayload(getCertReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpIDevIDGetCert,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)

	var certResp IDevIDGetCertResponse
	err = quic.DecodePayload(resp.Payload, &certResp)
	require.NoError(t, err)
	assert.NotNil(t, certResp.Certificate)
	assert.Empty(t, certResp.Certificate.PEM)
}

func TestQUICIDevIDGetCert_NotFound(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{hasIDevID: true, hasIDevIDCert: false}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpIDevIDGetCert,
		Payload: []byte{},
	}

	resp := handler.HandleRequest(ctx, req)
	assert.NotEqual(t, quic.StatusOK, resp.Status)
}

func TestQUICHasIDevID_Exists(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{hasIDevID: true}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpHasIDevID,
		Payload: []byte{},
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)

	var hasResp HasIDevIDResponse
	err := quic.DecodePayload(resp.Payload, &hasResp)
	require.NoError(t, err)
	assert.True(t, hasResp.Exists)
}

func TestQUICHasIDevID_NotExists(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{hasIDevID: false}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpHasIDevID,
		Payload: []byte{},
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)

	var hasResp HasIDevIDResponse
	err := quic.DecodePayload(resp.Payload, &hasResp)
	require.NoError(t, err)
	assert.False(t, hasResp.Exists)
}

func TestQUICHasIAK_Exists(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{hasIAK: true}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpHasIAK,
		Payload: []byte{},
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)

	var hasResp HasIAKResponse
	err := quic.DecodePayload(resp.Payload, &hasResp)
	require.NoError(t, err)
	assert.True(t, hasResp.Exists)
}

func TestQUICHasIAK_NotExists(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{hasIAK: false}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpHasIAK,
		Payload: []byte{},
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)

	var hasResp HasIAKResponse
	err := quic.DecodePayload(resp.Payload, &hasResp)
	require.NoError(t, err)
	assert.False(t, hasResp.Exists)
}

func TestQUICIDevIDDeleteCert_Success(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{hasIDevID: true, hasIDevIDCert: true}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpIDevIDDeleteCert,
		Payload: []byte{},
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)

	var deleteResp IDevIDDeleteCertResponse
	err := quic.DecodePayload(resp.Payload, &deleteResp)
	require.NoError(t, err)
	assert.True(t, deleteResp.Deleted)
}

func TestQUICIDevIDDeleteCert_Error(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{
		hasIDevID:           true,
		deleteIDevIDCertErr: errors.New("delete failed"),
	}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpIDevIDDeleteCert,
		Payload: []byte{},
	}

	resp := handler.HandleRequest(ctx, req)
	assert.NotEqual(t, quic.StatusOK, resp.Status)
}

func TestQUICIAKDeleteCert_Success(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{hasIAK: true, hasIAKCert: true}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpIAKDeleteCert,
		Payload: []byte{},
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)

	var deleteResp IAKDeleteCertResponse
	err := quic.DecodePayload(resp.Payload, &deleteResp)
	require.NoError(t, err)
	assert.True(t, deleteResp.Deleted)
}

func TestQUICIAKDeleteCert_Error(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{
		hasIAK:           true,
		deleteIAKCertErr: errors.New("delete failed"),
	}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpIAKDeleteCert,
		Payload: []byte{},
	}

	resp := handler.HandleRequest(ctx, req)
	assert.NotEqual(t, quic.StatusOK, resp.Status)
}

// =============================================================================
// IAK Handler Tests
// =============================================================================

func TestQUICIAKGenerate_Success(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	genReq := &IAKGenerateRequest{
		Algorithm: "ecdsa-p256",
		Overwrite: false,
	}
	payload, err := quic.EncodePayload(genReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpIAKGenerate,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)

	var genResp IAKGenerateResponse
	err = quic.DecodePayload(resp.Payload, &genResp)
	require.NoError(t, err)
	assert.NotZero(t, genResp.Handle)
}

func TestQUICIAKGenerate_EKError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{
		ekAttrsErr: errors.New("EK not available"),
	}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpIAKGenerate,
		Payload: []byte{},
	}

	resp := handler.HandleRequest(ctx, req)
	assert.NotEqual(t, quic.StatusOK, resp.Status)
}

func TestQUICIAKGenerate_CreateError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{
		createIAKErr: errors.New("IAK creation failed"),
	}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpIAKGenerate,
		Payload: []byte{},
	}

	resp := handler.HandleRequest(ctx, req)
	assert.NotEqual(t, quic.StatusOK, resp.Status)
}

func TestQUICIAKInfo_Exists(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{hasIAK: true}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpIAKInfo,
		Payload: []byte{},
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)

	var infoResp IAKInfoResponse
	err := quic.DecodePayload(resp.Payload, &infoResp)
	require.NoError(t, err)
	assert.True(t, infoResp.Exists)
}

func TestQUICIAKInfo_NotExists(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{hasIAK: false}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpIAKInfo,
		Payload: []byte{},
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)

	var infoResp IAKInfoResponse
	err := quic.DecodePayload(resp.Payload, &infoResp)
	require.NoError(t, err)
	assert.False(t, infoResp.Exists)
}

func TestQUICIAKInfo_WithCertificate(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{hasIAK: true, hasIAKCert: true}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpIAKInfo,
		Payload: []byte{},
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)

	var infoResp IAKInfoResponse
	err := quic.DecodePayload(resp.Payload, &infoResp)
	require.NoError(t, err)
	assert.True(t, infoResp.Exists)
	assert.True(t, infoResp.HasCertificate)
	assert.NotNil(t, infoResp.Certificate)
}

func TestQUICIAKDelete_Success(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{hasIAK: true}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpIAKDelete,
		Payload: []byte{},
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)

	var deleteResp IAKDeleteResponse
	err := quic.DecodePayload(resp.Payload, &deleteResp)
	require.NoError(t, err)
	assert.True(t, deleteResp.Deleted)
}

func TestQUICIAKCSR_Success(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{hasIAK: true}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	csrReq := &IAKCSRRequest{
		CommonName:   "test-iak",
		Organization: "Test Org",
	}
	payload, err := quic.EncodePayload(csrReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpIAKCSR,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)

	var csrResp IAKCSRResponse
	err = quic.DecodePayload(resp.Payload, &csrResp)
	require.NoError(t, err)
	assert.NotEmpty(t, csrResp.CSR)
}

func TestQUICIAKCSR_NoIAK(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{hasIAK: false}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpIAKCSR,
		Payload: []byte{},
	}

	resp := handler.HandleRequest(ctx, req)
	assert.NotEqual(t, quic.StatusOK, resp.Status)
}

func TestQUICIAKInstallCert_Success(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{hasIAK: true}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	certPEM, err := createIDevIDTestCertPEM("Test IAK")
	require.NoError(t, err)

	installReq := &IAKInstallCertRequest{
		CertificatePEM: certPEM,
	}
	payload, err := quic.EncodePayload(installReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpIAKInstallCert,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)

	var installResp IAKInstallCertResponse
	err = quic.DecodePayload(resp.Payload, &installResp)
	require.NoError(t, err)
	assert.True(t, installResp.Installed)
}

func TestQUICIAKInstallCert_MissingPEM(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{hasIAK: true}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	installReq := &IAKInstallCertRequest{
		CertificatePEM: "",
	}
	payload, err := quic.EncodePayload(installReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpIAKInstallCert,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
}

func TestQUICIAKGetCert_Success(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{hasIAK: true, hasIAKCert: true}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	getCertReq := &IAKGetCertRequest{
		IncludePEM: true,
	}
	payload, err := quic.EncodePayload(getCertReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpIAKGetCert,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)

	var certResp IAKGetCertResponse
	err = quic.DecodePayload(resp.Payload, &certResp)
	require.NoError(t, err)
	assert.NotNil(t, certResp.Certificate)
	assert.NotEmpty(t, certResp.Certificate.PEM)
}

func TestQUICIAKGetCert_NotFound(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{hasIAK: true, hasIAKCert: false}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpIAKGetCert,
		Payload: []byte{},
	}

	resp := handler.HandleRequest(ctx, req)
	assert.NotEqual(t, quic.StatusOK, resp.Status)
}

// =============================================================================
// Device Attributes and Activate Credential Tests
// =============================================================================

func TestQUICDeviceAttributes_Success(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpDeviceAttributes,
		Payload: []byte{},
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)

	var attrsResp DeviceAttributesResponse
	err := quic.DecodePayload(resp.Payload, &attrsResp)
	require.NoError(t, err)
	assert.Equal(t, "Test Manufacturer", attrsResp.TPMManufacturer)
	assert.NotZero(t, attrsResp.Timestamp)
}

func TestQUICDeviceAttributes_FixedPropsError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{
		fixedPropsErr: errors.New("TPM error"),
	}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpDeviceAttributes,
		Payload: []byte{},
	}

	// Should still return OK, just with empty TPM info
	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)

	var attrsResp DeviceAttributesResponse
	err := quic.DecodePayload(resp.Payload, &attrsResp)
	require.NoError(t, err)
	assert.Empty(t, attrsResp.TPMManufacturer)
}

func TestQUICActivateCredential_Success(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	// Use base64 encoded test data
	activateReq := &ActivateCredentialQUICRequest{
		CredentialBlob: "dGVzdC1jcmVkZW50aWFsLWJsb2I=", // "test-credential-blob" base64
		Secret:         "dGVzdC1zZWNyZXQ=",             // "test-secret" base64
	}
	payload, err := quic.EncodePayload(activateReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpActivateCredential,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)

	var activateResp ActivateCredentialQUICResponse
	err = quic.DecodePayload(resp.Payload, &activateResp)
	require.NoError(t, err)
	assert.NotEmpty(t, activateResp.Decrypted)
}

func TestQUICActivateCredential_MissingCredentialBlob(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	activateReq := &ActivateCredentialQUICRequest{
		CredentialBlob: "",
		Secret:         "dGVzdC1zZWNyZXQ=",
	}
	payload, err := quic.EncodePayload(activateReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpActivateCredential,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
}

func TestQUICActivateCredential_MissingSecret(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	activateReq := &ActivateCredentialQUICRequest{
		CredentialBlob: "dGVzdC1jcmVkZW50aWFsLWJsb2I=",
		Secret:         "",
	}
	payload, err := quic.EncodePayload(activateReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpActivateCredential,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
}

func TestQUICActivateCredential_InvalidBase64Credential(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	activateReq := &ActivateCredentialQUICRequest{
		CredentialBlob: "not-valid-base64!!!",
		Secret:         "dGVzdC1zZWNyZXQ=",
	}
	payload, err := quic.EncodePayload(activateReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpActivateCredential,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
}

func TestQUICActivateCredential_InvalidBase64Secret(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	activateReq := &ActivateCredentialQUICRequest{
		CredentialBlob: "dGVzdC1jcmVkZW50aWFsLWJsb2I=",
		Secret:         "not-valid-base64!!!",
	}
	payload, err := quic.EncodePayload(activateReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpActivateCredential,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
}

func TestQUICActivateCredential_TPMError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockTPM := &mockTPM2IDevIDService{
		activateCredentialErr: errors.New("TPM activation failed"),
	}
	handler := NewQUICServiceHandler(logger, WithQUICTPM2Service(mockTPM))
	ctx := context.Background()

	activateReq := &ActivateCredentialQUICRequest{
		CredentialBlob: "dGVzdC1jcmVkZW50aWFsLWJsb2I=",
		Secret:         "dGVzdC1zZWNyZXQ=",
	}
	payload, err := quic.EncodePayload(activateReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpActivateCredential,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)
	assert.NotEqual(t, quic.StatusOK, resp.Status)
}

// =============================================================================
// Helper Function Tests
// =============================================================================

func TestMapTPM2Error(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)

	testCases := []struct {
		name           string
		errorMsg       string
		expectedStatus byte
	}{
		{"not found error", "key not found", quic.StatusNotFound},
		{"does not exist error", "key does not exist", quic.StatusNotFound},
		{"already exists error", "key already exists", quic.StatusAlreadyExists},
		{"invalid error", "invalid key size", quic.StatusInvalidArgument},
		{"required error", "parameter required", quic.StatusInvalidArgument},
		{"must be error", "value must be positive", quic.StatusInvalidArgument},
		{"cannot be error", "value cannot be empty", quic.StatusInvalidArgument},
		{"mismatch error", "key mismatch", quic.StatusInvalidArgument},
		{"not available error", "TPM not available", quic.StatusUnavailable},
		{"unavailable error", "service unavailable", quic.StatusUnavailable},
		{"not configured error", "TPM not configured", quic.StatusUnavailable},
		{"generic error", "some random error", quic.StatusInternalError},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp := handler.mapTPM2Error(errors.New(tc.errorMsg))
			assert.Equal(t, tc.expectedStatus, resp.Status)
		})
	}
}

func TestMapTPM2Error_NilError(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)

	resp := handler.mapTPM2Error(nil)
	assert.Nil(t, resp)
}

func TestContainsIDevIDErrorPattern(t *testing.T) {
	testCases := []struct {
		s        string
		patterns []string
		expected bool
	}{
		{"key not found", []string{"not found"}, true},
		{"key not found", []string{"already exists"}, false},
		{"key already exists", []string{"already exists", "not found"}, true},
		{"short", []string{"longer pattern"}, false},
		{"", []string{"pattern"}, false},
		{"test", []string{}, false},
	}

	for _, tc := range testCases {
		result := containsIDevIDErrorPattern(tc.s, tc.patterns...)
		assert.Equal(t, tc.expected, result, "containsIDevIDErrorPattern(%q, %v)", tc.s, tc.patterns)
	}
}

func TestCertToQUIC(t *testing.T) {
	t.Run("valid certificate", func(t *testing.T) {
		cert, err := createIDevIDTestCert("Test Subject")
		require.NoError(t, err)

		result := certToQUIC(cert)
		assert.NotNil(t, result)
		assert.Equal(t, "Test Subject", result.SubjectCN)
		// Self-signed certificates have Issuer == Subject
		assert.Equal(t, "Test Subject", result.IssuerCN)
		assert.NotEmpty(t, result.SerialNumber)
		assert.NotEmpty(t, result.Fingerprint)
		assert.NotEmpty(t, result.PEM)
		assert.NotZero(t, result.NotBefore)
		assert.NotZero(t, result.NotAfter)
	})

	t.Run("nil certificate", func(t *testing.T) {
		result := certToQUIC(nil)
		assert.Nil(t, result)
	})
}

func TestEncodePublicKeyPEM(t *testing.T) {
	// The function returns empty string as placeholder
	result, err := encodePublicKeyPEM(nil)
	assert.NoError(t, err)
	assert.Empty(t, result)
}
