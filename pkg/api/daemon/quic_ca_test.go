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

//go:build codec_msgpack

package daemon

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"io"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-codec"
	common "github.com/jeremyhahn/go-objstore/pkg/common"
	goca "github.com/jeremyhahn/go-trusted-ca/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	// Initialize the QUIC codec for tests
	_ = quic.SetDefaultCodecType(codec.MsgPack)
}

// mockCertStoreForDaemon implements a basic certificate store for testing
// Uses hex encoding for serial numbers to match the CA handler behavior
type mockCertStoreForDaemon struct {
	certificates map[string]*x509.Certificate
}

func newMockCertStoreForDaemon() *mockCertStoreForDaemon {
	return &mockCertStoreForDaemon{
		certificates: make(map[string]*x509.Certificate),
	}
}

func (m *mockCertStoreForDaemon) GetCertificate(serial string) (*x509.Certificate, error) {
	cert, ok := m.certificates[serial]
	if !ok {
		return nil, quic.ErrCACertNotFound{Serial: serial}
	}
	return cert, nil
}

func (m *mockCertStoreForDaemon) StoreCertificate(cert *x509.Certificate) error {
	// Use hex encoding to match the CA handler's serial format
	hexSerial := hex.EncodeToString(cert.SerialNumber.Bytes())
	m.certificates[hexSerial] = cert
	return nil
}

func (m *mockCertStoreForDaemon) DeleteCertificate(serial string) error {
	delete(m.certificates, serial)
	return nil
}

func (m *mockCertStoreForDaemon) ListCertificates() ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, 0, len(m.certificates))
	for _, cert := range m.certificates {
		certs = append(certs, cert)
	}
	return certs, nil
}

// Implement remaining CertStore interface methods with stubs
func (m *mockCertStoreForDaemon) GetCRL(issuer string) (*x509.RevocationList, error) {
	return nil, nil
}
func (m *mockCertStoreForDaemon) StoreCRL(crl *x509.RevocationList) error { return nil }
func (m *mockCertStoreForDaemon) GetCertificateChain(cn string) ([]*x509.Certificate, error) {
	return nil, nil
}
func (m *mockCertStoreForDaemon) StoreCertificateChain(chain []*x509.Certificate) error { return nil }
func (m *mockCertStoreForDaemon) VerifyCertificate(cert *x509.Certificate, roots *x509.CertPool) error {
	return nil
}
func (m *mockCertStoreForDaemon) IsRevoked(cert *x509.Certificate) (bool, error) {
	return false, nil
}
func (m *mockCertStoreForDaemon) Close() error { return nil }

// mockCAForDaemon implements CertificateAuthority for testing
type mockCAForDaemon struct {
	initialized   bool
	identity      string
	rootCert      *x509.Certificate
	intermCert    *x509.Certificate
	defaultKeyAlg x509.PublicKeyAlgorithm
	defaultSigAlg x509.SignatureAlgorithm
	validity      time.Duration
	certStore     *mockCertStoreForDaemon
	issuedCerts   []*x509.Certificate
	revokedCerts  []*x509.Certificate
	generateCRL   bool
	privateKey    *ecdsa.PrivateKey
}

func newMockCAForDaemon() *mockCAForDaemon {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootCert := generateTestCertificateForDaemon("Test Root CA", true, nil, privateKey)
	intermCert := generateTestCertificateForDaemon("Test Intermediate CA", true, rootCert, privateKey)

	return &mockCAForDaemon{
		initialized:   true,
		identity:      "Test CA",
		rootCert:      rootCert,
		intermCert:    intermCert,
		defaultKeyAlg: x509.ECDSA,
		defaultSigAlg: x509.ECDSAWithSHA256,
		validity:      365 * 24 * time.Hour,
		certStore:     newMockCertStoreForDaemon(),
		issuedCerts:   make([]*x509.Certificate, 0),
		revokedCerts:  make([]*x509.Certificate, 0),
		generateCRL:   true,
		privateKey:    privateKey,
	}
}

// crypto.Signer interface
func (m *mockCAForDaemon) Public() crypto.PublicKey {
	return &m.privateKey.PublicKey
}

func (m *mockCAForDaemon) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return ecdsa.SignASN1(rand, m.privateKey, digest)
}

func (m *mockCAForDaemon) IsInitialized() bool {
	return m.initialized
}

func (m *mockCAForDaemon) Identity() string {
	return m.identity
}

func (m *mockCAForDaemon) DefaultKeyAlgorithm() x509.PublicKeyAlgorithm {
	return m.defaultKeyAlg
}

func (m *mockCAForDaemon) DefaultSignatureAlgorithm() x509.SignatureAlgorithm {
	return m.defaultSigAlg
}

func (m *mockCAForDaemon) DefaultValidityPeriod() time.Duration {
	return m.validity
}

func (m *mockCAForDaemon) TrustedRoot() (*x509.Certificate, error) {
	return m.rootCert, nil
}

func (m *mockCAForDaemon) TrustedIntermediate() (*x509.Certificate, error) {
	return m.intermCert, nil
}

func (m *mockCAForDaemon) CertificateStore() xkmssdk.CertStore {
	return m.certStore
}

func (m *mockCAForDaemon) IssueCertificate(req *goca.CACertificateRequest) (*x509.Certificate, error) {
	cert := generateTestCertificateForDaemon(req.Subject.CommonName, req.IsCA, m.intermCert, m.privateKey)
	m.issuedCerts = append(m.issuedCerts, cert)
	if m.certStore != nil {
		m.certStore.StoreCertificate(cert)
	}
	return cert, nil
}

func (m *mockCAForDaemon) Revoke(cert *x509.Certificate, keyAttrs *xkmssdk.KeyAttributes) error {
	m.revokedCerts = append(m.revokedCerts, cert)
	return nil
}

func (m *mockCAForDaemon) CABundle(storeType xkmssdk.StoreType, keyAlg x509.PublicKeyAlgorithm) ([]byte, error) {
	return m.rootCert.Raw, nil
}

func (m *mockCAForDaemon) ParseBundle(bundle []byte) ([]*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(bundle)
	if err != nil {
		return nil, err
	}
	return []*x509.Certificate{cert}, nil
}

func (m *mockCAForDaemon) GenerateCRL() ([]byte, error) {
	if !m.generateCRL {
		return nil, quic.ErrCACRLNotSupported
	}

	template := &x509.RevocationList{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		Number:             big.NewInt(1),
		ThisUpdate:         time.Now(),
		NextUpdate:         time.Now().Add(24 * time.Hour),
	}
	crlDER, _ := x509.CreateRevocationList(rand.Reader, template, m.rootCert, m.privateKey)
	return crlDER, nil
}

// Stub implementations for remaining interface methods
func (m *mockCAForDaemon) SignCSR(csrPEM []byte, request *goca.CACertificateRequest) (*x509.Certificate, error) {
	return nil, nil
}
func (m *mockCAForDaemon) SignTCGCSRIDevID(tcgCSRIDevID *xkmssdk.TCG_CSR_IDEVID, request *goca.CACertificateRequest) ([]byte, []byte, error) {
	return nil, nil, nil
}
func (m *mockCAForDaemon) ImportCertificate(certificate *x509.Certificate) error { return nil }
func (m *mockCAForDaemon) Certificate(attrs *xkmssdk.KeyAttributes) (*x509.Certificate, error) {
	return nil, nil
}
func (m *mockCAForDaemon) CertificatePEM(cn string) ([]byte, error) { return nil, nil }
func (m *mockCAForDaemon) Verify(certificate *x509.Certificate, xsigner crypto.Signer) ([][]*x509.Certificate, error) {
	return nil, nil
}
func (m *mockCAForDaemon) Signer() (crypto.Signer, error) { return m, nil }
func (m *mockCAForDaemon) CreateCSR(request *goca.CACertificateRequest) ([]byte, error) {
	return nil, nil
}
func (m *mockCAForDaemon) TLSCertificate(attrs *xkmssdk.KeyAttributes) (tls.Certificate, error) {
	return tls.Certificate{}, nil
}
func (m *mockCAForDaemon) TLSBundle(attrs *xkmssdk.KeyAttributes) ([]byte, error) { return nil, nil }
func (m *mockCAForDaemon) TLSConfig(attrs *xkmssdk.KeyAttributes) (*tls.Config, error) {
	return nil, nil
}
func (m *mockCAForDaemon) TLSConfigWithXSigner(attrs *xkmssdk.KeyAttributes, xsigner interface{}) (*tls.Config, error) {
	return nil, nil
}
func (m *mockCAForDaemon) QuantumSafeTLSConfig(attrs *xkmssdk.KeyAttributes) (*tls.Config, error) {
	return nil, nil
}
func (m *mockCAForDaemon) TLSBundleWithCrossSigner(attrs *xkmssdk.KeyAttributes, issuerCN string) ([][]byte, *x509.Certificate, error) {
	return nil, nil, nil
}
func (m *mockCAForDaemon) Issued(cn string) (bool, error) { return false, nil }
func (m *mockCAForDaemon) Exists(cn string, algorithm x509.SignatureAlgorithm) (bool, error) {
	return false, nil
}
func (m *mockCAForDaemon) ImportDistributionCRLs(cert *x509.Certificate) error { return nil }
func (m *mockCAForDaemon) IssueEKCertificate(request *goca.CACertificateRequest, ekPubKey crypto.PublicKey) (*x509.Certificate, error) {
	return nil, nil
}
func (m *mockCAForDaemon) IssueAKCertificate(request *goca.CACertificateRequest, pubKey crypto.PublicKey) (*x509.Certificate, error) {
	return nil, nil
}
func (m *mockCAForDaemon) ImportEndorsementKeyCertificate(cert *x509.Certificate) error { return nil }
func (m *mockCAForDaemon) ImportXSignedCertificate(issuerCN string, cert *x509.Certificate) error {
	return nil
}
func (m *mockCAForDaemon) EndorsementKeyCertificate(cn string) (*x509.Certificate, error) {
	return nil, nil
}
func (m *mockCAForDaemon) SignedBlob(data interface{}) ([]byte, error) { return nil, nil }
func (m *mockCAForDaemon) TrustedRootCertPool(cert *x509.Certificate, xsigner crypto.Signer) (*x509.CertPool, error) {
	return nil, nil
}
func (m *mockCAForDaemon) TrustedIntermediateCertPool(cert *x509.Certificate, xsigner crypto.Signer) (*x509.CertPool, error) {
	return nil, nil
}
func (m *mockCAForDaemon) CABundleCertPool(storeType xkmssdk.StoreType, keyAlgorithm x509.PublicKeyAlgorithm) (*x509.CertPool, error) {
	return nil, nil
}
func (m *mockCAForDaemon) ImportIssuingCAs(cert *x509.Certificate) error { return nil }
func (m *mockCAForDaemon) RootCertificate(childCert *x509.Certificate) (*x509.Certificate, error) {
	return m.rootCert, nil
}
func (m *mockCAForDaemon) ObjectStore() common.Storage                           { return nil }
func (m *mockCAForDaemon) PEM(attrs *xkmssdk.KeyAttributes) ([]byte, error)      { return nil, nil }
func (m *mockCAForDaemon) ImportCertificatePEM(cn string, pemData []byte) error  { return nil }
func (m *mockCAForDaemon) Blob(key string) ([]byte, error)                       { return nil, nil }
func (m *mockCAForDaemon) ImportBlob(key string, data []byte) error              { return nil }
func (m *mockCAForDaemon) KeyStore() interface{}                                 { return nil }
func (m *mockCAForDaemon) Key(attrs *xkmssdk.KeyAttributes) (interface{}, error) { return nil, nil }
func (m *mockCAForDaemon) PubKey(attrs *xkmssdk.KeyAttributes) (crypto.PublicKey, error) {
	return nil, nil
}
func (m *mockCAForDaemon) OSTrustStore() (*x509.CertPool, error) { return nil, nil }
func (m *mockCAForDaemon) IsAutoImportingIssuerCAs() bool        { return false }
func (m *mockCAForDaemon) Hash() crypto.Hash                     { return crypto.SHA256 }
func (m *mockCAForDaemon) CAKeyAttributes(storeType xkmssdk.StoreType) (*xkmssdk.KeyAttributes, error) {
	return nil, nil
}
func (m *mockCAForDaemon) CASigner(storeType xkmssdk.StoreType, algorithm x509.PublicKeyAlgorithm) (crypto.Signer, error) {
	return m, nil
}
func (m *mockCAForDaemon) Init() error             { return nil }
func (m *mockCAForDaemon) Load() error             { return nil }
func (m *mockCAForDaemon) CAConfig() goca.CAConfig { return goca.CAConfig{} }
func (m *mockCAForDaemon) ImportAttestation(akAttrs *xkmssdk.KeyAttributes, blobType string, data []byte) error {
	return nil
}
func (m *mockCAForDaemon) ImportAttestationKeyCertificate(attrs *xkmssdk.KeyAttributes, akDER []byte) error {
	return nil
}
func (m *mockCAForDaemon) ImportAttestationEventLog(akAttrs *xkmssdk.KeyAttributes, eventLog []byte) error {
	return nil
}
func (m *mockCAForDaemon) ImportAttestationPCRs(akAttrs *xkmssdk.KeyAttributes, pcrs []byte) error {
	return nil
}
func (m *mockCAForDaemon) ImportAttestationQuote(akAttrs *xkmssdk.KeyAttributes, quote []byte) error {
	return nil
}
func (m *mockCAForDaemon) ImportLocalAttestation(akAttrs *xkmssdk.KeyAttributes, quote *xkmssdk.Quote) error {
	return nil
}
func (m *mockCAForDaemon) VerifyQuote(akAttrs *xkmssdk.KeyAttributes, quote *xkmssdk.Quote, nonce []byte) error {
	return nil
}
func (m *mockCAForDaemon) VerifyAttestationQuote(akAttrs *xkmssdk.KeyAttributes, quote []byte) error {
	return nil
}
func (m *mockCAForDaemon) VerifyAttestationEventLog(akAttrs *xkmssdk.KeyAttributes, eventLog []byte) error {
	return nil
}
func (m *mockCAForDaemon) VerifyAttestationPCRs(akAttrs *xkmssdk.KeyAttributes, pcrs []byte) error {
	return nil
}
func (m *mockCAForDaemon) VerifyTCG_CSR_IDevIDBytes(packedCSR []byte, sigAlg interface{}) ([]byte, []byte, []byte, error) {
	return nil, nil, nil, nil
}
func (m *mockCAForDaemon) SetTPM(tpm xkmssdk.TrustedPlatformModule) {}
func (m *mockCAForDaemon) IsRevoked(serial *big.Int) (bool, error) {
	return false, nil
}

// generateTestCertificateForDaemon creates a test certificate
func generateTestCertificateForDaemon(cn string, isCA bool, parent *x509.Certificate, key *ecdsa.PrivateKey) *x509.Certificate {
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
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	if parent == nil {
		parent = template
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)
	return cert
}

// hexSerial returns the hex-encoded serial number for a certificate
func hexSerial(cert *x509.Certificate) string {
	return hex.EncodeToString(cert.SerialNumber.Bytes())
}

// createTestQUICServiceHandler creates a test handler with mock CA
func createTestQUICServiceHandler(t *testing.T) (*QUICServiceHandler, *mockCAForDaemon) {
	t.Helper()
	logger := logging.DefaultLogger()
	mockCA := newMockCAForDaemon()

	handler := NewQUICServiceHandler(logger,
		WithQUICCAService(mockCA),
	)

	return handler, mockCA
}

// =============================================================================
// CA Operation Routing Tests
// =============================================================================

func TestQUICServiceHandler_CARouting_Info(t *testing.T) {
	handler, _ := createTestQUICServiceHandler(t)
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpCAInfo,
		Payload: nil,
	}

	resp := handler.HandleRequest(ctx, req)

	require.Equal(t, quic.StatusOK, resp.Status)

	var infoResp quic.CAInfoResponse
	err := quic.DecodePayload(resp.Payload, &infoResp)
	require.NoError(t, err)

	assert.True(t, infoResp.IsInitialized)
	assert.Equal(t, "Test CA", infoResp.CommonName)
	assert.Equal(t, "ECDSA", infoResp.DefaultAlgorithm)
}

func TestQUICServiceHandler_CARouting_Issue(t *testing.T) {
	handler, _ := createTestQUICServiceHandler(t)
	ctx := context.Background()

	issueReq := &quic.CAIssueRequest{
		Subject: &quic.Subject{
			CommonName:   "test.example.com",
			Organization: "Test Org",
		},
		ValidDays:    365,
		KeyAlgorithm: "ECDSA",
	}

	payload, err := quic.EncodePayload(issueReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpCAIssue,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)

	require.Equal(t, quic.StatusOK, resp.Status)

	var issueResp quic.CAIssueResponse
	err = quic.DecodePayload(resp.Payload, &issueResp)
	require.NoError(t, err)

	assert.NotNil(t, issueResp.Certificate)
	assert.Equal(t, "test.example.com", issueResp.Certificate.Subject.CommonName)
}

func TestQUICServiceHandler_CARouting_Get(t *testing.T) {
	handler, mockCA := createTestQUICServiceHandler(t)
	ctx := context.Background()

	// Store a certificate first
	cert := generateTestCertificateForDaemon("test.example.com", false, mockCA.intermCert, mockCA.privateKey)
	mockCA.certStore.StoreCertificate(cert)

	getReq := &quic.CAGetRequest{
		Serial:     hexSerial(cert), // Use hex encoding to match CA handler
		IncludePem: true,
	}

	payload, err := quic.EncodePayload(getReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpCAGet,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)

	require.Equal(t, quic.StatusOK, resp.Status)

	var getResp quic.CAGetResponse
	err = quic.DecodePayload(resp.Payload, &getResp)
	require.NoError(t, err)

	assert.NotNil(t, getResp.Certificate)
	assert.Equal(t, "test.example.com", getResp.Certificate.Subject.CommonName)
	assert.NotEmpty(t, getResp.Certificate.Pem)
}

func TestQUICServiceHandler_CARouting_List(t *testing.T) {
	handler, _ := createTestQUICServiceHandler(t)
	ctx := context.Background()

	listReq := &quic.CAListRequest{
		Limit: 10,
	}

	payload, err := quic.EncodePayload(listReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpCAList,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)

	require.Equal(t, quic.StatusOK, resp.Status)

	var listResp quic.CAListResponse
	err = quic.DecodePayload(resp.Payload, &listResp)
	require.NoError(t, err)

	assert.NotNil(t, listResp.Certificates)
	assert.GreaterOrEqual(t, listResp.TotalCount, int32(2)) // Root and intermediate
}

func TestQUICServiceHandler_CARouting_Revoke(t *testing.T) {
	handler, mockCA := createTestQUICServiceHandler(t)
	ctx := context.Background()

	// Store a certificate first
	cert := generateTestCertificateForDaemon("revoke.example.com", false, mockCA.intermCert, mockCA.privateKey)
	mockCA.certStore.StoreCertificate(cert)

	revokeReq := &quic.CARevokeRequest{
		Serial:     hexSerial(cert), // Use hex encoding
		Reason:     1,
		DeleteKeys: false,
	}

	payload, err := quic.EncodePayload(revokeReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpCARevoke,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)

	require.Equal(t, quic.StatusOK, resp.Status)

	var revokeResp quic.CARevokeResponse
	err = quic.DecodePayload(resp.Payload, &revokeResp)
	require.NoError(t, err)

	assert.Equal(t, "REVOKED", revokeResp.Status)
	assert.Equal(t, int32(1), revokeResp.Reason)
}

func TestQUICServiceHandler_CARouting_Renew(t *testing.T) {
	handler, mockCA := createTestQUICServiceHandler(t)
	ctx := context.Background()

	// Store a certificate first
	cert := generateTestCertificateForDaemon("renew.example.com", false, mockCA.intermCert, mockCA.privateKey)
	mockCA.certStore.StoreCertificate(cert)

	renewReq := &quic.CARenewRequest{
		Serial:     hexSerial(cert), // Use hex encoding
		ExtendDays: 365,
	}

	payload, err := quic.EncodePayload(renewReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpCARenew,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)

	require.Equal(t, quic.StatusOK, resp.Status)

	var renewResp quic.CARenewResponse
	err = quic.DecodePayload(resp.Payload, &renewResp)
	require.NoError(t, err)

	assert.Equal(t, hexSerial(cert), renewResp.OldSerial)
	assert.NotNil(t, renewResp.Certificate)
}

func TestQUICServiceHandler_CARouting_Verify(t *testing.T) {
	handler, mockCA := createTestQUICServiceHandler(t)
	ctx := context.Background()

	// Create a certificate to verify
	cert := generateTestCertificateForDaemon("verify.example.com", false, mockCA.rootCert, mockCA.privateKey)

	verifyReq := &quic.CAVerifyRequest{
		CertificateDer: cert.Raw,
	}

	payload, err := quic.EncodePayload(verifyReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpCAVerify,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)

	require.Equal(t, quic.StatusOK, resp.Status)

	var verifyResp quic.CAVerifyResponse
	err = quic.DecodePayload(resp.Payload, &verifyResp)
	require.NoError(t, err)

	// Note: verification may return invalid due to mock certificate chain
	assert.NotEmpty(t, verifyResp.Status)
}

func TestQUICServiceHandler_CARouting_CRL(t *testing.T) {
	handler, _ := createTestQUICServiceHandler(t)
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpCACRL,
		Payload: nil,
	}

	resp := handler.HandleRequest(ctx, req)

	require.Equal(t, quic.StatusOK, resp.Status)

	var crlResp quic.CACRLResponse
	err := quic.DecodePayload(resp.Payload, &crlResp)
	require.NoError(t, err)

	assert.NotEmpty(t, crlResp.CRL)
	assert.NotZero(t, crlResp.LastUpdate)
}

func TestQUICServiceHandler_CARouting_Bundle(t *testing.T) {
	handler, _ := createTestQUICServiceHandler(t)
	ctx := context.Background()

	bundleReq := &quic.CABundleRequest{}

	payload, err := quic.EncodePayload(bundleReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpCABundle,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)

	require.Equal(t, quic.StatusOK, resp.Status)

	var bundleResp quic.CABundleResponse
	err = quic.DecodePayload(resp.Payload, &bundleResp)
	require.NoError(t, err)

	assert.NotEmpty(t, bundleResp.Bundle)
	assert.NotNil(t, bundleResp.Certificates)
}

// =============================================================================
// Error Handling Tests
// =============================================================================

func TestQUICServiceHandler_CA_ServiceUnavailable(t *testing.T) {
	logger := logging.DefaultLogger()
	// Create handler without CA service
	handler := NewQUICServiceHandler(logger)

	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpCAInfo,
		Payload: nil,
	}

	resp := handler.HandleRequest(ctx, req)

	assert.Equal(t, quic.StatusUnavailable, resp.Status)
	assert.Contains(t, string(resp.Payload), "ca")
}

func TestQUICServiceHandler_CARouting_InvalidPayload(t *testing.T) {
	handler, _ := createTestQUICServiceHandler(t)
	ctx := context.Background()

	// Send invalid payload for issue operation
	req := &quic.Request{
		Opcode:  quic.OpCAIssue,
		Payload: []byte("invalid payload"),
	}

	resp := handler.HandleRequest(ctx, req)

	assert.Equal(t, quic.StatusInvalidRequest, resp.Status)
}

func TestQUICServiceHandler_CARouting_MissingSerial(t *testing.T) {
	handler, _ := createTestQUICServiceHandler(t)
	ctx := context.Background()

	getReq := &quic.CAGetRequest{
		Serial: "", // Missing serial
	}

	payload, err := quic.EncodePayload(getReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpCAGet,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)

	assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
	assert.Contains(t, string(resp.Payload), "serial")
}

func TestQUICServiceHandler_CARouting_CertNotFound(t *testing.T) {
	handler, _ := createTestQUICServiceHandler(t)
	ctx := context.Background()

	getReq := &quic.CAGetRequest{
		Serial: "nonexistent-serial",
	}

	payload, err := quic.EncodePayload(getReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpCAGet,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)

	assert.Equal(t, quic.StatusNotFound, resp.Status)
	assert.Contains(t, string(resp.Payload), "certificate not found")
}

// =============================================================================
// Certificate Opcode Mapping Tests (0x80-0x8F mapped to CA ops)
// =============================================================================

func TestQUICServiceHandler_CertOpcodeMapping_Issue(t *testing.T) {
	handler, _ := createTestQUICServiceHandler(t)
	ctx := context.Background()

	issueReq := &quic.CAIssueRequest{
		Subject: &quic.Subject{
			CommonName: "cert-mapping-test.example.com",
		},
		KeyAlgorithm: "ECDSA",
	}

	payload, err := quic.EncodePayload(issueReq)
	require.NoError(t, err)

	// Use OpCertIssue (0x80) which should map to OpCAIssue
	req := &quic.Request{
		Opcode:  quic.OpCertIssue,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)

	require.Equal(t, quic.StatusOK, resp.Status)

	var issueResp quic.CAIssueResponse
	err = quic.DecodePayload(resp.Payload, &issueResp)
	require.NoError(t, err)

	assert.Equal(t, "cert-mapping-test.example.com", issueResp.Certificate.Subject.CommonName)
}

func TestQUICServiceHandler_CertOpcodeMapping_Revoke(t *testing.T) {
	handler, mockCA := createTestQUICServiceHandler(t)
	ctx := context.Background()

	cert := generateTestCertificateForDaemon("cert-revoke.example.com", false, mockCA.intermCert, mockCA.privateKey)
	mockCA.certStore.StoreCertificate(cert)

	revokeReq := &quic.CARevokeRequest{
		Serial: hexSerial(cert),
		Reason: 2,
	}

	payload, err := quic.EncodePayload(revokeReq)
	require.NoError(t, err)

	// Use OpCertRevoke (0x81) which should map to OpCARevoke
	req := &quic.Request{
		Opcode:  quic.OpCertRevoke,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)

	require.Equal(t, quic.StatusOK, resp.Status)
}

func TestQUICServiceHandler_CertOpcodeMapping_Get(t *testing.T) {
	handler, mockCA := createTestQUICServiceHandler(t)
	ctx := context.Background()

	cert := generateTestCertificateForDaemon("cert-get.example.com", false, mockCA.intermCert, mockCA.privateKey)
	mockCA.certStore.StoreCertificate(cert)

	getReq := &quic.CAGetRequest{
		Serial: hexSerial(cert),
	}

	payload, err := quic.EncodePayload(getReq)
	require.NoError(t, err)

	// Use OpCertGet (0x83) which should map to OpCAGet
	req := &quic.Request{
		Opcode:  quic.OpCertGet,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)

	require.Equal(t, quic.StatusOK, resp.Status)
}

func TestQUICServiceHandler_CertOpcodeMapping_List(t *testing.T) {
	handler, _ := createTestQUICServiceHandler(t)
	ctx := context.Background()

	listReq := &quic.CAListRequest{}

	payload, err := quic.EncodePayload(listReq)
	require.NoError(t, err)

	// Use OpCertList (0x84) which should map to OpCAList
	req := &quic.Request{
		Opcode:  quic.OpCertList,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)

	require.Equal(t, quic.StatusOK, resp.Status)
}

func TestQUICServiceHandler_CertOpcodeMapping_Verify(t *testing.T) {
	handler, mockCA := createTestQUICServiceHandler(t)
	ctx := context.Background()

	cert := generateTestCertificateForDaemon("cert-verify.example.com", false, mockCA.rootCert, mockCA.privateKey)

	verifyReq := &quic.CAVerifyRequest{
		CertificateDer: cert.Raw,
	}

	payload, err := quic.EncodePayload(verifyReq)
	require.NoError(t, err)

	// Use OpCertVerify (0x85) which should map to OpCAVerify
	req := &quic.Request{
		Opcode:  quic.OpCertVerify,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)

	require.Equal(t, quic.StatusOK, resp.Status)
}

func TestQUICServiceHandler_CertOpcodeMapping_GetChain(t *testing.T) {
	handler, _ := createTestQUICServiceHandler(t)
	ctx := context.Background()

	bundleReq := &quic.CABundleRequest{}

	payload, err := quic.EncodePayload(bundleReq)
	require.NoError(t, err)

	// Use OpCertGetChain (0x86) which should map to OpCABundle
	req := &quic.Request{
		Opcode:  quic.OpCertGetChain,
		Payload: payload,
	}

	resp := handler.HandleRequest(ctx, req)

	require.Equal(t, quic.StatusOK, resp.Status)
}

func TestQUICServiceHandler_CertOpcodeMapping_GetCRL(t *testing.T) {
	handler, _ := createTestQUICServiceHandler(t)
	ctx := context.Background()

	// Use OpCertGetCRL (0x87) which should map to OpCACRL
	req := &quic.Request{
		Opcode:  quic.OpCertGetCRL,
		Payload: nil,
	}

	resp := handler.HandleRequest(ctx, req)

	require.Equal(t, quic.StatusOK, resp.Status)
}

// =============================================================================
// Opcode Constant Verification Tests
// =============================================================================

func TestCAOpcodeConstants(t *testing.T) {
	// Verify CA opcodes are in the expected range (0xA0-0xA8)
	assert.Equal(t, byte(0xA0), quic.OpCAInfo)
	assert.Equal(t, byte(0xA1), quic.OpCAIssue)
	assert.Equal(t, byte(0xA2), quic.OpCARevoke)
	assert.Equal(t, byte(0xA3), quic.OpCARenew)
	assert.Equal(t, byte(0xA4), quic.OpCAGet)
	assert.Equal(t, byte(0xA5), quic.OpCAList)
	assert.Equal(t, byte(0xA6), quic.OpCAVerify)
	assert.Equal(t, byte(0xA7), quic.OpCACRL)
	assert.Equal(t, byte(0xA8), quic.OpCABundle)
}

func TestCertOpcodeConstants(t *testing.T) {
	// Verify Certificate opcodes are in the expected range (0x80-0x88)
	assert.Equal(t, byte(0x80), quic.OpCertIssue)
	assert.Equal(t, byte(0x81), quic.OpCertRevoke)
	assert.Equal(t, byte(0x82), quic.OpCertRenew)
	assert.Equal(t, byte(0x83), quic.OpCertGet)
	assert.Equal(t, byte(0x84), quic.OpCertList)
	assert.Equal(t, byte(0x85), quic.OpCertVerify)
	assert.Equal(t, byte(0x86), quic.OpCertGetChain)
	assert.Equal(t, byte(0x87), quic.OpCertGetCRL)
	assert.Equal(t, byte(0x88), quic.OpCertGetOCSP)
}

// =============================================================================
// SetCAHandler Tests
// =============================================================================

func TestQUICServiceHandler_SetCAHandler(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	mockCA := newMockCAForDaemon()

	// Initially CA should not be available
	ctx := context.Background()
	req := &quic.Request{
		Opcode:  quic.OpCAInfo,
		Payload: nil,
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusUnavailable, resp.Status)

	// Set CA handler
	caHandler := quic.NewCAHandler(logger, mockCA)
	handler.SetCAHandler(caHandler)

	// Now CA should be available
	resp = handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)
}

// =============================================================================
// Complete CA Operation Flow Tests
// =============================================================================

func TestQUICServiceHandler_CACompleteFlow(t *testing.T) {
	handler, _ := createTestQUICServiceHandler(t)
	ctx := context.Background()

	// Step 1: Get CA Info
	infoReq := &quic.Request{
		Opcode: quic.OpCAInfo,
	}
	infoResp := handler.HandleRequest(ctx, infoReq)
	require.Equal(t, quic.StatusOK, infoResp.Status)

	// Step 2: Issue Certificate
	issueReq := &quic.CAIssueRequest{
		Subject: &quic.Subject{
			CommonName:   "flow-test.example.com",
			Organization: "Flow Test Org",
		},
		ValidDays:    90,
		KeyAlgorithm: "ECDSA",
	}
	issuePayload, _ := quic.EncodePayload(issueReq)
	issueResp := handler.HandleRequest(ctx, &quic.Request{
		Opcode:  quic.OpCAIssue,
		Payload: issuePayload,
	})
	require.Equal(t, quic.StatusOK, issueResp.Status)

	var issued quic.CAIssueResponse
	err := quic.DecodePayload(issueResp.Payload, &issued)
	require.NoError(t, err)
	serial := issued.Certificate.Serial

	// Step 3: Get Certificate (using the hex-encoded serial returned from issue)
	getReq := &quic.CAGetRequest{
		Serial:     serial,
		IncludePem: true,
	}
	getPayload, _ := quic.EncodePayload(getReq)
	getResp := handler.HandleRequest(ctx, &quic.Request{
		Opcode:  quic.OpCAGet,
		Payload: getPayload,
	})
	require.Equal(t, quic.StatusOK, getResp.Status)

	// Step 4: List Certificates
	listReq := &quic.CAListRequest{
		Limit: 100,
	}
	listPayload, _ := quic.EncodePayload(listReq)
	listResp := handler.HandleRequest(ctx, &quic.Request{
		Opcode:  quic.OpCAList,
		Payload: listPayload,
	})
	require.Equal(t, quic.StatusOK, listResp.Status)

	// Step 5: Verify Certificate
	verifyReq := &quic.CAVerifyRequest{
		CertificatePem: issued.Certificate.Pem,
	}
	verifyPayload, _ := quic.EncodePayload(verifyReq)
	verifyResp := handler.HandleRequest(ctx, &quic.Request{
		Opcode:  quic.OpCAVerify,
		Payload: verifyPayload,
	})
	require.Equal(t, quic.StatusOK, verifyResp.Status)

	// Step 6: Get CA Bundle
	bundleReq := &quic.CABundleRequest{}
	bundlePayload, _ := quic.EncodePayload(bundleReq)
	bundleResp := handler.HandleRequest(ctx, &quic.Request{
		Opcode:  quic.OpCABundle,
		Payload: bundlePayload,
	})
	require.Equal(t, quic.StatusOK, bundleResp.Status)

	// Step 7: Get CRL
	crlResp := handler.HandleRequest(ctx, &quic.Request{
		Opcode: quic.OpCACRL,
	})
	require.Equal(t, quic.StatusOK, crlResp.Status)
}
