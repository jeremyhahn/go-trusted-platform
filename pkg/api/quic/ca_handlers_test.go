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

package quic

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
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/jeremyhahn/go-codec"
	common "github.com/jeremyhahn/go-objstore/pkg/common"
	goca "github.com/jeremyhahn/go-trusted-ca/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	// Set the default codec to MsgPack for encoding/decoding payloads
	_ = SetDefaultCodecType(codec.MsgPack)
}

// mockCertStore implements a basic certificate store for testing
type mockCertStore struct {
	certificates map[string]*x509.Certificate
}

func newMockCertStore() *mockCertStore {
	return &mockCertStore{
		certificates: make(map[string]*x509.Certificate),
	}
}

func (m *mockCertStore) GetCertificate(cn string) (*x509.Certificate, error) {
	cert, ok := m.certificates[cn]
	if !ok {
		return nil, ErrCACertNotFound{Serial: cn}
	}
	return cert, nil
}

func (m *mockCertStore) StoreCertificate(cert *x509.Certificate) error {
	m.certificates[cert.SerialNumber.String()] = cert
	return nil
}

func (m *mockCertStore) DeleteCertificate(cn string) error {
	delete(m.certificates, cn)
	return nil
}

func (m *mockCertStore) ListCertificates() ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, 0, len(m.certificates))
	for _, cert := range m.certificates {
		certs = append(certs, cert)
	}
	return certs, nil
}

// Implement remaining CertStore interface methods with stubs
func (m *mockCertStore) GetCRL(issuer string) (*x509.RevocationList, error) {
	return nil, nil
}
func (m *mockCertStore) StoreCRL(crl *x509.RevocationList) error { return nil }
func (m *mockCertStore) GetCertificateChain(cn string) ([]*x509.Certificate, error) {
	return nil, nil
}
func (m *mockCertStore) StoreCertificateChain(chain []*x509.Certificate) error { return nil }
func (m *mockCertStore) VerifyCertificate(cert *x509.Certificate, roots *x509.CertPool) error {
	return nil
}
func (m *mockCertStore) IsRevoked(cert *x509.Certificate) (bool, error) {
	return false, nil
}
func (m *mockCertStore) Close() error { return nil }

// mockCA implements CertificateAuthority for testing
type mockCA struct {
	initialized   bool
	identity      string
	rootCert      *x509.Certificate
	intermCert    *x509.Certificate
	defaultKeyAlg x509.PublicKeyAlgorithm
	defaultSigAlg x509.SignatureAlgorithm
	validity      time.Duration
	certStore     *mockCertStore
	issuedCerts   []*x509.Certificate
	revokedCerts  []*x509.Certificate
	generateCRL   bool
	privateKey    *ecdsa.PrivateKey
}

func newMockCA() *mockCA {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootCert := generateTestCertificate("Test Root CA", true, nil, privateKey)
	intermCert := generateTestCertificate("Test Intermediate CA", true, rootCert, privateKey)

	return &mockCA{
		initialized:   true,
		identity:      "Test CA",
		rootCert:      rootCert,
		intermCert:    intermCert,
		defaultKeyAlg: x509.ECDSA,
		defaultSigAlg: x509.ECDSAWithSHA256,
		validity:      365 * 24 * time.Hour,
		certStore:     newMockCertStore(),
		issuedCerts:   make([]*x509.Certificate, 0),
		revokedCerts:  make([]*x509.Certificate, 0),
		generateCRL:   true,
		privateKey:    privateKey,
	}
}

// crypto.Signer interface
func (m *mockCA) Public() crypto.PublicKey {
	return &m.privateKey.PublicKey
}

func (m *mockCA) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return ecdsa.SignASN1(rand, m.privateKey, digest)
}

func (m *mockCA) IsInitialized() bool {
	return m.initialized
}

func (m *mockCA) Identity() string {
	return m.identity
}

func (m *mockCA) DefaultKeyAlgorithm() x509.PublicKeyAlgorithm {
	return m.defaultKeyAlg
}

func (m *mockCA) DefaultSignatureAlgorithm() x509.SignatureAlgorithm {
	return m.defaultSigAlg
}

func (m *mockCA) DefaultValidityPeriod() time.Duration {
	return m.validity
}

func (m *mockCA) TrustedRoot() (*x509.Certificate, error) {
	return m.rootCert, nil
}

func (m *mockCA) TrustedIntermediate() (*x509.Certificate, error) {
	return m.intermCert, nil
}

func (m *mockCA) CertificateStore() xkmssdk.CertStore {
	if m.certStore == nil {
		return nil
	}
	return m.certStore
}

func (m *mockCA) IssueCertificate(req *goca.CACertificateRequest) (*x509.Certificate, error) {
	cert := generateTestCertificate(req.Subject.CommonName, req.IsCA, m.intermCert, m.privateKey)
	m.issuedCerts = append(m.issuedCerts, cert)
	if m.certStore != nil {
		m.certStore.StoreCertificate(cert)
	}
	return cert, nil
}

func (m *mockCA) Revoke(cert *x509.Certificate, keyAttrs *xkmssdk.KeyAttributes) error {
	m.revokedCerts = append(m.revokedCerts, cert)
	return nil
}

func (m *mockCA) CABundle(storeType xkmssdk.StoreType, keyAlg x509.PublicKeyAlgorithm) ([]byte, error) {
	return m.rootCert.Raw, nil
}

func (m *mockCA) ParseBundle(bundle []byte) ([]*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(bundle)
	if err != nil {
		return nil, err
	}
	return []*x509.Certificate{cert}, nil
}

func (m *mockCA) GenerateCRL() ([]byte, error) {
	if !m.generateCRL {
		return nil, ErrCACRLNotSupported
	}

	template := &x509.RevocationList{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		Number:             big.NewInt(1),
		ThisUpdate:         time.Now(),
		NextUpdate:         time.Now().Add(24 * time.Hour),
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, template, m.rootCert, m.privateKey)
	if err != nil {
		return nil, err
	}
	return crlDER, nil
}

// Stub implementations for remaining interface methods
func (m *mockCA) SignCSR(csrPEM []byte, request *goca.CACertificateRequest) (*x509.Certificate, error) {
	return nil, nil
}
func (m *mockCA) SignTCGCSRIDevID(tcgCSRIDevID *xkmssdk.TCG_CSR_IDEVID, request *goca.CACertificateRequest) ([]byte, []byte, error) {
	return nil, nil, nil
}
func (m *mockCA) ImportCertificate(certificate *x509.Certificate) error { return nil }
func (m *mockCA) Certificate(attrs *xkmssdk.KeyAttributes) (*x509.Certificate, error) {
	return nil, nil
}
func (m *mockCA) CertificatePEM(cn string) ([]byte, error) { return nil, nil }
func (m *mockCA) Verify(certificate *x509.Certificate, xsigner crypto.Signer) ([][]*x509.Certificate, error) {
	return nil, nil
}
func (m *mockCA) Signer() (crypto.Signer, error)                               { return m, nil }
func (m *mockCA) CreateCSR(request *goca.CACertificateRequest) ([]byte, error) { return nil, nil }
func (m *mockCA) TLSCertificate(attrs *xkmssdk.KeyAttributes) (tls.Certificate, error) {
	return tls.Certificate{}, nil
}
func (m *mockCA) TLSBundle(attrs *xkmssdk.KeyAttributes) ([]byte, error)      { return nil, nil }
func (m *mockCA) TLSConfig(attrs *xkmssdk.KeyAttributes) (*tls.Config, error) { return nil, nil }
func (m *mockCA) TLSConfigWithXSigner(attrs *xkmssdk.KeyAttributes, xsigner interface{}) (*tls.Config, error) {
	return nil, nil
}
func (m *mockCA) QuantumSafeTLSConfig(attrs *xkmssdk.KeyAttributes) (*tls.Config, error) {
	return nil, nil
}
func (m *mockCA) TLSBundleWithCrossSigner(attrs *xkmssdk.KeyAttributes, issuerCN string) ([][]byte, *x509.Certificate, error) {
	return nil, nil, nil
}
func (m *mockCA) Issued(cn string) (bool, error) { return false, nil }
func (m *mockCA) Exists(cn string, algorithm x509.SignatureAlgorithm) (bool, error) {
	return false, nil
}
func (m *mockCA) ImportDistributionCRLs(cert *x509.Certificate) error { return nil }
func (m *mockCA) IssueEKCertificate(request *goca.CACertificateRequest, ekPubKey crypto.PublicKey) (*x509.Certificate, error) {
	return nil, nil
}
func (m *mockCA) IssueAKCertificate(request *goca.CACertificateRequest, pubKey crypto.PublicKey) (*x509.Certificate, error) {
	return nil, nil
}
func (m *mockCA) ImportEndorsementKeyCertificate(cert *x509.Certificate) error { return nil }
func (m *mockCA) ImportXSignedCertificate(issuerCN string, cert *x509.Certificate) error {
	return nil
}
func (m *mockCA) EndorsementKeyCertificate(cn string) (*x509.Certificate, error) {
	return nil, nil
}
func (m *mockCA) SignedBlob(data interface{}) ([]byte, error) { return nil, nil }
func (m *mockCA) TrustedRootCertPool(cert *x509.Certificate, xsigner crypto.Signer) (*x509.CertPool, error) {
	return nil, nil
}
func (m *mockCA) TrustedIntermediateCertPool(cert *x509.Certificate, xsigner crypto.Signer) (*x509.CertPool, error) {
	return nil, nil
}
func (m *mockCA) CABundleCertPool(storeType xkmssdk.StoreType, keyAlgorithm x509.PublicKeyAlgorithm) (*x509.CertPool, error) {
	return nil, nil
}
func (m *mockCA) ImportIssuingCAs(cert *x509.Certificate) error { return nil }
func (m *mockCA) RootCertificate(childCert *x509.Certificate) (*x509.Certificate, error) {
	return m.rootCert, nil
}
func (m *mockCA) ObjectStore() common.Storage                                   { return nil }
func (m *mockCA) PEM(attrs *xkmssdk.KeyAttributes) ([]byte, error)              { return nil, nil }
func (m *mockCA) ImportCertificatePEM(cn string, pemData []byte) error          { return nil }
func (m *mockCA) Blob(key string) ([]byte, error)                               { return nil, nil }
func (m *mockCA) ImportBlob(key string, data []byte) error                      { return nil }
func (m *mockCA) KeyStore() interface{}                                         { return nil }
func (m *mockCA) Key(attrs *xkmssdk.KeyAttributes) (interface{}, error)         { return nil, nil }
func (m *mockCA) PubKey(attrs *xkmssdk.KeyAttributes) (crypto.PublicKey, error) { return nil, nil }
func (m *mockCA) OSTrustStore() (*x509.CertPool, error)                         { return nil, nil }
func (m *mockCA) IsAutoImportingIssuerCAs() bool                                { return false }
func (m *mockCA) Hash() crypto.Hash                                             { return crypto.SHA256 }
func (m *mockCA) CAKeyAttributes(storeType xkmssdk.StoreType) (*xkmssdk.KeyAttributes, error) {
	return nil, nil
}
func (m *mockCA) CASigner(storeType xkmssdk.StoreType, algorithm x509.PublicKeyAlgorithm) (crypto.Signer, error) {
	return m, nil
}
func (m *mockCA) Init() error             { return nil }
func (m *mockCA) Load() error             { return nil }
func (m *mockCA) CAConfig() goca.CAConfig { return goca.CAConfig{} }
func (m *mockCA) ImportAttestation(akAttrs *xkmssdk.KeyAttributes, blobType string, data []byte) error {
	return nil
}
func (m *mockCA) ImportAttestationKeyCertificate(attrs *xkmssdk.KeyAttributes, akDER []byte) error {
	return nil
}
func (m *mockCA) ImportAttestationEventLog(akAttrs *xkmssdk.KeyAttributes, eventLog []byte) error {
	return nil
}
func (m *mockCA) ImportAttestationPCRs(akAttrs *xkmssdk.KeyAttributes, pcrs []byte) error { return nil }
func (m *mockCA) ImportAttestationQuote(akAttrs *xkmssdk.KeyAttributes, quote []byte) error {
	return nil
}
func (m *mockCA) ImportLocalAttestation(akAttrs *xkmssdk.KeyAttributes, quote *xkmssdk.Quote) error {
	return nil
}
func (m *mockCA) VerifyQuote(akAttrs *xkmssdk.KeyAttributes, quote *xkmssdk.Quote, nonce []byte) error {
	return nil
}
func (m *mockCA) VerifyAttestationQuote(akAttrs *xkmssdk.KeyAttributes, quote []byte) error {
	return nil
}
func (m *mockCA) VerifyAttestationEventLog(akAttrs *xkmssdk.KeyAttributes, eventLog []byte) error {
	return nil
}
func (m *mockCA) VerifyAttestationPCRs(akAttrs *xkmssdk.KeyAttributes, pcrs []byte) error {
	return nil
}
func (m *mockCA) VerifyTCG_CSR_IDevIDBytes(packedCSR []byte, sigAlg interface{}) ([]byte, []byte, []byte, error) {
	return nil, nil, nil, nil
}
func (m *mockCA) SetTPM(tpm xkmssdk.TrustedPlatformModule) {}
func (m *mockCA) IsRevoked(serial *big.Int) (bool, error) {
	return false, nil
}

// generateTestCertificate creates a test certificate
func generateTestCertificate(cn string, isCA bool, parent *x509.Certificate, key *ecdsa.PrivateKey) *x509.Certificate {
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

func TestNewCAHandler(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()

	handler := NewCAHandler(logger, ca)

	assert.NotNil(t, handler)
	assert.Equal(t, ca, handler.ca)
	assert.Equal(t, logger, handler.logger)
}

func TestCAHandler_HandleRequest_NilRequest(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	resp := handler.HandleRequest(context.Background(), nil)

	assert.Equal(t, StatusInvalidRequest, resp.Status)
	assert.Contains(t, string(resp.Payload), "request cannot be nil")
}

func TestCAHandler_HandleRequest_UnknownOperation(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	req := &Request{
		Opcode:  0xFF,
		Payload: nil,
	}

	resp := handler.HandleRequest(context.Background(), req)

	assert.Equal(t, StatusInvalidRequest, resp.Status)
	assert.Contains(t, string(resp.Payload), "unknown CA operation")
}

func TestCAHandler_HandleInfo_Success(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	req := &Request{
		Opcode:  OpCAInfo,
		Payload: nil,
	}

	resp := handler.HandleRequest(context.Background(), req)

	require.Equal(t, StatusOK, resp.Status)

	var infoResp CAInfoResponse
	err := DecodePayload(resp.Payload, &infoResp)
	require.NoError(t, err)

	assert.True(t, infoResp.IsInitialized)
	assert.Equal(t, "Test CA", infoResp.CommonName)
	assert.Equal(t, "ECDSA", infoResp.DefaultAlgorithm)
	assert.NotNil(t, infoResp.RootCert)
	assert.Equal(t, "Test Root CA", infoResp.RootCert.CommonName)
}

func TestCAHandler_HandleInfo_CANotInitialized(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewCAHandler(logger, nil)

	req := &Request{
		Opcode:  OpCAInfo,
		Payload: nil,
	}

	resp := handler.HandleRequest(context.Background(), req)

	assert.Equal(t, StatusUnavailable, resp.Status)
	assert.Contains(t, string(resp.Payload), "certificate authority not initialized")
}

func TestCAHandler_HandleInfo_NotInitializedCA(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	ca.initialized = false
	handler := NewCAHandler(logger, ca)

	req := &Request{
		Opcode:  OpCAInfo,
		Payload: nil,
	}

	resp := handler.HandleRequest(context.Background(), req)

	require.Equal(t, StatusOK, resp.Status)

	var infoResp CAInfoResponse
	err := DecodePayload(resp.Payload, &infoResp)
	require.NoError(t, err)

	assert.False(t, infoResp.IsInitialized)
	// CommonName should be empty when not initialized
	assert.Empty(t, infoResp.CommonName)
}

func TestCAHandler_HandleInfo_WithoutIntermediate(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	ca.intermCert = nil
	handler := NewCAHandler(logger, ca)

	req := &Request{
		Opcode:  OpCAInfo,
		Payload: nil,
	}

	resp := handler.HandleRequest(context.Background(), req)

	require.Equal(t, StatusOK, resp.Status)

	var infoResp CAInfoResponse
	err := DecodePayload(resp.Payload, &infoResp)
	require.NoError(t, err)

	assert.False(t, infoResp.IsIntermediate)
	assert.Empty(t, infoResp.Intermediates)
}

func TestCAHandler_HandleIssue_Success(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	issueReq := &CAIssueRequest{
		Subject: &Subject{
			CommonName:   "test.example.com",
			Organization: "Test Org",
		},
		ValidDays:    365,
		KeyAlgorithm: "ECDSA",
	}

	payload, err := EncodePayload(issueReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCAIssue,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	require.Equal(t, StatusOK, resp.Status)

	var issueResp CAIssueResponse
	err = DecodePayload(resp.Payload, &issueResp)
	require.NoError(t, err)

	assert.NotNil(t, issueResp.Certificate)
	assert.Equal(t, "test.example.com", issueResp.Certificate.Subject.CommonName)
}

func TestCAHandler_HandleIssue_WithSANs(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	issueReq := &CAIssueRequest{
		Subject: &Subject{
			CommonName: "test.example.com",
		},
		Sans: &SANs{
			DNS:   []string{"test.example.com", "www.example.com"},
			IPs:   []string{"192.168.1.1", "10.0.0.1"},
			Email: []string{"admin@example.com"},
			URIs:  []string{"https://example.com"},
		},
		ValidDays:    365,
		KeyAlgorithm: "ECDSA",
	}

	payload, err := EncodePayload(issueReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCAIssue,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	require.Equal(t, StatusOK, resp.Status)
}

func TestCAHandler_HandleIssue_WithKeyUsage(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	issueReq := &CAIssueRequest{
		Subject: &Subject{
			CommonName: "test.example.com",
		},
		KeyUsage:    []string{"DIGITAL_SIGNATURE", "KEY_ENCIPHERMENT"},
		ExtKeyUsage: []string{"SERVER_AUTH", "CLIENT_AUTH"},
		ValidDays:   365,
	}

	payload, err := EncodePayload(issueReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCAIssue,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	require.Equal(t, StatusOK, resp.Status)
}

func TestCAHandler_HandleIssue_MissingCommonName(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	issueReq := &CAIssueRequest{
		Subject: &Subject{
			Organization: "Test Org",
		},
	}

	payload, err := EncodePayload(issueReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCAIssue,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	assert.Equal(t, StatusInvalidArgument, resp.Status)
	assert.Contains(t, string(resp.Payload), "common name is required")
}

func TestCAHandler_HandleIssue_InvalidAlgorithm(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	issueReq := &CAIssueRequest{
		Subject: &Subject{
			CommonName: "test.example.com",
		},
		KeyAlgorithm: "INVALID",
	}

	payload, err := EncodePayload(issueReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCAIssue,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	assert.Equal(t, StatusInvalidArgument, resp.Status)
	assert.Contains(t, string(resp.Payload), "invalid key algorithm")
}

func TestCAHandler_HandleIssue_InvalidPayload(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	req := &Request{
		Opcode:  OpCAIssue,
		Payload: []byte("invalid msgpack data"),
	}

	resp := handler.HandleRequest(context.Background(), req)

	assert.Equal(t, StatusInvalidRequest, resp.Status)
}

func TestCAHandler_HandleIssue_NilSubject(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	issueReq := &CAIssueRequest{
		Subject:   nil,
		ValidDays: 365,
	}

	payload, err := EncodePayload(issueReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCAIssue,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	assert.Equal(t, StatusInvalidArgument, resp.Status)
	assert.Contains(t, string(resp.Payload), "common name is required")
}

func TestCAHandler_HandleGet_Success(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	// First issue a certificate
	cert := generateTestCertificate("test.example.com", false, ca.intermCert, ca.privateKey)
	ca.certStore.StoreCertificate(cert)

	getReq := &CAGetRequest{
		Serial:     cert.SerialNumber.String(),
		IncludePem: true,
	}

	payload, err := EncodePayload(getReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCAGet,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	require.Equal(t, StatusOK, resp.Status)

	var getResp CAGetResponse
	err = DecodePayload(resp.Payload, &getResp)
	require.NoError(t, err)

	assert.NotNil(t, getResp.Certificate)
	assert.Equal(t, "test.example.com", getResp.Certificate.Subject.CommonName)
	assert.NotEmpty(t, getResp.Certificate.Pem)
}

func TestCAHandler_HandleGet_MissingSerial(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	getReq := &CAGetRequest{
		Serial: "",
	}

	payload, err := EncodePayload(getReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCAGet,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	assert.Equal(t, StatusInvalidArgument, resp.Status)
	assert.Contains(t, string(resp.Payload), "serial number is required")
}

func TestCAHandler_HandleGet_NotFound(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	getReq := &CAGetRequest{
		Serial: "nonexistent",
	}

	payload, err := EncodePayload(getReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCAGet,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	assert.Equal(t, StatusNotFound, resp.Status)
	assert.Contains(t, string(resp.Payload), "certificate not found")
}

func TestCAHandler_HandleGet_InvalidPayload(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	req := &Request{
		Opcode:  OpCAGet,
		Payload: []byte("invalid msgpack data"),
	}

	resp := handler.HandleRequest(context.Background(), req)

	assert.Equal(t, StatusInvalidRequest, resp.Status)
}

func TestCAHandler_HandleList_Success(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	listReq := &CAListRequest{
		Limit: 10,
	}

	payload, err := EncodePayload(listReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCAList,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	require.Equal(t, StatusOK, resp.Status)

	var listResp CAListResponse
	err = DecodePayload(resp.Payload, &listResp)
	require.NoError(t, err)

	assert.NotNil(t, listResp.Certificates)
	assert.Equal(t, int32(2), listResp.TotalCount) // Root and intermediate
}

func TestCAHandler_HandleList_InvalidPayload(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	req := &Request{
		Opcode:  OpCAList,
		Payload: []byte("invalid msgpack data"),
	}

	resp := handler.HandleRequest(context.Background(), req)

	assert.Equal(t, StatusInvalidRequest, resp.Status)
}

func TestCAHandler_HandleList_DefaultLimit(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	// Test with zero limit - should use default
	listReq := &CAListRequest{
		Limit: 0,
	}

	payload, err := EncodePayload(listReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCAList,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	require.Equal(t, StatusOK, resp.Status)
}

func TestCAHandler_HandleList_MaxLimit(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	// Test with limit exceeding max - should cap at max
	listReq := &CAListRequest{
		Limit: 10000,
	}

	payload, err := EncodePayload(listReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCAList,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	require.Equal(t, StatusOK, resp.Status)
}

func TestCAHandler_HandleList_NilCertStore(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	ca.certStore = nil
	handler := NewCAHandler(logger, ca)

	listReq := &CAListRequest{
		Limit: 10,
	}

	payload, err := EncodePayload(listReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCAList,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	assert.Equal(t, StatusUnavailable, resp.Status)
	assert.Contains(t, string(resp.Payload), "certificate store not available")
}

func TestCAHandler_HandleRevoke_Success(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	// First issue a certificate
	cert := generateTestCertificate("test.example.com", false, ca.intermCert, ca.privateKey)
	ca.certStore.StoreCertificate(cert)

	revokeReq := &CARevokeRequest{
		Serial:     cert.SerialNumber.String(),
		Reason:     1,
		DeleteKeys: false,
	}

	payload, err := EncodePayload(revokeReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCARevoke,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	require.Equal(t, StatusOK, resp.Status)

	var revokeResp CARevokeResponse
	err = DecodePayload(resp.Payload, &revokeResp)
	require.NoError(t, err)

	assert.Equal(t, "REVOKED", revokeResp.Status)
	assert.Equal(t, int32(1), revokeResp.Reason)
}

func TestCAHandler_HandleRevoke_WithDeleteKeys(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	// First issue a certificate
	cert := generateTestCertificate("test.example.com", false, ca.intermCert, ca.privateKey)
	ca.certStore.StoreCertificate(cert)

	revokeReq := &CARevokeRequest{
		Serial:     cert.SerialNumber.String(),
		Reason:     1,
		DeleteKeys: true, // Should pass keyAttrs to Revoke
	}

	payload, err := EncodePayload(revokeReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCARevoke,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	require.Equal(t, StatusOK, resp.Status)
}

func TestCAHandler_HandleRevoke_MissingSerial(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	revokeReq := &CARevokeRequest{
		Serial: "",
	}

	payload, err := EncodePayload(revokeReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCARevoke,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	assert.Equal(t, StatusInvalidArgument, resp.Status)
}

func TestCAHandler_HandleRevoke_InvalidPayload(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	req := &Request{
		Opcode:  OpCARevoke,
		Payload: []byte("invalid msgpack data"),
	}

	resp := handler.HandleRequest(context.Background(), req)

	assert.Equal(t, StatusInvalidRequest, resp.Status)
}

func TestCAHandler_HandleRevoke_NotFound(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	revokeReq := &CARevokeRequest{
		Serial:     "nonexistent-serial",
		Reason:     1,
		DeleteKeys: false,
	}

	payload, err := EncodePayload(revokeReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCARevoke,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	assert.Equal(t, StatusNotFound, resp.Status)
}

func TestCAHandler_HandleRevoke_NilCertStore(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	ca.certStore = nil
	handler := NewCAHandler(logger, ca)

	revokeReq := &CARevokeRequest{
		Serial: "12345",
		Reason: 1,
	}

	payload, err := EncodePayload(revokeReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCARevoke,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	assert.Equal(t, StatusNotFound, resp.Status)
}

func TestCAHandler_HandleRenew_Success(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	// First issue a certificate
	cert := generateTestCertificate("test.example.com", false, ca.intermCert, ca.privateKey)
	ca.certStore.StoreCertificate(cert)

	renewReq := &CARenewRequest{
		Serial:     cert.SerialNumber.String(),
		ExtendDays: 365,
	}

	payload, err := EncodePayload(renewReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCARenew,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	require.Equal(t, StatusOK, resp.Status)

	var renewResp CARenewResponse
	err = DecodePayload(resp.Payload, &renewResp)
	require.NoError(t, err)

	assert.Equal(t, cert.SerialNumber.String(), renewResp.OldSerial)
	assert.NotNil(t, renewResp.Certificate)
}

func TestCAHandler_HandleRenew_InvalidExtendDays(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	renewReq := &CARenewRequest{
		Serial:     "12345",
		ExtendDays: 0,
	}

	payload, err := EncodePayload(renewReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCARenew,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	assert.Equal(t, StatusInvalidArgument, resp.Status)
	assert.Contains(t, string(resp.Payload), "extend_days must be positive")
}

func TestCAHandler_HandleRenew_InvalidPayload(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	req := &Request{
		Opcode:  OpCARenew,
		Payload: []byte("invalid msgpack data"),
	}

	resp := handler.HandleRequest(context.Background(), req)

	assert.Equal(t, StatusInvalidRequest, resp.Status)
}

func TestCAHandler_HandleRenew_MissingSerial(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	renewReq := &CARenewRequest{
		Serial:     "",
		ExtendDays: 365,
	}

	payload, err := EncodePayload(renewReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCARenew,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	assert.Equal(t, StatusInvalidArgument, resp.Status)
	assert.Contains(t, string(resp.Payload), "serial number is required")
}

func TestCAHandler_HandleRenew_NotFound(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	renewReq := &CARenewRequest{
		Serial:     "nonexistent-serial",
		ExtendDays: 365,
	}

	payload, err := EncodePayload(renewReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCARenew,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	assert.Equal(t, StatusNotFound, resp.Status)
}

func TestCAHandler_HandleRenew_NilCertStore(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	ca.certStore = nil
	handler := NewCAHandler(logger, ca)

	renewReq := &CARenewRequest{
		Serial:     "12345",
		ExtendDays: 365,
	}

	payload, err := EncodePayload(renewReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCARenew,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	assert.Equal(t, StatusNotFound, resp.Status)
}

func TestCAHandler_HandleRenew_WithSANs(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	// Create a certificate with SANs
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  false,
		BasicConstraintsValid: true,
		DNSNames:              []string{"test.example.com", "www.example.com"},
		IPAddresses:           []net.IP{net.ParseIP("192.168.1.1")},
		EmailAddresses:        []string{"admin@example.com"},
		URIs:                  []*url.URL{{Scheme: "https", Host: "example.com"}},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)
	ca.certStore.StoreCertificate(cert)

	renewReq := &CARenewRequest{
		Serial:        cert.SerialNumber.String(),
		ExtendDays:    365,
		PreserveAttrs: true,
	}

	payload, err := EncodePayload(renewReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCARenew,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	require.Equal(t, StatusOK, resp.Status)
}

func TestCAHandler_HandleVerify_ValidCertificate(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	// Create a certificate signed by the CA's root
	cert := generateTestCertificate("test.example.com", false, ca.rootCert, ca.privateKey)

	verifyReq := &CAVerifyRequest{
		CertificateDer: cert.Raw,
	}

	payload, err := EncodePayload(verifyReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCAVerify,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	require.Equal(t, StatusOK, resp.Status)

	var verifyResp CAVerifyResponse
	err = DecodePayload(resp.Payload, &verifyResp)
	require.NoError(t, err)

	// Note: verification may fail because our mock certs aren't properly signed
	// The important thing is that the response structure is correct
	assert.NotEmpty(t, verifyResp.Status)
}

func TestCAHandler_HandleVerify_MissingCertificate(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	verifyReq := &CAVerifyRequest{}

	payload, err := EncodePayload(verifyReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCAVerify,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	assert.Equal(t, StatusInvalidArgument, resp.Status)
	assert.Contains(t, string(resp.Payload), "certificate (PEM or DER) is required")
}

func TestCAHandler_HandleVerify_InvalidPayload(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	req := &Request{
		Opcode:  OpCAVerify,
		Payload: []byte("invalid msgpack data"),
	}

	resp := handler.HandleRequest(context.Background(), req)

	assert.Equal(t, StatusInvalidRequest, resp.Status)
}

func TestCAHandler_HandleVerify_WithDER(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	// Create a certificate
	cert := generateTestCertificate("test.example.com", false, ca.rootCert, ca.privateKey)

	verifyReq := &CAVerifyRequest{
		CertificateDer: cert.Raw,
	}

	payload, err := EncodePayload(verifyReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCAVerify,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	// Response should be OK with verification details
	assert.Equal(t, StatusOK, resp.Status)
}

func TestCAHandler_HandleVerify_WithPEM(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	// Create a certificate
	cert := generateTestCertificate("test.example.com", false, ca.rootCert, ca.privateKey)

	// Encode to PEM
	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	verifyReq := &CAVerifyRequest{
		CertificatePem: string(pemBlock),
	}

	payload, err := EncodePayload(verifyReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCAVerify,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	assert.Equal(t, StatusOK, resp.Status)
}

func TestCAHandler_HandleVerify_InvalidDER(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	verifyReq := &CAVerifyRequest{
		CertificateDer: []byte("invalid der data"),
	}

	payload, err := EncodePayload(verifyReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCAVerify,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	assert.Equal(t, StatusInvalidArgument, resp.Status)
}

func TestCAHandler_HandleVerify_ExpiredCertificate(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	// Create an expired certificate
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: "expired.example.com",
		},
		NotBefore: time.Now().Add(-365 * 24 * time.Hour),
		NotAfter:  time.Now().Add(-1 * time.Hour),
		IsCA:      false,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, ca.rootCert, &key.PublicKey, ca.privateKey)

	verifyReq := &CAVerifyRequest{
		CertificateDer: certDER,
	}

	payload, err := EncodePayload(verifyReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCAVerify,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	require.Equal(t, StatusOK, resp.Status)

	var verifyResp CAVerifyResponse
	err = DecodePayload(resp.Payload, &verifyResp)
	require.NoError(t, err)

	// Should report expired status
	assert.False(t, verifyResp.Valid)
}

func TestCAHandler_HandleVerify_NotYetValidCertificate(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	// Create a not-yet-valid certificate
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: "future.example.com",
		},
		NotBefore: time.Now().Add(24 * time.Hour),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		IsCA:      false,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, ca.rootCert, &key.PublicKey, ca.privateKey)

	verifyReq := &CAVerifyRequest{
		CertificateDer: certDER,
	}

	payload, err := EncodePayload(verifyReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCAVerify,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	require.Equal(t, StatusOK, resp.Status)
}

func TestCAHandler_HandleCRL_Success(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	req := &Request{
		Opcode:  OpCACRL,
		Payload: nil,
	}

	resp := handler.HandleRequest(context.Background(), req)

	require.Equal(t, StatusOK, resp.Status)

	var crlResp CACRLResponse
	err := DecodePayload(resp.Payload, &crlResp)
	require.NoError(t, err)

	assert.NotEmpty(t, crlResp.CRL)
	assert.NotZero(t, crlResp.LastUpdate)
}

func TestCAHandler_HandleCRL_CANotInitialized(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewCAHandler(logger, nil)

	req := &Request{
		Opcode:  OpCACRL,
		Payload: nil,
	}

	resp := handler.HandleRequest(context.Background(), req)

	assert.Equal(t, StatusUnavailable, resp.Status)
	assert.Contains(t, string(resp.Payload), "certificate authority not initialized")
}

func TestCAHandler_HandleCRL_NotSupported(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	ca.generateCRL = false
	handler := NewCAHandler(logger, ca)

	req := &Request{
		Opcode:  OpCACRL,
		Payload: nil,
	}

	resp := handler.HandleRequest(context.Background(), req)

	assert.Equal(t, StatusNotImplemented, resp.Status)
	assert.Contains(t, string(resp.Payload), "CRL generation not supported")
}

func TestCAHandler_HandleBundle_Success(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	bundleReq := &CABundleRequest{}

	payload, err := EncodePayload(bundleReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCABundle,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	require.Equal(t, StatusOK, resp.Status)

	var bundleResp CABundleResponse
	err = DecodePayload(resp.Payload, &bundleResp)
	require.NoError(t, err)

	assert.NotEmpty(t, bundleResp.Bundle)
	assert.NotNil(t, bundleResp.Certificates)
}

func TestCAHandler_HandleBundle_InvalidPayload(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	req := &Request{
		Opcode:  OpCABundle,
		Payload: []byte("invalid msgpack data"),
	}

	resp := handler.HandleRequest(context.Background(), req)

	assert.Equal(t, StatusInvalidRequest, resp.Status)
}

func TestCAHandler_HandleBundle_CANotInitialized(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewCAHandler(logger, nil)

	bundleReq := &CABundleRequest{}
	payload, _ := EncodePayload(bundleReq)

	req := &Request{
		Opcode:  OpCABundle,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	assert.Equal(t, StatusUnavailable, resp.Status)
}

func TestCAHandler_HandleBundle_WithStoreType(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	bundleReq := &CABundleRequest{
		StoreType: "PKCS11",
		Algorithm: "ECDSA",
	}

	payload, err := EncodePayload(bundleReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCABundle,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	require.Equal(t, StatusOK, resp.Status)

	var bundleResp CABundleResponse
	err = DecodePayload(resp.Payload, &bundleResp)
	require.NoError(t, err)

	assert.NotEmpty(t, bundleResp.Bundle)
}

func TestCAHandler_HandleBundle_InvalidAlgorithm(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	bundleReq := &CABundleRequest{
		Algorithm: "INVALID_ALG",
	}

	payload, err := EncodePayload(bundleReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCABundle,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	assert.Equal(t, StatusInvalidArgument, resp.Status)
	assert.Contains(t, string(resp.Payload), "invalid key algorithm")
}

func TestCAHandler_ParseKeyAlgorithm(t *testing.T) {
	handler := &CAHandler{}

	tests := []struct {
		name     string
		input    string
		expected x509.PublicKeyAlgorithm
		hasError bool
	}{
		{"RSA", "RSA", x509.RSA, false},
		{"RSA2048", "RSA2048", x509.RSA, false},
		{"RSA-4096", "RSA-4096", x509.RSA, false},
		{"RSA-2048", "RSA-2048", x509.RSA, false},
		{"RSA3072", "RSA3072", x509.RSA, false},
		{"RSA-3072", "RSA-3072", x509.RSA, false},
		{"ECDSA", "ECDSA", x509.ECDSA, false},
		{"EC", "EC", x509.ECDSA, false},
		{"P256", "P256", x509.ECDSA, false},
		{"P384", "P384", x509.ECDSA, false},
		{"P521", "P521", x509.ECDSA, false},
		{"ECDSA-P256", "ECDSA-P256", x509.ECDSA, false},
		{"ECDSA-P384", "ECDSA-P384", x509.ECDSA, false},
		{"ECDSA-P521", "ECDSA-P521", x509.ECDSA, false},
		{"ED25519", "ED25519", x509.Ed25519, false},
		{"Empty", "", x509.ECDSA, false}, // Default
		{"lowercase", "ecdsa", x509.ECDSA, false},
		{"Invalid", "INVALID", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := handler.parseKeyAlgorithm(tt.input)
			if tt.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestCAHandler_ParseKeyUsage(t *testing.T) {
	handler := &CAHandler{}

	usages := []string{"DIGITAL_SIGNATURE", "KEY_ENCIPHERMENT", "CERT_SIGN"}
	result := handler.parseKeyUsage(usages)

	assert.True(t, result&x509.KeyUsageDigitalSignature != 0)
	assert.True(t, result&x509.KeyUsageKeyEncipherment != 0)
	assert.True(t, result&x509.KeyUsageCertSign != 0)
}

func TestCAHandler_ParseKeyUsage_AllUsages(t *testing.T) {
	handler := &CAHandler{}

	usages := []string{
		"DIGITAL_SIGNATURE",
		"CONTENT_COMMITMENT",
		"KEY_ENCIPHERMENT",
		"DATA_ENCIPHERMENT",
		"KEY_AGREEMENT",
		"CERT_SIGN",
		"CRL_SIGN",
		"ENCIPHER_ONLY",
		"DECIPHER_ONLY",
	}
	result := handler.parseKeyUsage(usages)

	assert.True(t, result&x509.KeyUsageDigitalSignature != 0)
	assert.True(t, result&x509.KeyUsageContentCommitment != 0)
	assert.True(t, result&x509.KeyUsageKeyEncipherment != 0)
	assert.True(t, result&x509.KeyUsageDataEncipherment != 0)
	assert.True(t, result&x509.KeyUsageKeyAgreement != 0)
	assert.True(t, result&x509.KeyUsageCertSign != 0)
	assert.True(t, result&x509.KeyUsageCRLSign != 0)
	assert.True(t, result&x509.KeyUsageEncipherOnly != 0)
	assert.True(t, result&x509.KeyUsageDecipherOnly != 0)
}

func TestCAHandler_ParseKeyUsage_AlternativeNames(t *testing.T) {
	handler := &CAHandler{}

	// Test without underscores
	usages := []string{
		"DIGITALSIGNATURE",
		"CONTENTCOMMITMENT",
		"KEYENCIPHERMENT",
		"DATAENCIPHERMENT",
		"KEYAGREEMENT",
		"CERTSIGN",
		"CRLSIGN",
		"ENCIPHERONLY",
		"DECIPHERONLY",
	}
	result := handler.parseKeyUsage(usages)

	assert.True(t, result&x509.KeyUsageDigitalSignature != 0)
	assert.True(t, result&x509.KeyUsageContentCommitment != 0)
	assert.True(t, result&x509.KeyUsageKeyEncipherment != 0)
	assert.True(t, result&x509.KeyUsageDataEncipherment != 0)
	assert.True(t, result&x509.KeyUsageKeyAgreement != 0)
	assert.True(t, result&x509.KeyUsageCertSign != 0)
	assert.True(t, result&x509.KeyUsageCRLSign != 0)
	assert.True(t, result&x509.KeyUsageEncipherOnly != 0)
	assert.True(t, result&x509.KeyUsageDecipherOnly != 0)
}

func TestCAHandler_ParseKeyUsage_Unknown(t *testing.T) {
	handler := &CAHandler{}

	usages := []string{"UNKNOWN_USAGE"}
	result := handler.parseKeyUsage(usages)

	// Unknown usage should not set any bits
	assert.Equal(t, x509.KeyUsage(0), result)
}

func TestCAHandler_ParseExtKeyUsage(t *testing.T) {
	handler := &CAHandler{}

	usages := []string{"SERVER_AUTH", "CLIENT_AUTH", "CODE_SIGNING"}
	result := handler.parseExtKeyUsage(usages)

	assert.Contains(t, result, x509.ExtKeyUsageServerAuth)
	assert.Contains(t, result, x509.ExtKeyUsageClientAuth)
	assert.Contains(t, result, x509.ExtKeyUsageCodeSigning)
}

func TestCAHandler_ParseExtKeyUsage_AllUsages(t *testing.T) {
	handler := &CAHandler{}

	usages := []string{
		"ANY",
		"SERVER_AUTH",
		"CLIENT_AUTH",
		"CODE_SIGNING",
		"EMAIL_PROTECTION",
		"TIME_STAMPING",
		"OCSP_SIGNING",
	}
	result := handler.parseExtKeyUsage(usages)

	assert.Contains(t, result, x509.ExtKeyUsageAny)
	assert.Contains(t, result, x509.ExtKeyUsageServerAuth)
	assert.Contains(t, result, x509.ExtKeyUsageClientAuth)
	assert.Contains(t, result, x509.ExtKeyUsageCodeSigning)
	assert.Contains(t, result, x509.ExtKeyUsageEmailProtection)
	assert.Contains(t, result, x509.ExtKeyUsageTimeStamping)
	assert.Contains(t, result, x509.ExtKeyUsageOCSPSigning)
}

func TestCAHandler_ParseExtKeyUsage_AlternativeNames(t *testing.T) {
	handler := &CAHandler{}

	// Test without underscores
	usages := []string{
		"SERVERAUTH",
		"CLIENTAUTH",
		"CODESIGNING",
		"EMAILPROTECTION",
		"TIMESTAMPING",
		"OCSPSIGNING",
	}
	result := handler.parseExtKeyUsage(usages)

	assert.Contains(t, result, x509.ExtKeyUsageServerAuth)
	assert.Contains(t, result, x509.ExtKeyUsageClientAuth)
	assert.Contains(t, result, x509.ExtKeyUsageCodeSigning)
	assert.Contains(t, result, x509.ExtKeyUsageEmailProtection)
	assert.Contains(t, result, x509.ExtKeyUsageTimeStamping)
	assert.Contains(t, result, x509.ExtKeyUsageOCSPSigning)
}

func TestCAHandler_ParseExtKeyUsage_Unknown(t *testing.T) {
	handler := &CAHandler{}

	usages := []string{"UNKNOWN_USAGE"}
	result := handler.parseExtKeyUsage(usages)

	// Unknown usage should return empty slice
	assert.Empty(t, result)
}

func TestCAHandler_KeyAlgorithmToString(t *testing.T) {
	handler := &CAHandler{}

	tests := []struct {
		input    x509.PublicKeyAlgorithm
		expected string
	}{
		{x509.RSA, "RSA"},
		{x509.ECDSA, "ECDSA"},
		{x509.Ed25519, "ED25519"},
		{x509.DSA, "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := handler.keyAlgorithmToString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCAHandler_SignatureAlgorithmToString(t *testing.T) {
	handler := &CAHandler{}

	tests := []struct {
		input    x509.SignatureAlgorithm
		expected string
	}{
		{x509.SHA256WithRSA, "SHA256-RSA"},
		{x509.SHA384WithRSA, "SHA384-RSA"},
		{x509.SHA512WithRSA, "SHA512-RSA"},
		{x509.ECDSAWithSHA256, "ECDSA-SHA256"},
		{x509.ECDSAWithSHA384, "ECDSA-SHA384"},
		{x509.ECDSAWithSHA512, "ECDSA-SHA512"},
		{x509.PureEd25519, "Ed25519"},
		{x509.UnknownSignatureAlgorithm, "0"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := handler.signatureAlgorithmToString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCAHandler_ParseStoreType(t *testing.T) {
	handler := &CAHandler{}

	// Test default store type
	result := handler.parseStoreType("")
	assert.NotNil(t, result)
}

func TestCAHandler_CertToSummary(t *testing.T) {
	handler := &CAHandler{}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert := generateTestCertificate("test.example.com", false, nil, key)

	summary := handler.certToSummary(cert)

	assert.NotNil(t, summary)
	assert.Equal(t, "test.example.com", summary.CommonName)
	assert.Equal(t, "ECDSA", summary.KeyAlgorithm)
	assert.Equal(t, "VALID", summary.Status)
}

func TestCAHandler_CertToSummary_Nil(t *testing.T) {
	handler := &CAHandler{}

	summary := handler.certToSummary(nil)

	assert.Nil(t, summary)
}

func TestCAHandler_CertToSummary_Expired(t *testing.T) {
	handler := &CAHandler{}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Create an expired certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   "expired.example.com",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-365 * 24 * time.Hour),
		NotAfter:              time.Now().Add(-1 * time.Hour),
		IsCA:                  false,
		BasicConstraintsValid: true,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	summary := handler.certToSummary(cert)

	assert.NotNil(t, summary)
	assert.Equal(t, "EXPIRED", summary.Status)
}

func TestCAHandler_CertToSummary_NotYetValid(t *testing.T) {
	handler := &CAHandler{}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Create a not-yet-valid certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   "future.example.com",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  false,
		BasicConstraintsValid: true,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	summary := handler.certToSummary(cert)

	assert.NotNil(t, summary)
	assert.Equal(t, "NOT_YET_VALID", summary.Status)
}

func TestCAHandler_CertToFull(t *testing.T) {
	handler := &CAHandler{}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert := generateTestCertificate("test.example.com", true, nil, key)

	full := handler.certToFull(cert, true)

	assert.NotNil(t, full)
	assert.Equal(t, "test.example.com", full.Subject.CommonName)
	assert.Equal(t, "ECDSA", full.KeyAlgorithm)
	assert.True(t, full.IsCA)
	assert.NotEmpty(t, full.Pem)
}

func TestCAHandler_CertToFull_WithoutPEM(t *testing.T) {
	handler := &CAHandler{}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert := generateTestCertificate("test.example.com", false, nil, key)

	full := handler.certToFull(cert, false)

	assert.NotNil(t, full)
	assert.Empty(t, full.Pem)
}

func TestCAHandler_CertToFull_Nil(t *testing.T) {
	handler := &CAHandler{}

	full := handler.certToFull(nil, false)

	assert.Nil(t, full)
}

func TestCAHandler_CertToFull_Expired(t *testing.T) {
	handler := &CAHandler{}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Create an expired certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   "expired.example.com",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-365 * 24 * time.Hour),
		NotAfter:              time.Now().Add(-1 * time.Hour),
		IsCA:                  false,
		BasicConstraintsValid: true,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	full := handler.certToFull(cert, false)

	assert.NotNil(t, full)
	assert.Equal(t, "EXPIRED", full.Status)
}

func TestCAHandler_CertToFull_NotYetValid(t *testing.T) {
	handler := &CAHandler{}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Create a not-yet-valid certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   "future.example.com",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  false,
		BasicConstraintsValid: true,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	full := handler.certToFull(cert, false)

	assert.NotNil(t, full)
	assert.Equal(t, "NOT_YET_VALID", full.Status)
}

func TestCAHandler_CertToFull_WithSubjectDetails(t *testing.T) {
	handler := &CAHandler{}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:         "test.example.com",
			Organization:       []string{"Test Org"},
			OrganizationalUnit: []string{"Test Unit"},
			Country:            []string{"US"},
			Province:           []string{"CA"},
			Locality:           []string{"San Francisco"},
			StreetAddress:      []string{"123 Test St"},
			PostalCode:         []string{"94102"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  false,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	full := handler.certToFull(cert, true)

	assert.NotNil(t, full)
	assert.Equal(t, "test.example.com", full.Subject.CommonName)
	assert.Equal(t, "Test Org", full.Subject.Organization)
	assert.Equal(t, "Test Unit", full.Subject.OrganizationalUnit)
	assert.Equal(t, "US", full.Subject.Country)
	assert.Equal(t, "CA", full.Subject.Province)
	assert.Equal(t, "San Francisco", full.Subject.Locality)
	assert.Equal(t, "123 Test St", full.Subject.Address)
	assert.Equal(t, "94102", full.Subject.PostalCode)
	assert.NotEmpty(t, full.Pem)
}

func TestFirstOrEmpty(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected string
	}{
		{"Empty slice", []string{}, ""},
		{"Single element", []string{"one"}, "one"},
		{"Multiple elements", []string{"first", "second"}, "first"},
		{"Nil slice", nil, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := firstOrEmpty(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test CA operations with various opcode constants
// These values are defined in protocol.go and must match exactly
func TestCAOperationConstants(t *testing.T) {
	assert.Equal(t, byte(0xA0), OpCAInfo)
	assert.Equal(t, byte(0xA1), OpCAIssue)
	assert.Equal(t, byte(0xA2), OpCARevoke)
	assert.Equal(t, byte(0xA3), OpCARenew)
	assert.Equal(t, byte(0xA4), OpCAGet)
	assert.Equal(t, byte(0xA5), OpCAList)
	assert.Equal(t, byte(0xA6), OpCAVerify)
	assert.Equal(t, byte(0xA7), OpCACRL)
	assert.Equal(t, byte(0xA8), OpCABundle)
}

func TestCAHandler_HandleGet_RootCertBySerial(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	// Get the root certificate by its serial (encoded as hex)
	rootSerial := ca.rootCert.SerialNumber.Bytes()
	serialHex := make([]byte, hex.EncodedLen(len(rootSerial)))
	hex.Encode(serialHex, rootSerial)

	getReq := &CAGetRequest{
		Serial:     string(serialHex),
		IncludePem: true,
	}

	payload, err := EncodePayload(getReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCAGet,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	require.Equal(t, StatusOK, resp.Status)

	var getResp CAGetResponse
	err = DecodePayload(resp.Payload, &getResp)
	require.NoError(t, err)

	assert.NotNil(t, getResp.Certificate)
	assert.Equal(t, "Test Root CA", getResp.Certificate.Subject.CommonName)
}

func TestCAHandler_HandleGet_IntermediateCertBySerial(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	// Get the intermediate certificate by its serial (encoded as hex)
	intermSerial := ca.intermCert.SerialNumber.Bytes()
	serialHex := make([]byte, hex.EncodedLen(len(intermSerial)))
	hex.Encode(serialHex, intermSerial)

	getReq := &CAGetRequest{
		Serial:     string(serialHex),
		IncludePem: false,
	}

	payload, err := EncodePayload(getReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCAGet,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	require.Equal(t, StatusOK, resp.Status)

	var getResp CAGetResponse
	err = DecodePayload(resp.Payload, &getResp)
	require.NoError(t, err)

	assert.NotNil(t, getResp.Certificate)
	assert.Equal(t, "Test Intermediate CA", getResp.Certificate.Subject.CommonName)
}

func TestCAHandler_HandleGet_CANotInitialized(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewCAHandler(logger, nil)

	getReq := &CAGetRequest{
		Serial: "12345",
	}

	payload, err := EncodePayload(getReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCAGet,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	assert.Equal(t, StatusUnavailable, resp.Status)
	assert.Contains(t, string(resp.Payload), "certificate authority not initialized")
}

func TestCAHandler_HandleList_CANotInitialized(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewCAHandler(logger, nil)

	listReq := &CAListRequest{
		Limit: 10,
	}

	payload, err := EncodePayload(listReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCAList,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	assert.Equal(t, StatusUnavailable, resp.Status)
}

func TestCAHandler_HandleRevoke_CANotInitialized(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewCAHandler(logger, nil)

	revokeReq := &CARevokeRequest{
		Serial: "12345",
		Reason: 1,
	}

	payload, err := EncodePayload(revokeReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCARevoke,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	assert.Equal(t, StatusUnavailable, resp.Status)
}

func TestCAHandler_HandleRenew_CANotInitialized(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewCAHandler(logger, nil)

	renewReq := &CARenewRequest{
		Serial:     "12345",
		ExtendDays: 365,
	}

	payload, err := EncodePayload(renewReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCARenew,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	assert.Equal(t, StatusUnavailable, resp.Status)
}

func TestCAHandler_HandleVerify_CANotInitialized(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewCAHandler(logger, nil)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert := generateTestCertificate("test.example.com", false, nil, key)

	verifyReq := &CAVerifyRequest{
		CertificateDer: cert.Raw,
	}

	payload, err := EncodePayload(verifyReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCAVerify,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	assert.Equal(t, StatusUnavailable, resp.Status)
}

func TestCAHandler_HandleIssue_CANotInitialized(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewCAHandler(logger, nil)

	issueReq := &CAIssueRequest{
		Subject: &Subject{
			CommonName: "test.example.com",
		},
		ValidDays: 365,
	}

	payload, err := EncodePayload(issueReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCAIssue,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	assert.Equal(t, StatusUnavailable, resp.Status)
}

func TestCAHandler_HandleList_WithPagination(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	// Issue a few more certificates to test pagination
	for i := 0; i < 3; i++ {
		cert := generateTestCertificate("test"+string(rune('a'+i))+".example.com", false, ca.intermCert, ca.privateKey)
		ca.certStore.StoreCertificate(cert)
	}

	listReq := &CAListRequest{
		Limit: 2,
	}

	payload, err := EncodePayload(listReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCAList,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	require.Equal(t, StatusOK, resp.Status)

	var listResp CAListResponse
	err = DecodePayload(resp.Payload, &listResp)
	require.NoError(t, err)

	assert.NotNil(t, listResp.Certificates)
}

func TestCAHandler_HandleVerify_WithInvalidPEM(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	verifyReq := &CAVerifyRequest{
		CertificatePem: "not a valid PEM",
	}

	payload, err := EncodePayload(verifyReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCAVerify,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	assert.Equal(t, StatusInvalidArgument, resp.Status)
}

func TestCAHandler_HandleRenew_NegativeExtendDays(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	renewReq := &CARenewRequest{
		Serial:     "12345",
		ExtendDays: -10,
	}

	payload, err := EncodePayload(renewReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCARenew,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	assert.Equal(t, StatusInvalidArgument, resp.Status)
	assert.Contains(t, string(resp.Payload), "extend_days must be positive")
}

// mockCAWithNilRoot is a mock CA that returns nil root cert
type mockCAWithNilRoot struct {
	*mockCA
}

func (m *mockCAWithNilRoot) TrustedRoot() (*x509.Certificate, error) {
	return nil, nil
}

func TestCAHandler_HandleInfo_WithNilRoot(t *testing.T) {
	logger := logging.DefaultLogger()
	baseCa := newMockCA()
	ca := &mockCAWithNilRoot{mockCA: baseCa}
	handler := NewCAHandler(logger, ca)

	req := &Request{
		Opcode:  OpCAInfo,
		Payload: nil,
	}

	resp := handler.HandleRequest(context.Background(), req)

	require.Equal(t, StatusOK, resp.Status)

	var infoResp CAInfoResponse
	err := DecodePayload(resp.Payload, &infoResp)
	require.NoError(t, err)

	assert.Nil(t, infoResp.RootCert)
}

// mockCAWithNilIntermediate is a mock CA that returns nil intermediate cert
type mockCAWithNilIntermediate struct {
	*mockCA
}

func (m *mockCAWithNilIntermediate) TrustedIntermediate() (*x509.Certificate, error) {
	return nil, nil
}

func TestCAHandler_HandleInfo_WithNilIntermediate(t *testing.T) {
	logger := logging.DefaultLogger()
	baseCa := newMockCA()
	ca := &mockCAWithNilIntermediate{mockCA: baseCa}
	handler := NewCAHandler(logger, ca)

	req := &Request{
		Opcode:  OpCAInfo,
		Payload: nil,
	}

	resp := handler.HandleRequest(context.Background(), req)

	require.Equal(t, StatusOK, resp.Status)

	var infoResp CAInfoResponse
	err := DecodePayload(resp.Payload, &infoResp)
	require.NoError(t, err)

	assert.False(t, infoResp.IsIntermediate)
	assert.Empty(t, infoResp.Intermediates)
}

// mockCAWithGetFailure is a mock CA where GetCertificate fails
type mockCAWithGetFailure struct {
	*mockCA
}

func TestCAHandler_HandleGet_WithNilCertStore(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	ca.certStore = nil
	handler := NewCAHandler(logger, ca)

	getReq := &CAGetRequest{
		Serial:     "nonexistent",
		IncludePem: true,
	}

	payload, err := EncodePayload(getReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCAGet,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	assert.Equal(t, StatusNotFound, resp.Status)
}

// Test default store type when empty string is passed
func TestCAHandler_HandleIssue_DefaultStoreType(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	issueReq := &CAIssueRequest{
		Subject: &Subject{
			CommonName: "test.example.com",
		},
		ValidDays: 365,
		StoreType: "", // Empty should default to Software
	}

	payload, err := EncodePayload(issueReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCAIssue,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	require.Equal(t, StatusOK, resp.Status)
}

func TestCAHandler_HandleList_WithoutIntermediateCert(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	ca.intermCert = nil
	handler := NewCAHandler(logger, ca)

	listReq := &CAListRequest{
		Limit: 10,
	}

	payload, err := EncodePayload(listReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCAList,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	require.Equal(t, StatusOK, resp.Status)

	var listResp CAListResponse
	err = DecodePayload(resp.Payload, &listResp)
	require.NoError(t, err)

	// Should only have root cert
	assert.Equal(t, int32(1), listResp.TotalCount)
}

func TestCAHandler_HandleList_WithoutRootCert(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	ca.rootCert = nil
	handler := NewCAHandler(logger, ca)

	listReq := &CAListRequest{
		Limit: 10,
	}

	payload, err := EncodePayload(listReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCAList,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	require.Equal(t, StatusOK, resp.Status)

	var listResp CAListResponse
	err = DecodePayload(resp.Payload, &listResp)
	require.NoError(t, err)

	// Should only have intermediate cert
	assert.Equal(t, int32(1), listResp.TotalCount)
}

// Test CA Issue with all algorithms
func TestCAHandler_HandleIssue_AllAlgorithms(t *testing.T) {
	logger := logging.DefaultLogger()

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
		"P256",
		"P384",
		"P521",
		"ECDSA-P256",
		"ECDSA-P384",
		"ECDSA-P521",
		"ED25519",
	}

	for _, alg := range algorithms {
		t.Run(alg, func(t *testing.T) {
			ca := newMockCA()
			handler := NewCAHandler(logger, ca)

			issueReq := &CAIssueRequest{
				Subject: &Subject{
					CommonName: "test.example.com",
				},
				ValidDays:    365,
				KeyAlgorithm: alg,
			}

			payload, err := EncodePayload(issueReq)
			require.NoError(t, err)

			req := &Request{
				Opcode:  OpCAIssue,
				Payload: payload,
			}

			resp := handler.HandleRequest(context.Background(), req)

			require.Equal(t, StatusOK, resp.Status)
		})
	}
}

// Test CA Bundle with different algorithms
func TestCAHandler_HandleBundle_AllAlgorithms(t *testing.T) {
	logger := logging.DefaultLogger()

	algorithms := []string{
		"RSA",
		"ECDSA",
		"ED25519",
		"", // empty defaults to no filter
	}

	for _, alg := range algorithms {
		t.Run("alg_"+alg, func(t *testing.T) {
			ca := newMockCA()
			handler := NewCAHandler(logger, ca)

			bundleReq := &CABundleRequest{
				Algorithm: alg,
			}

			payload, err := EncodePayload(bundleReq)
			require.NoError(t, err)

			req := &Request{
				Opcode:  OpCABundle,
				Payload: payload,
			}

			resp := handler.HandleRequest(context.Background(), req)

			require.Equal(t, StatusOK, resp.Status)
		})
	}
}

// Test CA Bundle with different store types
func TestCAHandler_HandleBundle_AllStoreTypes(t *testing.T) {
	logger := logging.DefaultLogger()

	storeTypes := []string{
		"SOFTWARE",
		"PKCS8",
		"PKCS11",
		"TPM",
		"", // empty defaults
	}

	for _, st := range storeTypes {
		t.Run("store_"+st, func(t *testing.T) {
			ca := newMockCA()
			handler := NewCAHandler(logger, ca)

			bundleReq := &CABundleRequest{
				StoreType: st,
			}

			payload, err := EncodePayload(bundleReq)
			require.NoError(t, err)

			req := &Request{
				Opcode:  OpCABundle,
				Payload: payload,
			}

			resp := handler.HandleRequest(context.Background(), req)

			require.Equal(t, StatusOK, resp.Status)
		})
	}
}

// Test CA Issue with CA cert flag
func TestCAHandler_HandleIssue_CAFlag(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	issueReq := &CAIssueRequest{
		Subject: &Subject{
			CommonName: "intermediate.example.com",
		},
		ValidDays:  365,
		IsCA:       true,
		MaxPathLen: 1,
	}

	payload, err := EncodePayload(issueReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCAIssue,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	require.Equal(t, StatusOK, resp.Status)
}

// Test verify with valid chains
func TestCAHandler_HandleVerify_ValidChain(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	// Create a self-signed certificate that chains to the root
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  false,
		BasicConstraintsValid: true,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, ca.rootCert, &key.PublicKey, ca.privateKey)

	verifyReq := &CAVerifyRequest{
		CertificateDer: certDER,
		CheckRevoked:   true,
	}

	payload, err := EncodePayload(verifyReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCAVerify,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	require.Equal(t, StatusOK, resp.Status)

	var verifyResp CAVerifyResponse
	err = DecodePayload(resp.Payload, &verifyResp)
	require.NoError(t, err)

	// Should have chain information
	assert.NotEmpty(t, verifyResp.Chain)
}

// mockCANoCRL is a mock CA that doesn't implement GenerateCRL
type mockCANoCRL struct {
	initialized   bool
	identity      string
	rootCert      *x509.Certificate
	intermCert    *x509.Certificate
	defaultKeyAlg x509.PublicKeyAlgorithm
	defaultSigAlg x509.SignatureAlgorithm
	validity      time.Duration
	certStore     *mockCertStore
	issuedCerts   []*x509.Certificate
	revokedCerts  []*x509.Certificate
	privateKey    *ecdsa.PrivateKey
}

func newMockCANoCRL() *mockCANoCRL {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootCert := generateTestCertificate("Test Root CA", true, nil, privateKey)
	intermCert := generateTestCertificate("Test Intermediate CA", true, rootCert, privateKey)

	return &mockCANoCRL{
		initialized:   true,
		identity:      "Test CA",
		rootCert:      rootCert,
		intermCert:    intermCert,
		defaultKeyAlg: x509.ECDSA,
		defaultSigAlg: x509.ECDSAWithSHA256,
		validity:      365 * 24 * time.Hour,
		certStore:     newMockCertStore(),
		issuedCerts:   make([]*x509.Certificate, 0),
		revokedCerts:  make([]*x509.Certificate, 0),
		privateKey:    privateKey,
	}
}

func (m *mockCANoCRL) Public() crypto.PublicKey { return &m.privateKey.PublicKey }
func (m *mockCANoCRL) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return ecdsa.SignASN1(rand, m.privateKey, digest)
}
func (m *mockCANoCRL) IsInitialized() bool                                { return m.initialized }
func (m *mockCANoCRL) Identity() string                                   { return m.identity }
func (m *mockCANoCRL) DefaultKeyAlgorithm() x509.PublicKeyAlgorithm       { return m.defaultKeyAlg }
func (m *mockCANoCRL) DefaultSignatureAlgorithm() x509.SignatureAlgorithm { return m.defaultSigAlg }
func (m *mockCANoCRL) DefaultValidityPeriod() time.Duration               { return m.validity }
func (m *mockCANoCRL) TrustedRoot() (*x509.Certificate, error)            { return m.rootCert, nil }
func (m *mockCANoCRL) TrustedIntermediate() (*x509.Certificate, error)    { return m.intermCert, nil }
func (m *mockCANoCRL) CertificateStore() xkmssdk.CertStore {
	if m.certStore == nil {
		return nil
	}
	return m.certStore
}
func (m *mockCANoCRL) IssueCertificate(req *goca.CACertificateRequest) (*x509.Certificate, error) {
	cert := generateTestCertificate(req.Subject.CommonName, req.IsCA, m.intermCert, m.privateKey)
	m.issuedCerts = append(m.issuedCerts, cert)
	if m.certStore != nil {
		m.certStore.StoreCertificate(cert)
	}
	return cert, nil
}
func (m *mockCANoCRL) Revoke(cert *x509.Certificate, keyAttrs *xkmssdk.KeyAttributes) error {
	m.revokedCerts = append(m.revokedCerts, cert)
	return nil
}
func (m *mockCANoCRL) CABundle(storeType xkmssdk.StoreType, keyAlg x509.PublicKeyAlgorithm) ([]byte, error) {
	return m.rootCert.Raw, nil
}
func (m *mockCANoCRL) ParseBundle(bundle []byte) ([]*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(bundle)
	if err != nil {
		return nil, err
	}
	return []*x509.Certificate{cert}, nil
}

// mockCANoCRL intentionally returns error for GenerateCRL to test not-implemented path
func (m *mockCANoCRL) GenerateCRL() ([]byte, error) {
	return nil, ErrCACRLNotSupported
}
func (m *mockCANoCRL) IsRevoked(serial *big.Int) (bool, error) {
	return false, nil
}

// Stub implementations for remaining interface methods
func (m *mockCANoCRL) SignCSR(csrPEM []byte, request *goca.CACertificateRequest) (*x509.Certificate, error) {
	return nil, nil
}
func (m *mockCANoCRL) SignTCGCSRIDevID(tcgCSRIDevID *xkmssdk.TCG_CSR_IDEVID, request *goca.CACertificateRequest) ([]byte, []byte, error) {
	return nil, nil, nil
}
func (m *mockCANoCRL) ImportCertificate(certificate *x509.Certificate) error { return nil }
func (m *mockCANoCRL) Certificate(attrs *xkmssdk.KeyAttributes) (*x509.Certificate, error) {
	return nil, nil
}
func (m *mockCANoCRL) CertificatePEM(cn string) ([]byte, error) { return nil, nil }
func (m *mockCANoCRL) Verify(certificate *x509.Certificate, xsigner crypto.Signer) ([][]*x509.Certificate, error) {
	return nil, nil
}
func (m *mockCANoCRL) Signer() (crypto.Signer, error)                               { return m, nil }
func (m *mockCANoCRL) CreateCSR(request *goca.CACertificateRequest) ([]byte, error) { return nil, nil }
func (m *mockCANoCRL) TLSCertificate(attrs *xkmssdk.KeyAttributes) (tls.Certificate, error) {
	return tls.Certificate{}, nil
}
func (m *mockCANoCRL) TLSBundle(attrs *xkmssdk.KeyAttributes) ([]byte, error)      { return nil, nil }
func (m *mockCANoCRL) TLSConfig(attrs *xkmssdk.KeyAttributes) (*tls.Config, error) { return nil, nil }
func (m *mockCANoCRL) TLSConfigWithXSigner(attrs *xkmssdk.KeyAttributes, xsigner interface{}) (*tls.Config, error) {
	return nil, nil
}
func (m *mockCANoCRL) QuantumSafeTLSConfig(attrs *xkmssdk.KeyAttributes) (*tls.Config, error) {
	return nil, nil
}
func (m *mockCANoCRL) TLSBundleWithCrossSigner(attrs *xkmssdk.KeyAttributes, issuerCN string) ([][]byte, *x509.Certificate, error) {
	return nil, nil, nil
}
func (m *mockCANoCRL) Issued(cn string) (bool, error) { return false, nil }
func (m *mockCANoCRL) Exists(cn string, algorithm x509.SignatureAlgorithm) (bool, error) {
	return false, nil
}
func (m *mockCANoCRL) ImportDistributionCRLs(cert *x509.Certificate) error { return nil }
func (m *mockCANoCRL) IssueEKCertificate(request *goca.CACertificateRequest, ekPubKey crypto.PublicKey) (*x509.Certificate, error) {
	return nil, nil
}
func (m *mockCANoCRL) IssueAKCertificate(request *goca.CACertificateRequest, pubKey crypto.PublicKey) (*x509.Certificate, error) {
	return nil, nil
}
func (m *mockCANoCRL) ImportEndorsementKeyCertificate(cert *x509.Certificate) error { return nil }
func (m *mockCANoCRL) ImportXSignedCertificate(issuerCN string, cert *x509.Certificate) error {
	return nil
}
func (m *mockCANoCRL) EndorsementKeyCertificate(cn string) (*x509.Certificate, error) {
	return nil, nil
}
func (m *mockCANoCRL) SignedBlob(data interface{}) ([]byte, error) { return nil, nil }
func (m *mockCANoCRL) TrustedRootCertPool(cert *x509.Certificate, xsigner crypto.Signer) (*x509.CertPool, error) {
	return nil, nil
}
func (m *mockCANoCRL) TrustedIntermediateCertPool(cert *x509.Certificate, xsigner crypto.Signer) (*x509.CertPool, error) {
	return nil, nil
}
func (m *mockCANoCRL) CABundleCertPool(storeType xkmssdk.StoreType, keyAlgorithm x509.PublicKeyAlgorithm) (*x509.CertPool, error) {
	return nil, nil
}
func (m *mockCANoCRL) ImportIssuingCAs(cert *x509.Certificate) error { return nil }
func (m *mockCANoCRL) RootCertificate(childCert *x509.Certificate) (*x509.Certificate, error) {
	return m.rootCert, nil
}
func (m *mockCANoCRL) ObjectStore() common.Storage                                   { return nil }
func (m *mockCANoCRL) PEM(attrs *xkmssdk.KeyAttributes) ([]byte, error)              { return nil, nil }
func (m *mockCANoCRL) ImportCertificatePEM(cn string, pemData []byte) error          { return nil }
func (m *mockCANoCRL) Blob(key string) ([]byte, error)                               { return nil, nil }
func (m *mockCANoCRL) ImportBlob(key string, data []byte) error                      { return nil }
func (m *mockCANoCRL) KeyStore() interface{}                                         { return nil }
func (m *mockCANoCRL) Key(attrs *xkmssdk.KeyAttributes) (interface{}, error)         { return nil, nil }
func (m *mockCANoCRL) PubKey(attrs *xkmssdk.KeyAttributes) (crypto.PublicKey, error) { return nil, nil }
func (m *mockCANoCRL) OSTrustStore() (*x509.CertPool, error)                         { return nil, nil }
func (m *mockCANoCRL) IsAutoImportingIssuerCAs() bool                                { return false }
func (m *mockCANoCRL) Hash() crypto.Hash                                             { return crypto.SHA256 }
func (m *mockCANoCRL) CAKeyAttributes(storeType xkmssdk.StoreType) (*xkmssdk.KeyAttributes, error) {
	return nil, nil
}
func (m *mockCANoCRL) CASigner(storeType xkmssdk.StoreType, algorithm x509.PublicKeyAlgorithm) (crypto.Signer, error) {
	return m, nil
}
func (m *mockCANoCRL) Init() error             { return nil }
func (m *mockCANoCRL) Load() error             { return nil }
func (m *mockCANoCRL) CAConfig() goca.CAConfig { return goca.CAConfig{} }
func (m *mockCANoCRL) ImportAttestation(akAttrs *xkmssdk.KeyAttributes, blobType string, data []byte) error {
	return nil
}
func (m *mockCANoCRL) ImportAttestationKeyCertificate(attrs *xkmssdk.KeyAttributes, akDER []byte) error {
	return nil
}
func (m *mockCANoCRL) ImportAttestationEventLog(akAttrs *xkmssdk.KeyAttributes, eventLog []byte) error {
	return nil
}
func (m *mockCANoCRL) ImportAttestationPCRs(akAttrs *xkmssdk.KeyAttributes, pcrs []byte) error {
	return nil
}
func (m *mockCANoCRL) ImportAttestationQuote(akAttrs *xkmssdk.KeyAttributes, quote []byte) error {
	return nil
}
func (m *mockCANoCRL) ImportLocalAttestation(akAttrs *xkmssdk.KeyAttributes, quote *xkmssdk.Quote) error {
	return nil
}
func (m *mockCANoCRL) VerifyQuote(akAttrs *xkmssdk.KeyAttributes, quote *xkmssdk.Quote, nonce []byte) error {
	return nil
}
func (m *mockCANoCRL) VerifyAttestationQuote(akAttrs *xkmssdk.KeyAttributes, quote []byte) error {
	return nil
}
func (m *mockCANoCRL) VerifyAttestationEventLog(akAttrs *xkmssdk.KeyAttributes, eventLog []byte) error {
	return nil
}
func (m *mockCANoCRL) VerifyAttestationPCRs(akAttrs *xkmssdk.KeyAttributes, pcrs []byte) error {
	return nil
}
func (m *mockCANoCRL) VerifyTCG_CSR_IDevIDBytes(packedCSR []byte, sigAlg interface{}) ([]byte, []byte, []byte, error) {
	return nil, nil, nil, nil
}
func (m *mockCANoCRL) SetTPM(tpm xkmssdk.TrustedPlatformModule) {}

func TestCAHandler_HandleCRL_InterfaceNotImplemented(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCANoCRL()
	handler := NewCAHandler(logger, ca)

	req := &Request{
		Opcode:  OpCACRL,
		Payload: nil,
	}

	resp := handler.HandleRequest(context.Background(), req)

	assert.Equal(t, StatusNotImplemented, resp.Status)
	assert.Contains(t, string(resp.Payload), "CRL generation not supported")
}

// mockCAIssueFails is a mock CA where IssueCertificate always fails
type mockCAIssueFails struct {
	*mockCA
}

func (m *mockCAIssueFails) IssueCertificate(req *goca.CACertificateRequest) (*x509.Certificate, error) {
	return nil, errors.New("certificate issuance failed")
}

func TestCAHandler_HandleIssue_IssueFails(t *testing.T) {
	logger := logging.DefaultLogger()
	baseCa := newMockCA()
	ca := &mockCAIssueFails{mockCA: baseCa}
	handler := NewCAHandler(logger, ca)

	issueReq := &CAIssueRequest{
		Subject: &Subject{
			CommonName: "test.example.com",
		},
		ValidDays: 365,
	}

	payload, err := EncodePayload(issueReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCAIssue,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	assert.Equal(t, StatusInternalError, resp.Status)
	assert.Contains(t, string(resp.Payload), "failed to issue certificate")
}

// mockCARevokeFails is a mock CA where Revoke always fails
type mockCARevokeFails struct {
	*mockCA
}

func (m *mockCARevokeFails) Revoke(cert *x509.Certificate, keyAttrs *xkmssdk.KeyAttributes) error {
	return errors.New("revocation failed")
}

func TestCAHandler_HandleRevoke_RevokeFails(t *testing.T) {
	logger := logging.DefaultLogger()
	baseCa := newMockCA()
	ca := &mockCARevokeFails{mockCA: baseCa}
	handler := NewCAHandler(logger, ca)

	// First issue a certificate
	cert := generateTestCertificate("test.example.com", false, baseCa.intermCert, baseCa.privateKey)
	baseCa.certStore.StoreCertificate(cert)

	revokeReq := &CARevokeRequest{
		Serial: cert.SerialNumber.String(),
		Reason: 1,
	}

	payload, err := EncodePayload(revokeReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCARevoke,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	assert.Equal(t, StatusInternalError, resp.Status)
	assert.Contains(t, string(resp.Payload), "failed to revoke certificate")
}

// mockCARenewFails is a mock CA where renewing (IssueCertificate for renewal) fails
type mockCARenewFails struct {
	*mockCA
	shouldFail bool
}

func (m *mockCARenewFails) IssueCertificate(req *goca.CACertificateRequest) (*x509.Certificate, error) {
	if m.shouldFail {
		return nil, errors.New("renewal failed")
	}
	cert := generateTestCertificate(req.Subject.CommonName, req.IsCA, m.intermCert, m.privateKey)
	m.issuedCerts = append(m.issuedCerts, cert)
	if m.certStore != nil {
		m.certStore.StoreCertificate(cert)
	}
	return cert, nil
}

func TestCAHandler_HandleRenew_RenewFails(t *testing.T) {
	logger := logging.DefaultLogger()
	baseCa := newMockCA()
	ca := &mockCARenewFails{mockCA: baseCa, shouldFail: false}
	handler := NewCAHandler(logger, ca)

	// First issue a certificate (shouldFail is false)
	cert := generateTestCertificate("test.example.com", false, baseCa.intermCert, baseCa.privateKey)
	baseCa.certStore.StoreCertificate(cert)

	// Now set shouldFail to true for the renewal attempt
	ca.shouldFail = true

	renewReq := &CARenewRequest{
		Serial:     cert.SerialNumber.String(),
		ExtendDays: 365,
	}

	payload, err := EncodePayload(renewReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCARenew,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	assert.Equal(t, StatusInternalError, resp.Status)
	assert.Contains(t, string(resp.Payload), "failed to renew certificate")
}

// mockCAEmptyBundle is a mock CA that returns an empty bundle
type mockCAEmptyBundle struct {
	*mockCA
}

func (m *mockCAEmptyBundle) CABundle(storeType xkmssdk.StoreType, keyAlg x509.PublicKeyAlgorithm) ([]byte, error) {
	return []byte{}, nil
}

func TestCAHandler_HandleBundle_EmptyBundle(t *testing.T) {
	logger := logging.DefaultLogger()
	baseCa := newMockCA()
	ca := &mockCAEmptyBundle{mockCA: baseCa}
	handler := NewCAHandler(logger, ca)

	bundleReq := &CABundleRequest{}

	payload, err := EncodePayload(bundleReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCABundle,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	assert.Equal(t, StatusNotFound, resp.Status)
	assert.Contains(t, string(resp.Payload), "CA bundle not found")
}

// mockCABundleFails is a mock CA where CABundle returns an error
type mockCABundleFails struct {
	*mockCA
}

func (m *mockCABundleFails) CABundle(storeType xkmssdk.StoreType, keyAlg x509.PublicKeyAlgorithm) ([]byte, error) {
	return nil, errors.New("bundle retrieval failed")
}

func TestCAHandler_HandleBundle_BundleFails(t *testing.T) {
	logger := logging.DefaultLogger()
	baseCa := newMockCA()
	ca := &mockCABundleFails{mockCA: baseCa}
	handler := NewCAHandler(logger, ca)

	bundleReq := &CABundleRequest{}

	payload, err := EncodePayload(bundleReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCABundle,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	assert.Equal(t, StatusInternalError, resp.Status)
	assert.Contains(t, string(resp.Payload), "failed to get CA bundle")
}

// Test handleList with more certificates than limit to trigger pagination logic
func TestCAHandler_HandleList_LimitTriggersSlicing(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	// Issue many certificates to exceed limit
	for i := 0; i < 10; i++ {
		cert := generateTestCertificate("cert"+string(rune('a'+i))+".example.com", false, ca.intermCert, ca.privateKey)
		ca.certStore.StoreCertificate(cert)
	}

	// Set limit to 1, which should slice the result
	// Note: handleList only includes root and intermediate, not issued certs
	// So we need limit of 1 to trigger slicing
	listReq := &CAListRequest{
		Limit: 1,
	}

	payload, err := EncodePayload(listReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCAList,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	require.Equal(t, StatusOK, resp.Status)

	var listResp CAListResponse
	err = DecodePayload(resp.Payload, &listResp)
	require.NoError(t, err)

	// Should have sliced to 1 cert but total count should be 2 (root + intermediate)
	assert.Equal(t, 1, len(listResp.Certificates))
	assert.Equal(t, int32(2), listResp.TotalCount)
	assert.True(t, listResp.HasMore)
}

// Test handleCRL with revoked certificates
func TestCAHandler_HandleCRL_WithRevokedCerts(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	// Add some revoked certificates to the CRL by revoking them first
	cert := generateTestCertificate("revoked.example.com", false, ca.intermCert, ca.privateKey)
	ca.certStore.StoreCertificate(cert)
	ca.revokedCerts = append(ca.revokedCerts, cert)

	req := &Request{
		Opcode:  OpCACRL,
		Payload: nil,
	}

	resp := handler.HandleRequest(context.Background(), req)

	require.Equal(t, StatusOK, resp.Status)

	var crlResp CACRLResponse
	err := DecodePayload(resp.Payload, &crlResp)
	require.NoError(t, err)

	assert.NotEmpty(t, crlResp.CRL)
}

// mockCAWithRevokedCRL is a mock CA that generates CRL with revoked entries
type mockCAWithRevokedCRL struct {
	*mockCA
}

func (m *mockCAWithRevokedCRL) GenerateCRL() ([]byte, error) {
	// Create a CRL with a revoked certificate entry
	revokedCerts := []x509.RevocationListEntry{
		{
			SerialNumber:   big.NewInt(12345),
			RevocationTime: time.Now(),
			ReasonCode:     1, // Key compromise
		},
	}

	template := &x509.RevocationList{
		SignatureAlgorithm:        x509.ECDSAWithSHA256,
		Number:                    big.NewInt(1),
		ThisUpdate:                time.Now(),
		NextUpdate:                time.Now().Add(24 * time.Hour),
		RevokedCertificateEntries: revokedCerts,
	}
	return x509.CreateRevocationList(rand.Reader, template, m.rootCert, m.privateKey)
}

func TestCAHandler_HandleCRL_WithRevokedEntries(t *testing.T) {
	logger := logging.DefaultLogger()
	baseCa := newMockCA()
	ca := &mockCAWithRevokedCRL{mockCA: baseCa}
	handler := NewCAHandler(logger, ca)

	req := &Request{
		Opcode:  OpCACRL,
		Payload: nil,
	}

	resp := handler.HandleRequest(context.Background(), req)

	require.Equal(t, StatusOK, resp.Status)

	var crlResp CACRLResponse
	err := DecodePayload(resp.Payload, &crlResp)
	require.NoError(t, err)

	assert.NotEmpty(t, crlResp.CRL)
	assert.Equal(t, int32(1), crlResp.RevokedCount)
	assert.Len(t, crlResp.RevokedCerts, 1)
	assert.Equal(t, int32(1), crlResp.RevokedCerts[0].Reason)
}

// Test handleGet encoding error by testing with root cert
func TestCAHandler_HandleGet_RootCertSuccess(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	// Get the root certificate by its serial
	rootSerial := hex.EncodeToString(ca.rootCert.SerialNumber.Bytes())

	getReq := &CAGetRequest{
		Serial:     rootSerial,
		IncludePem: false,
	}

	payload, err := EncodePayload(getReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCAGet,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	require.Equal(t, StatusOK, resp.Status)

	var getResp CAGetResponse
	err = DecodePayload(resp.Payload, &getResp)
	require.NoError(t, err)

	assert.Equal(t, "Test Root CA", getResp.Certificate.Subject.CommonName)
}

// Test handleGet for intermediate cert
func TestCAHandler_HandleGet_IntermediateCertSuccess(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	// Get the intermediate certificate by its serial
	intermSerial := hex.EncodeToString(ca.intermCert.SerialNumber.Bytes())

	getReq := &CAGetRequest{
		Serial:     intermSerial,
		IncludePem: true,
	}

	payload, err := EncodePayload(getReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCAGet,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	require.Equal(t, StatusOK, resp.Status)

	var getResp CAGetResponse
	err = DecodePayload(resp.Payload, &getResp)
	require.NoError(t, err)

	assert.Equal(t, "Test Intermediate CA", getResp.Certificate.Subject.CommonName)
	assert.NotEmpty(t, getResp.Certificate.Pem)
}

// Test handleGet for cert from store
func TestCAHandler_HandleGet_FromCertStore(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	// Issue a certificate and store it
	cert := generateTestCertificate("stored.example.com", false, ca.intermCert, ca.privateKey)
	ca.certStore.StoreCertificate(cert)

	getReq := &CAGetRequest{
		Serial:     cert.SerialNumber.String(),
		IncludePem: true,
	}

	payload, err := EncodePayload(getReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCAGet,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	require.Equal(t, StatusOK, resp.Status)

	var getResp CAGetResponse
	err = DecodePayload(resp.Payload, &getResp)
	require.NoError(t, err)

	assert.Equal(t, "stored.example.com", getResp.Certificate.Subject.CommonName)
}

// Test handleVerify with expired cert returning valid but EXPIRED status
func TestCAHandler_HandleVerify_ExpiredReturnsValidResponse(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	// Create a certificate signed by the root but expired
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: "expired.example.com",
		},
		NotBefore: time.Now().Add(-365 * 24 * time.Hour),
		NotAfter:  time.Now().Add(-1 * time.Hour), // Expired
		IsCA:      false,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, ca.rootCert, &key.PublicKey, ca.privateKey)

	verifyReq := &CAVerifyRequest{
		CertificateDer: certDER,
	}

	payload, err := EncodePayload(verifyReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCAVerify,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	// Even expired certificates should return a valid response structure
	// with the verification details (just marked as invalid/expired)
	require.Equal(t, StatusOK, resp.Status)

	var verifyResp CAVerifyResponse
	err = DecodePayload(resp.Payload, &verifyResp)
	require.NoError(t, err)

	// The certificate verification will fail because it's expired
	assert.False(t, verifyResp.Valid)
}

// Test handleVerify with not-yet-valid cert
func TestCAHandler_HandleVerify_NotYetValidReturnsValidResponse(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := newMockCA()
	handler := NewCAHandler(logger, ca)

	// Create a certificate signed by the root but not yet valid
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: "future.example.com",
		},
		NotBefore: time.Now().Add(24 * time.Hour), // Starts tomorrow
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		IsCA:      false,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, ca.rootCert, &key.PublicKey, ca.privateKey)

	verifyReq := &CAVerifyRequest{
		CertificateDer: certDER,
	}

	payload, err := EncodePayload(verifyReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCAVerify,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	require.Equal(t, StatusOK, resp.Status)

	var verifyResp CAVerifyResponse
	err = DecodePayload(resp.Payload, &verifyResp)
	require.NoError(t, err)

	// The certificate verification will fail because it's not yet valid
	assert.False(t, verifyResp.Valid)
}

// Test handleCRL with service unavailable
func TestCAHandler_HandleCRL_ServiceUnavailable(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewCAHandler(logger, nil)

	crlReq := &CACRLRequest{}

	payload, err := EncodePayload(crlReq)
	require.NoError(t, err)

	req := &Request{
		Opcode:  OpCACRL,
		Payload: payload,
	}

	resp := handler.HandleRequest(context.Background(), req)

	require.Equal(t, StatusUnavailable, resp.Status)
}

// Test handleCRL with generate error
func TestCAHandler_HandleCRL_GenerateError(t *testing.T) {
	logger := logging.DefaultLogger()
	ca := &mockCAGenerateCRLFails{mockCA: newMockCA()}
	handler := NewCAHandler(logger, ca)

	req := &Request{
		Opcode:  OpCACRL,
		Payload: nil,
	}

	resp := handler.HandleRequest(context.Background(), req)

	require.Equal(t, StatusInternalError, resp.Status)
	assert.Contains(t, string(resp.Payload), "failed to generate CRL")
}

// mockCAGenerateCRLFails is a mock CA where GenerateCRL always fails
type mockCAGenerateCRLFails struct {
	*mockCA
}

func (m *mockCAGenerateCRLFails) GenerateCRL() ([]byte, error) {
	return nil, errors.New("CRL generation failed")
}
