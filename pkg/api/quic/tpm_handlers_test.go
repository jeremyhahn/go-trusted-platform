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
	"crypto/x509"
	"errors"
	"math/big"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockTPM implements xkmssdk.TrustedPlatformModule for handler tests.
type mockTPM struct {
	xkmssdk.TrustedPlatformModule

	infoResult         string
	infoErr            error
	fixedProps         *xkmssdk.PropertiesFixed
	fixedPropsErr      error
	config             *xkmssdk.TPMConfig
	provisionOwnerErr  error
	clearErr           error
	ekAttrs            *xkmssdk.KeyAttributes
	ekAttrsErr         error
	createEKErr        error
	ekCert             *x509.Certificate
	ekCertErr          error
	provisionEKCertErr error
	ssrkAttrs          *xkmssdk.KeyAttributes
	ssrkAttrsErr       error
	createSRKErr       error
	iakAttrs           *xkmssdk.KeyAttributes
	iakAttrsErr        error
	iakPubKey          crypto.PublicKey
	iakPubKeyErr       error
	createIAKAttrs     *xkmssdk.KeyAttributes
	createIAKErr       error
	idevidAttrs        *xkmssdk.KeyAttributes
	idevidAttrsErr     error
	idevidPubKey       crypto.PublicKey
	idevidPubKeyErr    error
	quoteResult        xkmssdk.Quote
	quoteErr           error
	readPCRsResult     []xkmssdk.PCRBank
	readPCRsErr        error
	extendPCRErr       error
	eventLogData       []byte
	eventLogErr        error
	parsedEvents       []xkmssdk.TPMEvent
	parsedEventsErr    error
	supportedAlgs      []string
	supportedAlgsErr   error
	supportedCmds      []string
	supportedCmdsErr   error
	supportedCurves    []string
	supportedCurvesErr error
	randomBytesResult  []byte
	randomBytesErr     error
	sealResult         *xkmssdk.SealedData
	sealErr            error
	unsealResult       []byte
	unsealErr          error
	deviceResult       string
	isFIPSResult       bool
	isFIPSErr          error
	isPCRExtResult     bool
	isPCRExtErr        error
	canSealResult      bool
}

func newMockTPM() *mockTPM {
	return &mockTPM{
		config:        &xkmssdk.TPMConfig{UseSimulator: true},
		infoResult:    "mock-tpm-info",
		deviceResult:  "/dev/tpmrm0",
		canSealResult: true,
		fixedProps: &xkmssdk.PropertiesFixed{
			Manufacturer: "TEST-MFR",
			Model:        "TestModel",
			Family:       "2.0",
			Revision:     "1.0",
			VendorID:     "TST",
		},
		ekAttrs: &xkmssdk.KeyAttributes{
			CN:           "test-ek",
			KeyAlgorithm: x509.RSA,
			TPMAttributes: &xkmssdk.TPMAttributes{
				Handle:         0x81010001,
				PublicKeyBytes: []byte("test-ek-pub"),
			},
		},
		ssrkAttrs: &xkmssdk.KeyAttributes{
			CN: "test-srk",
			TPMAttributes: &xkmssdk.TPMAttributes{
				Handle: 0x81000001,
			},
		},
		iakAttrs: &xkmssdk.KeyAttributes{
			CN: "test-iak",
			TPMAttributes: &xkmssdk.TPMAttributes{
				Handle:         0x81020001,
				PublicKeyBytes: []byte("test-iak-pub"),
			},
		},
		idevidAttrs: &xkmssdk.KeyAttributes{
			CN:           "test-idevid",
			KeyAlgorithm: x509.ECDSA,
			TPMAttributes: &xkmssdk.TPMAttributes{
				Handle:         0x81030001,
				PublicKeyBytes: []byte("test-idevid-pub"),
			},
		},
		readPCRsResult: []xkmssdk.PCRBank{
			{Algorithm: "sha256", PCRs: []xkmssdk.PCR{{ID: 0, Value: []byte{0}}}},
		},
		supportedAlgs:   []string{"RSA", "ECDSA", "SHA256"},
		supportedCmds:   []string{"TPM2_Create", "TPM2_Sign"},
		supportedCurves: []string{"P256", "P384"},
	}
}

func (m *mockTPM) Info() (string, error) { return m.infoResult, m.infoErr }
func (m *mockTPM) FixedProperties() (*xkmssdk.PropertiesFixed, error) {
	return m.fixedProps, m.fixedPropsErr
}
func (m *mockTPM) Config() *xkmssdk.TPMConfig { return m.config }
func (m *mockTPM) ProvisionOwner(auth xkmssdk.Password) (*xkmssdk.KeyAttributes, error) {
	if m.provisionOwnerErr != nil {
		return nil, m.provisionOwnerErr
	}
	return m.ekAttrs, nil
}
func (m *mockTPM) Clear(lockoutAuth []byte) error                 { return m.clearErr }
func (m *mockTPM) EKAttributes() (*xkmssdk.KeyAttributes, error)  { return m.ekAttrs, m.ekAttrsErr }
func (m *mockTPM) CreateEK(keyAttrs *xkmssdk.KeyAttributes) error { return m.createEKErr }
func (m *mockTPM) Flush(handle tpm2.TPMHandle)                    {}
func (m *mockTPM) EKCertificate() (*x509.Certificate, error) {
	if m.ekCertErr != nil {
		return nil, m.ekCertErr
	}
	if m.ekCert != nil {
		return m.ekCert, nil
	}
	return &x509.Certificate{Raw: []byte("test-cert"), SerialNumber: big.NewInt(1)}, nil
}
func (m *mockTPM) ProvisionEKCert(hierarchyAuth, ekCert []byte) error { return m.provisionEKCertErr }
func (m *mockTPM) SSRKAttributes() (*xkmssdk.KeyAttributes, error) {
	return m.ssrkAttrs, m.ssrkAttrsErr
}
func (m *mockTPM) CreateSRK(keyAttrs *xkmssdk.KeyAttributes) error { return m.createSRKErr }
func (m *mockTPM) IAKAttributes() (*xkmssdk.KeyAttributes, error)  { return m.iakAttrs, m.iakAttrsErr }
func (m *mockTPM) IAK() (crypto.PublicKey, error) {
	if m.iakPubKeyErr != nil {
		return nil, m.iakPubKeyErr
	}
	if m.iakPubKey != nil {
		return m.iakPubKey, nil
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return &key.PublicKey, nil
}
func (m *mockTPM) CreateIAK(ekAttrs *xkmssdk.KeyAttributes, qualifyingData []byte) (*xkmssdk.KeyAttributes, error) {
	if m.createIAKErr != nil {
		return nil, m.createIAKErr
	}
	return m.createIAKAttrs, nil
}
func (m *mockTPM) IDevIDAttributes() (*xkmssdk.KeyAttributes, error) {
	return m.idevidAttrs, m.idevidAttrsErr
}
func (m *mockTPM) IDevID() (crypto.PublicKey, error) {
	if m.idevidPubKeyErr != nil {
		return nil, m.idevidPubKeyErr
	}
	if m.idevidPubKey != nil {
		return m.idevidPubKey, nil
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return &key.PublicKey, nil
}
func (m *mockTPM) Quote(pcrs []uint, nonce []byte) (xkmssdk.Quote, error) {
	return m.quoteResult, m.quoteErr
}
func (m *mockTPM) ReadPCRs(pcrList []uint) ([]xkmssdk.PCRBank, error) {
	return m.readPCRsResult, m.readPCRsErr
}
func (m *mockTPM) ExtendPCR(pcrIndex int, hashAlg string, data []byte) error { return m.extendPCRErr }
func (m *mockTPM) EventLog() ([]byte, error) {
	if m.eventLogErr != nil {
		return nil, m.eventLogErr
	}
	if m.eventLogData != nil {
		return m.eventLogData, nil
	}
	return []byte("test-event-log"), nil
}
func (m *mockTPM) ParsedEventLog() ([]xkmssdk.TPMEvent, error) {
	return m.parsedEvents, m.parsedEventsErr
}
func (m *mockTPM) SupportedAlgorithms() ([]string, error) { return m.supportedAlgs, m.supportedAlgsErr }
func (m *mockTPM) SupportedCommands() ([]string, error)   { return m.supportedCmds, m.supportedCmdsErr }
func (m *mockTPM) SupportedECCCurves() ([]string, error) {
	return m.supportedCurves, m.supportedCurvesErr
}
func (m *mockTPM) RandomBytes(n int) ([]byte, error) {
	if m.randomBytesErr != nil {
		return nil, m.randomBytesErr
	}
	if m.randomBytesResult != nil {
		return m.randomBytesResult, nil
	}
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b, nil
}
func (m *mockTPM) Seal(ctx context.Context, data []byte, opts *xkmssdk.SealOptions) (*xkmssdk.SealedData, error) {
	if m.sealErr != nil {
		return nil, m.sealErr
	}
	if m.sealResult != nil {
		return m.sealResult, nil
	}
	return &xkmssdk.SealedData{Ciphertext: data}, nil
}
func (m *mockTPM) Unseal(ctx context.Context, sealed *xkmssdk.SealedData, opts *xkmssdk.UnsealOptions) ([]byte, error) {
	if m.unsealErr != nil {
		return nil, m.unsealErr
	}
	return m.unsealResult, nil
}
func (m *mockTPM) Device() string                       { return m.deviceResult }
func (m *mockTPM) IsFIPS140_2() (bool, error)           { return m.isFIPSResult, m.isFIPSErr }
func (m *mockTPM) IsPlatformPCRExtended() (bool, error) { return m.isPCRExtResult, m.isPCRExtErr }
func (m *mockTPM) CanSeal() bool                        { return m.canSealResult }
func (m *mockTPM) CreateTCG_CSR_IDEVID(ekCert *x509.Certificate, akAttrs *xkmssdk.KeyAttributes, idevidAttrs *xkmssdk.KeyAttributes) (xkmssdk.TCG_CSR_IDEVID, error) {
	return xkmssdk.TCG_CSR_IDEVID{}, nil
}

// =============================================================================
// Tests: Constructor and Dispatch
// =============================================================================

func TestNewTPM2Handler(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	require.NotNil(t, h)
	assert.NotNil(t, h.handlers)
	assert.Len(t, h.handlers, 31)
	assert.Nil(t, h.tpm)
}

func TestTPM2Handler_SetTPM2Service(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	assert.NotNil(t, h.tpm)
}

func TestTPM2Handler_HandleMessage_NilRequest(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), nil)
	require.NotNil(t, resp)
	assert.Equal(t, StatusInvalidRequest, resp.Status)
}

func TestTPM2Handler_HandleMessage_NilTPM(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{SubOpTPM2Info}})
	require.NotNil(t, resp)
	assert.Equal(t, StatusUnavailable, resp.Status)
}

func TestTPM2Handler_HandleMessage_EmptyPayload(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{}})
	require.NotNil(t, resp)
	assert.Equal(t, StatusInvalidRequest, resp.Status)
}

func TestTPM2Handler_HandleMessage_UnknownSubOpcode(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{0xFF}})
	require.NotNil(t, resp)
	assert.Equal(t, StatusNotImplemented, resp.Status)
}

// =============================================================================
// Tests: Handler Methods
// =============================================================================

func TestTPM2Handler_HandleInfo_Success(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{SubOpTPM2Info}})
	require.NotNil(t, resp)
	assert.Equal(t, StatusOK, resp.Status)
	var infoResp TPM2InfoResponse
	require.NoError(t, DecodePayload(resp.Payload, &infoResp))
	assert.Equal(t, "mock-tpm-info", infoResp.Info)
	assert.Equal(t, "TEST-MFR", infoResp.Manufacturer)
	assert.True(t, infoResp.IsSimulator)
}

func TestTPM2Handler_HandleInfo_Error(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.infoErr = errors.New("tpm not available")
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{SubOpTPM2Info}})
	assert.NotEqual(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleInfo_NoProperties(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.fixedPropsErr = errors.New("n/a")
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{SubOpTPM2Info}})
	assert.Equal(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleInfo_NilConfig(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.config = nil
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{SubOpTPM2Info}})
	assert.Equal(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleProvision_Success(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{SubOpTPM2Provision}})
	assert.Equal(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleProvision_WithPassword(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	req := TPM2ProvisionRequest{OwnerPassword: "test-pw"}
	payload, _ := EncodePayload(req)
	resp := h.HandleMessage(context.Background(), &Request{Payload: append([]byte{SubOpTPM2Provision}, payload...)})
	assert.Equal(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleProvision_Error(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.provisionOwnerErr = errors.New("failed")
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{SubOpTPM2Provision}})
	assert.NotEqual(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleClear_Success(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{SubOpTPM2Clear}})
	assert.Equal(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleClear_Error(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.clearErr = errors.New("authorization denied")
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{SubOpTPM2Clear}})
	assert.NotEqual(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleGetEK_Success(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{SubOpTPM2GetEK}})
	assert.Equal(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleGetEK_Error(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.ekAttrsErr = errors.New("EK not found")
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{SubOpTPM2GetEK}})
	assert.Equal(t, StatusNotFound, resp.Status)
}

func TestTPM2Handler_HandleCreateEK_Success(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{SubOpTPM2CreateEK}})
	assert.Equal(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleCreateEK_Error(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.createEKErr = errors.New("already exists")
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{SubOpTPM2CreateEK}})
	assert.Equal(t, StatusAlreadyExists, resp.Status)
}

func TestTPM2Handler_HandleDeleteEK(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{SubOpTPM2DeleteEK}})
	assert.Equal(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleGetEKCert_Success(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{SubOpTPM2GetEKCert}})
	assert.Equal(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleGetEKCert_Error(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.ekCertErr = errors.New("not found")
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{SubOpTPM2GetEKCert}})
	assert.NotEqual(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleImportEKCert_MissingData(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{SubOpTPM2ImportEKCert}})
	assert.Equal(t, StatusInvalidArgument, resp.Status)
}

func TestTPM2Handler_HandleImportEKCert_Success(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	req := &TPM2ImportEKCertRequest{Certificate: []byte("test-cert")}
	payload, _ := EncodePayload(req)
	resp := h.HandleMessage(context.Background(), &Request{Payload: append([]byte{SubOpTPM2ImportEKCert}, payload...)})
	assert.Equal(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleGetSRK(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{SubOpTPM2GetSRK}})
	assert.Equal(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleCreateSRK(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{SubOpTPM2CreateSRK}})
	assert.Equal(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleDeleteSRK(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{SubOpTPM2DeleteSRK}})
	assert.Equal(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleGetIAK(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{SubOpTPM2GetIAK}})
	assert.Equal(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleCreateIAK_Success(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.createIAKAttrs = &xkmssdk.KeyAttributes{
		CN: "new-iak",
		TPMAttributes: &xkmssdk.TPMAttributes{
			Handle: 0x81020001,
		},
	}
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{SubOpTPM2CreateIAK}})
	assert.Equal(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleDeleteIAK(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{SubOpTPM2DeleteIAK}})
	assert.Equal(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleQuote_Success(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.quoteResult = xkmssdk.Quote{Quoted: []byte("quoted"), Signature: []byte("sig")}
	h.SetTPM2Service(mock)
	req := &TPM2QuoteRequest{PCRIndices: []uint32{0, 1, 7}, Nonce: []byte("nonce")}
	payload, _ := EncodePayload(req)
	resp := h.HandleMessage(context.Background(), &Request{Payload: append([]byte{SubOpTPM2Quote}, payload...)})
	assert.Equal(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleQuote_Error(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.quoteErr = errors.New("failed")
	h.SetTPM2Service(mock)
	req := &TPM2QuoteRequest{PCRIndices: []uint32{0}}
	payload, _ := EncodePayload(req)
	resp := h.HandleMessage(context.Background(), &Request{Payload: append([]byte{SubOpTPM2Quote}, payload...)})
	assert.NotEqual(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleReadPCRs_Success(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	req := &TPM2ReadPCRsRequest{Indices: []uint32{0, 1, 7}}
	payload, _ := EncodePayload(req)
	resp := h.HandleMessage(context.Background(), &Request{Payload: append([]byte{SubOpTPM2ReadPCRs}, payload...)})
	assert.Equal(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleReadPCRs_Default(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{SubOpTPM2ReadPCRs}})
	assert.Equal(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleExtendPCR_Success(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	req := &TPM2ExtendPCRRequest{PCRIndex: 14, HashAlg: "sha256", Data: []byte("data")}
	payload, _ := EncodePayload(req)
	resp := h.HandleMessage(context.Background(), &Request{Payload: append([]byte{SubOpTPM2ExtendPCR}, payload...)})
	assert.Equal(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleExtendPCR_InvalidIndex(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	req := &TPM2ExtendPCRRequest{PCRIndex: 25, HashAlg: "sha256", Data: []byte("data")}
	payload, _ := EncodePayload(req)
	resp := h.HandleMessage(context.Background(), &Request{Payload: append([]byte{SubOpTPM2ExtendPCR}, payload...)})
	assert.Equal(t, StatusInvalidArgument, resp.Status)
}

func TestTPM2Handler_HandleExtendPCR_MissingData(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	req := &TPM2ExtendPCRRequest{PCRIndex: 14, HashAlg: "sha256"}
	payload, _ := EncodePayload(req)
	resp := h.HandleMessage(context.Background(), &Request{Payload: append([]byte{SubOpTPM2ExtendPCR}, payload...)})
	assert.Equal(t, StatusInvalidArgument, resp.Status)
}

func TestTPM2Handler_HandleEventLog(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{SubOpTPM2EventLog}})
	assert.Equal(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleRandom_Success(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{SubOpTPM2Random}})
	assert.Equal(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleRandom_TooManyBytes(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	req := &TPM2RandomRequest{NumBytes: 2048}
	payload, _ := EncodePayload(req)
	resp := h.HandleMessage(context.Background(), &Request{Payload: append([]byte{SubOpTPM2Random}, payload...)})
	assert.Equal(t, StatusInvalidArgument, resp.Status)
}

func TestTPM2Handler_HandleSeal_Success(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	req := &TPM2SealRequest{Data: []byte("secret")}
	payload, _ := EncodePayload(req)
	resp := h.HandleMessage(context.Background(), &Request{Payload: append([]byte{SubOpTPM2Seal}, payload...)})
	assert.Equal(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleSeal_MissingData(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	req := &TPM2SealRequest{}
	payload, _ := EncodePayload(req)
	resp := h.HandleMessage(context.Background(), &Request{Payload: append([]byte{SubOpTPM2Seal}, payload...)})
	assert.Equal(t, StatusInvalidArgument, resp.Status)
}

func TestTPM2Handler_HandleUnseal_Success(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.unsealResult = []byte("plaintext")
	h.SetTPM2Service(mock)
	req := &TPM2UnsealRequest{CN: "test-key"}
	payload, _ := EncodePayload(req)
	resp := h.HandleMessage(context.Background(), &Request{Payload: append([]byte{SubOpTPM2Unseal}, payload...)})
	assert.Equal(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleUnseal_MissingCN(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	req := &TPM2UnsealRequest{}
	payload, _ := EncodePayload(req)
	resp := h.HandleMessage(context.Background(), &Request{Payload: append([]byte{SubOpTPM2Unseal}, payload...)})
	assert.Equal(t, StatusInvalidArgument, resp.Status)
}

func TestTPM2Handler_HandleCapabilities_Success(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{SubOpTPM2Capabilities}})
	assert.Equal(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleCapabilities_Errors(t *testing.T) {
	for _, tc := range []struct {
		name string
		fn   func(m *mockTPM)
	}{
		{"AlgErr", func(m *mockTPM) { m.supportedAlgsErr = errors.New("err") }},
		{"CmdErr", func(m *mockTPM) { m.supportedCmdsErr = errors.New("err") }},
		{"CurveErr", func(m *mockTPM) { m.supportedCurvesErr = errors.New("err") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := NewTPM2Handler(logging.DefaultLogger())
			mock := newMockTPM()
			tc.fn(mock)
			h.SetTPM2Service(mock)
			resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{SubOpTPM2Capabilities}})
			assert.NotEqual(t, StatusOK, resp.Status)
		})
	}
}

func TestTPM2Handler_HandleNVOps(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	for _, op := range []byte{SubOpTPM2NVRead, SubOpTPM2NVWrite, SubOpTPM2NVDelete, SubOpTPM2NVList} {
		resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{op}})
		assert.Equal(t, StatusNotImplemented, resp.Status)
	}
}

func TestTPM2Handler_HandlePlatformAttributes_Success(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{SubOpTPM2PlatformAttrs}})
	assert.Equal(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandlePlatformAttributes_ErrorPaths(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.isFIPSErr = errors.New("n/a")
	mock.isPCRExtErr = errors.New("n/a")
	mock.config = nil
	mock.fixedPropsErr = errors.New("n/a")
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{SubOpTPM2PlatformAttrs}})
	assert.Equal(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleGetIDevID_Success(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubBytes, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	mock := newMockTPM()
	mock.idevidAttrs = &xkmssdk.KeyAttributes{
		CN: "test-idevid", KeyAlgorithm: x509.ECDSA,
		TPMAttributes: &xkmssdk.TPMAttributes{Handle: 0x81030000, PublicKeyBytes: pubBytes},
	}
	mock.idevidPubKey = &key.PublicKey
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{SubOpTPM2GetIDevID}})
	assert.Equal(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleGetIDevID_AttrsError(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.idevidAttrsErr = errors.New("IDevID not found")
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{SubOpTPM2GetIDevID}})
	assert.Equal(t, StatusNotFound, resp.Status)
}

func TestTPM2Handler_HandleVerifyQuote(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{SubOpTPM2VerifyQuote}})
	assert.Equal(t, StatusNotImplemented, resp.Status)
}

func TestTPM2Handler_HandleCreateIDevIDCSR(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{SubOpTPM2IDevIDCSR}})
	assert.Equal(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleCreateIDevIDCSR_EKCertError(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.ekCertErr = errors.New("no EK certificate")
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{SubOpTPM2IDevIDCSR}})
	assert.NotEqual(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleCreateLDevIDCSR(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{SubOpTPM2LDevIDCSR}})
	assert.Equal(t, StatusOK, resp.Status)
}

// =============================================================================
// Error Type Tests
// =============================================================================

func TestErrTPM2EncodingFailed(t *testing.T) {
	cause := errors.New("codec error")
	err := ErrTPM2EncodingFailed{Cause: cause}
	assert.Contains(t, err.Error(), "failed to encode TPM2 payload")
	assert.Equal(t, cause, err.Unwrap())
}

func TestErrTPM2DecodingFailed(t *testing.T) {
	cause := errors.New("invalid data")
	err := ErrTPM2DecodingFailed{Cause: cause}
	assert.Contains(t, err.Error(), "failed to decode TPM2 payload")
	assert.Equal(t, cause, err.Unwrap())
}

func TestErrTPM2OperationFailed(t *testing.T) {
	cause := errors.New("tpm error")
	err := ErrTPM2OperationFailed{Operation: "Seal", Cause: cause}
	assert.Contains(t, err.Error(), "TPM2 operation Seal failed")
	assert.Equal(t, cause, err.Unwrap())
}

func TestErrTPM2UnknownSubOpcode(t *testing.T) {
	err := ErrTPM2UnknownSubOpcode{SubOpcode: 0xAB}
	assert.Contains(t, err.Error(), "0xAB")
}

// =============================================================================
// Helper Function Tests
// =============================================================================

func TestContainsAnyTPM(t *testing.T) {
	assert.True(t, containsAnyTPM("key not found", "not found"))
	assert.True(t, containsAnyTPM("Key NOT FOUND", "not found"))
	assert.False(t, containsAnyTPM("success", "error", "failed"))
	assert.False(t, containsAnyTPM("", "error"))
}

func TestTPMErrorResponse_StatusMapping(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	tests := []struct {
		errMsg     string
		wantStatus byte
	}{
		{"key not found", StatusNotFound},
		{"already exists", StatusAlreadyExists},
		{"invalid argument", StatusInvalidArgument},
		{"permission denied", StatusPermissionDenied},
		{"not implemented", StatusNotImplemented},
		{"service unavailable", StatusUnavailable},
		{"some error", StatusInternalError},
	}
	for _, tt := range tests {
		resp := h.tpmErrorResponse(errors.New(tt.errMsg))
		assert.Equal(t, tt.wantStatus, resp.Status, "for error: %s", tt.errMsg)
	}
}

// =============================================================================
// Decode Error Tests - cover invalid payload decode paths
// =============================================================================

func TestTPM2Handler_HandleProvision_DecodeError(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &Request{Payload: append([]byte{SubOpTPM2Provision}, []byte{0xFF, 0xFE}...)})
	assert.Equal(t, StatusInvalidRequest, resp.Status)
}

func TestTPM2Handler_HandleClear_DecodeError(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &Request{Payload: append([]byte{SubOpTPM2Clear}, []byte{0xFF, 0xFE}...)})
	assert.Equal(t, StatusInvalidRequest, resp.Status)
}

func TestTPM2Handler_HandleClear_WithPassword(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	req := TPM2ClearRequest{OwnerPassword: "test-pw"}
	payload, _ := EncodePayload(req)
	resp := h.HandleMessage(context.Background(), &Request{Payload: append([]byte{SubOpTPM2Clear}, payload...)})
	assert.Equal(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleQuote_DecodeError(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &Request{Payload: append([]byte{SubOpTPM2Quote}, []byte{0xFF, 0xFE}...)})
	assert.Equal(t, StatusInvalidRequest, resp.Status)
}

func TestTPM2Handler_HandleReadPCRs_DecodeError(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &Request{Payload: append([]byte{SubOpTPM2ReadPCRs}, []byte{0xFF, 0xFE}...)})
	assert.Equal(t, StatusInvalidRequest, resp.Status)
}

func TestTPM2Handler_HandleExtendPCR_DecodeError(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &Request{Payload: append([]byte{SubOpTPM2ExtendPCR}, []byte{0xFF, 0xFE}...)})
	assert.Equal(t, StatusInvalidRequest, resp.Status)
}

func TestTPM2Handler_HandleRandom_DecodeError(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &Request{Payload: append([]byte{SubOpTPM2Random}, []byte{0xFF, 0xFE}...)})
	assert.Equal(t, StatusInvalidRequest, resp.Status)
}

func TestTPM2Handler_HandleSeal_DecodeError(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &Request{Payload: append([]byte{SubOpTPM2Seal}, []byte{0xFF, 0xFE}...)})
	assert.Equal(t, StatusInvalidRequest, resp.Status)
}

func TestTPM2Handler_HandleUnseal_DecodeError(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &Request{Payload: append([]byte{SubOpTPM2Unseal}, []byte{0xFF, 0xFE}...)})
	assert.Equal(t, StatusInvalidRequest, resp.Status)
}

func TestTPM2Handler_HandleImportEKCert_DecodeError(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &Request{Payload: append([]byte{SubOpTPM2ImportEKCert}, []byte{0xFF, 0xFE}...)})
	assert.Equal(t, StatusInvalidRequest, resp.Status)
}

func TestTPM2Handler_HandleGetSRK_Error(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.ssrkAttrsErr = errors.New("SRK not found")
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{SubOpTPM2GetSRK}})
	assert.NotEqual(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleCreateSRK_Error(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.createSRKErr = errors.New("SRK already exists")
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{SubOpTPM2CreateSRK}})
	assert.NotEqual(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleGetIAK_Error(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.iakAttrsErr = errors.New("IAK not found")
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{SubOpTPM2GetIAK}})
	assert.NotEqual(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleGetIAK_PubKeyError(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.iakPubKeyErr = errors.New("key retrieval failed")
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{SubOpTPM2GetIAK}})
	assert.NotEqual(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleCreateIAK_Error(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.createIAKErr = errors.New("creation failed")
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{SubOpTPM2CreateIAK}})
	assert.NotEqual(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleExtendPCR_TPMError(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.extendPCRErr = errors.New("PCR extend failed")
	h.SetTPM2Service(mock)
	req := &TPM2ExtendPCRRequest{PCRIndex: 14, HashAlg: "sha256", Data: []byte("data")}
	payload, _ := EncodePayload(req)
	resp := h.HandleMessage(context.Background(), &Request{Payload: append([]byte{SubOpTPM2ExtendPCR}, payload...)})
	assert.NotEqual(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleRandom_TPMError(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.randomBytesErr = errors.New("RNG failed")
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{SubOpTPM2Random}})
	assert.NotEqual(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleSeal_TPMError(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.sealErr = errors.New("seal failed")
	h.SetTPM2Service(mock)
	req := &TPM2SealRequest{Data: []byte("secret")}
	payload, _ := EncodePayload(req)
	resp := h.HandleMessage(context.Background(), &Request{Payload: append([]byte{SubOpTPM2Seal}, payload...)})
	assert.NotEqual(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleUnseal_TPMError(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.unsealErr = errors.New("unseal failed")
	h.SetTPM2Service(mock)
	req := &TPM2UnsealRequest{CN: "test-key"}
	payload, _ := EncodePayload(req)
	resp := h.HandleMessage(context.Background(), &Request{Payload: append([]byte{SubOpTPM2Unseal}, payload...)})
	assert.NotEqual(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleEventLog_Error(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.eventLogErr = errors.New("event log unavailable")
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{SubOpTPM2EventLog}})
	assert.NotEqual(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleReadPCRs_Error(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.readPCRsErr = errors.New("PCR read failed")
	h.SetTPM2Service(mock)
	req := &TPM2ReadPCRsRequest{Indices: []uint32{0}}
	payload, _ := EncodePayload(req)
	resp := h.HandleMessage(context.Background(), &Request{Payload: append([]byte{SubOpTPM2ReadPCRs}, payload...)})
	assert.NotEqual(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleGetIDevID_PubKeyError(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.idevidPubKeyErr = errors.New("key not available")
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{SubOpTPM2GetIDevID}})
	assert.NotEqual(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleCreateIDevIDCSR_IAKError(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.iakAttrsErr = errors.New("IAK not found")
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{SubOpTPM2IDevIDCSR}})
	assert.NotEqual(t, StatusOK, resp.Status)
}

func TestTPM2Handler_HandleCreateIDevIDCSR_IDevIDError(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.idevidAttrsErr = errors.New("IDevID not found")
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &Request{Payload: []byte{SubOpTPM2IDevIDCSR}})
	assert.NotEqual(t, StatusOK, resp.Status)
}
