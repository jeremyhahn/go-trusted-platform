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
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockTPM implements xkmssdk.TrustedPlatformModule for handler tests.
type mockTPM struct {
	xkmssdk.TrustedPlatformModule

	// transport is nil in unit tests; integration tests against
	// swtpm / hardware supply a live transport for the NV round-trip.
	transport transport.TPM

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
	ekPersisted        bool
	createdEK          *xkmssdk.KeyAttributes
	ekCert             *x509.Certificate
	ekCertErr          error
	provisionEKCertErr error
	ssrkAttrs          *xkmssdk.KeyAttributes
	psrkAttrs          *xkmssdk.KeyAttributes
	psrkAttrsErr       error
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
	quoted             []byte
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
		config:        &xkmssdk.TPMConfig{UseSimulator: true, EK: &xkmssdk.EKConfig{Handle: 0x81010001}},
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
				Template:       tpm2.RSAEKTemplate,
			},
		},
		ssrkAttrs: &xkmssdk.KeyAttributes{
			CN: "test-srk",
			TPMAttributes: &xkmssdk.TPMAttributes{
				Handle:         0x81000001,
				PublicKeyBytes: []byte("ssrk-public-key"),
			},
		},
		// Distinct in handle AND public key, so a test can tell a
		// resolved platform key from an ignored request answered with
		// the SSRK (#475).
		psrkAttrs: &xkmssdk.KeyAttributes{
			CN: "test-platform-srk",
			TPMAttributes: &xkmssdk.TPMAttributes{
				Handle:         0x81000002,
				PublicKeyBytes: []byte("platform-srk-public-key"),
			},
		},
		iakAttrs: &xkmssdk.KeyAttributes{
			CN:                 "test-iak",
			SignatureAlgorithm: x509.SHA256WithRSAPSS,
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

func (m *mockTPM) Transport() transport.TPM { return m.transport }

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
func (m *mockTPM) Clear(lockoutAuth []byte) error                { return m.clearErr }
func (m *mockTPM) EKAttributes() (*xkmssdk.KeyAttributes, error) { return m.ekAttrs, m.ekAttrsErr }

// CreateEK stamps the public key on success, as the backend does once the
// primary exists.
func (m *mockTPM) CreateEK(keyAttrs *xkmssdk.KeyAttributes) error {
	if m.createEKErr != nil {
		return m.createEKErr
	}
	keyAttrs.TPMAttributes.PublicKeyBytes = m.ekAttrs.TPMAttributes.PublicKeyBytes
	m.createdEK = keyAttrs
	return nil
}

// ReadHandle reports the EK handle occupied only when ekPersisted is set.
func (m *mockTPM) ReadHandle(tpm2.TPMHandle) (tpm2.TPM2BName, tpm2.TPMTPublic, error) {
	if m.ekPersisted {
		return tpm2.TPM2BName{}, tpm2.TPMTPublic{}, nil
	}
	return tpm2.TPM2BName{}, tpm2.TPMTPublic{}, tpm2.TPMRCHandle
}
func (m *mockTPM) Flush(handle tpm2.TPMHandle) {}
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
func (m *mockTPM) PlatformSRKAttributes() (*xkmssdk.KeyAttributes, error) {
	return m.psrkAttrs, m.psrkAttrsErr
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
	m.quoted = nonce
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
	// 34 sub-opcodes less SubOpTPM2DeleteIAK, which the daemon refuses.
	assert.Len(t, h.handlers, 33)
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
	assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
}

func TestTPM2Handler_HandleMessage_NilTPM(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2Info}})
	require.NotNil(t, resp)
	assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
}

func TestTPM2Handler_HandleMessage_EmptyPayload(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{}})
	require.NotNil(t, resp)
	assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
}

func TestTPM2Handler_HandleMessage_UnknownSubOpcode(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{0xFF}})
	require.NotNil(t, resp)
	assert.Equal(t, quicwire.StatusNotImplemented, resp.Status)
}

// =============================================================================
// Tests: Handler Methods
// =============================================================================

func TestTPM2Handler_HandleInfo_Success(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.readPCRsResult = []xkmssdk.PCRBank{{Algorithm: "SHA1"}, {Algorithm: "SHA256"}}
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2Info}})
	require.NotNil(t, resp)
	assert.Equal(t, quicwire.StatusOK, resp.Status)
	var infoResp TPM2InfoResponse
	require.NoError(t, quicwire.DecodePayload(resp.Payload, &infoResp))
	assert.Equal(t, "mock-tpm-info", infoResp.Info)
	assert.Equal(t, "TEST-MFR", infoResp.Manufacturer)
	assert.True(t, infoResp.IsSimulator)
	assert.Equal(t, "2.0", infoResp.Version)
	assert.Equal(t, []string{"sha1", "sha256"}, infoResp.PCRBanks)
}

func TestTPM2Handler_HandleInfo_Error(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.infoErr = errors.New("tpm not available")
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2Info}})
	assert.NotEqual(t, quicwire.StatusOK, resp.Status)
}

func TestTPM2Handler_HandleInfo_NoProperties(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.fixedPropsErr = errors.New("n/a")
	mock.readPCRsResult = []xkmssdk.PCRBank{{Algorithm: "SHA256"}}
	mock.readPCRsErr = errors.New("n/a")
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2Info}})
	require.Equal(t, quicwire.StatusOK, resp.Status)
	var infoResp TPM2InfoResponse
	require.NoError(t, quicwire.DecodePayload(resp.Payload, &infoResp))
	assert.Empty(t, infoResp.PCRBanks, "a refused PCR read leaves the banks empty and fails nothing")
}

func TestTPM2Handler_HandleInfo_NilConfig(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.config = nil
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2Info}})
	assert.Equal(t, quicwire.StatusOK, resp.Status)
}

func TestTPM2Handler_HandleInfo_PublishesConfiguredSRKHandles(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.config = &xkmssdk.TPMConfig{
		PlatformSRK: &xkmssdk.PlatformSRKConfig{SRKHandle: 0x81000005},
		SSRK:        &xkmssdk.SRKConfig{Handle: 0x81000007},
	}
	h.SetTPM2Service(mock)

	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2Info}})

	require.Equal(t, quicwire.StatusOK, resp.Status)
	var infoResp TPM2InfoResponse
	require.NoError(t, quicwire.DecodePayload(resp.Payload, &infoResp))
	assert.Equal(t, "0x81000005", infoResp.Properties["platform_srk_handle"])
	assert.Equal(t, "0x81000007", infoResp.Properties["ssrk_handle"])
	assert.Equal(t, "mock-tpm-info", infoResp.Properties["info"])
}

func TestTPM2Handler_HandleInfo_PublishesDefaultSRKHandlesWithNilConfig(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.config = nil
	h.SetTPM2Service(mock)

	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2Info}})

	require.Equal(t, quicwire.StatusOK, resp.Status)
	var infoResp TPM2InfoResponse
	require.NoError(t, quicwire.DecodePayload(resp.Payload, &infoResp))
	assert.Equal(t, "0x81000002", infoResp.Properties["platform_srk_handle"])
	assert.Equal(t, "0x81000001", infoResp.Properties["ssrk_handle"])
}

func TestTPM2Handler_HandleProvision_Success(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2Provision}})
	assert.Equal(t, quicwire.StatusOK, resp.Status)
}

func TestTPM2Handler_HandleProvision_WithPassword(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	req := TPM2ProvisionRequest{OwnerPassword: "test-pw"}
	payload, _ := quicwire.EncodePayload(req)
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: append([]byte{quicwire.SubOpTPM2Provision}, payload...)})
	assert.Equal(t, quicwire.StatusOK, resp.Status)
}

func TestTPM2Handler_HandleProvision_Error(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.provisionOwnerErr = errors.New("failed")
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2Provision}})
	assert.NotEqual(t, quicwire.StatusOK, resp.Status)
}

func TestTPM2Handler_HandleClear_Success(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2Clear}})
	assert.Equal(t, quicwire.StatusOK, resp.Status)
}

func TestTPM2Handler_HandleClear_Error(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.clearErr = errors.New("authorization denied")
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2Clear}})
	assert.NotEqual(t, quicwire.StatusOK, resp.Status)
}

func TestTPM2Handler_HandleGetEK_Success(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2GetEK}})
	assert.Equal(t, quicwire.StatusOK, resp.Status)
}

func TestTPM2Handler_HandleGetEK_Error(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.ekAttrsErr = errors.New("EK not found")
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2GetEK}})
	assert.Equal(t, quicwire.StatusNotFound, resp.Status)
}

func TestTPM2Handler_HandleCreateEK_Success(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2CreateEK}})
	require.Equal(t, quicwire.StatusOK, resp.Status)

	// The handle and public key match gRPC's CreateEKResponse.
	key := decodeKeyResponse(t, resp)
	assert.Equal(t, uint32(0x81010001), key.Handle)
	assert.Equal(t, []byte("test-ek-pub"), key.PublicKey)
	assert.Equal(t, "RSA", key.Algorithm)
}

func TestTPM2Handler_HandleCreateEK_Error(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.createEKErr = errors.New("already exists")
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2CreateEK}})
	assert.Equal(t, quicwire.StatusAlreadyExists, resp.Status)
}

func TestTPM2Handler_HandleCreateEK_PersistedEKIsAlreadyExists(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.ekPersisted = true
	mock.createEKErr = errors.New("CreateEK must not run on an occupied handle")
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2CreateEK}})
	assert.Equal(t, quicwire.StatusAlreadyExists, resp.Status)
}

// Sub-opcode 0x05 used to panic the server, and later refused, when the
// backend's cached EK attributes carried no template. CreateEK now builds
// the EK from tpm.ek, so the cached attributes no longer matter (#949).
func TestTPM2Handler_HandleCreateEK_BuildsTemplateFromConfig(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.ekAttrs.TPMAttributes.Template = tpm2.TPMTPublic{}
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2CreateEK}})
	require.Equal(t, quicwire.StatusOK, resp.Status)

	require.NotNil(t, mock.createdEK, "CreateEK reached the backend")
	assert.Equal(t, tpm2.RSAEKTemplate, mock.createdEK.TPMAttributes.Template)
	assert.Equal(t, xkmssdk.TPMHandle(0x81010001), mock.createdEK.TPMAttributes.Handle)
}

func TestTPM2Handler_HandleDeleteEK(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2DeleteEK}})
	assert.Equal(t, quicwire.StatusOK, resp.Status)
}

func TestTPM2Handler_HandleGetEKCert_Success(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2GetEKCert}})
	assert.Equal(t, quicwire.StatusOK, resp.Status)
}

func TestTPM2Handler_HandleGetEKCert_Error(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.ekCertErr = errors.New("not found")
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2GetEKCert}})
	assert.NotEqual(t, quicwire.StatusOK, resp.Status)
}

func TestTPM2Handler_HandleImportEKCert_MissingData(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2ImportEKCert}})
	assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
}

func TestTPM2Handler_HandleImportEKCert_Success(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	req := &TPM2ImportEKCertRequest{Certificate: []byte("test-cert")}
	payload, _ := quicwire.EncodePayload(req)
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: append([]byte{quicwire.SubOpTPM2ImportEKCert}, payload...)})
	assert.Equal(t, quicwire.StatusOK, resp.Status)
}

func TestTPM2Handler_HandleGetSRK(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2GetSRK}})
	assert.Equal(t, quicwire.StatusOK, resp.Status)
}

// newSSRKMockTPM is a mock whose tpm.ssrk names the Shared SRK handle and
// whose handles read back empty, as they do after TPM2_Clear.
func newSSRKMockTPM() *mockTPM {
	mock := newMockTPM()
	mock.config.SSRK = &xkmssdk.SRKConfig{Handle: 0x81000001}
	return mock
}

// CreateSRK answers with the key, so a client reads the handle the Shared
// SRK was persisted at.
func TestTPM2Handler_HandleCreateSRK(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newSSRKMockTPM())
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2CreateSRK}})
	require.Equal(t, quicwire.StatusOK, resp.Status)
	key := decodeKeyResponse(t, resp)
	assert.Equal(t, uint32(0x81000001), key.Handle)
	assert.Equal(t, x509.RSA.String(), key.Algorithm)
}

func TestTPM2Handler_HandleDeleteSRK(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2DeleteSRK}})
	assert.Equal(t, quicwire.StatusOK, resp.Status)
}

func TestTPM2Handler_HandleGetIAK(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2GetIAK}})
	assert.Equal(t, quicwire.StatusOK, resp.Status)
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
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2CreateIAK}})
	assert.Equal(t, quicwire.StatusOK, resp.Status)
}

// The IAK delete is refused by the daemon dispatcher before it reaches this
// handler; the handler itself must not serve it, so it cannot flush the key.
func TestTPM2Handler_DeleteIAKNotServed(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2DeleteIAK}})
	assert.Equal(t, quicwire.StatusNotImplemented, resp.Status)
}

func TestTPM2Handler_HandleQuote_Success(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.quoteResult = xkmssdk.Quote{Quoted: []byte("quoted"), Signature: []byte("sig")}
	h.SetTPM2Service(mock)
	req := &quicwire.TPM2QuoteRequest{PCRIndices: []uint32{0, 1, 7}, Nonce: []byte("nonce")}
	payload, _ := quicwire.EncodePayload(req)
	state := testutil.ServerConnectionState(t)
	resp := h.HandleMessage(WithConnectionTLS(context.Background(), state), &quicwire.Request{Payload: append([]byte{quicwire.SubOpTPM2Quote}, payload...)})
	require.Equal(t, quicwire.StatusOK, resp.Status)

	// The TPM quoted SHA-256(nonce || binding) for this connection, and the
	// response echoes that binding so the caller can check it.
	var out quicwire.TPM2QuoteResponse
	require.NoError(t, quicwire.DecodePayload(resp.Payload, &out))
	binding, err := xkmssdk.PeerChannelBinding(state)
	require.NoError(t, err)
	assert.Equal(t, binding, out.ChannelBinding)
	assert.Equal(t, xkmssdk.PeerQualifyingData([]byte("nonce"), binding), mock.quoted)
	assert.Equal(t, x509.SHA256WithRSAPSS.String(), out.SignatureAlgorithm,
		"the response names the scheme the IAK signed under")
}

func TestTPM2Handler_HandleQuote_RefusesAnIAKWithoutAScheme(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.iakAttrs.SignatureAlgorithm = x509.UnknownSignatureAlgorithm
	h.SetTPM2Service(mock)
	payload, err := quicwire.EncodePayload(&quicwire.TPM2QuoteRequest{PCRIndices: []uint32{0}, Nonce: []byte("nonce")})
	require.NoError(t, err)
	ctx := WithConnectionTLS(context.Background(), testutil.ServerConnectionState(t))
	resp := h.HandleMessage(ctx, &quicwire.Request{Payload: append([]byte{quicwire.SubOpTPM2Quote}, payload...)})
	assert.NotEqual(t, quicwire.StatusOK, resp.Status)
	assert.Nil(t, mock.quoted, "a quote nobody could verify was never taken")
}

func TestTPM2Handler_HandleQuote_RefusesAConnectionItCannotBind(t *testing.T) {
	for name, ctx := range map[string]context.Context{
		"no TLS state": context.Background(),
		"TLS 1.2":      WithConnectionTLS(context.Background(), &tls.ConnectionState{Version: tls.VersionTLS12}),
	} {
		t.Run(name, func(t *testing.T) {
			h := NewTPM2Handler(logging.DefaultLogger())
			mock := newMockTPM()
			h.SetTPM2Service(mock)
			payload, err := quicwire.EncodePayload(&quicwire.TPM2QuoteRequest{PCRIndices: []uint32{0}, Nonce: []byte("nonce")})
			require.NoError(t, err)
			resp := h.HandleMessage(ctx, &quicwire.Request{Payload: append([]byte{quicwire.SubOpTPM2Quote}, payload...)})
			assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
			assert.Nil(t, mock.quoted, "nothing may be quoted unbound")
		})
	}
}

func TestTPM2Handler_HandleQuote_Error(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.quoteErr = errors.New("failed")
	h.SetTPM2Service(mock)
	req := &quicwire.TPM2QuoteRequest{PCRIndices: []uint32{0}}
	payload, _ := quicwire.EncodePayload(req)
	ctx := WithConnectionTLS(context.Background(), testutil.ServerConnectionState(t))
	resp := h.HandleMessage(ctx, &quicwire.Request{Payload: append([]byte{quicwire.SubOpTPM2Quote}, payload...)})
	assert.NotEqual(t, quicwire.StatusOK, resp.Status)
}

func TestTPM2Handler_HandleReadPCRs_Success(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	req := &TPM2ReadPCRsRequest{Indices: []uint32{0, 1, 7}}
	payload, _ := quicwire.EncodePayload(req)
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: append([]byte{quicwire.SubOpTPM2ReadPCRs}, payload...)})
	assert.Equal(t, quicwire.StatusOK, resp.Status)
}

func TestTPM2Handler_HandleReadPCRs_Default(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2ReadPCRs}})
	assert.Equal(t, quicwire.StatusOK, resp.Status)
}

func TestTPM2Handler_HandleExtendPCR_Success(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	req := &TPM2ExtendPCRRequest{PCRIndex: 14, HashAlg: "sha256", Data: []byte("data")}
	payload, _ := quicwire.EncodePayload(req)
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: append([]byte{quicwire.SubOpTPM2ExtendPCR}, payload...)})
	assert.Equal(t, quicwire.StatusOK, resp.Status)
}

func TestTPM2Handler_HandleExtendPCR_InvalidIndex(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	req := &TPM2ExtendPCRRequest{PCRIndex: 25, HashAlg: "sha256", Data: []byte("data")}
	payload, _ := quicwire.EncodePayload(req)
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: append([]byte{quicwire.SubOpTPM2ExtendPCR}, payload...)})
	assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
}

func TestTPM2Handler_HandleExtendPCR_MissingData(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	req := &TPM2ExtendPCRRequest{PCRIndex: 14, HashAlg: "sha256"}
	payload, _ := quicwire.EncodePayload(req)
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: append([]byte{quicwire.SubOpTPM2ExtendPCR}, payload...)})
	assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
}

func TestTPM2Handler_HandleEventLog(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2EventLog}})
	assert.Equal(t, quicwire.StatusOK, resp.Status)
}

func TestTPM2Handler_HandleRandom_Success(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2Random}})
	assert.Equal(t, quicwire.StatusOK, resp.Status)
}

func TestTPM2Handler_HandleRandom_TooManyBytes(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	req := &TPM2RandomRequest{NumBytes: 2048}
	payload, _ := quicwire.EncodePayload(req)
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: append([]byte{quicwire.SubOpTPM2Random}, payload...)})
	assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
}

func TestTPM2Handler_HandleSeal_Success(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	req := &TPM2SealRequest{Data: []byte("secret")}
	payload, _ := quicwire.EncodePayload(req)
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: append([]byte{quicwire.SubOpTPM2Seal}, payload...)})
	assert.Equal(t, quicwire.StatusOK, resp.Status)
}

func TestTPM2Handler_HandleSeal_MissingData(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	req := &TPM2SealRequest{}
	payload, _ := quicwire.EncodePayload(req)
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: append([]byte{quicwire.SubOpTPM2Seal}, payload...)})
	assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
}

func TestTPM2Handler_HandleUnseal_Success(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.unsealResult = []byte("plaintext")
	h.SetTPM2Service(mock)
	req := &TPM2UnsealRequest{CN: "test-key"}
	payload, _ := quicwire.EncodePayload(req)
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: append([]byte{quicwire.SubOpTPM2Unseal}, payload...)})
	assert.Equal(t, quicwire.StatusOK, resp.Status)
}

func TestTPM2Handler_HandleUnseal_MissingCN(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	req := &TPM2UnsealRequest{}
	payload, _ := quicwire.EncodePayload(req)
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: append([]byte{quicwire.SubOpTPM2Unseal}, payload...)})
	assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
}

func TestTPM2Handler_HandleCapabilities_Success(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())

	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2Capabilities}})

	require.Equal(t, quicwire.StatusOK, resp.Status)
	var out TPM2CapabilitiesResponse
	require.NoError(t, quicwire.DecodePayload(resp.Payload, &out))
	assert.Equal(t, []string{"RSA", "ECDSA", "SHA256"}, out.Algorithms)
	assert.Equal(t, []string{"TPM2_Create", "TPM2_Sign"}, out.Commands)
	assert.Equal(t, []string{"P256", "P384"}, out.ECCCurves)
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
			resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2Capabilities}})
			assert.NotEqual(t, quicwire.StatusOK, resp.Status)
		})
	}
}

func TestTPM2Handler_HandleNVList_Success(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2NVList}})
	assert.Equal(t, quicwire.StatusOK, resp.Status)

	var out TPM2NVListResponse
	require.NoError(t, quicwire.DecodePayload(resp.Payload, &out))
}

func TestTPM2Handler_HandleNVList_Error(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.fixedPropsErr = errors.New("cap read failed")
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2NVList}})
	assert.NotEqual(t, quicwire.StatusOK, resp.Status)
}

func TestTPM2Handler_HandleNVRead_MissingIndex(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	body, err := quicwire.EncodePayload(&TPM2NVReadRequest{Index: 0})
	require.NoError(t, err)
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: append([]byte{quicwire.SubOpTPM2NVRead}, body...)})
	assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
}

func TestTPM2Handler_HandleNVRead_TransportUnavailable(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM()) // nil transport
	body, err := quicwire.EncodePayload(&TPM2NVReadRequest{Index: 0x01500001, Size: 32})
	require.NoError(t, err)
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: append([]byte{quicwire.SubOpTPM2NVRead}, body...)})
	assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
}

func TestTPM2Handler_HandleNVWrite_Validation(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())

	// missing index
	body, err := quicwire.EncodePayload(&TPM2NVWriteRequest{Index: 0, Data: []byte("x")})
	require.NoError(t, err)
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: append([]byte{quicwire.SubOpTPM2NVWrite}, body...)})
	assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)

	// missing data
	body, err = quicwire.EncodePayload(&TPM2NVWriteRequest{Index: 0x01500001})
	require.NoError(t, err)
	resp = h.HandleMessage(context.Background(), &quicwire.Request{Payload: append([]byte{quicwire.SubOpTPM2NVWrite}, body...)})
	assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)

	// valid request, nil transport
	body, err = quicwire.EncodePayload(&TPM2NVWriteRequest{Index: 0x01500001, Data: []byte("payload")})
	require.NoError(t, err)
	resp = h.HandleMessage(context.Background(), &quicwire.Request{Payload: append([]byte{quicwire.SubOpTPM2NVWrite}, body...)})
	assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
}

func TestTPM2Handler_HandleNVDelete_Validation(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())

	body, err := quicwire.EncodePayload(&TPM2NVDeleteRequest{Index: 0})
	require.NoError(t, err)
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: append([]byte{quicwire.SubOpTPM2NVDelete}, body...)})
	assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)

	body, err = quicwire.EncodePayload(&TPM2NVDeleteRequest{Index: 0x01500001})
	require.NoError(t, err)
	resp = h.HandleMessage(context.Background(), &quicwire.Request{Payload: append([]byte{quicwire.SubOpTPM2NVDelete}, body...)})
	assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
}

func TestTPM2Handler_HandleVerifyQuote_Validation(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())

	// missing quote
	body, err := quicwire.EncodePayload(&quicwire.TPM2VerifyQuoteRequest{Signature: []byte("sig")})
	require.NoError(t, err)
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: append([]byte{quicwire.SubOpTPM2VerifyQuote}, body...)})
	assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)

	// missing signature
	body, err = quicwire.EncodePayload(&quicwire.TPM2VerifyQuoteRequest{Quote: []byte("quote")})
	require.NoError(t, err)
	resp = h.HandleMessage(context.Background(), &quicwire.Request{Payload: append([]byte{quicwire.SubOpTPM2VerifyQuote}, body...)})
	assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
}

func TestTPM2Handler_HandleVerifyQuote_BadSignature(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM()) // IAK() returns a valid ECDSA key
	body, err := quicwire.EncodePayload(&quicwire.TPM2VerifyQuoteRequest{
		Quote:     []byte("not-a-real-attest"),
		Signature: []byte("garbage-signature"),
	})
	require.NoError(t, err)
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: append([]byte{quicwire.SubOpTPM2VerifyQuote}, body...)})
	// Verification failure is a successful RPC with verified=false.
	assert.Equal(t, quicwire.StatusOK, resp.Status)
	var out quicwire.TPM2VerifyQuoteResponse
	require.NoError(t, quicwire.DecodePayload(resp.Payload, &out))
	assert.False(t, out.Verified)
}

func TestTPM2Handler_HandleVerifyQuote_DeclaredScheme(t *testing.T) {
	quote := []byte("quoted-attest")
	signature, akPublic := testutil.SignPSSQuote(t, quote)
	verify := func(t *testing.T, scheme string) quicwire.TPM2VerifyQuoteResponse {
		t.Helper()
		h := NewTPM2Handler(logging.DefaultLogger())
		h.SetTPM2Service(newMockTPM())
		body, err := quicwire.EncodePayload(&quicwire.TPM2VerifyQuoteRequest{
			Quote:              quote,
			Signature:          signature,
			AKPublic:           akPublic,
			SignatureAlgorithm: scheme,
		})
		require.NoError(t, err)
		resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: append([]byte{quicwire.SubOpTPM2VerifyQuote}, body...)})
		require.Equal(t, quicwire.StatusOK, resp.Status)
		var out quicwire.TPM2VerifyQuoteResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &out))
		return out
	}

	t.Run("an RSA-PSS quote verifies under the scheme it declares", func(t *testing.T) {
		out := verify(t, testutil.PSSQuoteScheme)
		assert.True(t, out.Verified, out.Message)
	})
	t.Run("no scheme or the wrong one fails", func(t *testing.T) {
		for name, scheme := range map[string]string{
			"undeclared":    "",
			"PKCS#1 v1.5":   x509.SHA256WithRSA.String(),
			"ECDSA for RSA": x509.ECDSAWithSHA256.String(),
		} {
			t.Run(name, func(t *testing.T) {
				out := verify(t, scheme)
				assert.False(t, out.Verified)
				assert.Contains(t, out.Message, "signature_verification_failed")
			})
		}
	})
}

func TestTPM2Handler_HandleVerifyQuote_ChannelBinding(t *testing.T) {
	nonce := []byte("verify-nonce")
	binding := bytes.Repeat([]byte{0x5a}, 32)
	quote := tpm2.Marshal(tpm2.TPMSAttest{
		Magic:     tpm2.TPMGeneratedValue,
		Type:      tpm2.TPMSTAttestQuote,
		ExtraData: tpm2.TPM2BData{Buffer: xkmssdk.PeerQualifyingData(nonce, binding)},
		Attested:  tpm2.NewTPMUAttest(tpm2.TPMSTAttestQuote, &tpm2.TPMSQuoteInfo{}),
	})
	verify := func(t *testing.T, req quicwire.TPM2VerifyQuoteRequest) *quicwire.Response {
		t.Helper()
		h := NewTPM2Handler(logging.DefaultLogger())
		h.SetTPM2Service(newMockTPM())
		req.Quote = quote
		req.Signature = []byte("garbage-signature")
		body, err := quicwire.EncodePayload(&req)
		require.NoError(t, err)
		return h.HandleMessage(context.Background(), &quicwire.Request{Payload: append([]byte{quicwire.SubOpTPM2VerifyQuote}, body...)})
	}
	message := func(t *testing.T, resp *quicwire.Response) string {
		t.Helper()
		require.Equal(t, quicwire.StatusOK, resp.Status)
		var out quicwire.TPM2VerifyQuoteResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &out))
		assert.False(t, out.Verified)
		return out.Message
	}

	t.Run("the bound echo passes the nonce check", func(t *testing.T) {
		resp := verify(t, quicwire.TPM2VerifyQuoteRequest{Nonce: nonce, ChannelBinding: binding})
		assert.Contains(t, message(t, resp), "signature_verification_failed")
	})
	t.Run("the bare nonce does not", func(t *testing.T) {
		resp := verify(t, quicwire.TPM2VerifyQuoteRequest{Nonce: nonce})
		assert.Contains(t, message(t, resp), "nonce_verification_failed")
	})
	t.Run("a binding without a nonce is refused", func(t *testing.T) {
		resp := verify(t, quicwire.TPM2VerifyQuoteRequest{ChannelBinding: binding})
		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})
}

func TestTPM2Handler_HandlePlatformAttributes_Success(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.deviceResult = "/dev/tpmrm0"
	mock.ekAttrs = &xkmssdk.KeyAttributes{KeyAlgorithm: x509.RSA, TPMAttributes: &xkmssdk.TPMAttributes{Handle: 0x81010001}}
	mock.ssrkAttrs = &xkmssdk.KeyAttributes{KeyAlgorithm: x509.RSA, TPMAttributes: &xkmssdk.TPMAttributes{Handle: 0x81000001}}
	mock.iakAttrs = nil
	mock.iakAttrsErr = errors.New("IAK not provisioned")
	h.SetTPM2Service(mock)

	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2PlatformAttrs}})

	require.Equal(t, quicwire.StatusOK, resp.Status)
	var out TPM2PlatformAttributesResponse
	require.NoError(t, quicwire.DecodePayload(resp.Payload, &out))
	assert.Equal(t, "/dev/tpmrm0", out.Device)
	assert.Equal(t, &TPM2KeyRef{Handle: 0x81010001, Algorithm: "RSA"}, out.EK)
	assert.Equal(t, &TPM2KeyRef{Handle: 0x81000001, Algorithm: "RSA"}, out.SRK)
	assert.Nil(t, out.IAK, "an unprovisioned IAK is absent, not a zero handle")
}

func TestTPM2Handler_HandlePlatformAttributes_ErrorPaths(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.isFIPSResult = true
	mock.isFIPSErr = errors.New("n/a")
	mock.isPCRExtErr = errors.New("n/a")
	mock.config = nil
	mock.fixedPropsErr = errors.New("n/a")
	h.SetTPM2Service(mock)

	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2PlatformAttrs}})

	require.Equal(t, quicwire.StatusOK, resp.Status)
	var out TPM2PlatformAttributesResponse
	require.NoError(t, quicwire.DecodePayload(resp.Payload, &out))
	assert.False(t, out.IsFIPS, "a refused FIPS read reports false")
	assert.Empty(t, out.Manufacturer)
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
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2GetIDevID}})
	assert.Equal(t, quicwire.StatusOK, resp.Status)
}

func TestTPM2Handler_HandleGetIDevID_AttrsError(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.idevidAttrsErr = errors.New("IDevID not found")
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2GetIDevID}})
	assert.Equal(t, quicwire.StatusNotFound, resp.Status)
}

func TestTPM2Handler_HandleVerifyQuote_EmptyPayload(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	// A bare sub-opcode with no request body must be rejected, not
	// silently treated as an empty (and therefore invalid) quote.
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2VerifyQuote}})
	assert.NotEqual(t, quicwire.StatusOK, resp.Status)
}

func TestTPM2Handler_HandleCreateIDevIDCSR(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2IDevIDCSR}})
	assert.Equal(t, quicwire.StatusOK, resp.Status)
}

func TestTPM2Handler_HandleCreateIDevIDCSR_EKCertError(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.ekCertErr = errors.New("no EK certificate")
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2IDevIDCSR}})
	assert.NotEqual(t, quicwire.StatusOK, resp.Status)
}

func TestTPM2Handler_HandleCreateLDevIDCSR(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2LDevIDCSR}})
	assert.Equal(t, quicwire.StatusOK, resp.Status)
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
		{"key not found", quicwire.StatusNotFound},
		{"already exists", quicwire.StatusAlreadyExists},
		{"invalid argument", quicwire.StatusInvalidArgument},
		{"permission denied", quicwire.StatusPermissionDenied},
		{"not implemented", quicwire.StatusNotImplemented},
		{"service unavailable", quicwire.StatusUnavailable},
		{"some error", quicwire.StatusInternalError},
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
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: append([]byte{quicwire.SubOpTPM2Provision}, []byte{0xFF, 0xFE}...)})
	assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
}

func TestTPM2Handler_HandleClear_DecodeError(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: append([]byte{quicwire.SubOpTPM2Clear}, []byte{0xFF, 0xFE}...)})
	assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
}

func TestTPM2Handler_HandleClear_WithPassword(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	req := TPM2ClearRequest{OwnerPassword: "test-pw"}
	payload, _ := quicwire.EncodePayload(req)
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: append([]byte{quicwire.SubOpTPM2Clear}, payload...)})
	assert.Equal(t, quicwire.StatusOK, resp.Status)
}

func TestTPM2Handler_HandleQuote_DecodeError(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: append([]byte{quicwire.SubOpTPM2Quote}, []byte{0xFF, 0xFE}...)})
	assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
}

func TestTPM2Handler_HandleReadPCRs_DecodeError(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: append([]byte{quicwire.SubOpTPM2ReadPCRs}, []byte{0xFF, 0xFE}...)})
	assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
}

func TestTPM2Handler_HandleExtendPCR_DecodeError(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: append([]byte{quicwire.SubOpTPM2ExtendPCR}, []byte{0xFF, 0xFE}...)})
	assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
}

func TestTPM2Handler_HandleRandom_DecodeError(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: append([]byte{quicwire.SubOpTPM2Random}, []byte{0xFF, 0xFE}...)})
	assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
}

func TestTPM2Handler_HandleSeal_DecodeError(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: append([]byte{quicwire.SubOpTPM2Seal}, []byte{0xFF, 0xFE}...)})
	assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
}

func TestTPM2Handler_HandleUnseal_DecodeError(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: append([]byte{quicwire.SubOpTPM2Unseal}, []byte{0xFF, 0xFE}...)})
	assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
}

func TestTPM2Handler_HandleImportEKCert_DecodeError(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: append([]byte{quicwire.SubOpTPM2ImportEKCert}, []byte{0xFF, 0xFE}...)})
	assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
}

func TestTPM2Handler_HandleGetSRK_Error(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.ssrkAttrsErr = errors.New("SRK not found")
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2GetSRK}})
	assert.NotEqual(t, quicwire.StatusOK, resp.Status)
}

func TestTPM2Handler_HandleCreateSRK_Error(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newSSRKMockTPM()
	mock.createSRKErr = errors.New("TPM_RC_BAD_AUTH")
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2CreateSRK}})
	assert.NotEqual(t, quicwire.StatusOK, resp.Status)
}

func TestTPM2Handler_HandleGetIAK_Error(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.iakAttrsErr = errors.New("IAK not found")
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2GetIAK}})
	assert.NotEqual(t, quicwire.StatusOK, resp.Status)
}

func TestTPM2Handler_HandleGetIAK_PubKeyError(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.iakPubKeyErr = errors.New("key retrieval failed")
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2GetIAK}})
	assert.NotEqual(t, quicwire.StatusOK, resp.Status)
}

func TestTPM2Handler_HandleCreateIAK_Error(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.createIAKErr = errors.New("creation failed")
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2CreateIAK}})
	assert.NotEqual(t, quicwire.StatusOK, resp.Status)
}

func TestTPM2Handler_HandleExtendPCR_TPMError(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.extendPCRErr = errors.New("PCR extend failed")
	h.SetTPM2Service(mock)
	req := &TPM2ExtendPCRRequest{PCRIndex: 14, HashAlg: "sha256", Data: []byte("data")}
	payload, _ := quicwire.EncodePayload(req)
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: append([]byte{quicwire.SubOpTPM2ExtendPCR}, payload...)})
	assert.NotEqual(t, quicwire.StatusOK, resp.Status)
}

func TestTPM2Handler_HandleRandom_TPMError(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.randomBytesErr = errors.New("RNG failed")
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2Random}})
	assert.NotEqual(t, quicwire.StatusOK, resp.Status)
}

func TestTPM2Handler_HandleSeal_TPMError(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.sealErr = errors.New("seal failed")
	h.SetTPM2Service(mock)
	req := &TPM2SealRequest{Data: []byte("secret")}
	payload, _ := quicwire.EncodePayload(req)
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: append([]byte{quicwire.SubOpTPM2Seal}, payload...)})
	assert.NotEqual(t, quicwire.StatusOK, resp.Status)
}

func TestTPM2Handler_HandleUnseal_TPMError(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.unsealErr = errors.New("unseal failed")
	h.SetTPM2Service(mock)
	req := &TPM2UnsealRequest{CN: "test-key"}
	payload, _ := quicwire.EncodePayload(req)
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: append([]byte{quicwire.SubOpTPM2Unseal}, payload...)})
	assert.NotEqual(t, quicwire.StatusOK, resp.Status)
}

func TestTPM2Handler_HandleEventLog_Error(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.eventLogErr = errors.New("event log unavailable")
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2EventLog}})
	assert.NotEqual(t, quicwire.StatusOK, resp.Status)
}

func TestTPM2Handler_HandleReadPCRs_Error(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.readPCRsErr = errors.New("PCR read failed")
	h.SetTPM2Service(mock)
	req := &TPM2ReadPCRsRequest{Indices: []uint32{0}}
	payload, _ := quicwire.EncodePayload(req)
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: append([]byte{quicwire.SubOpTPM2ReadPCRs}, payload...)})
	assert.NotEqual(t, quicwire.StatusOK, resp.Status)
}

func TestTPM2Handler_HandleGetIDevID_PubKeyError(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.idevidPubKeyErr = errors.New("key not available")
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2GetIDevID}})
	assert.NotEqual(t, quicwire.StatusOK, resp.Status)
}

func TestTPM2Handler_HandleCreateIDevIDCSR_IAKError(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.iakAttrsErr = errors.New("IAK not found")
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2IDevIDCSR}})
	assert.NotEqual(t, quicwire.StatusOK, resp.Status)
}

func TestTPM2Handler_HandleCreateIDevIDCSR_IDevIDError(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	mock := newMockTPM()
	mock.idevidAttrsErr = errors.New("IDevID not found")
	h.SetTPM2Service(mock)
	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2IDevIDCSR}})
	assert.NotEqual(t, quicwire.StatusOK, resp.Status)
}
