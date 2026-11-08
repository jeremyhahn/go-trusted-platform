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

package rest

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/channelbind"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

const (
	tpmReaderToken = "tpm-reader"
	tpmWriterToken = "tpm-writer"
	tpmAdminToken  = "tpm-admin"
)

// fakeTPMService records the request the handlers forwarded and answers
// every TPMService RPC with resp when it is that RPC's response type, an
// empty response otherwise, or err when it is set.
type fakeTPMService struct {
	platformv1.UnimplementedTPMServiceServer

	resp proto.Message
	err  error

	ctx context.Context
	req proto.Message
}

func tpmAnswer[Resp proto.Message](f *fakeTPMService, ctx context.Context, req proto.Message, empty Resp) (Resp, error) {
	f.ctx, f.req = ctx, req
	if f.err != nil {
		var none Resp
		return none, f.err
	}
	if resp, ok := f.resp.(Resp); ok {
		return resp, nil
	}
	return empty, nil
}

func (f *fakeTPMService) Info(ctx context.Context, req *platformv1.TPMInfoRequest) (*platformv1.TPMInfoResponse, error) {
	return tpmAnswer(f, ctx, req, &platformv1.TPMInfoResponse{})
}

func (f *fakeTPMService) Provision(ctx context.Context, req *platformv1.TPMProvisionRequest) (*platformv1.TPMProvisionResponse, error) {
	return tpmAnswer(f, ctx, req, &platformv1.TPMProvisionResponse{})
}

func (f *fakeTPMService) Clear(ctx context.Context, req *platformv1.TPMClearRequest) (*platformv1.TPMClearResponse, error) {
	return tpmAnswer(f, ctx, req, &platformv1.TPMClearResponse{})
}

func (f *fakeTPMService) GetCapabilities(ctx context.Context, req *platformv1.TPMCapabilitiesRequest) (*platformv1.TPMCapabilitiesResponse, error) {
	return tpmAnswer(f, ctx, req, &platformv1.TPMCapabilitiesResponse{})
}

func (f *fakeTPMService) GetPlatformAttributes(ctx context.Context, req *platformv1.TPMPlatformAttributesRequest) (*platformv1.TPMPlatformAttributesResponse, error) {
	return tpmAnswer(f, ctx, req, &platformv1.TPMPlatformAttributesResponse{})
}

func (f *fakeTPMService) ExtendPCR(ctx context.Context, req *platformv1.ExtendPCRRequest) (*platformv1.ExtendPCRResponse, error) {
	return tpmAnswer(f, ctx, req, &platformv1.ExtendPCRResponse{})
}

func (f *fakeTPMService) CreateEK(ctx context.Context, req *platformv1.CreateEKRequest) (*platformv1.CreateEKResponse, error) {
	return tpmAnswer(f, ctx, req, &platformv1.CreateEKResponse{})
}

func (f *fakeTPMService) GetEK(ctx context.Context, req *platformv1.GetEKRequest) (*platformv1.GetEKResponse, error) {
	return tpmAnswer(f, ctx, req, &platformv1.GetEKResponse{})
}

func (f *fakeTPMService) GetEKCertificate(ctx context.Context, req *platformv1.GetEKCertificateRequest) (*platformv1.GetEKCertificateResponse, error) {
	return tpmAnswer(f, ctx, req, &platformv1.GetEKCertificateResponse{})
}

func (f *fakeTPMService) ImportEKCertificate(ctx context.Context, req *platformv1.ImportEKCertificateRequest) (*platformv1.ImportEKCertificateResponse, error) {
	return tpmAnswer(f, ctx, req, &platformv1.ImportEKCertificateResponse{})
}

func (f *fakeTPMService) DeleteEK(ctx context.Context, req *platformv1.DeleteEKRequest) (*platformv1.DeleteEKResponse, error) {
	return tpmAnswer(f, ctx, req, &platformv1.DeleteEKResponse{})
}

func (f *fakeTPMService) CreateSRK(ctx context.Context, req *platformv1.CreateSRKRequest) (*platformv1.CreateSRKResponse, error) {
	return tpmAnswer(f, ctx, req, &platformv1.CreateSRKResponse{})
}

func (f *fakeTPMService) GetSRK(ctx context.Context, req *platformv1.GetSRKRequest) (*platformv1.GetSRKResponse, error) {
	return tpmAnswer(f, ctx, req, &platformv1.GetSRKResponse{})
}

func (f *fakeTPMService) DeleteSRK(ctx context.Context, req *platformv1.DeleteSRKRequest) (*platformv1.DeleteSRKResponse, error) {
	return tpmAnswer(f, ctx, req, &platformv1.DeleteSRKResponse{})
}

func (f *fakeTPMService) CreateAK(ctx context.Context, req *platformv1.CreateAKRequest) (*platformv1.CreateAKResponse, error) {
	return tpmAnswer(f, ctx, req, &platformv1.CreateAKResponse{})
}

func (f *fakeTPMService) GetAK(ctx context.Context, req *platformv1.GetAKRequest) (*platformv1.GetAKResponse, error) {
	return tpmAnswer(f, ctx, req, &platformv1.GetAKResponse{})
}

func (f *fakeTPMService) DeleteAK(ctx context.Context, req *platformv1.DeleteAKRequest) (*platformv1.DeleteAKResponse, error) {
	return tpmAnswer(f, ctx, req, &platformv1.DeleteAKResponse{})
}

func (f *fakeTPMService) Seal(ctx context.Context, req *platformv1.SealRequest) (*platformv1.SealResponse, error) {
	return tpmAnswer(f, ctx, req, &platformv1.SealResponse{})
}

func (f *fakeTPMService) Unseal(ctx context.Context, req *platformv1.UnsealRequest) (*platformv1.UnsealResponse, error) {
	return tpmAnswer(f, ctx, req, &platformv1.UnsealResponse{})
}

func (f *fakeTPMService) Quote(ctx context.Context, req *platformv1.QuoteRequest) (*platformv1.QuoteResponse, error) {
	return tpmAnswer(f, ctx, req, &platformv1.QuoteResponse{})
}

func (f *fakeTPMService) VerifyQuote(ctx context.Context, req *platformv1.VerifyQuoteRequest) (*platformv1.VerifyQuoteResponse, error) {
	return tpmAnswer(f, ctx, req, &platformv1.VerifyQuoteResponse{})
}

func (f *fakeTPMService) Certify(ctx context.Context, req *platformv1.CertifyRequest) (*platformv1.CertifyResponse, error) {
	return tpmAnswer(f, ctx, req, &platformv1.CertifyResponse{})
}

func (f *fakeTPMService) GetEventLog(ctx context.Context, req *platformv1.GetEventLogRequest) (*platformv1.GetEventLogResponse, error) {
	return tpmAnswer(f, ctx, req, &platformv1.GetEventLogResponse{})
}

func (f *fakeTPMService) GetPCRs(ctx context.Context, req *platformv1.GetPCRsRequest) (*platformv1.GetPCRsResponse, error) {
	return tpmAnswer(f, ctx, req, &platformv1.GetPCRsResponse{})
}

func (f *fakeTPMService) MakeCredential(ctx context.Context, req *platformv1.MakeCredentialRequest) (*platformv1.MakeCredentialResponse, error) {
	return tpmAnswer(f, ctx, req, &platformv1.MakeCredentialResponse{})
}

func (f *fakeTPMService) ActivateCredential(ctx context.Context, req *platformv1.TPMActivateCredentialRequest) (*platformv1.TPMActivateCredentialResponse, error) {
	return tpmAnswer(f, ctx, req, &platformv1.TPMActivateCredentialResponse{})
}

func (f *fakeTPMService) DefineNVRAM(ctx context.Context, req *platformv1.DefineNVRAMRequest) (*platformv1.DefineNVRAMResponse, error) {
	return tpmAnswer(f, ctx, req, &platformv1.DefineNVRAMResponse{})
}

func (f *fakeTPMService) WriteNVRAM(ctx context.Context, req *platformv1.WriteNVRAMRequest) (*platformv1.WriteNVRAMResponse, error) {
	return tpmAnswer(f, ctx, req, &platformv1.WriteNVRAMResponse{})
}

func (f *fakeTPMService) ReadNVRAM(ctx context.Context, req *platformv1.ReadNVRAMRequest) (*platformv1.ReadNVRAMResponse, error) {
	return tpmAnswer(f, ctx, req, &platformv1.ReadNVRAMResponse{})
}

func (f *fakeTPMService) UndefineNVRAM(ctx context.Context, req *platformv1.UndefineNVRAMRequest) (*platformv1.UndefineNVRAMResponse, error) {
	return tpmAnswer(f, ctx, req, &platformv1.UndefineNVRAMResponse{})
}

func (f *fakeTPMService) GetRandom(ctx context.Context, req *platformv1.GetRandomRequest) (*platformv1.GetRandomResponse, error) {
	return tpmAnswer(f, ctx, req, &platformv1.GetRandomResponse{})
}

// nilContextAuthorizer accepts every token but authorizes no context.
type nilContextAuthorizer struct{}

func (nilContextAuthorizer) AuthorizeToken(context.Context, string, string, string, string, string) (*platformtoken.AuthorizedContext, error) {
	return nil, nil
}

// tpmScopedAuthorizer grants tpmReaderToken tpm:read, tpmWriterToken
// tpm:read and tpm:write, and tpmAdminToken all three TPM scopes.
func tpmScopedAuthorizer() *scopedAuthorizer {
	return &scopedAuthorizer{scopes: map[string][]string{
		tpmReaderToken: {tpmScopeRead},
		tpmWriterToken: {tpmScopeRead, tpmScopeWrite},
		tpmAdminToken:  {tpmScopeRead, tpmScopeWrite, tpmScopeDelete},
	}}
}

// tpmGuard checks bearer tokens through tpmScopedAuthorizer.
func tpmGuard() *ScopeGuard {
	return NewScopeGuard(tpmScopedAuthorizer(), nil, nil)
}

// tpmRouter mounts TPM handlers that serve tpm and authorize through
// guard. Either may be nil.
func tpmRouter(tpm platformv1.TPMServiceServer, guard *ScopeGuard) *mux.Router {
	router := mux.NewRouter()
	NewTPMHandlers(nil).WithTPMService(tpm).WithScopeGuard(guard).RegisterRoutes(router)
	return router
}

// serveTPM sends one request through router, with token as its bearer token
// when it is not empty.
func serveTPM(router http.Handler, req *http.Request, token string) *httptest.ResponseRecorder {
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// newTPMRequest builds a request with body as its JSON body when it is not
// empty.
func newTPMRequest(method, target, body string) *http.Request {
	if body == "" {
		return httptest.NewRequest(method, target, nil)
	}
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

// decodeTPMError decodes the ErrorResponse a refused request answers with.
func decodeTPMError(t *testing.T, rec *httptest.ResponseRecorder) ErrorResponse {
	t.Helper()
	var body ErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body), rec.Body.String())
	return body
}

// tpmRouteCase is one mounted route called the way an SDK calls it.
type tpmRouteCase struct {
	route  string // the mounted method and path template
	method string
	target string
	body   string        // the camelCase protojson body, if any
	want   proto.Message // the request the TPM service must receive
	resp   proto.Message // what the TPM service answers
	key    string        // a camelCase key the response must carry
}

const (
	ekHandle    = 0x81010001
	akHandle    = 0x81010002
	srkHandle   = 0x81000002
	nvramIndex  = 0x1c00002
	ekHandleDec = "2164326401"
	akHandleDec = "2164326402"
	srkHandleJS = "2164260866"
	nvramDec    = "29360130"
)

func tpmRouteCases() []tpmRouteCase {
	rsa := platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048
	p256 := platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256
	sha256 := platformv1.PCRBank_PCR_BANK_SHA256
	sha384 := platformv1.PCRBank_PCR_BANK_SHA384
	return []tpmRouteCase{
		{
			route: "GET /api/v1/tpm/info", method: http.MethodGet, target: "/api/v1/tpm/info",
			want: &platformv1.TPMInfoRequest{},
			resp: &platformv1.TPMInfoResponse{MaxNvramSize: 2048}, key: "maxNvramSize",
		},
		{
			route: "POST /api/v1/tpm/provision", method: http.MethodPost, target: "/api/v1/tpm/provision",
			body: `{"ownerPassword":"owner","createEk":true,"createSrk":true}`,
			want: &platformv1.TPMProvisionRequest{OwnerPassword: "owner", CreateEk: true, CreateSrk: true},
			resp: &platformv1.TPMProvisionResponse{EkPublic: []byte("ek")}, key: "ekPublic",
		},
		{
			route: "POST /api/v1/tpm/clear", method: http.MethodPost, target: "/api/v1/tpm/clear",
			body: `{"ownerPassword":"owner","confirm":true}`,
			want: &platformv1.TPMClearRequest{OwnerPassword: "owner", Confirm: true},
			resp: &platformv1.TPMClearResponse{}, key: "status",
		},
		{
			route: "GET /api/v1/tpm/capabilities", method: http.MethodGet, target: "/api/v1/tpm/capabilities",
			want: &platformv1.TPMCapabilitiesRequest{},
			resp: &platformv1.TPMCapabilitiesResponse{Algorithms: []string{"RSA"}, EccCurves: []string{"NIST_P256"}}, key: "eccCurves",
		},
		{
			route: "GET /api/v1/tpm/platform", method: http.MethodGet, target: "/api/v1/tpm/platform",
			want: &platformv1.TPMPlatformAttributesRequest{},
			resp: &platformv1.TPMPlatformAttributesResponse{Device: "/dev/tpmrm0", Ek: &platformv1.TPMKeyRef{Handle: ekHandle, Algorithm: "RSA"}}, key: "ek",
		},
		{
			route: "GET /api/v1/tpm/ek", method: http.MethodGet, target: "/api/v1/tpm/ek?algorithm=KEY_ALGORITHM_RSA_2048&handle=0x81010001",
			want: &platformv1.GetEKRequest{Algorithm: rsa, Handle: ekHandle},
			resp: &platformv1.GetEKResponse{PublicKey: []byte("ek")}, key: "publicKey",
		},
		{
			route: "POST /api/v1/tpm/ek", method: http.MethodPost, target: "/api/v1/tpm/ek",
			body: `{"persistent":true}`,
			want: &platformv1.CreateEKRequest{Persistent: true},
			resp: &platformv1.CreateEKResponse{Handle: ekHandle}, key: "publicKey",
		},
		{
			route: "DELETE /api/v1/tpm/ek", method: http.MethodDelete, target: "/api/v1/tpm/ek",
			body: `{"handle":` + ekHandleDec + `,"algorithm":"KEY_ALGORITHM_ECDSA_P256"}`,
			want: &platformv1.DeleteEKRequest{Handle: ekHandle, Algorithm: p256},
			resp: &platformv1.DeleteEKResponse{}, key: "status",
		},
		{
			route: "DELETE /api/v1/tpm/ek/{handle}", method: http.MethodDelete, target: "/api/v1/tpm/ek/0x81010001",
			want: &platformv1.DeleteEKRequest{Handle: ekHandle},
			resp: &platformv1.DeleteEKResponse{}, key: "status",
		},
		{
			route: "GET /api/v1/tpm/ek/certificate", method: http.MethodGet, target: "/api/v1/tpm/ek/certificate?algorithm=1",
			want: &platformv1.GetEKCertificateRequest{Algorithm: rsa},
			resp: &platformv1.GetEKCertificateResponse{Certificate: []byte("der"), Format: "DER"}, key: "certificate",
		},
		{
			route: "POST /api/v1/tpm/ek/certificate", method: http.MethodPost, target: "/api/v1/tpm/ek/certificate",
			body: `{"certificate":"ZGVy","format":"DER","nvramIndex":` + nvramDec + `}`,
			want: &platformv1.ImportEKCertificateRequest{Certificate: []byte("der"), Format: "DER", NvramIndex: nvramIndex},
			resp: &platformv1.ImportEKCertificateResponse{}, key: "status",
		},
		{
			route: "GET /api/v1/tpm/srk", method: http.MethodGet, target: "/api/v1/tpm/srk?handle=0x81000002",
			want: &platformv1.GetSRKRequest{Handle: srkHandle},
			resp: &platformv1.GetSRKResponse{PublicKey: []byte("srk")}, key: "publicKey",
		},
		{
			route: "POST /api/v1/tpm/srk", method: http.MethodPost, target: "/api/v1/tpm/srk",
			body: `{"persistent":true,"parentHandle":` + ekHandleDec + `,"parentPassword":"pw"}`,
			want: &platformv1.CreateSRKRequest{Persistent: true, ParentHandle: ekHandle, ParentPassword: "pw"},
			resp: &platformv1.CreateSRKResponse{Handle: srkHandle}, key: "publicKey",
		},
		{
			route: "DELETE /api/v1/tpm/srk", method: http.MethodDelete, target: "/api/v1/tpm/srk",
			body: `{"handle":` + srkHandleJS + `}`,
			want: &platformv1.DeleteSRKRequest{Handle: srkHandle},
			resp: &platformv1.DeleteSRKResponse{}, key: "status",
		},
		{
			route: "DELETE /api/v1/tpm/srk/{handle}", method: http.MethodDelete, target: "/api/v1/tpm/srk/" + srkHandleJS,
			want: &platformv1.DeleteSRKRequest{Handle: srkHandle},
			resp: &platformv1.DeleteSRKResponse{}, key: "status",
		},
		{
			route: "GET /api/v1/tpm/ak", method: http.MethodGet, target: "/api/v1/tpm/ak?algorithm=KEY_ALGORITHM_ECDSA_P256",
			want: &platformv1.GetAKRequest{Algorithm: p256},
			resp: &platformv1.GetAKResponse{PublicKey: []byte("ak")}, key: "publicKey",
		},
		{
			route: "POST /api/v1/tpm/ak", method: http.MethodPost, target: "/api/v1/tpm/ak",
			body: `{"parentHandle":` + srkHandleJS + `}`,
			want: &platformv1.CreateAKRequest{ParentHandle: srkHandle},
			resp: &platformv1.CreateAKResponse{Handle: akHandle}, key: "credentialBlob",
		},
		{
			route: "DELETE /api/v1/tpm/ak", method: http.MethodDelete, target: "/api/v1/tpm/ak",
			body: `{"handle":` + akHandleDec + `,"password":"pw"}`,
			want: &platformv1.DeleteAKRequest{Handle: akHandle, Password: "pw"},
			resp: &platformv1.DeleteAKResponse{}, key: "status",
		},
		{
			route: "DELETE /api/v1/tpm/ak/{handle}", method: http.MethodDelete, target: "/api/v1/tpm/ak/0x81010002",
			want: &platformv1.DeleteAKRequest{Handle: akHandle},
			resp: &platformv1.DeleteAKResponse{}, key: "status",
		},
		{
			route: "POST /api/v1/tpm/make-credential", method: http.MethodPost, target: "/api/v1/tpm/make-credential",
			body: `{"akName":"bmFtZQ==","secret":"c2VjcmV0"}`,
			want: &platformv1.MakeCredentialRequest{AkName: []byte("name"), Secret: []byte("secret")},
			resp: &platformv1.MakeCredentialResponse{CredentialBlob: []byte("blob")}, key: "encryptedSecret",
		},
		{
			route: "POST /api/v1/tpm/activate-credential", method: http.MethodPost, target: "/api/v1/tpm/activate-credential",
			body: `{"credentialBlob":"YmxvYg==","encryptedSecret":"c2VjcmV0"}`,
			want: &platformv1.TPMActivateCredentialRequest{CredentialBlob: []byte("blob"), EncryptedSecret: []byte("secret")},
			resp: &platformv1.TPMActivateCredentialResponse{Secret: []byte("activated")}, key: "secret",
		},
		{
			route: "POST /api/v1/tpm/quote", method: http.MethodPost, target: "/api/v1/tpm/quote",
			body: `{"akHandle":` + akHandleDec + `,"pcrIndices":[0,7],"pcrBank":"PCR_BANK_SHA256","nonce":"bm9uY2U="}`,
			want: &platformv1.QuoteRequest{AkHandle: akHandle, PcrIndices: []uint32{0, 7}, PcrBank: sha256, Nonce: []byte("nonce")},
			resp: &platformv1.QuoteResponse{Quote: []byte("quote"), SignatureAlgorithm: "SHA256-RSAPSS"}, key: "signatureAlgorithm",
		},
		{
			route: "POST /api/v1/tpm/quote/verify", method: http.MethodPost, target: "/api/v1/tpm/quote/verify",
			body: `{"quote":"cXVvdGU=","akPublic":"YWs=","signatureAlgorithm":"SHA256-RSAPSS","channelBinding":"Ymlu"}`,
			want: &platformv1.VerifyQuoteRequest{Quote: []byte("quote"), AkPublic: []byte("ak"), SignatureAlgorithm: "SHA256-RSAPSS", ChannelBinding: []byte("bin")},
			resp: &platformv1.VerifyQuoteResponse{Verified: true}, key: "actualPcrs",
		},
		{
			route: "POST /api/v1/tpm/certify", method: http.MethodPost, target: "/api/v1/tpm/certify",
			body: `{"keyHandle":2164260865,"keyPassword":"pw","nonce":"bm9uY2U="}`,
			want: &platformv1.CertifyRequest{KeyHandle: 0x81000001, KeyPassword: "pw", Nonce: []byte("nonce")},
			resp: &platformv1.CertifyResponse{CertifyInfo: []byte("attest"), SignatureAlgorithm: "SHA256-RSAPSS"}, key: "certifyInfo",
		},
		{
			route: "GET /api/v1/tpm/pcrs", method: http.MethodGet, target: "/api/v1/tpm/pcrs?indices=0&indices=7&bank=PCR_BANK_SHA256",
			want: &platformv1.GetPCRsRequest{Indices: []uint32{0, 7}, Bank: sha256},
			resp: &platformv1.GetPCRsResponse{}, key: "pcrValues",
		},
		{
			route: "POST /api/v1/tpm/pcrs", method: http.MethodPost, target: "/api/v1/tpm/pcrs",
			body: `{"indices":[0,7],"bank":"PCR_BANK_SHA384"}`,
			want: &platformv1.GetPCRsRequest{Indices: []uint32{0, 7}, Bank: sha384},
			resp: &platformv1.GetPCRsResponse{}, key: "pcrValues",
		},
		{
			route: "POST /api/v1/tpm/pcrs/extend", method: http.MethodPost, target: "/api/v1/tpm/pcrs/extend",
			body: `{"index":16,"hashAlg":"sha256","data":"bWVhc3VyZW1lbnQ="}`,
			want: &platformv1.ExtendPCRRequest{Index: 16, HashAlg: "sha256", Data: []byte("measurement")},
			resp: &platformv1.ExtendPCRResponse{}, key: "status",
		},
		{
			route: "GET /api/v1/tpm/eventlog", method: http.MethodGet, target: "/api/v1/tpm/eventlog?format=json",
			want: &platformv1.GetEventLogRequest{Format: "json"},
			resp: &platformv1.GetEventLogResponse{EventCount: 3}, key: "eventCount",
		},
		{
			route: "POST /api/v1/tpm/nvram", method: http.MethodPost, target: "/api/v1/tpm/nvram",
			body: `{"index":` + nvramDec + `,"size":64,"password":"pw","parentPassword":"owner"}`,
			want: &platformv1.DefineNVRAMRequest{Index: nvramIndex, Size: 64, Password: "pw", ParentPassword: "owner"},
			resp: &platformv1.DefineNVRAMResponse{}, key: "status",
		},
		{
			route: "GET /api/v1/tpm/nvram", method: http.MethodGet, target: "/api/v1/tpm/nvram",
			body: `{"index":` + nvramDec + `,"size":32}`,
			want: &platformv1.ReadNVRAMRequest{Index: nvramIndex, Size: 32},
			resp: &platformv1.ReadNVRAMResponse{Data: []byte("data")}, key: "data",
		},
		{
			route: "PUT /api/v1/tpm/nvram", method: http.MethodPut, target: "/api/v1/tpm/nvram",
			body: `{"index":` + nvramDec + `,"data":"ZGF0YQ==","offset":4}`,
			want: &platformv1.WriteNVRAMRequest{Index: nvramIndex, Data: []byte("data"), Offset: 4},
			resp: &platformv1.WriteNVRAMResponse{}, key: "status",
		},
		{
			route: "DELETE /api/v1/tpm/nvram", method: http.MethodDelete, target: "/api/v1/tpm/nvram",
			body: `{"index":` + nvramDec + `,"parentPassword":"owner"}`,
			want: &platformv1.UndefineNVRAMRequest{Index: nvramIndex, ParentPassword: "owner"},
			resp: &platformv1.UndefineNVRAMResponse{}, key: "status",
		},
		{
			route: "GET /api/v1/tpm/nvram/{index}", method: http.MethodGet, target: "/api/v1/tpm/nvram/0x1c00002?offset=4&size=32",
			want: &platformv1.ReadNVRAMRequest{Index: nvramIndex, Offset: 4, Size: 32},
			resp: &platformv1.ReadNVRAMResponse{Data: []byte("data")}, key: "data",
		},
		{
			route: "PUT /api/v1/tpm/nvram/{index}", method: http.MethodPut, target: "/api/v1/tpm/nvram/0x1c00002",
			body: `{"data":"ZGF0YQ==","password":"pw","offset":4}`,
			want: &platformv1.WriteNVRAMRequest{Index: nvramIndex, Data: []byte("data"), Password: "pw", Offset: 4},
			resp: &platformv1.WriteNVRAMResponse{}, key: "status",
		},
		{
			route: "DELETE /api/v1/tpm/nvram/{index}", method: http.MethodDelete, target: "/api/v1/tpm/nvram/0x1c00002",
			want: &platformv1.UndefineNVRAMRequest{Index: nvramIndex},
			resp: &platformv1.UndefineNVRAMResponse{}, key: "status",
		},
		{
			route: "POST /api/v1/tpm/random", method: http.MethodPost, target: "/api/v1/tpm/random",
			body: `{"numBytes":32}`,
			want: &platformv1.GetRandomRequest{NumBytes: 32},
			resp: &platformv1.GetRandomResponse{RandomBytes: []byte{1, 2, 3}}, key: "randomBytes",
		},
		{
			route: "POST /api/v1/tpm/seal", method: http.MethodPost, target: "/api/v1/tpm/seal",
			body: `{"data":"c2VjcmV0","cn":"disk","parentHandle":` + srkHandleJS + `}`,
			want: &platformv1.SealRequest{Data: []byte("secret"), Cn: "disk", ParentHandle: srkHandle},
			resp: &platformv1.SealResponse{SealedData: []byte("sealed")}, key: "sealedData",
		},
		{
			route: "POST /api/v1/tpm/unseal", method: http.MethodPost, target: "/api/v1/tpm/unseal",
			body: `{"cn":"disk","pcrIndices":[7]}`,
			want: &platformv1.UnsealRequest{Cn: "disk", PcrIndices: []uint32{7}},
			resp: &platformv1.UnsealResponse{Data: []byte("secret")}, key: "data",
		},
	}
}

// TestTPMRoutesServeTheSDKContract calls every mounted route the way the
// SDKs do: a camelCase protojson body, query parameters or a path parameter
// must reach the TPM service as the matching request, and the response must
// come back as protojson.
func TestTPMRoutesServeTheSDKContract(t *testing.T) {
	cases := tpmRouteCases()

	mounted := map[string]bool{}
	for _, route := range NewTPMHandlers(nil).routes() {
		mounted[route.method+" "+route.path] = true
	}
	covered := map[string]bool{}
	for _, tc := range cases {
		covered[tc.route] = true
	}
	require.Equal(t, mounted, covered, "every mounted TPM route needs exactly one case")

	for _, tc := range cases {
		t.Run(tc.route, func(t *testing.T) {
			tpm := &fakeTPMService{resp: tc.resp}
			router := tpmRouter(tpm, tpmGuard())

			rec := serveTPM(router, newTPMRequest(tc.method, tc.target, tc.body), tpmAdminToken)

			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
			require.NotNil(t, tpm.req, "the TPM service must be called")
			assert.True(t, proto.Equal(tc.want, tpm.req), "want %v, got %v", tc.want, tpm.req)

			var keys map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &keys), rec.Body.String())
			assert.Contains(t, keys, tc.key, rec.Body.String())

			got := tc.resp.ProtoReflect().New().Interface()
			require.NoError(t, protojson.Unmarshal(rec.Body.Bytes(), got))
			assert.True(t, proto.Equal(tc.resp, got), "want %v, got %v", tc.resp, got)
		})
	}
}

// TestTPMRoutesRefuseMalformedRequests pins that a request field the
// message does not have is an error on every route, never a silent default.
func TestTPMRoutesRefuseMalformedRequests(t *testing.T) {
	for _, tc := range tpmRouteCases() {
		t.Run(tc.route+" unknown body field", func(t *testing.T) {
			tpm := &fakeTPMService{}
			router := tpmRouter(tpm, tpmGuard())

			rec := serveTPM(router, newTPMRequest(tc.method, tc.target, `{"notAField":1}`), tpmAdminToken)

			require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			assert.Contains(t, decodeTPMError(t, rec).Error, `unknown field "notAField"`)
			assert.Nil(t, tpm.req, "a malformed request must not reach the TPM service")
		})

		t.Run(tc.route+" unknown query parameter", func(t *testing.T) {
			tpm := &fakeTPMService{}
			router := tpmRouter(tpm, tpmGuard())
			separator := "?"
			if strings.Contains(tc.target, "?") {
				separator = "&"
			}

			rec := serveTPM(router, newTPMRequest(tc.method, tc.target+separator+"notAField=1", ""), tpmAdminToken)

			require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			want := ErrInvalidQueryParameter{
				Name:   "notAField",
				Value:  "1",
				Reason: "not a field of " + string(tc.want.ProtoReflect().Descriptor().FullName()),
			}
			assert.Equal(t, want.Error(), decodeTPMError(t, rec).Error)
			assert.Nil(t, tpm.req, "a malformed request must not reach the TPM service")
		})
	}

	t.Run("a body that is not a JSON object", func(t *testing.T) {
		tpm := &fakeTPMService{}
		router := tpmRouter(tpm, tpmGuard())

		rec := serveTPM(router, newTPMRequest(http.MethodPost, "/api/v1/tpm/quote/verify", "[]"), tpmReaderToken)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Nil(t, tpm.req)
	})

	t.Run("a path handle that is not a uint32", func(t *testing.T) {
		tpm := &fakeTPMService{}
		router := tpmRouter(tpm, tpmGuard())

		rec := serveTPM(router, newTPMRequest(http.MethodDelete, "/api/v1/tpm/ak/persistent", ""), tpmAdminToken)

		require.Equal(t, http.StatusBadRequest, rec.Code)
		want := ErrInvalidQueryParameter{Name: "handle", Value: "persistent", Reason: "not a valid uint32"}
		assert.Equal(t, want.Error(), decodeTPMError(t, rec).Error)
		assert.Nil(t, tpm.req)
	})
}

// TestTPMLegacyRoutesAreGone pins that the routes the TPMService has no RPC
// for are no longer mounted.
func TestTPMLegacyRoutesAreGone(t *testing.T) {
	legacy := []struct{ method, path string }{
		{http.MethodPost, "/api/v1/tpm/csr/idevid"},
		{http.MethodPost, "/api/v1/tpm/iak"},
	}
	router := tpmRouter(&fakeTPMService{}, tpmGuard())
	for _, route := range legacy {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			rec := serveTPM(router, newTPMRequest(route.method, route.path, ""), tpmAdminToken)

			assert.Equal(t, http.StatusNotFound, rec.Code)
		})
	}
}

func TestTPMRequireScope(t *testing.T) {
	t.Run("a token granting the route's scope reaches the handler", func(t *testing.T) {
		tpm := &fakeTPMService{}
		router := tpmRouter(tpm, tpmGuard())

		rec := serveTPM(router, newTPMRequest(http.MethodPost, "/api/v1/tpm/quote", ""), tpmReaderToken)

		assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.NotNil(t, tpm.req, "the TPM service must be called")
	})

	t.Run("the token is validated at the request URL and the guard checks the scope", func(t *testing.T) {
		tokens := tpmScopedAuthorizer()
		router := tpmRouter(&fakeTPMService{}, NewScopeGuard(tokens, nil, nil))

		rec := serveTPM(router, newTPMRequest(http.MethodPost, "/api/v1/tpm/seal", ""), tpmWriterToken)

		assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Empty(t, tokens.asked, "the guard checks the route scope itself")
		assert.True(t, strings.HasSuffix(tokens.askedHTU, "/api/v1/tpm/seal"), tokens.askedHTU)
	})

	t.Run("the verified operator client certificate reaches every route", func(t *testing.T) {
		guard := NewScopeGuard(nil, grantingPeers{scopes: []string{"*:*"}}, nil)
		for _, route := range NewTPMHandlers(nil).routes() {
			tpm := &fakeTPMService{}
			target := strings.NewReplacer("{handle}", ekHandleDec, "{index}", nvramDec).Replace(route.path)

			rec := serveTPM(tpmRouter(tpm, guard), certificateRequest(route.method, target, "operator"), "")

			assert.NotEqual(t, http.StatusUnauthorized, rec.Code, "%s %s: %s", route.method, route.path, rec.Body.String())
			assert.NotEqual(t, http.StatusForbidden, rec.Code, "%s %s: %s", route.method, route.path, rec.Body.String())
		}
	})

	refusals := []struct {
		name       string
		guard      *ScopeGuard
		method     string
		path       string
		header     string
		wantStatus int
		wantErr    error
	}{
		{
			name:       "no bearer token or client certificate",
			guard:      tpmGuard(),
			method:     http.MethodPost,
			path:       "/api/v1/tpm/quote",
			wantStatus: http.StatusUnauthorized,
			wantErr:    ErrRouteUnauthenticated{Reason: "no bearer token or verified client certificate"},
		},
		{
			name:       "a token the authorizer rejects",
			guard:      tpmGuard(),
			method:     http.MethodPost,
			path:       "/api/v1/tpm/quote",
			header:     "Bearer stolen",
			wantStatus: http.StatusUnauthorized,
			wantErr:    ErrRouteUnauthenticated{Reason: "token invalid"},
		},
		{
			name:       "a read token on a write route",
			guard:      tpmGuard(),
			method:     http.MethodPost,
			path:       "/api/v1/tpm/seal",
			header:     "Bearer " + tpmReaderToken,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "a write token on a delete route",
			guard:      tpmGuard(),
			method:     http.MethodDelete,
			path:       "/api/v1/tpm/ek",
			header:     "Bearer " + tpmWriterToken,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "no guard configured",
			method:     http.MethodPost,
			path:       "/api/v1/tpm/quote",
			header:     "Bearer " + tpmReaderToken,
			wantStatus: http.StatusForbidden,
			wantErr:    ErrRouteForbidden{Scope: tpmScopeRead, Reason: "no authorization is configured for this route"},
		},
		{
			name:       "an authorizer that authorizes no context",
			guard:      NewScopeGuard(nilContextAuthorizer{}, nil, nil),
			method:     http.MethodPost,
			path:       "/api/v1/tpm/quote",
			header:     "Bearer " + tpmReaderToken,
			wantStatus: http.StatusUnauthorized,
			wantErr:    ErrRouteUnauthenticated{Reason: "the credential authorized no caller"},
		},
	}
	for _, tc := range refusals {
		t.Run("refuses "+tc.name, func(t *testing.T) {
			tpm := &fakeTPMService{}
			router := tpmRouter(tpm, tc.guard)
			req := newTPMRequest(tc.method, tc.path, "")
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}

			rec := serveTPM(router, req, "")

			assert.Equal(t, tc.wantStatus, rec.Code, rec.Body.String())
			if tc.wantErr != nil {
				assert.Equal(t, tc.wantErr.Error(), decodeTPMError(t, rec).Error)
			}
			assert.Nil(t, tpm.req, "a refused request must not reach the TPM service")
		})
	}
}

// TestTPMRouteScopes pins the scope tiers of docs/tpm/api.md §9: every route
// has a scope, observers need tpm:read, and every DELETE needs tpm:delete.
func TestTPMRouteScopes(t *testing.T) {
	tiers := map[string]bool{tpmScopeRead: true, tpmScopeWrite: true, tpmScopeDelete: true}
	for _, route := range NewTPMHandlers(nil).routes() {
		assert.True(t, tiers[route.scope], "%s %s has scope %q", route.method, route.path, route.scope)
		switch route.method {
		case http.MethodGet:
			assert.Equal(t, tpmScopeRead, route.scope, "%s %s", route.method, route.path)
		case http.MethodDelete:
			assert.Equal(t, tpmScopeDelete, route.scope, "%s %s", route.method, route.path)
		}
	}
}

func TestTPMRPC(t *testing.T) {
	t.Run("hands the service the request's TLS connection", func(t *testing.T) {
		tpm := &fakeTPMService{}
		router := tpmRouter(tpm, tpmGuard())
		req := newTPMRequest(http.MethodPost, "/api/v1/tpm/quote", "")
		req.TLS = testutil.ServerConnectionState(t)

		rec := serveTPM(router, req, tpmReaderToken)

		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		state, transport, ok := channelbind.ConnectionTLS(tpm.ctx)
		require.True(t, ok, "the RPC context must record the connection")
		assert.Same(t, req.TLS, state)
		assert.Equal(t, channelbind.TransportREST, transport)
	})

	t.Run("an empty body is the zero request", func(t *testing.T) {
		tpm := &fakeTPMService{}
		router := tpmRouter(tpm, tpmGuard())

		rec := serveTPM(router, newTPMRequest(http.MethodPost, "/api/v1/tpm/quote", ""), tpmReaderToken)

		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.True(t, proto.Equal(&platformv1.QuoteRequest{}, tpm.req), "%v", tpm.req)
	})

	t.Run("no TPM service is 503", func(t *testing.T) {
		router := tpmRouter(nil, tpmGuard())

		rec := serveTPM(router, newTPMRequest(http.MethodPost, "/api/v1/tpm/quote", ""), tpmReaderToken)

		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
		assert.Equal(t, ErrTPMServiceNotAvailable{}.Error(), decodeTPMError(t, rec).Error)
	})

	t.Run("a body that cannot be read is 400", func(t *testing.T) {
		tpm := &fakeTPMService{}
		router := tpmRouter(tpm, tpmGuard())
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/quote", iotest.ErrReader(errors.New("connection reset")))

		rec := serveTPM(router, req, tpmReaderToken)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "connection reset")
		assert.Nil(t, tpm.req)
	})

	t.Run("a response that cannot be encoded is 500", func(t *testing.T) {
		// protojson refuses a string field that is not valid UTF-8.
		tpm := &fakeTPMService{resp: &platformv1.QuoteResponse{SignatureAlgorithm: "\xff"}}
		router := tpmRouter(tpm, tpmGuard())

		rec := serveTPM(router, newTPMRequest(http.MethodPost, "/api/v1/tpm/quote", ""), tpmReaderToken)

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		assert.Contains(t, rec.Body.String(), "encode_response")
	})

	t.Run("a quote that fails verification is 200 with the reason", func(t *testing.T) {
		tpm := &fakeTPMService{resp: &platformv1.VerifyQuoteResponse{Message: "signature_verification_failed"}}
		router := tpmRouter(tpm, tpmGuard())

		rec := serveTPM(router, newTPMRequest(http.MethodPost, "/api/v1/tpm/quote/verify", ""), tpmReaderToken)

		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var resp platformv1.VerifyQuoteResponse
		require.NoError(t, protojson.Unmarshal(rec.Body.Bytes(), &resp))
		assert.False(t, resp.GetVerified())
		assert.Equal(t, "signature_verification_failed", resp.GetMessage())
	})

	statuses := []struct {
		err  error
		want int
	}{
		{status.Error(codes.InvalidArgument, "nonce too long"), http.StatusBadRequest},
		{status.Error(codes.FailedPrecondition, "no channel binding"), http.StatusConflict},
		{status.Error(codes.PermissionDenied, "denied"), http.StatusForbidden},
		{status.Error(codes.Unavailable, "no TPM"), http.StatusServiceUnavailable},
		{errors.New("not a status error"), http.StatusInternalServerError},
	}
	for _, tc := range statuses {
		t.Run("maps "+tc.err.Error(), func(t *testing.T) {
			router := tpmRouter(&fakeTPMService{err: tc.err}, tpmGuard())

			rec := serveTPM(router, newTPMRequest(http.MethodPost, "/api/v1/tpm/quote", ""), tpmReaderToken)

			assert.Equal(t, tc.want, rec.Code)
			assert.Contains(t, rec.Body.String(), status.Convert(tc.err).Message())
		})
	}
}

// DeleteAK refuses because the IAK is not evicted. Both routes answer that
// FailedPrecondition refusal 409, the shared mapping (#665), as the daemon's
// IAK delete route does; every other error keeps the generic mapping too.
func TestTPMDeleteAKStatuses(t *testing.T) {
	refused := status.Error(codes.FailedPrecondition, "the IAK key is TPM-resident")
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"refusal is 409", refused, http.StatusConflict},
		{"unavailable stays 503", status.Error(codes.Unavailable, "no TPM"), http.StatusServiceUnavailable},
		{"non-status error stays 500", errors.New("not a status error"), http.StatusInternalServerError},
	}
	for _, target := range []string{"/api/v1/tpm/ak", "/api/v1/tpm/ak/0x81010002"} {
		for _, tc := range cases {
			t.Run(target+" "+tc.name, func(t *testing.T) {
				router := tpmRouter(&fakeTPMService{err: tc.err}, tpmGuard())

				rec := serveTPM(router, newTPMRequest(http.MethodDelete, target, ""), tpmAdminToken)

				assert.Equal(t, tc.want, rec.Code)
				assert.Contains(t, rec.Body.String(), status.Convert(tc.err).Message())
			})
		}
	}

	t.Run("other routes keep the shared FailedPrecondition 409", func(t *testing.T) {
		router := tpmRouter(&fakeTPMService{err: refused}, tpmGuard())

		rec := serveTPM(router, newTPMRequest(http.MethodDelete, "/api/v1/tpm/srk", ""), tpmAdminToken)

		assert.Equal(t, http.StatusConflict, rec.Code)
	})
}

func TestTPMHandlerErrors(t *testing.T) {
	t.Run("ErrTPMServiceNotAvailable", func(t *testing.T) {
		assert.Equal(t, "TPM service not available", ErrTPMServiceNotAvailable{}.Error())
	})

}
