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

package tpm

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// tpmRoute is one REST route and the TPMService RPC it must dispatch to.
// decodesBody marks the routes that read a JSON request body.
type tpmRoute struct {
	method      string
	path        string
	rpc         string
	decodesBody bool
}

// tpmRoutes is every route RegisterRoutes mounts, under /api/v1.
var tpmRoutes = []tpmRoute{
	{http.MethodGet, "/api/v1/tpm/info", "Info", false},
	{http.MethodPost, "/api/v1/tpm/provision", "Provision", true},
	{http.MethodPost, "/api/v1/tpm/clear", "Clear", true},
	{http.MethodGet, "/api/v1/tpm/capabilities", "GetCapabilities", false},
	{http.MethodGet, "/api/v1/tpm/platform", "GetPlatformAttributes", false},
	{http.MethodGet, "/api/v1/tpm/ek", "GetEK", false},
	{http.MethodPost, "/api/v1/tpm/ek", "CreateEK", true},
	{http.MethodDelete, "/api/v1/tpm/ek", "DeleteEK", true},
	{http.MethodGet, "/api/v1/tpm/ek/certificate", "GetEKCertificate", false},
	{http.MethodPost, "/api/v1/tpm/ek/certificate", "ImportEKCertificate", true},
	{http.MethodGet, "/api/v1/tpm/srk", "GetSRK", false},
	{http.MethodPost, "/api/v1/tpm/srk", "CreateSRK", true},
	{http.MethodDelete, "/api/v1/tpm/srk", "DeleteSRK", true},
	{http.MethodGet, "/api/v1/tpm/ak", "GetAK", false},
	{http.MethodPost, "/api/v1/tpm/ak", "CreateAK", true},
	{http.MethodDelete, "/api/v1/tpm/ak", "DeleteAK", true},
	{http.MethodPost, "/api/v1/tpm/seal", "Seal", true},
	{http.MethodPost, "/api/v1/tpm/unseal", "Unseal", true},
	{http.MethodPost, "/api/v1/tpm/quote", "Quote", true},
	{http.MethodPost, "/api/v1/tpm/quote/verify", "VerifyQuote", true},
	{http.MethodPost, "/api/v1/tpm/certify", "Certify", true},
	{http.MethodPost, "/api/v1/tpm/make-credential", "MakeCredential", true},
	{http.MethodPost, "/api/v1/tpm/activate-credential", "ActivateCredential", true},
	{http.MethodGet, "/api/v1/tpm/eventlog", "GetEventLog", false},
	{http.MethodGet, "/api/v1/tpm/pcrs", "GetPCRs", false},
	{http.MethodPost, "/api/v1/tpm/pcrs", "GetPCRs", true},
	{http.MethodPost, "/api/v1/tpm/pcrs/extend", "ExtendPCR", true},
	{http.MethodPost, "/api/v1/tpm/nvram", "DefineNVRAM", true},
	{http.MethodGet, "/api/v1/tpm/nvram/0x1c00002", "ReadNVRAM", true},
	{http.MethodPut, "/api/v1/tpm/nvram/0x1c00002", "WriteNVRAM", true},
	{http.MethodDelete, "/api/v1/tpm/nvram/0x1c00002", "UndefineNVRAM", true},
	{http.MethodPost, "/api/v1/tpm/random", "GetRandom", true},
}

// forwardingServer records the request each RPC receives and answers with
// resp, so a test pins both what the handler decoded from HTTP and what it
// put back on the wire. RPCs it does not override stay Unimplemented.
type forwardingServer struct {
	platformv1.UnimplementedTPMServiceServer

	resp proto.Message
	got  proto.Message
}

// forward records req and returns the canned response as T; a canned
// response of another type means the route reached the wrong RPC.
func forward[T proto.Message](s *forwardingServer, req proto.Message) (T, error) {
	s.got = req
	resp, ok := s.resp.(T)
	if !ok {
		var zero T
		return zero, status.Errorf(codes.Internal, "fake has no %T response", zero)
	}
	return resp, nil
}

func (s *forwardingServer) Provision(_ context.Context, req *platformv1.TPMProvisionRequest) (*platformv1.TPMProvisionResponse, error) {
	return forward[*platformv1.TPMProvisionResponse](s, req)
}

func (s *forwardingServer) Clear(_ context.Context, req *platformv1.TPMClearRequest) (*platformv1.TPMClearResponse, error) {
	return forward[*platformv1.TPMClearResponse](s, req)
}

func (s *forwardingServer) CreateEK(_ context.Context, req *platformv1.CreateEKRequest) (*platformv1.CreateEKResponse, error) {
	return forward[*platformv1.CreateEKResponse](s, req)
}

func (s *forwardingServer) GetEK(_ context.Context, req *platformv1.GetEKRequest) (*platformv1.GetEKResponse, error) {
	return forward[*platformv1.GetEKResponse](s, req)
}

func (s *forwardingServer) GetEKCertificate(_ context.Context, req *platformv1.GetEKCertificateRequest) (*platformv1.GetEKCertificateResponse, error) {
	return forward[*platformv1.GetEKCertificateResponse](s, req)
}

func (s *forwardingServer) ImportEKCertificate(_ context.Context, req *platformv1.ImportEKCertificateRequest) (*platformv1.ImportEKCertificateResponse, error) {
	return forward[*platformv1.ImportEKCertificateResponse](s, req)
}

func (s *forwardingServer) CreateSRK(_ context.Context, req *platformv1.CreateSRKRequest) (*platformv1.CreateSRKResponse, error) {
	return forward[*platformv1.CreateSRKResponse](s, req)
}

func (s *forwardingServer) GetSRK(_ context.Context, req *platformv1.GetSRKRequest) (*platformv1.GetSRKResponse, error) {
	return forward[*platformv1.GetSRKResponse](s, req)
}

func (s *forwardingServer) CreateAK(_ context.Context, req *platformv1.CreateAKRequest) (*platformv1.CreateAKResponse, error) {
	return forward[*platformv1.CreateAKResponse](s, req)
}

func (s *forwardingServer) GetAK(_ context.Context, req *platformv1.GetAKRequest) (*platformv1.GetAKResponse, error) {
	return forward[*platformv1.GetAKResponse](s, req)
}

func (s *forwardingServer) Seal(_ context.Context, req *platformv1.SealRequest) (*platformv1.SealResponse, error) {
	return forward[*platformv1.SealResponse](s, req)
}

func (s *forwardingServer) Unseal(_ context.Context, req *platformv1.UnsealRequest) (*platformv1.UnsealResponse, error) {
	return forward[*platformv1.UnsealResponse](s, req)
}

func (s *forwardingServer) VerifyQuote(_ context.Context, req *platformv1.VerifyQuoteRequest) (*platformv1.VerifyQuoteResponse, error) {
	return forward[*platformv1.VerifyQuoteResponse](s, req)
}

func (s *forwardingServer) GetEventLog(_ context.Context, req *platformv1.GetEventLogRequest) (*platformv1.GetEventLogResponse, error) {
	return forward[*platformv1.GetEventLogResponse](s, req)
}

func (s *forwardingServer) GetPCRs(_ context.Context, req *platformv1.GetPCRsRequest) (*platformv1.GetPCRsResponse, error) {
	return forward[*platformv1.GetPCRsResponse](s, req)
}

func (s *forwardingServer) DefineNVRAM(_ context.Context, req *platformv1.DefineNVRAMRequest) (*platformv1.DefineNVRAMResponse, error) {
	return forward[*platformv1.DefineNVRAMResponse](s, req)
}

func (s *forwardingServer) GetRandom(_ context.Context, req *platformv1.GetRandomRequest) (*platformv1.GetRandomResponse, error) {
	return forward[*platformv1.GetRandomResponse](s, req)
}

// serveRoute mounts the TPM router over server and serves one request.
func serveRoute(t *testing.T, server platformv1.TPMServiceServer, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	w := response.NewResponseWriter(logging.NewLogger(slog.LevelError, io.Discard), nil)
	parent := mux.NewRouter()
	NewTPMRouter(logging.NewLogger(slog.LevelError, io.Discard), server, w).
		RegisterRoutes(parent.PathPrefix("/api/v1").Subrouter())

	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	parent.ServeHTTP(rec, req)
	return rec
}

// envelopeOf decodes the standard response envelope.
func envelopeOf(t *testing.T, rec *httptest.ResponseRecorder) map[string]json.RawMessage {
	t.Helper()
	var envelope map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &envelope))
	return envelope
}

// A router registered without a TPM answers every route with the canonical
// SERVICE_NOT_CONFIGURED 503, never a panic or a 404.
func TestRoutes_NilServerIsServiceNotConfigured(t *testing.T) {
	for _, rt := range tpmRoutes {
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			rec := serveRoute(t, nil, rt.method, rt.path, "")

			require.Equal(t, http.StatusServiceUnavailable, rec.Code)
			envelope := envelopeOf(t, rec)
			assert.JSONEq(t, `false`, string(envelope["success"]))
			assert.JSONEq(t, `"tpm"`, string(envelope["service"]))
			assert.JSONEq(t, `"`+response.ReasonServiceNotConfigured+`"`, string(envelope["reason"]))
		})
	}
}

// Every route reaches its own RPC, and the RPC's gRPC status comes back as
// the mapped HTTP status: Unimplemented names the method that was called.
func TestRoutes_DispatchToTheirRPCAndMapItsError(t *testing.T) {
	for _, rt := range tpmRoutes {
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			rec := serveRoute(t, &platformv1.UnimplementedTPMServiceServer{}, rt.method, rt.path, "")

			require.Equal(t, http.StatusNotImplemented, rec.Code)
			envelope := envelopeOf(t, rec)
			assert.JSONEq(t, `false`, string(envelope["success"]))
			assert.Contains(t, string(envelope["error"]), "method "+rt.rpc+" not implemented")
		})
	}
}

// A body that is not JSON is a 400 before the TPM is touched.
func TestRoutes_MalformedBodyIsRejectedBeforeTheRPC(t *testing.T) {
	for _, rt := range tpmRoutes {
		if !rt.decodesBody {
			continue
		}
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			srv := &forwardingServer{}

			rec := serveRoute(t, srv, rt.method, rt.path, `{"broken":`)

			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Nil(t, srv.got, "the RPC must not run on a malformed body")
		})
	}
}

// Each handler forwards exactly the request the HTTP body describes, answers
// with its documented status, and puts the RPC response on the wire intact.
func TestRoutes_ForwardTheRequestAndReturnTheResponse(t *testing.T) {
	ed25519 := platformv1.KeyAlgorithm_KEY_ALGORITHM_ED25519
	sha256 := platformv1.PCRBank_PCR_BANK_SHA256
	ok := &platformv1.Status{Success: true, Message: "done"}

	cases := []struct {
		name       string
		method     string
		path       string
		body       string
		wantStatus int
		wantReq    proto.Message
		resp       proto.Message
	}{
		{
			name: "provision", method: http.MethodPost, path: "/api/v1/tpm/provision",
			body:       `{"ownerPassword":"own","createEk":true,"ekAttributes":{"cn":"ek","algorithm":"KEY_ALGORITHM_ED25519"}}`,
			wantStatus: http.StatusOK,
			wantReq: &platformv1.TPMProvisionRequest{
				OwnerPassword: "own", CreateEk: true,
				EkAttributes: &platformv1.KeyAttributes{Cn: "ek", Algorithm: ed25519},
			},
			resp: &platformv1.TPMProvisionResponse{Status: ok, EkPublic: []byte{1, 2, 3}},
		},
		{
			name: "clear", method: http.MethodPost, path: "/api/v1/tpm/clear",
			body:       `{"ownerPassword":"own","confirm":true}`,
			wantStatus: http.StatusOK,
			wantReq:    &platformv1.TPMClearRequest{OwnerPassword: "own", Confirm: true},
			resp:       &platformv1.TPMClearResponse{Status: ok},
		},
		{
			name: "create ek", method: http.MethodPost, path: "/api/v1/tpm/ek",
			body:       `{"persistent":true,"attributes":{"handle":2164326401}}`,
			wantStatus: http.StatusCreated,
			wantReq: &platformv1.CreateEKRequest{
				Persistent: true, Attributes: &platformv1.KeyAttributes{Handle: 0x81010001},
			},
			resp: &platformv1.CreateEKResponse{Status: ok, PublicKey: []byte{1, 2, 3}, Handle: 0x81010001},
		},
		{
			name: "get ek", method: http.MethodGet, path: "/api/v1/tpm/ek",
			wantStatus: http.StatusOK,
			wantReq:    &platformv1.GetEKRequest{},
			resp:       &platformv1.GetEKResponse{PublicKey: []byte{1, 2, 3}, Handle: 0x81010001, Algorithm: ed25519},
		},
		{
			name: "get ek certificate", method: http.MethodGet, path: "/api/v1/tpm/ek/certificate",
			wantStatus: http.StatusOK,
			wantReq:    &platformv1.GetEKCertificateRequest{},
			resp:       &platformv1.GetEKCertificateResponse{Certificate: []byte("-----BEGIN CERTIFICATE-----"), Format: "PEM"},
		},
		{
			name: "import ek certificate", method: http.MethodPost, path: "/api/v1/tpm/ek/certificate",
			body:       `{"certificate":"AQID","format":"DER","nvramIndex":29360130}`,
			wantStatus: http.StatusCreated,
			wantReq: &platformv1.ImportEKCertificateRequest{
				Certificate: []byte{1, 2, 3}, Format: "DER", NvramIndex: 0x01c00002,
			},
			resp: &platformv1.ImportEKCertificateResponse{Status: ok},
		},
		{
			name: "create srk", method: http.MethodPost, path: "/api/v1/tpm/srk",
			body:       `{"persistent":true,"parentHandle":2164326401,"parentPassword":"ekpw"}`,
			wantStatus: http.StatusCreated,
			wantReq: &platformv1.CreateSRKRequest{
				Persistent: true, ParentHandle: 0x81010001, ParentPassword: "ekpw",
			},
			resp: &platformv1.CreateSRKResponse{Status: ok, PublicKey: []byte{4}, Handle: 0x81000001},
		},
		{
			name: "get srk", method: http.MethodGet, path: "/api/v1/tpm/srk",
			wantStatus: http.StatusOK,
			wantReq:    &platformv1.GetSRKRequest{},
			resp:       &platformv1.GetSRKResponse{PublicKey: []byte{4}, Handle: 0x81000001, Algorithm: ed25519},
		},
		{
			name: "create ak", method: http.MethodPost, path: "/api/v1/tpm/ak",
			body:       `{"parentHandle":2164260865,"attributes":{"cn":"ak"}}`,
			wantStatus: http.StatusCreated,
			wantReq: &platformv1.CreateAKRequest{
				ParentHandle: 0x81000001, Attributes: &platformv1.KeyAttributes{Cn: "ak"},
			},
			resp: &platformv1.CreateAKResponse{Status: ok, Handle: 0x81010002, CredentialBlob: []byte{4, 5}},
		},
		{
			name: "get ak", method: http.MethodGet, path: "/api/v1/tpm/ak",
			wantStatus: http.StatusOK,
			wantReq:    &platformv1.GetAKRequest{},
			resp:       &platformv1.GetAKResponse{PublicKey: []byte{5}, Handle: 0x81010002},
		},
		{
			name: "seal", method: http.MethodPost, path: "/api/v1/tpm/seal",
			body:       `{"data":"c2VjcmV0","cn":"disk","pcrIndices":[0,7],"pcrBank":"PCR_BANK_SHA256","overwrite":true}`,
			wantStatus: http.StatusOK,
			wantReq: &platformv1.SealRequest{
				Data: []byte("secret"), Cn: "disk", PcrIndices: []uint32{0, 7}, PcrBank: sha256, Overwrite: true,
			},
			resp: &platformv1.SealResponse{Status: ok, SealedData: []byte{9}},
		},
		{
			name: "unseal", method: http.MethodPost, path: "/api/v1/tpm/unseal",
			body:       `{"cn":"disk","password":"pw","pcrIndices":[7]}`,
			wantStatus: http.StatusOK,
			wantReq:    &platformv1.UnsealRequest{Cn: "disk", Password: "pw", PcrIndices: []uint32{7}},
			resp:       &platformv1.UnsealResponse{Status: ok, Data: []byte("secret")},
		},
		{
			name: "verify quote", method: http.MethodPost, path: "/api/v1/tpm/quote/verify",
			body:       `{"quote":"AQID","signature":"BAU=","nonce":"Bg==","signatureAlgorithm":"SHA256-RSAPSS"}`,
			wantStatus: http.StatusOK,
			wantReq: &platformv1.VerifyQuoteRequest{
				Quote: []byte{1, 2, 3}, Signature: []byte{4, 5}, Nonce: []byte{6}, SignatureAlgorithm: "SHA256-RSAPSS",
			},
			resp: &platformv1.VerifyQuoteResponse{Status: ok, Verified: true, Message: "quote verified"},
		},
		{
			name: "event log", method: http.MethodGet, path: "/api/v1/tpm/eventlog",
			wantStatus: http.StatusOK,
			wantReq:    &platformv1.GetEventLogRequest{},
			resp:       &platformv1.GetEventLogResponse{EventLog: []byte{1}, Format: "binary", EventCount: 1},
		},
		{
			name: "pcrs by GET", method: http.MethodGet, path: "/api/v1/tpm/pcrs",
			wantStatus: http.StatusOK,
			wantReq:    &platformv1.GetPCRsRequest{},
			resp: &platformv1.GetPCRsResponse{PcrValues: []*platformv1.PCRValue{
				{Index: 7, Bank: sha256, Value: []byte{0xaa}},
			}},
		},
		{
			name: "pcrs by POST with a selection", method: http.MethodPost, path: "/api/v1/tpm/pcrs",
			body:       `{"indices":[0,7],"bank":"PCR_BANK_SHA256"}`,
			wantStatus: http.StatusOK,
			wantReq:    &platformv1.GetPCRsRequest{Indices: []uint32{0, 7}, Bank: sha256},
			resp: &platformv1.GetPCRsResponse{PcrValues: []*platformv1.PCRValue{
				{Index: 0, Bank: sha256, Value: []byte{0xbb}},
			}},
		},
		{
			name: "pcrs by POST without a body", method: http.MethodPost, path: "/api/v1/tpm/pcrs",
			wantStatus: http.StatusOK,
			wantReq:    &platformv1.GetPCRsRequest{},
			resp:       &platformv1.GetPCRsResponse{},
		},
		{
			name: "define nvram", method: http.MethodPost, path: "/api/v1/tpm/nvram",
			body:       `{"index":29360130,"size":64,"attributes":["AUTHWRITE","AUTHREAD"],"parentPassword":"own"}`,
			wantStatus: http.StatusCreated,
			wantReq: &platformv1.DefineNVRAMRequest{
				Index: 0x01c00002, Size: 64, Attributes: []string{"AUTHWRITE", "AUTHREAD"}, ParentPassword: "own",
			},
			resp: &platformv1.DefineNVRAMResponse{Status: ok},
		},
		{
			name: "random", method: http.MethodPost, path: "/api/v1/tpm/random",
			body:       `{"numBytes":4}`,
			wantStatus: http.StatusOK,
			wantReq:    &platformv1.GetRandomRequest{NumBytes: 4},
			resp:       &platformv1.GetRandomResponse{RandomBytes: []byte{1, 2, 3, 4}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := &forwardingServer{resp: tc.resp}

			rec := serveRoute(t, srv, tc.method, tc.path, tc.body)

			require.Equal(t, tc.wantStatus, rec.Code, rec.Body.String())
			assert.True(t, proto.Equal(tc.wantReq, srv.got), "forwarded %v, want %v", srv.got, tc.wantReq)

			envelope := envelopeOf(t, rec)
			assert.JSONEq(t, `true`, string(envelope["success"]))
			onWire := tc.resp.ProtoReflect().New().Interface()
			require.NoError(t, protojson.Unmarshal(envelope["payload"], onWire))
			assert.True(t, proto.Equal(tc.resp, onWire), "payload %v, want %v", onWire, tc.resp)
		})
	}
}

// GET /srk?handle= selects the SRK by handle, in hex (either prefix case)
// or decimal; anything that is not a 32-bit handle is a 400 and never
// reaches the TPM.
func TestGetSRK_HandleQuery(t *testing.T) {
	accepted := map[string]uint32{
		"0x81000001": 0x81000001,
		"0X81000001": 0x81000001,
		"2164260865": 0x81000001,
	}
	for raw, want := range accepted {
		t.Run("accepts "+raw, func(t *testing.T) {
			srv := &forwardingServer{resp: &platformv1.GetSRKResponse{Handle: want}}

			rec := serveRoute(t, srv, http.MethodGet, "/api/v1/tpm/srk?handle="+raw, "")

			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			assert.True(t, proto.Equal(&platformv1.GetSRKRequest{Handle: want}, srv.got), "forwarded %v", srv.got)
		})
	}

	for _, raw := range []string{"srk", "0x", "0x1FFFFFFFF", "-1", "0x8100zz01"} {
		t.Run("rejects "+raw, func(t *testing.T) {
			srv := &forwardingServer{resp: &platformv1.GetSRKResponse{}}

			rec := serveRoute(t, srv, http.MethodGet, "/api/v1/tpm/srk?handle="+raw, "")

			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Nil(t, srv.got)
		})
	}
}
