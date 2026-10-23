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

package idevid_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// recordingServer is the service layer behind every route. It records the
// RPC it was asked for and the request it received, then answers with reply,
// or with err when set.
type recordingServer struct {
	platformv1.UnimplementedIDevIDServiceServer

	reply proto.Message
	err   error

	rpc string
	req proto.Message
}

func answer[T proto.Message](s *recordingServer, rpc string, req proto.Message) (T, error) {
	s.rpc, s.req = rpc, req
	var zero T
	if s.err != nil {
		return zero, s.err
	}
	return s.reply.(T), nil
}

func (s *recordingServer) GenerateIDevID(_ context.Context, req *platformv1.GenerateIDevIDRequest) (*platformv1.GenerateIDevIDResponse, error) {
	return answer[*platformv1.GenerateIDevIDResponse](s, "GenerateIDevID", req)
}

func (s *recordingServer) GetIDevIDInfo(_ context.Context, req *platformv1.GetIDevIDInfoRequest) (*platformv1.GetIDevIDInfoResponse, error) {
	return answer[*platformv1.GetIDevIDInfoResponse](s, "GetIDevIDInfo", req)
}

func (s *recordingServer) HasIDevID(_ context.Context, req *platformv1.HasIDevIDRequest) (*platformv1.HasIDevIDResponse, error) {
	return answer[*platformv1.HasIDevIDResponse](s, "HasIDevID", req)
}

func (s *recordingServer) DeleteIDevID(_ context.Context, req *platformv1.DeleteIDevIDRequest) (*platformv1.DeleteIDevIDResponse, error) {
	return answer[*platformv1.DeleteIDevIDResponse](s, "DeleteIDevID", req)
}

func (s *recordingServer) GenerateIAK(_ context.Context, req *platformv1.GenerateIAKRequest) (*platformv1.GenerateIAKResponse, error) {
	return answer[*platformv1.GenerateIAKResponse](s, "GenerateIAK", req)
}

func (s *recordingServer) GetIAKInfo(_ context.Context, req *platformv1.GetIAKInfoRequest) (*platformv1.GetIAKInfoResponse, error) {
	return answer[*platformv1.GetIAKInfoResponse](s, "GetIAKInfo", req)
}

func (s *recordingServer) HasIAK(_ context.Context, req *platformv1.HasIAKRequest) (*platformv1.HasIAKResponse, error) {
	return answer[*platformv1.HasIAKResponse](s, "HasIAK", req)
}

func (s *recordingServer) DeleteIAK(_ context.Context, req *platformv1.DeleteIAKRequest) (*platformv1.DeleteIAKResponse, error) {
	return answer[*platformv1.DeleteIAKResponse](s, "DeleteIAK", req)
}

func (s *recordingServer) CreateIDevIDCSR(_ context.Context, req *platformv1.CreateIDevIDCSRRequest) (*platformv1.CreateIDevIDCSRResponse, error) {
	return answer[*platformv1.CreateIDevIDCSRResponse](s, "CreateIDevIDCSR", req)
}

func (s *recordingServer) CreateIAKCSR(_ context.Context, req *platformv1.CreateIAKCSRRequest) (*platformv1.CreateIAKCSRResponse, error) {
	return answer[*platformv1.CreateIAKCSRResponse](s, "CreateIAKCSR", req)
}

func (s *recordingServer) CreateLDevID(_ context.Context, req *platformv1.CreateLDevIDRequest) (*platformv1.CreateLDevIDResponse, error) {
	return answer[*platformv1.CreateLDevIDResponse](s, "CreateLDevID", req)
}

func (s *recordingServer) InstallIDevIDCertificate(_ context.Context, req *platformv1.InstallIDevIDCertificateRequest) (*platformv1.InstallIDevIDCertificateResponse, error) {
	return answer[*platformv1.InstallIDevIDCertificateResponse](s, "InstallIDevIDCertificate", req)
}

func (s *recordingServer) InstallIAKCertificate(_ context.Context, req *platformv1.InstallIAKCertificateRequest) (*platformv1.InstallIAKCertificateResponse, error) {
	return answer[*platformv1.InstallIAKCertificateResponse](s, "InstallIAKCertificate", req)
}

func (s *recordingServer) GetIDevIDCertificate(_ context.Context, req *platformv1.GetIDevIDCertificateRequest) (*platformv1.GetIDevIDCertificateResponse, error) {
	return answer[*platformv1.GetIDevIDCertificateResponse](s, "GetIDevIDCertificate", req)
}

func (s *recordingServer) GetIAKCertificate(_ context.Context, req *platformv1.GetIAKCertificateRequest) (*platformv1.GetIAKCertificateResponse, error) {
	return answer[*platformv1.GetIAKCertificateResponse](s, "GetIAKCertificate", req)
}

func (s *recordingServer) DeleteIDevIDCertificate(_ context.Context, req *platformv1.DeleteIDevIDCertificateRequest) (*platformv1.DeleteIDevIDCertificateResponse, error) {
	return answer[*platformv1.DeleteIDevIDCertificateResponse](s, "DeleteIDevIDCertificate", req)
}

func (s *recordingServer) DeleteIAKCertificate(_ context.Context, req *platformv1.DeleteIAKCertificateRequest) (*platformv1.DeleteIAKCertificateResponse, error) {
	return answer[*platformv1.DeleteIAKCertificateResponse](s, "DeleteIAKCertificate", req)
}

func (s *recordingServer) GetDeviceAttributes(_ context.Context, req *platformv1.GetDeviceAttributesRequest) (*platformv1.GetDeviceAttributesResponse, error) {
	return answer[*platformv1.GetDeviceAttributesResponse](s, "GetDeviceAttributes", req)
}

func (s *recordingServer) FlushTransientContexts(_ context.Context, req *platformv1.FlushTransientContextsRequest) (*platformv1.FlushTransientContextsResponse, error) {
	return answer[*platformv1.FlushTransientContextsResponse](s, "FlushTransientContexts", req)
}

func (s *recordingServer) ActivateCredential(_ context.Context, req *platformv1.ActivateCredentialRequest) (*platformv1.ActivateCredentialResponse, error) {
	return answer[*platformv1.ActivateCredentialResponse](s, "ActivateCredential", req)
}

func ok(message string) *platformv1.Status {
	return &platformv1.Status{Success: true, Message: message}
}

// route is one REST endpoint: the request a client sends, the RPC and
// request the service must receive, and the reply the client must get back.
type route struct {
	method string
	path   string
	body   string

	rpc     string
	wantReq proto.Message
	reply   proto.Message
	status  int
}

// routes is every service-backed endpoint RegisterRoutes serves. Bytes
// fields travel base64-encoded in protojson: "Y2VydA==" is "cert",
// "YmxvYg==" is "blob" and "c2VjcmV0" is "secret".
var routes = []route{
	{
		method: http.MethodPost, path: "/api/v1/idevid/generate",
		body: `{"config": {"handle": 2164326400, "subjectCommonName": "dev-1", "overwrite": true}}`,
		rpc:  "GenerateIDevID",
		wantReq: &platformv1.GenerateIDevIDRequest{Config: &platformv1.IDevIDConfig{
			Handle: 2164326400, SubjectCommonName: "dev-1", Overwrite: true,
		}},
		reply:  &platformv1.GenerateIDevIDResponse{Status: ok("idevid generated")},
		status: http.StatusCreated,
	},
	{
		method: http.MethodGet, path: "/api/v1/idevid",
		rpc:     "GetIDevIDInfo",
		wantReq: &platformv1.GetIDevIDInfoRequest{},
		reply: &platformv1.GetIDevIDInfoResponse{KeyInfo: &platformv1.DeviceKeyInfo{
			Handle: 2164326400, HasCertificate: true,
		}},
		status: http.StatusOK,
	},
	{
		method: http.MethodGet, path: "/api/v1/idevid/info",
		rpc:     "GetIDevIDInfo",
		wantReq: &platformv1.GetIDevIDInfoRequest{},
		reply:   &platformv1.GetIDevIDInfoResponse{KeyInfo: &platformv1.DeviceKeyInfo{Handle: 2164326400}},
		status:  http.StatusOK,
	},
	{
		method: http.MethodGet, path: "/api/v1/idevid/exists",
		rpc:     "HasIDevID",
		wantReq: &platformv1.HasIDevIDRequest{},
		reply:   &platformv1.HasIDevIDResponse{Exists: true},
		status:  http.StatusOK,
	},
	{
		method: http.MethodDelete, path: "/api/v1/idevid",
		rpc:     "DeleteIDevID",
		wantReq: &platformv1.DeleteIDevIDRequest{},
		reply:   &platformv1.DeleteIDevIDResponse{Status: ok("idevid deleted")},
		status:  http.StatusOK,
	},
	{
		method: http.MethodDelete, path: "/api/v1/tpm/idevid",
		rpc:     "DeleteIDevID",
		wantReq: &platformv1.DeleteIDevIDRequest{},
		reply:   &platformv1.DeleteIDevIDResponse{Status: ok("idevid deleted")},
		status:  http.StatusOK,
	},
	{
		method: http.MethodPost, path: "/api/v1/idevid/csr",
		body:    `{"template": {"commonName": "dev-1", "dnsNames": ["dev-1.local"]}}`,
		rpc:     "CreateIDevIDCSR",
		wantReq: &platformv1.CreateIDevIDCSRRequest{Template: &platformv1.CSRTemplate{CommonName: "dev-1", DnsNames: []string{"dev-1.local"}}},
		reply:   &platformv1.CreateIDevIDCSRResponse{Status: ok("csr created"), CsrPem: []byte("idevid-csr")},
		status:  http.StatusOK,
	},
	{
		method: http.MethodGet, path: "/api/v1/idevid/certificate",
		rpc:     "GetIDevIDCertificate",
		wantReq: &platformv1.GetIDevIDCertificateRequest{},
		reply:   &platformv1.GetIDevIDCertificateResponse{Certificate: &platformv1.DeviceIdentityCertificate{SubjectCn: "dev-1", SerialNumber: "01"}},
		status:  http.StatusOK,
	},
	{
		method: http.MethodPost, path: "/api/v1/idevid/certificate",
		body:    `{"certificatePem": "Y2VydA=="}`,
		rpc:     "InstallIDevIDCertificate",
		wantReq: &platformv1.InstallIDevIDCertificateRequest{CertificatePem: []byte("cert")},
		reply:   &platformv1.InstallIDevIDCertificateResponse{Status: ok("certificate installed")},
		status:  http.StatusCreated,
	},
	{
		method: http.MethodDelete, path: "/api/v1/idevid/certificate",
		rpc:     "DeleteIDevIDCertificate",
		wantReq: &platformv1.DeleteIDevIDCertificateRequest{},
		reply:   &platformv1.DeleteIDevIDCertificateResponse{Status: ok("certificate deleted")},
		status:  http.StatusOK,
	},
	{
		method: http.MethodPost, path: "/api/v1/idevid/ldevid",
		body:    `{"handle": 2164326402, "profile": "tls"}`,
		rpc:     "CreateLDevID",
		wantReq: &platformv1.CreateLDevIDRequest{Handle: 2164326402, Profile: "tls"},
		reply:   &platformv1.CreateLDevIDResponse{Status: ok("ldevid created"), CertificatePem: []byte("ldevid-cert")},
		status:  http.StatusCreated,
	},
	{
		method: http.MethodGet, path: "/api/v1/idevid/iak",
		rpc:     "GetIAKInfo",
		wantReq: &platformv1.GetIAKInfoRequest{},
		reply:   &platformv1.GetIAKInfoResponse{KeyInfo: &platformv1.DeviceKeyInfo{Handle: 2164326401}},
		status:  http.StatusOK,
	},
	{
		method: http.MethodPost, path: "/api/v1/idevid/iak/generate",
		body:    `{"config": {"handle": 2164326401, "hierarchy": "endorsement"}}`,
		rpc:     "GenerateIAK",
		wantReq: &platformv1.GenerateIAKRequest{Config: &platformv1.IAKConfig{Handle: 2164326401, Hierarchy: "endorsement"}},
		reply:   &platformv1.GenerateIAKResponse{Status: ok("iak generated")},
		status:  http.StatusCreated,
	},
	{
		method: http.MethodGet, path: "/api/v1/idevid/iak/exists",
		rpc:     "HasIAK",
		wantReq: &platformv1.HasIAKRequest{},
		reply:   &platformv1.HasIAKResponse{Exists: true},
		status:  http.StatusOK,
	},
	{
		method: http.MethodDelete, path: "/api/v1/idevid/iak",
		rpc:     "DeleteIAK",
		wantReq: &platformv1.DeleteIAKRequest{},
		reply:   &platformv1.DeleteIAKResponse{Status: ok("iak deleted")},
		status:  http.StatusOK,
	},
	{
		method: http.MethodDelete, path: "/api/v1/tpm/iak",
		rpc:     "DeleteIAK",
		wantReq: &platformv1.DeleteIAKRequest{},
		reply:   &platformv1.DeleteIAKResponse{Status: ok("iak deleted")},
		status:  http.StatusOK,
	},
	{
		method: http.MethodPost, path: "/api/v1/idevid/iak/csr",
		body:    `{"template": {"commonName": "dev-1-iak"}}`,
		rpc:     "CreateIAKCSR",
		wantReq: &platformv1.CreateIAKCSRRequest{Template: &platformv1.CSRTemplate{CommonName: "dev-1-iak"}},
		reply:   &platformv1.CreateIAKCSRResponse{Status: ok("csr created"), CsrPem: []byte("iak-csr")},
		status:  http.StatusOK,
	},
	{
		method: http.MethodGet, path: "/api/v1/idevid/iak/certificate",
		rpc:     "GetIAKCertificate",
		wantReq: &platformv1.GetIAKCertificateRequest{},
		reply:   &platformv1.GetIAKCertificateResponse{Certificate: &platformv1.DeviceIdentityCertificate{SubjectCn: "dev-1-iak"}},
		status:  http.StatusOK,
	},
	{
		method: http.MethodPost, path: "/api/v1/idevid/iak/certificate",
		body:    `{"certificatePem": "Y2VydA=="}`,
		rpc:     "InstallIAKCertificate",
		wantReq: &platformv1.InstallIAKCertificateRequest{CertificatePem: []byte("cert")},
		reply:   &platformv1.InstallIAKCertificateResponse{Status: ok("certificate installed")},
		status:  http.StatusCreated,
	},
	{
		method: http.MethodDelete, path: "/api/v1/idevid/iak/certificate",
		rpc:     "DeleteIAKCertificate",
		wantReq: &platformv1.DeleteIAKCertificateRequest{},
		reply:   &platformv1.DeleteIAKCertificateResponse{Status: ok("certificate deleted")},
		status:  http.StatusOK,
	},
	{
		method: http.MethodGet, path: "/api/v1/idevid/attributes",
		rpc:     "GetDeviceAttributes",
		wantReq: &platformv1.GetDeviceAttributesRequest{},
		reply:   &platformv1.GetDeviceAttributesResponse{Attributes: &platformv1.TCGDeviceAttributes{TpmManufacturer: "IBM", PlatformSerial: "SN-1"}},
		status:  http.StatusOK,
	},
	{
		method: http.MethodPost, path: "/api/v1/idevid/flush",
		rpc:     "FlushTransientContexts",
		wantReq: &platformv1.FlushTransientContextsRequest{},
		reply:   &platformv1.FlushTransientContextsResponse{Status: ok("flushed"), FlushedCount: 3},
		status:  http.StatusOK,
	},
	{
		method: http.MethodPost, path: "/api/v1/idevid/activate-credential",
		body:    `{"credentialBlob": "YmxvYg==", "secret": "c2VjcmV0"}`,
		rpc:     "ActivateCredential",
		wantReq: &platformv1.ActivateCredentialRequest{CredentialBlob: []byte("blob"), Secret: []byte("secret")},
		reply:   &platformv1.ActivateCredentialResponse{Status: ok("activated"), DecryptedSecret: []byte("secret")},
		status:  http.StatusOK,
	},
}

// envelope is the response writer's JSON envelope with the payload kept raw,
// so a proto payload can be decoded with protojson.
type envelope struct {
	Code    int             `json:"code"`
	Error   string          `json:"error"`
	Success bool            `json:"success"`
	Payload json.RawMessage `json:"payload"`
}

func serve(t *testing.T, server platformv1.IDevIDServiceServer, method, path, body string) (*httptest.ResponseRecorder, envelope) {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	rec := httptest.NewRecorder()
	newServedRouter(server).ServeHTTP(rec, req)

	var env envelope
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env), rec.Body.String())
	return rec, env
}

func TestRoutes_ForwardTheRequestAndAnswerWithTheServiceReply(t *testing.T) {
	for _, tc := range routes {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			server := &recordingServer{reply: tc.reply}
			rec, env := serve(t, server, tc.method, tc.path, tc.body)

			require.Equal(t, tc.status, rec.Code, rec.Body.String())
			assert.Equal(t, tc.status, env.Code)
			assert.True(t, env.Success)
			assert.Empty(t, env.Error)

			assert.Equal(t, tc.rpc, server.rpc)
			assert.True(t, proto.Equal(tc.wantReq, server.req), "service received %v, want %v", server.req, tc.wantReq)

			got := tc.reply.ProtoReflect().New().Interface()
			require.NoError(t, protojson.Unmarshal(env.Payload, got), string(env.Payload))
			assert.True(t, proto.Equal(tc.reply, got), "payload %v, want %v", got, tc.reply)
		})
	}
}

func TestRoutes_MapTheServiceErrorToItsHTTPStatus(t *testing.T) {
	cases := []struct {
		code   codes.Code
		status int
	}{
		{codes.NotFound, http.StatusNotFound},
		{codes.InvalidArgument, http.StatusBadRequest},
		{codes.Unavailable, http.StatusServiceUnavailable},
		{codes.Internal, http.StatusInternalServerError},
	}
	for _, tc := range routes {
		for _, c := range cases {
			t.Run(tc.method+" "+tc.path+" "+c.code.String(), func(t *testing.T) {
				server := &recordingServer{err: status.Error(c.code, "tpm said no")}
				rec, env := serve(t, server, tc.method, tc.path, tc.body)

				require.Equal(t, c.status, rec.Code, rec.Body.String())
				assert.Equal(t, tc.rpc, server.rpc)
				assert.False(t, env.Success)
				assert.Contains(t, env.Error, "tpm said no")
			})
		}
	}
}

func TestRoutes_RejectAMalformedBodyBeforeTheService(t *testing.T) {
	for _, tc := range routes {
		if tc.body == "" {
			continue
		}
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			server := &recordingServer{reply: tc.reply}
			rec, env := serve(t, server, tc.method, tc.path, `{"config": `)

			require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			assert.False(t, env.Success)
			assert.NotEmpty(t, env.Error)
			assert.Empty(t, server.rpc, "a malformed body must not reach the service")
		})
	}
}

func TestRoutes_NoServiceWiredIs503(t *testing.T) {
	for _, tc := range routes {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			rec, env := serve(t, nil, tc.method, tc.path, tc.body)

			require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
			assert.False(t, env.Success)
			assert.Contains(t, env.Error, "idevid service is not available")
		})
	}
}

// GetExpiringIDevIDs answers count=0 whether or not a service is wired, so
// the dashboard renders without the renewal banner instead of failing.
func TestGetExpiringIDevIDs_AnswersZeroWithOrWithoutAService(t *testing.T) {
	servers := map[string]platformv1.IDevIDServiceServer{
		"wired":   &recordingServer{err: status.Error(codes.Internal, "must not be called")},
		"unwired": nil,
	}
	for name, server := range servers {
		t.Run(name, func(t *testing.T) {
			rec, env := serve(t, server, http.MethodGet, "/api/v1/idevid/expiring", "")

			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			assert.True(t, env.Success)
			assert.JSONEq(t, `{"count": 0}`, string(env.Payload))
		})
	}
	assert.Empty(t, servers["wired"].(*recordingServer).rpc)
}
