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

package eab

import (
	"context"
	"encoding/json"
	"errors"
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
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/internal/protorest"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

var testCredential = &platformv1.EABCredential{
	Id:       42,
	KeyId:    "kid-1",
	HmacKey:  "hmac-secret",
	TenantId: "t1",
	Status:   platformv1.EABCredentialStatus_EAB_CREDENTIAL_STATUS_ACTIVE,
}

// fakeEABServer records the method and request each handler forwards, and
// answers with a fixed response, or with err when it is set.
type fakeEABServer struct {
	platformv1.UnimplementedEABServiceServer
	err   error
	calls []string
	got   proto.Message
}

func (s *fakeEABServer) record(method string, req proto.Message) error {
	s.calls = append(s.calls, method)
	s.got = req
	return s.err
}

func (s *fakeEABServer) ListCredentials(
	_ context.Context, req *platformv1.ListEABCredentialsRequest,
) (*platformv1.ListEABCredentialsResponse, error) {
	if err := s.record("ListCredentials", req); err != nil {
		return nil, err
	}
	return &platformv1.ListEABCredentialsResponse{Credentials: []*platformv1.EABCredential{testCredential}, Total: 1}, nil
}

func (s *fakeEABServer) CreateCredential(
	_ context.Context, req *platformv1.CreateEABCredentialRequest,
) (*platformv1.CreateEABCredentialResponse, error) {
	if err := s.record("CreateCredential", req); err != nil {
		return nil, err
	}
	return &platformv1.CreateEABCredentialResponse{Credential: testCredential}, nil
}

func (s *fakeEABServer) GetCredential(
	_ context.Context, req *platformv1.GetEABCredentialRequest,
) (*platformv1.GetEABCredentialResponse, error) {
	if err := s.record("GetCredential", req); err != nil {
		return nil, err
	}
	return &platformv1.GetEABCredentialResponse{Credential: testCredential}, nil
}

func (s *fakeEABServer) GetCredentialByKeyID(
	_ context.Context, req *platformv1.GetEABCredentialByKeyIDRequest,
) (*platformv1.GetEABCredentialResponse, error) {
	if err := s.record("GetCredentialByKeyID", req); err != nil {
		return nil, err
	}
	return &platformv1.GetEABCredentialResponse{Credential: testCredential}, nil
}

func (s *fakeEABServer) DeleteCredential(
	_ context.Context, req *platformv1.DeleteEABCredentialRequest,
) (*platformv1.DeleteEABCredentialResponse, error) {
	if err := s.record("DeleteCredential", req); err != nil {
		return nil, err
	}
	return &platformv1.DeleteEABCredentialResponse{}, nil
}

func (s *fakeEABServer) RevokeCredential(
	_ context.Context, req *platformv1.RevokeEABCredentialRequest,
) (*platformv1.RevokeEABCredentialResponse, error) {
	if err := s.record("RevokeCredential", req); err != nil {
		return nil, err
	}
	return &platformv1.RevokeEABCredentialResponse{}, nil
}

func (s *fakeEABServer) MarkCredentialUsed(
	_ context.Context, req *platformv1.MarkEABCredentialUsedRequest,
) (*platformv1.MarkEABCredentialUsedResponse, error) {
	if err := s.record("MarkCredentialUsed", req); err != nil {
		return nil, err
	}
	return &platformv1.MarkEABCredentialUsedResponse{}, nil
}

func (s *fakeEABServer) GetCredentialQRCode(
	_ context.Context, req *platformv1.GetEABCredentialQRCodeRequest,
) (*platformv1.GetEABCredentialQRCodeResponse, error) {
	if err := s.record("GetCredentialQRCode", req); err != nil {
		return nil, err
	}
	return &platformv1.GetEABCredentialQRCodeResponse{QrCode: []byte("png-bytes"), ContentType: "image/png"}, nil
}

func (s *fakeEABServer) GetEnrollmentURL(
	_ context.Context, req *platformv1.GetEABEnrollmentURLRequest,
) (*platformv1.GetEABEnrollmentURLResponse, error) {
	if err := s.record("GetEnrollmentURL", req); err != nil {
		return nil, err
	}
	return &platformv1.GetEABEnrollmentURLResponse{Url: "https://ca.example/enroll?kid=kid-1"}, nil
}

func (s *fakeEABServer) ValidateCredential(
	_ context.Context, req *platformv1.ValidateEABCredentialRequest,
) (*platformv1.ValidateEABCredentialResponse, error) {
	if err := s.record("ValidateCredential", req); err != nil {
		return nil, err
	}
	return &platformv1.ValidateEABCredentialResponse{Valid: true, Credential: testCredential}, nil
}

func (s *fakeEABServer) CleanupExpiredCredentials(
	_ context.Context, req *platformv1.CleanupExpiredEABCredentialsRequest,
) (*platformv1.CleanupExpiredEABCredentialsResponse, error) {
	if err := s.record("CleanupExpiredCredentials", req); err != nil {
		return nil, err
	}
	return &platformv1.CleanupExpiredEABCredentialsResponse{DeletedCount: 3}, nil
}

// envelope is the REST response envelope with the payload kept raw, so a
// test can decode it back into the proto the handler wrote.
type envelope struct {
	Code    int             `json:"code"`
	Error   string          `json:"error"`
	Success bool            `json:"success"`
	Payload json.RawMessage `json:"payload"`
}

func routerWith(server platformv1.EABServiceServer) *mux.Router {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	parent := mux.NewRouter()
	NewEABRouter(logger, server, response.NewResponseWriter(logger, nil)).
		RegisterRoutes(parent.PathPrefix("/api/v1").Subrouter())
	return parent
}

func serve(t *testing.T, parent *mux.Router, method, path, body string) (int, envelope) {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	rec := httptest.NewRecorder()
	parent.ServeHTTP(rec, httptest.NewRequest(method, path, reader))
	var env envelope
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env), rec.Body.String())
	return rec.Code, env
}

// route names every EAB endpoint once, with a path that reaches its handler.
type route struct {
	method, path string
}

var allRoutes = map[string]route{
	"ListCredentials":           {http.MethodGet, "/api/v1/eab/credentials"},
	"CreateCredential":          {http.MethodPost, "/api/v1/eab/credentials"},
	"GetCredential":             {http.MethodGet, "/api/v1/eab/credentials/42"},
	"GetCredentialByKeyID":      {http.MethodGet, "/api/v1/eab/credentials/key/kid-1"},
	"DeleteCredential":          {http.MethodDelete, "/api/v1/eab/credentials/42"},
	"RevokeCredential":          {http.MethodPost, "/api/v1/eab/credentials/42/revoke"},
	"MarkCredentialUsed":        {http.MethodPost, "/api/v1/eab/credentials/42/used"},
	"GetCredentialQRCode":       {http.MethodGet, "/api/v1/eab/credentials/42/qrcode"},
	"GetEnrollmentURL":          {http.MethodGet, "/api/v1/eab/credentials/42/url"},
	"ValidateCredential":        {http.MethodPost, "/api/v1/eab/credentials/validate"},
	"CleanupExpiredCredentials": {http.MethodPost, "/api/v1/eab/credentials/cleanup"},
}

func TestHandlers_ForwardRequestAndWriteResponse(t *testing.T) {
	cases := []struct {
		name       string
		method     string
		path       string
		body       string
		wantStatus int
		wantCall   string
		wantReq    proto.Message
		wantResp   proto.Message
	}{
		{
			name:   "list with every filter",
			method: http.MethodGet,
			path: "/api/v1/eab/credentials?tenant_id=t1&profile_id=5&active_only=true" +
				"&status=revoked&page=2&page_size=10",
			wantStatus: http.StatusOK,
			wantCall:   "ListCredentials",
			wantReq: &platformv1.ListEABCredentialsRequest{
				TenantId:     "t1",
				ProfileId:    5,
				ActiveOnly:   true,
				StatusFilter: platformv1.EABCredentialStatus_EAB_CREDENTIAL_STATUS_REVOKED,
				Pagination:   &platformv1.PaginationRequest{Page: 2, PageSize: 10},
			},
			wantResp: &platformv1.ListEABCredentialsResponse{Credentials: []*platformv1.EABCredential{testCredential}, Total: 1},
		},
		{
			name:       "list with the enum-name status and no pagination",
			method:     http.MethodGet,
			path:       "/api/v1/eab/credentials?status=EAB_CREDENTIAL_STATUS_USED",
			wantStatus: http.StatusOK,
			wantCall:   "ListCredentials",
			wantReq: &platformv1.ListEABCredentialsRequest{
				StatusFilter: platformv1.EABCredentialStatus_EAB_CREDENTIAL_STATUS_USED,
			},
			wantResp: &platformv1.ListEABCredentialsResponse{Credentials: []*platformv1.EABCredential{testCredential}, Total: 1},
		},
		{
			name:       "list page size alone sets pagination",
			method:     http.MethodGet,
			path:       "/api/v1/eab/credentials?page_size=25",
			wantStatus: http.StatusOK,
			wantCall:   "ListCredentials",
			wantReq: &platformv1.ListEABCredentialsRequest{
				Pagination: &platformv1.PaginationRequest{PageSize: 25},
			},
			wantResp: &platformv1.ListEABCredentialsResponse{Credentials: []*platformv1.EABCredential{testCredential}, Total: 1},
		},
		{
			name:       "create answers 201",
			method:     http.MethodPost,
			path:       "/api/v1/eab/credentials",
			body:       `{"profileId":"3","tenantId":"t1","expiresInSeconds":"3600"}`,
			wantStatus: http.StatusCreated,
			wantCall:   "CreateCredential",
			wantReq:    &platformv1.CreateEABCredentialRequest{ProfileId: 3, TenantId: "t1", ExpiresInSeconds: 3600},
			wantResp:   &platformv1.CreateEABCredentialResponse{Credential: testCredential},
		},
		{
			name:       "get by id",
			method:     http.MethodGet,
			path:       "/api/v1/eab/credentials/42",
			wantStatus: http.StatusOK,
			wantCall:   "GetCredential",
			wantReq:    &platformv1.GetEABCredentialRequest{CredentialId: 42},
			wantResp:   &platformv1.GetEABCredentialResponse{Credential: testCredential},
		},
		{
			name:       "get by key id",
			method:     http.MethodGet,
			path:       "/api/v1/eab/credentials/key/kid-1",
			wantStatus: http.StatusOK,
			wantCall:   "GetCredentialByKeyID",
			wantReq:    &platformv1.GetEABCredentialByKeyIDRequest{KeyId: "kid-1"},
			wantResp:   &platformv1.GetEABCredentialResponse{Credential: testCredential},
		},
		{
			name:       "delete",
			method:     http.MethodDelete,
			path:       "/api/v1/eab/credentials/42",
			wantStatus: http.StatusOK,
			wantCall:   "DeleteCredential",
			wantReq:    &platformv1.DeleteEABCredentialRequest{CredentialId: 42},
			wantResp:   &platformv1.DeleteEABCredentialResponse{},
		},
		{
			name:       "revoke takes the id from the path, not the body",
			method:     http.MethodPost,
			path:       "/api/v1/eab/credentials/7/revoke",
			body:       `{"credentialId":"1","revokerId":"9"}`,
			wantStatus: http.StatusOK,
			wantCall:   "RevokeCredential",
			wantReq:    &platformv1.RevokeEABCredentialRequest{CredentialId: 7, RevokerId: 9},
			wantResp:   &platformv1.RevokeEABCredentialResponse{},
		},
		{
			name:       "mark used",
			method:     http.MethodPost,
			path:       "/api/v1/eab/credentials/7/used",
			wantStatus: http.StatusOK,
			wantCall:   "MarkCredentialUsed",
			wantReq:    &platformv1.MarkEABCredentialUsedRequest{CredentialId: 7},
			wantResp:   &platformv1.MarkEABCredentialUsedResponse{},
		},
		{
			name:       "qrcode with size",
			method:     http.MethodGet,
			path:       "/api/v1/eab/credentials/7/qrcode?size=256",
			wantStatus: http.StatusOK,
			wantCall:   "GetCredentialQRCode",
			wantReq:    &platformv1.GetEABCredentialQRCodeRequest{CredentialId: 7, Size: 256},
			wantResp:   &platformv1.GetEABCredentialQRCodeResponse{QrCode: []byte("png-bytes"), ContentType: "image/png"},
		},
		{
			name:       "qrcode without size leaves the server default",
			method:     http.MethodGet,
			path:       "/api/v1/eab/credentials/7/qrcode",
			wantStatus: http.StatusOK,
			wantCall:   "GetCredentialQRCode",
			wantReq:    &platformv1.GetEABCredentialQRCodeRequest{CredentialId: 7},
			wantResp:   &platformv1.GetEABCredentialQRCodeResponse{QrCode: []byte("png-bytes"), ContentType: "image/png"},
		},
		{
			name:       "enrollment url carries the path query",
			method:     http.MethodGet,
			path:       "/api/v1/eab/credentials/7/url?path=/acme/enroll",
			wantStatus: http.StatusOK,
			wantCall:   "GetEnrollmentURL",
			wantReq:    &platformv1.GetEABEnrollmentURLRequest{CredentialId: 7, Path: "/acme/enroll"},
			wantResp:   &platformv1.GetEABEnrollmentURLResponse{Url: "https://ca.example/enroll?kid=kid-1"},
		},
		{
			name:       "validate",
			method:     http.MethodPost,
			path:       "/api/v1/eab/credentials/validate",
			body:       `{"keyId":"kid-1","hmacKey":"hmac-secret"}`,
			wantStatus: http.StatusOK,
			wantCall:   "ValidateCredential",
			wantReq:    &platformv1.ValidateEABCredentialRequest{KeyId: "kid-1", HmacKey: "hmac-secret"},
			wantResp:   &platformv1.ValidateEABCredentialResponse{Valid: true, Credential: testCredential},
		},
		{
			name:       "cleanup prefers the body tenant over the query",
			method:     http.MethodPost,
			path:       "/api/v1/eab/credentials/cleanup?tenant_id=t-query",
			body:       `{"tenantId":"t-body"}`,
			wantStatus: http.StatusOK,
			wantCall:   "CleanupExpiredCredentials",
			wantReq:    &platformv1.CleanupExpiredEABCredentialsRequest{TenantId: "t-body"},
			wantResp:   &platformv1.CleanupExpiredEABCredentialsResponse{DeletedCount: 3},
		},
		{
			name:       "cleanup without a body takes the query tenant",
			method:     http.MethodPost,
			path:       "/api/v1/eab/credentials/cleanup?tenant_id=t-query",
			wantStatus: http.StatusOK,
			wantCall:   "CleanupExpiredCredentials",
			wantReq:    &platformv1.CleanupExpiredEABCredentialsRequest{TenantId: "t-query"},
			wantResp:   &platformv1.CleanupExpiredEABCredentialsResponse{DeletedCount: 3},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := &fakeEABServer{}
			code, env := serve(t, routerWith(srv), tc.method, tc.path, tc.body)

			require.Equal(t, tc.wantStatus, code, env.Error)
			assert.True(t, env.Success)
			assert.Equal(t, tc.wantStatus, env.Code)
			assert.Equal(t, []string{tc.wantCall}, srv.calls)
			assert.True(t, proto.Equal(tc.wantReq, srv.got), "server got %v, want %v", srv.got, tc.wantReq)

			got := tc.wantResp.ProtoReflect().New().Interface()
			require.NoError(t, protojson.Unmarshal(env.Payload, got))
			assert.True(t, proto.Equal(tc.wantResp, got), "payload %s, want %v", env.Payload, tc.wantResp)
		})
	}
}

func TestHandlers_ServerErrorIsMappedToItsHTTPStatus(t *testing.T) {
	for name, rt := range allRoutes {
		t.Run(name, func(t *testing.T) {
			srv := &fakeEABServer{err: status.Error(codes.NotFound, "credential not found")}
			code, env := serve(t, routerWith(srv), rt.method, rt.path, "")

			assert.Equal(t, http.StatusNotFound, code)
			assert.False(t, env.Success)
			assert.Contains(t, env.Error, "credential not found")
			assert.Equal(t, []string{name}, srv.calls)
		})
	}
}

func TestHandlers_NilServerIsServiceUnavailable(t *testing.T) {
	parent := routerWith(nil)
	for name, rt := range allRoutes {
		t.Run(name, func(t *testing.T) {
			code, env := serve(t, parent, rt.method, rt.path, "")

			assert.Equal(t, http.StatusServiceUnavailable, code)
			assert.False(t, env.Success)
			assert.Contains(t, env.Error, "eab")
		})
	}
}

func TestHandlers_BadInputIsRefusedBeforeTheServer(t *testing.T) {
	// 18446744073709551616 is 2^64: it matches the routes' [0-9]+ pattern
	// but overflows the uint64 credential id.
	const overflowID = "18446744073709551616"
	cases := []struct {
		name, method, path, body string
		wantError                string
	}{
		{"list bad profile_id", http.MethodGet, "/api/v1/eab/credentials?profile_id=abc", "", `"profile_id"`},
		{"list bad active_only", http.MethodGet, "/api/v1/eab/credentials?active_only=maybe", "", `"active_only"`},
		{"list bad page", http.MethodGet, "/api/v1/eab/credentials?page=-1", "", `"page"`},
		{"list bad page_size", http.MethodGet, "/api/v1/eab/credentials?page_size=x", "", `"page_size"`},
		{"list unknown status", http.MethodGet, "/api/v1/eab/credentials?status=pending", "", "unknown status filter: pending"},
		{"create malformed body", http.MethodPost, "/api/v1/eab/credentials", "{", "invalid"},
		{"revoke malformed body", http.MethodPost, "/api/v1/eab/credentials/7/revoke", "{", "invalid"},
		{"validate malformed body", http.MethodPost, "/api/v1/eab/credentials/validate", "{", "invalid"},
		{"cleanup malformed body", http.MethodPost, "/api/v1/eab/credentials/cleanup", "{", "invalid"},
		{"qrcode non-numeric size", http.MethodGet, "/api/v1/eab/credentials/7/qrcode?size=big", "", `"size"`},
		{"qrcode size above int32", http.MethodGet, "/api/v1/eab/credentials/7/qrcode?size=2147483648", "", "qrcode size out of range"},
		{"get id overflow", http.MethodGet, "/api/v1/eab/credentials/" + overflowID, "", `"id"`},
		{"delete id overflow", http.MethodDelete, "/api/v1/eab/credentials/" + overflowID, "", `"id"`},
		{"revoke id overflow", http.MethodPost, "/api/v1/eab/credentials/" + overflowID + "/revoke", "", `"id"`},
		{"used id overflow", http.MethodPost, "/api/v1/eab/credentials/" + overflowID + "/used", "", `"id"`},
		{"qrcode id overflow", http.MethodGet, "/api/v1/eab/credentials/" + overflowID + "/qrcode", "", `"id"`},
		{"url id overflow", http.MethodGet, "/api/v1/eab/credentials/" + overflowID + "/url", "", `"id"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := &fakeEABServer{}
			code, env := serve(t, routerWith(srv), tc.method, tc.path, tc.body)

			assert.Equal(t, http.StatusBadRequest, code)
			assert.False(t, env.Success)
			assert.Contains(t, env.Error, tc.wantError)
			assert.Empty(t, srv.calls, "a refused request must not reach the server")
		})
	}
}

func TestListCredentialsRequestFromQuery_UnknownStatusIsTyped(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/eab/credentials?status=pending", nil)

	req, err := listCredentialsRequestFromQuery(r)

	assert.Nil(t, req)
	var invalid *protorest.ErrInvalidQuery
	require.True(t, errors.As(err, &invalid))
	assert.Equal(t, "status", invalid.Name)
	var unknown *ErrUnknownStatusFilter
	require.True(t, errors.As(err, &unknown))
	assert.Equal(t, "pending", unknown.Value)
	assert.Equal(t, "eab: unknown status filter: pending", unknown.Error())
}

func TestListCredentialsRequestFromQuery_EveryShortStatusName(t *testing.T) {
	for name, want := range map[string]platformv1.EABCredentialStatus{
		"active":  platformv1.EABCredentialStatus_EAB_CREDENTIAL_STATUS_ACTIVE,
		"revoked": platformv1.EABCredentialStatus_EAB_CREDENTIAL_STATUS_REVOKED,
		"expired": platformv1.EABCredentialStatus_EAB_CREDENTIAL_STATUS_EXPIRED,
		"used":    platformv1.EABCredentialStatus_EAB_CREDENTIAL_STATUS_USED,
	} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/api/v1/eab/credentials?status="+name, nil)

			req, err := listCredentialsRequestFromQuery(r)

			require.NoError(t, err)
			assert.Equal(t, want, req.GetStatusFilter())
			assert.Nil(t, req.GetPagination())
		})
	}
}

func TestQRCodeSizeFromQuery_AcceptsTheInt32Maximum(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/x?size=2147483647", nil)

	size, err := qrCodeSizeFromQuery(r)

	require.NoError(t, err)
	assert.Equal(t, int32(2147483647), size)
}

func TestQRCodeSizeFromQuery_RefusesSizesThatWouldWrapNegative(t *testing.T) {
	// Before the bound, 4294967295 was cast straight to int32 and reached
	// the server as -1.
	for _, raw := range []string{"2147483648", "4294967295"} {
		t.Run(raw, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/x?size="+raw, nil)

			size, err := qrCodeSizeFromQuery(r)

			assert.Zero(t, size)
			var invalid *protorest.ErrInvalidQuery
			require.True(t, errors.As(err, &invalid))
			assert.Equal(t, "size", invalid.Name)
			assert.Equal(t, raw, invalid.Value)
			var outOfRange *ErrQRCodeSizeOutOfRange
			require.True(t, errors.As(err, &outOfRange))
			assert.Equal(t, "eab: qrcode size out of range: "+raw, outOfRange.Error())
		})
	}
}
