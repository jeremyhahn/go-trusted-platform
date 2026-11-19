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

package tenant

import (
	"context"
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
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// fakeTenantServer records the last request each handler forwarded and
// returns err (when set) instead of a response.
type fakeTenantServer struct {
	platformv1.UnimplementedTenantServiceServer
	last proto.Message
	err  error
}

func (f *fakeTenantServer) reply(req proto.Message) error {
	f.last = req
	return f.err
}

func (f *fakeTenantServer) ListTenants(_ context.Context, r *platformv1.ListTenantsRequest) (*platformv1.ListTenantsResponse, error) {
	return &platformv1.ListTenantsResponse{Total: 1}, f.reply(r)
}
func (f *fakeTenantServer) CreateTenant(_ context.Context, r *platformv1.CreateTenantRequest) (*platformv1.CreateTenantResponse, error) {
	return &platformv1.CreateTenantResponse{Tenant: &platformv1.Tenant{Id: "t1", Name: r.GetName()}}, f.reply(r)
}
func (f *fakeTenantServer) GetTenant(_ context.Context, r *platformv1.GetTenantRequest) (*platformv1.GetTenantResponse, error) {
	return &platformv1.GetTenantResponse{Tenant: &platformv1.Tenant{Id: r.GetTenantId()}}, f.reply(r)
}
func (f *fakeTenantServer) GetTenantByName(_ context.Context, r *platformv1.GetTenantByNameRequest) (*platformv1.GetTenantByNameResponse, error) {
	return &platformv1.GetTenantByNameResponse{}, f.reply(r)
}
func (f *fakeTenantServer) UpdateTenant(_ context.Context, r *platformv1.UpdateTenantRequest) (*platformv1.UpdateTenantResponse, error) {
	return &platformv1.UpdateTenantResponse{}, f.reply(r)
}
func (f *fakeTenantServer) DeleteTenant(_ context.Context, r *platformv1.DeleteTenantRequest) (*platformv1.DeleteTenantResponse, error) {
	return &platformv1.DeleteTenantResponse{}, f.reply(r)
}
func (f *fakeTenantServer) SuspendTenant(_ context.Context, r *platformv1.SuspendTenantRequest) (*platformv1.SuspendTenantResponse, error) {
	return &platformv1.SuspendTenantResponse{}, f.reply(r)
}
func (f *fakeTenantServer) ResumeTenant(_ context.Context, r *platformv1.ResumeTenantRequest) (*platformv1.ResumeTenantResponse, error) {
	return &platformv1.ResumeTenantResponse{}, f.reply(r)
}
func (f *fakeTenantServer) GetQuotas(_ context.Context, r *platformv1.GetQuotasRequest) (*platformv1.GetQuotasResponse, error) {
	return &platformv1.GetQuotasResponse{}, f.reply(r)
}
func (f *fakeTenantServer) UpdateQuotas(_ context.Context, r *platformv1.UpdateQuotasRequest) (*platformv1.UpdateQuotasResponse, error) {
	return &platformv1.UpdateQuotasResponse{}, f.reply(r)
}
func (f *fakeTenantServer) GetUsage(_ context.Context, r *platformv1.GetUsageRequest) (*platformv1.GetUsageResponse, error) {
	return &platformv1.GetUsageResponse{}, f.reply(r)
}
func (f *fakeTenantServer) CheckQuota(_ context.Context, r *platformv1.CheckQuotaRequest) (*platformv1.CheckQuotaResponse, error) {
	return &platformv1.CheckQuotaResponse{}, f.reply(r)
}
func (f *fakeTenantServer) Sync(_ context.Context, r *platformv1.SyncTenantsRequest) (*platformv1.SyncTenantsResponse, error) {
	return &platformv1.SyncTenantsResponse{}, f.reply(r)
}
func (f *fakeTenantServer) RotateTenantDEK(_ context.Context, r *platformv1.RotateTenantDEKRequest) (*platformv1.RotateTenantDEKResponse, error) {
	return &platformv1.RotateTenantDEKResponse{}, f.reply(r)
}
func (f *fakeTenantServer) GetTenantDEKStatus(_ context.Context, r *platformv1.GetTenantDEKStatusRequest) (*platformv1.GetTenantDEKStatusResponse, error) {
	return &platformv1.GetTenantDEKStatusResponse{}, f.reply(r)
}
func (f *fakeTenantServer) InitTenantBarrier(_ context.Context, r *platformv1.InitTenantBarrierRequest) (*platformv1.InitTenantBarrierResponse, error) {
	return &platformv1.InitTenantBarrierResponse{}, f.reply(r)
}
func (f *fakeTenantServer) UnsealTenantBarrier(_ context.Context, r *platformv1.UnsealTenantBarrierRequest) (*platformv1.UnsealTenantBarrierResponse, error) {
	return &platformv1.UnsealTenantBarrierResponse{}, f.reply(r)
}
func (f *fakeTenantServer) SealTenantBarrier(_ context.Context, r *platformv1.SealTenantBarrierRequest) (*platformv1.SealTenantBarrierResponse, error) {
	return &platformv1.SealTenantBarrierResponse{}, f.reply(r)
}
func (f *fakeTenantServer) GetTenantBarrierStatus(_ context.Context, r *platformv1.GetTenantBarrierStatusRequest) (*platformv1.GetTenantBarrierStatusResponse, error) {
	return &platformv1.GetTenantBarrierStatusResponse{}, f.reply(r)
}

func newRouterWithServer(t *testing.T, srv platformv1.TenantServiceServer) *mux.Router {
	t.Helper()
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	w := response.NewResponseWriter(logger, nil)
	r, err := NewTenantRouter(logger, srv, w, passthroughAuthorization())
	require.NoError(t, err)
	parent := mux.NewRouter()
	r.RegisterRoutes(parent.PathPrefix("/api/v1").Subrouter())
	return parent
}

type tenantRoute struct {
	method, path, body string
	created            bool
	// tenantID, when set, is the id the handler must forward from the path.
	tenantID string
}

var tenantRoutes = []tenantRoute{
	{http.MethodGet, "/api/v1/tenants", "", false, ""},
	{http.MethodPost, "/api/v1/tenants", `{"name":"acme"}`, true, ""},
	{http.MethodPost, "/api/v1/tenants/sync", `{}`, false, ""},
	{http.MethodGet, "/api/v1/tenants/by-name/acme", "", false, ""},
	{http.MethodGet, "/api/v1/tenants/t1", "", false, "t1"},
	{http.MethodPut, "/api/v1/tenants/t1", `{"displayName":"Acme"}`, false, "t1"},
	{http.MethodDelete, "/api/v1/tenants/t1", "", false, "t1"},
	{http.MethodPost, "/api/v1/tenants/t1/suspend", `{}`, false, "t1"},
	{http.MethodPost, "/api/v1/tenants/t1/resume", "", false, "t1"},
	{http.MethodGet, "/api/v1/tenants/t1/quotas", "", false, "t1"},
	{http.MethodPut, "/api/v1/tenants/t1/quotas", `{}`, false, "t1"},
	{http.MethodGet, "/api/v1/tenants/t1/usage", "", false, "t1"},
	{http.MethodPost, "/api/v1/tenants/t1/quota-check", `{"resource":"vms","amount":1}`, false, "t1"},
	{http.MethodPost, "/api/v1/tenants/t1/dek/rotate", `{"background":true}`, false, "t1"},
	{http.MethodGet, "/api/v1/tenants/t1/dek", "", false, "t1"},
	{http.MethodPost, "/api/v1/tenants/t1/barrier/init", `{}`, true, "t1"},
	{http.MethodPost, "/api/v1/tenants/t1/barrier/unseal", `{}`, false, "t1"},
	{http.MethodPost, "/api/v1/tenants/t1/barrier/seal", "", false, "t1"},
	{http.MethodGet, "/api/v1/tenants/t1/barrier", "", false, "t1"},
}

func serve(router *mux.Router, method, path, body string) *httptest.ResponseRecorder {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rd)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// tenantIDOf extracts the tenant id a forwarded request carries.
func tenantIDOf(m proto.Message) string {
	if g, ok := m.(interface{ GetTenantId() string }); ok {
		return g.GetTenantId()
	}
	return ""
}

// TestHandlers_ForwardToServer drives every route against a fake server and
// checks the status code and that the path's tenant id is forwarded.
func TestHandlers_ForwardToServer(t *testing.T) {
	for _, rt := range tenantRoutes {
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			srv := &fakeTenantServer{}
			rec := serve(newRouterWithServer(t, srv), rt.method, rt.path, rt.body)
			want := http.StatusOK
			if rt.created {
				want = http.StatusCreated
			}
			assert.Equal(t, want, rec.Code, rec.Body.String())
			require.NotNil(t, srv.last, "the handler did not reach the server")
			if rt.tenantID != "" {
				assert.Equal(t, rt.tenantID, tenantIDOf(srv.last))
			}
		})
	}
}

// TestHandlers_ServerErrors maps a server error onto the HTTP status the
// protorest layer assigns to its gRPC code.
func TestHandlers_ServerErrors(t *testing.T) {
	for _, rt := range tenantRoutes {
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			srv := &fakeTenantServer{err: status.Error(codes.NotFound, "tenant not found")}
			rec := serve(newRouterWithServer(t, srv), rt.method, rt.path, rt.body)
			assert.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
		})
	}
}

// TestHandlers_InvalidBody refuses malformed JSON on every route that
// decodes a body, before reaching the server.
func TestHandlers_InvalidBody(t *testing.T) {
	for _, rt := range tenantRoutes {
		if rt.body == "" {
			continue
		}
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			srv := &fakeTenantServer{}
			rec := serve(newRouterWithServer(t, srv), rt.method, rt.path, "{not json")
			assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			assert.Nil(t, srv.last, "a malformed body must not reach the server")
		})
	}
}

// TestHandlers_CreateIgnoresRetiredVLANRange posts the retired VLAN range
// fields: they are no longer part of CreateTenantRequest and are discarded.
func TestHandlers_CreateIgnoresRetiredVLANRange(t *testing.T) {
	srv := &fakeTenantServer{}
	rec := serve(newRouterWithServer(t, srv), http.MethodPost, "/api/v1/tenants",
		`{"name":"acme","vlanRangeStart":100,"vlanRangeEnd":199}`)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	req, ok := srv.last.(*platformv1.CreateTenantRequest)
	require.True(t, ok)
	assert.Equal(t, "acme", req.GetName())
	assert.Empty(t, req.ProtoReflect().GetUnknown(), "retired fields must not survive decoding")
}

// TestHandlers_RotateDEKCarriesBackground proves the DEK rotate route passes
// the body's background flag to the server, as the gRPC transport does, and
// that the tenant always comes from the path.
func TestHandlers_RotateDEKCarriesBackground(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"background", `{"tenantId":"other","background":true}`, true},
		{"foreground", `{"background":false}`, false},
		{"no body", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := &fakeTenantServer{}
			rec := serve(newRouterWithServer(t, srv), http.MethodPost, "/api/v1/tenants/t1/dek/rotate", tc.body)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			req, ok := srv.last.(*platformv1.RotateTenantDEKRequest)
			require.True(t, ok, "server received %T", srv.last)
			assert.Equal(t, "t1", req.GetTenantId())
			assert.Equal(t, tc.want, req.GetBackground())
		})
	}
}

func TestHandlers_ListTenantsForwardsLimitOffset(t *testing.T) {
	srv := &fakeTenantServer{}
	rec := serve(newRouterWithServer(t, srv), http.MethodGet, "/api/v1/tenants?limit=100&offset=200", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	req, ok := srv.last.(*platformv1.ListTenantsRequest)
	require.True(t, ok, "server received %T", srv.last)
	assert.Equal(t, int32(100), req.GetLimit())
	assert.Equal(t, int32(200), req.GetOffset())
}

func TestHandlers_ListTenantsRejectsBadPaging(t *testing.T) {
	for _, query := range []string{"?offset=-1", "?limit=abc", "?limit=-5", "?offset=1.5"} {
		t.Run(query, func(t *testing.T) {
			srv := &fakeTenantServer{}
			rec := serve(newRouterWithServer(t, srv), http.MethodGet, "/api/v1/tenants"+query, "")
			assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			assert.Nil(t, srv.last, "bad paging must not reach the server")
		})
	}
}
