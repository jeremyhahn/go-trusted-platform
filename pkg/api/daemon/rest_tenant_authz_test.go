// Copyright (c) 2026 Automate The Things, LLC
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

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
)

// restTenantRoute is the daemon REST route serving one tenant parity op.
// {subject} in path is replaced by the tenant ID (or name) the op names.
type restTenantRoute struct {
	method string
	path   string
	body   func(subject string) interface{}
}

// restTenantRoutes maps every tenant parity op to its daemon REST route,
// sending the request the op's gRPC call sends.
var restTenantRoutes = map[string]restTenantRoute{
	"tenant_get":         {method: http.MethodGet, path: "/api/v1/tenants/{subject}"},
	"tenant_get_by_name": {method: http.MethodGet, path: "/api/v1/tenants/name/{subject}"},
	"tenant_list":        {method: http.MethodGet, path: "/api/v1/tenants"},
	"tenant_create": {method: http.MethodPost, path: "/api/v1/tenants", body: func(subject string) interface{} {
		return restapi.CreateTenantRequest{Name: subject, DisplayName: "Tenant C"}
	}},
	"tenant_update": {method: http.MethodPut, path: "/api/v1/tenants/{subject}", body: func(string) interface{} {
		displayName := "Tenant A"
		return restapi.UpdateTenantRequest{DisplayName: &displayName}
	}},
	"tenant_delete":     {method: http.MethodDelete, path: "/api/v1/tenants/{subject}"},
	"tenant_get_quotas": {method: http.MethodGet, path: "/api/v1/tenants/{subject}/quotas"},
	"tenant_update_quotas": {method: http.MethodPut, path: "/api/v1/tenants/{subject}/quotas", body: func(string) interface{} {
		return restapi.UpdateQuotasRequest{Compute: &restapi.ComputeQuotaRequest{MaxVMs: 7}}
	}},
	"tenant_get_usage": {method: http.MethodGet, path: "/api/v1/tenants/{subject}/usage"},
	"tenant_check_quota": {method: http.MethodPost, path: "/api/v1/tenants/{subject}/check-quota", body: func(string) interface{} {
		return restapi.CheckQuotaRequest{Resource: "vms", Amount: 1}
	}},
	"tenant_suspend": {method: http.MethodPost, path: "/api/v1/tenants/{subject}/suspend"},
	"tenant_resume":  {method: http.MethodPost, path: "/api/v1/tenants/{subject}/resume"},
	"tenant_sync":    {method: http.MethodPost, path: "/api/v1/tenants/sync"},
	"tenant_rotate_dek": {method: http.MethodPost, path: "/api/v1/tenants/{subject}/dek/rotate", body: func(string) interface{} {
		return restapi.RotateDEKRequest{Background: true}
	}},
	"tenant_get_dek_status":          {method: http.MethodGet, path: "/api/v1/tenants/{subject}/dek/status"},
	"platform_tenant_barrier_init":   {method: http.MethodPost, path: "/api/v1/tenants/{subject}/barrier/init"},
	"platform_tenant_barrier_seal":   {method: http.MethodPost, path: "/api/v1/tenants/{subject}/barrier/seal"},
	"platform_tenant_barrier_status": {method: http.MethodGet, path: "/api/v1/tenants/{subject}/barrier/status"},
	"platform_tenant_barrier_unseal": {method: http.MethodPost, path: "/api/v1/tenants/{subject}/barrier/unseal", body: func(string) interface{} {
		return restapi.UnsealTenantBarrierRequest{Key: []byte("unseal-key")}
	}},
}

// errParityToken is the refusal for a bearer token naming no parity tenant.
var errParityToken = errors.New("token names no parity tenant")

// parityTokens authenticates a bearer token equal to a tenant label as an
// operator of that tenant, the way the daemon's token authorizer binds a
// verified token to its tenant.
type parityTokens map[string]*platformtoken.AuthorizedContext

func (p parityTokens) AuthorizeToken(_ context.Context, token, _, _, _, _ string) (*platformtoken.AuthorizedContext, error) {
	caller, ok := p[token]
	if !ok {
		return nil, errParityToken
	}
	return caller, nil
}

// restRouter serves the harness's tenant manager on a daemon REST server
// whose scope guard knows each parity tenant and whose system tenant is the
// one the harness's gRPC server treats as system.
func (h *tenantParityHarness) restRouter(t *testing.T) http.Handler {
	t.Helper()
	cfg := DefaultConfig()
	cfg.RESTListenAddr = "127.0.0.1:0"
	svc, err := NewService(cfg)
	require.NoError(t, err)
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	s, err := NewRESTServer(cfg, svc, quiet)
	require.NoError(t, err)

	tokens := make(parityTokens, len(parityTenantNames))
	for label := range parityTenantNames {
		tokens[label] = &platformtoken.AuthorizedContext{Subject: label, TenantID: h.id(label), Scopes: []string{"*:*"}}
	}
	s.SetTenantHandlers(h.manager, restapi.NewScopeGuard(tokens, nil, quiet), h.id(paritySystemTenant))
	return s.Router()
}

// callREST makes the op's daemon REST call as caller, naming subject, and
// returns the status and the refusal text with tenant IDs put back as labels.
func (h *tenantParityHarness) callREST(t *testing.T, op tenantParityOp, caller, subject string) (int, string) {
	t.Helper()
	route, ok := restTenantRoutes[op.tool]
	require.True(t, ok, "no daemon REST route for %s", op.tool)

	var body io.Reader = http.NoBody
	if route.body != nil {
		raw, err := json.Marshal(route.body(h.id(subject)))
		require.NoError(t, err)
		body = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(route.method, strings.ReplaceAll(route.path, "{subject}", h.id(subject)), body)
	req.Header.Set("Authorization", "Bearer "+caller)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.restRouter(t).ServeHTTP(rec, req)

	if rec.Code < http.StatusBadRequest {
		return rec.Code, ""
	}
	var refusal restapi.TenantErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &refusal), "body: %s", rec.Body.String())
	return rec.Code, h.unlabel(refusal.Error)
}

// grpcRefusal is the gRPC status message with tenant IDs put back as labels,
// so two harnesses' refusals compare equal.
func (h *tenantParityHarness) grpcRefusal(err error) string {
	return h.unlabel(status.Convert(err).Message())
}

func (h *tenantParityHarness) unlabel(text string) string {
	for label, id := range h.labelledIDs() {
		text = strings.ReplaceAll(text, id, label)
	}
	return text
}

// assertRESTLikeGRPC makes the op's call as caller on both transports, each
// against a fresh harness, and asserts daemon REST admits exactly the
// callers the tenant gRPC server admits and refuses the rest with the same
// typed refusal, changing nothing.
func assertRESTLikeGRPC(t *testing.T, op tenantParityOp, caller, subject string, wantRefused bool) {
	t.Helper()
	grpcSide, restSide := parityHarnesses(t, op)
	before := restSide.snapshot()
	calls := restSide.backendCalls(subject)

	_, grpcErr := grpcSide.callGRPC(op, caller, subject)
	restCode, restRefusal := restSide.callREST(t, op, caller, subject)

	if !wantRefused && op.gap {
		// Admitted, then refused as the declared gap
		// (docs/tenant/engineering.md §6).
		require.Equal(t, codes.Unimplemented, status.Code(grpcErr), "gRPC admits %s: %v", caller, grpcErr)
		assert.Equal(t, http.StatusNotImplemented, restCode, "REST admits %s: %s", caller, restRefusal)
		assert.Equal(t, before, restSide.snapshot(), "REST changed nothing")
		return
	}
	if !wantRefused {
		require.NoError(t, grpcErr, "gRPC admits %s", caller)
		assert.Less(t, restCode, http.StatusMultipleChoices, "REST admits %s: %s", caller, restRefusal)
		return
	}
	require.Equal(t, codes.PermissionDenied, status.Code(grpcErr), "gRPC: %v", grpcErr)
	assert.Equal(t, http.StatusForbidden, restCode, "REST: %s", restRefusal)
	assert.Equal(t, grpcSide.grpcRefusal(grpcErr), restRefusal, "the same typed refusal")
	assert.Equal(t, before, restSide.snapshot(), "REST changed nothing")
	assert.Equal(t, calls, restSide.backendCalls(subject), "REST reached no backend")
}

func TestDaemonRESTTenantRoutesAuthorizeLikeGRPC(t *testing.T) {
	cases := []struct {
		name            string
		caller, subject string
		refused         bool
	}{
		{name: "system acts on another tenant", caller: paritySystemTenant, subject: parityTenantA},
		{name: "a tenant acts on itself", caller: parityTenantA, subject: parityTenantA},
		{name: "a tenant acts on another tenant", caller: parityTenantA, subject: parityTenantB, refused: true},
	}
	routes := 0
	for _, op := range tenantParityOps() {
		if op.systemOnly {
			continue
		}
		routes++
		for _, c := range cases {
			t.Run(op.tool+"/"+c.name, func(t *testing.T) {
				assertRESTLikeGRPC(t, op, c.caller, c.subject, c.refused)
			})
		}
	}
	assert.Equal(t, 15, routes, "every per-tenant route")
}

func TestDaemonRESTTenantSystemOnlyRoutesLikeGRPC(t *testing.T) {
	routes := 0
	for _, op := range tenantParityOps() {
		if !op.systemOnly || op.tool == "tenant_get_by_name" {
			continue
		}
		routes++
		t.Run(op.tool+"/system", func(t *testing.T) {
			assertRESTLikeGRPC(t, op, paritySystemTenant, op.subject, false)
		})
		t.Run(op.tool+"/another tenant", func(t *testing.T) {
			assertRESTLikeGRPC(t, op, parityTenantA, op.subject, true)
		})
	}
	assert.Equal(t, 3, routes, "list, create and sync act across tenants")
}

func TestDaemonRESTTenantGetByNameLikeGRPC(t *testing.T) {
	var byName tenantParityOp
	for _, op := range tenantParityOps() {
		if op.tool == "tenant_get_by_name" {
			byName = op
		}
	}
	require.Equal(t, "tenant_get_by_name", byName.tool)

	t.Run("a tenant resolves its own name", func(t *testing.T) {
		assertRESTLikeGRPC(t, byName, parityTenantA, parityTenantNames[parityTenantA], false)
	})
	t.Run("system resolves another tenant's name", func(t *testing.T) {
		assertRESTLikeGRPC(t, byName, paritySystemTenant, parityTenantNames[parityTenantB], false)
	})
	t.Run("another tenant's name is refused", func(t *testing.T) {
		assertRESTLikeGRPC(t, byName, parityTenantA, parityTenantNames[parityTenantB], true)
	})
	t.Run("an unknown name is refused", func(t *testing.T) {
		assertRESTLikeGRPC(t, byName, parityTenantA, parityGhostTenant, true)
	})
	t.Run("an unknown name is refused exactly like another tenant's", func(t *testing.T) {
		h := newTenantParityHarness(t)
		foreignCode, foreign := h.callREST(t, byName, parityTenantA, parityTenantNames[parityTenantB])
		ghostCode, ghost := h.callREST(t, byName, parityTenantA, parityGhostTenant)
		assert.Equal(t, foreignCode, ghostCode)
		assert.Equal(t, foreign, ghost)
		assert.Equal(t, tenant.ErrNameLookupDenied{}.Error(), ghost)
	})
	t.Run("system is told an unknown name does not exist", func(t *testing.T) {
		grpcSide, restSide := parityHarnesses(t, byName)
		_, grpcErr := grpcSide.callGRPC(byName, paritySystemTenant, parityGhostTenant)
		restCode, _ := restSide.callREST(t, byName, paritySystemTenant, parityGhostTenant)
		assert.Equal(t, codes.NotFound, status.Code(grpcErr), "gRPC: %v", grpcErr)
		assert.Equal(t, http.StatusNotFound, restCode)
	})
}
