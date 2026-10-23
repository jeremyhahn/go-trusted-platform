//go:build integration

// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-or-later

package tenant

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// foreignTenantTimeout bounds the whole foreign-tenant suite.
const foreignTenantTimeout = 2 * time.Minute

// TestForeignTenant_IAM asserts what a caller bound to a tenant other than
// the system tenant is refused (docs/iam/api.md): CreateTenant and
// ListTenants admit the system tenant only, and IAM reads are confined to
// the caller's own tenant. The caller is the harness tenant credential
// (helpers.ForeignTenantID, PLATFORM_TENANT_CLIENT_CERT/KEY).
//
// The IAM tenant is created first over the Unix socket: the local operator
// is bound to no tenant (docs/auth/api.md §4), so it is admitted everywhere.
func TestForeignTenant_IAM(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), foreignTenantTimeout)
	defer cancel()

	unix := NewUnixAdapter()
	require.NoError(t, unix.Setup(ctx), "Unix setup")
	// A cleanup, not a defer: ensureIAMTenant deletes the tenant in a cleanup
	// over this connection, and cleanups run after defers, last in first out,
	// so the connection closes only after that delete.
	t.Cleanup(func() {
		require.NoError(t, unix.Teardown(context.Background()), "Unix teardown")
	})
	operatorIAM := platformv1.NewPlatformIAMServiceClient(unix.conn)

	ensureIAMTenant(t, ctx, operatorIAM, helpers.ForeignTenantID)

	t.Run("Unix", func(t *testing.T) {
		for _, tenantID := range []string{helpers.HarnessTenantID, helpers.ForeignTenantID} {
			_, err := operatorIAM.ListUsers(ctx, listIAMUsersRequest(tenantID))
			require.NoError(t, err, "the unbound operator lists users in %q", tenantID)
		}
	})
	t.Run("gRPC", func(t *testing.T) { testForeignTenantGRPC(t, ctx) })
	t.Run("REST", func(t *testing.T) { testForeignTenantREST(t, ctx) })
	t.Run("MCP", func(t *testing.T) { testForeignTenantMCP(t, ctx) })
	t.Run("QUIC", func(t *testing.T) { testForeignTenantQUIC(t, ctx) })
}

// ensureIAMTenant creates the IAM tenant tenantID as the Unix operator. A
// tenant left by an earlier run is reused; it is deleted again only when this
// run created it.
func ensureIAMTenant(t *testing.T, ctx context.Context, client platformv1.PlatformIAMServiceClient, tenantID string) {
	t.Helper()

	_, err := client.CreateTenant(ctx, &platformv1.CreateIAMTenantRequest{Id: tenantID, Name: tenantID})
	if status.Code(err) == codes.AlreadyExists {
		return
	}
	require.NoError(t, err, "the unbound operator creates IAM tenant %q", tenantID)

	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, err := client.DeleteTenant(cleanupCtx, &platformv1.DeleteIAMTenantRequest{TenantId: tenantID})
		require.NoError(t, err, "delete IAM tenant %q", tenantID)
	})
}

// listIAMUsersRequest lists the first page of users in tenantID, the request
// the IAM suite's adapters send.
func listIAMUsersRequest(tenantID string) *platformv1.ListIAMUsersRequest {
	return &platformv1.ListIAMUsersRequest{
		TenantId:   tenantID,
		Pagination: &platformv1.PaginationRequest{Page: 1},
	}
}

func testForeignTenantGRPC(t *testing.T, ctx context.Context) {
	adapter := NewGRPCAdapterWithTLS(helpers.TenantTLSConfig())
	require.NoError(t, adapter.Setup(ctx), "gRPC setup")
	defer adapter.Teardown(ctx)
	iam := platformv1.NewPlatformIAMServiceClient(adapter.conn)

	_, err := iam.CreateTenant(ctx, &platformv1.CreateIAMTenantRequest{Id: GenerateTestTenantName("foreign")})
	require.Equal(t, codes.PermissionDenied, status.Code(err), "CreateTenant: %v", err)

	_, err = iam.ListTenants(ctx, &platformv1.ListIAMTenantsRequest{})
	require.Equal(t, codes.PermissionDenied, status.Code(err), "ListTenants: %v", err)

	_, err = iam.ListUsers(ctx, listIAMUsersRequest(helpers.HarnessTenantID))
	require.Equal(t, codes.PermissionDenied, status.Code(err), "ListUsers in the system tenant: %v", err)

	_, err = iam.ListUsers(ctx, listIAMUsersRequest(helpers.ForeignTenantID))
	require.NoError(t, err, "ListUsers in the caller's own tenant")
}

func testForeignTenantREST(t *testing.T, ctx context.Context) {
	client := helpers.NewTenantHTTPClient(30 * time.Second)
	base := GetRESTEndpoint()

	createBody, err := json.Marshal(map[string]string{"id": GenerateTestTenantName("foreign")})
	require.NoError(t, err)

	cases := []struct {
		name   string
		method string
		path   string
		body   []byte
		want   int
	}{
		{"create tenant", http.MethodPost, "/api/v1/iam/tenants", createBody, http.StatusForbidden},
		{"list tenants", http.MethodGet, "/api/v1/iam/tenants", nil, http.StatusForbidden},
		{"list users in the system tenant", http.MethodGet, "/api/v1/iam/tenants/" + helpers.HarnessTenantID + "/users", nil, http.StatusForbidden},
		{"list users in its own tenant", http.MethodGet, "/api/v1/iam/tenants/" + helpers.ForeignTenantID + "/users", nil, http.StatusOK},
	}
	for _, tc := range cases {
		got, respBody := restCall(t, ctx, client, tc.method, base+tc.path, tc.body)
		require.Equal(t, tc.want, got, "%s: %s %s answered %s", tc.name, tc.method, tc.path, respBody)
	}
}

// restCall sends one JSON request and returns its status and body.
func restCall(t *testing.T, ctx context.Context, client *http.Client, method, url string, body []byte) (int, string) {
	t.Helper()

	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := client.Do(req)
	require.NoError(t, err, "%s %s", method, url)
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(respBody)
}

func testForeignTenantMCP(t *testing.T, ctx context.Context) {
	client := helpers.NewTenantHTTPClient(30 * time.Second)
	url := helpers.MCPEndpointURL(GetMCPEndpoint())

	cases := []struct {
		name string
		tool string
		args map[string]interface{}
		want int // JSON-RPC error code; 0 is success
	}{
		{"create tenant", "iam_create_tenant", map[string]interface{}{"id": GenerateTestTenantName("foreign")}, mcpwire.PermissionDenied},
		{"list tenants", "iam_list_tenants", map[string]interface{}{}, mcpwire.PermissionDenied},
		{"list users in the system tenant", "iam_list_users", map[string]interface{}{"tenant_id": helpers.HarnessTenantID}, mcpwire.PermissionDenied},
		{"list users in its own tenant", "iam_list_users", map[string]interface{}{"tenant_id": helpers.ForeignTenantID}, 0},
	}
	for i, tc := range cases {
		got, message := mcpToolCall(t, ctx, client, url, int64(i+1), tc.tool, tc.args)
		require.Equal(t, tc.want, got, "%s: %s answered %q", tc.name, tc.tool, message)
	}
}

// mcpToolCall calls one MCP tool and returns the JSON-RPC error code and
// message, or 0 and "" when the call succeeded.
func mcpToolCall(t *testing.T, ctx context.Context, client *http.Client, url string, id int64, tool string, args map[string]interface{}) (int, string) {
	t.Helper()

	body, err := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  "tools/call",
		"params":  map[string]interface{}{"name": tool, "arguments": args},
	})
	require.NoError(t, err)

	status, respBody := restCall(t, ctx, client, http.MethodPost, url, body)
	require.Equal(t, http.StatusOK, status, "%s: HTTP %d %s", tool, status, respBody)

	var resp struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal([]byte(respBody), &resp), "%s: %s", tool, respBody)
	if resp.Error == nil {
		return 0, ""
	}
	return resp.Error.Code, resp.Error.Message
}

// testForeignTenantQUIC covers the tenant cases QUIC has opcodes for. No QUIC
// opcode creates an IAM tenant, so the create case goes through the platform
// TenantService create, which admits the system tenant only as well; the
// user listings use the IAM opcode.
func testForeignTenantQUIC(t *testing.T, ctx context.Context) {
	adapter := &QUICAdapter{endpoint: GetQUICEndpoint(), tlsConfig: helpers.TenantQUICTLSConfig()}
	require.NoError(t, adapter.Setup(ctx), "QUIC setup")
	defer adapter.Teardown(ctx)

	var statusErr ErrQUICStatus
	_, err := adapter.CreateTenant(ctx, CreateTenantOptions{Name: GenerateTestTenantName("foreign")})
	require.ErrorAs(t, err, &statusErr, "CreateTenant")
	require.Equal(t, quicwire.StatusPermissionDenied, statusErr.Status, "CreateTenant: %v", err)

	_, err = quicIAMListUsers(ctx, adapter, helpers.HarnessTenantID)
	require.ErrorAs(t, err, &statusErr, "ListUsers in the system tenant")
	require.Equal(t, quicwire.StatusPermissionDenied, statusErr.Status, "ListUsers in the system tenant: %v", err)

	_, err = quicIAMListUsers(ctx, adapter, helpers.ForeignTenantID)
	require.NoError(t, err, "ListUsers in the caller's own tenant")
}

// quicIAMListUsers lists the users in tenantID with the IAM user-list opcode.
func quicIAMListUsers(ctx context.Context, adapter *QUICAdapter, tenantID string) (*platformv1.ListIAMUsersResponse, error) {
	payload, err := quicwire.EncodePayload(listIAMUsersRequest(tenantID))
	if err != nil {
		return nil, ErrQUICRequestFailed{Operation: "ListUsers", Message: "encode: " + err.Error()}
	}
	raw, err := adapter.roundTrip(ctx, "ListUsers", quicwire.OpIAMUserList, payload)
	if err != nil {
		return nil, err
	}
	var resp platformv1.ListIAMUsersResponse
	if err := quicwire.DecodePayload(raw, &resp); err != nil {
		return nil, ErrQUICRequestFailed{Operation: "ListUsers", Message: "decode: " + err.Error()}
	}
	return &resp, nil
}
