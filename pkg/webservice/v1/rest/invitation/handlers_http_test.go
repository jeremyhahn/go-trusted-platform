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

package invitation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// serve runs one request through the invitation routes over srv and
// returns the recorded response.
func serve(srv platformv1.InvitationServiceServer, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	invitationMux(srv).ServeHTTP(rec, r)
	return rec
}

// TestSDKREST_ListInvitations: the SDK client lists through the REST route
// and receives the invitations the service returned.
func TestSDKREST_ListInvitations(t *testing.T) {
	srv := &fakeInvitationServer{}
	_, client := serveInvitations(t, srv)

	resp, err := client.ListInvitations(context.Background(), &platformv1.ListInvitationsRequest{})

	require.NoError(t, err)
	require.IsType(t, &platformv1.ListInvitationsRequest{}, srv.last)
	assert.Equal(t, int64(2), resp.GetTotal())
	require.Len(t, resp.GetInvitations(), 2)
	assert.Equal(t, "b@example.com", resp.GetInvitations()[1].GetEmail())
}

// TestSDKREST_CreateInvitation: the body the SDK client sends reaches the
// service unchanged, and the created invitation comes back.
func TestSDKREST_CreateInvitation(t *testing.T) {
	srv := &fakeInvitationServer{}
	_, client := serveInvitations(t, srv)
	req := &platformv1.CreateInvitationRequest{
		TenantId: "acme", Email: "new@example.com", Role: "operator", InvitedById: 7, ExpiresInSeconds: 3600,
	}

	resp, err := client.CreateInvitation(context.Background(), req)

	require.NoError(t, err)
	assert.True(t, proto.Equal(req, srv.last), "service received %v, want %v", srv.last, req)
	assert.Equal(t, uint64(21), resp.GetInvitation().GetId())
	assert.Equal(t, "acme", resp.GetInvitation().GetTenantId())
	assert.Equal(t, "new@example.com", resp.GetInvitation().GetEmail())
}

// TestSDKREST_GetInvitation: the numeric path id becomes invitation_id.
func TestSDKREST_GetInvitation(t *testing.T) {
	srv := &fakeInvitationServer{}
	_, client := serveInvitations(t, srv)

	resp, err := client.GetInvitation(context.Background(), &platformv1.GetInvitationRequest{InvitationId: 42})

	require.NoError(t, err)
	assert.True(t, proto.Equal(&platformv1.GetInvitationRequest{InvitationId: 42}, srv.last))
	assert.Equal(t, uint64(42), resp.GetInvitation().GetId())
}

// TestSDKREST_AcceptInvitation: the invitee route carries the token and
// accepting user to the service.
func TestSDKREST_AcceptInvitation(t *testing.T) {
	srv := &fakeInvitationServer{}
	_, client := serveInvitations(t, srv)
	req := &platformv1.AcceptInvitationRequest{Token: "inv-tok_ABC123", UserId: 9}

	resp, err := client.AcceptInvitation(context.Background(), req)

	require.NoError(t, err)
	assert.True(t, proto.Equal(req, srv.last), "service received %v, want %v", srv.last, req)
	assert.Equal(t, "inv-tok_ABC123", resp.GetInvitation().GetToken())
}

// TestSDKREST_ServiceErrorsKeepTheirStatus: every handler reports a
// service error with its gRPC code intact, so the client sees the same
// refusal the service made.
func TestSDKREST_ServiceErrorsKeepTheirStatus(t *testing.T) {
	ctx := context.Background()
	calls := map[string]func(platformv1.InvitationServiceClient) error{
		"ListInvitations": func(c platformv1.InvitationServiceClient) error {
			_, err := c.ListInvitations(ctx, &platformv1.ListInvitationsRequest{})
			return err
		},
		"CreateInvitation": func(c platformv1.InvitationServiceClient) error {
			_, err := c.CreateInvitation(ctx, &platformv1.CreateInvitationRequest{Email: "x@example.com"})
			return err
		},
		"GetInvitation": func(c platformv1.InvitationServiceClient) error {
			_, err := c.GetInvitation(ctx, &platformv1.GetInvitationRequest{InvitationId: 3})
			return err
		},
		"DeleteInvitation": func(c platformv1.InvitationServiceClient) error {
			_, err := c.DeleteInvitation(ctx, &platformv1.DeleteInvitationRequest{InvitationId: 3})
			return err
		},
		"GetInvitationByToken": func(c platformv1.InvitationServiceClient) error {
			_, err := c.GetInvitationByToken(ctx, &platformv1.GetInvitationByTokenRequest{Token: "t"})
			return err
		},
		"AcceptInvitation": func(c platformv1.InvitationServiceClient) error {
			_, err := c.AcceptInvitation(ctx, &platformv1.AcceptInvitationRequest{Token: "t", UserId: 9})
			return err
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			srv := &fakeInvitationServer{err: status.Error(codes.PermissionDenied, "not your tenant")}
			_, client := serveInvitations(t, srv)

			err := call(client)

			require.Error(t, err)
			assert.Equal(t, codes.PermissionDenied, status.Code(err))
			assert.NotNil(t, srv.last, "the request never reached the service")
		})
	}
}

// TestCreateInvitation_DefaultsTenantAndInviterFromTheSession: a WebUI
// form that omits tenant_id and invited_by_id gets both from the
// verified session, and the response is 201.
func TestCreateInvitation_DefaultsTenantAndInviterFromTheSession(t *testing.T) {
	srv := &fakeInvitationServer{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/invitations",
		strings.NewReader(`{"email":"new@example.com","role":"viewer"}`))
	req = withSession(req, "caller-tenant", "42")

	rec := serve(srv, req)

	assert.Equal(t, http.StatusCreated, rec.Code)
	want := &platformv1.CreateInvitationRequest{
		TenantId: "caller-tenant", Email: "new@example.com", Role: "viewer", InvitedById: 42,
	}
	assert.True(t, proto.Equal(want, srv.last), "service received %v, want %v", srv.last, want)
}

// TestCreateInvitation_KeepsExplicitTenantAndInviter: values the caller
// set are not overwritten by the session defaults.
func TestCreateInvitation_KeepsExplicitTenantAndInviter(t *testing.T) {
	srv := &fakeInvitationServer{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/invitations",
		strings.NewReader(`{"tenant_id":"other","email":"new@example.com","invited_by_id":5}`))
	req = withSession(req, "caller-tenant", "42")

	rec := serve(srv, req)

	assert.Equal(t, http.StatusCreated, rec.Code)
	got, ok := srv.last.(*platformv1.CreateInvitationRequest)
	require.True(t, ok, "service received %T", srv.last)
	assert.Equal(t, "other", got.GetTenantId())
	assert.Equal(t, uint64(5), got.GetInvitedById())
}

// TestListInvitations_ScopesToTheSessionTenant: the list is scoped by the
// verified session; a tenant_id query parameter cannot widen it.
func TestListInvitations_ScopesToTheSessionTenant(t *testing.T) {
	srv := &fakeInvitationServer{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/invitations?tenant_id=victim-tenant", nil)
	req = withSession(req, "caller-tenant", "42")

	rec := serve(srv, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, proto.Equal(&platformv1.ListInvitationsRequest{TenantId: "caller-tenant"}, srv.last),
		"service received %v", srv.last)
}

// TestInvitationHandlers_MalformedBodyIs400: a body that is not the
// request message is refused before the service is called.
func TestInvitationHandlers_MalformedBodyIs400(t *testing.T) {
	for _, path := range []string{
		"/api/v1/invitations",
		"/api/v1/invitations/accept",
		"/api/v1/invitations/42/revoke",
	} {
		t.Run(path, func(t *testing.T) {
			srv := &fakeInvitationServer{}
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"email":`))

			rec := serve(srv, req)

			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Contains(t, rec.Body.String(), "invalid request body")
			assert.Nil(t, srv.last, "a malformed body reached the service")
		})
	}
}

// TestInvitationHandlers_OverflowingIDIs400: an id that matches the
// numeric route pattern but does not fit a uint64 is a 400 naming the
// parameter, never a call with a truncated id.
func TestInvitationHandlers_OverflowingIDIs400(t *testing.T) {
	const tooBig = "18446744073709551616" // math.MaxUint64 + 1
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/invitations/" + tooBig},
		{http.MethodDelete, "/api/v1/invitations/" + tooBig},
		{http.MethodPost, "/api/v1/invitations/" + tooBig + "/revoke"},
	} {
		t.Run(tc.method, func(t *testing.T) {
			srv := &fakeInvitationServer{}

			rec := serve(srv, httptest.NewRequest(tc.method, tc.path, nil))

			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Contains(t, rec.Body.String(), `invalid query parameter \"id\"`)
			assert.Nil(t, srv.last, "an unparseable id reached the service")
		})
	}
}

// TestInvitationHandlers_NilServerIs503: with no invitation service wired
// every route answers 503 instead of panicking.
func TestInvitationHandlers_NilServerIs503(t *testing.T) {
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/invitations"},
		{http.MethodGet, "/api/v1/invitations/1"},
		{http.MethodDelete, "/api/v1/invitations/1"},
		{http.MethodPost, "/api/v1/invitations/1/revoke"},
		{http.MethodGet, "/api/v1/invitations/token/abc"},
		{http.MethodPost, "/api/v1/invitations/accept"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			rec := serve(nil, httptest.NewRequest(tc.method, tc.path, nil))

			assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
			assert.Contains(t, rec.Body.String(), "invitation service is not available")
		})
	}
}
