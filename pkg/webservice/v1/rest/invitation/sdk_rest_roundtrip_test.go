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
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

// fakeInvitationServer records the request each item handler built.
type fakeInvitationServer struct {
	platformv1.UnimplementedInvitationServiceServer
	last proto.Message
	err  error
}

func (f *fakeInvitationServer) GetInvitationByToken(_ context.Context, r *platformv1.GetInvitationByTokenRequest) (*platformv1.GetInvitationResponse, error) {
	f.last = r
	return &platformv1.GetInvitationResponse{
		Invitation: &platformv1.Invitation{Id: 17, Token: r.GetToken(), Email: "invitee@example.com"},
	}, f.err
}

func (f *fakeInvitationServer) RevokeInvitation(_ context.Context, r *platformv1.RevokeInvitationRequest) (*platformv1.RevokeInvitationResponse, error) {
	f.last = r
	return &platformv1.RevokeInvitationResponse{}, f.err
}

func (f *fakeInvitationServer) DeleteInvitation(_ context.Context, r *platformv1.DeleteInvitationRequest) (*platformv1.DeleteInvitationResponse, error) {
	f.last = r
	return &platformv1.DeleteInvitationResponse{}, f.err
}

// serveInvitations serves both halves of the invitation router over TLS, as
// the webservice mounts them, and returns the server and the SDK invitation
// client dialed through the REST transport.
func serveInvitations(t *testing.T, srv platformv1.InvitationServiceServer) (*httptest.Server, platformv1.InvitationServiceClient) {
	t.Helper()

	logger := logging.NewLogger(slog.LevelError, io.Discard)
	r := NewInvitationRouter(logger, srv, response.NewResponseWriter(logger, nil))
	root := mux.NewRouter()
	root.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	sub := root.PathPrefix("/api/v1").Subrouter()
	r.RegisterInviteeRoutes(sub)
	r.RegisterRoutes(sub)

	server := httptest.NewTLSServer(root)
	t.Cleanup(server.Close)

	tlsConfig := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	adapter, err := sdkrest.Connect(context.Background(),
		platform.NewOptions(platform.WithRESTAddr(server.URL), platform.WithTLSConfig(tlsConfig)))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, adapter.Close()) })

	return server, platformv1.NewInvitationServiceClient(adapter.Connection())
}

// TestSDKREST_GetInvitationByToken: the token travels in the path of the
// invitee route, and the invitation the handler returns reaches the caller.
// Before #452 the SDK sent GET /api/v1/invitations/by-token, which 404'd.
func TestSDKREST_GetInvitationByToken(t *testing.T) {
	srv := &fakeInvitationServer{}
	_, client := serveInvitations(t, srv)

	resp, err := client.GetInvitationByToken(context.Background(),
		&platformv1.GetInvitationByTokenRequest{Token: "inv-tok_ABC123"})

	require.NoError(t, err)
	assert.True(t, proto.Equal(&platformv1.GetInvitationByTokenRequest{Token: "inv-tok_ABC123"}, srv.last))
	assert.Equal(t, uint64(17), resp.GetInvitation().GetId())
	assert.Equal(t, "inv-tok_ABC123", resp.GetInvitation().GetToken())
}

// TestSDKREST_GetInvitationByToken_EmptyTokenNeverLeavesTheClient: an empty
// token would turn the path into the collection, so the SDK refuses it.
func TestSDKREST_GetInvitationByToken_EmptyTokenNeverLeavesTheClient(t *testing.T) {
	srv := &fakeInvitationServer{}
	_, client := serveInvitations(t, srv)

	_, err := client.GetInvitationByToken(context.Background(), &platformv1.GetInvitationByTokenRequest{})

	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Nil(t, srv.last)
}

// TestSDKREST_InvitationItemOperations: the invitation id travels in the
// numeric {id} segment, and RevokeInvitation keeps revoker_id in the body.
func TestSDKREST_InvitationItemOperations(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		call func(platformv1.InvitationServiceClient) error
		want proto.Message
	}{
		{
			name: "RevokeInvitation",
			call: func(c platformv1.InvitationServiceClient) error {
				_, err := c.RevokeInvitation(ctx, &platformv1.RevokeInvitationRequest{InvitationId: 42, RevokerId: 7})
				return err
			},
			want: &platformv1.RevokeInvitationRequest{InvitationId: 42, RevokerId: 7},
		},
		{
			name: "DeleteInvitation",
			call: func(c platformv1.InvitationServiceClient) error {
				_, err := c.DeleteInvitation(ctx, &platformv1.DeleteInvitationRequest{InvitationId: 42})
				return err
			},
			want: &platformv1.DeleteInvitationRequest{InvitationId: 42},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := &fakeInvitationServer{}
			_, client := serveInvitations(t, srv)

			require.NoError(t, tc.call(client))

			require.NotNil(t, srv.last, "the request reached no handler")
			assert.True(t, proto.Equal(tc.want, srv.last),
				"handler received %T %v, want %T %v", srv.last, srv.last, tc.want, tc.want)
		})
	}
}

// TestSDKREST_RevokeInvitation_ZeroIDNeverLeavesTheClient: zero is no
// invitation, and the {id:[0-9]+} segment cannot be empty, so the SDK refuses
// it before the wire.
func TestSDKREST_RevokeInvitation_ZeroIDNeverLeavesTheClient(t *testing.T) {
	srv := &fakeInvitationServer{}
	_, client := serveInvitations(t, srv)

	_, err := client.RevokeInvitation(context.Background(), &platformv1.RevokeInvitationRequest{RevokerId: 7})

	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Nil(t, srv.last)
}

// TestSDKREST_RevokeInvitation_NonNumericIDIsRefused: the route the SDK now
// claims accepts only a numeric id. A non-numeric one, which the uint64 field
// cannot produce but a hand-built request can, matches no route and reaches no
// handler.
func TestSDKREST_RevokeInvitation_NonNumericIDIsRefused(t *testing.T) {
	srv := &fakeInvitationServer{}
	server, _ := serveInvitations(t, srv)

	for _, req := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/invitations/abc/revoke"},
		{http.MethodDelete, "/api/v1/invitations/abc"},
	} {
		httpReq, err := http.NewRequestWithContext(context.Background(), req.method, server.URL+req.path, nil)
		require.NoError(t, err)
		resp, err := server.Client().Do(httpReq)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())

		assert.Equal(t, http.StatusNotFound, resp.StatusCode, "%s %s", req.method, req.path)
	}
	assert.Nil(t, srv.last, "a non-numeric invitation id reached a handler")
}

// TestSDKREST_RevokeInvitation_ServerErrorKeepsItsStatus: a NotFound from the
// server comes back to the SDK caller as NotFound.
func TestSDKREST_RevokeInvitation_ServerErrorKeepsItsStatus(t *testing.T) {
	srv := &fakeInvitationServer{err: status.Error(codes.NotFound, "invitation not found")}
	_, client := serveInvitations(t, srv)

	_, err := client.RevokeInvitation(context.Background(), &platformv1.RevokeInvitationRequest{InvitationId: 999, RevokerId: 7})

	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}
