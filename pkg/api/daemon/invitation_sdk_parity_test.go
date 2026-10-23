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

package daemon

import (
	"context"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformservice "github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// invitationSDKConnect serves server through one daemon transport handler
// and returns the SDK's adapter for that transport, connected as a caller
// holding scopes.
type invitationSDKConnect func(t *testing.T, server platformv1.InvitationServiceServer, scopes ...string) grpc.ClientConnInterface

// invitationSDKFixture is an InvitationGRPCService over a fake servicer
// that records every call it sees.
type invitationSDKFixture struct {
	svc    *fakeInvitationServicer
	server *InvitationGRPCService
}

func newInvitationSDKFixture() *invitationSDKFixture {
	accepted := newTestInvitation()
	acceptedAt := accepted.CreatedAt.Add(time.Hour)
	accepted.Status = entities.InvitationStatusAccepted
	accepted.AcceptedAt = &acceptedAt
	fake := &fakeInvitationServicer{
		createResult:     newTestInvitation(),
		getByIDResult:    newTestInvitation(),
		getByTokenResult: accepted,
		listResult:       []*entities.Invitation{newTestInvitation(), accepted},
	}
	return &invitationSDKFixture{
		svc:    fake,
		server: NewInvitationGRPCService(logging.DefaultLogger(), fake),
	}
}

// recorded returns the calls the servicer saw.
func (f *invitationSDKFixture) recorded() invitationCalls {
	return f.svc.calls()
}

// invokeInvitationServer calls method on server through the generated
// gRPC handler, so the reply is exactly what a gRPC caller receives.
func invokeInvitationServer(server platformv1.InvitationServiceServer, method string, req proto.Message) (proto.Message, error) {
	for _, desc := range platformv1.InvitationService_ServiceDesc.Methods {
		if desc.MethodName != path.Base(method) {
			continue
		}
		decode := func(in interface{}) error {
			proto.Merge(in.(proto.Message), req)
			return nil
		}
		resp, err := desc.Handler(server, context.Background(), decode, nil)
		if err != nil {
			return nil, err
		}
		return resp.(proto.Message), nil
	}
	return nil, status.Errorf(codes.Unimplemented, "%s is not an InvitationService method", method)
}

// invitationSDKRequests holds one request per InvitationService method.
func invitationSDKRequests() map[string]proto.Message {
	return map[string]proto.Message{
		platformv1.InvitationService_CreateInvitation_FullMethodName: &platformv1.CreateInvitationRequest{
			TenantId: "tenant-1", Email: "alice@example.com", Role: "member", InvitedById: 99, ExpiresInSeconds: 3600,
		},
		platformv1.InvitationService_GetInvitation_FullMethodName:        &platformv1.GetInvitationRequest{InvitationId: 42},
		platformv1.InvitationService_GetInvitationByToken_FullMethodName: &platformv1.GetInvitationByTokenRequest{Token: "tok-1"},
		platformv1.InvitationService_ListInvitations_FullMethodName: &platformv1.ListInvitationsRequest{
			TenantId: "tenant-1", PendingOnly: true, StatusFilter: platformv1.InvitationStatus_INVITATION_STATUS_ACCEPTED,
		},
		platformv1.InvitationService_RevokeInvitation_FullMethodName: &platformv1.RevokeInvitationRequest{InvitationId: 42, RevokerId: 99},
		platformv1.InvitationService_AcceptInvitation_FullMethodName: &platformv1.AcceptInvitationRequest{Token: "tok-1", UserId: 7},
		platformv1.InvitationService_DeleteInvitation_FullMethodName: &platformv1.DeleteInvitationRequest{InvitationId: 42},
	}
}

// invitationSDKReplies holds an empty reply for each InvitationService
// method, for calls that are expected to fail.
func invitationSDKReplies() map[string]proto.Message {
	return map[string]proto.Message{
		platformv1.InvitationService_CreateInvitation_FullMethodName:     &platformv1.CreateInvitationResponse{},
		platformv1.InvitationService_GetInvitation_FullMethodName:        &platformv1.GetInvitationResponse{},
		platformv1.InvitationService_GetInvitationByToken_FullMethodName: &platformv1.GetInvitationResponse{},
		platformv1.InvitationService_ListInvitations_FullMethodName:      &platformv1.ListInvitationsResponse{},
		platformv1.InvitationService_RevokeInvitation_FullMethodName:     &platformv1.RevokeInvitationResponse{},
		platformv1.InvitationService_AcceptInvitation_FullMethodName:     &platformv1.AcceptInvitationResponse{},
		platformv1.InvitationService_DeleteInvitation_FullMethodName:     &platformv1.DeleteInvitationResponse{},
	}
}

// invitationInviteeMethods are the methods gRPC serves without a scope: the
// invitee holds no platform credential yet.
var invitationInviteeMethods = map[string]bool{
	platformv1.InvitationService_GetInvitationByToken_FullMethodName: true,
	platformv1.InvitationService_AcceptInvitation_FullMethodName:     true,
}

// clearInvitationTimestamp drops the reply's server clock reading, which
// differs between any two calls, after checking the reply carries one.
func clearInvitationTimestamp(t *testing.T, transport string, reply proto.Message) {
	t.Helper()
	msg := reply.ProtoReflect()
	field := msg.Descriptor().Fields().ByName("timestamp")
	require.NotNil(t, field, "%T has no timestamp field", reply)
	require.True(t, msg.Has(field), "%s reply carries no timestamp", transport)
	msg.Clear(field)
}

// testSDKInvitationMethods drives every InvitationService method through
// connect as a caller holding only the scope gRPC requires for it (none for
// the invitee methods), and requires the reply and the servicer calls to
// match a direct gRPC call.
func testSDKInvitationMethods(t *testing.T, transport string, connect invitationSDKConnect) {
	requests := invitationSDKRequests()
	require.Len(t, requests, len(platformv1.InvitationService_ServiceDesc.Methods))
	untouched := newInvitationSDKFixture().recorded()

	for method, req := range requests {
		t.Run(path.Base(method), func(t *testing.T) {
			direct := newInvitationSDKFixture()
			want, err := invokeInvitationServer(direct.server, method, req)
			require.NoError(t, err)

			var scopes []string
			scope := grpcapi.ScopeForMethod(method)
			if invitationInviteeMethods[method] {
				require.Empty(t, scope, "gRPC scopes the invitee method %s", method)
			} else {
				require.NotEmpty(t, scope, "gRPC has no scope for %s", method)
				scopes = append(scopes, scope)
			}

			via := newInvitationSDKFixture()
			got := want.ProtoReflect().New().Interface()
			conn := connect(t, via.server, scopes...)
			require.NoError(t, conn.Invoke(context.Background(), method, req, got))

			clearInvitationTimestamp(t, "gRPC", want)
			clearInvitationTimestamp(t, transport, got)
			require.True(t, proto.Equal(want, got), "%s reply\n%v\nwant the gRPC reply\n%v", transport, got, want)
			require.NotEqual(t, untouched, via.recorded(), "the invitation service saw no call")
			require.Equal(t, direct.recorded(), via.recorded())
		})
	}
}

// invitationRefusalCase is one scope class: a method needing it, and a
// caller holding every invitation scope but that one.
type invitationRefusalCase struct {
	class  string
	method string
	scopes []string
}

func invitationRefusalCases() []invitationRefusalCase {
	return []invitationRefusalCase{
		{
			class:  "invitation:read",
			method: platformv1.InvitationService_GetInvitation_FullMethodName,
			scopes: []string{"invitation:write", "invitation:delete"},
		},
		{
			class:  "invitation:write",
			method: platformv1.InvitationService_CreateInvitation_FullMethodName,
			scopes: []string{"invitation:read", "invitation:delete"},
		},
		{
			class:  "invitation:delete",
			method: platformv1.InvitationService_DeleteInvitation_FullMethodName,
			scopes: []string{"invitation:read", "invitation:write"},
		},
	}
}

// testSDKInvitationRefusesScope requires PermissionDenied for a caller
// without the method's scope, with the servicer never reached.
func testSDKInvitationRefusesScope(t *testing.T, transport string, connect invitationSDKConnect) {
	for _, tc := range invitationRefusalCases() {
		t.Run(tc.class+" without the scope", func(t *testing.T) {
			require.Equal(t, tc.class, grpcapi.ScopeForMethod(tc.method))
			f := newInvitationSDKFixture()
			before := f.recorded()
			conn := connect(t, f.server, tc.scopes...)

			err := conn.Invoke(context.Background(), tc.method, invitationSDKRequests()[tc.method], invitationSDKReplies()[tc.method])

			require.Equal(t, codes.PermissionDenied, status.Code(err), "%s: %v", transport, err)
			require.Equal(t, before, f.recorded(), "a refused caller reached the invitation service")
		})
	}
}

// invitationNotFoundCases makes the servicer miss the invitation each
// method names, by ID or by token.
func invitationNotFoundCases() map[string]func(f *fakeInvitationServicer) {
	byID := platformservice.ErrInvitationNotFound{ID: 42}
	byToken := platformservice.ErrInvitationNotFound{Token: "tok-1"}
	return map[string]func(f *fakeInvitationServicer){
		platformv1.InvitationService_GetInvitation_FullMethodName:        func(f *fakeInvitationServicer) { f.getByIDErr = byID },
		platformv1.InvitationService_GetInvitationByToken_FullMethodName: func(f *fakeInvitationServicer) { f.getByTokenErr = byToken },
		platformv1.InvitationService_RevokeInvitation_FullMethodName:     func(f *fakeInvitationServicer) { f.revokeReturned = byID },
		platformv1.InvitationService_AcceptInvitation_FullMethodName:     func(f *fakeInvitationServicer) { f.acceptReturned = byToken },
		platformv1.InvitationService_DeleteInvitation_FullMethodName:     func(f *fakeInvitationServicer) { f.deleteReturned = byID },
	}
}

// testSDKInvitationRefusesNotFound requires NotFound, as gRPC answers, for
// every method that names an invitation that does not exist.
func testSDKInvitationRefusesNotFound(t *testing.T, transport string, connect invitationSDKConnect) {
	for method, missing := range invitationNotFoundCases() {
		req := invitationSDKRequests()[method]

		t.Run(path.Base(method)+" of an invitation not found", func(t *testing.T) {
			direct := newInvitationSDKFixture()
			missing(direct.svc)
			want, err := invokeInvitationServer(direct.server, method, req)
			require.Nil(t, want)
			require.Equal(t, codes.NotFound, status.Code(err), "gRPC: %v", err)

			via := newInvitationSDKFixture()
			missing(via.svc)
			conn := connect(t, via.server, "*:*")
			err = conn.Invoke(context.Background(), method, req, invitationSDKReplies()[method])
			require.Equal(t, codes.NotFound, status.Code(err), "%s: %v", transport, err)
		})
	}
}
