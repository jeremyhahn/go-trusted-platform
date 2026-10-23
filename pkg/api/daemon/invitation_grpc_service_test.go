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
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformservice "github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestNewInvitationGRPCService(t *testing.T) {
	logger := logging.DefaultLogger()
	service := NewInvitationGRPCService(logger, nil)
	if service == nil {
		t.Fatal("NewInvitationGRPCService returned nil")
	}
	if service.logger == nil {
		t.Error("expected logger to be set")
	}
}

func TestInvitationGRPCService_AllMethodsReturnUnimplemented(t *testing.T) {
	logger := logging.DefaultLogger()
	service := NewInvitationGRPCService(logger, nil)
	ctx := context.Background()

	tests := []struct {
		name string
		call func() error
	}{
		{
			name: "CreateInvitation",
			call: func() error {
				_, err := service.CreateInvitation(ctx, &platformv1.CreateInvitationRequest{})
				return err
			},
		},
		{
			name: "GetInvitation",
			call: func() error {
				_, err := service.GetInvitation(ctx, &platformv1.GetInvitationRequest{})
				return err
			},
		},
		{
			name: "GetInvitationByToken",
			call: func() error {
				_, err := service.GetInvitationByToken(ctx, &platformv1.GetInvitationByTokenRequest{})
				return err
			},
		},
		{
			name: "ListInvitations",
			call: func() error {
				_, err := service.ListInvitations(ctx, &platformv1.ListInvitationsRequest{})
				return err
			},
		},
		{
			name: "RevokeInvitation",
			call: func() error {
				_, err := service.RevokeInvitation(ctx, &platformv1.RevokeInvitationRequest{})
				return err
			},
		},
		{
			name: "AcceptInvitation",
			call: func() error {
				_, err := service.AcceptInvitation(ctx, &platformv1.AcceptInvitationRequest{})
				return err
			},
		},
		{
			name: "DeleteInvitation",
			call: func() error {
				_, err := service.DeleteInvitation(ctx, &platformv1.DeleteInvitationRequest{})
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.call()
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			st, ok := status.FromError(err)
			if !ok {
				t.Fatalf("expected gRPC status error, got %T: %v", err, err)
			}
			if st.Code() != codes.Unimplemented {
				t.Errorf("expected code Unimplemented, got %v", st.Code())
			}
		})
	}
}

func TestInvitationGRPCService_NilReturns(t *testing.T) {
	logger := logging.DefaultLogger()
	service := NewInvitationGRPCService(logger, nil)
	ctx := context.Background()

	t.Run("CreateInvitation_returns_nil_response", func(t *testing.T) {
		resp, err := service.CreateInvitation(ctx, &platformv1.CreateInvitationRequest{})
		if resp != nil {
			t.Error("expected nil response")
		}
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("GetInvitation_returns_nil_response", func(t *testing.T) {
		resp, err := service.GetInvitation(ctx, &platformv1.GetInvitationRequest{})
		if resp != nil {
			t.Error("expected nil response")
		}
		if err == nil {
			t.Error("expected error")
		}
	})
}

// =============================================================================
// Wired-in servicer tests
//
// These tests exercise the gRPC service when an InvitationServicer has
// been injected, mirroring the same test surface the daemon's
// MCPServiceProvider exercises. The fakeInvitationServicer fixture is
// shared with mcp_invitation_test.go.
// =============================================================================

func TestInvitationGRPCService_WithService_Create(t *testing.T) {
	logger := logging.DefaultLogger()
	inv := newTestInvitation()
	fake := &fakeInvitationServicer{createResult: inv}
	svc := NewInvitationGRPCService(logger, fake)

	resp, err := svc.CreateInvitation(context.Background(), &platformv1.CreateInvitationRequest{
		TenantId:         "tenant-1",
		Email:            "alice@example.com",
		Role:             "member",
		InvitedById:      99,
		ExpiresInSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.Invitation == nil {
		t.Fatalf("expected invitation in response")
	}
	if resp.Invitation.Id != 42 {
		t.Errorf("id = %d", resp.Invitation.Id)
	}
	if fake.createReq.ExpiresIn.Seconds() != 3600 {
		t.Errorf("ExpiresIn = %v", fake.createReq.ExpiresIn)
	}
	if svc.Service() != fake {
		t.Errorf("Service() did not return injected fake")
	}
}

func TestInvitationGRPCService_WithService_NilRequestRejected(t *testing.T) {
	logger := logging.DefaultLogger()
	fake := &fakeInvitationServicer{}
	svc := NewInvitationGRPCService(logger, fake)
	ctx := context.Background()

	calls := []func() error{
		func() error { _, err := svc.CreateInvitation(ctx, nil); return err },
		func() error { _, err := svc.GetInvitation(ctx, nil); return err },
		func() error { _, err := svc.GetInvitationByToken(ctx, nil); return err },
		func() error { _, err := svc.ListInvitations(ctx, nil); return err },
		func() error { _, err := svc.RevokeInvitation(ctx, nil); return err },
		func() error { _, err := svc.AcceptInvitation(ctx, nil); return err },
		func() error { _, err := svc.DeleteInvitation(ctx, nil); return err },
	}
	for i, c := range calls {
		err := c()
		if err == nil {
			t.Errorf("case %d: expected error", i)
			continue
		}
		st, ok := status.FromError(err)
		if !ok || st.Code() != codes.InvalidArgument {
			t.Errorf("case %d: expected InvalidArgument, got %v", i, err)
		}
	}
}

func TestInvitationGRPCService_WithService_GetByID(t *testing.T) {
	fake := &fakeInvitationServicer{getByIDResult: newTestInvitation()}
	svc := NewInvitationGRPCService(logging.DefaultLogger(), fake)

	resp, err := svc.GetInvitation(context.Background(), &platformv1.GetInvitationRequest{InvitationId: 42})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Invitation.Id != 42 {
		t.Errorf("id = %d", resp.Invitation.Id)
	}
}

func TestInvitationGRPCService_WithService_GetByID_Error(t *testing.T) {
	sentinel := errors.New("nope")
	fake := &fakeInvitationServicer{getByIDErr: sentinel}
	svc := NewInvitationGRPCService(logging.DefaultLogger(), fake)

	_, err := svc.GetInvitation(context.Background(), &platformv1.GetInvitationRequest{InvitationId: 1})
	assertInvitationStatus(t, err, codes.Internal, sentinel.Error())
}

func TestInvitationGRPCService_WithService_GetByToken(t *testing.T) {
	fake := &fakeInvitationServicer{getByTokenResult: newTestInvitation()}
	svc := NewInvitationGRPCService(logging.DefaultLogger(), fake)

	resp, err := svc.GetInvitationByToken(context.Background(), &platformv1.GetInvitationByTokenRequest{Token: "tok-1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Invitation.Token != "tok-1" {
		t.Errorf("token = %q", resp.Invitation.Token)
	}
}

func TestInvitationGRPCService_WithService_GetByToken_Error(t *testing.T) {
	sentinel := errors.New("nope")
	fake := &fakeInvitationServicer{getByTokenErr: sentinel}
	svc := NewInvitationGRPCService(logging.DefaultLogger(), fake)

	_, err := svc.GetInvitationByToken(context.Background(), &platformv1.GetInvitationByTokenRequest{Token: "x"})
	assertInvitationStatus(t, err, codes.Internal, sentinel.Error())
}

func TestInvitationGRPCService_WithService_List(t *testing.T) {
	pending := newTestInvitation()
	accepted := newTestInvitation()
	accepted.ID = 43
	accepted.Email = "bob@example.com"
	accepted.Status = entities.InvitationStatusAccepted
	fake := &fakeInvitationServicer{listResult: []*entities.Invitation{pending, accepted}}
	svc := NewInvitationGRPCService(logging.DefaultLogger(), fake)
	ctx := context.Background()

	// All
	resp, err := svc.ListInvitations(ctx, &platformv1.ListInvitationsRequest{TenantId: "tenant-1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Invitations) != 2 {
		t.Errorf("expected 2, got %d", len(resp.Invitations))
	}
	if fake.listPending {
		t.Errorf("expected listAll, got listPending")
	}

	// Pending only flag delegates to ListPendingByTenant.
	_, err = svc.ListInvitations(ctx, &platformv1.ListInvitationsRequest{TenantId: "tenant-1", PendingOnly: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !fake.listPending {
		t.Errorf("expected ListPendingByTenant call")
	}

	// Status filter retains only ACCEPTED.
	resp, err = svc.ListInvitations(ctx, &platformv1.ListInvitationsRequest{
		TenantId:     "tenant-1",
		StatusFilter: platformv1.InvitationStatus_INVITATION_STATUS_ACCEPTED,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Invitations) != 1 || resp.Invitations[0].Status != platformv1.InvitationStatus_INVITATION_STATUS_ACCEPTED {
		t.Errorf("unexpected list result with status filter: %+v", resp.Invitations)
	}

	// Email filter is case-insensitive substring match.
	resp, err = svc.ListInvitations(ctx, &platformv1.ListInvitationsRequest{
		TenantId:    "tenant-1",
		EmailFilter: "BOB",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Invitations) != 1 || resp.Invitations[0].Email != "bob@example.com" {
		t.Errorf("unexpected list result with email filter: %+v", resp.Invitations)
	}
}

func TestInvitationGRPCService_WithService_List_Error(t *testing.T) {
	sentinel := errors.New("db gone")
	fake := &fakeInvitationServicer{listErr: sentinel}
	svc := NewInvitationGRPCService(logging.DefaultLogger(), fake)

	_, err := svc.ListInvitations(context.Background(), &platformv1.ListInvitationsRequest{TenantId: "t"})
	assertInvitationStatus(t, err, codes.Internal, sentinel.Error())
}

func TestInvitationGRPCService_WithService_Revoke(t *testing.T) {
	fake := &fakeInvitationServicer{}
	svc := NewInvitationGRPCService(logging.DefaultLogger(), fake)

	resp, err := svc.RevokeInvitation(context.Background(), &platformv1.RevokeInvitationRequest{InvitationId: 42, RevokerId: 99})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Status.Success {
		t.Errorf("expected Success=true")
	}
	if fake.revokeID != 42 || fake.revokeRevoker != 99 {
		t.Errorf("delegation mismatch")
	}
}

func TestInvitationGRPCService_WithService_Revoke_Error(t *testing.T) {
	sentinel := errors.New("nope")
	fake := &fakeInvitationServicer{revokeReturned: sentinel}
	svc := NewInvitationGRPCService(logging.DefaultLogger(), fake)

	_, err := svc.RevokeInvitation(context.Background(), &platformv1.RevokeInvitationRequest{InvitationId: 1, RevokerId: 2})
	assertInvitationStatus(t, err, codes.Internal, sentinel.Error())
}

func TestInvitationGRPCService_WithService_Accept(t *testing.T) {
	inv := newTestInvitation()
	now := time.Now().UTC()
	inv.Status = entities.InvitationStatusAccepted
	inv.AcceptedAt = &now
	fake := &fakeInvitationServicer{getByTokenResult: inv}
	svc := NewInvitationGRPCService(logging.DefaultLogger(), fake)

	resp, err := svc.AcceptInvitation(context.Background(), &platformv1.AcceptInvitationRequest{Token: "tok-1", UserId: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Status.Success {
		t.Errorf("expected Success=true")
	}
	if resp.Invitation == nil || resp.Invitation.Status != platformv1.InvitationStatus_INVITATION_STATUS_ACCEPTED {
		t.Errorf("expected accepted invitation in response")
	}
}

func TestInvitationGRPCService_WithService_Accept_Error(t *testing.T) {
	sentinel := errors.New("expired")
	fake := &fakeInvitationServicer{acceptReturned: sentinel}
	svc := NewInvitationGRPCService(logging.DefaultLogger(), fake)

	_, err := svc.AcceptInvitation(context.Background(), &platformv1.AcceptInvitationRequest{Token: "t", UserId: 1})
	assertInvitationStatus(t, err, codes.Internal, sentinel.Error())
}

func TestInvitationGRPCService_WithService_Accept_ReadbackFailure(t *testing.T) {
	fake := &fakeInvitationServicer{getByTokenErr: errors.New("disk")}
	svc := NewInvitationGRPCService(logging.DefaultLogger(), fake)

	resp, err := svc.AcceptInvitation(context.Background(), &platformv1.AcceptInvitationRequest{Token: "tok-1", UserId: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Status.Success {
		t.Errorf("expected Success=true")
	}
	if resp.Invitation != nil {
		t.Errorf("expected nil invitation when read-back fails")
	}
}

func TestInvitationGRPCService_WithService_Delete(t *testing.T) {
	fake := &fakeInvitationServicer{}
	svc := NewInvitationGRPCService(logging.DefaultLogger(), fake)

	resp, err := svc.DeleteInvitation(context.Background(), &platformv1.DeleteInvitationRequest{InvitationId: 42})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Status.Success {
		t.Errorf("expected Success=true")
	}
	if fake.deleteID != 42 {
		t.Errorf("id = %d", fake.deleteID)
	}
}

func TestInvitationGRPCService_WithService_Delete_Error(t *testing.T) {
	sentinel := errors.New("nope")
	fake := &fakeInvitationServicer{deleteReturned: sentinel}
	svc := NewInvitationGRPCService(logging.DefaultLogger(), fake)

	_, err := svc.DeleteInvitation(context.Background(), &platformv1.DeleteInvitationRequest{InvitationId: 1})
	assertInvitationStatus(t, err, codes.Internal, sentinel.Error())
}

func TestInvitationGRPCService_SetService(t *testing.T) {
	fake := &fakeInvitationServicer{}
	svc := NewInvitationGRPCService(logging.DefaultLogger(), nil)
	if svc.Service() != nil {
		t.Errorf("expected nil service initially")
	}
	svc.SetService(fake)
	if svc.Service() != fake {
		t.Errorf("SetService did not take")
	}
}

func TestInvitationStatusToProto_Mapping(t *testing.T) {
	cases := []struct {
		in   entities.InvitationStatus
		want platformv1.InvitationStatus
	}{
		{entities.InvitationStatusPending, platformv1.InvitationStatus_INVITATION_STATUS_PENDING},
		{entities.InvitationStatusAccepted, platformv1.InvitationStatus_INVITATION_STATUS_ACCEPTED},
		{entities.InvitationStatusExpired, platformv1.InvitationStatus_INVITATION_STATUS_EXPIRED},
		{entities.InvitationStatusRevoked, platformv1.InvitationStatus_INVITATION_STATUS_REVOKED},
		{entities.InvitationStatus("garbage"), platformv1.InvitationStatus_INVITATION_STATUS_UNSPECIFIED},
	}
	for _, c := range cases {
		got := invitationStatusToProto(c.in)
		if got != c.want {
			t.Errorf("%q: got %v, want %v", c.in, got, c.want)
		}
	}
}

func TestInvitationToProto_Nil(t *testing.T) {
	if invitationToProto(nil) != nil {
		t.Errorf("expected nil for nil input")
	}
}

func TestContainsFold(t *testing.T) {
	cases := []struct {
		hay, needle string
		want        bool
	}{
		{"alice@example.com", "ALICE", true},
		{"alice@example.com", "bob", false},
		{"AbCdEf", "cdef", true},
		{"abc", "", true},
	}
	for _, c := range cases {
		if got := containsFold(c.hay, c.needle); got != c.want {
			t.Errorf("containsFold(%q,%q) = %v, want %v", c.hay, c.needle, got, c.want)
		}
	}
}

// assertInvitationStatus checks err is a gRPC status with the given code and
// the service error's message.
func assertInvitationStatus(t *testing.T, err error, want codes.Code, message string) {
	t.Helper()
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("error %v is not a gRPC status", err)
	}
	if st.Code() != want || st.Message() != message {
		t.Fatalf("status = %v %q, want %v %q", st.Code(), st.Message(), want, message)
	}
}

// TestInvitationGRPCService_ServiceErrorsKeepTheirClass pins the code each
// typed invitation error is answered with. Without the mapping a missing
// invitation reached gRPC, QUIC and the SDK as Unknown.
func TestInvitationGRPCService_ServiceErrorsKeepTheirClass(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want codes.Code
	}{
		{"not found by id", platformservice.ErrInvitationNotFound{ID: 7}, codes.NotFound},
		{"not found by token", platformservice.ErrInvitationNotFound{Token: "gone"}, codes.NotFound},
		{"invalid", platformservice.ErrInvalidInvitation{Reason: "email is required"}, codes.InvalidArgument},
		{"email registered", platformservice.ErrEmailAlreadyRegistered{Email: "a@b.c", TenantID: "t"}, codes.AlreadyExists},
		{"expired", platformservice.ErrInvitationExpired{Token: "t"}, codes.FailedPrecondition},
		{"already accepted", platformservice.ErrInvitationAlreadyAccepted{Token: "t"}, codes.FailedPrecondition},
		{"revoked", platformservice.ErrInvitationRevoked{Token: "t"}, codes.FailedPrecondition},
		{"already revoked", platformservice.ErrInvitationAlreadyRevoked{ID: 7}, codes.FailedPrecondition},
		{"bad status", platformservice.ErrInvalidInvitationStatus{Status: "garbage"}, codes.FailedPrecondition},
		{"save failed", platformservice.ErrInvitationSaveFailed{Cause: errors.New("disk")}, codes.Internal},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fake := &fakeInvitationServicer{getByIDErr: c.err}
			svc := NewInvitationGRPCService(logging.DefaultLogger(), fake)

			_, err := svc.GetInvitation(context.Background(), &platformv1.GetInvitationRequest{InvitationId: 7})
			assertInvitationStatus(t, err, c.want, c.err.Error())
		})
	}
}
