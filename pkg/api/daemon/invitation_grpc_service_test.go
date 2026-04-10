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
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestNewInvitationGRPCService(t *testing.T) {
	logger := logging.DefaultLogger()
	service := NewInvitationGRPCService(logger)
	if service == nil {
		t.Fatal("NewInvitationGRPCService returned nil")
	}
	if service.logger == nil {
		t.Error("expected logger to be set")
	}
}

func TestInvitationGRPCService_AllMethodsReturnUnimplemented(t *testing.T) {
	logger := logging.DefaultLogger()
	service := NewInvitationGRPCService(logger)
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
	service := NewInvitationGRPCService(logger)
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
