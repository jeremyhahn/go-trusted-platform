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

func TestNewEABGRPCService(t *testing.T) {
	logger := logging.DefaultLogger()
	service := NewEABGRPCService(logger)
	if service == nil {
		t.Fatal("NewEABGRPCService returned nil")
	}
	if service.logger == nil {
		t.Error("expected logger to be set")
	}
}

func TestEABGRPCService_AllMethodsReturnUnimplemented(t *testing.T) {
	logger := logging.DefaultLogger()
	service := NewEABGRPCService(logger)
	ctx := context.Background()

	tests := []struct {
		name string
		call func() error
	}{
		{
			name: "CreateCredential",
			call: func() error {
				_, err := service.CreateCredential(ctx, &platformv1.CreateEABCredentialRequest{})
				return err
			},
		},
		{
			name: "GetCredential",
			call: func() error {
				_, err := service.GetCredential(ctx, &platformv1.GetEABCredentialRequest{})
				return err
			},
		},
		{
			name: "GetCredentialByKeyID",
			call: func() error {
				_, err := service.GetCredentialByKeyID(ctx, &platformv1.GetEABCredentialByKeyIDRequest{})
				return err
			},
		},
		{
			name: "ListCredentials",
			call: func() error {
				_, err := service.ListCredentials(ctx, &platformv1.ListEABCredentialsRequest{})
				return err
			},
		},
		{
			name: "RevokeCredential",
			call: func() error {
				_, err := service.RevokeCredential(ctx, &platformv1.RevokeEABCredentialRequest{})
				return err
			},
		},
		{
			name: "ValidateCredential",
			call: func() error {
				_, err := service.ValidateCredential(ctx, &platformv1.ValidateEABCredentialRequest{})
				return err
			},
		},
		{
			name: "DeleteCredential",
			call: func() error {
				_, err := service.DeleteCredential(ctx, &platformv1.DeleteEABCredentialRequest{})
				return err
			},
		},
		{
			name: "GetCredentialQRCode",
			call: func() error {
				_, err := service.GetCredentialQRCode(ctx, &platformv1.GetEABCredentialQRCodeRequest{})
				return err
			},
		},
		{
			name: "GetEnrollmentURL",
			call: func() error {
				_, err := service.GetEnrollmentURL(ctx, &platformv1.GetEABEnrollmentURLRequest{})
				return err
			},
		},
		{
			name: "MarkCredentialUsed",
			call: func() error {
				_, err := service.MarkCredentialUsed(ctx, &platformv1.MarkEABCredentialUsedRequest{})
				return err
			},
		},
		{
			name: "CleanupExpiredCredentials",
			call: func() error {
				_, err := service.CleanupExpiredCredentials(ctx, &platformv1.CleanupExpiredEABCredentialsRequest{})
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

func TestEABGRPCService_NilReturns(t *testing.T) {
	logger := logging.DefaultLogger()
	service := NewEABGRPCService(logger)
	ctx := context.Background()

	t.Run("CreateCredential_returns_nil_response", func(t *testing.T) {
		resp, err := service.CreateCredential(ctx, &platformv1.CreateEABCredentialRequest{})
		if resp != nil {
			t.Error("expected nil response")
		}
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("GetCredential_returns_nil_response", func(t *testing.T) {
		resp, err := service.GetCredential(ctx, &platformv1.GetEABCredentialRequest{})
		if resp != nil {
			t.Error("expected nil response")
		}
		if err == nil {
			t.Error("expected error")
		}
	})
}
