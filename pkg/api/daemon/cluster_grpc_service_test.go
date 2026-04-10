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

func TestNewClusterGRPCService(t *testing.T) {
	logger := logging.DefaultLogger()
	service := NewClusterGRPCService(logger)
	if service == nil {
		t.Fatal("NewClusterGRPCService returned nil")
	}
	if service.logger == nil {
		t.Error("expected logger to be set")
	}
}

func TestClusterGRPCService_AllMethodsReturnUnimplemented(t *testing.T) {
	logger := logging.DefaultLogger()
	service := NewClusterGRPCService(logger)
	ctx := context.Background()

	tests := []struct {
		name string
		call func() error
	}{
		{
			name: "Bootstrap",
			call: func() error {
				_, err := service.Bootstrap(ctx, &platformv1.BootstrapClusterRequest{})
				return err
			},
		},
		{
			name: "Join",
			call: func() error {
				_, err := service.Join(ctx, &platformv1.JoinClusterRequest{})
				return err
			},
		},
		{
			name: "Leave",
			call: func() error {
				_, err := service.Leave(ctx, &platformv1.LeaveClusterRequest{})
				return err
			},
		},
		{
			name: "GetStatus",
			call: func() error {
				_, err := service.GetStatus(ctx, &platformv1.GetClusterStatusRequest{})
				return err
			},
		},
		{
			name: "ListNodes",
			call: func() error {
				_, err := service.ListNodes(ctx, &platformv1.ListClusterNodesRequest{})
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

func TestClusterGRPCService_NilReturns(t *testing.T) {
	logger := logging.DefaultLogger()
	service := NewClusterGRPCService(logger)
	ctx := context.Background()

	t.Run("Bootstrap_returns_nil_response", func(t *testing.T) {
		resp, err := service.Bootstrap(ctx, &platformv1.BootstrapClusterRequest{})
		if resp != nil {
			t.Error("expected nil response")
		}
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("GetStatus_returns_nil_response", func(t *testing.T) {
		resp, err := service.GetStatus(ctx, &platformv1.GetClusterStatusRequest{})
		if resp != nil {
			t.Error("expected nil response")
		}
		if err == nil {
			t.Error("expected error")
		}
	})
}
