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

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestNewBarrierGRPCService(t *testing.T) {
	logger := logging.DefaultLogger()
	service := NewBarrierGRPCService(logger, nil)
	if service == nil {
		t.Fatal("NewBarrierGRPCService returned nil")
	}
	if service.logger == nil {
		t.Error("expected logger to be set")
	}
	if service.barrier != nil {
		t.Error("expected barrier to be nil when no manager provided")
	}
}

func TestBarrierGRPCService_NilBarrierReturnsUnavailable(t *testing.T) {
	logger := logging.DefaultLogger()
	service := NewBarrierGRPCService(logger, nil)
	ctx := context.Background()

	tests := []struct {
		name string
		call func() error
	}{
		{
			name: "Init",
			call: func() error {
				_, err := service.Init(ctx, &platformv1.BarrierInitRequest{
					Secret: "test-secret",
				})
				return err
			},
		},
		{
			name: "GetStatus",
			call: func() error {
				_, err := service.GetStatus(ctx, &platformv1.BarrierStatusRequest{})
				return err
			},
		},
		{
			name: "Unseal",
			call: func() error {
				_, err := service.Unseal(ctx, &platformv1.BarrierUnsealRequest{
					Secret: "test-secret",
				})
				return err
			},
		},
		{
			name: "Seal",
			call: func() error {
				_, err := service.Seal(ctx, &platformv1.BarrierSealRequest{})
				return err
			},
		},
		{
			name: "Rekey",
			call: func() error {
				_, err := service.Rekey(ctx, &platformv1.BarrierRekeyRequest{
					Threshold: 3,
					Shares:    5,
				})
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
			if st.Code() != codes.Unavailable {
				t.Errorf("expected code Unavailable, got %v", st.Code())
			}
		})
	}
}

func TestBarrierGRPCService_NilReturns(t *testing.T) {
	logger := logging.DefaultLogger()
	service := NewBarrierGRPCService(logger, nil)
	ctx := context.Background()

	t.Run("Init_returns_nil_response", func(t *testing.T) {
		resp, err := service.Init(ctx, &platformv1.BarrierInitRequest{})
		if resp != nil {
			t.Error("expected nil response")
		}
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("GetStatus_returns_nil_response", func(t *testing.T) {
		resp, err := service.GetStatus(ctx, &platformv1.BarrierStatusRequest{})
		if resp != nil {
			t.Error("expected nil response")
		}
		if err == nil {
			t.Error("expected error")
		}
	})
}

func TestStrategyStringToProto(t *testing.T) {
	tests := []struct {
		input    string
		expected platformv1.BarrierStrategy
	}{
		{"single_key", platformv1.BarrierStrategy_BARRIER_STRATEGY_SINGLE_KEY},
		{"shamir", platformv1.BarrierStrategy_BARRIER_STRATEGY_SHAMIR},
		{"unknown", platformv1.BarrierStrategy_BARRIER_STRATEGY_UNSPECIFIED},
		{"", platformv1.BarrierStrategy_BARRIER_STRATEGY_UNSPECIFIED},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := strategyStringToProto(tt.input)
			if result != tt.expected {
				t.Errorf("strategyStringToProto(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestBarrierErrorToGRPC(t *testing.T) {
	t.Run("nil_error_returns_nil", func(t *testing.T) {
		if err := barrierErrorToGRPC(nil); err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	})

	t.Run("unknown_error_returns_internal", func(t *testing.T) {
		err := barrierErrorToGRPC(context.DeadlineExceeded)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("expected gRPC status error")
		}
		if st.Code() != codes.Internal {
			t.Errorf("expected Internal, got %v", st.Code())
		}
	})
}
