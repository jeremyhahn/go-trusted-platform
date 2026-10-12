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
	"fmt"
	"log/slog"
	"testing"
	"time"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/pkg/barrier"
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

func TestStrategyToProto(t *testing.T) {
	tests := []struct {
		name      string
		strategy  string
		threshold int
		expected  platformv1.BarrierStrategy
	}{
		{"shamir", "shamir", 0, platformv1.BarrierStrategy_BARRIER_STRATEGY_SHAMIR},
		{"threshold_means_shamir", "system-barrier", 3, platformv1.BarrierStrategy_BARRIER_STRATEGY_SHAMIR},
		{"passphrase", "passphrase", 0, platformv1.BarrierStrategy_BARRIER_STRATEGY_SINGLE_KEY},
		{"software", "software", 0, platformv1.BarrierStrategy_BARRIER_STRATEGY_SINGLE_KEY},
		{"tpm2", "tpm2", 0, platformv1.BarrierStrategy_BARRIER_STRATEGY_SINGLE_KEY},
		{"pkcs11", "pkcs11", 0, platformv1.BarrierStrategy_BARRIER_STRATEGY_SINGLE_KEY},
		{"system_barrier", "system-barrier", 0, platformv1.BarrierStrategy_BARRIER_STRATEGY_SINGLE_KEY},
		{"none", "none", 0, platformv1.BarrierStrategy_BARRIER_STRATEGY_UNSPECIFIED},
		{"unknown", "unknown", 0, platformv1.BarrierStrategy_BARRIER_STRATEGY_UNSPECIFIED},
		{"empty", "", 0, platformv1.BarrierStrategy_BARRIER_STRATEGY_UNSPECIFIED},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := strategyToProto(tt.strategy, tt.threshold)
			if result != tt.expected {
				t.Errorf("strategyToProto(%q, %d) = %v, want %v", tt.strategy, tt.threshold, result, tt.expected)
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

	tests := []struct {
		name string
		err  error
		want codes.Code
	}{
		{"wrapped_sealed", &barrier.ManagerError{Op: "Rekey", Err: fmt.Errorf("upstream: %w", barrier.ErrSealed)}, codes.FailedPrecondition},
		{"wrapped_already_initialized", fmt.Errorf("init: %w", barrier.ErrAlreadyInitialized), codes.AlreadyExists},
		{"wrapped_invalid_threshold", fmt.Errorf("rekey: %w", barrier.ErrInvalidThreshold), codes.InvalidArgument},
		{"upstream_grpc_status", &barrier.ManagerError{Op: "Unseal", Err: status.Error(codes.PermissionDenied, "wrong secret")}, codes.PermissionDenied},
		{"deadline", fmt.Errorf("status: %w", context.DeadlineExceeded), codes.DeadlineExceeded},
		{"unclassified", errors.New("disk on fire"), codes.Internal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st, ok := status.FromError(barrierErrorToGRPC(tt.err))
			if !ok {
				t.Fatal("expected gRPC status error")
			}
			if st.Code() != tt.want {
				t.Errorf("code = %v, want %v", st.Code(), tt.want)
			}
			if st.Message() != tt.err.Error() {
				t.Errorf("message = %q, want %q", st.Message(), tt.err.Error())
			}
		})
	}
}

// stubBarrierClient answers the barrier calls the service makes with
// canned SDK responses.
type stubBarrierClient struct {
	quicbaassdk.QRDBBarrierClient
	status    *quicbaassdk.QRDBBarrierStatusResponse
	statusErr error
	rekey     *quicbaassdk.QRDBBarrierRekeyResponse
}

func (c *stubBarrierClient) BarrierStatus(context.Context) (*quicbaassdk.QRDBBarrierStatusResponse, error) {
	return c.status, c.statusErr
}

func (c *stubBarrierClient) BarrierRekey(context.Context, *quicbaassdk.QRDBBarrierRekeyRequest) (*quicbaassdk.QRDBBarrierRekeyResponse, error) {
	return c.rekey, nil
}

type stubBarrierSecurity struct {
	quicbaassdk.SecurityService
	client *stubBarrierClient
}

func (s stubBarrierSecurity) Barrier() (quicbaassdk.QRDBBarrierClient, error) { return s.client, nil }

type stubBarrierSDK struct {
	quicbaassdk.Client
	client *stubBarrierClient
}

func (c stubBarrierSDK) Security() quicbaassdk.SecurityService {
	return stubBarrierSecurity{client: c.client}
}

// newStubBarrierService builds the service over a real barrier.Manager whose
// SDK is the stub. The manager is never synced, so its cached flags keep
// their defaults: initialized false, sealed true.
func newStubBarrierService(t *testing.T, client *stubBarrierClient) *BarrierGRPCService {
	t.Helper()
	mgr, err := barrier.NewManager(stubBarrierSDK{client: client}, barrier.DefaultConfig(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return NewBarrierGRPCService(logging.DefaultLogger(), mgr)
}

func TestBarrierGRPCService_GetStatusFromSDKStatus(t *testing.T) {
	initializedAt := "2026-10-11T10:00:00Z"
	want, err := time.Parse(time.RFC3339, initializedAt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	tests := []struct {
		name            string
		status          *quicbaassdk.QRDBBarrierStatusResponse
		wantInitialized bool
		wantSealed      bool
		wantStrategy    platformv1.BarrierStrategy
		wantThreshold   int32
		wantSharesTotal int32
		wantTimestamp   bool
	}{
		{
			name:            "shamir",
			status:          &quicbaassdk.QRDBBarrierStatusResponse{Sealed: true, Strategy: "shamir", InitializedAt: initializedAt, ShamirThreshold: 3, ShamirTotal: 5},
			wantInitialized: true,
			wantSealed:      true,
			wantStrategy:    platformv1.BarrierStrategy_BARRIER_STRATEGY_SHAMIR,
			wantThreshold:   3,
			wantSharesTotal: 5,
			wantTimestamp:   true,
		},
		{
			name:            "passphrase",
			status:          &quicbaassdk.QRDBBarrierStatusResponse{Sealed: false, Strategy: "passphrase", InitializedAt: initializedAt},
			wantInitialized: true,
			wantStrategy:    platformv1.BarrierStrategy_BARRIER_STRATEGY_SINGLE_KEY,
			wantTimestamp:   true,
		},
		{
			name:         "uninitialized",
			status:       &quicbaassdk.QRDBBarrierStatusResponse{Sealed: true, Strategy: "none"},
			wantSealed:   true,
			wantStrategy: platformv1.BarrierStrategy_BARRIER_STRATEGY_UNSPECIFIED,
		},
		{
			name:            "unparseable_timestamp",
			status:          &quicbaassdk.QRDBBarrierStatusResponse{Sealed: true, Strategy: "passphrase", InitializedAt: "yesterday"},
			wantInitialized: true,
			wantSealed:      true,
			wantStrategy:    platformv1.BarrierStrategy_BARRIER_STRATEGY_SINGLE_KEY,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := newStubBarrierService(t, &stubBarrierClient{status: tt.status})

			resp, err := service.GetStatus(context.Background(), &platformv1.BarrierStatusRequest{})
			if err != nil {
				t.Fatalf("GetStatus: %v", err)
			}
			if resp.GetInitialized() != tt.wantInitialized {
				t.Errorf("initialized = %v, want %v", resp.GetInitialized(), tt.wantInitialized)
			}
			if resp.GetSealed() != tt.wantSealed {
				t.Errorf("sealed = %v, want %v", resp.GetSealed(), tt.wantSealed)
			}
			if resp.GetStrategy() != tt.wantStrategy {
				t.Errorf("strategy = %v, want %v", resp.GetStrategy(), tt.wantStrategy)
			}
			if resp.GetThreshold() != tt.wantThreshold {
				t.Errorf("threshold = %d, want %d", resp.GetThreshold(), tt.wantThreshold)
			}
			if resp.GetSharesTotal() != tt.wantSharesTotal {
				t.Errorf("shares_total = %d, want %d", resp.GetSharesTotal(), tt.wantSharesTotal)
			}
			if tt.wantTimestamp {
				if !resp.GetInitializedAt().AsTime().Equal(want) {
					t.Errorf("initialized_at = %v, want %v", resp.GetInitializedAt(), want)
				}
			} else if resp.GetInitializedAt() != nil {
				t.Errorf("initialized_at = %v, want unset", resp.GetInitializedAt())
			}
		})
	}
}

func TestBarrierGRPCService_GetStatusError(t *testing.T) {
	service := newStubBarrierService(t, &stubBarrierClient{statusErr: status.Error(codes.Unavailable, "qrdb down")})

	resp, err := service.GetStatus(context.Background(), &platformv1.BarrierStatusRequest{})
	if resp != nil {
		t.Errorf("expected nil response, got %v", resp)
	}
	if got := status.Code(err); got != codes.Unavailable {
		t.Errorf("code = %v, want Unavailable", got)
	}
}

func TestBarrierGRPCService_RekeyStrategyFromSDKResponse(t *testing.T) {
	tests := []struct {
		name         string
		rekey        *quicbaassdk.QRDBBarrierRekeyResponse
		wantStrategy platformv1.BarrierStrategy
	}{
		{
			name:         "shamir_split",
			rekey:        &quicbaassdk.QRDBBarrierRekeyResponse{Threshold: 3, TotalShares: 5, ShareCount: 5},
			wantStrategy: platformv1.BarrierStrategy_BARRIER_STRATEGY_SHAMIR,
		},
		{
			name:         "no_split_reported",
			rekey:        &quicbaassdk.QRDBBarrierRekeyResponse{},
			wantStrategy: platformv1.BarrierStrategy_BARRIER_STRATEGY_UNSPECIFIED,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &stubBarrierClient{
				status: &quicbaassdk.QRDBBarrierStatusResponse{Sealed: false, Strategy: "passphrase", InitializedAt: "2026-10-11T10:00:00Z"},
				rekey:  tt.rekey,
			}
			service := newStubBarrierService(t, client)
			if err := service.barrier.SyncStatus(context.Background()); err != nil {
				t.Fatalf("SyncStatus: %v", err)
			}

			resp, err := service.Rekey(context.Background(), &platformv1.BarrierRekeyRequest{Threshold: 3, Shares: 5})
			if err != nil {
				t.Fatalf("Rekey: %v", err)
			}
			if resp.GetStrategy() != tt.wantStrategy {
				t.Errorf("strategy = %v, want %v", resp.GetStrategy(), tt.wantStrategy)
			}
			if resp.GetThreshold() != int32(tt.rekey.Threshold) {
				t.Errorf("threshold = %d, want %d", resp.GetThreshold(), tt.rekey.Threshold)
			}
			if resp.GetSharesTotal() != int32(tt.rekey.TotalShares) {
				t.Errorf("shares_total = %d, want %d", resp.GetSharesTotal(), tt.rekey.TotalShares)
			}
			if resp.GetShareCount() != int32(tt.rekey.ShareCount) {
				t.Errorf("share_count = %d, want %d", resp.GetShareCount(), tt.rekey.ShareCount)
			}
		})
	}
}

func TestBarrierGRPCService_RekeySealedIsFailedPrecondition(t *testing.T) {
	service := newStubBarrierService(t, &stubBarrierClient{})

	resp, err := service.Rekey(context.Background(), &platformv1.BarrierRekeyRequest{Threshold: 3, Shares: 5})
	if resp != nil {
		t.Errorf("expected nil response, got %v", resp)
	}
	if got := status.Code(err); got != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition", got)
	}
}
