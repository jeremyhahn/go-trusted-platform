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
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/barrier"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// BarrierGRPCService implements the Barrier gRPC service for barrier
// lifecycle operations including initialization, seal/unseal, and rekeying.
type BarrierGRPCService struct {
	platformv1.UnimplementedBarrierServiceServer

	logger  *logging.Logger
	barrier *barrier.Manager
}

// NewBarrierGRPCService creates a new Barrier gRPC service instance.
func NewBarrierGRPCService(logger *logging.Logger, mgr *barrier.Manager) *BarrierGRPCService {
	return &BarrierGRPCService{
		logger:  logger,
		barrier: mgr,
	}
}

// Init initializes the barrier with the specified configuration.
// If threshold >= 2, Shamir secret sharing is used; otherwise single-key mode.
func (s *BarrierGRPCService) Init(
	ctx context.Context,
	req *platformv1.BarrierInitRequest,
) (*platformv1.BarrierInitResponse, error) {
	if s.barrier == nil {
		return nil, status.Error(codes.Unavailable, "barrier: manager not configured")
	}

	now := timestamppb.New(time.Now())

	// Shamir mode: threshold >= 2
	if req.GetThreshold() >= 2 {
		resp, err := s.barrier.InitializeShamir(
			ctx,
			req.GetSecret(),
			int(req.GetThreshold()),
			int(req.GetShares()),
		)
		if err != nil {
			return nil, barrierErrorToGRPC(err)
		}

		return &platformv1.BarrierInitResponse{
			Status:        &platformv1.Status{Success: true, Message: "barrier initialized with shamir secret sharing"},
			Strategy:      platformv1.BarrierStrategy_BARRIER_STRATEGY_SHAMIR,
			UnsealKeys:    resp.Shares,
			InitializedAt: now,
		}, nil
	}

	// Single-key mode
	if err := s.barrier.Initialize(ctx, req.GetSecret()); err != nil {
		return nil, barrierErrorToGRPC(err)
	}

	return &platformv1.BarrierInitResponse{
		Status:        &platformv1.Status{Success: true, Message: "barrier initialized with single key"},
		Strategy:      platformv1.BarrierStrategy_BARRIER_STRATEGY_SINGLE_KEY,
		UnsealKeys:    []string{req.GetSecret()},
		InitializedAt: now,
	}, nil
}

// GetStatus returns the current status of the barrier.
func (s *BarrierGRPCService) GetStatus(
	ctx context.Context,
	req *platformv1.BarrierStatusRequest,
) (*platformv1.BarrierStatusResponse, error) {
	if s.barrier == nil {
		return nil, status.Error(codes.Unavailable, "barrier: manager not configured")
	}

	sdkStatus, err := s.barrier.Status(ctx)
	if err != nil {
		return nil, barrierErrorToGRPC(err)
	}

	resp := &platformv1.BarrierStatusResponse{
		Status:      &platformv1.Status{Success: true},
		Sealed:      sdkStatus.Sealed,
		Initialized: s.barrier.IsInitialized(),
	}

	// Map strategy string to protobuf enum
	resp.Strategy = strategyStringToProto(sdkStatus.Strategy)

	// Parse initialized_at timestamp if present
	if sdkStatus.InitializedAt != "" {
		if t, parseErr := time.Parse(time.RFC3339, sdkStatus.InitializedAt); parseErr == nil {
			resp.InitializedAt = timestamppb.New(t)
		}
	}

	return resp, nil
}

// Unseal unseals the barrier using a secret or Shamir share.
// The barrier configuration determines whether to use single-key or
// Shamir share mode. When Shamir is configured, the secret is submitted
// as a share toward the unseal threshold.
func (s *BarrierGRPCService) Unseal(
	ctx context.Context,
	req *platformv1.BarrierUnsealRequest,
) (*platformv1.BarrierUnsealResponse, error) {
	if s.barrier == nil {
		return nil, status.Error(codes.Unavailable, "barrier: manager not configured")
	}

	// Check barrier configuration to determine unseal mode
	cfg := s.barrier.Config()
	if cfg != nil && cfg.IsShamir() {
		// Shamir mode: submit the secret as a share
		shareResp, err := s.barrier.UnsealWithShare(ctx, req.GetSecret())
		if err != nil {
			return nil, barrierErrorToGRPC(err)
		}

		return &platformv1.BarrierUnsealResponse{
			Status:          &platformv1.Status{Success: true},
			Sealed:          !shareResp.Complete,
			SharesProvided:  int32(shareResp.Submitted),
			SharesThreshold: int32(shareResp.Required),
		}, nil
	}

	// Single-key mode: direct unseal
	if err := s.barrier.Unseal(ctx, req.GetSecret()); err != nil {
		return nil, barrierErrorToGRPC(err)
	}

	return &platformv1.BarrierUnsealResponse{
		Status: &platformv1.Status{Success: true, Message: "barrier unsealed"},
		Sealed: false,
	}, nil
}

// Seal seals the barrier, protecting all data at rest.
func (s *BarrierGRPCService) Seal(
	ctx context.Context,
	req *platformv1.BarrierSealRequest,
) (*platformv1.BarrierSealResponse, error) {
	if s.barrier == nil {
		return nil, status.Error(codes.Unavailable, "barrier: manager not configured")
	}

	if err := s.barrier.Seal(ctx); err != nil {
		return nil, barrierErrorToGRPC(err)
	}

	return &platformv1.BarrierSealResponse{
		Status: &platformv1.Status{Success: true, Message: "barrier sealed"},
		Sealed: true,
	}, nil
}

// Rekey generates new unseal keys for the barrier.
func (s *BarrierGRPCService) Rekey(
	ctx context.Context,
	req *platformv1.BarrierRekeyRequest,
) (*platformv1.BarrierRekeyResponse, error) {
	if s.barrier == nil {
		return nil, status.Error(codes.Unavailable, "barrier: manager not configured")
	}

	resp, err := s.barrier.Rekey(ctx, int(req.GetThreshold()), int(req.GetShares()))
	if err != nil {
		return nil, barrierErrorToGRPC(err)
	}

	return &platformv1.BarrierRekeyResponse{
		Status:     &platformv1.Status{Success: true, Message: "barrier rekeyed"},
		Strategy:   platformv1.BarrierStrategy_BARRIER_STRATEGY_SHAMIR,
		UnsealKeys: resp.Shares,
	}, nil
}

// strategyStringToProto maps a barrier strategy string from the SDK to
// the corresponding protobuf enum value.
func strategyStringToProto(strategy string) platformv1.BarrierStrategy {
	strategyMap := map[string]platformv1.BarrierStrategy{
		"single_key": platformv1.BarrierStrategy_BARRIER_STRATEGY_SINGLE_KEY,
		"shamir":     platformv1.BarrierStrategy_BARRIER_STRATEGY_SHAMIR,
	}
	if v, ok := strategyMap[strategy]; ok {
		return v
	}
	return platformv1.BarrierStrategy_BARRIER_STRATEGY_UNSPECIFIED
}

// barrierErrorToGRPC maps barrier package errors to appropriate gRPC status codes.
func barrierErrorToGRPC(err error) error {
	if err == nil {
		return nil
	}

	errorCodeMap := map[error]codes.Code{
		barrier.ErrAlreadyInitialized: codes.AlreadyExists,
		barrier.ErrNotInitialized:     codes.FailedPrecondition,
		barrier.ErrSealed:             codes.FailedPrecondition,
		barrier.ErrNotSealed:          codes.FailedPrecondition,
		barrier.ErrEmptySecret:        codes.InvalidArgument,
		barrier.ErrEmptyShare:         codes.InvalidArgument,
		barrier.ErrInvalidThreshold:   codes.InvalidArgument,
		barrier.ErrNilContext:         codes.InvalidArgument,
		barrier.ErrNilSDKClient:       codes.Internal,
		barrier.ErrNilConfig:          codes.Internal,
	}

	for sentinel, code := range errorCodeMap {
		if err == sentinel {
			return status.Error(code, err.Error())
		}
	}

	return status.Errorf(codes.Internal, "barrier: %v", err)
}
