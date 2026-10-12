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

	"github.com/jeremyhahn/go-trusted-platform/pkg/barrier"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"

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
// If threshold >= barrier.MinShamirThreshold, Shamir secret sharing is used;
// otherwise single-key mode.
func (s *BarrierGRPCService) Init(
	ctx context.Context,
	req *platformv1.BarrierInitRequest,
) (*platformv1.BarrierInitResponse, error) {
	if s.barrier == nil {
		return nil, status.Error(codes.Unavailable, "barrier: manager not configured")
	}

	now := timestamppb.New(time.Now())

	// Shamir mode: the threshold reaches the platform minimum.
	if req.GetThreshold() >= barrier.MinShamirThreshold {
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
			Status:        &platformv1.Status{Success: true, Message: "barrier initialized with shamir secret sharing; shares are sealed to enrolled security officers and claimed via the share-claim flow"},
			Strategy:      platformv1.BarrierStrategy_BARRIER_STRATEGY_SHAMIR,
			Threshold:     int32(resp.Threshold),
			SharesTotal:   int32(resp.TotalShares),
			ShareCount:    int32(resp.ShareCount),
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
		InitializedAt: now,
	}, nil
}

// GetStatus returns the current status of the barrier. Every field comes
// from one SDK status call, never from the manager's cached flags, so the
// response cannot mix two readings of the barrier.
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
		Status: &platformv1.Status{Success: true},
		Sealed: sdkStatus.Sealed,
		// A non-empty InitializedAt is the SDK's signal that the barrier
		// has been initialized, as in Manager.SyncStatus.
		Initialized: sdkStatus.InitializedAt != "",
		Strategy:    strategyToProto(sdkStatus.Strategy, sdkStatus.ShamirThreshold),
		Threshold:   int32(sdkStatus.ShamirThreshold),
		SharesTotal: int32(sdkStatus.ShamirTotal),
	}

	if sdkStatus.InitializedAt != "" {
		t, parseErr := time.Parse(time.RFC3339, sdkStatus.InitializedAt)
		if parseErr != nil {
			s.logger.Warn("barrier status: unparseable initialized_at",
				"initialized_at", sdkStatus.InitializedAt, "error", parseErr)
		} else {
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

// Rekey generates new unseal keys for the barrier. The reported strategy
// comes from the split the SDK says it made, not from the request.
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
		Status:      &platformv1.Status{Success: true, Message: "barrier rekeyed; new shares are sealed to enrolled security officers and claimed via the share-claim flow"},
		Strategy:    strategyToProto("", resp.Threshold),
		Threshold:   int32(resp.Threshold),
		SharesTotal: int32(resp.TotalShares),
		ShareCount:  int32(resp.ShareCount),
	}, nil
}

// strategyNameToProto maps the SDK's seal strategy names to the wire enum.
// Every strategy that unseals with one secret is SINGLE_KEY; "none" and any
// name not listed are UNSPECIFIED.
var strategyNameToProto = map[string]platformv1.BarrierStrategy{
	"shamir":         platformv1.BarrierStrategy_BARRIER_STRATEGY_SHAMIR,
	"passphrase":     platformv1.BarrierStrategy_BARRIER_STRATEGY_SINGLE_KEY,
	"software":       platformv1.BarrierStrategy_BARRIER_STRATEGY_SINGLE_KEY,
	"tpm2":           platformv1.BarrierStrategy_BARRIER_STRATEGY_SINGLE_KEY,
	"pkcs11":         platformv1.BarrierStrategy_BARRIER_STRATEGY_SINGLE_KEY,
	"system-barrier": platformv1.BarrierStrategy_BARRIER_STRATEGY_SINGLE_KEY,
}

// strategyToProto reports the wire strategy of an SDK status or rekey
// response. A Shamir threshold means SHAMIR whatever the strategy name, since
// the SDK sets one only on a Shamir-split barrier.
func strategyToProto(strategy string, threshold int) platformv1.BarrierStrategy {
	if threshold > 0 {
		return platformv1.BarrierStrategy_BARRIER_STRATEGY_SHAMIR
	}
	if v, ok := strategyNameToProto[strategy]; ok {
		return v
	}
	return platformv1.BarrierStrategy_BARRIER_STRATEGY_UNSPECIFIED
}

// barrierErrorToGRPC turns a barrier error into a gRPC status carrying the
// code barrier.Code assigns, so every transport classifies it the same way.
func barrierErrorToGRPC(err error) error {
	if err == nil {
		return nil
	}
	return status.Error(barrier.Code(err), err.Error())
}
