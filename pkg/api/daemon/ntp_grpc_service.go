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

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// NTPGRPCService implements the platform.v1 NTPService backed by the
// platform's ntp.Service. The same instance is registered on the TCP gRPC
// server and the Unix-socket gRPC server, and backs the REST, QUIC, and MCP
// transports, so every protocol reports the same clock.
type NTPGRPCService struct {
	platformv1.UnimplementedNTPServiceServer

	backend NTPBackend
	logger  *logging.Logger
}

// NewNTPGRPCService creates the NTP gRPC service. A nil backend means the
// node has no `ntp:` section; every RPC then returns a typed Unavailable
// error rather than panicking.
func NewNTPGRPCService(logger *logging.Logger, backend NTPBackend) *NTPGRPCService {
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	return &NTPGRPCService{logger: logger, backend: backend}
}

// SetBackend wires the time-synchronization backend after construction.
func (s *NTPGRPCService) SetBackend(backend NTPBackend) { s.backend = backend }

// Backend returns the configured backend.
func (s *NTPGRPCService) Backend() NTPBackend { return s.backend }

// requireBackend returns a typed Unavailable error when time synchronization
// is not configured on this node.
func (s *NTPGRPCService) requireBackend() error {
	if s.backend == nil {
		return status.Error(codes.Unavailable, ErrNTPNotConfigured{}.Error())
	}
	return nil
}

// GetStatus returns the node's current synchronization state.
//
// Permission: ntp:read.
func (s *NTPGRPCService) GetStatus(ctx context.Context, _ *platformv1.GetNTPStatusRequest) (*platformv1.GetNTPStatusResponse, error) {
	if err := s.requireBackend(); err != nil {
		return nil, err
	}

	result, err := s.backend.Status(ctx)
	if err != nil {
		s.logger.Error(err, "ntp status query failed")
		return nil, ntpErrToGRPC(err)
	}

	return &platformv1.GetNTPStatusResponse{Status: ntpStatusToPb(result)}, nil
}

// ListSources returns every configured time source and its live state.
//
// Permission: ntp:read.
func (s *NTPGRPCService) ListSources(ctx context.Context, _ *platformv1.ListNTPSourcesRequest) (*platformv1.ListNTPSourcesResponse, error) {
	if err := s.requireBackend(); err != nil {
		return nil, err
	}

	sources, err := s.backend.Sources(ctx)
	if err != nil {
		s.logger.Error(err, "ntp source enumeration failed")
		return nil, ntpErrToGRPC(err)
	}

	return &platformv1.ListNTPSourcesResponse{Sources: ntpSourcesToPb(sources)}, nil
}

// Step forces an immediate clock correction. It is an operator recovery
// action and fails with Aborted (REST 409 Conflict) when no source is
// reachable, rather than moving the clock on stale data.
//
// Permission: ntp:write.
func (s *NTPGRPCService) Step(ctx context.Context, _ *platformv1.StepNTPClockRequest) (*platformv1.StepNTPClockResponse, error) {
	if err := s.requireBackend(); err != nil {
		return nil, err
	}

	result, err := s.backend.Step(ctx)
	if err != nil {
		s.logger.Error(err, "ntp manual step failed")
		return nil, ntpErrToGRPC(err)
	}

	s.logger.Info("ntp clock stepped by operator request",
		"stratum", result.Stratum,
		"offset_seconds", result.OffsetSeconds)

	return &platformv1.StepNTPClockResponse{Status: ntpStatusToPb(result)}, nil
}
