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

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/nat64"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// GatewayNAT64Interface abstracts the NAT64 translator status for the API
// layers. *gateway.Gateway implements it by delegating to its running
// nat64 service.
type GatewayNAT64Interface interface {
	NAT64Status(ctx context.Context) (nat64.Health, error)
}

// Ensure gateway.Gateway implements GatewayNAT64Interface.
var _ GatewayNAT64Interface = (*gateway.Gateway)(nil)

// WithNAT64 sets the NAT64 backend for the service.
func WithNAT64(n GatewayNAT64Interface) GatewayServiceOption {
	return func(s *GatewayService) {
		s.nat64 = n
	}
}

// NAT64 returns the NAT64 backend, for tests.
func (s *GatewayService) NAT64() GatewayNAT64Interface {
	return s.nat64
}

// SetNAT64 sets the NAT64 backend, for tests.
func (s *GatewayService) SetNAT64(n GatewayNAT64Interface) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nat64 = n
}

// requireNAT64 refuses the call when no translator backend is wired.
func (s *GatewayService) requireNAT64() error {
	if s.nat64 == nil {
		return status.Error(codes.Unavailable, "nat64 translator not configured")
	}
	return nil
}

// nat64ErrToGRPC maps NAT64 errors to gRPC status codes. A section that is
// not running is Unavailable, not NotFound: the translator may be
// configured and simply refused at start, and the operator needs to tell
// those apart from a gateway that never had the section.
func nat64ErrToGRPC(err error) error {
	if err == nil {
		return nil
	}
	var notActive *gateway.ErrServiceNotActive
	var unavailable *nat64.ErrNAT64ModuleUnavailable
	switch {
	case errors.As(err, &notActive), errors.Is(err, nat64.ErrNotStarted):
		return status.Error(codes.Unavailable, err.Error())
	case errors.As(err, &unavailable):
		return status.Error(codes.FailedPrecondition, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}

// nat64HealthToProto converts the service health snapshot to the wire type.
// It is shared by every transport so the transports cannot drift in what
// they report.
func nat64HealthToProto(health nat64.Health) *platformv1.NAT64Status {
	out := &platformv1.NAT64Status{
		Active:          health.Active,
		InstancePresent: health.InstancePresent,
		Prefix:          health.Prefix,
		Instance:        health.Instance,
		Sessions:        health.Sessions,
		Pool4Used:       health.Pool4Used,
		ModuleVersion:   health.ModuleVersion,
		FlowCount:       uint32(health.FlowCount),
	}
	if !health.LastReconcile.IsZero() {
		out.LastReconcile = timestamppb.New(health.LastReconcile)
	}
	if health.LastError != nil {
		out.LastError = health.LastError.Error()
	}
	return out
}

// GetNAT64Status reports the translator's health.
func (s *GatewayService) GetNAT64Status(ctx context.Context, req *platformv1.GetNAT64StatusRequest) (*platformv1.GetNAT64StatusResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if err := s.requireNAT64(); err != nil {
		return nil, err
	}
	health, err := s.nat64.NAT64Status(ctx)
	if err != nil {
		return nil, nat64ErrToGRPC(err)
	}
	return &platformv1.GetNAT64StatusResponse{Status: nat64HealthToProto(health)}, nil
}
