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

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/nat64"
)

// requireNAT64 refuses when no translator backend is wired.
func (s *gatewayRESTService) requireNAT64() (GatewayNAT64Interface, error) {
	if s.nat64 == nil {
		return nil, rest.ErrNAT64NotConfigured{}
	}
	return s.nat64, nil
}

// mapNAT64Error converts NAT64 errors to typed REST errors.
func mapNAT64Error(err error) error {
	if err == nil {
		return nil
	}
	var notActive *gateway.ErrServiceNotActive
	var unavailable *nat64.ErrNAT64ModuleUnavailable
	switch {
	case errors.As(err, &notActive), errors.Is(err, nat64.ErrNotStarted):
		return rest.ErrNAT64NotConfigured{}
	case errors.As(err, &unavailable):
		return rest.ErrNAT64ModuleUnavailable{Detail: unavailable.Error()}
	default:
		return err
	}
}

// GetNAT64Status implements rest.GatewayServiceInterface.
func (s *gatewayRESTService) GetNAT64Status(ctx context.Context) (*rest.NAT64StatusResponse, error) {
	backend, err := s.requireNAT64()
	if err != nil {
		return nil, err
	}
	health, err := backend.NAT64Status(ctx)
	if err != nil {
		return nil, mapNAT64Error(err)
	}
	out := &rest.NAT64StatusResponse{
		Active:          health.Active,
		InstancePresent: health.InstancePresent,
		Prefix:          health.Prefix,
		Instance:        health.Instance,
		Sessions:        health.Sessions,
		Pool4Used:       health.Pool4Used,
		ModuleVersion:   health.ModuleVersion,
		FlowCount:       health.FlowCount,
		LastReconcile:   health.LastReconcile,
	}
	if health.LastError != nil {
		out.LastError = health.LastError.Error()
	}
	return out, nil
}
