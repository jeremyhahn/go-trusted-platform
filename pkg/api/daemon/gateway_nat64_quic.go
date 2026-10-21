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

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/nat64"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// NAT64Status on the zone-only adapter reports that no translator is wired.
// This adapter serves a daemon with zone services but no gateway
// controller, so the honest answer is "not configured", not a zero health
// snapshot that would read as a translator holding no sessions.
func (a *zoneGatewayAdapter) NAT64Status(_ context.Context) (*quicwire.NAT64StatusInfo, error) {
	return nil, errGatewayFeatureNotConfigured
}

// requireNAT64 resolves the shared service's translator backend, or
// reports errGatewayFeatureNotConfigured (StatusUnavailable on the wire).
func (a *fullGatewayQUICAdapter) requireNAT64() (GatewayNAT64Interface, error) {
	if a.backends == nil || a.backends.NAT64() == nil {
		return nil, errGatewayFeatureNotConfigured
	}
	return a.backends.NAT64(), nil
}

// mapNAT64ToQUICError converts NAT64 errors to the QUIC adapter's
// vocabulary. A section that is not running is "not configured" on the
// wire: from a caller's side there is no translator to report on, and the
// reason travels in the message. A kernel that cannot carry the translator
// is a failed precondition, as it is on gRPC and REST.
func mapNAT64ToQUICError(err error) error {
	if err == nil {
		return nil
	}
	var notActive *gateway.ErrServiceNotActive
	var unavailable *nat64.ErrNAT64ModuleUnavailable
	switch {
	case errors.As(err, &notActive), errors.Is(err, nat64.ErrNotStarted):
		return errGatewayFeatureNotConfigured
	case errors.As(err, &unavailable):
		return quic.ErrGatewayPreconditionDetail{Reason: unavailable.Error()}
	default:
		return err
	}
}

// nat64HealthToQUICInfo converts the service health snapshot to the QUIC
// wire shape.
func nat64HealthToQUICInfo(health nat64.Health) *quicwire.NAT64StatusInfo {
	out := &quicwire.NAT64StatusInfo{
		Active:          health.Active,
		InstancePresent: health.InstancePresent,
		Prefix:          health.Prefix,
		Instance:        health.Instance,
		Sessions:        health.Sessions,
		Pool4Used:       health.Pool4Used,
		ModuleVersion:   health.ModuleVersion,
		FlowCount:       health.FlowCount,
	}
	if !health.LastReconcile.IsZero() {
		out.LastReconcile = health.LastReconcile.Unix()
	}
	if health.LastError != nil {
		out.LastError = health.LastError.Error()
	}
	return out
}

// NAT64Status returns the NAT64 translator's health snapshot.
func (a *fullGatewayQUICAdapter) NAT64Status(ctx context.Context) (*quicwire.NAT64StatusInfo, error) {
	backend, err := a.requireNAT64()
	if err != nil {
		return nil, err
	}
	health, err := backend.NAT64Status(ctx)
	if err != nil {
		return nil, mapNAT64ToQUICError(err)
	}
	return nat64HealthToQUICInfo(health), nil
}
