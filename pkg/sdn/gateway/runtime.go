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

package gateway

import (
	"fmt"
	"log/slog"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ct"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// GatewayRuntime carries the runtime dependencies the daemon injects into
// the gateway before Start. It is never serialized; config-file loading
// leaves it nil, and services that need it (firewall, NAT) fail Start with
// ErrRuntimeMissing when their config section is enabled without it.
type GatewayRuntime struct {
	// Controller installs OpenFlow rules (the shared policy flow path).
	Controller policy.FlowController

	// OVS is the OVSDB/OpenFlow client for cookie-scoped flow deletion,
	// strict deletes, and OF port resolution.
	OVS ovs.ClientInterface

	// Groups programs OpenFlow group table entries (load balancer select
	// groups). The concrete ovs.Client implements it; injectors normally
	// pass the same client as OVS.
	Groups ovs.GroupClient

	// Bridge is the OVS bridge the gateway services program. Individual
	// service configs may override it.
	Bridge string

	// Zones returns the current resolved zone set (hot-refreshable).
	Zones func() []zone.ZoneConfig

	// Networks returns the current zone → VLAN/subnet summary map
	// (hot-refreshable).
	Networks func() map[zone.Zone]zoneflows.NetworkSummary

	// CTZones allocates conntrack zone IDs shared by all gateway services.
	CTZones *ct.ZoneAllocator

	// Logger receives service lifecycle logs.
	Logger *slog.Logger

	// pipelineGuard tracks the base pipeline this runtime holds (#567).
	pipelineGuard
}

// Close releases the runtime's OVS connection. Safe to call on a nil
// receiver or a runtime without an OVS client; the injecting daemon owns
// the call once the gateway no longer needs the datapath.
func (r *GatewayRuntime) Close() error {
	if r == nil || r.OVS == nil {
		return nil
	}
	return r.OVS.Close()
}

// ErrRuntimeMissing is returned when a service that requires injected
// runtime dependencies is enabled while GatewayConfig.Runtime is nil.
type ErrRuntimeMissing struct {
	// Service is the service that required the runtime.
	Service string
}

// Error implements the error interface.
func (e *ErrRuntimeMissing) Error() string {
	return fmt.Sprintf("gateway: service %s enabled without injected runtime dependencies", e.Service)
}
