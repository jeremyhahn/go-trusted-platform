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
	"errors"
	"fmt"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/hostfw"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/nat64"
	"log/slog"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ct"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/modes"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// GatewayRuntime carries the runtime dependencies the daemon injects into
// the gateway before Start. It is never serialized; config-file loading
// leaves it nil, and services that need it (firewall, NAT) fail Start with
// ErrRuntimeMissing when their config section is enabled without it.
type overlayOpenFlowClient interface {
	modes.OverlayOpenFlowClient
	Close() error
}

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

	// Networks returns the current zone -> VLAN/subnet summary map
	// (hot-refreshable).
	Networks func() map[zone.Zone]zoneflows.NetworkSummary

	// CTZones allocates conntrack zone IDs shared by all gateway services.
	CTZones *ct.ZoneAllocator

	// OverlayIPAM reads fabric reservations used to admit remote VTEPs.
	OverlayIPAM OverlayIPAMReader

	// OverlayDevices loads device records attached to fabric VTEP reservations.
	OverlayDevices OverlayDeviceGetter

	// OverlayVerdicts reads the latest attestation verdict for overlay admission.
	OverlayVerdicts OverlayVerdictReader

	// OverlayVerdictStream delivers device verdicts as platformd records
	// them, so a failed verdict withdraws the device's VTEPs at once.
	OverlayVerdictStream OverlayVerdictStream

	// OverlayOpenFlow programs the overlay terminal's OpenFlow tables.
	OverlayOpenFlow overlayOpenFlowClient

	// OverlayPlatform is the SDK connection backing overlay admission reads.
	OverlayPlatform interface{ Close() error }

	// OverlayIPsec builds the overlay's VTEP-to-VTEP IPsec. It is required
	// only when gateway.overlay.ipsec is enabled.
	OverlayIPsec OverlayIPsecFactory

	// VPN carries what the management VPN service needs from the assembly.
	// Nil refuses the service with ErrRuntimeMissing.
	VPN *VPNRuntime

	// Logger receives service lifecycle logs.
	Logger *slog.Logger

	// pipelineGuard tracks the base pipeline this runtime holds (#567).
	pipelineGuard
}

// Close releases the runtime's OVS connection. Safe to call on a nil
// receiver or a runtime without an OVS client; the injecting daemon owns
// the call once the gateway no longer needs the datapath.
func (r *GatewayRuntime) Close() error {
	if r == nil {
		return nil
	}
	var errs []error
	if r.OVS != nil {
		errs = append(errs, r.OVS.Close())
	}
	if r.OverlayOpenFlow != nil {
		errs = append(errs, r.OverlayOpenFlow.Close())
	}
	if r.OverlayPlatform != nil {
		errs = append(errs, r.OverlayPlatform.Close())
	}
	return errors.Join(errs...)
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

// HostRuntime carries the daemon-injected dependencies of the services that
// program the host rather than the OVS datapath: the nftables host filter,
// the netlink tunnel manager and the BGP speaker (#568). It is separate from
// GatewayRuntime because those services need no OVS connection — a gateway
// running only hostfw and tunnels must not have to dial OVSDB. Every field
// is optional: a nil applier or manager means the real netlink one, a nil
// inventory means only the operator-declared listeners are admitted, and a
// nil logger means slog.Default.
type HostRuntime struct {
	// Listeners reports the daemon's own listeners for the host filter.
	Listeners hostfw.ListenerInventory
	// HostFWApplier programs the nftables table; nil opens netlink.
	HostFWApplier hostfw.Applier
	// TunnelManager drives tunnel interfaces; nil uses the netlink manager.
	TunnelManager TunnelManager
	// UplinkManager programs the routing-uplinks: section for an injected
	// TunnelManager, and is required with one when the section is set. The
	// netlink manager built when TunnelManager is nil brings its own
	// tunnel.UplinkManager and ignores this field.
	UplinkManager UplinkManager
	// NAT64Driver programs the kernel translator; nil drives the real jool
	// tool, which needs the module the packaging installs (#601).
	NAT64Driver nat64.Driver
	// BGPServer, when set, is the GoBGP server the transit speaker wraps
	// instead of running its own (tests, or a daemon-managed instance).
	BGPServer bgp.BGPServerInterface
	// SecretResolver resolves every secret reference the configuration
	// carries — the bgp: section's neighbor passwords and keychain master
	// keys, and the tunnels: section's ipsec/wireguard keys (the tunnel
	// manager built here adapts it as its KeyProvider). The daemon supplies
	// pkg/sdn/gateway/secrets.Store.Resolve (kms:// and secret:// through
	// the SDK secret store). Nil means a service that references a secret
	// cannot start.
	SecretResolver bgp.SecretResolver
	// Logger receives service lifecycle logs.
	Logger *slog.Logger
}

// hostRuntime returns the injected HostRuntime or a zero one whose fields
// resolve to the real implementations, always with a usable logger.
func (c *GatewayConfig) hostRuntime() HostRuntime {
	var host HostRuntime
	if c.Host != nil {
		host = *c.Host
	}
	if host.Logger == nil {
		if c.Runtime != nil && c.Runtime.Logger != nil {
			host.Logger = c.Runtime.Logger
		} else {
			host.Logger = slog.Default()
		}
	}
	return host
}
