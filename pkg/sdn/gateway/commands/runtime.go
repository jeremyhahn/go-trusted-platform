// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package commands

import (
	"context"
	"log/slog"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ct"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// ovsConnectTimeout bounds the OVSDB dial and bridge lookup during
// assembly so a wedged ovsdb-server cannot hang daemon startup before
// signal handling is installed.
const ovsConnectTimeout = 30 * time.Second

// datapathService returns the first enabled datapath service (firewall,
// NAT, load balancer) this gateway hosts, or "" when there is none. These are
// the services that require the OVS runtime; when none is hosted the runtime
// is not assembled and the sdn: section's OVS endpoint is never dialed — a
// supervised parser child never opens OVSDB.
func datapathService(gwCfg *gateway.GatewayConfig) string {
	enabled := func(on bool, service string) bool { return on && gwCfg.Hosts(service) }
	switch {
	case enabled(gwCfg.Firewall != nil && gwCfg.Firewall.Enabled, gateway.ServiceFirewall):
		return gateway.ServiceFirewall
	case enabled(gwCfg.NAT != nil && gwCfg.NAT.Enabled, gateway.ServiceNAT):
		return gateway.ServiceNAT
	case enabled(gwCfg.LoadBalancer != nil && gwCfg.LoadBalancer.Enabled, gateway.ServiceLoadBalancer):
		return gateway.ServiceLoadBalancer
	default:
		return ""
	}
}

// zoneMatrixService returns the enabled service that compiles the
// per-zone flow matrix (firewall or NAT), or "" when neither is enabled.
// These services silently enforce nothing when the per-zone network
// summaries are empty, so assembly fails closed for them instead.
func zoneMatrixService(gwCfg *gateway.GatewayConfig) string {
	switch {
	case gwCfg.Firewall != nil && gwCfg.Firewall.Enabled:
		return gateway.ServiceFirewall
	case gwCfg.NAT != nil && gwCfg.NAT.Enabled:
		return gateway.ServiceNAT
	default:
		return ""
	}
}

// buildGatewayRuntime constructs the OVS runtime dependency set the
// datapath services require, from the gatewayd `sdn:` configuration
// section. Returns (nil, nil) when the section is absent or disabled.
// matrixService names the enabled firewall/NAT service, or "" — when set,
// an empty per-zone network summary map fails assembly with
// ErrNoZoneNetworks rather than letting the zone matrix compile to
// nothing and pass traffic silently.
//
// gatewayd programs flows on a bridge provisioned by the node's installer
// or by platformd on a gateway-role node — it does not create the bridge.
// A missing bridge fails assembly closed with ErrBridgeNotProvisioned.
//
// The returned runtime owns a live OVSDB connection; the caller is
// responsible for runtime.Close() once the gateway no longer needs it.
func buildGatewayRuntime(ctx context.Context, sdnCfg *sdn.Config, matrixService string, logger *slog.Logger) (*gateway.GatewayRuntime, error) {
	if sdnCfg == nil || !sdnCfg.Enabled {
		return nil, nil
	}
	if err := sdnCfg.Validate(); err != nil {
		return nil, &ErrConfigSection{Section: "sdn", Cause: err}
	}
	if sdnCfg.OVS == nil {
		return nil, ErrSDNOVSRequired
	}

	zonesFn, networksFn, err := zoneProviders(sdnCfg)
	if err != nil {
		return nil, err
	}
	if matrixService != "" && len(networksFn()) == 0 {
		return nil, &ErrNoZoneNetworks{Service: matrixService}
	}

	client, err := ovs.NewClient(sdnCfg.OVS.Socket)
	if err != nil {
		return nil, &ErrOVSClientInit{Socket: sdnCfg.OVS.Socket, Cause: err}
	}
	connectCtx, cancel := context.WithTimeout(ctx, ovsConnectTimeout)
	defer cancel()
	if err := client.Connect(connectCtx); err != nil {
		return nil, &ErrOVSConnectFailed{Socket: sdnCfg.OVS.Socket, Cause: err}
	}
	if _, err := client.GetBridge(connectCtx, sdnCfg.OVS.Bridge); err != nil {
		closeOVSClient(client, logger)
		return nil, &ErrBridgeNotProvisioned{Bridge: sdnCfg.OVS.Bridge, Cause: err}
	}

	controller, err := policy.NewOVSFlowController(client)
	if err != nil {
		closeOVSClient(client, logger)
		return nil, &ErrOVSClientInit{Socket: sdnCfg.OVS.Socket, Cause: err}
	}

	return &gateway.GatewayRuntime{
		Controller: controller,
		OVS:        client,
		Groups:     client,
		Bridge:     sdnCfg.OVS.Bridge,
		Zones:      zonesFn,
		Networks:   networksFn,
		CTZones:    ct.NewZoneAllocator(nil),
		Logger:     logger,
	}, nil
}

// closeOVSClient closes the OVS client, logging rather than masking a
// close failure on an assembly error path.
func closeOVSClient(client *ovs.Client, logger *slog.Logger) {
	if err := client.Close(); err != nil {
		logger.Warn("gatewayd: closing OVS client failed", slog.Any("error", err))
	}
}

// zoneProviders derives the zone and network-summary closures from the
// validated SDN configuration: the resolved zone set and one network summary
// per zone of the network plan. Validate guarantees both are present.
func zoneProviders(sdnCfg *sdn.Config) (func() []zone.ZoneConfig, func() map[zone.Zone]zoneflows.NetworkSummary, error) {
	resolved := sdnCfg.ResolvedZones()
	plan := sdnCfg.Plan()
	if len(resolved) == 0 || plan == nil {
		return nil, nil, &ErrConfigSection{Section: "sdn", Cause: sdn.ErrEnvironmentRequired{}}
	}
	nets := sdn.NetworkSummaries(plan)

	zonesFn := func() []zone.ZoneConfig { return resolved }
	networksFn := func() map[zone.Zone]zoneflows.NetworkSummary { return nets }
	return zonesFn, networksFn, nil
}
