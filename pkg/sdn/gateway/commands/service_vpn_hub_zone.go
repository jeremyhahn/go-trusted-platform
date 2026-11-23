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

package commands

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// vpnHubZone is the zone traffic entering from the WireGuard hub interface
// is classified into (#2093, docs/vpn/architecture.md trust boundary 4).
// Its AllowTo in the SDN zone declarations is what the compiled matrix
// opens for management-VPN clients.
const vpnHubZone zone.Zone = "management-vpn"

// classifyVPNHubIngress classifies traffic by its ingress interface: only
// the hub interface is management-VPN ingress.
func classifyVPNHubIngress(ingress string) (zone.Zone, bool) {
	if ingress == vpnHubInterface {
		return vpnHubZone, true
	}
	return "", false
}

// vpnHubZoneEnforcement is the hub's destination-zone check over the
// compiled zone matrix, the same matrix that programs the OVS flows and the
// trusted proxy. A nil enforcement admits nothing.
type vpnHubZoneEnforcement struct {
	matrix zone.Matrix
	// nets are the zones' networks, from the same zoneProviders that feed
	// the OVS zone flows; the forward chain's accepts name their subnets.
	nets map[zone.Zone]zoneflows.NetworkSummary
	// forward is the programmed vpn-hub0 forward chain.
	forward *vpnHubForwardFilter
}

func newVPNHubZoneEnforcement(m zone.Matrix) *vpnHubZoneEnforcement {
	return &vpnHubZoneEnforcement{matrix: m}
}

// Allow reports whether traffic entering on ingress from the peer holding
// lease may reach service in zone dst: the ingress must classify as
// management-VPN, dst must be one of the lease's zones (its AllowTo), and
// the matrix must open management-VPN to dst for that service. Everything
// else is dropped.
func (e *vpnHubZoneEnforcement) Allow(ingress string, lease *vpn.Lease, dst zone.Zone, service string) bool {
	if e == nil || lease == nil {
		return false
	}
	from, ok := classifyVPNHubIngress(ingress)
	if !ok || !slices.Contains(lease.Zones, string(dst)) {
		return false
	}
	v := e.matrix.Allowed(from, dst)
	if !v.Allowed {
		return false
	}
	return len(v.Services) == 0 || slices.Contains(v.Services, service)
}

// admitLease refuses a lease naming a zone the matrix does not open from
// the management-VPN zone, so no peer is installed with an AllowTo the
// enforcement would not honour.
func (e *vpnHubZoneEnforcement) admitLease(lease *vpn.Lease) error {
	if lease == nil {
		return nil
	}
	for _, z := range lease.Zones {
		if e == nil || !e.matrix.Allowed(vpnHubZone, zone.Zone(z)).Allowed {
			return &vpn.ErrZoneNotAllowed{Zone: z}
		}
	}
	return nil
}

// compileVPNHubZoneEnforcement compiles the enforcement from the resolved
// zone declarations. It fails when there are none or when the
// management-VPN zone is not declared: there is then nothing to enforce,
// and the hub stays refused.
func compileVPNHubZoneEnforcement(zones []zone.ZoneConfig) (*vpnHubZoneEnforcement, error) {
	if len(zones) == 0 {
		return nil, errors.New("no SDN zone declarations to compile")
	}
	if !slices.ContainsFunc(zones, func(z zone.ZoneConfig) bool { return z.Name == vpnHubZone }) {
		return nil, errors.New("the SDN zones do not declare the " + string(vpnHubZone) + " zone")
	}
	return newVPNHubZoneEnforcement(zone.CompileMatrix(zones)), nil
}

// installVPNHubForwardFilter installs the filter on the kernel forwarding
// path of vpn-hub0: it opens netlink, programs the inet tp_vpn_hub forward
// chain for the empty lease set (the closing drop alone) and
// sets e.forward, so each peer's accepts follow its install. It fails closed
// on either error. A variable so tests can stand one in.
var installVPNHubForwardFilter = func(e *vpnHubZoneEnforcement, _ *slog.Logger) error {
	if e == nil {
		return errors.New("no destination-zone enforcement for the " + vpnHubInterface + " forward chain")
	}
	conn, err := newVPNHubNFTConn()
	if err != nil {
		return fmt.Errorf("open netlink for the %s forward chain: %w", vpnHubInterface, err)
	}
	f := newVPNHubForwardFilter(e, conn)
	if err := f.keep(context.Background(), nil); err != nil {
		return err
	}
	e.forward = f
	return nil
}

// installVPNHubZones compiles the enforcement from zones, keeps the zones'
// networks nets, and installs it on the forwarding path; it returns the
// enforcement only when both succeed.
func installVPNHubZones(zones []zone.ZoneConfig, nets map[zone.Zone]zoneflows.NetworkSummary, logger *slog.Logger) (*vpnHubZoneEnforcement, error) {
	e, err := compileVPNHubZoneEnforcement(zones)
	if err != nil {
		return nil, err
	}
	e.nets = nets
	if err := installVPNHubForwardFilter(e, logger); err != nil {
		return nil, err
	}
	logger.Info("The WireGuard hub's destination zones are enforced through the compiled zone matrix",
		slog.String("ingress", vpnHubInterface), slog.String("zone", string(vpnHubZone)),
		slog.String("table", vpnHubTableName))
	return e, nil
}

// installVPNHubZoneEnforcement installs the hub's destination-zone
// enforcement from the configuration's SDN zones and networks (the
// zoneProviders the OVS zone flows use): the compiled matrix and the
// vpn-hub0 forwarding-path filter. vpnDataPlanes builds the hub only when it
// succeeds. A variable so tests can stand one in.
var installVPNHubZoneEnforcement = func(cfg *ServeConfig, logger *slog.Logger) (*vpnHubZoneEnforcement, error) {
	if cfg == nil || cfg.SDN == nil {
		return nil, errors.New("no SDN configuration")
	}
	zonesFn, netsFn, err := zoneProviders(cfg.SDN)
	if err != nil {
		return nil, err
	}
	return installVPNHubZones(zonesFn(), netsFn(), logger)
}
