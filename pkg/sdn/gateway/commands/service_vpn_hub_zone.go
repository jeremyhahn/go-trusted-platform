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
	"errors"
	"log/slog"
	"slices"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
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

// errVPNHubNoForwardFilter is the production forwarding-path filter
// install's refusal: no filter in pkg/sdn/gateway can apply Allow to traffic
// forwarded from vpn-hub0 yet. The host filter renders only an input-hook
// chain, and the compiled zone flows classify by VLAN and destination subnet,
// not by an L3 ingress device or a lease's source address (docs/plans/1698.md
// B3). Until one exists the hub stays refused (Tenant Agent ruling 1028).
var errVPNHubNoForwardFilter = errors.New("no forwarding-path filter for " + vpnHubInterface + " exists yet")

// installVPNHubForwardFilter installs the filter on the kernel forwarding
// path of vpn-hub0 that drops whatever e.Allow refuses. A variable so tests
// can stand one in; the production default fails closed.
var installVPNHubForwardFilter = func(*vpnHubZoneEnforcement, *slog.Logger) error {
	return errVPNHubNoForwardFilter
}

// installVPNHubZones compiles the enforcement from zones and installs it on
// the forwarding path; it returns the enforcement only when both succeed.
func installVPNHubZones(zones []zone.ZoneConfig, logger *slog.Logger) (*vpnHubZoneEnforcement, error) {
	e, err := compileVPNHubZoneEnforcement(zones)
	if err != nil {
		return nil, err
	}
	if err := installVPNHubForwardFilter(e, logger); err != nil {
		return nil, err
	}
	logger.Info("The WireGuard hub's destination zones are enforced through the compiled zone matrix",
		slog.String("ingress", vpnHubInterface), slog.String("zone", string(vpnHubZone)))
	return e, nil
}

// installVPNHubZoneEnforcement installs the hub's destination-zone
// enforcement from the configuration's SDN zones: the compiled matrix and the
// vpn-hub0 forwarding-path filter. vpnDataPlanes builds the hub only when it
// succeeds. A variable so tests can stand one in.
var installVPNHubZoneEnforcement = func(cfg *ServeConfig, logger *slog.Logger) (*vpnHubZoneEnforcement, error) {
	if cfg == nil || cfg.SDN == nil {
		return nil, errors.New("no SDN configuration")
	}
	return installVPNHubZones(cfg.SDN.ResolvedZones(), logger)
}
