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

package installer

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// roleZones is the host-addressing rule of the reference network
// (docs/architecture/reference-network.md, "Host addressing"): the zones a
// host of each role may hold an address on. Every platform host holds a
// fabric address (its VTEP); control-plane nodes are hypervisors too. A role
// absent from this table is exempt (gateways route and NAT by role).
var roleZones = map[HostRole][]zone.Zone{
	HostRoleControlPlane: {zone.ZoneFabric, zone.ZoneHypervisor, zone.ZoneStorage, zone.ZoneControlPlane},
	HostRoleCompute:      {zone.ZoneFabric, zone.ZoneHypervisor, zone.ZoneStorage},
}

// validHostRoles lists every accepted network.role value.
var validHostRoles = map[HostRole]struct{}{
	"":                   {},
	HostRoleGateway:      {},
	HostRoleControlPlane: {},
	HostRoleCompute:      {},
}

// ErrInvalidHostRole is returned for an unknown network.role.
type ErrInvalidHostRole struct {
	// Role is the rejected value.
	Role HostRole
}

// Error implements the error interface.
func (e *ErrInvalidHostRole) Error() string {
	return fmt.Sprintf("installer: network.role %q is not gateway, control-plane or compute", e.Role)
}

// ErrForwardingNotAllowed is returned when a host other than a gateway sets
// network.ip-forward: only gateways route.
type ErrForwardingNotAllowed struct {
	// Role is the host's role.
	Role HostRole
}

// Error implements the error interface.
func (e *ErrForwardingNotAllowed) Error() string {
	return fmt.Sprintf("installer: network.ip-forward is only allowed on a gateway, not on role %q", e.Role)
}

// ErrNetworkPlanRequired is returned when the network config uses the
// reference network (a role, a zone VLAN or a platform VRF) but no network
// plan (sdn.environment) is available to check it against.
type ErrNetworkPlanRequired struct {
	// Field names what needs the plan.
	Field string
}

// Error implements the error interface.
func (e *ErrNetworkPlanRequired) Error() string {
	return fmt.Sprintf("installer: %s needs the network plan (sdn.environment)", e.Field)
}

// ErrAddressNotPermitted is returned when a host address lies outside the
// zones its role may use, or outside every zone.
type ErrAddressNotPermitted struct {
	// Role is the host's role.
	Role HostRole
	// Where names the interface, bridge, bond or VLAN holding the address.
	Where string
	// Address is the offending address.
	Address string
	// Zone is the zone the address lies in; empty when it is in none.
	Zone zone.Zone
}

// Error implements the error interface.
func (e *ErrAddressNotPermitted) Error() string {
	if e.Zone == "" {
		return fmt.Sprintf("installer: %s address %s is in no platform zone; a %s host may only hold addresses on %s",
			e.Where, e.Address, e.Role, zoneList(roleZones[e.Role]))
	}
	return fmt.Sprintf("installer: %s address %s is in zone %q; a %s host may only hold addresses on %s",
		e.Where, e.Address, e.Zone, e.Role, zoneList(roleZones[e.Role]))
}

// ErrDHCPNotPermitted is returned when a control-plane or compute host
// configures an interface by DHCP: its address would land on provisioning.
type ErrDHCPNotPermitted struct {
	// Role is the host's role.
	Role HostRole
	// Where names the DHCP-configured interface, bridge, bond or VLAN.
	Where string
}

// Error implements the error interface.
func (e *ErrDHCPNotPermitted) Error() string {
	return fmt.Sprintf("installer: %s uses DHCP; a %s host must address its zones statically", e.Where, e.Role)
}

// ErrFabricAddressRequired is returned when a control-plane or compute host
// has no address on the fabric zone (its VTEP).
type ErrFabricAddressRequired struct {
	// Role is the host's role.
	Role HostRole
}

// Error implements the error interface.
func (e *ErrFabricAddressRequired) Error() string {
	return fmt.Sprintf("installer: a %s host needs an address on the fabric zone (its VTEP)", e.Role)
}

// ErrBondZoneVLAN is returned for a bond zone VLAN whose zone is not in the
// plan or whose address is not inside the zone's subnet.
type ErrBondZoneVLAN struct {
	// Bond is the bond name.
	Bond string
	// Zone is the zone the entry names.
	Zone string
	// Reason says what is wrong.
	Reason string
}

// Error implements the error interface.
func (e *ErrBondZoneVLAN) Error() string {
	return fmt.Sprintf("installer: bond %s vlan zone %q: %s", e.Bond, e.Zone, e.Reason)
}

// ErrVLANZone is returned for a network.vlans entry whose zone is not in the
// plan, whose address is not in the zone's subnet, or that sets both zone
// and a literal id.
type ErrVLANZone struct {
	// VLAN is the VLAN interface name.
	VLAN string
	// Zone is the zone the entry names.
	Zone string
	// Reason says what is wrong.
	Reason string
}

// Error implements the error interface.
func (e *ErrVLANZone) Error() string {
	return fmt.Sprintf("installer: vlan %s zone %q: %s", e.VLAN, e.Zone, e.Reason)
}

// ErrLiteralVLANWithRole is returned when a host with a network.role
// declares a VLAN interface by literal id: a platform host addresses its
// zones by name so the plan, not the config, numbers them.
type ErrLiteralVLANWithRole struct {
	// VLAN is the VLAN interface name.
	VLAN string
	// Role is the host's role.
	Role HostRole
}

// Error implements the error interface.
func (e *ErrLiteralVLANWithRole) Error() string {
	return fmt.Sprintf("installer: vlan %s uses a literal id on a %s host; name its zone instead", e.VLAN, e.Role)
}

// ErrInvalidPlatformVRF is returned for a malformed network.platform-vrf.
type ErrInvalidPlatformVRF struct {
	// Reason says what is wrong.
	Reason string
}

// Error implements the error interface.
func (e *ErrInvalidPlatformVRF) Error() string {
	return "installer: network.platform-vrf: " + e.Reason
}

// zoneList renders zones as "a, b and c".
func zoneList(zones []zone.Zone) string {
	names := make([]string, len(zones))
	for i, z := range zones {
		names[i] = string(z)
	}
	switch len(names) {
	case 0:
		return "no zone"
	case 1:
		return names[0]
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}

// EffectiveName returns the VRF device name, applying the default.
func (v *PlatformVRFConfig) EffectiveName() string {
	if v.Name == "" {
		return DefaultPlatformVRFName
	}
	return v.Name
}

// EffectiveTable returns the VRF routing table, applying the default.
func (v *PlatformVRFConfig) EffectiveTable() int {
	if v.Table == 0 {
		return DefaultPlatformVRFTable
	}
	return v.Table
}

// hostAddress is one statically configured host address and where it is.
type hostAddress struct {
	where string
	addr  string
}

// parseHostAddress parses "a.b.c.d", "a.b.c.d/nn" or an IPv6 equivalent.
func parseHostAddress(s string) (netip.Addr, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Addr{}, err
		}
		return p.Addr(), nil
	}
	return netip.ParseAddr(s)
}

// validateReferenceNetwork applies the reference-network rules to nc:
// role, forwarding, zone VLANs, the platform VRF and host addressing by
// role.
func (nc *NetworkConfig) validateReferenceNetwork(plan *netplan.Plan) error {
	if _, ok := validHostRoles[nc.Role]; !ok {
		return &ErrInvalidHostRole{Role: nc.Role}
	}
	if nc.IPForward && nc.Role != HostRoleGateway {
		return &ErrForwardingNotAllowed{Role: nc.Role}
	}
	if plan == nil {
		return nc.requirePlanFree()
	}
	if err := nc.validateBondZoneVLANs(plan); err != nil {
		return err
	}
	if err := nc.validateVLANZones(plan); err != nil {
		return err
	}
	if err := nc.validatePlatformVRF(plan); err != nil {
		return err
	}
	return nc.validateHostAddressing(plan)
}

// requirePlanFree refuses the settings that cannot be checked without a
// network plan.
func (nc *NetworkConfig) requirePlanFree() error {
	if nc.Role != "" {
		return &ErrNetworkPlanRequired{Field: "network.role"}
	}
	if nc.PlatformVRF != nil {
		return &ErrNetworkPlanRequired{Field: "network.platform-vrf"}
	}
	for _, b := range nc.Bonds {
		if len(b.VLANs) > 0 {
			return &ErrNetworkPlanRequired{Field: "network.bonds[" + b.Name + "].vlans"}
		}
	}
	for _, v := range nc.VLANs {
		if v.Zone != "" {
			return &ErrNetworkPlanRequired{Field: "network.vlans[" + v.Name + "].zone"}
		}
	}
	return nil
}

// validateVLANZones checks each network.vlans entry: a zone VLAN names a
// plan zone and carries an address inside it; a literal id is refused on a
// host with a role.
func (nc *NetworkConfig) validateVLANZones(plan *netplan.Plan) error {
	for _, v := range nc.VLANs {
		if v.Zone == "" {
			if nc.Role != "" {
				return &ErrLiteralVLANWithRole{VLAN: v.Name, Role: nc.Role}
			}
			continue
		}
		n, ok := plan.Zone(zone.Zone(v.Zone))
		if !ok {
			return &ErrVLANZone{VLAN: v.Name, Zone: v.Zone, Reason: "the zone is not in the network plan"}
		}
		if v.IPv4Address == "" {
			continue
		}
		a, err := parseHostAddress(v.IPv4Address)
		if err != nil {
			return &ErrVLANZone{VLAN: v.Name, Zone: v.Zone, Reason: "address " + v.IPv4Address + " does not parse"}
		}
		if !n.Subnet4.Contains(a) {
			return &ErrVLANZone{VLAN: v.Name, Zone: v.Zone,
				Reason: fmt.Sprintf("address %s is outside the zone subnet %s", v.IPv4Address, n.Subnet4)}
		}
	}
	return nil
}

// validateBondZoneVLANs checks each bond zone VLAN names a plan zone and
// carries an address inside that zone's subnet.
func (nc *NetworkConfig) validateBondZoneVLANs(plan *netplan.Plan) error {
	for _, b := range nc.Bonds {
		for _, v := range b.VLANs {
			n, ok := plan.Zone(zone.Zone(v.Zone))
			if !ok {
				return &ErrBondZoneVLAN{Bond: b.Name, Zone: v.Zone, Reason: "the zone is not in the network plan"}
			}
			if v.IPv4Address == "" {
				continue
			}
			a, err := parseHostAddress(v.IPv4Address)
			if err != nil {
				return &ErrBondZoneVLAN{Bond: b.Name, Zone: v.Zone, Reason: "address " + v.IPv4Address + " does not parse"}
			}
			if !n.Subnet4.Contains(a) {
				return &ErrBondZoneVLAN{Bond: b.Name, Zone: v.Zone,
					Reason: fmt.Sprintf("address %s is outside the zone subnet %s", v.IPv4Address, n.Subnet4)}
			}
		}
	}
	return nil
}

// validatePlatformVRF checks the platform VRF address is a /32 inside the
// environment's platform-hosts range.
func (nc *NetworkConfig) validatePlatformVRF(plan *netplan.Plan) error {
	v := nc.PlatformVRF
	if v == nil {
		return nil
	}
	if v.Table < 0 {
		return &ErrInvalidPlatformVRF{Reason: "table must be positive"}
	}
	p, err := netip.ParsePrefix(v.Address)
	if err != nil || !p.Addr().Is4() || p.Bits() != 32 {
		return &ErrInvalidPlatformVRF{Reason: "address " + v.Address + " must be an IPv4 /32"}
	}
	hosts, _ := plan.Range(netplan.RangePlatformHosts)
	if !hosts.Contains(p.Addr()) {
		return &ErrInvalidPlatformVRF{Reason: fmt.Sprintf("address %s is outside the platform-hosts range %s", v.Address, hosts)}
	}
	return nil
}

// validateHostAddressing applies the role→zones table: every static address
// in a permitted zone, no DHCP, a fabric address present. Gateways and hosts
// with no role are exempt.
func (nc *NetworkConfig) validateHostAddressing(plan *netplan.Plan) error {
	permitted, constrained := roleZones[nc.Role]
	if !constrained {
		return nil
	}
	if where, dhcp := nc.firstDHCP(); dhcp {
		return &ErrDHCPNotPermitted{Role: nc.Role, Where: where}
	}
	hasFabric := false
	for _, ha := range nc.staticAddresses() {
		a, err := parseHostAddress(ha.addr)
		if err != nil {
			return ErrInvalidConfig(fmt.Sprintf("%s: address %q does not parse", ha.where, ha.addr))
		}
		z, ok := plan.ZoneForAddr(a)
		if !ok || !slices.Contains(permitted, z) {
			return &ErrAddressNotPermitted{Role: nc.Role, Where: ha.where, Address: ha.addr, Zone: z}
		}
		if z == zone.ZoneFabric {
			hasFabric = true
		}
	}
	if !hasFabric {
		return &ErrFabricAddressRequired{Role: nc.Role}
	}
	return nil
}

// firstDHCP returns the first DHCP-configured interface, bridge, bond or
// VLAN.
func (nc *NetworkConfig) firstDHCP() (string, bool) {
	for _, i := range nc.Interfaces {
		if i.Type == InterfaceTypeDHCP {
			return "interface " + i.Name, true
		}
	}
	for _, b := range nc.Bridges {
		if b.DHCP {
			return "bridge " + b.Name, true
		}
	}
	for _, b := range nc.Bonds {
		if b.DHCP {
			return "bond " + b.Name, true
		}
	}
	for _, v := range nc.VLANs {
		if v.DHCP {
			return "vlan " + v.Name, true
		}
	}
	return "", false
}

// staticAddresses lists every statically configured host address.
func (nc *NetworkConfig) staticAddresses() []hostAddress {
	var out []hostAddress
	add := func(where, addr string) {
		if addr != "" {
			out = append(out, hostAddress{where: where, addr: addr})
		}
	}
	for _, i := range nc.Interfaces {
		add("interface "+i.Name, i.IPv4Address)
		add("interface "+i.Name, i.IPv6Address)
	}
	for _, b := range nc.Bridges {
		add("bridge "+b.Name, b.IPv4Address)
	}
	for _, b := range nc.Bonds {
		add("bond "+b.Name, b.IPv4Address)
		for _, v := range b.VLANs {
			add("bond "+b.Name+" zone "+v.Zone, v.IPv4Address)
		}
	}
	for _, v := range nc.VLANs {
		add("vlan "+v.Name, v.IPv4Address)
	}
	return out
}
