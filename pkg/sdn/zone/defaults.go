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

package zone

// builtins is the authoritative list of the built-in underlay zones, in
// offset order. Policy fields transcribe the "Routing and inter-zone policy"
// table of docs/architecture/reference-network.md: the default between zones
// is deny, every zone is isolated, and only the listed paths are open.
var builtins = []ZoneConfig{
	// transit (x00) — the gateway edge: upstream handoff and BGP peering.
	// Only gateway ports carry it. Nothing but gateways attaches, so no
	// path leaves it toward another zone.
	{
		Name:            ZoneTransit,
		Offset:          OffsetTransit,
		PortClasses:     []PortClass{PortClassGateway},
		InternetIngress: true,
		Isolate:         true,
	},

	// fabric (x01) — the VXLAN underlay: VTEPs and EVPN between gateways
	// and hypervisors. A single L2 segment that is never routed.
	{
		Name:        ZoneFabric,
		Offset:      OffsetFabric,
		PortClasses: []PortClass{PortClassGateway, PortClassHypervisor},
		Isolate:     true,
		Services:    []string{"vxlan", "bgp", "ipsec"},
		AllowTo: []ZonePath{
			{Zone: ZoneFabric, Services: []string{"vxlan", "bgp", "ipsec"}},
		},
	},

	// management (x02) — out-of-band BMC/IPMI and consoles. BMC access
	// ports and the management firewall uplink only. The platform never
	// routes it and it never reaches another zone.
	{
		Name:        ZoneManagement,
		Offset:      OffsetManagement,
		PortClasses: []PortClass{PortClassBMC, PortClassMgmtUplink},
		OOB:         true,
		Isolate:     true,
	},

	// hypervisor (x03) — live migration between hypervisors (TLS).
	{
		Name:        ZoneHypervisor,
		Offset:      OffsetHypervisor,
		PortClasses: []PortClass{PortClassHypervisor},
		Isolate:     true,
		Services:    []string{"migration"},
		AllowTo: []ZonePath{
			{Zone: ZoneHypervisor, Services: []string{"migration"}},
		},
	},

	// quarantine (x04) — non-compliant or failed nodes: the control plane's
	// authentication and remediation endpoints only.
	{
		Name:          ZoneQuarantine,
		Offset:        OffsetQuarantine,
		PortClasses:   []PortClass{PortClassGateway, PortClassHypervisor},
		LifecycleRole: LifecycleRoleQuarantine,
		Isolate:       true,
		Services:      []string{"dhcp", "dns", "auth", "remediation"},
		AllowTo: []ZonePath{
			{Zone: ZoneControlPlane, Services: []string{"dns", "auth", "remediation"}},
		},
	},

	// provisioning (x05) — onboarding: the control plane's enrollment
	// services only. It is the hypervisor trunk's native VLAN.
	{
		Name:          ZoneProvisioning,
		Offset:        OffsetProvisioning,
		PortClasses:   []PortClass{PortClassGateway, PortClassHypervisor},
		LifecycleRole: LifecycleRoleProvisioning,
		Isolate:       true,
		Services:      []string{"dhcp", "tftp", "http", "dns", "acme"},
		AllowTo: []ZonePath{
			{Zone: ZoneControlPlane, Services: []string{"tftp", "http", "dns", "acme"}},
		},
	},

	// control-plane (x06) — control-plane nodes: CA, ACME, IAM, KMS, DNS,
	// Raft. Control-plane APIs reach enrolled nodes over the platform
	// overlay, not through another zone.
	{
		Name:        ZoneControlPlane,
		Offset:      OffsetControlPlane,
		PortClasses: []PortClass{PortClassGateway, PortClassHypervisor},
		Isolate:     true,
		AllowTo: []ZonePath{
			{Zone: ZoneControlPlane},
		},
	},

	// storage (x07) — block and object storage between storage clients and
	// targets (TLS). Never routed.
	{
		Name:        ZoneStorage,
		Offset:      OffsetStorage,
		PortClasses: []PortClass{PortClassHypervisor},
		Isolate:     true,
		Services:    []string{"storage"},
		AllowTo: []ZonePath{
			{Zone: ZoneStorage, Services: []string{"storage"}},
		},
	},

	// backup (x08) — backup streams, encrypted at source, to declared backup
	// targets only.
	{
		Name:        ZoneBackup,
		Offset:      OffsetBackup,
		PortClasses: []PortClass{PortClassGateway, PortClassHypervisor},
		Isolate:     true,
		Services:    []string{"backup"},
		AllowTo: []ZonePath{
			{Zone: ZoneBackup, Services: []string{"backup"}},
		},
	},
}

// requiredBuiltins are the built-in zones the platform cannot run without:
// they may be tuned but never omitted.
var requiredBuiltins = map[Zone]struct{}{
	ZoneFabric:       {},
	ZoneQuarantine:   {},
	ZoneProvisioning: {},
	ZoneControlPlane: {},
}

// privilegedZones are the destinations an AllowTo path may only open beyond
// the reference defaults with an explicit PrivilegedAccess override.
var privilegedZones = map[Zone]struct{}{
	ZoneControlPlane: {},
	ZoneManagement:   {},
}

// ownerPortClasses are the port classes an owner-defined zone may join.
var ownerPortClasses = map[PortClass]struct{}{
	PortClassGateway:    {},
	PortClassHypervisor: {},
}

// reservedNames are names no zone may take: the overlay kinds, which are
// never zones, and the retired "trusted" zone.
var reservedNames = map[Zone]struct{}{
	"platform": {},
	"tenant":   {},
	"public":   {},
	"trusted":  {},
}

// Defaults returns deep copies of the built-in ZoneConfig values in offset
// order. Callers may mutate the returned slice without affecting the
// package-level defaults.
func Defaults() []ZoneConfig {
	out := make([]ZoneConfig, len(builtins))
	for i, b := range builtins {
		out[i] = copyZoneConfig(b)
	}
	return out
}

// Builtin returns a deep copy of the built-in zone named z and true, or the
// zero value and false when z is not built in.
func Builtin(z Zone) (ZoneConfig, bool) {
	for _, b := range builtins {
		if b.Name == z {
			return copyZoneConfig(b), true
		}
	}
	return ZoneConfig{}, false
}

// IsBuiltin reports whether z names a built-in zone.
func IsBuiltin(z Zone) bool {
	_, ok := Builtin(z)
	return ok
}

// copyZoneConfig returns a deep copy of z so mutations do not propagate to
// the original.
func copyZoneConfig(z ZoneConfig) ZoneConfig {
	c := z

	if z.PortClasses != nil {
		c.PortClasses = make([]PortClass, len(z.PortClasses))
		copy(c.PortClasses, z.PortClasses)
	}

	if z.IsolateFrom != nil {
		c.IsolateFrom = make([]Zone, len(z.IsolateFrom))
		copy(c.IsolateFrom, z.IsolateFrom)
	}

	if z.AllowTo != nil {
		c.AllowTo = make([]ZonePath, len(z.AllowTo))
		for i, p := range z.AllowTo {
			np := ZonePath{Zone: p.Zone}
			if p.Services != nil {
				np.Services = make([]string, len(p.Services))
				copy(np.Services, p.Services)
			}
			c.AllowTo[i] = np
		}
	}

	if z.Services != nil {
		c.Services = make([]string, len(z.Services))
		copy(c.Services, z.Services)
	}

	if z.PrivilegedAccess != nil {
		pa := *z.PrivilegedAccess
		c.PrivilegedAccess = &pa
	}

	return c
}
