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

// Package zone defines the underlay zone vocabulary of the reference network
// (docs/architecture/reference-network.md): the built-in zones at their fixed
// offsets inside an environment block, the schema for owner-defined zones,
// merge/resolve semantics, validation, and the inter-zone allow/deny matrix.
//
// A zone is an underlay VLAN of an environment. Overlay networks (the
// platform-services overlay, tenant overlays and the public overlay) are not
// zones and never appear here. Tenants never create zones.
//
// Zones carry policy and identity (name, offset, port-class membership); they
// carry no numbers. Every VLAN ID, subnet, VNI and pool is derived from a
// zone's offset by package netplan, the only place numbering is derived.
//
// Usage outline:
//
//	resolved, err := zone.Resolve(userZones)
//	if err != nil { … }
//	if err := zone.Validate(resolved); err != nil { … }
//	matrix := zone.CompileMatrix(resolved)
//	verdict := matrix.Allowed(zone.ZoneProvisioning, zone.ZoneControlPlane)
package zone

// Zone is the name of an underlay zone. Values are lowercase DNS-label
// strings (e.g. "fabric", "control-plane").
type Zone string

// Offset is a zone's position inside an environment block of 100 VLANs: the
// tens and units digits of its VLAN ID. Offsets 0–8 belong to the built-in
// zones and never change; owner-defined zones take 9–99.
type Offset uint8

// LifecycleRole marks a zone as fulfilling a required device-lifecycle
// function. The empty string means the zone has no special lifecycle role.
// Exactly one zone must carry each non-empty role value.
type LifecycleRole string

const (
	// LifecycleRoleProvisioning identifies the zone that handles device
	// onboarding (DHCP/PXE/TFTP/DNS/ACME).
	LifecycleRoleProvisioning LifecycleRole = "provisioning"

	// LifecycleRoleQuarantine identifies the zone that isolates untrusted or
	// non-compliant devices for authentication and remediation.
	LifecycleRoleQuarantine LifecycleRole = "quarantine"
)

// PortClass names a class of physical switch port. Each class carries its
// own allowed-VLAN list, derived from the zones that are members of it; no
// port is trunked the whole block.
type PortClass string

const (
	// PortClassGateway is a gateway data trunk. It is the only class that
	// carries transit.
	PortClassGateway PortClass = "gateway"

	// PortClassHypervisor is a hypervisor (compute or control-plane node)
	// trunk. Its native VLAN is the provisioning zone, so a factory NIC
	// PXE-boots into provisioning.
	PortClassHypervisor PortClass = "hypervisor"

	// PortClassBMC is a BMC access port. It is the only access class and the
	// only class besides the management uplink that carries management.
	PortClassBMC PortClass = "bmc"

	// PortClassMgmtUplink is the external management firewall uplink: a
	// trunk carrying management only.
	PortClassMgmtUplink PortClass = "mgmt-uplink"

	// PortClassPeerLink is the vPC/MLAG inter-switch link. It carries every
	// underlay VLAN of the block.
	PortClassPeerLink PortClass = "peer-link"
)

// Built-in zone names. These are the underlay zones at offsets x00–x08 of
// every environment block (docs/architecture/reference-network.md).
const (
	ZoneTransit      Zone = "transit"
	ZoneFabric       Zone = "fabric"
	ZoneManagement   Zone = "management"
	ZoneHypervisor   Zone = "hypervisor"
	ZoneQuarantine   Zone = "quarantine"
	ZoneProvisioning Zone = "provisioning"
	ZoneControlPlane Zone = "control-plane"
	ZoneStorage      Zone = "storage"
	ZoneBackup       Zone = "backup"
)

// Built-in zone offsets.
const (
	OffsetTransit      Offset = 0
	OffsetFabric       Offset = 1
	OffsetManagement   Offset = 2
	OffsetHypervisor   Offset = 3
	OffsetQuarantine   Offset = 4
	OffsetProvisioning Offset = 5
	OffsetControlPlane Offset = 6
	OffsetStorage      Offset = 7
	OffsetBackup       Offset = 8
)

const (
	// MinOwnerOffset is the lowest offset an owner-defined zone may take.
	MinOwnerOffset Offset = 9

	// MaxOffset is the highest offset inside an environment block.
	MaxOffset Offset = 99
)

// ZonePath declares an allowed directed traffic path from a source zone to
// the named destination zone, optionally scoped to specific services.
// An empty Services slice means all services are allowed on that path.
type ZonePath struct {
	// Zone is the destination zone name.
	Zone Zone `yaml:"zone" json:"zone" mapstructure:"zone"`

	// Services is the optional list of service names allowed on this path.
	// When empty, all services are permitted toward the destination.
	Services []string `yaml:"services,omitempty" json:"services,omitempty" mapstructure:"services"`
}

// PrivilegedAccess is the explicit, audited override a zone must carry when
// its allow_to opens a path into control-plane or management that the
// reference does not. The reason is recorded in the zone's configuration and
// logged as an audit event every time the zone set is loaded.
type PrivilegedAccess struct {
	// Reason states why the path is needed. It must not be empty.
	Reason string `yaml:"reason" json:"reason" mapstructure:"reason"`

	// ApprovedBy names who approved the path. It must not be empty.
	ApprovedBy string `yaml:"approved_by" json:"approved_by" mapstructure:"approved_by"`
}

// ZoneConfig is the declarative schema for a single underlay zone. Built-in
// zones are pre-declared in defaults.go: an operator may tune their policy
// fields but not their identity (offset, lifecycle role, port classes, OOB).
// An operator may also add owner-defined zones at offsets 9–99.
type ZoneConfig struct {
	// Name is the unique zone identifier; must be a non-empty lowercase
	// DNS-label string, and not one of the overlay kinds (platform, tenant,
	// public).
	Name Zone `yaml:"name" json:"name" mapstructure:"name"`

	// Offset is the zone's position in the environment block. Built-in zones
	// carry fixed offsets 0–8 and an operator entry may only repeat it.
	// Owner-defined zones must set 9–99.
	Offset Offset `yaml:"offset,omitempty" json:"offset,omitempty" mapstructure:"offset"`

	// PortClasses lists the switch port classes that carry this zone's VLAN.
	// Fixed for built-in zones; owner-defined zones choose from gateway and
	// hypervisor. The peer-link carries every zone without being listed.
	PortClasses []PortClass `yaml:"port_classes,omitempty" json:"port_classes,omitempty" mapstructure:"port_classes"`

	// InternetIngress indicates that this zone accepts inbound traffic from
	// the internet. Must not be set together with OOB.
	InternetIngress bool `yaml:"internet_ingress,omitempty" json:"internet_ingress,omitempty" mapstructure:"internet_ingress"`

	// IsolateFrom lists zones to which this zone unconditionally denies
	// traffic, even when an AllowTo path would open it.
	IsolateFrom []Zone `yaml:"isolate_from,omitempty" json:"isolate_from,omitempty" mapstructure:"isolate_from"`

	// AllowTo declares directed paths from this zone to other zones with an
	// optional per-path service allowlist.
	AllowTo []ZonePath `yaml:"allow_to,omitempty" json:"allow_to,omitempty" mapstructure:"allow_to"`

	// Services is the list of services permitted within this zone (intra-zone)
	// and implicitly available to zones that declare an AllowTo path here.
	Services []string `yaml:"services,omitempty" json:"services,omitempty" mapstructure:"services"`

	// Isolate, when true, denies all traffic from this zone except for paths
	// explicitly declared in AllowTo, including traffic inside the zone.
	Isolate bool `yaml:"isolate,omitempty" json:"isolate,omitempty" mapstructure:"isolate"`

	// OOB marks the out-of-band hardware management zone (BMC/IPMI). Only
	// the built-in management zone carries it. An OOB zone never routes to
	// any data zone and must not have InternetIngress set.
	OOB bool `yaml:"oob,omitempty" json:"oob,omitempty" mapstructure:"oob"`

	// LifecycleRole indicates the device-lifecycle function this zone
	// fulfils. Only the built-in provisioning and quarantine zones carry one.
	LifecycleRole LifecycleRole `yaml:"lifecycle_role,omitempty" json:"lifecycle_role,omitempty" mapstructure:"lifecycle_role"`

	// PrivilegedAccess is the audited override required when AllowTo opens a
	// path into control-plane or management beyond the reference defaults.
	PrivilegedAccess *PrivilegedAccess `yaml:"privileged_access,omitempty" json:"privileged_access,omitempty" mapstructure:"privileged_access"`

	// Omit, when true on an operator entry whose name matches a built-in,
	// drops the built-in from the resolved set. The zones the platform
	// cannot run without (fabric, provisioning, quarantine, control-plane)
	// cannot be omitted. Omit on a name that is not built in is an error.
	Omit bool `yaml:"omit,omitempty" json:"omit,omitempty" mapstructure:"omit"`
}

// PrivilegedPath is one AllowTo path into control-plane or management that
// goes beyond the reference defaults, together with the override that
// permits it. Callers log every PrivilegedPath as an audit event.
type PrivilegedPath struct {
	// From is the source zone.
	From Zone
	// To is the privileged destination zone.
	To Zone
	// Services is the path's service allowlist; empty means all services.
	Services []string
	// Access is the override that permits the path.
	Access PrivilegedAccess
}
