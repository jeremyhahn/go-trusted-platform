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

// Package zone defines the declarative zone schema, built-in defaults,
// merge/resolve semantics, validation, and the inter-zone allow/deny matrix
// for the trusted-platform network model.
//
// Zones are data, not code. All enforcement — SDN flow rules, firewall
// policy, compute placement, DNS naming, and identity — is derived from
// zone declarations; nothing is hard-coded to a VLAN number or IP prefix.
//
// Usage outline:
//
//	resolved, err := zone.Resolve(userZones)
//	if err != nil { … }
//	if err := zone.Validate(resolved); err != nil { … }
//	matrix := zone.CompileMatrix(resolved)
//	verdict := matrix.Allowed(zone.ZoneTrusted, zone.ZonePublic)
package zone

// Zone is a named trust/exposure classification.  Values are lowercase
// DNS-label strings (e.g. "trusted", "public").
type Zone string

// LifecycleRole marks a zone as fulfilling a required device-lifecycle
// function.  The empty string means the zone has no special lifecycle role.
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

// Built-in zone name constants.  These match the zone taxonomy defined in
// docs/architecture/reference-network.md.
const (
	ZoneTrusted      Zone = "trusted"
	ZonePublic       Zone = "public"
	ZoneProvisioning Zone = "provisioning"
	ZoneQuarantine   Zone = "quarantine"
	ZoneStorage      Zone = "storage"
	ZoneTenant       Zone = "tenant"
	ZoneManagement   Zone = "management"
)

// ZonePath declares an allowed directed traffic path from a source zone to
// the named destination zone, optionally scoped to specific services.
// An empty Services slice means all services are allowed on that path.
type ZonePath struct {
	// Zone is the destination zone name.
	Zone Zone `yaml:"zone"`

	// Services is the optional list of service names allowed on this path.
	// When empty, all services are permitted toward the destination.
	Services []string `yaml:"services,omitempty"`
}

// ZoneConfig is the declarative schema for a single network zone.  Built-in
// zones are pre-declared in defaults.go; operators may override any built-in
// or add entirely new zones.
type ZoneConfig struct {
	// Name is the unique zone identifier; must be a non-empty lowercase
	// DNS-label string.
	Name Zone `yaml:"name"`

	// InternetIngress indicates that this zone accepts inbound traffic from
	// the internet.  Must not be set together with OOB.
	InternetIngress bool `yaml:"internet_ingress,omitempty"`

	// IsolateFrom lists zones from which this zone unconditionally denies
	// traffic, even if the peer declares an AllowTo path toward this zone.
	IsolateFrom []Zone `yaml:"isolate_from,omitempty"`

	// AllowTo declares directed paths from this zone to other zones with an
	// optional per-path service allowlist.
	AllowTo []ZonePath `yaml:"allow_to,omitempty"`

	// Services is the list of services permitted within this zone (intra-zone)
	// and implicitly available to zones that declare an AllowTo path here.
	Services []string `yaml:"services,omitempty"`

	// Isolate, when true, denies all inter-zone traffic from this zone except
	// for paths explicitly declared in AllowTo.
	Isolate bool `yaml:"isolate,omitempty"`

	// IsolatePerTenant, when true, enforces per-tenant micro-zone isolation:
	// traffic between different tenants in this zone is denied.
	IsolatePerTenant bool `yaml:"isolate_per_tenant,omitempty"`

	// OOB marks this zone as out-of-band hardware management (e.g. IPMI/BMC).
	// An OOB zone never routes to any data zone and must not have
	// InternetIngress set.
	OOB bool `yaml:"oob,omitempty"`

	// LifecycleRole indicates the device-lifecycle function this zone
	// fulfills.  Valid values are "" (none), "provisioning", and "quarantine".
	LifecycleRole LifecycleRole `yaml:"lifecycle_role,omitempty"`

	// Omit, when true on a user-supplied entry whose name matches a built-in,
	// drops the built-in from the resolved set.  Omitting a built-in that
	// holds a lifecycle role fails validation unless another zone takes that
	// role.  Omit is ignored for zones whose name does not match any built-in.
	Omit bool `yaml:"omit,omitempty"`
}
