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

// builtins is the authoritative ordered list of pre-declared zone
// configurations.  Policy fields are transcribed from the zone taxonomy and
// inter-zone matrix in docs/architecture/reference-network.md.
var builtins = []ZoneConfig{
	// trusted — enrolled, attested, compliant; internal east-west traffic.
	// No internet ingress.  May reach public on declared service paths and
	// may reach storage.  Non-isolated so intra-zone is auto-allowed.
	{
		Name:            ZoneTrusted,
		InternetIngress: false,
		AllowTo: []ZonePath{
			{Zone: ZonePublic},  // trusted → public: declared service paths (matrix: allow)
			{Zone: ZoneStorage}, // trusted → storage: storage clients (matrix: allow)
		},
	},

	// public — enrolled, attested; internet-facing.  Accepts internet ingress.
	// IsolateFrom: [trusted] means public cannot send TO trusted (defense-
	// in-depth: a compromised internet host cannot reach internal workloads).
	// Isolate=true so only explicitly declared AllowTo paths are open.
	// Intra-zone (public→public) allowed via the explicit self-entry.
	{
		Name:            ZonePublic,
		InternetIngress: true,
		IsolateFrom:     []Zone{ZoneTrusted},
		Isolate:         true,
		AllowTo: []ZonePath{
			{Zone: ZonePublic}, // intra-zone east-west
		},
	},

	// provisioning — device onboarding (pre-trust).  No internet ingress.
	// Isolate=true; only reaches control-plane services: DHCP/DNS/TFTP/ACME
	// via the management plane.  Carries LifecycleRoleProvisioning.
	{
		Name:          ZoneProvisioning,
		LifecycleRole: LifecycleRoleProvisioning,
		Isolate:       true,
		Services:      []string{"dhcp", "tftp", "dns", "acme"},
		AllowTo: []ZonePath{
			{
				Zone:     ZoneManagement,
				Services: []string{"dhcp", "dns", "acme"},
			},
		},
	},

	// quarantine — untrusted / failed devices; fully isolated.
	// Isolate=true; only reaches auth + remediation on the management plane.
	// Carries LifecycleRoleQuarantine.
	{
		Name:          ZoneQuarantine,
		LifecycleRole: LifecycleRoleQuarantine,
		Isolate:       true,
		Services:      []string{"auth", "remediation"},
		AllowTo: []ZonePath{
			{
				Zone:     ZoneManagement,
				Services: []string{"auth", "remediation"},
			},
		},
	},

	// storage — attested; storage protocols only; isolated; high-bandwidth.
	// Isolate=true.  Intra-zone (storage→storage) is allowed via the
	// explicit self-entry.  Accepts connections from trusted (clients) via
	// the trusted→storage path; also declares storage→trusted so that the
	// matrix symmetric cell (storage→trusted, "allow clients") is present.
	{
		Name:    ZoneStorage,
		Isolate: true,
		AllowTo: []ZonePath{
			{Zone: ZoneStorage}, // intra-zone (storage nodes communicate)
			{Zone: ZoneTrusted}, // storage → trusted clients
		},
	},

	// tenant — attested; per-tenant micro-zone isolation.
	// Isolate=true so tenants cannot reach other zones by default.
	// IsolatePerTenant enforces per-tenant micro-zone within this zone.
	// Declares access to storage for per-tenant data.
	{
		Name:             ZoneTenant,
		IsolatePerTenant: true,
		Isolate:          true,
		AllowTo: []ZonePath{
			{Zone: ZoneStorage}, // per-tenant storage access
		},
	},

	// management — shared out-of-band; IPMI/BMC/console.
	// OOB=true: separate NIC, never routes to any data zone.
	// No Isolate, so intra-zone management traffic (BMC-to-BMC) is allowed.
	// No AllowTo to any data zone.
	{
		Name: ZoneManagement,
		OOB:  true,
	},
}

// Defaults returns deep copies of all seven built-in ZoneConfig values.
// Callers may mutate the returned slice without affecting the package-level
// defaults.
func Defaults() []ZoneConfig {
	out := make([]ZoneConfig, len(builtins))
	for i, b := range builtins {
		out[i] = copyZoneConfig(b)
	}
	return out
}

// copyZoneConfig returns a deep copy of z so mutations do not propagate to
// the original.
func copyZoneConfig(z ZoneConfig) ZoneConfig {
	c := z

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

	return c
}
