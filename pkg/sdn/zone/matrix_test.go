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

package zone_test

import (
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// docMatrix encodes the full 7×7 inter-zone connectivity matrix from
// docs/architecture/reference-network.md, table "Inter-zone policy matrix".
//
// Row headers are "from" zones; column headers are "to" zones.
// "allow" means Verdict.Allowed==true; "deny" means Verdict.Allowed==false.
// Service-scoped allows note the expected allowlist in wantServices.
//
// Disambiguation notes (cells not explicit in the doc table):
//
//   - storage→storage: the doc table cell shows "allow"; defaults carry an
//     explicit self-entry in AllowTo because Isolate=true suppresses the
//     auto-intra-zone rule.
//
//   - management→management: the doc does not have a management "from" row in
//     the matrix.  Management has OOB=true and no Isolate, so intra-zone
//     traffic (BMC-to-BMC) is auto-allowed by the non-isolated intra-zone
//     rule.  Management→(data zone) remains denied: management has no AllowTo
//     toward any data zone.
//
//   - Internet→public ingress: captured by ZoneConfig.InternetIngress and
//     enforced at the flow-rule generation layer; it is not a matrix cell and
//     is excluded from this fixture.
//
// IsolateFrom semantics: a zone Z with IsolateFrom=[T] cannot send TO T
// (outbound deny).  Example: public.IsolateFrom=[trusted] → public→trusted
// is denied; trusted→public is still allowed per the doc.
var docMatrix = []struct {
	from         zone.Zone
	to           zone.Zone
	wantAllowed  bool
	wantServices []string // nil = any services; non-nil = exact allowlist check
}{
	// ── trusted row ──────────────────────────────────────────────────────────
	// trusted → trusted: allow east-west (per device profile; non-isolated).
	{zone.ZoneTrusted, zone.ZoneTrusted, true, nil},
	// trusted → public: allowed on declared service paths (matrix: "declared
	// service paths only").  The service scope is enforced at the flow-rule
	// layer; the matrix entry carries no service restriction at this level.
	{zone.ZoneTrusted, zone.ZonePublic, true, nil},
	// trusted → storage: allow (storage clients).
	{zone.ZoneTrusted, zone.ZoneStorage, true, nil},
	// trusted → provisioning: deny.
	{zone.ZoneTrusted, zone.ZoneProvisioning, false, nil},
	// trusted → quarantine: deny.
	{zone.ZoneTrusted, zone.ZoneQuarantine, false, nil},
	// trusted → tenant: deny.
	{zone.ZoneTrusted, zone.ZoneTenant, false, nil},
	// trusted → management: deny (management is OOB; no data zone AllowTo it).
	{zone.ZoneTrusted, zone.ZoneManagement, false, nil},

	// ── public row ───────────────────────────────────────────────────────────
	// public → trusted: DENY.  public.IsolateFrom=[trusted] means public
	// cannot send TO trusted (defense-in-depth: compromised internet host
	// cannot reach internal workloads).
	{zone.ZonePublic, zone.ZoneTrusted, false, nil},
	// public → public: allow intra-zone (explicit self-AllowTo in defaults).
	{zone.ZonePublic, zone.ZonePublic, true, nil},
	// public → storage: deny.
	{zone.ZonePublic, zone.ZoneStorage, false, nil},
	// public → provisioning: deny.
	{zone.ZonePublic, zone.ZoneProvisioning, false, nil},
	// public → quarantine: deny.
	{zone.ZonePublic, zone.ZoneQuarantine, false, nil},
	// public → tenant: deny.
	{zone.ZonePublic, zone.ZoneTenant, false, nil},
	// public → management: deny.
	{zone.ZonePublic, zone.ZoneManagement, false, nil},

	// ── storage row ──────────────────────────────────────────────────────────
	// storage → trusted: allow (storage nodes respond to trusted clients;
	// matrix cell: "allow (clients)").
	{zone.ZoneStorage, zone.ZoneTrusted, true, nil},
	// storage → public: deny.
	{zone.ZoneStorage, zone.ZonePublic, false, nil},
	// storage → storage: allow intra-zone.  Isolate=true suppresses the
	// auto-rule; an explicit self-AllowTo in defaults opens intra-zone
	// traffic (storage nodes communicate with each other).
	{zone.ZoneStorage, zone.ZoneStorage, true, nil},
	// storage → provisioning: deny.
	{zone.ZoneStorage, zone.ZoneProvisioning, false, nil},
	// storage → quarantine: deny.
	{zone.ZoneStorage, zone.ZoneQuarantine, false, nil},
	// storage → tenant: deny.
	{zone.ZoneStorage, zone.ZoneTenant, false, nil},
	// storage → management: deny.
	{zone.ZoneStorage, zone.ZoneManagement, false, nil},

	// ── provisioning row ─────────────────────────────────────────────────────
	// provisioning → trusted: deny.
	{zone.ZoneProvisioning, zone.ZoneTrusted, false, nil},
	// provisioning → public: deny.
	{zone.ZoneProvisioning, zone.ZonePublic, false, nil},
	// provisioning → storage: deny.
	{zone.ZoneProvisioning, zone.ZoneStorage, false, nil},
	// provisioning → provisioning: deny (isolate=true; no self-AllowTo).
	{zone.ZoneProvisioning, zone.ZoneProvisioning, false, nil},
	// provisioning → quarantine: deny.
	{zone.ZoneProvisioning, zone.ZoneQuarantine, false, nil},
	// provisioning → tenant: deny.
	{zone.ZoneProvisioning, zone.ZoneTenant, false, nil},
	// provisioning → management: allow; CP services only (DHCP/DNS/ACME).
	// Matrix cell: "CP services only (DHCP/DNS/ACME)".
	{zone.ZoneProvisioning, zone.ZoneManagement, true, []string{"dhcp", "dns", "acme"}},

	// ── quarantine row ───────────────────────────────────────────────────────
	// quarantine → trusted: deny.
	{zone.ZoneQuarantine, zone.ZoneTrusted, false, nil},
	// quarantine → public: deny.
	{zone.ZoneQuarantine, zone.ZonePublic, false, nil},
	// quarantine → storage: deny.
	{zone.ZoneQuarantine, zone.ZoneStorage, false, nil},
	// quarantine → provisioning: deny.
	{zone.ZoneQuarantine, zone.ZoneProvisioning, false, nil},
	// quarantine → quarantine: deny (isolate=true; no self-AllowTo).
	{zone.ZoneQuarantine, zone.ZoneQuarantine, false, nil},
	// quarantine → tenant: deny.
	{zone.ZoneQuarantine, zone.ZoneTenant, false, nil},
	// quarantine → management: allow; auth + remediation only.
	// Matrix cell: "auth + remediation only".
	{zone.ZoneQuarantine, zone.ZoneManagement, true, []string{"auth", "remediation"}},

	// ── tenant row ───────────────────────────────────────────────────────────
	// tenant → trusted: deny.
	{zone.ZoneTenant, zone.ZoneTrusted, false, nil},
	// tenant → public: deny.
	{zone.ZoneTenant, zone.ZonePublic, false, nil},
	// tenant → storage: allow; per-tenant storage access.
	// Matrix cell: "per-tenant".
	{zone.ZoneTenant, zone.ZoneStorage, true, nil},
	// tenant → provisioning: deny.
	{zone.ZoneTenant, zone.ZoneProvisioning, false, nil},
	// tenant → quarantine: deny.
	{zone.ZoneTenant, zone.ZoneQuarantine, false, nil},
	// tenant → tenant: deny (isolate=true; IsolatePerTenant; no self-AllowTo).
	// Matrix cell: "isolated per tenant" — cross-tenant traffic denied.
	{zone.ZoneTenant, zone.ZoneTenant, false, nil},
	// tenant → management: deny.
	{zone.ZoneTenant, zone.ZoneManagement, false, nil},

	// ── management row ───────────────────────────────────────────────────────
	// management is OOB and "never routes to any data zone."  No AllowTo
	// toward any data zone is declared.  management has no Isolate flag, so
	// the auto-intra-zone rule fires for management→management.
	{zone.ZoneManagement, zone.ZoneTrusted, false, nil},
	{zone.ZoneManagement, zone.ZonePublic, false, nil},
	{zone.ZoneManagement, zone.ZoneStorage, false, nil},
	{zone.ZoneManagement, zone.ZoneProvisioning, false, nil},
	{zone.ZoneManagement, zone.ZoneQuarantine, false, nil},
	{zone.ZoneManagement, zone.ZoneTenant, false, nil},
	// management → management: allow (OOB intra-zone; BMC-to-BMC traffic).
	{zone.ZoneManagement, zone.ZoneManagement, true, nil},
}

// TestCompileMatrix_Defaults verifies that CompileMatrix(Defaults()) produces
// exactly the matrix described in docs/architecture/reference-network.md.
func TestCompileMatrix_Defaults(t *testing.T) {
	t.Parallel()

	defaults := zone.Defaults()
	m := zone.CompileMatrix(defaults)

	for _, tc := range docMatrix {
		tc := tc
		t.Run(string(tc.from)+"→"+string(tc.to), func(t *testing.T) {
			t.Parallel()
			v := m.Allowed(tc.from, tc.to)
			if v.Allowed != tc.wantAllowed {
				t.Errorf("Allowed(%q, %q): got %v, want %v",
					tc.from, tc.to, v.Allowed, tc.wantAllowed)
			}
			if tc.wantServices != nil && v.Allowed {
				if len(v.Services) != len(tc.wantServices) {
					t.Errorf("Allowed(%q, %q): services %v, want %v",
						tc.from, tc.to, v.Services, tc.wantServices)
					return
				}
				for i, s := range tc.wantServices {
					if v.Services[i] != s {
						t.Errorf("Allowed(%q, %q): services[%d] = %q, want %q",
							tc.from, tc.to, i, v.Services[i], s)
					}
				}
			}
		})
	}
}

// TestCompileMatrix_UnknownZone verifies that querying absent zone names
// always returns deny.
func TestCompileMatrix_UnknownZone(t *testing.T) {
	t.Parallel()

	m := zone.CompileMatrix(zone.Defaults())
	v := m.Allowed("nonexistent", "trusted")
	if v.Allowed {
		t.Errorf("Allowed(nonexistent, trusted): want deny, got allow")
	}
}

// TestCompileMatrix_UserZone verifies that a user-added zone with AllowTo
// declarations appears in the compiled matrix.
func TestCompileMatrix_UserZone(t *testing.T) {
	t.Parallel()

	custom := []zone.ZoneConfig{
		{
			Name: "dmz",
			AllowTo: []zone.ZonePath{
				{Zone: "dmz"},
				{Zone: zone.ZoneTrusted, Services: []string{"https"}},
			},
		},
	}
	// Resolve so built-ins are present (AllowTo targets must be declared).
	resolved, err := zone.Resolve(custom)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	m := zone.CompileMatrix(resolved)

	// dmz → trusted allowed (service-scoped).
	v := m.Allowed("dmz", zone.ZoneTrusted)
	if !v.Allowed {
		t.Errorf("dmz → trusted: want allow, got deny")
	}
	if len(v.Services) != 1 || v.Services[0] != "https" {
		t.Errorf("dmz → trusted: services %v, want [https]", v.Services)
	}

	// dmz → public not declared → deny.
	v2 := m.Allowed("dmz", zone.ZonePublic)
	if v2.Allowed {
		t.Errorf("dmz → public: want deny, got allow")
	}
}

// TestCompileMatrix_IsolateFromDeniesOutbound verifies that IsolateFrom on a
// zone denies that zone's OUTBOUND traffic to the listed destinations, while
// inbound traffic from those destinations is unaffected.
//
// Concretely: public.IsolateFrom=[trusted] → public→trusted is denied;
// trusted→public is still allowed (as the doc matrix prescribes).
func TestCompileMatrix_IsolateFromDeniesOutbound(t *testing.T) {
	t.Parallel()

	m := zone.CompileMatrix(zone.Defaults())

	// public cannot send TO trusted.
	v1 := m.Allowed(zone.ZonePublic, zone.ZoneTrusted)
	if v1.Allowed {
		t.Errorf("public → trusted: want deny (IsolateFrom outbound), got allow")
	}

	// trusted CAN still send to public.
	v2 := m.Allowed(zone.ZoneTrusted, zone.ZonePublic)
	if !v2.Allowed {
		t.Errorf("trusted → public: want allow, got deny")
	}
}
