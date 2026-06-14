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

// expectedBuiltins lists the names and key invariants that every built-in zone
// must satisfy, sourced from the zone taxonomy in
// docs/architecture/reference-network.md.
var expectedBuiltins = []struct {
	name             zone.Zone
	internetIngress  bool
	oob              bool
	isolate          bool
	isolatePerTenant bool
	lifecycleRole    zone.LifecycleRole
}{
	{zone.ZoneTrusted, false, false, false, false, ""},
	{zone.ZonePublic, true, false, true, false, ""},
	{zone.ZoneProvisioning, false, false, true, false, zone.LifecycleRoleProvisioning},
	{zone.ZoneQuarantine, false, false, true, false, zone.LifecycleRoleQuarantine},
	{zone.ZoneStorage, false, false, true, false, ""},
	{zone.ZoneTenant, false, false, true, true, ""},
	{zone.ZoneManagement, false, true, false, false, ""},
}

// TestDefaults_Count verifies that exactly seven built-in zones are returned.
func TestDefaults_Count(t *testing.T) {
	t.Parallel()

	d := zone.Defaults()
	if len(d) != 7 {
		t.Errorf("Defaults() returned %d zones, want 7", len(d))
	}
}

// TestDefaults_Invariants checks key policy fields for each built-in zone.
func TestDefaults_Invariants(t *testing.T) {
	t.Parallel()

	byName := make(map[zone.Zone]zone.ZoneConfig, 7)
	for _, z := range zone.Defaults() {
		byName[z.Name] = z
	}

	for _, tc := range expectedBuiltins {
		tc := tc
		t.Run(string(tc.name), func(t *testing.T) {
			t.Parallel()
			z, ok := byName[tc.name]
			if !ok {
				t.Fatalf("built-in zone %q not found in Defaults()", tc.name)
			}
			if z.InternetIngress != tc.internetIngress {
				t.Errorf("InternetIngress = %v, want %v", z.InternetIngress, tc.internetIngress)
			}
			if z.OOB != tc.oob {
				t.Errorf("OOB = %v, want %v", z.OOB, tc.oob)
			}
			if z.Isolate != tc.isolate {
				t.Errorf("Isolate = %v, want %v", z.Isolate, tc.isolate)
			}
			if z.IsolatePerTenant != tc.isolatePerTenant {
				t.Errorf("IsolatePerTenant = %v, want %v", z.IsolatePerTenant, tc.isolatePerTenant)
			}
			if z.LifecycleRole != tc.lifecycleRole {
				t.Errorf("LifecycleRole = %q, want %q", z.LifecycleRole, tc.lifecycleRole)
			}
		})
	}
}

// TestDefaults_DeepCopy verifies that mutating the returned slice does not
// alter a second call to Defaults().
func TestDefaults_DeepCopy(t *testing.T) {
	t.Parallel()

	first := zone.Defaults()
	// Mutate first.
	for i := range first {
		first[i].InternetIngress = true
		first[i].Services = append(first[i].Services, "injected")
		if len(first[i].AllowTo) > 0 {
			first[i].AllowTo[0].Services = append(first[i].AllowTo[0].Services, "injected")
		}
		if len(first[i].IsolateFrom) > 0 {
			first[i].IsolateFrom[0] = "injected"
		}
	}

	second := zone.Defaults()
	for _, z := range second {
		if z.InternetIngress && z.Name != zone.ZonePublic {
			t.Errorf("zone %q has InternetIngress=true after mutation of previous Defaults() result", z.Name)
		}
		for _, s := range z.Services {
			if s == "injected" {
				t.Errorf("zone %q has injected service after mutation of previous Defaults() result", z.Name)
			}
		}
	}
}

// TestDefaults_PublicIsolatesFromTrusted verifies that the public zone
// carries IsolateFrom: [trusted] as required by the inter-zone matrix.
func TestDefaults_PublicIsolatesFromTrusted(t *testing.T) {
	t.Parallel()

	byName := make(map[zone.Zone]zone.ZoneConfig, 7)
	for _, z := range zone.Defaults() {
		byName[z.Name] = z
	}
	pub := byName[zone.ZonePublic]
	found := false
	for _, iso := range pub.IsolateFrom {
		if iso == zone.ZoneTrusted {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("public zone must list trusted in IsolateFrom; IsolateFrom = %v", pub.IsolateFrom)
	}
}
