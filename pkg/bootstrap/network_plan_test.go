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

package bootstrap

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// testEnvironment is environment 4 of the reference network on the default
// base, the environment the bootstrap tests are numbered from. Management
// and provisioning carry the documentation reference ranges as overrides.
func testEnvironment() *netplan.Environment {
	return &netplan.Environment{ID: 4, Overrides: []netplan.Override{
		{Zone: zone.ZoneManagement, Subnet: netip.MustParsePrefix("198.51.100.0/24")},
		{Zone: zone.ZoneProvisioning, Subnet: netip.MustParsePrefix("192.0.2.0/24")},
	}}
}

// TestNetworkPlan derives the plan from the environment and an owner zone.
func TestNetworkPlan(t *testing.T) {
	cfg := &BootstrapConfig{
		Environment: testEnvironment(),
		Zones: []zone.ZoneConfig{
			{Name: "lab", Offset: 9, PortClasses: []zone.PortClass{zone.PortClassHypervisor}, Isolate: true},
		},
		Switch: &SwitchConfig{PortAssignments: []PortAssignment{{Port: "Eth1/25", Class: zone.PortClassHypervisor}}},
	}
	plan, err := cfg.NetworkPlan()
	if err != nil {
		t.Fatalf("NetworkPlan: %v", err)
	}
	prov, ok := plan.Zone(zone.ZoneProvisioning)
	if !ok || prov.VLAN != 405 || prov.Subnet4.String() != "192.0.2.0/24" {
		t.Fatalf("unexpected provisioning zone %+v", prov)
	}
	lab, ok := plan.Zone("lab")
	if !ok || lab.VLAN != 409 {
		t.Fatalf("unexpected owner zone %+v", lab)
	}
}

// TestNetworkPlan_Errors covers a missing environment, a bad environment,
// an invalid zone set, and port assignments with no port or a bad class.
func TestNetworkPlan_Errors(t *testing.T) {
	var missing ErrMissingRequiredField
	if _, err := (&BootstrapConfig{}).NetworkPlan(); !errors.As(err, &missing) || missing.Field != "environment" {
		t.Fatalf("want missing environment, got %v", err)
	}

	var envErr netplan.ErrEnvironmentID
	if _, err := (&BootstrapConfig{Environment: &netplan.Environment{ID: 1}}).NetworkPlan(); !errors.As(err, &envErr) {
		t.Fatalf("want ErrEnvironmentID, got %v", err)
	}

	var reserved zone.ErrReservedZoneName
	bad := &BootstrapConfig{Environment: testEnvironment(), Zones: []zone.ZoneConfig{
		{Name: "trusted", Offset: 9, PortClasses: []zone.PortClass{zone.PortClassHypervisor}},
	}}
	if _, err := bad.NetworkPlan(); !errors.As(err, &reserved) {
		t.Fatalf("want ErrReservedZoneName, got %v", err)
	}

	var omit zone.ErrOmitRequired
	omitted := &BootstrapConfig{Environment: testEnvironment(), Zones: []zone.ZoneConfig{{Name: zone.ZoneProvisioning, Omit: true}}}
	if _, err := omitted.NetworkPlan(); !errors.As(err, &omit) {
		t.Fatalf("want ErrOmitRequired, got %v", err)
	}

	noPort := &BootstrapConfig{Environment: testEnvironment(), Switch: &SwitchConfig{PortAssignments: []PortAssignment{{Class: zone.PortClassBMC}}}}
	if _, err := noPort.NetworkPlan(); !errors.As(err, &missing) {
		t.Fatalf("want missing port, got %v", err)
	}

	var classErr ErrSwitchPortClass
	badClass := &BootstrapConfig{Environment: testEnvironment(), Switch: &SwitchConfig{PortAssignments: []PortAssignment{{Port: "Eth1/9", Class: "uplink"}}}}
	if _, err := badClass.NetworkPlan(); !errors.As(err, &classErr) {
		t.Fatalf("want ErrSwitchPortClass, got %v", err)
	}
	if !strings.Contains(classErr.Error(), `"Eth1/9"`) || errors.Unwrap(classErr) == nil {
		t.Fatalf("ErrSwitchPortClass must name the port and wrap the cause: %v", classErr)
	}

	// An override may only name a declared zone, so omitting management
	// drops its override too.
	noMgmtEnv := testEnvironment()
	noMgmtEnv.Overrides = slices.DeleteFunc(noMgmtEnv.Overrides, func(o netplan.Override) bool {
		return o.Zone == zone.ZoneManagement
	})
	noMgmt := &BootstrapConfig{
		Environment: noMgmtEnv,
		Zones:       []zone.ZoneConfig{{Name: zone.ZoneManagement, Omit: true}},
		Switch:      &SwitchConfig{PortAssignments: []PortAssignment{{Port: "Eth1/41", Class: zone.PortClassBMC}}},
	}
	var empty netplan.ErrEmptyPortClass
	if _, err := noMgmt.NetworkPlan(); !errors.As(err, &empty) {
		t.Fatalf("want ErrEmptyPortClass for a BMC port without management, got %v", err)
	}
}

// TestLoadBootstrapConfig_RetiredKeys refuses every key the reference
// network retired, naming its line and its replacement.
func TestLoadBootstrapConfig_RetiredKeys(t *testing.T) {
	const base = "deployer:\n  host: deploy.example.com\nenvironment:\n  id: 4\nplatform:\n  domain: example.com\n"
	tests := []struct {
		name, extra, key, use string
	}{
		{"subnets", "subnets:\n  - name: provisioning\n", "subnets", "environment"},
		{"fabric", "fabric:\n  mode: vlan\n", "fabric", "port classes"},
		{"switch vlans", "switch:\n  vendor: noop\n  vlans:\n    provisioning: {vlan: 405}\n", "switch.vlans", "environment"},
		{"port mode", "switch:\n  vendor: noop\n  port_assignments:\n    - {port: Eth1/1, class: bmc}\n    - {port: Eth1/2, mode: trunk}\n", "switch.port_assignments[1].mode", "class"},
		{"port vlans", "switch:\n  vendor: noop\n  port_assignments:\n    - {port: Eth1/2, vlans: [405]}\n", "switch.port_assignments[0].vlans", "class"},
		{"post enrollment", "nodes:\n  - hostname: cp-0\n    post_enrollment: {switch_vlan: production}\n", "nodes[0].post_enrollment", "port class"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := writeYAMLFile(t, base+tc.extra)
			_, err := LoadBootstrapConfig(path)
			var target ErrRetiredKey
			if !errors.As(err, &target) {
				t.Fatalf("want ErrRetiredKey, got %v", err)
			}
			if target.Key != tc.key || target.Line == 0 || !strings.Contains(target.Use, tc.use) {
				t.Fatalf("unexpected %+v", target)
			}
			if !strings.Contains(err.Error(), path) {
				t.Fatalf("error must name the file: %v", err)
			}
		})
	}

	// platform.networks is nested one level deeper than the others.
	path := writeYAMLFile(t, strings.Replace(base, "  domain: example.com\n", "  domain: example.com\n  networks:\n    mgmt: {vlan: 402}\n", 1))
	var target ErrRetiredKey
	if _, err := LoadBootstrapConfig(path); !errors.As(err, &target) || target.Key != "platform.networks" {
		t.Fatalf("want platform.networks refused, got %v", err)
	}
}

// TestLoadBootstrapConfig_PortClasses decodes the switch block on the new
// schema and leaves a clean config alone.
func TestLoadBootstrapConfig_PortClasses(t *testing.T) {
	path := writeYAMLFile(t, `deployer:
  host: deploy.example.com
environment:
  id: 4
  ula: fd12:3456:789a::/48
switch:
  vendor: cisco-nexus
  host: 192.0.2.10
  port_assignments:
    - {port: Eth1/3, class: gateway, description: edge-01}
    - {port: Eth1/25-27, class: hypervisor}
platform:
  domain: example.com
`)
	cfg, err := LoadBootstrapConfig(path)
	if err != nil {
		t.Fatalf("LoadBootstrapConfig: %v", err)
	}
	if cfg.Environment.ULA.String() != "fd12:3456:789a::/48" {
		t.Fatalf("unexpected environment %+v", cfg.Environment)
	}
	if len(cfg.Switch.PortAssignments) != 2 || cfg.Switch.PortAssignments[1].Class != zone.PortClassHypervisor {
		t.Fatalf("unexpected port assignments %+v", cfg.Switch.PortAssignments)
	}
	if _, err := cfg.NetworkPlan(); err != nil {
		t.Fatalf("NetworkPlan: %v", err)
	}
}

// TestNodeConfig_SwitchPort_YAMLRoundTrip keeps the informational switch
// port on a node.
func TestNodeConfig_SwitchPort_YAMLRoundTrip(t *testing.T) {
	var n NodeConfig
	if err := yaml.Unmarshal([]byte("hostname: compute-01\nrole: worker\nswitch_port: Ethernet1/28\n"), &n); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if n.SwitchPort != "Ethernet1/28" {
		t.Errorf("SwitchPort = %q, want Ethernet1/28", n.SwitchPort)
	}
}

// TestErrRetiredKey_Error names file, line, key and replacement.
func TestErrRetiredKey_Error(t *testing.T) {
	msg := ErrRetiredKey{Path: "/x/bootstrap.yaml", Key: "subnets", Line: 7, Use: "environment"}.Error()
	for _, want := range []string{"/x/bootstrap.yaml:7", `"subnets"`, "environment"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("missing %q in %q", want, msg)
		}
	}
}

// TestConfigureSwitch applies the derived configuration through the noop
// configurator, and refuses a config with no environment or a bad class.
func TestConfigureSwitch(t *testing.T) {
	ctx := context.Background()
	o := &Orchestrator{logger: orchTestLogger(), config: &BootstrapConfig{
		Environment: testEnvironment(),
		Switch: &SwitchConfig{Vendor: "noop", PortAssignments: []PortAssignment{
			{Port: "Eth1/25", Class: zone.PortClassHypervisor},
		}},
	}}
	if err := o.configureSwitch(ctx); err != nil {
		t.Fatalf("configureSwitch: %v", err)
	}

	o.config.Environment = nil
	var missing ErrMissingRequiredField
	if err := o.configureSwitch(ctx); !errors.As(err, &missing) {
		t.Fatalf("want ErrMissingRequiredField, got %v", err)
	}
}
