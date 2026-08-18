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
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
)

func TestApplyNetworkIdentity_EmptyTemplate(t *testing.T) {
	global := &PlatformGlobalConfig{
		Domain:      "example.com",
		Hostmaster:  "admin@example.com",
		TenantID:    "tenant-001",
		Environment: "production",
		UpstreamDNS: []string{"1.1.1.1:53", "8.8.8.8:53"},
	}

	target := &DeviceIdentity{}

	result := ApplyNetworkIdentity(global, target)

	if result.Domain != "example.com" {
		t.Errorf("expected domain example.com, got %s", result.Domain)
	}
	if result.Hostmaster != "admin@example.com" {
		t.Errorf("expected hostmaster admin@example.com, got %s", result.Hostmaster)
	}
	if result.TenantID != "tenant-001" {
		t.Errorf("expected tenant-id tenant-001, got %s", result.TenantID)
	}
	if result.Environment != "production" {
		t.Errorf("expected environment production, got %s", result.Environment)
	}
	if len(result.DNSFallback) != 2 {
		t.Fatalf("expected 2 fallback DNS servers, got %d", len(result.DNSFallback))
	}
	if result.DNSFallback[0] != "1.1.1.1:53" {
		t.Errorf("expected first fallback 1.1.1.1:53, got %s", result.DNSFallback[0])
	}
	if result.DNSFallback[1] != "8.8.8.8:53" {
		t.Errorf("expected second fallback 8.8.8.8:53, got %s", result.DNSFallback[1])
	}
}

func TestApplyNetworkIdentity_TemplateOverrides(t *testing.T) {
	global := &PlatformGlobalConfig{
		Domain:      "global.example.com",
		Hostmaster:  "global@example.com",
		TenantID:    "global-tenant",
		Environment: "production",
		UpstreamDNS: []string{"1.1.1.1:53"},
	}

	target := &DeviceIdentity{
		Domain:      "override.example.com",
		Hostmaster:  "override@example.com",
		TenantID:    "override-tenant",
		Environment: "staging",
		DNSFallback: []string{"9.9.9.9:53"},
	}

	result := ApplyNetworkIdentity(global, target)

	if result.Domain != "override.example.com" {
		t.Errorf("expected domain override.example.com, got %s", result.Domain)
	}
	if result.Hostmaster != "override@example.com" {
		t.Errorf("expected hostmaster override@example.com, got %s", result.Hostmaster)
	}
	if result.TenantID != "override-tenant" {
		t.Errorf("expected tenant-id override-tenant, got %s", result.TenantID)
	}
	if result.Environment != "staging" {
		t.Errorf("expected environment staging, got %s", result.Environment)
	}
	if len(result.DNSFallback) != 1 || result.DNSFallback[0] != "9.9.9.9:53" {
		t.Errorf("expected fallback [9.9.9.9:53], got %v", result.DNSFallback)
	}
}

func TestApplyNetworkIdentity_NilGlobal(t *testing.T) {
	target := &DeviceIdentity{
		Domain: "existing.example.com",
	}

	result := ApplyNetworkIdentity(nil, target)

	if result.Domain != "existing.example.com" {
		t.Errorf("expected domain existing.example.com, got %s", result.Domain)
	}
}

func TestApplyNetworkIdentity_NilTarget(t *testing.T) {
	global := &PlatformGlobalConfig{
		Domain: "example.com",
	}

	result := ApplyNetworkIdentity(global, nil)

	if result != nil {
		t.Errorf("expected nil result for nil target, got %v", result)
	}
}

func TestApplyNetworkIdentity_PartialOverride(t *testing.T) {
	global := &PlatformGlobalConfig{
		Domain:      "example.com",
		Hostmaster:  "admin@example.com",
		TenantID:    "tenant-001",
		Environment: "development",
	}

	target := &DeviceIdentity{
		Domain: "custom.example.com",
		// Hostmaster, TenantID, and Environment are empty.
	}

	result := ApplyNetworkIdentity(global, target)

	if result.Domain != "custom.example.com" {
		t.Errorf("expected domain custom.example.com, got %s", result.Domain)
	}
	if result.Hostmaster != "admin@example.com" {
		t.Errorf("expected hostmaster admin@example.com, got %s", result.Hostmaster)
	}
	if result.TenantID != "tenant-001" {
		t.Errorf("expected tenant-id tenant-001, got %s", result.TenantID)
	}
	if result.Environment != "development" {
		t.Errorf("expected environment development, got %s", result.Environment)
	}
}

func TestApplyNetworkIdentity_NoDNSWhenEmpty(t *testing.T) {
	global := &PlatformGlobalConfig{
		Domain: "example.com",
	}

	target := &DeviceIdentity{}

	result := ApplyNetworkIdentity(global, target)

	if len(result.DNSFallback) != 0 {
		t.Errorf("expected empty DNS fallback when no upstream DNS, got %v", result.DNSFallback)
	}
}

func TestApplyNetworkIdentity_DNSCopyIndependence(t *testing.T) {
	upstream := []string{"1.1.1.1:53", "8.8.8.8:53"}
	global := &PlatformGlobalConfig{
		Domain:      "example.com",
		UpstreamDNS: upstream,
	}

	target := &DeviceIdentity{}

	result := ApplyNetworkIdentity(global, target)

	// Modify the global slice to verify the copy is independent.
	upstream[0] = "modified"

	if result.DNSFallback[0] != "1.1.1.1:53" {
		t.Errorf("DNS fallback was modified via global reference: got %s", result.DNSFallback[0])
	}
}

// TestApplyNodeIdentity_FullInjection verifies hostname, BMC block, and
// interfaces are injected into the merged config map, overwriting template
// placeholder values, with interface keys matching the
// installer.InterfaceConfig YAML tags.
func TestApplyNodeIdentity_FullInjection(t *testing.T) {
	m := map[string]interface{}{
		"os": map[string]interface{}{
			"hostname": "template-host",
			"timezone": "UTC",
		},
		"bmc": map[string]interface{}{
			"address": "0.0.0.0",
			"port":    623,
		},
		"network": map[string]interface{}{
			"cidr": "10.0.0.0/24",
		},
	}
	node := &NodeConfig{
		Hostname:    "cp-01",
		BMCAddress:  "10.200.0.10",
		BMCUser:     "admin",
		BMCPassword: "secret",
		BMCProtocol: "redfish",
		Interfaces: []installer.InterfaceConfig{
			{
				Name:        "eth0",
				Type:        installer.InterfaceTypeStatic,
				IPv4Address: "198.18.1.140/24",
			},
		},
	}

	if err := ApplyNodeIdentity(m, node); err != nil {
		t.Fatalf("ApplyNodeIdentity: %v", err)
	}

	osMap := m["os"].(map[string]interface{})
	if osMap["hostname"] != "cp-01" {
		t.Errorf("os.hostname = %v, want cp-01 (overwrite wins)", osMap["hostname"])
	}
	if osMap["timezone"] != "UTC" {
		t.Errorf("os.timezone = %v, want UTC (untouched)", osMap["timezone"])
	}

	bmcMap := m["bmc"].(map[string]interface{})
	if bmcMap["address"] != "10.200.0.10" {
		t.Errorf("bmc.address = %v, want 10.200.0.10", bmcMap["address"])
	}
	if bmcMap["username"] != "admin" {
		t.Errorf("bmc.username = %v, want admin", bmcMap["username"])
	}
	if bmcMap["password"] != "secret" {
		t.Errorf("bmc.password = %v, want secret", bmcMap["password"])
	}
	if bmcMap["protocol"] != "redfish" {
		t.Errorf("bmc.protocol = %v, want redfish", bmcMap["protocol"])
	}
	if bmcMap["port"] != 623 {
		t.Errorf("bmc.port = %v, want 623 (untouched)", bmcMap["port"])
	}

	netMap := m["network"].(map[string]interface{})
	if netMap["cidr"] != "10.0.0.0/24" {
		t.Errorf("network.cidr = %v, want 10.0.0.0/24 (untouched)", netMap["cidr"])
	}
	ifaces, ok := netMap["interfaces"].([]interface{})
	if !ok || len(ifaces) != 1 {
		t.Fatalf("network.interfaces = %v, want 1 injected interface", netMap["interfaces"])
	}
	iface, ok := ifaces[0].(map[string]interface{})
	if !ok {
		t.Fatalf("injected interface should be map[string]interface{}, got %T", ifaces[0])
	}
	if iface["name"] != "eth0" {
		t.Errorf("interface name = %v, want eth0", iface["name"])
	}
	if iface["type"] != "static" {
		t.Errorf("interface type = %v, want static", iface["type"])
	}
	if iface["ipv4-address"] != "198.18.1.140/24" {
		t.Errorf("interface ipv4-address = %v, want 198.18.1.140/24 (YAML-tag key)", iface["ipv4-address"])
	}
}

// TestApplyNodeIdentity_CreatesMissingSubmaps verifies the os / bmc /
// network submaps are created when the template does not declare them.
func TestApplyNodeIdentity_CreatesMissingSubmaps(t *testing.T) {
	m := map[string]interface{}{}
	node := &NodeConfig{
		Hostname:   "w-01",
		BMCAddress: "10.200.0.20",
		Interfaces: []installer.InterfaceConfig{
			{Name: "eth0", Type: installer.InterfaceTypeStatic, IPv4Address: "10.0.0.9"},
		},
	}

	if err := ApplyNodeIdentity(m, node); err != nil {
		t.Fatalf("ApplyNodeIdentity: %v", err)
	}
	if m["os"].(map[string]interface{})["hostname"] != "w-01" {
		t.Error("os.hostname should be injected into a freshly created os map")
	}
	if m["bmc"].(map[string]interface{})["address"] != "10.200.0.20" {
		t.Error("bmc.address should be injected into a freshly created bmc map")
	}
	if _, ok := m["network"].(map[string]interface{})["interfaces"]; !ok {
		t.Error("network.interfaces should be injected into a freshly created network map")
	}
}

// TestApplyNodeIdentity_Untouched verifies that absent node fields leave
// the corresponding config sections untouched.
func TestApplyNodeIdentity_Untouched(t *testing.T) {
	tests := []struct {
		name string
		node NodeConfig
		m    map[string]interface{}
		key  string
	}{
		{
			name: "no BMCAddress leaves bmc untouched",
			node: NodeConfig{Hostname: "w-01", BMCUser: "ignored-without-address"},
			m:    map[string]interface{}{},
			key:  "bmc",
		},
		{
			name: "empty Interfaces leaves network untouched",
			node: NodeConfig{Hostname: "w-01"},
			m:    map[string]interface{}{},
			key:  "network",
		},
		{
			name: "empty Hostname leaves os untouched",
			node: NodeConfig{},
			m:    map[string]interface{}{},
			key:  "os",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ApplyNodeIdentity(tt.m, &tt.node); err != nil {
				t.Fatalf("ApplyNodeIdentity: %v", err)
			}
			if _, exists := tt.m[tt.key]; exists {
				t.Errorf("key %q should not be created", tt.key)
			}
		})
	}
}

// TestApplyNodeIdentity_NilMap verifies the typed error for a nil map.
func TestApplyNodeIdentity_NilMap(t *testing.T) {
	err := ApplyNodeIdentity(nil, &NodeConfig{Hostname: "cp-01"})
	if err == nil {
		t.Fatal("expected error for nil map")
	}
	var nilErr ErrNilConfigMap
	if !errors.As(err, &nilErr) {
		t.Errorf("expected ErrNilConfigMap, got %T: %v", err, err)
	}
}

// TestApplyNodeIdentity_NonMapCollision verifies that a non-map value under
// an injected key returns the typed collision error for each injected
// section instead of silently clobbering the value.
func TestApplyNodeIdentity_NonMapCollision(t *testing.T) {
	tests := []struct {
		name string
		m    map[string]interface{}
		node NodeConfig
		key  string
	}{
		{
			name: "os is a string",
			m:    map[string]interface{}{"os": "oops"},
			node: NodeConfig{Hostname: "cp-01"},
			key:  "os",
		},
		{
			name: "bmc is a list",
			m:    map[string]interface{}{"bmc": []interface{}{"oops"}},
			node: NodeConfig{Hostname: "cp-01", BMCAddress: "10.200.0.10"},
			key:  "bmc",
		},
		{
			name: "network is an int",
			m:    map[string]interface{}{"network": 42},
			node: NodeConfig{
				Interfaces: []installer.InterfaceConfig{{Name: "eth0", IPv4Address: "10.0.0.9"}},
			},
			key: "network",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ApplyNodeIdentity(tt.m, &tt.node)
			if err == nil {
				t.Fatal("expected collision error")
			}
			var collision ErrConfigKeyNotMap
			if !errors.As(err, &collision) {
				t.Fatalf("expected ErrConfigKeyNotMap, got %T: %v", err, err)
			}
			if collision.Key != tt.key {
				t.Errorf("collision key = %q, want %q", collision.Key, tt.key)
			}
		})
	}
}
