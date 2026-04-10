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

import "testing"

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
