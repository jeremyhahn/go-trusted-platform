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
)

// --- Boot retry error tests ---

func TestErrBootRetryExhausted(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		err := ErrBootRetryExhausted{
			Hostname:   "lab-node-3",
			MaxRetries: 3,
			Cause:      errors.New("install log not found"),
		}
		want := "bootstrap: node lab-node-3: boot retry exhausted after 3 attempts (check BIOS boot order: ATEN CDROM must be before Hard Disk): install log not found"
		if got := err.Error(); got != want {
			t.Errorf("Error() = %q, want %q", got, want)
		}
		if err.Unwrap() == nil {
			t.Error("Unwrap should return cause")
		}
	})

	t.Run("without cause", func(t *testing.T) {
		err := ErrBootRetryExhausted{
			Hostname:   "lab-node-3",
			MaxRetries: 3,
		}
		want := "bootstrap: node lab-node-3: boot retry exhausted after 3 attempts (check BIOS boot order: ATEN CDROM must be before Hard Disk)"
		if got := err.Error(); got != want {
			t.Errorf("Error() = %q, want %q", got, want)
		}
		if err.Unwrap() != nil {
			t.Error("Unwrap should return nil when no cause")
		}
	})
}

func TestErrBootFromDiskDetected(t *testing.T) {
	err := ErrBootFromDiskDetected{
		Hostname: "lab-node-3",
		Attempt:  2,
	}
	want := "bootstrap: node lab-node-3: booted from disk instead of ISO on attempt 2"
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestErrTemplateMergeFailed(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		err := ErrTemplateMergeFailed{
			Hostname: "w1",
			Role:     "worker",
			Cause:    errors.New("yaml parse error"),
		}
		want := "bootstrap: failed to merge template for node w1 (role=worker): yaml parse error"
		if got := err.Error(); got != want {
			t.Errorf("Error() = %q, want %q", got, want)
		}
	})

	t.Run("without cause", func(t *testing.T) {
		err := ErrTemplateMergeFailed{
			Hostname: "w1",
			Role:     "worker",
		}
		want := "bootstrap: failed to merge template for node w1 (role=worker)"
		if got := err.Error(); got != want {
			t.Errorf("Error() = %q, want %q", got, want)
		}
	})
}

// --- Config type tests ---

// --- Deep merge tests ---

func TestDeepMergeSeeder(t *testing.T) {
	t.Run("simple override", func(t *testing.T) {
		dst := map[string]interface{}{
			"hostname": "default",
			"port":     8443,
		}
		src := map[string]interface{}{
			"hostname": "lab-node-3",
		}
		result := deepMergeSeeder(dst, src)
		if result["hostname"] != "lab-node-3" {
			t.Errorf("hostname = %v, want lab-node-3", result["hostname"])
		}
		if result["port"] != 8443 {
			t.Errorf("port = %v, want 8443", result["port"])
		}
	})

	t.Run("nested merge", func(t *testing.T) {
		dst := map[string]interface{}{
			"os": map[string]interface{}{
				"hostname": "default",
				"timezone": "UTC",
			},
		}
		src := map[string]interface{}{
			"os": map[string]interface{}{
				"hostname": "lab-node-3",
			},
		}
		result := deepMergeSeeder(dst, src)
		osMap, ok := result["os"].(map[string]interface{})
		if !ok {
			t.Fatal("os should be a map")
		}
		if osMap["hostname"] != "lab-node-3" {
			t.Errorf("os.hostname = %v, want lab-node-3", osMap["hostname"])
		}
		if osMap["timezone"] != "UTC" {
			t.Errorf("os.timezone = %v, want UTC", osMap["timezone"])
		}
	})

	t.Run("add new key", func(t *testing.T) {
		dst := map[string]interface{}{
			"existing": "value",
		}
		src := map[string]interface{}{
			"new_key": "new_value",
		}
		result := deepMergeSeeder(dst, src)
		if result["existing"] != "value" {
			t.Errorf("existing = %v, want value", result["existing"])
		}
		if result["new_key"] != "new_value" {
			t.Errorf("new_key = %v, want new_value", result["new_key"])
		}
	})

	t.Run("does not mutate dst", func(t *testing.T) {
		dst := map[string]interface{}{
			"key": "original",
		}
		src := map[string]interface{}{
			"key": "override",
		}
		result := deepMergeSeeder(dst, src)
		if dst["key"] != "original" {
			t.Error("dst should not be mutated")
		}
		if result["key"] != "override" {
			t.Errorf("result should have override value, got %v", result["key"])
		}
	})
}

func TestApplyGlobalIdentitySeeder(t *testing.T) {
	t.Run("fills empty fields with device-schema tenant key", func(t *testing.T) {
		m := map[string]interface{}{
			"domain":      "",
			"hostmaster":  "",
			"tenant-id":   "",
			"environment": "",
		}
		platform := &PlatformGlobalConfig{
			Domain:      "test.io",
			Hostmaster:  "host@test.io",
			TenantID:    "default",
			Environment: "production",
		}
		applyGlobalIdentitySeeder(m, platform)
		if m["domain"] != "test.io" {
			t.Errorf("domain = %v, want test.io", m["domain"])
		}
		if m["hostmaster"] != "host@test.io" {
			t.Errorf("hostmaster = %v, want host@test.io", m["hostmaster"])
		}
		if m["tenant-id"] != "default" {
			t.Errorf("tenant-id = %v, want default", m["tenant-id"])
		}
		if _, exists := m["tenant_id"]; exists {
			t.Error("legacy tenant_id key must not be injected")
		}
		if m["environment"] != "production" {
			t.Errorf("environment = %v, want production", m["environment"])
		}
	})

	t.Run("overwrites template placeholders", func(t *testing.T) {
		// Templates ship non-empty example placeholders; the platform
		// global must replace them. Per-node identity overrides still
		// win because the override merge runs AFTER this function.
		m := map[string]interface{}{
			"domain": "placeholder.example.com",
		}
		platform := &PlatformGlobalConfig{
			Domain: "prod.io",
		}
		applyGlobalIdentitySeeder(m, platform)
		if m["domain"] != "prod.io" {
			t.Errorf("domain = %v, want prod.io (placeholder must be overwritten)", m["domain"])
		}
	})

	t.Run("empty platform value leaves template value", func(t *testing.T) {
		m := map[string]interface{}{
			"domain": "existing.io",
		}
		applyGlobalIdentitySeeder(m, &PlatformGlobalConfig{})
		if m["domain"] != "existing.io" {
			t.Errorf("domain = %v, want existing.io (empty platform value must not clobber)", m["domain"])
		}
	})

	t.Run("spiffe trust domain follows the internal domain", func(t *testing.T) {
		// The trust domain is deployment identity: the seeder must
		// overwrite the template's example.internal placeholder inside
		// the nested quicbaas section with platform.internal_domain.
		m := map[string]interface{}{
			"quicbaas": map[string]interface{}{
				"spiffe-trust-domain": "example.internal",
				"data-dir":            "/var/lib/trusted-platform/quicbaas",
			},
		}
		platform := &PlatformGlobalConfig{InternalDomain: "prod.internal"}
		applyGlobalIdentitySeeder(m, platform)
		section := m["quicbaas"].(map[string]interface{})
		if section["spiffe-trust-domain"] != "prod.internal" {
			t.Errorf("spiffe-trust-domain = %v, want prod.internal", section["spiffe-trust-domain"])
		}
		if section["data-dir"] != "/var/lib/trusted-platform/quicbaas" {
			t.Error("sibling quicbaas keys must be untouched")
		}
	})

	t.Run("spiffe trust domain untouched without internal domain or section", func(t *testing.T) {
		// No internal domain: the template value stands.
		m := map[string]interface{}{
			"quicbaas": map[string]interface{}{"spiffe-trust-domain": "example.internal"},
		}
		applyGlobalIdentitySeeder(m, &PlatformGlobalConfig{Domain: "prod.io"})
		if m["quicbaas"].(map[string]interface{})["spiffe-trust-domain"] != "example.internal" {
			t.Error("template value must stand when platform.internal_domain is empty")
		}
		// No quicbaas section: nothing is invented.
		m2 := map[string]interface{}{}
		applyGlobalIdentitySeeder(m2, &PlatformGlobalConfig{InternalDomain: "prod.internal"})
		if _, exists := m2["quicbaas"]; exists {
			t.Error("a quicbaas section must not be invented")
		}
	})

	t.Run("nil platform", func(t *testing.T) {
		m := map[string]interface{}{
			"domain": "",
		}
		applyGlobalIdentitySeeder(m, nil)
		if m["domain"] != "" {
			t.Errorf("domain should remain empty with nil platform")
		}
	})
}

// --- Verify power on helper tests ---

func TestVerifyPowerOn_Constants(t *testing.T) {
	// Verify the boot retry constants are sensible.
	if defaultBootRetryMax < 1 {
		t.Errorf("defaultBootRetryMax = %d, want >= 1", defaultBootRetryMax)
	}
	if bootProbeTimeout < powerVerifyInterval {
		t.Errorf("bootProbeTimeout (%s) should be >= powerVerifyInterval (%s)",
			bootProbeTimeout, powerVerifyInterval)
	}
}
