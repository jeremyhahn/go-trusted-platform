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

package commands

import (
	"testing"
	"time"

	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
)

// TestBridgePlatformTokenConfig_ConfiguredPropagatesAllFields verifies that a
// fully populated, enabled webservice JWT.PlatformToken section is projected
// field-for-field onto the daemon validator config, with CacheTTLSeconds
// converted to the daemon's CacheTTL time.Duration. This is the activation
// path: a configured section turns daemon-side broker-token enforcement on.
func TestBridgePlatformTokenConfig_ConfiguredPropagatesAllFields(t *testing.T) {
	src := v1.PlatformTokenConfig{
		Enabled:          true,
		Issuer:           "https://broker.example.com",
		JWKSURL:          "https://broker.example.com/.well-known/jwks.json",
		Audience:         "api://platform-prod",
		AllowBearer:      true,
		ClockSkewSeconds: 90,
		CacheTTLSeconds:  1800,
	}

	got := bridgePlatformTokenConfig(src)

	if !got.Enabled {
		t.Fatalf("Enabled: got false, want true")
	}
	if got.Issuer != src.Issuer {
		t.Errorf("Issuer: got %q, want %q", got.Issuer, src.Issuer)
	}
	if got.JWKSURL != src.JWKSURL {
		t.Errorf("JWKSURL: got %q, want %q", got.JWKSURL, src.JWKSURL)
	}
	if got.Audience != src.Audience {
		t.Errorf("Audience: got %q, want %q", got.Audience, src.Audience)
	}
	if got.AllowBearer != src.AllowBearer {
		t.Errorf("AllowBearer: got %v, want %v", got.AllowBearer, src.AllowBearer)
	}
	wantTTL := 1800 * time.Second
	if got.CacheTTL != wantTTL {
		t.Errorf("CacheTTL: got %v, want %v", got.CacheTTL, wantTTL)
	}
}

// TestBridgePlatformTokenConfig_AbsentLeavesValidatorDisabled verifies that an
// absent/disabled webservice JWT.PlatformToken section (the zero value) yields
// a zero-Enabled daemon config. daemon.New only constructs the shared
// validator when PlatformToken.Enabled is true, so this keeps the serve path
// booting on its legacy per-transport validators rather than failing closed.
func TestBridgePlatformTokenConfig_AbsentLeavesValidatorDisabled(t *testing.T) {
	got := bridgePlatformTokenConfig(v1.PlatformTokenConfig{})

	if got.Enabled {
		t.Fatalf("Enabled: got true, want false for absent section")
	}
	if got.Issuer != "" {
		t.Errorf("Issuer: got %q, want empty", got.Issuer)
	}
	if got.JWKSURL != "" {
		t.Errorf("JWKSURL: got %q, want empty", got.JWKSURL)
	}
	if got.Audience != "" {
		t.Errorf("Audience: got %q, want empty", got.Audience)
	}
	if got.AllowBearer {
		t.Errorf("AllowBearer: got true, want false")
	}
	if got.CacheTTL != 0 {
		t.Errorf("CacheTTL: got %v, want 0", got.CacheTTL)
	}
}

// TestBridgePlatformTokenConfig_DisabledButPopulated verifies that a populated
// section with Enabled=false still carries its fields through but reports
// Enabled=false, so the operator can stage broker config without activating
// enforcement until they flip the enabled flag.
func TestBridgePlatformTokenConfig_DisabledButPopulated(t *testing.T) {
	src := v1.PlatformTokenConfig{
		Enabled:         false,
		Issuer:          "https://broker.example.com",
		JWKSURL:         "https://broker.example.com/jwks.json",
		CacheTTLSeconds: 60,
	}

	got := bridgePlatformTokenConfig(src)

	if got.Enabled {
		t.Fatalf("Enabled: got true, want false")
	}
	if got.Issuer != src.Issuer {
		t.Errorf("Issuer: got %q, want %q", got.Issuer, src.Issuer)
	}
	if got.CacheTTL != 60*time.Second {
		t.Errorf("CacheTTL: got %v, want %v", got.CacheTTL, 60*time.Second)
	}
}

// TestBridgePlatformTokenConfig_ZeroCacheTTLSeconds verifies that a zero
// CacheTTLSeconds maps to a zero CacheTTL. The daemon validator builder
// (newPlatformTokenValidator) applies its own one-hour default when CacheTTL
// is non-positive, mirroring the HTTP path; the bridge itself must not invent
// a default so the builder's documented default remains the single source.
func TestBridgePlatformTokenConfig_ZeroCacheTTLSeconds(t *testing.T) {
	src := v1.PlatformTokenConfig{
		Enabled:         true,
		Issuer:          "https://broker.example.com",
		JWKSURL:         "https://broker.example.com/jwks.json",
		CacheTTLSeconds: 0,
	}

	got := bridgePlatformTokenConfig(src)

	if got.CacheTTL != 0 {
		t.Errorf("CacheTTL: got %v, want 0 (builder applies the default, not the bridge)", got.CacheTTL)
	}
}
