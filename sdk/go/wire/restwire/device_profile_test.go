// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package restwire

import (
	"encoding/base64"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestDeviceRole_RoundTripsEveryDomainString verifies every domain role
// string maps to an enum that maps back to the same string, so a profile
// read and written back keeps its role.
func TestDeviceRole_RoundTripsEveryDomainString(t *testing.T) {
	for name := range deviceRoles {
		role := DeviceRoleFromJSON(name)
		back, ok := DeviceRoleToJSON(role)
		if !ok || back != name {
			t.Errorf("%q -> %v -> (%q, %t)", name, role, back, ok)
		}
	}
}

// TestDeviceRole_UnknownAndUnspecified verifies an unknown string reads as
// DEVICE_ROLE_UNKNOWN and DEVICE_ROLE_UNSPECIFIED has no domain string, so an
// encoder omits it.
func TestDeviceRole_UnknownAndUnspecified(t *testing.T) {
	if got := DeviceRoleFromJSON("mystery-box"); got != platformv1.DeviceRole_DEVICE_ROLE_UNKNOWN {
		t.Errorf("unknown role = %v, want DEVICE_ROLE_UNKNOWN", got)
	}
	if name, ok := DeviceRoleToJSON(platformv1.DeviceRole_DEVICE_ROLE_UNSPECIFIED); ok {
		t.Errorf("UNSPECIFIED encoded as %q, want omitted", name)
	}
}

// TestAuthMethod_RoundTripsEveryDomainString verifies the auth-method strings
// survive a decode and re-encode.
func TestAuthMethod_RoundTripsEveryDomainString(t *testing.T) {
	for name := range authMethods {
		method := AuthMethodFromJSON(name)
		back, ok := AuthMethodToJSON(method)
		if !ok || back != name {
			t.Errorf("%q -> %v -> (%q, %t)", name, method, back, ok)
		}
	}
}

// TestAuthMethod_UnknownAndUnspecified verifies an unknown string reads as
// AUTH_METHOD_NONE, the server's default, and UNSPECIFIED is omitted.
func TestAuthMethod_UnknownAndUnspecified(t *testing.T) {
	if got := AuthMethodFromJSON("kerberos"); got != platformv1.AuthMethod_AUTH_METHOD_NONE {
		t.Errorf("unknown auth method = %v, want AUTH_METHOD_NONE", got)
	}
	if name, ok := AuthMethodToJSON(platformv1.AuthMethod_AUTH_METHOD_UNSPECIFIED); ok {
		t.Errorf("UNSPECIFIED encoded as %q, want omitted", name)
	}
}

// TestNormalizeProfileJSON_UnknownEnums verifies unknown role / auth_method
// strings map to the same defaults the daemon converters use.
func TestNormalizeProfileJSON_UnknownEnums(t *testing.T) {
	profile := map[string]any{
		"role": "mystery-box",
		"networks": map[string]any{
			"lab": map[string]any{"auth_method": "kerberos"},
		},
	}
	NormalizeProfileJSON(profile)

	if profile["role"] != "DEVICE_ROLE_UNKNOWN" {
		t.Errorf("role = %v, want DEVICE_ROLE_UNKNOWN", profile["role"])
	}
	lab := profile["networks"].(map[string]any)["lab"].(map[string]any)
	if lab["auth_method"] != "AUTH_METHOD_NONE" {
		t.Errorf("auth_method = %v, want AUTH_METHOD_NONE", lab["auth_method"])
	}
}

// TestNormalizeProfileJSON_ConfigAndAssignedAtEdgeCases verifies the
// normalization edge cases for the config and assigned_at fields: a null
// config and a zero assignment timestamp are dropped (matching the gRPC
// converter's nil/IsZero guards), while a non-object config value is still
// carried as base64(JSON) bytes.
func TestNormalizeProfileJSON_ConfigAndAssignedAtEdgeCases(t *testing.T) {
	profile := map[string]any{
		"config":      nil,
		"assigned_at": ZeroRFC3339,
	}
	NormalizeProfileJSON(profile)
	if _, present := profile["config"]; present {
		t.Error("null config must be dropped")
	}
	if _, present := profile["assigned_at"]; present {
		t.Error("zero assigned_at must be dropped")
	}

	profile = map[string]any{
		"config":      []any{"a", "b"},
		"assigned_at": "2026-08-01T09:00:00Z",
	}
	NormalizeProfileJSON(profile)
	encoded, ok := profile["config"].(string)
	if !ok {
		t.Fatalf("config = %T, want base64 string", profile["config"])
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("config is not base64: %v", err)
	}
	if string(raw) != `["a","b"]` {
		t.Errorf("config JSON = %s", raw)
	}
	if profile["assigned_at"] != "2026-08-01T09:00:00Z" {
		t.Errorf("non-zero assigned_at must be preserved, got %v", profile["assigned_at"])
	}
}

// TestNormalizeProfileJSON_UnencodableConfigIsDropped verifies a config value
// that cannot be JSON-encoded is dropped rather than sent as garbage bytes.
func TestNormalizeProfileJSON_UnencodableConfigIsDropped(t *testing.T) {
	profile := map[string]any{"config": func() {}}
	NormalizeProfileJSON(profile)
	if _, present := profile["config"]; present {
		t.Error("an unencodable config must be dropped")
	}
}

// TestNormalizeProfileJSON_InlineString verifies a string-typed platformd
// inline value passes through unchanged (already base64/bytes-compatible).
func TestNormalizeProfileJSON_InlineString(t *testing.T) {
	already := base64.StdEncoding.EncodeToString([]byte(`{"a":1}`))
	profile := map[string]any{
		"platformd": map[string]any{"config_type": "inline", "inline": already},
	}
	NormalizeProfileJSON(profile)

	pd, ok := profile["platformd_config"].(map[string]any)
	if !ok {
		t.Fatal("platformd not renamed to platformd_config")
	}
	if pd["inline"] != already {
		t.Errorf("inline changed: %v", pd["inline"])
	}
	if _, stillThere := profile["platformd"]; stillThere {
		t.Error("platformd key must be removed after rename")
	}
}

// TestNormalizeProfileJSON_InlineObject verifies an object-typed platformd
// inline value is carried as base64 of its JSON, and a null one is dropped.
func TestNormalizeProfileJSON_InlineObject(t *testing.T) {
	profile := map[string]any{
		"platformd": map[string]any{"inline": map[string]any{"a": 1}},
	}
	NormalizeProfileJSON(profile)
	pd := profile["platformd_config"].(map[string]any)
	if pd["inline"] != base64.StdEncoding.EncodeToString([]byte(`{"a":1}`)) {
		t.Errorf("inline = %v, want base64 of {\"a\":1}", pd["inline"])
	}

	profile = map[string]any{"platformd": map[string]any{"inline": nil}}
	NormalizeProfileJSON(profile)
	if _, present := profile["platformd_config"].(map[string]any)["inline"]; present {
		t.Error("a null inline must be dropped")
	}
}
