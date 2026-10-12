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

package provision

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestDecodeFetchConfigJSON_Delivered verifies the delivered arm: a payload
// with a "config" key maps onto the pb Delivered oneof with the exact raw
// config JSON in config_json.
func TestDecodeFetchConfigJSON_Delivered(t *testing.T) {
	payload := []byte(`{"config":{"hostname":"node-02","tpm":{"device":"/dev/tpmrm0"}},"status":"ok"}`)

	resp, err := DecodeFetchConfigJSON(payload)
	if err != nil {
		t.Fatalf("DecodeFetchConfigJSON() unexpected error: %v", err)
	}

	delivered := resp.GetDelivered()
	if delivered == nil {
		t.Fatalf("expected delivered arm, got %+v", resp)
	}
	if delivered.GetStatus() != "ok" {
		t.Errorf("status = %q, want %q", delivered.GetStatus(), "ok")
	}

	var cfg map[string]any
	if err := json.Unmarshal(delivered.GetConfigJson(), &cfg); err != nil {
		t.Fatalf("config_json is not valid JSON: %v", err)
	}
	if cfg["hostname"] != "node-02" {
		t.Errorf("config hostname = %v, want node-02", cfg["hostname"])
	}
}

// TestDecodeFetchConfigJSON_Pending verifies the pending arm: a payload
// without a "config" key maps onto the pb Pending oneof.
func TestDecodeFetchConfigJSON_Pending(t *testing.T) {
	payload := []byte(`{"session_id":"sess-1","provision_url":"https://cp:8443/provision/sess-1","poll_interval_seconds":5}`)

	resp, err := DecodeFetchConfigJSON(payload)
	if err != nil {
		t.Fatalf("DecodeFetchConfigJSON() unexpected error: %v", err)
	}

	pending := resp.GetPending()
	if pending == nil {
		t.Fatalf("expected pending arm, got %+v", resp)
	}
	if pending.GetSessionId() != "sess-1" {
		t.Errorf("session_id = %q, want sess-1", pending.GetSessionId())
	}
	if pending.GetProvisionUrl() != "https://cp:8443/provision/sess-1" {
		t.Errorf("provision_url = %q", pending.GetProvisionUrl())
	}
	if pending.GetPollIntervalSeconds() != 5 {
		t.Errorf("poll_interval_seconds = %d, want 5", pending.GetPollIntervalSeconds())
	}
}

// TestDecodeFetchConfigJSON_InvalidJSON verifies malformed payloads surface
// the typed wire decode error.
func TestDecodeFetchConfigJSON_InvalidJSON(t *testing.T) {
	_, err := DecodeFetchConfigJSON([]byte(`not-json`))
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
	var wireErr *ErrWireDecodeFailed
	if !errors.As(err, &wireErr) {
		t.Fatalf("expected *ErrWireDecodeFailed, got %T: %v", err, err)
	}
	if wireErr.Op != "FetchConfig" {
		t.Errorf("Op = %q, want FetchConfig", wireErr.Op)
	}
}

// TestDecodePollSessionJSON_Delivered verifies the delivered arm of a poll
// response.
func TestDecodePollSessionJSON_Delivered(t *testing.T) {
	payload := []byte(`{"config":{"role":"compute"},"status":"ok"}`)

	resp, err := DecodePollSessionJSON(payload)
	if err != nil {
		t.Fatalf("DecodePollSessionJSON() unexpected error: %v", err)
	}
	delivered := resp.GetDelivered()
	if delivered == nil {
		t.Fatalf("expected delivered arm, got %+v", resp)
	}
	if delivered.GetStatus() != "ok" {
		t.Errorf("status = %q, want ok", delivered.GetStatus())
	}
	if string(delivered.GetConfigJson()) != `{"role":"compute"}` {
		t.Errorf("config_json = %s", delivered.GetConfigJson())
	}
}

// TestDecodePollSessionJSON_Pending verifies the pending arm: status
// "pending" with no config key.
func TestDecodePollSessionJSON_Pending(t *testing.T) {
	resp, err := DecodePollSessionJSON([]byte(`{"status":"pending"}`))
	if err != nil {
		t.Fatalf("DecodePollSessionJSON() unexpected error: %v", err)
	}
	if resp.GetPendingStatus() != "pending" {
		t.Errorf("pending_status = %q, want pending", resp.GetPendingStatus())
	}
	if resp.GetDelivered() != nil {
		t.Error("delivered must be nil for a pending response")
	}
}

// TestDecodePollSessionJSON_InvalidJSON verifies malformed payloads surface
// the typed wire decode error.
func TestDecodePollSessionJSON_InvalidJSON(t *testing.T) {
	_, err := DecodePollSessionJSON([]byte(`[1,2,3`))
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
	var wireErr *ErrWireDecodeFailed
	if !errors.As(err, &wireErr) {
		t.Fatalf("expected *ErrWireDecodeFailed, got %T: %v", err, err)
	}
}

// sessionFixtureJSON is a domain configdelivery.Session JSON object as the
// REST handler serves it, including the enum-string and object-typed profile
// fields that require normalization.
const sessionFixtureJSON = `{
	"id": "sess-9",
	"ek_serial": "EK123",
	"mac_address": "aa:bb:cc:dd:ee:ff",
	"tenant_id": "tenant-1",
	"profile_id": 18446744073709551615,
	"fulfilled": true,
	"created_at": "2026-08-01T10:00:00Z",
	"expires_at": "2026-08-01T10:15:00Z",
	"profile": {
		"id": 42,
		"tenant_id": "tenant-1",
		"name": "node-02",
		"model": "X10SDV",
		"role": "server",
		"zone": "control-plane",
		"config": {"full": "platform config object"},
		"ek_serial": "EK123",
		"mac_address": "aa:bb:cc:dd:ee:ff",
		"assigned": true,
		"assigned_at": "2026-08-01T09:00:00Z",
		"ek_cert": "-----BEGIN CERTIFICATE-----",
		"workload_pcr": 14,
		"networks": {
			"provisioning": {
				"vlan": 100,
				"auth_method": "none",
				"dhcp": true
			},
			"control-plane": {
				"vlan": 200,
				"auth_method": "802.1x",
				"static_ip": "10.0.0.2",
				"dhcp": false
			}
		},
		"platformd": {
			"config_type": "inline",
			"inline": {"listen": ":8443"}
		},
		"match_rules": {"mac_prefix": "aa:bb:cc"},
		"bmc": {"address": "10.4.6.103", "port": 443, "protocol": "redfish"}
	}
}`

// TestDecodeGetSessionJSON_BareObject verifies the REST form (bare session
// object) decodes with full profile normalization.
func TestDecodeGetSessionJSON_BareObject(t *testing.T) {
	resp, err := DecodeGetSessionJSON([]byte(sessionFixtureJSON))
	if err != nil {
		t.Fatalf("DecodeGetSessionJSON() unexpected error: %v", err)
	}
	assertSessionFixture(t, resp.GetSession())
}

// TestDecodeGetSessionJSON_Wrapped verifies the MCP form ({"session": ...})
// decodes identically.
func TestDecodeGetSessionJSON_Wrapped(t *testing.T) {
	wrapped := []byte(`{"session":` + sessionFixtureJSON + `}`)
	resp, err := DecodeGetSessionJSON(wrapped)
	if err != nil {
		t.Fatalf("DecodeGetSessionJSON() unexpected error: %v", err)
	}
	assertSessionFixture(t, resp.GetSession())
}

// TestDecodeGetSessionJSON_Invalid verifies non-object payloads error.
func TestDecodeGetSessionJSON_Invalid(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"malformed", []byte(`{`)},
		{"null", []byte(`null`)},
		{"array", []byte(`[]`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := DecodeGetSessionJSON(tt.data); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

// assertSessionFixture checks the decoded pb ProvisioningSession against
// sessionFixtureJSON, including the normalized profile enums.
func assertSessionFixture(t *testing.T, s *platformv1.ProvisioningSession) {
	t.Helper()
	if s == nil {
		t.Fatal("session is nil")
	}
	if s.GetId() != "sess-9" {
		t.Errorf("id = %q, want sess-9", s.GetId())
	}
	if s.GetEkSerial() != "EK123" {
		t.Errorf("ek_serial = %q", s.GetEkSerial())
	}
	if s.GetMacAddress() != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("mac_address = %q", s.GetMacAddress())
	}
	if s.GetTenantId() != "tenant-1" {
		t.Errorf("tenant_id = %q", s.GetTenantId())
	}
	// Max uint64: pins that the decode path preserves full precision
	// (protojson parses integer digits exactly; no float64 round-trip).
	if s.GetProfileId() != 18446744073709551615 {
		t.Errorf("profile_id = %d, want max uint64", s.GetProfileId())
	}
	if !s.GetFulfilled() {
		t.Error("fulfilled = false, want true")
	}
	if s.GetCreatedAt() == nil || s.GetCreatedAt().AsTime().UTC().Hour() != 10 {
		t.Errorf("created_at = %v", s.GetCreatedAt())
	}

	profile := s.GetProfile()
	if profile == nil {
		t.Fatal("profile is nil")
	}
	if profile.GetId() != 42 {
		t.Errorf("profile.id = %d, want 42", profile.GetId())
	}
	if profile.GetRole() != platformv1.DeviceRole_DEVICE_ROLE_SERVER {
		t.Errorf("profile.role = %v, want DEVICE_ROLE_SERVER", profile.GetRole())
	}
	if profile.GetZone() != "control-plane" {
		t.Errorf("profile.zone = %q", profile.GetZone())
	}
	var config map[string]any
	if err := json.Unmarshal(profile.GetConfig(), &config); err != nil {
		t.Fatalf("profile.config is not JSON bytes: %v", err)
	}
	if config["full"] != "platform config object" {
		t.Errorf("profile.config = %v", config)
	}
	if profile.GetEkSerial() != "EK123" {
		t.Errorf("profile.ek_serial = %q", profile.GetEkSerial())
	}
	if profile.GetMacAddress() != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("profile.mac_address = %q", profile.GetMacAddress())
	}
	// The prestaged EK certificate is a real pb field now: the domain
	// ek_cert key must decode into pb ek_cert instead of being dropped
	// by DiscardUnknown.
	if profile.GetEkCert() != "-----BEGIN CERTIFICATE-----" {
		t.Errorf("profile.ek_cert = %q, want fixture PEM marker", profile.GetEkCert())
	}
	if !profile.GetAssigned() {
		t.Error("profile.assigned = false, want true")
	}
	if profile.GetAssignedAt() == nil || profile.GetAssignedAt().AsTime().UTC().Hour() != 9 {
		t.Errorf("profile.assigned_at = %v", profile.GetAssignedAt())
	}

	networks := profile.GetNetworks()
	if len(networks) != 2 {
		t.Fatalf("networks = %d entries, want 2", len(networks))
	}
	if networks["provisioning"].GetAuthMethod() != platformv1.AuthMethod_AUTH_METHOD_NONE {
		t.Errorf("provisioning auth_method = %v", networks["provisioning"].GetAuthMethod())
	}
	if networks["control-plane"].GetAuthMethod() != platformv1.AuthMethod_AUTH_METHOD_802_1X {
		t.Errorf("trusted auth_method = %v", networks["control-plane"].GetAuthMethod())
	}
	if networks["control-plane"].GetStaticIp() != "10.0.0.2" {
		t.Errorf("trusted static_ip = %q", networks["control-plane"].GetStaticIp())
	}

	pd := profile.GetPlatformdConfig()
	if pd == nil {
		t.Fatal("platformd_config is nil (platformd key not renamed)")
	}
	if pd.GetConfigType() != "inline" {
		t.Errorf("platformd_config.config_type = %q", pd.GetConfigType())
	}
	var inline map[string]any
	if err := json.Unmarshal(pd.GetInline(), &inline); err != nil {
		t.Fatalf("platformd_config.inline is not JSON bytes: %v", err)
	}
	if inline["listen"] != ":8443" {
		t.Errorf("inline listen = %v", inline["listen"])
	}

	if profile.GetMatchRules().GetMacPrefix() != "aa:bb:cc" {
		t.Errorf("match_rules.mac_prefix = %q", profile.GetMatchRules().GetMacPrefix())
	}
	if profile.GetBmc().GetAddress() != "10.4.6.103" {
		t.Errorf("bmc.address = %q", profile.GetBmc().GetAddress())
	}
	if profile.GetBmc().GetProtocol() != "redfish" {
		t.Errorf("bmc.protocol = %q", profile.GetBmc().GetProtocol())
	}
}

// TestDecodeListSessionsJSON_BareArray verifies the REST form (bare array).
func TestDecodeListSessionsJSON_BareArray(t *testing.T) {
	payload := []byte(`[` + sessionFixtureJSON + `]`)
	resp, err := DecodeListSessionsJSON(payload)
	if err != nil {
		t.Fatalf("DecodeListSessionsJSON() unexpected error: %v", err)
	}
	if len(resp.GetSessions()) != 1 {
		t.Fatalf("sessions = %d, want 1", len(resp.GetSessions()))
	}
	assertSessionFixture(t, resp.GetSessions()[0])
}

// TestDecodeListSessionsJSON_Wrapped verifies the MCP form
// ({"sessions": [...]}).
func TestDecodeListSessionsJSON_Wrapped(t *testing.T) {
	payload := []byte(`{"sessions":[` + sessionFixtureJSON + `]}`)
	resp, err := DecodeListSessionsJSON(payload)
	if err != nil {
		t.Fatalf("DecodeListSessionsJSON() unexpected error: %v", err)
	}
	if len(resp.GetSessions()) != 1 {
		t.Fatalf("sessions = %d, want 1", len(resp.GetSessions()))
	}
	assertSessionFixture(t, resp.GetSessions()[0])
}

// TestDecodeListSessionsJSON_EmptyForms verifies empty, null, and empty
// array payloads decode to an empty session list.
func TestDecodeListSessionsJSON_EmptyForms(t *testing.T) {
	for _, data := range [][]byte{nil, []byte("null"), []byte("[]"), []byte(`{"sessions":[]}`)} {
		resp, err := DecodeListSessionsJSON(data)
		if err != nil {
			t.Fatalf("DecodeListSessionsJSON(%q) unexpected error: %v", data, err)
		}
		if len(resp.GetSessions()) != 0 {
			t.Errorf("DecodeListSessionsJSON(%q) = %d sessions, want 0", data, len(resp.GetSessions()))
		}
	}
}

// TestDecodeListSessionsJSON_Invalid verifies malformed payloads surface the
// typed wire decode error.
func TestDecodeListSessionsJSON_Invalid(t *testing.T) {
	_, err := DecodeListSessionsJSON([]byte(`{"sessions":"nope"}`))
	if err == nil {
		t.Fatal("expected error")
	}
	var wireErr *ErrWireDecodeFailed
	if !errors.As(err, &wireErr) {
		t.Fatalf("expected *ErrWireDecodeFailed, got %T: %v", err, err)
	}
}

// TestDecodeGetSessionJSON_ProfileBaselineAndTLSServerName verifies the
// domain-JSON profile fields added by #448 decode into the pb DeviceProfile
// with no normalization: entities.PCRBaseline encodes its digests as base64
// under string register keys, which is exactly protojson's map<uint32,bytes>
// form, and tls_server_name matches the pb field name.
func TestDecodeGetSessionJSON_ProfileBaselineAndTLSServerName(t *testing.T) {
	const session = `{
	"id": "sess-448",
	"profile_id": 7,
	"created_at": "2026-08-01T10:00:00Z",
	"expires_at": "2026-08-01T10:15:00Z",
	"profile": {
		"id": 7,
		"name": "compute",
		"role": "worker",
		"tls_server_name": "compute.example.internal",
		"pcr_baseline": {
			"values": {"0": "qrs=", "7": "AQ=="},
			"source": "tofu",
			"recorded_at": "2026-09-01T12:00:00.5Z",
			"recorded_from_device_id": 9007199254740993
		}
	}
}`
	resp, err := DecodeGetSessionJSON([]byte(session))
	if err != nil {
		t.Fatalf("DecodeGetSessionJSON() unexpected error: %v", err)
	}
	profile := resp.GetSession().GetProfile()
	if profile.GetTlsServerName() != "compute.example.internal" {
		t.Fatalf("tls_server_name = %q", profile.GetTlsServerName())
	}
	baseline := profile.GetPcrBaseline()
	if baseline == nil {
		t.Fatal("pcr_baseline dropped")
	}
	if string(baseline.GetValues()[0]) != "\xaa\xbb" || string(baseline.GetValues()[7]) != "\x01" {
		t.Fatalf("values = %v", baseline.GetValues())
	}
	if baseline.GetSource() != "tofu" || baseline.GetRecordedFromDeviceId() != 9007199254740993 {
		t.Fatalf("source/device = %q/%d", baseline.GetSource(), baseline.GetRecordedFromDeviceId())
	}
	if want := time.Date(2026, 9, 1, 12, 0, 0, 500_000_000, time.UTC); !baseline.GetRecordedAt().AsTime().Equal(want) {
		t.Fatalf("recorded_at = %v, want %v", baseline.GetRecordedAt().AsTime(), want)
	}

	// A profile without either field decodes with both unset.
	bare, err := DecodeGetSessionJSON([]byte(`{"id": "s", "profile_id": 1, "profile": {"id": 1, "name": "q", "role": "worker"}}`))
	if err != nil {
		t.Fatalf("DecodeGetSessionJSON(bare) unexpected error: %v", err)
	}
	if bare.GetSession().GetProfile().GetPcrBaseline() != nil || bare.GetSession().GetProfile().GetTlsServerName() != "" {
		t.Fatal("absent fields must stay absent")
	}
}
