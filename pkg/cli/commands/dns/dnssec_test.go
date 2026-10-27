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

package dns

import (
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func TestDNSSECSign_SignsZone(t *testing.T) {
	fake := newFakeDNSClient()
	out := withFakeClient(t, fake)
	if err := execute(t, "dnssec", "sign", "example.test."); err != nil {
		t.Fatalf("dnssec sign: %v", err)
	}
	if fake.requests["SignZone"].(*platformv1.SignZoneRequest).GetZoneName() != "example.test." {
		t.Errorf("request = %v", fake.requests["SignZone"])
	}
	if got := tableValue(t, requireTable(t, out), "name"); got != "example.test." {
		t.Errorf("name = %q", got)
	}
}

func TestDNSSECSign_RPCError(t *testing.T) {
	fake := newFakeDNSClient()
	fake.err = errRPC
	withFakeClient(t, fake)
	requireRPCError(t, execute(t, "dnssec", "sign", "example.test."))
}

func TestDNSSECStatus_ShowsKeysAndDS(t *testing.T) {
	fake := newFakeDNSClient()
	fake.dnssec = &platformv1.DNSSECStatus{
		Enabled:    true,
		ZoneSigned: true,
		Algorithm:  "ECDSAP256SHA256",
		KeySize:    "256",
		Keys:       []*platformv1.DNSKEYRecord{{}, {}},
		DsRecords:  []*platformv1.DSRecord{{KeyTag: 12345, Algorithm: 13, DigestType: 2, Digest: "abcd"}},
	}
	out := withFakeClient(t, fake)
	if err := execute(t, "dnssec", "status", "example.test."); err != nil {
		t.Fatalf("dnssec status: %v", err)
	}
	if fake.requests["GetDNSSECStatus"].(*platformv1.GetDNSSECStatusRequest).GetZoneName() != "example.test." {
		t.Errorf("request = %v", fake.requests["GetDNSSECStatus"])
	}
	table := requireTable(t, out)
	want := map[string]string{
		"zone": "example.test.", "enabled": "true", "signed": "true", "algorithm": "ECDSAP256SHA256",
		"key size": "256", "keys": "2", "ds": "12345 13 2 abcd",
	}
	for field, value := range want {
		if got := tableValue(t, table, field); got != value {
			t.Errorf("%s = %q, want %q", field, got, value)
		}
	}
}

func TestDNSSECStatus_UnsignedZone(t *testing.T) {
	out := withFakeClient(t, newFakeDNSClient())
	if err := execute(t, "dnssec", "status", "example.test."); err != nil {
		t.Fatalf("dnssec status: %v", err)
	}
	table := requireTable(t, out)
	if got := tableValue(t, table, "signed"); got != "false" {
		t.Errorf("signed = %q", got)
	}
	if got := tableValue(t, table, "keys"); got != "0" {
		t.Errorf("keys = %q", got)
	}
}

func TestDNSSECStatus_RPCError(t *testing.T) {
	fake := newFakeDNSClient()
	fake.err = errRPC
	withFakeClient(t, fake)
	requireRPCError(t, execute(t, "dnssec", "status", "example.test."))
}
