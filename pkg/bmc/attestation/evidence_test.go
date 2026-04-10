// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// Dual-licensed under AGPL-3.0 or a commercial license.

package attestation

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestEvidenceRoundTrip(t *testing.T) {
	now := time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC)
	original := Evidence{
		Vendor:    VendorSupermicro,
		Action:    ActionDump,
		ID:        "id-123",
		Nonce:     []byte{0x01, 0x02, 0x03},
		CreatedAt: now,
		Raw:       []byte("opaque-bytes"),
		Metadata:  map[string]string{"bmc_host": "10.0.0.1"},
	}
	b, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got Evidence
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Vendor != original.Vendor || got.Action != original.Action || got.ID != original.ID {
		t.Errorf("header mismatch: %+v", got)
	}
	if !bytes.Equal(got.Raw, original.Raw) {
		t.Errorf("Raw mismatch: %q vs %q", got.Raw, original.Raw)
	}
	if !bytes.Equal(got.Nonce, original.Nonce) {
		t.Errorf("Nonce mismatch")
	}
	if !got.CreatedAt.Equal(original.CreatedAt) {
		t.Errorf("CreatedAt mismatch: %v vs %v", got.CreatedAt, original.CreatedAt)
	}
	if got.Metadata["bmc_host"] != "10.0.0.1" {
		t.Errorf("Metadata lost")
	}
}

func TestEvidenceZeroTimeOmitted(t *testing.T) {
	ev := Evidence{Vendor: VendorDell, Action: ActionList, Raw: []byte{0xAA}}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes.Contains(b, []byte("created_at")) {
		t.Errorf("zero CreatedAt should be omitted, got %s", b)
	}
	var got Evidence
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !got.CreatedAt.IsZero() {
		t.Errorf("expected zero CreatedAt, got %v", got.CreatedAt)
	}
}

func TestEvidenceUnmarshalError(t *testing.T) {
	var ev Evidence
	if err := ev.UnmarshalJSON([]byte("not-json")); err == nil {
		t.Fatal("expected error for malformed input")
	}
}

func TestVendorConstants(t *testing.T) {
	cases := map[Vendor]string{
		VendorSupermicro: "supermicro",
		VendorDell:       "dell",
		VendorHPE:        "hpe",
		VendorUnknown:    "",
	}
	for v, want := range cases {
		if string(v) != want {
			t.Errorf("vendor %q want %q", v, want)
		}
	}
}
