// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package verdict

import (
	"errors"
	"testing"
)

func TestEventMetadata_RoundTripsTheOutcome(t *testing.T) {
	cases := map[string]DeviceVerdict{
		"passed":                {DeviceID: 7, HostID: "node-7", Serial: "SN7", Passed: true},
		"cryptographic failure": {DeviceID: 7, HostID: "node-7", Cryptographic: true, Reason: "signature invalid"},
		"absence of evidence":   {DeviceID: 7, Serial: "SN7", Reason: "no attestation certificate"},
	}
	for name, v := range cases {
		got, err := FromEventMetadata(EventMetadata(v))
		if err != nil {
			t.Fatalf("%s: FromEventMetadata: %v", name, err)
		}
		if got != v {
			t.Fatalf("%s: got %+v, want %+v", name, got, v)
		}
	}
}

func TestFromEventMetadata_RejectsMalformedMetadata(t *testing.T) {
	valid := func() map[string]string {
		return EventMetadata(DeviceVerdict{DeviceID: 7, Reason: "signature invalid", Cryptographic: true})
	}
	cases := map[string]func(map[string]string){
		"no device":             func(m map[string]string) { delete(m, "device_id") },
		"malformed device":      func(m map[string]string) { m["device_id"] = "seven" },
		"no outcome":            func(m map[string]string) { delete(m, "passed") },
		"malformed outcome":     func(m map[string]string) { m["passed"] = "yes" },
		"malformed failure":     func(m map[string]string) { m["cryptographic"] = "maybe" },
		"failure with no cause": func(m map[string]string) { delete(m, "reason") },
	}
	for name, corrupt := range cases {
		meta := valid()
		corrupt(meta)
		_, err := FromEventMetadata(meta)
		var malformed ErrMalformedVerdictEvent
		var invalid ErrInvalidVerdict
		if !errors.As(err, &malformed) && !errors.As(err, &invalid) {
			t.Errorf("%s: expected a typed rejection, got %v", name, err)
		}
	}
	if _, err := FromEventMetadata(nil); err == nil {
		t.Error("an event with no metadata must be rejected")
	}
}
