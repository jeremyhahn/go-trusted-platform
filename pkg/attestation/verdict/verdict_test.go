// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package verdict

import (
	"errors"
	"testing"
)

func TestDeviceVerdict_Validate_AcceptsConsistentVerdicts(t *testing.T) {
	cases := map[string]DeviceVerdict{
		"passed":                {DeviceID: 7, Passed: true},
		"cryptographic failure": {DeviceID: 7, Passed: false, Cryptographic: true, Reason: "signature invalid"},
		"absence of evidence":   {DeviceID: 7, Passed: false, Cryptographic: false, Reason: "no attestation certificate"},
		"passed with baseline":  {DeviceID: 7, Passed: true, BaselineCaptured: true, BaselineSource: "tofu", ProfileID: 3},
	}
	for name, v := range cases {
		if err := v.Validate(); err != nil {
			t.Errorf("%s: unexpected error: %v", name, err)
		}
	}
}

func TestDeviceVerdict_Validate_RejectsInconsistentVerdicts(t *testing.T) {
	cases := map[string]DeviceVerdict{
		"no device":             {Passed: true},
		"passed with reason":    {DeviceID: 7, Passed: true, Reason: "should not be here"},
		"failed without reason": {DeviceID: 7, Passed: false},
	}
	for name, v := range cases {
		err := v.Validate()
		if err == nil {
			t.Errorf("%s: expected an error", name)
			continue
		}
		if !errors.As(err, new(ErrInvalidVerdict)) {
			t.Errorf("%s: expected ErrInvalidVerdict, got %T", name, err)
		}
	}
}
