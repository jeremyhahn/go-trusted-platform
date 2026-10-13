package deviceverdict

import (
	"errors"
	"testing"
)

func TestDeviceVerdictValidateAcceptsConsistentVerdicts(t *testing.T) {
	for _, v := range []DeviceVerdict{
		{DeviceID: 1, Passed: true},
		{DeviceID: 2, Passed: false, Cryptographic: true, Reason: "pcr mismatch"},
	} {
		if err := v.Validate(); err != nil {
			t.Fatalf("Validate() unexpected error: %v", err)
		}
	}
}

func TestDeviceVerdictValidateRejectsInconsistentVerdicts(t *testing.T) {
	for _, v := range []DeviceVerdict{
		{DeviceID: 0, Passed: true},
		{DeviceID: 1, Passed: true, Reason: "unexpected"},
		{DeviceID: 2, Passed: false},
	} {
		var invalid ErrInvalidVerdict
		if err := v.Validate(); !errors.As(err, &invalid) {
			t.Fatalf("Validate() error = %v, want ErrInvalidVerdict", err)
		}
	}
}
