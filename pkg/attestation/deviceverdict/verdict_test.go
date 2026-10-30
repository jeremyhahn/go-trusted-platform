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
	tests := []struct {
		name    string
		verdict DeviceVerdict
		reason  string
	}{
		{"missing device ID", DeviceVerdict{DeviceID: 0, Passed: true}, "device ID is required"},
		{"passed with reason", DeviceVerdict{DeviceID: 1, Passed: true, Reason: "unexpected"}, "a passed verdict must not carry a failure reason"},
		{"failed without reason", DeviceVerdict{DeviceID: 2, Passed: false}, "a failed verdict must carry a reason"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var invalid ErrInvalidVerdict
			err := tt.verdict.Validate()
			if !errors.As(err, &invalid) {
				t.Fatalf("Validate() error = %v, want ErrInvalidVerdict", err)
			}
			if invalid.Reason != tt.reason {
				t.Fatalf("Reason = %q, want %q", invalid.Reason, tt.reason)
			}
			if want := "verdict: invalid device verdict: " + tt.reason; err.Error() != want {
				t.Fatalf("Error() = %q, want %q", err.Error(), want)
			}
		})
	}
}
