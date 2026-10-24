package diskimage

import "testing"

// TestErrorMessages pins the operator-facing text of the refusals: each
// names the flag or value at fault and what is wanted instead.
func TestErrorMessages(t *testing.T) {
	tests := map[string]struct {
		err  error
		want string
	}{
		"role template": {
			err:  ErrRoleTemplate{Target: "qemu-virt", Model: "rpi4", Role: "compute", Reason: "dedicated roles are built for the rpi target only"},
			want: "diskimage: --role compute (target qemu-virt, model rpi4): dedicated roles are built for the rpi target only",
		},
		"port forward": {
			err:  ErrInvalidPortForward{Spec: "8080"},
			want: "diskimage test: invalid --forward 8080 (want host:guest[/tcp|udp])",
		},
		"source date epoch missing": {
			err:  ErrSourceDateEpoch{},
			want: "diskimage netboot: --diskless needs --source-date-epoch or SOURCE_DATE_EPOCH",
		},
		"source date epoch invalid": {
			err:  ErrSourceDateEpoch{Value: "-5"},
			want: "diskimage netboot: invalid SOURCE_DATE_EPOCH -5 (want seconds since 1970, >= 0)",
		},
		"unknown media set": {
			err:  ErrUnknownMediaSet{Name: "nope", Known: []string{"x86_64", "arm64-virt"}},
			want: "unknown media set nope (known: x86_64, arm64-virt)",
		},
		"source date epoch without fleet key or diskless": {
			err:  ErrHTTPBootFlags{Flag: "source-date-epoch"},
			want: "--source-date-epoch needs --fleet-key or --diskless: it times only the HTTP boot files and the diskless root",
		},
		"flag without fleet key": {
			err:  ErrHTTPBootFlags{Flag: "target-soc"},
			want: "--target-soc needs --fleet-key: the HTTP boot files are only built when the fleet key is given",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := tc.err.Error(); got != tc.want {
				t.Errorf("Error() = %q, want %q", got, tc.want)
			}
		})
	}
}
