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

package install

import (
	"errors"
	"testing"
)

// TestUKIRebuildErrors pins the operator-facing message of every typed error
// and checks that the wrapping ones expose their cause to errors.Is.
func TestUKIRebuildErrors(t *testing.T) {
	cause := errors.New("boom")
	cases := []struct {
		name    string
		err     error
		want    string
		wrapped bool
	}{
		{
			name: "config not found at a path",
			err:  ErrUKIRebuildConfigNotFound{Path: "/tmp/c.yaml"},
			want: "uki-rebuild: config not found at /tmp/c.yaml (and no /etc/platformd/config.yaml or /etc/platformd/install.yaml)",
		},
		{
			name: "config not found without a path",
			err:  ErrUKIRebuildConfigNotFound{},
			want: "uki-rebuild: no platform config found (looked for /etc/platformd/config.yaml and /etc/platformd/install.yaml)",
		},
		{
			name:    "remote signer setup",
			err:     ErrRemoteSignerSetup{Err: cause},
			want:    "uki-rebuild: failed to set up remote DB signer over the platform SDK client: boom",
			wrapped: true,
		},
		{
			name:    "CA bundle read",
			err:     ErrCABundleRead{Path: "/ca.pem", Err: cause},
			want:    "install: failed to read CA bundle /ca.pem: boom",
			wrapped: true,
		},
		{
			name: "CA bundle parse",
			err:  ErrCABundleParse{Path: "/ca.pem"},
			want: "install: CA bundle /ca.pem contained no PEM certificates",
		},
		{
			name:    "EK certificate read",
			err:     ErrEKCertRead{Path: "/ek.pem", Err: cause},
			want:    "install: failed to read EK certificate /ek.pem: boom",
			wrapped: true,
		},
		{
			name:    "EK certificate parse",
			err:     ErrEKCertParse{Path: "/ek.pem", Err: cause},
			want:    "install: EK certificate /ek.pem did not parse: boom",
			wrapped: true,
		},
		{
			name: "remote sign key reference",
			err:  ErrRemoteSignKeyRef{KeyURI: "kms://"},
			want: `uki-rebuild: secure-boot db key-uri "kms://" is not a usable kms:// reference`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.err.Error(); got != tc.want {
				t.Errorf("Error() = %q, want %q", got, tc.want)
			}
			if got := errors.Is(tc.err, cause); got != tc.wrapped {
				t.Errorf("errors.Is(err, cause) = %v, want %v", got, tc.wrapped)
			}
		})
	}
}
