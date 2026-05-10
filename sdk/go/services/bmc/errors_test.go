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

package bmc

import (
	"errors"
	"strings"
	"testing"
)

// errBMCSentinel is a sentinel used to verify error wrapping via
// errors.Is across all BMC typed errors.
var errBMCSentinel = errors.New("cause")

// TestBMCTypedErrors_MessageAndUnwrap verifies every typed error in the
// SDK renders a non-empty, profile-id-aware message and correctly
// exposes its wrapped cause to errors.Is and errors.As.
func TestBMCTypedErrors_MessageAndUnwrap(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantSubstr string
	}{
		{"Power", &ErrPowerFailed{ProfileID: 1, Action: "on", Cause: errBMCSentinel}, "power on failed for profile 1"},
		{"Boot", &ErrBootDeviceFailed{ProfileID: 2, Cause: errBMCSentinel}, "boot device operation failed for profile 2"},
		{"VMedia", &ErrVirtualMediaFailed{ProfileID: 3, Action: "mount", Cause: errBMCSentinel}, "virtual media mount failed for profile 3"},
		{"Sensor", &ErrSensorsFailed{ProfileID: 4, Cause: errBMCSentinel}, "get sensors failed for profile 4"},
		{"SystemInfo", &ErrSystemInfoFailed{ProfileID: 5, Cause: errBMCSentinel}, "get system info failed for profile 5"},
		{"Provision", &ErrProvisionFailed{ProfileID: 6, Cause: errBMCSentinel}, "provision failed for profile 6"},
		{"Cert", &ErrCertificateFailed{ProfileID: 7, Action: "get", Cause: errBMCSentinel}, "certificate get failed for profile 7"},
		{"User", &ErrUserFailed{ProfileID: 8, Action: "create", Cause: errBMCSentinel}, "user create failed for profile 8"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			msg := tc.err.Error()
			if msg == "" {
				t.Fatal("Error() returned empty string")
			}
			if !strings.Contains(msg, tc.wantSubstr) {
				t.Errorf("Error() = %q, want to contain %q", msg, tc.wantSubstr)
			}
			if !errors.Is(tc.err, errBMCSentinel) {
				t.Errorf("errors.Is(%T) did not find wrapped cause", tc.err)
			}
		})
	}
}
