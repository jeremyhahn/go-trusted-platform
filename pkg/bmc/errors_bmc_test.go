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
	"io"
	"testing"
)

// TestErrorMessages pins the operator-facing text of each typed error and,
// for wrapping errors, that the cause stays reachable through errors.Is.
func TestErrorMessages(t *testing.T) {
	license := ErrVirtualMediaLicenseRequired{Vendor: "Dell", License: "iDRAC Enterprise"}
	tests := []struct {
		name  string
		err   error
		want  string
		cause error
	}{
		{
			name: "boot override unsupported with every field",
			err:  ErrBootOverrideUnsupported{Backend: "redfish", Vendor: "supermicro", Device: "cd", Reason: "no UEFI CD target"},
			want: "bmc: boot override unsupported: backend=redfish vendor=supermicro device=cd: no UEFI CD target",
		},
		{
			name: "boot override unsupported bare",
			err:  ErrBootOverrideUnsupported{},
			want: "bmc: boot override unsupported",
		},
		{
			name: "unknown boot override strategy",
			err:  ErrUnknownBootOverrideStrategy{Strategy: "floppy"},
			want: `bmc: unknown boot override strategy "floppy" (not registered in bootOverrideBackends)`,
		},
		{
			name:  "UEFI boot clear unsupported with platform and cause",
			err:   ErrUEFIBootClearUnsupported{Manufacturer: "Dell", Model: "R640", Cause: io.EOF},
			want:  "bmc: UEFI NVRAM boot-entry clear unsupported on Dell/R640: EOF",
			cause: io.EOF,
		},
		{
			name: "UEFI boot clear unsupported bare",
			err:  ErrUEFIBootClearUnsupported{},
			want: "bmc: UEFI NVRAM boot-entry clear unsupported",
		},
		{
			name:  "get SDR repository info",
			err:   ErrGetSDRRepoInfo{Cause: io.EOF},
			want:  "bmc: get SDR repository info: EOF",
			cause: io.EOF,
		},
		{
			name: "SDR response too short without operation",
			err:  ErrSDRResponseTooShort{Length: 3, Expected: 5},
			want: "bmc: SDR response too short: 3 bytes (need >=5)",
		},
		{
			name: "SDR response too short with operation",
			err:  ErrSDRResponseTooShort{Operation: "Get SDR", Length: 3, Expected: 5},
			want: "bmc: Get SDR response too short: 3 bytes (need >=5)",
		},
		{
			name:  "reserve SDR",
			err:   ErrReserveSDR{Cause: io.EOF},
			want:  "bmc: reserve SDR repository: EOF",
			cause: io.EOF,
		},
		{
			name:  "BMC reset timeout",
			err:   ErrBMCResetTimeout{Cause: io.EOF},
			want:  "bmc: timed out waiting for BMC to become ready after reset: EOF",
			cause: io.EOF,
		},
		{
			name: "Redfish service root status",
			err:  ErrRedfishServiceRootStatus{Status: 503},
			want: "bmc: redfish service root status 503",
		},
		{
			name: "event log walk stalled",
			err:  ErrEventLogWalkStalled{RecordID: 7, Read: 3, Reported: 10},
			want: "bmc: SEL walk stalled at record 7 after 3 of 10 reported entries",
		},
		{
			name: "event log paging",
			err:  ErrEventLogPaging{Link: "/redfish/v1/log?$skip=5", Pages: 100},
			want: "bmc: Redfish log paging did not terminate after 100 pages (next /redfish/v1/log?$skip=5)",
		},
		{
			name: "virtual media invalid spec",
			err:  ErrVirtualMediaInvalidSpec{Field: "url", Reason: "empty"},
			want: "bmc: invalid virtual media spec: url: empty",
		},
		{
			name: "virtual media unsupported",
			err:  ErrVirtualMediaUnsupported{Backend: "ipmi", Vendor: "dell", Reason: "no virtual media"},
			want: `bmc: virtual media unsupported by backend "ipmi" (vendor "dell"): no virtual media`,
		},
		{
			name: "virtual media license required",
			err:  license,
			want: "bmc: virtual media requires iDRAC Enterprise license from Dell",
		},
		{
			name:  "virtual media backend failed with cause",
			err:   ErrVirtualMediaBackendFailed{Backend: "redfish-std", Cause: io.EOF},
			want:  `bmc: virtual media backend "redfish-std" failed: EOF`,
			cause: io.EOF,
		},
		{
			name: "virtual media backend failed bare",
			err:  ErrVirtualMediaBackendFailed{Backend: "redfish-std"},
			want: `bmc: virtual media backend "redfish-std" failed`,
		},
		{
			name: "virtual media all backends failed without attempts",
			err:  ErrVirtualMediaAllBackendsFailed{},
			want: "bmc: virtual media: no backend supported the request",
		},
		{
			name: "virtual media all backends failed lists every attempt",
			err: ErrVirtualMediaAllBackendsFailed{Attempts: []VirtualMediaAttempt{
				{Backend: "redfish-std", Err: io.EOF},
				{Backend: "redfish-smc", Err: license},
			}},
			want: "bmc: virtual media: all backends failed: redfish-std: EOF; redfish-smc: " + license.Error(),
		},
		{
			name:  "virtual media auth with cause",
			err:   ErrVirtualMediaAuth{Backend: "redfish-smc", Cause: io.EOF},
			want:  `bmc: virtual media auth failed for backend "redfish-smc": EOF`,
			cause: io.EOF,
		},
		{
			name: "virtual media auth bare",
			err:  ErrVirtualMediaAuth{Backend: "redfish-smc"},
			want: `bmc: virtual media auth failed for backend "redfish-smc"`,
		},
		{
			name: "Redfish not a service root",
			err:  ErrRedfishNotServiceRoot{Address: "10.0.0.5"},
			want: "bmc: 10.0.0.5 did not answer " + redfishServiceRootPath + " as a Redfish service root",
		},
		{
			name:  "Redfish transport init",
			err:   ErrRedfishTransportInit{Cause: io.EOF},
			want:  "bmc: redfish transport init failed: EOF",
			cause: io.EOF,
		},
		{
			name: "FIPS algorithm not approved",
			err:  ErrFIPSAlgorithmNotApproved{Field: "integrity", Algorithm: 0x01, Approved: 0x04},
			want: "bmc: BMC selected non-approved RMCP+ integrity algorithm 0x01; this FIPS build accepts 0x04 only",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.err.Error(); got != tc.want {
				t.Errorf("Error() = %q\nwant      %q", got, tc.want)
			}
			if tc.cause != nil && !errors.Is(tc.err, tc.cause) {
				t.Errorf("errors.Is(%v, %v) = false, want the cause reachable", tc.err, tc.cause)
			}
			if tc.cause == nil && errors.Unwrap(tc.err) != nil {
				t.Errorf("Unwrap() = %v, want nil without a cause", errors.Unwrap(tc.err))
			}
		})
	}
}
