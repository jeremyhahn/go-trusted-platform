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

import "testing"

func TestPrivilege_IsValid(t *testing.T) {
	cases := []struct {
		p    Privilege
		want bool
	}{
		{PrivilegeNoAccess, true},
		{PrivilegeCallback, true},
		{PrivilegeUser, true},
		{PrivilegeOperator, true},
		{PrivilegeAdministrator, true},
		{Privilege(0x00), false},
		{Privilege(0x05), false},
		{Privilege(0xFE), false},
	}
	for _, tc := range cases {
		if got := tc.p.IsValid(); got != tc.want {
			t.Errorf("Privilege(0x%02x).IsValid() = %v, want %v", uint8(tc.p), got, tc.want)
		}
	}
}

func TestPrivilege_String(t *testing.T) {
	cases := []struct {
		p    Privilege
		want string
	}{
		{PrivilegeNoAccess, "no-access"},
		{PrivilegeCallback, "callback"},
		{PrivilegeUser, "user"},
		{PrivilegeOperator, "operator"},
		{PrivilegeAdministrator, "administrator"},
		{Privilege(0x99), "unknown"},
	}
	for _, tc := range cases {
		if got := tc.p.String(); got != tc.want {
			t.Errorf("Privilege(0x%02x).String() = %q, want %q", uint8(tc.p), got, tc.want)
		}
	}
}

func TestCertBackend_IsValid(t *testing.T) {
	cases := []struct {
		b    CertBackend
		want bool
	}{
		{CertBackendAuto, true},
		{CertBackendRedfish, true},
		{CertBackendSMCCGI, true},
		{CertBackend(""), false},
		{CertBackend("ipmi"), false},
		{CertBackend("dell-racadm"), false},
	}
	for _, tc := range cases {
		if got := tc.b.IsValid(); got != tc.want {
			t.Errorf("CertBackend(%q).IsValid() = %v, want %v", string(tc.b), got, tc.want)
		}
	}
}
