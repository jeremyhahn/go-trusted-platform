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

package switchmgmt

import (
	"errors"
	"testing"
)

func TestErrSSHConnectionFailed_Error(t *testing.T) {
	cause := errors.New("connection refused")
	err := ErrSSHConnectionFailed{Host: "10.0.0.1", Cause: cause}
	msg := err.Error()
	if msg != "switchmgmt: ssh connection failed to 10.0.0.1: connection refused" {
		t.Fatalf("unexpected error message: %s", msg)
	}
}

func TestErrSSHConnectionFailed_Unwrap(t *testing.T) {
	cause := errors.New("timeout")
	err := ErrSSHConnectionFailed{Host: "10.0.0.1", Cause: cause}
	if !errors.Is(err, cause) {
		t.Fatal("expected Unwrap to return the cause")
	}
}

func TestErrCommandFailed_Error(t *testing.T) {
	cause := errors.New("exit status 1")
	err := ErrCommandFailed{Command: "show vlan", Output: "bad cmd", Cause: cause}
	msg := err.Error()
	if msg != `switchmgmt: command failed "show vlan" (output: bad cmd): exit status 1` {
		t.Fatalf("unexpected error message: %s", msg)
	}
}

func TestErrCommandFailed_ErrorNoCause(t *testing.T) {
	err := ErrCommandFailed{Command: "show vlan", Output: "bad cmd"}
	msg := err.Error()
	if msg != `switchmgmt: command failed "show vlan" (output: bad cmd)` {
		t.Fatalf("unexpected error message: %s", msg)
	}
}

func TestErrCommandFailed_Unwrap(t *testing.T) {
	cause := errors.New("exit status 1")
	err := ErrCommandFailed{Command: "show vlan", Cause: cause}
	if !errors.Is(err, cause) {
		t.Fatal("expected Unwrap to return the cause")
	}
}

func TestErrVLANConfigFailed_Error(t *testing.T) {
	cause := errors.New("permission denied")
	err := ErrVLANConfigFailed{VLANID: 10, Cause: cause}
	msg := err.Error()
	if msg != "switchmgmt: vlan 10 configuration failed: permission denied" {
		t.Fatalf("unexpected error message: %s", msg)
	}
}

func TestErrVLANConfigFailed_Unwrap(t *testing.T) {
	cause := errors.New("denied")
	err := ErrVLANConfigFailed{VLANID: 10, Cause: cause}
	if !errors.Is(err, cause) {
		t.Fatal("expected Unwrap to return the cause")
	}
}

func TestErrPortConfigFailed_Error(t *testing.T) {
	cause := errors.New("port busy")
	err := ErrPortConfigFailed{Port: "Eth1/1", Cause: cause}
	msg := err.Error()
	if msg != "switchmgmt: port Eth1/1 configuration failed: port busy" {
		t.Fatalf("unexpected error message: %s", msg)
	}
}

func TestErrPortConfigFailed_Unwrap(t *testing.T) {
	cause := errors.New("busy")
	err := ErrPortConfigFailed{Port: "Eth1/1", Cause: cause}
	if !errors.Is(err, cause) {
		t.Fatal("expected Unwrap to return the cause")
	}
}

func TestErrUnsupportedVendor_Error(t *testing.T) {
	err := ErrUnsupportedVendor{Vendor: "juniper"}
	msg := err.Error()
	if msg != "switchmgmt: unsupported vendor: juniper" {
		t.Fatalf("unexpected error message: %s", msg)
	}
}

func TestErrVerificationFailed_Error(t *testing.T) {
	err := ErrVerificationFailed{Details: "vlan 10 missing"}
	msg := err.Error()
	if msg != "switchmgmt: verification failed: vlan 10 missing" {
		t.Fatalf("unexpected error message: %s", msg)
	}
}

func TestErrInvalidConfig_Error(t *testing.T) {
	err := ErrInvalidConfig{Field: "host", Reason: "must not be empty"}
	msg := err.Error()
	if msg != "switchmgmt: invalid config: field host: must not be empty" {
		t.Fatalf("unexpected error message: %s", msg)
	}
}

func TestErrInvalidPortRange_Error(t *testing.T) {
	err := ErrInvalidPortRange{Port: "Eth1/abc", Reason: "not a number"}
	msg := err.Error()
	if msg != `switchmgmt: invalid port range "Eth1/abc": not a number` {
		t.Fatalf("unexpected error message: %s", msg)
	}
}

func TestErrNilConfig_Error(t *testing.T) {
	err := ErrNilConfig{}
	msg := err.Error()
	if msg != "switchmgmt: configuration cannot be nil" {
		t.Fatalf("unexpected error message: %s", msg)
	}
}
