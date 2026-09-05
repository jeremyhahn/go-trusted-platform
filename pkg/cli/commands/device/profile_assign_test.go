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

package device

import (
	"errors"
	"testing"
)

// TestRunProfileAssign_InvalidDeviceID verifies a non-numeric or zero
// --device fails with the typed error before any daemon connection is
// attempted; the identity itself is derived on the control plane (#463).
func TestRunProfileAssign_InvalidDeviceID(t *testing.T) {
	for _, bad := range []string{"not-a-number", "0", "-1"} {
		err := runProfileAssign(nil, 1, &assignFlags{deviceID: bad})
		var typed ErrInvalidDeviceID
		if !errors.As(err, &typed) || typed.ID != bad {
			t.Errorf("--device %q: err = %v, want ErrInvalidDeviceID", bad, err)
		}
	}
}

// TestRunProfileAssign_IdentityRequired verifies the fail-fast validation
// before any daemon connection is attempted.
func TestRunProfileAssign_IdentityRequired(t *testing.T) {
	err := runProfileAssign(nil, 1, &assignFlags{})
	var typed ErrAssignIdentityRequired
	if !errors.As(err, &typed) {
		t.Errorf("err = %v, want ErrAssignIdentityRequired", err)
	}
}

// TestRunProfileAssign_InvalidEKCert verifies a malformed --ek-cert value
// is rejected before any daemon connection is attempted.
func TestRunProfileAssign_InvalidEKCert(t *testing.T) {
	err := runProfileAssign(nil, 1, &assignFlags{ekSerial: "EK-1", ekCert: "-----BEGIN NOPE-----"})
	var typed ErrProfileEKCertInvalid
	if !errors.As(err, &typed) {
		t.Errorf("err = %v, want ErrProfileEKCertInvalid", err)
	}
}

// TestProfileAssignCommand_InvalidProfileID verifies argument validation
// on both assign and unassign.
func TestProfileAssignCommand_InvalidProfileID(t *testing.T) {
	assign := newProfileAssignCommand(nil)
	assign.SetArgs([]string{"not-a-number", "--ek-serial", "EK-1"})
	if err := assign.Execute(); err == nil {
		t.Error("assign accepted a non-numeric profile ID")
	} else {
		var typed ErrInvalidProfileID
		if !errors.As(err, &typed) {
			t.Errorf("assign err = %v, want ErrInvalidProfileID", err)
		}
	}

	unassign := newProfileUnassignCommand(nil)
	unassign.SetArgs([]string{"not-a-number"})
	if err := unassign.Execute(); err == nil {
		t.Error("unassign accepted a non-numeric profile ID")
	} else {
		var typed ErrInvalidProfileID
		if !errors.As(err, &typed) {
			t.Errorf("unassign err = %v, want ErrInvalidProfileID", err)
		}
	}
}
