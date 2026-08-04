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
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// fakeDeviceGetter satisfies deviceProfileClient for the EK-identity
// derivation tests.
type fakeDeviceGetter struct {
	device *platformv1.Device
	err    error
}

func (f *fakeDeviceGetter) Get(ctx context.Context, id uint64) (*platformv1.Device, error) {
	return f.device, f.err
}

// TestParseEKSerialFromPEM verifies the decimal serial extraction and the
// malformed-input error paths.
func TestParseEKSerialFromPEM(t *testing.T) {
	certPEM := newCLITestEKCertPEM(t)

	serial, err := parseEKSerialFromPEM(certPEM)
	if err != nil {
		t.Fatalf("parseEKSerialFromPEM: %v", err)
	}

	block, _ := pem.Decode([]byte(certPEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse test cert: %v", err)
	}
	if serial != cert.SerialNumber.String() {
		t.Errorf("serial = %q, want %q", serial, cert.SerialNumber.String())
	}

	t.Run("NotPEM", func(t *testing.T) {
		if _, err := parseEKSerialFromPEM("garbage"); err == nil {
			t.Error("expected error for non-PEM input")
		}
	})

	t.Run("NotCertificate", func(t *testing.T) {
		bogus := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x01}}))
		if _, err := parseEKSerialFromPEM(bogus); err == nil {
			t.Error("expected error for invalid certificate bytes")
		}
	})
}

// TestDeriveEKIdentityFromDevice verifies the EK serial and certificate
// derivation from a registered device record (source-agnostic: the same
// X.509 shape whether the EK came from a swtpm-backed vTPM or a physical
// hardware TPM).
func TestDeriveEKIdentityFromDevice(t *testing.T) {
	certPEM := newCLITestEKCertPEM(t)
	ctx := context.Background()

	serial, cert, err := deriveEKIdentityFromDevice(ctx, &fakeDeviceGetter{
		device: &platformv1.Device{Id: 42, EkCert: certPEM},
	}, 42)
	if err != nil {
		t.Fatalf("deriveEKIdentityFromDevice: %v", err)
	}
	if cert != certPEM {
		t.Error("derived certificate does not match the device record")
	}
	if serial == "" {
		t.Error("derived serial is empty")
	}
}

// TestDeriveEKIdentityFromDevice_Errors verifies the lookup-failure and
// missing-EK-certificate error paths.
func TestDeriveEKIdentityFromDevice_Errors(t *testing.T) {
	ctx := context.Background()

	t.Run("LookupFailed", func(t *testing.T) {
		_, _, err := deriveEKIdentityFromDevice(ctx, &fakeDeviceGetter{
			err: errors.New("not found"),
		}, 42)
		var typed ErrGetDeviceFailed
		if !errors.As(err, &typed) {
			t.Errorf("err = %v, want ErrGetDeviceFailed", err)
		}
	})

	t.Run("NoEKCert", func(t *testing.T) {
		_, _, err := deriveEKIdentityFromDevice(ctx, &fakeDeviceGetter{
			device: &platformv1.Device{Id: 42},
		}, 42)
		var typed ErrAssignDeviceHasNoEKCert
		if !errors.As(err, &typed) {
			t.Errorf("err = %v, want ErrAssignDeviceHasNoEKCert", err)
		}
		if typed.DeviceID != 42 {
			t.Errorf("DeviceID = %d, want 42", typed.DeviceID)
		}
	})
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
