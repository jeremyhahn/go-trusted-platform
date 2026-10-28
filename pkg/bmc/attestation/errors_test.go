// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// Dual-licensed under AGPL-3.0 or a commercial license.

package attestation_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc/attestation"
)

// TestErrorMessages pins every typed error's message, including the
// optional-field omissions callers rely on to keep log lines readable.
func TestErrorMessages(t *testing.T) {
	cause := errors.New("connection refused")
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "unsupported vendor without manufacturer",
			err:  attestation.ErrUnsupportedVendor{},
			want: "bmc attestation: unsupported vendor: (unknown manufacturer)",
		},
		{
			name: "unsupported vendor with manufacturer",
			err:  attestation.ErrUnsupportedVendor{Manufacturer: "Lenovo"},
			want: "bmc attestation: unsupported vendor: Lenovo",
		},
		{
			name: "attestation unsupported, no fields",
			err:  attestation.ErrAttestationUnsupported{},
			want: "bmc attestation: unsupported",
		},
		{
			name: "attestation unsupported, all fields",
			err: attestation.ErrAttestationUnsupported{
				Vendor:   attestation.VendorSupermicro,
				Platform: "X10SDV-TP8F",
				Reason:   "no Silicon Root of Trust",
			},
			want: "bmc attestation: unsupported on supermicro (X10SDV-TP8F): no Silicon Root of Trust",
		},
		{
			name: "attestation unsupported, reason only",
			err:  attestation.ErrAttestationUnsupported{Reason: "no ComponentIntegrity"},
			want: "bmc attestation: unsupported: no ComponentIntegrity",
		},
		{
			name: "attestation failed, no fields",
			err:  attestation.ErrAttestationFailed{},
			want: "bmc attestation: failed",
		},
		{
			name: "attestation failed, all fields",
			err: attestation.ErrAttestationFailed{
				Vendor: attestation.VendorDell,
				Action: attestation.ActionGetInfo,
				Reason: "redfish GET",
				Cause:  cause,
			},
			want: "bmc attestation: dell getinfo failed: redfish GET: connection refused",
		},
		{
			name: "attestation failed, cause only",
			err:  attestation.ErrAttestationFailed{Cause: cause},
			want: "bmc attestation: failed: connection refused",
		},
		{
			name: "policy violation, no fields",
			err:  attestation.ErrPolicyViolation{},
			want: "bmc attestation: policy violation",
		},
		{
			name: "policy violation, rule and detail",
			err:  attestation.ErrPolicyViolation{Rule: "firmware-version", Detail: "1.2 < 1.3"},
			want: "bmc attestation: policy violation [firmware-version]: 1.2 < 1.3",
		},
		{
			name: "policy violation, detail only",
			err:  attestation.ErrPolicyViolation{Detail: "nonce mismatch"},
			want: "bmc attestation: policy violation: nonce mismatch",
		},
		{
			name: "invalid evidence without reason",
			err:  attestation.ErrInvalidEvidence{},
			want: "bmc attestation: invalid evidence",
		},
		{
			name: "invalid evidence with reason",
			err:  attestation.ErrInvalidEvidence{Reason: "empty measurements"},
			want: "bmc attestation: invalid evidence: empty measurements",
		},
		{
			name: "not implemented, no fields",
			err:  attestation.ErrNotImplemented{},
			want: "bmc attestation: not implemented",
		},
		{
			name: "not implemented, vendor and action",
			err:  attestation.ErrNotImplemented{Vendor: attestation.VendorHPE, Action: attestation.ActionCompare},
			want: "bmc attestation: not implemented for hpe (compare)",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.err.Error(); got != tc.want {
				t.Fatalf("Error() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestErrAttestationFailedUnwrap checks that the vendor-side cause stays
// reachable through errors.Is / errors.As after wrapping, and that a
// failure without a cause unwraps to nil.
func TestErrAttestationFailedUnwrap(t *testing.T) {
	cause := attestation.ErrInvalidEvidence{Reason: "truncated"}
	wrapped := fmt.Errorf("verify: %w", attestation.ErrAttestationFailed{
		Vendor: attestation.VendorDell,
		Action: attestation.ActionCompare,
		Cause:  cause,
	})

	var failed attestation.ErrAttestationFailed
	if !errors.As(wrapped, &failed) {
		t.Fatalf("errors.As(ErrAttestationFailed) = false for %v", wrapped)
	}
	if failed.Vendor != attestation.VendorDell || failed.Action != attestation.ActionCompare {
		t.Fatalf("unexpected fields: %+v", failed)
	}
	if !errors.Is(wrapped, cause) {
		t.Fatalf("errors.Is(cause) = false for %v", wrapped)
	}
	var invalid attestation.ErrInvalidEvidence
	if !errors.As(wrapped, &invalid) || invalid.Reason != "truncated" {
		t.Fatalf("errors.As(ErrInvalidEvidence) = %+v", invalid)
	}

	if got := (attestation.ErrAttestationFailed{Reason: "no cause"}).Unwrap(); got != nil {
		t.Fatalf("Unwrap() without cause = %v, want nil", got)
	}
}
