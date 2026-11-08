// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// Dual-licensed under AGPL-3.0 or a commercial license.

package supermicro_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc/attestation"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc/attestation/supermicro"
)

// TestStubBackend_AllMethodsReturnUnsupported locks in the contract
// that every [attestation.AttestationProvider] method on the Supermicro
// stub backend returns [attestation.ErrAttestationUnsupported] with the
// vendor tag set to VendorSupermicro. A regression here would let a
// caller mistakenly treat Supermicro as "not yet implemented" (a
// transient state) instead of "hardware incapable" (a permanent state
// on X10-class hardware).
func TestStubBackend_AllMethodsReturnUnsupported(t *testing.T) {
	b := supermicro.NewStubBackend("X10SDV-TP8F")
	ctx := context.Background()

	assertUnsupported := func(t *testing.T, op string, err error) {
		t.Helper()
		if err == nil {
			t.Fatalf("%s: want ErrAttestationUnsupported, got nil", op)
		}
		var target attestation.ErrAttestationUnsupported
		if !errors.As(err, &target) {
			t.Fatalf("%s: want ErrAttestationUnsupported, got %T: %v", op, err, err)
		}
		if target.Vendor != attestation.VendorSupermicro {
			t.Errorf("%s: Vendor=%q want %q", op, target.Vendor, attestation.VendorSupermicro)
		}
		if target.Platform != "X10SDV-TP8F" {
			t.Errorf("%s: Platform=%q want X10SDV-TP8F", op, target.Platform)
		}
		if !strings.Contains(target.Reason, "X10") {
			t.Errorf("%s: Reason should mention X10 hardware gap, got %q", op, target.Reason)
		}
	}

	_, err := b.Dump(ctx, []byte("nonce"))
	assertUnsupported(t, "Dump", err)

	_, err = b.List(ctx)
	assertUnsupported(t, "List", err)

	_, err = b.Download(ctx, "id")
	assertUnsupported(t, "Download", err)

	err = b.Delete(ctx, "id")
	assertUnsupported(t, "Delete", err)

	_, err = b.GetInfo(ctx, &attestation.Evidence{})
	assertUnsupported(t, "GetInfo", err)

	_, err = b.Compare(ctx, &attestation.Evidence{}, &attestation.Evidence{})
	assertUnsupported(t, "Compare", err)
}

// TestStubBackend_RegisteredWithDispatcher proves the package's init
// registration: the dispatcher routes every Supermicro manufacturer
// spelling to a StubBackend carrying the target's platform, and that
// backend refuses with the typed unsupported error rather than a nil
// provider or a generic error.
func TestStubBackend_RegisteredWithDispatcher(t *testing.T) {
	tests := []struct {
		name         string
		manufacturer string
		platform     string
	}{
		{name: "redfish manufacturer", manufacturer: "Supermicro", platform: "X10SDV-TP8F"},
		{name: "spaced spelling", manufacturer: "Super Micro Computer, Inc.", platform: "X11SPM-TF"},
		{name: "unknown platform", manufacturer: "SUPERMICRO", platform: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			p, err := attestation.NewProvider(ctx, nil, attestation.Target{
				Manufacturer: tc.manufacturer,
				Platform:     tc.platform,
			})
			if err != nil {
				t.Fatalf("NewProvider: %v", err)
			}
			if _, ok := p.(*supermicro.StubBackend); !ok {
				t.Fatalf("provider is %T, want *supermicro.StubBackend", p)
			}

			_, err = p.Dump(ctx, []byte("nonce"))
			var unsupported attestation.ErrAttestationUnsupported
			if !errors.As(err, &unsupported) {
				t.Fatalf("Dump: want ErrAttestationUnsupported, got %T: %v", err, err)
			}
			if unsupported.Vendor != attestation.VendorSupermicro {
				t.Errorf("Vendor=%q want %q", unsupported.Vendor, attestation.VendorSupermicro)
			}
			if unsupported.Platform != tc.platform {
				t.Errorf("Platform=%q want %q", unsupported.Platform, tc.platform)
			}
		})
	}
}

// TestStubBackend_ImplementsProviderInterface is a compile-time guard
// (the stub file has a `var _ AttestationProvider = (*StubBackend)(nil)`
// line, but this test makes the contract explicit at test time too).
func TestStubBackend_ImplementsProviderInterface(t *testing.T) {
	var _ attestation.AttestationProvider = supermicro.NewStubBackend("")
}

// TestStubBackend_ErrorMessageMentionsDesignDoc ensures the error
// message points operators at the architecture design document so they
// can see the revival plan, not just hit a dead end.
func TestStubBackend_ErrorMessageMentionsDesignDoc(t *testing.T) {
	b := supermicro.NewStubBackend("X10SDV-TP8F")
	_, err := b.Dump(context.Background(), nil)
	if err == nil {
		t.Fatal("Dump: want error, got nil")
	}
	if !strings.Contains(err.Error(), "bmc-attestation.md") {
		t.Errorf("error message should reference design doc, got: %q", err.Error())
	}
}
