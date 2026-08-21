// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package luks

import (
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/fips"
)

// applyFIPSKeyslotPolicy is where the gate actually lives. The regression it
// guards is the one the local review caught: validating only what the CALLER
// passed left the default path — nil options, or options with an empty KDF —
// creating argon2id keyslots under FIPS, because go-luks2 documents an unset
// KDF as defaulting to argon2id and does not consult /proc itself.
//
// These assertions are mode-independent where they can be, since the test host
// may or may not be FIPS-activated.

func TestApplyFIPSKeyslotPolicy_RefusesUnknown(t *testing.T) {
	kdf, hash := "scrypt", ""
	if err := applyFIPSKeyslotPolicy(&kdf, &hash); err == nil {
		t.Fatal("an unrecognised KDF must be refused in every mode")
	}

	kdf, hash = "", "md5"
	if err := applyFIPSKeyslotPolicy(&kdf, &hash); err == nil {
		t.Fatal("an unrecognised hash must be refused in every mode")
	}
}

func TestApplyFIPSKeyslotPolicy_ResolvesOrPreserves(t *testing.T) {
	kdf, hash := "", ""
	if err := applyFIPSKeyslotPolicy(&kdf, &hash); err != nil {
		t.Fatalf("empty values must be resolvable, not rejected: %v", err)
	}

	if fips.IsEnabled() {
		// The load-bearing case: an empty KDF must NOT be left empty, because
		// go-luks2 would then default it to argon2id.
		if kdf != fips.KDFPBKDF2 {
			t.Errorf("under FIPS an empty KDF must resolve to %q, got %q", fips.KDFPBKDF2, kdf)
		}
		if hash == "" {
			t.Error("under FIPS the hash must be pinned rather than left to a default")
		}
		if err := fips.ValidateKeyslot(kdf, hash); err != nil {
			t.Errorf("resolved values must themselves validate: %v", err)
		}
	} else if kdf != "" || hash != "" {
		// Outside FIPS nothing changes — go-luks2's own defaults still apply.
		t.Errorf("outside FIPS values must be left untouched, got kdf=%q hash=%q", kdf, hash)
	}
}

func TestApplyFIPSKeyslotPolicy_AcceptsApproved(t *testing.T) {
	for _, kdf := range []string{
		fips.KDFPBKDF2, fips.KDFPBKDF2SHA256, fips.KDFPBKDF2SHA384, fips.KDFPBKDF2SHA512,
	} {
		k, h := kdf, fips.HashSHA256
		if err := applyFIPSKeyslotPolicy(&k, &h); err != nil {
			t.Errorf("approved KDF %q rejected: %v", kdf, err)
		}
		if k != kdf {
			t.Errorf("an explicit approved KDF must be preserved: %q became %q", kdf, k)
		}
	}
}
