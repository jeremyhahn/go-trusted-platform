// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package installer

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/fips"
)

// The hosted review flagged that the installer's FIPS behaviour had no
// production-path coverage: the pkg/fips tests exercise the helpers but never
// the code that APPLIES them, so unwiring it would not fail a test.
//
// These drive the real decision function. config.FIPS is used to activate,
// which is also the case that matters most — it is the path that does NOT
// depend on the test host's kernel state, and the one where an earlier version
// of this code let SHA-1 through.

func TestResolveLUKSAlgorithms_ConfigFIPSActivates(t *testing.T) {
	// The regression this guards: consulting only kernel state meant a
	// config-only --fips run applied none of the restrictions.
	_, _, _, err := resolveLUKSAlgorithms(&EncryptionConfig{FIPS: true, Hash: "sha1"})
	if err == nil {
		t.Fatal("--fips must reject SHA-1 even when the kernel is not FIPS-activated")
	}
	var notApproved fips.ErrHashNotApproved
	if !errors.As(err, &notApproved) {
		t.Errorf("expected ErrHashNotApproved to surface, got %T: %v", err, err)
	}
}

func TestResolveLUKSAlgorithms_SubstitutesOnlyArgon2(t *testing.T) {
	t.Run("argon2id is substituted and reported", func(t *testing.T) {
		// docs/installer/cli.md: --fips "forces PBKDF2 over Argon2id".
		kdf, _, subst, err := resolveLUKSAlgorithms(&EncryptionConfig{FIPS: true, PBKDF: "argon2id"})
		if err != nil {
			t.Fatalf("the documented override must substitute, not fail: %v", err)
		}
		if kdf != fips.KDFPBKDF2 {
			t.Errorf("KDF = %q, want %q", kdf, fips.KDFPBKDF2)
		}
		if subst != "argon2id" {
			t.Errorf("the substitution must be reported so it can be logged, got %q", subst)
		}
	})

	t.Run("mixed-case argon2 is still substituted", func(t *testing.T) {
		// Normalisation put the canonical name in the error; if that regressed,
		// this takes the rejection path instead of substituting.
		kdf, _, subst, err := resolveLUKSAlgorithms(&EncryptionConfig{FIPS: true, PBKDF: "Argon2id"})
		if err != nil {
			t.Fatalf("a recognised Argon2 spelling must substitute: %v", err)
		}
		if kdf != fips.KDFPBKDF2 || subst == "" {
			t.Errorf("kdf=%q substituted=%q, want pbkdf2 with a reported substitution", kdf, subst)
		}
	})

	t.Run("pbkdf2-sha1 is REFUSED, not substituted", func(t *testing.T) {
		// It is also ErrKDFNotApproved, so a naive check silently rewrote it.
		// Nothing documents swapping a caller's chosen PRF.
		_, _, _, err := resolveLUKSAlgorithms(&EncryptionConfig{FIPS: true, PBKDF: "pbkdf2-sha1"})
		if err == nil {
			t.Fatal("pbkdf2-sha1 must be refused under FIPS, not rewritten")
		}
	})

	t.Run("a typo is REFUSED, not substituted", func(t *testing.T) {
		_, _, _, err := resolveLUKSAlgorithms(&EncryptionConfig{FIPS: true, PBKDF: "pbkdf2x"})
		if err == nil {
			t.Fatal("an unrecognised KDF must surface as a config error")
		}
	})
}

func TestResolveLUKSAlgorithms_Defaults(t *testing.T) {
	t.Run("fips default", func(t *testing.T) {
		kdf, hash, subst, err := resolveLUKSAlgorithms(&EncryptionConfig{FIPS: true})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if kdf != fips.KDFPBKDF2 {
			t.Errorf("KDF = %q, want %q", kdf, fips.KDFPBKDF2)
		}
		if hash != "sha256" {
			t.Errorf("hash = %q, want sha256", hash)
		}
		if subst != "" {
			t.Errorf("nothing was overridden, so nothing should be reported; got %q", subst)
		}
	})

	t.Run("approved explicit selections pass through", func(t *testing.T) {
		kdf, hash, _, err := resolveLUKSAlgorithms(&EncryptionConfig{
			FIPS: true, PBKDF: fips.KDFPBKDF2, Hash: "sha512",
		})
		if err != nil {
			t.Fatalf("approved selections must be accepted: %v", err)
		}
		if kdf != fips.KDFPBKDF2 || hash != "sha512" {
			t.Errorf("kdf=%q hash=%q, want pbkdf2/sha512", kdf, hash)
		}
	})
}

// TestResolveLUKSAlgorithms_RejectsUnusableFormatDigest covers the finding that
// SetupLUKS is a FORMAT path and so carries the narrower LUKS constraint, not
// just FIPS approval.
//
// SHA-384 is FIPS-approved, so the generic validator accepted it — and it then
// reached FormatOptions.HashAlgo, which go-luks2 shares with the anti-forensic
// splitter. AFSplit supports only sha256/sha512, so the install aborted inside
// the library with an opaque error instead of failing here with an explanation.
func TestResolveLUKSAlgorithms_RejectsUnusableFormatDigest(t *testing.T) {
	for _, fipsMode := range []bool{true, false} {
		// Unconditional: the limitation is go-luks2's, not FIPS's, so a
		// non-FIPS install with sha384 fails just as hard.
		_, _, _, err := resolveLUKSAlgorithms(&EncryptionConfig{FIPS: fipsMode, Hash: "sha384"})
		if err == nil {
			t.Errorf("FIPS=%v: sha384 must be refused — AFSplit cannot use it as a format digest", fipsMode)
		}
	}

	// The digests LUKS can actually use still work.
	for _, h := range []string{"sha256", "sha512"} {
		_, hash, _, err := resolveLUKSAlgorithms(&EncryptionConfig{FIPS: true, Hash: h})
		if err != nil {
			t.Errorf("usable digest %q rejected: %v", h, err)
		}
		if hash != h {
			t.Errorf("digest = %q, want %q", hash, h)
		}
	}
}
