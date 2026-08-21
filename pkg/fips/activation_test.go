// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package fips

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// These are the assertions issue #26 asks for, and none of them could be
// written before: IsEnabled read a hardcoded path, so no test could put the
// process into the FIPS-activated state whose behaviour is the whole point.

func TestFIPSActivated_RefusesArgon2Keyslots(t *testing.T) {
	withFIPSActivation(t, true)

	for _, kdf := range []string{KDFArgon2id, KDFArgon2i} {
		t.Run(kdf, func(t *testing.T) {
			err := ValidateKDF(kdf)
			if err == nil {
				t.Fatalf("ValidateKDF(%q) must be refused when FIPS is activated", kdf)
			}
			var typed ErrKDFNotApproved
			if !errors.As(err, &typed) {
				t.Fatalf("expected ErrKDFNotApproved, got %T: %v", err, err)
			}
			if typed.KDF != kdf || typed.Approved != KDFPBKDF2 {
				t.Errorf("error carries KDF=%q Approved=%q, want %q/%q",
					typed.KDF, typed.Approved, kdf, KDFPBKDF2)
			}
		})
	}

	if err := ValidateKDF(KDFPBKDF2); err != nil {
		t.Errorf("pbkdf2 must remain usable under FIPS: %v", err)
	}
}

func TestFIPSActivated_RefusesSHA1(t *testing.T) {
	withFIPSActivation(t, true)

	err := ValidateHash(HashSHA1)
	if err == nil {
		t.Fatal("SHA-1 must be refused when FIPS is activated")
	}
	var typed ErrHashNotApproved
	if !errors.As(err, &typed) {
		t.Fatalf("expected ErrHashNotApproved, got %T: %v", err, err)
	}
	if typed.Hash != HashSHA1 {
		t.Errorf("error carries Hash=%q, want %q", typed.Hash, HashSHA1)
	}

	for _, h := range ApprovedHashes {
		if err := ValidateHash(h); err != nil {
			t.Errorf("approved hash %q rejected under FIPS: %v", h, err)
		}
	}
}

// TestNotActivated_LeavesBehaviourUnchanged is the other half of the ruling:
// "outside FIPS, current defaults unchanged". A gate that also changes the
// non-FIPS path would be a regression for every existing deployment.
func TestNotActivated_LeavesBehaviourUnchanged(t *testing.T) {
	withFIPSActivation(t, false)

	for _, kdf := range []string{KDFPBKDF2, KDFArgon2id, KDFArgon2i} {
		if err := ValidateKDF(kdf); err != nil {
			t.Errorf("KDF %q must stay usable outside FIPS: %v", kdf, err)
		}
	}
	for _, h := range []string{HashSHA256, HashSHA384, HashSHA512, HashSHA1} {
		if err := ValidateHash(h); err != nil {
			t.Errorf("hash %q must stay usable outside FIPS: %v", h, err)
		}
	}
	if got := GetKDF(); got != KDFArgon2id {
		t.Errorf("default KDF outside FIPS = %q, want %q", got, KDFArgon2id)
	}
	if got := GetHashWithDefault(HashSHA1); got != HashSHA1 {
		t.Errorf("outside FIPS a preference must pass through unchanged, got %q", got)
	}
}

func TestFIPSActivated_SelectorsNeverYieldUnapproved(t *testing.T) {
	withFIPSActivation(t, true)

	if got := GetKDF(); got != KDFPBKDF2 {
		t.Errorf("GetKDF under FIPS = %q, want %q", got, KDFPBKDF2)
	}
	if got := GetKDFWithDefault(KDFArgon2id); got != KDFPBKDF2 {
		t.Errorf("GetKDFWithDefault(argon2id) under FIPS = %q, want %q", got, KDFPBKDF2)
	}
	// The selector must not hand back what the validator would reject, or the
	// two disagree and the caller's choice of helper decides the posture.
	got := GetHashWithDefault(HashSHA1)
	if got == HashSHA1 {
		t.Fatal("GetHashWithDefault returned SHA-1 under FIPS")
	}
	if err := ValidateHash(got); err != nil {
		t.Errorf("selector returned %q which the validator rejects: %v", got, err)
	}
}

func TestValidateKeyslot(t *testing.T) {
	t.Run("activated refuses either half", func(t *testing.T) {
		withFIPSActivation(t, true)

		if err := ValidateKeyslot(KDFArgon2id, HashSHA256); err == nil {
			t.Error("an unapproved KDF must be refused")
		}
		if err := ValidateKeyslot(KDFPBKDF2, HashSHA1); err == nil {
			t.Error("an unapproved hash must be refused")
		}
		if err := ValidateKeyslot(KDFPBKDF2, HashSHA256); err != nil {
			t.Errorf("an approved pair must be accepted: %v", err)
		}
		// Empty means "platform default", which is FIPS-safe by construction.
		if err := ValidateKeyslot("", ""); err != nil {
			t.Errorf("defaults must be accepted: %v", err)
		}
	})

	t.Run("unknown values refused in every mode", func(t *testing.T) {
		withFIPSActivation(t, false)

		var unknownKDF ErrUnknownKDF
		if err := ValidateKeyslot("scrypt", ""); !errors.As(err, &unknownKDF) {
			t.Errorf("expected ErrUnknownKDF, got %v", err)
		}
		var unknownHash ErrUnknownHash
		if err := ValidateKeyslot("", "md5"); !errors.As(err, &unknownHash) {
			t.Errorf("expected ErrUnknownHash, got %v", err)
		}
	})
}

// TestValidateForMode covers the explicit-activation variants the installer
// needs. Without them a caller gating on `config.FIPS || IsEnabled()` would
// delegate to validators consulting only IsEnabled(), so a config-only --fips
// run would let SHA-1 through while a FIPS kernel refused it — the
// inconsistency the local review caught.
func TestValidateForMode(t *testing.T) {
	// Pin the ambient state to OFF so these assertions are driven purely by the
	// explicit argument; otherwise the test would pass for the wrong reason on
	// a FIPS-activated host.
	withFIPSActivation(t, false)

	t.Run("active refuses even when the kernel is not", func(t *testing.T) {
		if err := ValidateHashForMode(HashSHA1, true); err == nil {
			t.Error("SHA-1 must be refused when the caller says FIPS is active")
		}
		if err := ValidateKDFForMode(KDFArgon2id, true); err == nil {
			t.Error("argon2id must be refused when the caller says FIPS is active")
		}
		if err := ValidateKeyslotForMode(KDFPBKDF2, HashSHA1, true); err == nil {
			t.Error("ValidateKeyslotForMode must refuse an unapproved hash")
		}
	})

	t.Run("inactive permits", func(t *testing.T) {
		if err := ValidateHashForMode(HashSHA1, false); err != nil {
			t.Errorf("SHA-1 must remain usable outside FIPS: %v", err)
		}
		if err := ValidateKDFForMode(KDFArgon2id, false); err != nil {
			t.Errorf("argon2id must remain usable outside FIPS: %v", err)
		}
	})

	t.Run("unknown refused in either mode", func(t *testing.T) {
		for _, active := range []bool{true, false} {
			if err := ValidateKDFForMode("scrypt", active); err == nil {
				t.Errorf("unknown KDF must be refused (active=%v)", active)
			}
			if err := ValidateHashForMode("md5", active); err == nil {
				t.Errorf("unknown hash must be refused (active=%v)", active)
			}
		}
	})
}

// TestHashQualifiedPBKDF2Names covers the names go-luks2 accepts. Before this
// they fell through to ErrUnknownKDF, so a perfectly valid `pbkdf2-sha256`
// selection would have been rejected as unrecognised — a false refusal is as
// much a defect as a false accept.
func TestHashQualifiedPBKDF2Names(t *testing.T) {
	withFIPSActivation(t, true)

	for _, kdf := range []string{KDFPBKDF2, KDFPBKDF2SHA256, KDFPBKDF2SHA384, KDFPBKDF2SHA512} {
		if err := ValidateKDF(kdf); err != nil {
			t.Errorf("%q is FIPS-approved and must be accepted: %v", kdf, err)
		}
	}

	// PBKDF2 is approved; SHA-1 as its PRF is not.
	err := ValidateKDF(KDFPBKDF2SHA1)
	if err == nil {
		t.Fatal("pbkdf2-sha1 must be refused under FIPS — the PRF is SHA-1")
	}
	var typed ErrKDFNotApproved
	if !errors.As(err, &typed) {
		t.Errorf("expected ErrKDFNotApproved, got %T: %v", err, err)
	}
}

// TestUnknownKDFIsDistinctFromUnapproved is what lets the installer tell a typo
// apart from a documented Argon2 override. Collapsing them meant `pbkdf: pbkdf2x`
// was silently rewritten to pbkdf2 instead of failing.
func TestUnknownKDFIsDistinctFromUnapproved(t *testing.T) {
	withFIPSActivation(t, true)

	var notApproved ErrKDFNotApproved
	var unknown ErrUnknownKDF

	if err := ValidateKDF(KDFArgon2id); !errors.As(err, &notApproved) {
		t.Errorf("argon2id must yield ErrKDFNotApproved, got %T", err)
	}
	if err := ValidateKDF("pbkdf2x"); !errors.As(err, &unknown) {
		t.Errorf("a typo must yield ErrUnknownKDF, got %T", err)
	}
	if err := ValidateKDF("pbkdf2x"); errors.As(err, &notApproved) {
		t.Error("a typo must NOT be mistaken for an unapproved-algorithm request")
	}
}

// TestResolveKeyslotPolicy covers the exported policy every LUKS entry point
// now shares. The regression it guards: go-luks2 defaults an unset KDF to
// argon2id and does not read /proc itself, so leaving the value empty on a
// FIPS-activated host silently produced a non-approved keyslot.
func TestResolveKeyslotPolicy(t *testing.T) {
	t.Run("activated resolves empty away from the library default", func(t *testing.T) {
		withFIPSActivation(t, true)

		kdf, hash := "", ""
		if err := ResolveKeyslotPolicy(&kdf, &hash); err != nil {
			t.Fatalf("empty values must resolve, not fail: %v", err)
		}
		if kdf != KDFPBKDF2 {
			t.Errorf("empty KDF must resolve to %q (NOT be left for go-luks2 to default to argon2id), got %q",
				KDFPBKDF2, kdf)
		}
		if hash == "" {
			t.Error("hash must be pinned rather than left to a library default")
		}
		if err := ValidateKeyslot(kdf, hash); err != nil {
			t.Errorf("resolved values must themselves validate: %v", err)
		}
	})

	t.Run("activated refuses unapproved explicit values", func(t *testing.T) {
		withFIPSActivation(t, true)

		kdf, hash := KDFArgon2id, ""
		if err := ResolveKeyslotPolicy(&kdf, &hash); err == nil {
			t.Error("argon2id must be refused, not silently resolved")
		}
		kdf, hash = KDFPBKDF2SHA1, ""
		if err := ResolveKeyslotPolicy(&kdf, &hash); err == nil {
			t.Error("pbkdf2-sha1 must be refused — the PRF is SHA-1")
		}
	})

	t.Run("inactive leaves everything untouched", func(t *testing.T) {
		withFIPSActivation(t, false)

		kdf, hash := "", ""
		if err := ResolveKeyslotPolicy(&kdf, &hash); err != nil {
			t.Fatalf("unexpected error outside FIPS: %v", err)
		}
		if kdf != "" || hash != "" {
			t.Errorf("outside FIPS nothing may change, got kdf=%q hash=%q", kdf, hash)
		}
		kdf = KDFArgon2id
		if err := ResolveKeyslotPolicy(&kdf, &hash); err != nil {
			t.Errorf("argon2id must remain usable outside FIPS: %v", err)
		}
		if kdf != KDFArgon2id {
			t.Errorf("outside FIPS an explicit KDF must be preserved, got %q", kdf)
		}
	})
}

// TestResolveKeyslotPolicy_PreservesQualifiedPRF is the regression test for a
// bug this policy introduced: pinning the hash whenever it was empty meant a
// caller selecting pbkdf2-sha512 (which carries its own PRF) had Hash filled
// with sha256, and go-luks2 treats a non-empty hash option as an OVERRIDE — so
// the keyslot silently got SHA-256 instead of the SHA-512 that was asked for.
func TestResolveKeyslotPolicy_PreservesQualifiedPRF(t *testing.T) {
	withFIPSActivation(t, true)

	for _, kdf := range []string{KDFPBKDF2SHA256, KDFPBKDF2SHA512} {
		t.Run(kdf, func(t *testing.T) {
			k, h := kdf, ""
			if err := ResolveKeyslotPolicy(&k, &h); err != nil {
				t.Fatalf("approved qualified KDF rejected: %v", err)
			}
			if k != kdf {
				t.Errorf("KDF must be preserved: %q became %q", kdf, k)
			}
			// The PRF must be resolved EXPLICITLY. Leaving it empty does not
			// work: go-luks2's Format fills an empty HashAlgo with sha256
			// before CreateKDF, and a non-empty HashAlgo takes precedence over
			// the suffix — so an empty hash silently yields a SHA-256 keyslot
			// for pbkdf2-sha512.
			want := map[string]string{
				KDFPBKDF2SHA256: HashSHA256,
				KDFPBKDF2SHA512: HashSHA512,
			}[kdf]
			if h != want {
				t.Errorf("PRF for %q = %q, want %q — otherwise the keyslot is silently created with the wrong digest", kdf, h, want)
			}
		})
	}

	// The unqualified name has no PRF of its own, so it still gets one pinned.
	k, h := KDFPBKDF2, ""
	if err := ResolveKeyslotPolicy(&k, &h); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h == "" {
		t.Error("plain pbkdf2 carries no PRF, so the hash must be pinned")
	}
}

// TestPRFForKDF documents and pins the mapping the keyslot policy depends on.
//
// This exists because the naive readings both fail: go-luks2's Format fills an
// empty HashAlgo with sha256 BEFORE CreateKDF, and getHashAlgoForKDFType gives
// a non-empty HashAlgo precedence over the KDF suffix. So leaving the hash empty
// AND filling it with sha256 both produce a SHA-256 keyslot, even when the
// caller asked for pbkdf2-sha512. Resolving the suffix ourselves is the only
// approach that does not depend on the library's defaulting order.
func TestPRFForKDF(t *testing.T) {
	cases := map[string]string{
		KDFPBKDF2SHA256: HashSHA256,
		KDFPBKDF2SHA384: HashSHA384,
		KDFPBKDF2SHA512: HashSHA512,
		KDFPBKDF2:       DefaultHash, // unqualified carries no PRF of its own
		"":              DefaultHash,
	}
	for kdf, want := range cases {
		if got := prfForKDF(kdf); got != want {
			t.Errorf("prfForKDF(%q) = %q, want %q", kdf, got, want)
		}
	}
}

// TestFormatVsAddKeyPolicies pins the distinction the seventh review round
// surfaced: the two LUKS paths are NOT the same rule, and treating them alike
// broke valid enrollments.
//
//   - FORMAT: FormatOptions.HashAlgo is shared with the anti-forensic splitter,
//     whose getHashFunc accepts only sha256/sha512. SHA-384 therefore fails at
//     format time, and a hash-qualified alias is unreliable because Format fills
//     an empty HashAlgo with sha256 before CreateKDF and gives it precedence
//     over the suffix.
//   - ADD-KEY: AddKeyOptions.Hash is ONLY the PBKDF2 PRF; go-luks2's AddKey
//     calls AFSplit with its own DefaultHashAlgo, so SHA-384 is perfectly
//     usable and must not be refused.
func TestFormatVsAddKeyPolicies(t *testing.T) {
	withFIPSActivation(t, true)

	t.Run("format refuses sha384", func(t *testing.T) {
		kdf, hash := KDFPBKDF2, HashSHA384
		err := ResolveFormatKeyslotPolicy(&kdf, &hash)
		var typed ErrHashUnsupportedByLUKS
		if !errors.As(err, &typed) {
			t.Fatalf("expected ErrHashUnsupportedByLUKS on the format path, got %T: %v", err, err)
		}
	})

	t.Run("add-key ACCEPTS sha384", func(t *testing.T) {
		// The regression: applying the format constraint here rejected valid
		// FIPS-approved enrollments.
		kdf, hash := KDFPBKDF2, HashSHA384
		if err := ResolveKeyslotPolicy(&kdf, &hash); err != nil {
			t.Fatalf("SHA-384 is a valid PBKDF2 PRF on the add-key path: %v", err)
		}
		if hash != HashSHA384 {
			t.Errorf("the requested PRF must be preserved, got %q", hash)
		}
	})

	t.Run("format TRANSLATES qualified aliases", func(t *testing.T) {
		// Refusing these regressed pbkdf2-sha256, which already worked because
		// go-luks2's default digest happened to match. Translating to plain
		// pbkdf2 plus an explicit digest keeps that working AND makes
		// pbkdf2-sha512 actually produce SHA-512 instead of silently
		// downgrading to the default.
		for _, tc := range []struct{ alias, wantHash string }{
			{KDFPBKDF2SHA256, HashSHA256},
			{KDFPBKDF2SHA512, HashSHA512},
		} {
			kdf, hash := tc.alias, ""
			if err := ResolveFormatKeyslotPolicy(&kdf, &hash); err != nil {
				t.Fatalf("%s must translate, not fail: %v", tc.alias, err)
			}
			if kdf != KDFPBKDF2 {
				t.Errorf("%s: KDF = %q, want %q", tc.alias, kdf, KDFPBKDF2)
			}
			if hash != tc.wantHash {
				t.Errorf("%s: digest = %q, want %q — otherwise go-luks2 silently uses its default",
					tc.alias, hash, tc.wantHash)
			}
		}
	})

	t.Run("format refuses a contradictory alias/hash pair", func(t *testing.T) {
		kdf, hash := KDFPBKDF2SHA512, HashSHA256
		err := ResolveFormatKeyslotPolicy(&kdf, &hash)
		var typed ErrQualifiedKDFHashConflict
		if !errors.As(err, &typed) {
			t.Fatalf("expected ErrQualifiedKDFHashConflict, got %T: %v", err, err)
		}
	})

	t.Run("format still refuses an alias implying an unusable digest", func(t *testing.T) {
		kdf, hash := KDFPBKDF2SHA384, ""
		err := ResolveFormatKeyslotPolicy(&kdf, &hash)
		var typed ErrHashUnsupportedByLUKS
		if !errors.As(err, &typed) {
			t.Fatalf("pbkdf2-sha384 implies a digest AFSplit cannot use; got %T: %v", err, err)
		}
	})

	t.Run("add-key accepts qualified aliases", func(t *testing.T) {
		kdf, hash := KDFPBKDF2SHA512, ""
		if err := ResolveKeyslotPolicy(&kdf, &hash); err != nil {
			t.Fatalf("qualified alias must work on the add-key path: %v", err)
		}
		if hash != HashSHA512 {
			t.Errorf("PRF must resolve to %q, got %q", HashSHA512, hash)
		}
	})

	t.Run("format still resolves the plain default", func(t *testing.T) {
		kdf, hash := "", ""
		if err := ResolveFormatKeyslotPolicy(&kdf, &hash); err != nil {
			t.Fatalf("defaults must resolve on the format path: %v", err)
		}
		if kdf != KDFPBKDF2 {
			t.Errorf("empty KDF must resolve to %q, got %q", KDFPBKDF2, kdf)
		}
		if !luksDigestSupported(hash) {
			t.Errorf("resolved format digest %q must be LUKS-usable", hash)
		}
	})
}

// TestSelectorsAgreeWithValidators is the invariant behind two separate
// findings in this change's review history: a SELECTOR must never hand back a
// value its VALIDATOR would reject. Each helper was originally written with its
// own hand-maintained list of bad algorithms, and each list fell out of date
// when a new alias was added — GetHashWithDefault first, then
// GetKDFWithDefault with pbkdf2-sha1.
//
// Enumerating every recognised algorithm here means the next alias added to the
// validator is checked against every selector automatically.
func TestSelectorsAgreeWithValidators(t *testing.T) {
	withFIPSActivation(t, true)

	kdfs := []string{
		KDFPBKDF2, KDFPBKDF2SHA1, KDFPBKDF2SHA256, KDFPBKDF2SHA384, KDFPBKDF2SHA512,
		KDFArgon2id, KDFArgon2i,
	}
	for _, kdf := range kdfs {
		got := GetKDFWithDefault(kdf)
		if err := ValidateKDF(got); err != nil {
			t.Errorf("GetKDFWithDefault(%q) returned %q, which ValidateKDF rejects: %v", kdf, got, err)
		}
	}

	hashes := []string{HashSHA1, HashSHA256, HashSHA384, HashSHA512}
	for _, h := range hashes {
		got := GetHashWithDefault(h)
		if err := ValidateHash(got); err != nil {
			t.Errorf("GetHashWithDefault(%q) returned %q, which ValidateHash rejects: %v", h, got, err)
		}
	}

	// Specifically the alias that slipped through.
	if got := GetKDFWithDefault(KDFPBKDF2SHA1); got == KDFPBKDF2SHA1 {
		t.Error("pbkdf2-sha1 must not be returned by the selector under FIPS")
	}
}

// TestAlgorithmNamesAreNormalized guards a NON-FIPS regression: go-luks2
// normalises algorithm names with ToLower+TrimSpace, so it has always accepted
// "ARGON2ID" and " sha512 ". A case-sensitive switch in this package rejected
// them as unknown even with FIPS off, changing behaviour for existing
// deployments — which this change is explicitly not allowed to do.
func TestAlgorithmNamesAreNormalized(t *testing.T) {
	withFIPSActivation(t, false)

	for _, kdf := range []string{"ARGON2ID", "Argon2id", " argon2id ", "PBKDF2"} {
		if err := ValidateKDF(kdf); err != nil {
			t.Errorf("ValidateKDF(%q) must accept what go-luks2 accepts: %v", kdf, err)
		}
	}
	for _, h := range []string{"SHA512", "Sha256", " sha384 "} {
		if err := ValidateHash(h); err != nil {
			t.Errorf("ValidateHash(%q) must accept what go-luks2 accepts: %v", h, err)
		}
	}

	// Normalisation must not smuggle an unapproved value past FIPS either.
	withFIPSActivation(t, true)
	for _, h := range []string{"SHA1", " sha1 "} {
		if err := ValidateHash(h); err == nil {
			t.Errorf("ValidateHash(%q) must still be refused under FIPS", h)
		}
	}
	for _, kdf := range []string{"ARGON2ID", " Argon2i "} {
		if err := ValidateKDF(kdf); err == nil {
			t.Errorf("ValidateKDF(%q) must still be refused under FIPS", kdf)
		}
	}
}

// TestFormatErrorsAreAccurate pins the ordering: FIPS validation runs before the
// narrower LUKS rules, so a caller gets the error that actually describes the
// problem. Previously SHA-1 on the format path returned
// ErrHashUnsupportedByLUKS, whose message says the hash IS FIPS-approved —
// exactly backwards.
func TestFormatErrorsAreAccurate(t *testing.T) {
	withFIPSActivation(t, true)

	kdf, hash := KDFPBKDF2, HashSHA1
	err := ResolveFormatKeyslotPolicy(&kdf, &hash)
	var notApproved ErrHashNotApproved
	if !errors.As(err, &notApproved) {
		t.Fatalf("SHA-1 on the format path must report ErrHashNotApproved, got %T: %v", err, err)
	}

	kdf, hash = KDFArgon2id, ""
	err = ResolveFormatKeyslotPolicy(&kdf, &hash)
	var kdfNotApproved ErrKDFNotApproved
	if !errors.As(err, &kdfNotApproved) {
		t.Errorf("argon2id on the format path must report ErrKDFNotApproved, got %T: %v", err, err)
	}

	kdf, hash = "scrypt", ""
	err = ResolveFormatKeyslotPolicy(&kdf, &hash)
	var unknown ErrUnknownKDF
	if !errors.As(err, &unknown) {
		t.Errorf("an unknown KDF must report ErrUnknownKDF, got %T: %v", err, err)
	}
}

// TestUnapprovedErrorsCarryNormalizedNames pins the contract the installer's
// documented Argon2 substitution depends on.
//
// After normalisation was added, ErrKDFNotApproved still carried the operator's
// original spelling, so a consumer comparing against the package constants
// (as the installer does, to decide substitute-vs-reject) took the wrong branch
// for "Argon2id". A recognised-but-unapproved algorithm now reports its
// canonical name; an UNKNOWN one keeps the original so a typo is echoed back
// verbatim.
func TestUnapprovedErrorsCarryNormalizedNames(t *testing.T) {
	withFIPSActivation(t, true)

	for _, spelling := range []string{"Argon2id", " ARGON2ID ", "argon2id"} {
		var typed ErrKDFNotApproved
		if !errors.As(ValidateKDF(spelling), &typed) {
			t.Fatalf("%q must be recognised as unapproved", spelling)
		}
		if typed.KDF != KDFArgon2id {
			t.Errorf("error for %q carries KDF=%q, want the canonical %q — the installer compares against the constant",
				spelling, typed.KDF, KDFArgon2id)
		}
	}

	var hashTyped ErrHashNotApproved
	if !errors.As(ValidateHash(" SHA1 "), &hashTyped) {
		t.Fatal("SHA-1 must be recognised as unapproved regardless of spelling")
	}
	if hashTyped.Hash != HashSHA1 {
		t.Errorf("error carries Hash=%q, want canonical %q", hashTyped.Hash, HashSHA1)
	}

	// A typo is NOT normalised away — the operator should see what they typed.
	var unknown ErrUnknownKDF
	if !errors.As(ValidateKDF("Argon2idd"), &unknown) {
		t.Fatal("a typo must be ErrUnknownKDF")
	}
	if unknown.KDF != "Argon2idd" {
		t.Errorf("unknown KDF must echo the original text, got %q", unknown.KDF)
	}
}

// TestDetectionFailsClosed covers the second hosted-review finding: a
// compliance control must not answer "not FIPS" when it cannot tell.
//
// The original IsEnabled turned ANY read error into false, so a permission
// problem, a transient I/O error, or malformed contents silently disabled every
// keyslot restriction downstream — the exact fail-open shape this whole issue
// exists to remove.
func TestDetectionFailsClosed(t *testing.T) {
	t.Run("absent indicator is genuinely not FIPS", func(t *testing.T) {
		// The normal case on a non-FIPS kernel — it must NOT fail closed, or
		// every ordinary machine would suddenly enforce FIPS restrictions.
		dir := t.TempDir()
		original := fipsIndicatorPath
		fipsIndicatorPath = filepath.Join(dir, "does-not-exist")
		t.Cleanup(func() { fipsIndicatorPath = original })

		active, err := DetectActivation()
		if err != nil {
			t.Errorf("an absent indicator is normal, not an error: %v", err)
		}
		if active {
			t.Error("an absent indicator must report not-activated")
		}
		if IsEnabled() {
			t.Error("IsEnabled must be false when the indicator is simply absent")
		}
	})

	t.Run("unreadable indicator fails closed", func(t *testing.T) {
		// A DIRECTORY, not a chmod-000 file. Permission bits do not restrict
		// root, so a 0o000 file forced a skip guard — and CI containers
		// commonly run as root, meaning the fail-closed path would never be
		// exercised in the environment that matters. This project forbids skip
		// guards outright, and rightly: the guard was hiding the gap rather
		// than reporting it. Reading a directory returns EISDIR for every user,
		// so this runs everywhere.
		path := t.TempDir()
		original := fipsIndicatorPath
		fipsIndicatorPath = path
		t.Cleanup(func() { fipsIndicatorPath = original })

		_, err := DetectActivation()
		if err == nil {
			t.Fatal("an unreadable indicator must surface an error, not report not-activated")
		}
		var unreadable ErrFIPSIndicatorUnreadable
		if !errors.As(err, &unreadable) {
			t.Errorf("expected ErrFIPSIndicatorUnreadable, got %T: %v", err, err)
		}
		if !IsEnabled() {
			t.Error("IsEnabled must FAIL CLOSED when it cannot read the indicator")
		}
	})

	t.Run("malformed indicator fails closed", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "fips_enabled")
		if err := os.WriteFile(path, []byte("banana\n"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		original := fipsIndicatorPath
		fipsIndicatorPath = path
		t.Cleanup(func() { fipsIndicatorPath = original })

		var malformed ErrFIPSIndicatorMalformed
		_, err := DetectActivation()
		if !errors.As(err, &malformed) {
			t.Fatalf("expected ErrFIPSIndicatorMalformed, got %T: %v", err, err)
		}
		if !IsEnabled() {
			t.Error("unrecognised contents must FAIL CLOSED, not silently select non-FIPS")
		}
	})
}

// TestLUKSDigestsIsImmutable guards a security-relevant API property: the
// enforced digest policy must not be alterable by a consumer.
//
// It was previously an exported `var LUKSDigests []string` consulted directly
// while making the decision, so any importing package could append "sha384" and
// make ResolveFormatKeyslotPolicy accept a digest this package documents as
// failing inside AFSplit — and concurrent mutation would race.
func TestLUKSDigestsIsImmutable(t *testing.T) {
	first := LUKSDigests()
	if len(first) == 0 {
		t.Fatal("the policy list must not be empty")
	}

	// Mutate what the caller was handed, as a hostile or careless consumer
	// might. Element assignment is the case that matters: it writes through to
	// the backing array if a copy was not made. (append is not tested here —
	// it would allocate a new slice and prove nothing about the original.)
	first[0] = "sha384"

	second := LUKSDigests()
	for _, bad := range []string{"sha384"} {
		for _, got := range second {
			if got == bad {
				t.Fatalf("caller mutation leaked into the policy: %q is now listed", bad)
			}
		}
	}

	// And the decision itself must be unaffected.
	if err := ValidateLUKSFormatDigest(HashSHA384); err == nil {
		t.Error("SHA-384 must still be refused as a LUKS format digest after caller mutation")
	}
	if err := ValidateLUKSFormatDigest(HashSHA256); err != nil {
		t.Errorf("SHA-256 must remain usable: %v", err)
	}
}
