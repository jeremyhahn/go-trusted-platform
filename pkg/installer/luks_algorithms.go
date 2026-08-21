// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package installer

import (
	"errors"

	"github.com/jeremyhahn/go-trusted-platform/pkg/fips"
)

// resolveLUKSAlgorithms decides the KDF and hash a LUKS container is formatted
// with, applying the installer's FIPS policy.
//
// It returns the chosen kdf and hash, plus substituted — non-empty when an
// operator-selected KDF was overridden, so the caller can say so out loud.
//
// Extracted from SetupLUKS deliberately: the decision used to sit inline in a
// long function that partitions and formats real disks, so none of this
// behaviour could be tested without hardware. That is why the gaps it now
// closes went unnoticed.
func resolveLUKSAlgorithms(config *EncryptionConfig) (kdf, hash, substituted string, err error) {
	hash = "sha256"
	if config.Hash != "" {
		hash = config.Hash
	}

	// ONE effective FIPS mode, computed once and used for every decision below.
	// The installer treats --fips as activating even on a non-FIPS kernel, so
	// every check must consult this rather than fips.IsEnabled() directly —
	// mixing the two applies the restriction inconsistently, and a config-only
	// --fips run would let SHA-1 through while a FIPS kernel rejected it.
	fipsActive := config.FIPS || fips.IsEnabled()

	kdf = config.PBKDF
	switch {
	case kdf == "" && fipsActive:
		kdf = fips.KDFPBKDF2
	case kdf == "":
		kdf = fips.DefaultKDF // argon2id
	default:
		if vErr := fips.ValidateKDFForMode(kdf, fipsActive); vErr != nil {
			// ONLY the documented Argon2 override is substituted
			// (docs/installer/cli.md: --fips "forces PBKDF2 over Argon2id").
			// Everything else propagates: a typo must surface as a config
			// error, and pbkdf2-sha1 — also ErrKDFNotApproved — must be
			// REFUSED rather than quietly rewritten, since nothing documents
			// silently swapping a caller's chosen PRF.
			var notApproved fips.ErrKDFNotApproved
			if !errors.As(vErr, &notApproved) {
				return "", "", "", ErrEncryption("LUKS KDF invalid", vErr)
			}
			if notApproved.KDF != fips.KDFArgon2id && notApproved.KDF != fips.KDFArgon2i {
				return "", "", "", ErrEncryption("LUKS KDF rejected under FIPS", vErr)
			}
			substituted = kdf
			kdf = fips.KDFPBKDF2
		}
	}

	// The hash is operator-supplied on the same path and reached LUKS unchecked.
	// Unlike the KDF there is no documented forcing behaviour for it, and
	// silently rewriting a hash is not something --fips promises, so an
	// unapproved selection is REFUSED with the typed error.
	if hErr := fips.ValidateHashForMode(hash, fipsActive); hErr != nil {
		return "", "", "", ErrEncryption("LUKS hash rejected under FIPS", hErr)
	}

	// SetupLUKS is a FORMAT path, so the narrower LUKS constraint applies too:
	// FormatOptions.HashAlgo is shared with go-luks2's anti-forensic splitter,
	// which supports only sha256/sha512. Checking only FIPS approval let
	// sha384 — approved, but unusable here — through to abort the install
	// inside AFSplit with an opaque error. Unconditional, because the
	// limitation is the library's and applies in every mode.
	if dErr := fips.ValidateLUKSFormatDigest(hash); dErr != nil {
		return "", "", "", ErrEncryption("LUKS hash unusable for formatting", dErr)
	}

	return kdf, hash, substituted, nil
}
