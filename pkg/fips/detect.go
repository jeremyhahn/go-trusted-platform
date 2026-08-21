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

package fips

import (
	"errors"
	"io/fs"
	"os"
	"strings"
)

// Supported KDF types
const (
	KDFPBKDF2 = "pbkdf2"
	// go-luks2 also accepts hash-qualified PBKDF2 names. They are recognised
	// here so a valid selection is not rejected as unknown; pbkdf2-sha1 is
	// PBKDF2 with a SHA-1 PRF and is NOT approved.
	KDFPBKDF2SHA1   = "pbkdf2-sha1"
	KDFPBKDF2SHA256 = "pbkdf2-sha256"
	KDFPBKDF2SHA384 = "pbkdf2-sha384"
	KDFPBKDF2SHA512 = "pbkdf2-sha512"
	KDFArgon2id     = "argon2id"
	KDFArgon2i      = "argon2i"
)

// Supported hash algorithms for PBKDF2
const (
	HashSHA256 = "sha256"
	HashSHA512 = "sha512"
	HashSHA384 = "sha384"
	// HashSHA1 is accepted by LUKS2 and therefore selectable, but it is NOT
	// FIPS 140-3 approved. ValidateHash refuses it whenever the kernel is
	// FIPS-activated.
	HashSHA1 = "sha1"
)

// Default values
const (
	DefaultHash    = HashSHA256
	DefaultKDFFIPS = KDFPBKDF2
	DefaultKDF     = KDFArgon2id
)

// fipsIndicatorPath is the kernel's FIPS indicator.
//
// It is a package-level variable rather than a literal ONLY so that this
// package's own tests can point it at a fixture and exercise both modes —
// before this, no test could cover FIPS-activated behaviour at all, which is
// why the restrictions were never verified. It is deliberately NOT settable
// from outside the package and NOT overridable by environment: a security
// control that an env var can switch off is not a control.
var fipsIndicatorPath = "/proc/sys/crypto/fips_enabled"

// IsEnabled checks if the kernel is running in FIPS mode by reading
// /proc/sys/crypto/fips_enabled. Returns true if FIPS mode is enabled.
//
// This is the standard way to detect FIPS mode at runtime:
// - The kernel sets this to "1" when booted with fips=1 kernel parameter
// - If the file doesn't exist or contains "0", FIPS mode is disabled
func IsEnabled() bool {
	active, err := DetectActivation()
	if err != nil {
		// FAIL CLOSED. Any error other than "the indicator is absent" means we
		// could not determine the kernel's state, and a compliance control that
		// answers "not FIPS" when it does not know is fail-open: a permission
		// or transient I/O error would silently disable every keyslot
		// restriction downstream. Assuming activation is the safe direction —
		// it restricts algorithms rather than permitting them.
		return true
	}
	return active
}

// DetectActivation reports whether the kernel is FIPS-activated, distinguishing
// "definitely not activated" from "could not tell".
//
// An ABSENT indicator is the normal case on a non-FIPS kernel and is reported
// as (false, nil). Any other read failure, or contents that are neither "0" nor
// "1", return an error — callers that can surface it should, and IsEnabled
// treats it as activation.
func DetectActivation() (bool, error) {
	data, err := os.ReadFile(fipsIndicatorPath)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, ErrFIPSIndicatorUnreadable{Path: fipsIndicatorPath, Cause: err}
	}
	switch strings.TrimSpace(string(data)) {
	case "1":
		return true, nil
	case "0":
		return false, nil
	default:
		return false, ErrFIPSIndicatorMalformed{Path: fipsIndicatorPath, Contents: strings.TrimSpace(string(data))}
	}
}

// GetKDF returns the appropriate KDF algorithm based on FIPS mode.
// Returns "pbkdf2" if FIPS is enabled, "argon2id" otherwise.
//
// FIPS 140-3 does not approve Argon2id, so PBKDF2 must be used
// for all key derivation operations in FIPS mode.
func GetKDF() string {
	if IsEnabled() {
		return DefaultKDFFIPS
	}
	return DefaultKDF
}

// GetKDFWithDefault returns the KDF algorithm, using the provided default
// if not empty, otherwise falling back to FIPS-appropriate default.
func GetKDFWithDefault(preferred string) string {
	if preferred == "" {
		return GetKDF()
	}
	// Outside FIPS the preference passes through unchanged — existing
	// deployments must behave byte-identically.
	if !IsEnabled() {
		return preferred
	}
	// FIPS-activated: defer to the validator rather than enumerating
	// non-compliant KDFs here. Listing argon2i/argon2id by hand meant
	// pbkdf2-sha1 — added later, and unapproved for the same reason — passed
	// straight through, so a caller reaching for the selector instead of
	// ValidateKDF could still get a SHA-1 PBKDF2 keyslot. A selector must never
	// return what the validator would reject; the two disagreeing means
	// whichever helper a caller happens to use decides the security posture.
	if ValidateKDF(preferred) == nil {
		return preferred
	}
	return DefaultKDFFIPS
}

// GetHash returns the default hash algorithm.
// Returns "sha256" which is approved for both FIPS and non-FIPS modes.
func GetHash() string {
	return DefaultHash
}

// GetHashWithDefault returns the hash algorithm, using the provided preference
// when it is usable on this system and falling back to sha256 otherwise.
//
// Under FIPS activation an unapproved preference (SHA-1) is NOT returned:
// selection helpers must not hand back a value that ValidateHash would reject,
// or the two disagree and whichever the caller happens to use decides the
// outcome.
func GetHashWithDefault(preferred string) string {
	if preferred == "" {
		return DefaultHash
	}
	// Outside FIPS the preference passes through unchanged — existing
	// deployments must behave byte-identically.
	if !IsEnabled() {
		return preferred
	}
	// FIPS-activated: never hand back a value ValidateHash would reject, or the
	// selector and the validator disagree and whichever one the caller happens
	// to use decides the outcome. Callers taking operator input should call
	// ValidateHash and surface the typed error; this is the safe-default path.
	if ValidateHash(preferred) == nil {
		return preferred
	}
	return DefaultHash
}

// ApprovedHashes lists the hash algorithms accepted under FIPS activation.
// SHA-1 is deliberately absent.
var ApprovedHashes = []string{HashSHA256, HashSHA384, HashSHA512}

// ValidateKDF reports whether the given KDF may be used on this system,
// returning a typed error explaining why not.
//
// Outside FIPS every recognised KDF is permitted, so existing deployments are
// unaffected. Under FIPS activation only PBKDF2 is approved, and an Argon2
// request is REFUSED rather than quietly downgraded: substituting silently
// would hand the caller a different security posture than it asked for with no
// signal that it happened.
func ValidateKDF(kdfType string) error {
	return ValidateKDFForMode(kdfType, IsEnabled())
}

// ValidateKDFForMode is ValidateKDF against an explicitly supplied activation
// state.
//
// The installer needs this: it treats `--fips` as activating even on a
// non-FIPS kernel, so a caller that gates on `config.FIPS || IsEnabled()` and
// then calls a validator that consults only IsEnabled() would apply the
// restriction inconsistently — precisely the config-only case where SHA-1 would
// otherwise slip through.
func ValidateKDFForMode(kdfType string, fipsActive bool) error {
	// Normalise exactly as go-luks2 does (ToLower + TrimSpace). Without this a
	// case-sensitive switch rejects "ARGON2ID" as unknown EVEN WITH FIPS OFF —
	// a regression in non-FIPS behaviour, which this change must not have,
	// since go-luks2 previously accepted it.
	// A RECOGNISED-but-unapproved algorithm reports its NORMALISED name, so a
	// consumer comparing against the package constants works regardless of how
	// the operator spelled it — the installer's documented Argon2 substitution
	// depends on that. An UNKNOWN algorithm keeps the original text, so a typo
	// is echoed back exactly as typed.
	normalized := normalizeAlgorithm(kdfType)
	switch normalized {
	case KDFPBKDF2, KDFPBKDF2SHA256, KDFPBKDF2SHA384, KDFPBKDF2SHA512:
		return nil
	case KDFPBKDF2SHA1:
		// PBKDF2 itself is approved; SHA-1 as its PRF is not.
		if fipsActive {
			return ErrKDFNotApproved{KDF: normalized, Approved: KDFPBKDF2}
		}
		return nil
	case KDFArgon2id, KDFArgon2i:
		if fipsActive {
			return ErrKDFNotApproved{KDF: normalized, Approved: KDFPBKDF2}
		}
		return nil
	default:
		return ErrUnknownKDF{KDF: kdfType}
	}
}

// ValidateHash reports whether the given hash may be used on this system,
// returning a typed error explaining why not.
//
// LUKS2 accepts SHA-1, so it is a reachable selection that nothing else in the
// stack would reject; under FIPS activation this is where it is refused.
func ValidateHash(hash string) error {
	return ValidateHashForMode(hash, IsEnabled())
}

// ValidateHashForMode is ValidateHash against an explicitly supplied activation
// state. See ValidateKDFForMode for why the installer needs it.
func ValidateHashForMode(hash string, fipsActive bool) error {
	normalized := normalizeAlgorithm(hash)
	switch normalized {
	case HashSHA256, HashSHA384, HashSHA512:
		return nil
	case HashSHA1:
		if fipsActive {
			return ErrHashNotApproved{Hash: normalized, Approved: ApprovedHashes}
		}
		return nil
	default:
		return ErrUnknownHash{Hash: hash}
	}
}

// ValidateKeyslot checks the KDF and hash a new LUKS2 keyslot would be created
// with. It is the single entry point callers on the keyslot path should use, so
// the restriction cannot be half-applied by checking one and forgetting the
// other. Empty values mean "use the platform default" and are accepted; the
// defaults are FIPS-safe by construction (see GetKDF and GetHash).
func ValidateKeyslot(kdfType, hash string) error {
	return ValidateKeyslotForMode(kdfType, hash, IsEnabled())
}

// ValidateKeyslotForMode is ValidateKeyslot against an explicitly supplied
// activation state.
func ValidateKeyslotForMode(kdfType, hash string, fipsActive bool) error {
	if kdfType != "" {
		if err := ValidateKDFForMode(kdfType, fipsActive); err != nil {
			return err
		}
	}
	if hash != "" {
		if err := ValidateHashForMode(hash, fipsActive); err != nil {
			return err
		}
	}
	return nil
}

// ResolveKeyslotPolicy resolves the effective KDF and hash for a new LUKS2
// keyslot on the ADD-KEY path, refusing anything this system may not use and
// mutating the values in place.
//
// Resolution rather than validation is the point: go-luks2 documents an unset
// KDF as defaulting to argon2id and does not consult
// /proc/sys/crypto/fips_enabled itself, so a check that only inspected what a
// caller passed left every default path creating a non-approved keyslot on a
// FIPS-activated host.
//
// On this path the hash is ONLY the PBKDF2 PRF: go-luks2's AddKey calls
// AFSplit with its own DefaultHashAlgo (keyslot.go), so the anti-forensic
// splitter's sha256/sha512 limitation does not apply here and SHA-384 is
// usable. The format path is different and has its own function.
//
// Outside FIPS nothing is changed: empty stays empty and go-luks2's own
// defaults apply.
func ResolveKeyslotPolicy(kdfType, hash *string) error {
	active := IsEnabled()

	if active && *kdfType == "" {
		// Never leave this to the library default, which is argon2id.
		*kdfType = KDFPBKDF2
	}
	if err := ValidateKeyslotForMode(*kdfType, *hash, active); err != nil {
		return err
	}
	if active && *hash == "" {
		*hash = prfForKDF(*kdfType)
	}
	return nil
}

// ResolveFormatKeyslotPolicy is ResolveKeyslotPolicy for the FORMAT path, where
// one extra constraint applies.
//
// FormatOptions.HashAlgo is a SHARED field: go-luks2's Format feeds it to both
// the keyslot digest and AFSplit, and the splitter's getHashFunc accepts only
// sha256 and sha512. Two consequences, neither obvious:
//
//   - SHA-384 is FIPS-approved but unusable here — it fails inside AFSplit at
//     format time, so it is refused up front with an explanation.
//   - A hash-qualified KDF alias is unreliable here, because Format fills an
//     empty HashAlgo with sha256 BEFORE CreateKDF and a non-empty HashAlgo
//     takes precedence over the suffix. Rather than silently producing a
//     SHA-256 keyslot for a pbkdf2-sha512 request, the alias is refused with a
//     message naming the working alternative.
func ResolveFormatKeyslotPolicy(kdfType, hashAlgo *string) error {
	// FIPS validation FIRST, so the caller gets the accurate error. Running the
	// LUKS-specific checks first meant HashAlgo "sha1" under FIPS returned
	// ErrHashUnsupportedByLUKS — whose message says the hash is FIPS-approved
	// but unusable by LUKS, which is exactly backwards for SHA-1.
	if err := ValidateKeyslotForMode(*kdfType, *hashAlgo, IsEnabled()); err != nil {
		return err
	}

	// TRANSLATE a hash-qualified alias into plain pbkdf2 plus an explicit
	// digest, rather than refusing it.
	//
	// Format needs this because HashAlgo wins over the KDF suffix: go-luks2
	// fills an empty HashAlgo with sha256 before CreateKDF, and
	// getHashAlgoForKDFType gives a non-empty HashAlgo precedence. So
	// pbkdf2-sha512 with an empty hash silently produced a SHA-256 keyslot.
	// Setting the digest explicitly makes the request mean what it says — and
	// it keeps pbkdf2-sha256 working, which already did because the default
	// happened to match.
	if prf := impliedPRF(*kdfType); prf != "" {
		switch {
		case *hashAlgo == "":
			*hashAlgo = prf
			*kdfType = KDFPBKDF2
		case normalizeAlgorithm(*hashAlgo) == prf:
			// Consistent; collapse to the plain name so the suffix cannot be
			// second-guessed downstream.
			*kdfType = KDFPBKDF2
		default:
			// The alias and the explicit digest disagree. go-luks2 would
			// silently honour HashAlgo, so the caller would get a PRF it did
			// not ask for; refuse instead of picking one.
			return ErrQualifiedKDFHashConflict{KDF: *kdfType, Hash: *hashAlgo, ImpliedPRF: prf}
		}
	}

	// FormatOptions.HashAlgo is shared with the anti-forensic splitter, which
	// supports only sha256/sha512 — so SHA-384 is FIPS-approved yet unusable
	// here, and would otherwise fail deep inside AFSplit.
	if *hashAlgo != "" && !luksDigestSupported(*hashAlgo) {
		return ErrHashUnsupportedByLUKS{Hash: *hashAlgo, Supported: LUKSDigests()}
	}

	if err := ResolveKeyslotPolicy(kdfType, hashAlgo); err != nil {
		return err
	}
	if *hashAlgo != "" && !luksDigestSupported(*hashAlgo) {
		return ErrHashUnsupportedByLUKS{Hash: *hashAlgo, Supported: LUKSDigests()}
	}
	return nil
}

// impliedPRF returns the digest a hash-qualified PBKDF2 alias names, or "" if
// the KDF is not such an alias.
func impliedPRF(kdfType string) string {
	switch normalizeAlgorithm(kdfType) {
	case KDFPBKDF2SHA1:
		return HashSHA1
	case KDFPBKDF2SHA256:
		return HashSHA256
	case KDFPBKDF2SHA384:
		return HashSHA384
	case KDFPBKDF2SHA512:
		return HashSHA512
	default:
		return ""
	}
}

// normalizeAlgorithm canonicalises an algorithm name the way go-luks2 does, so
// this package accepts exactly what the library would.
func normalizeAlgorithm(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// luksDigests are the digests usable as a LUKS2 FORMAT digest. Narrower than
// ApprovedHashes because go-luks2's anti-forensic splitter shares that field and
// supports only these two.
//
// UNEXPORTED deliberately. An exported slice is mutable by any importing
// package, and this one is consulted while making a security decision — a
// consumer appending "sha384" would make ResolveFormatKeyslotPolicy accept a
// digest this package documents as failing inside AFSplit, and concurrent
// mutation would race. Use LUKSDigests() for a copy.
var luksDigests = [...]string{HashSHA256, HashSHA512}

// LUKSDigests returns the digests usable as a LUKS2 format digest. It returns a
// fresh copy each call, so a caller cannot alter the enforced policy.
func LUKSDigests() []string {
	out := make([]string, len(luksDigests))
	copy(out, luksDigests[:])
	return out
}

// ValidateLUKSFormatDigest reports whether a digest can be used as a LUKS2
// FORMAT digest, which is narrower than FIPS approval.
//
// FormatOptions.HashAlgo is shared with go-luks2's anti-forensic splitter, and
// getHashFunc there accepts only sha256/sha512. SHA-384 is FIPS-approved yet
// aborts formatting inside AFSplit, so callers on a format path must check this
// IN ADDITION to ValidateHash. The constraint is the library's, not FIPS's, and
// applies in every mode — a non-FIPS install with sha384 fails just as hard,
// only with a more opaque message.
func ValidateLUKSFormatDigest(hash string) error {
	if hash == "" || luksDigestSupported(hash) {
		return nil
	}
	return ErrHashUnsupportedByLUKS{Hash: hash, Supported: LUKSDigests()}
}

func luksDigestSupported(hash string) bool {
	n := normalizeAlgorithm(hash)
	for _, h := range luksDigests {
		if h == n {
			return true
		}
	}
	return false
}

// prfForKDF returns the digest a PBKDF2 KDF name implies. Unqualified "pbkdf2"
// carries no PRF of its own and takes the platform default.
func prfForKDF(kdfType string) string {
	switch normalizeAlgorithm(kdfType) {
	case KDFPBKDF2SHA256:
		return HashSHA256
	case KDFPBKDF2SHA384:
		return HashSHA384
	case KDFPBKDF2SHA512:
		return HashSHA512
	default:
		return GetHash()
	}
}
