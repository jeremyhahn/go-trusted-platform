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

import "fmt"

// ErrKDFNotApproved reports a key-derivation function that FIPS 140-3 does not
// approve, requested while the kernel is FIPS-activated.
//
// Argon2id is the case this exists for: it is the platform's default OUTSIDE
// FIPS and stays that way, but it has no FIPS approval. An activated system
// refuses it rather than silently substituting PBKDF2 — a caller that asked for
// argon2id and got pbkdf2 keyslots without being told has a different security
// posture than the one it requested, and no way to know.
type ErrKDFNotApproved struct {
	// KDF is the requested key-derivation function.
	KDF string
	// Approved is the KDF this platform accepts under FIPS activation.
	Approved string
}

func (e ErrKDFNotApproved) Error() string {
	return fmt.Sprintf(
		"fips: key-derivation function %q is not FIPS 140-3 approved; this system is FIPS-activated and accepts %q",
		e.KDF, e.Approved)
}

// ErrHashNotApproved reports a hash algorithm that FIPS 140-3 does not approve,
// requested while the kernel is FIPS-activated.
//
// SHA-1 is the case this exists for. LUKS2 accepts it, so it is a reachable
// selection, and nothing else in the stack would reject it.
type ErrHashNotApproved struct {
	// Hash is the requested hash algorithm.
	Hash string
	// Approved lists the algorithms accepted under FIPS activation.
	Approved []string
}

func (e ErrHashNotApproved) Error() string {
	return fmt.Sprintf(
		"fips: hash algorithm %q is not FIPS 140-3 approved; this system is FIPS-activated and accepts %v",
		e.Hash, e.Approved)
}

// ErrUnknownKDF reports an unrecognised key-derivation function, in any mode.
type ErrUnknownKDF struct {
	KDF string
}

func (e ErrUnknownKDF) Error() string {
	return fmt.Sprintf("fips: unknown key-derivation function %q", e.KDF)
}

// ErrUnknownHash reports an unrecognised hash algorithm, in any mode.
type ErrUnknownHash struct {
	Hash string
}

func (e ErrUnknownHash) Error() string {
	return fmt.Sprintf("fips: unknown hash algorithm %q", e.Hash)
}

// ErrHashUnsupportedByLUKS reports a hash that is FIPS-approved in general but
// cannot be used as a LUKS2 keyslot digest.
//
// The constraint is go-luks2's, not FIPS's: FormatOptions.HashAlgo is a SHARED
// field feeding both the keyslot digest and the anti-forensic splitter, and the
// splitter's getHashFunc accepts only sha256 and sha512. Mapping an approved
// SHA-384 selection into that field produces a runtime failure deep inside
// AFSplit, so it is refused up front with an explanation instead.
type ErrHashUnsupportedByLUKS struct {
	// Hash is the requested digest.
	Hash string
	// Supported lists what LUKS2 can actually use here.
	Supported []string
}

func (e ErrHashUnsupportedByLUKS) Error() string {
	return fmt.Sprintf(
		"fips: hash %q is FIPS-approved but not usable as a LUKS2 keyslot digest; "+
			"go-luks2 shares this field with the anti-forensic splitter, which supports %v",
		e.Hash, e.Supported)
}

// ErrQualifiedKDFHashConflict reports a hash-qualified PBKDF2 alias whose
// implied PRF contradicts an explicitly supplied digest.
//
// go-luks2 would silently honour the explicit HashAlgo and ignore the suffix, so
// the caller would receive a PRF it did not ask for. Refusing is better than
// choosing one of the two for them.
type ErrQualifiedKDFHashConflict struct {
	KDF        string
	Hash       string
	ImpliedPRF string
}

func (e ErrQualifiedKDFHashConflict) Error() string {
	return fmt.Sprintf(
		"fips: KDF %q implies PRF %q but hash %q was also specified; go-luks2 would silently use %q. "+
			"Specify KDF %q with the digest you want, or drop the explicit hash",
		e.KDF, e.ImpliedPRF, e.Hash, e.Hash, KDFPBKDF2)
}

// ErrFIPSIndicatorUnreadable reports that the kernel's FIPS indicator exists but
// could not be read — a permission problem or transient I/O error.
//
// This is deliberately distinct from the indicator being ABSENT, which is the
// normal state on a non-FIPS kernel. Collapsing the two meant an unreadable
// indicator silently selected non-FIPS mode and disabled every keyslot
// restriction: a compliance control swallowing an error into a permissive
// default.
type ErrFIPSIndicatorUnreadable struct {
	Path  string
	Cause error
}

func (e ErrFIPSIndicatorUnreadable) Error() string {
	return fmt.Sprintf("fips: cannot read the kernel FIPS indicator %s: %v", e.Path, e.Cause)
}

func (e ErrFIPSIndicatorUnreadable) Unwrap() error { return e.Cause }

// ErrFIPSIndicatorMalformed reports indicator contents that are neither "0" nor
// "1". Treating anything unrecognised as "not FIPS" would be the same fail-open
// mistake as swallowing a read error.
type ErrFIPSIndicatorMalformed struct {
	Path     string
	Contents string
}

func (e ErrFIPSIndicatorMalformed) Error() string {
	return fmt.Sprintf("fips: kernel FIPS indicator %s holds %q, expected \"0\" or \"1\"",
		e.Path, e.Contents)
}
