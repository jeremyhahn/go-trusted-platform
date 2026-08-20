// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build fips

package ima

import "hash"

// newSHA1 refuses to compute SHA-1 in a FIPS build.
//
// The IMA log remains PARSEABLE: length dispatch and structural decoding use
// constants only, so a SHA-1 measurement can still be read and reported. What
// cannot happen is a SHA-1 digest being COMPUTED and then relied upon — a
// verification result resting on a non-approved primitive would be a
// compliance claim this build is not entitled to make. The caller sees a typed
// error and fails closed rather than silently reporting the measurement as
// verified.
func newSHA1() (hash.Hash, error) {
	return nil, ErrFIPSHashNotApproved{Algorithm: "sha1"}
}

// assertApprovedMeasurement refuses to produce a verification verdict for a
// measurement that rests on a non-approved digest.
//
// It deliberately checks TWO things, because the algorithm label alone is not
// sufficient. In an `ima-ng` record, event.HashAlgorithm describes the FILE
// DATA hash (template field 4), not the template hash — so an event can
// legitimately declare "sha256" while carrying a 20-byte SHA-1 TemplateHash,
// and an event may omit the label entirely. Checking only the label let exactly
// that shape through with Passed=true, which is the defect the hosted review
// caught on PR #27.
//
// A 20-byte template hash is therefore refused on WIDTH, independently of what
// the record claims. Parsing is unaffected: verifyTemplateHash still accepts
// the length, so a legacy log remains readable — it simply cannot be reported
// as verified.
func (v *Verifier) assertApprovedMeasurement(event *Event) error {
	switch event.HashAlgorithm {
	case "sha1", "md5":
		return ErrFIPSHashNotApproved{Algorithm: event.HashAlgorithm}
	}
	if len(event.TemplateHash) == sha1DigestSize {
		return ErrFIPSHashNotApproved{Algorithm: "sha1 (inferred from a 20-byte template hash)"}
	}
	return nil
}
