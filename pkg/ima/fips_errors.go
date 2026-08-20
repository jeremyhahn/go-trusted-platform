// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package ima

import "fmt"

// ErrFIPSHashNotApproved reports that a measurement requires a hash algorithm
// this FIPS build will not compute. The measurement can still be read; it
// cannot be verified, and callers must treat that as a failure rather than as
// a pass.
type ErrFIPSHashNotApproved struct {
	Algorithm string
}

func (e ErrFIPSHashNotApproved) Error() string {
	return fmt.Sprintf(
		"ima: hash algorithm %q is not FIPS-approved; this build cannot verify measurements that use it",
		e.Algorithm)
}

// sha1DigestSize is crypto/sha1.Size, redeclared so structural parsing of a
// measurement log does not require importing crypto/sha1. Length dispatch is
// not a cryptographic operation: reading the shape of a legacy entry must keep
// working in every build, including FIPS.
const sha1DigestSize = 20
