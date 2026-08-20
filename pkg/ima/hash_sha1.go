// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build !fips

package ima

import (
	// #nosec G505 -- the kernel IMA log records SHA-1 template hashes on
	// systems whose policy selects the SHA-1 PCR bank. This computes the same
	// digest in order to VERIFY externally-produced measurements; it is not a
	// signature or key-derivation input. A FIPS build does not compile this
	// file — see hash_sha1_fips.go.
	"crypto/sha1"
	"hash"
)

// newSHA1 returns a SHA-1 hasher for parsing legacy IMA measurements.
func newSHA1() (hash.Hash, error) { return sha1.New(), nil }

// assertApprovedMeasurement permits every measurement the parser understands in
// a non-FIPS build.
func (v *Verifier) assertApprovedMeasurement(_ *Event) error { return nil }
