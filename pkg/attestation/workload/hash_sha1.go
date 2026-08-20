// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build !fips

package workload

import (
	// #nosec G505 -- TPM hardware exposes a SHA-1 PCR bank, and a workload
	// measurement extended into that bank must be computed with the bank's own
	// algorithm or it will not match. Verification of externally-produced
	// measurements, not signing or key derivation. Not compiled in a FIPS build
	// — see hash_sha1_fips.go.
	"crypto/sha1"
	"hash"
)

// newSHA1 returns a SHA-1 hasher for the TPM SHA-1 PCR bank.
func newSHA1() hash.Hash { return sha1.New() }
