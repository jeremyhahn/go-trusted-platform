// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build fips

package workload

import "hash"

// newSHA1 returns nil in a FIPS build, so getHasher yields no hasher for
// HashAlgorithmSHA1 and every caller fails closed with
// ErrInvalidHashAlgorithm.
//
// The SHA-1 PCR bank stays describable — the HashAlgorithm value still exists
// and still round-trips — but a digest over it is never COMPUTED here, so no
// attestation decision in this build can rest on a non-approved primitive.
// Selecting the SHA-256 bank is the supported path.
func newSHA1() hash.Hash { return nil }
