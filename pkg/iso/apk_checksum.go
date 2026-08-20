// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build !fips

package iso

import (
	// #nosec G505 -- Alpine's APKINDEX format defines the package checksum as
	// "Q1" + base64(SHA-1). The algorithm is dictated by the on-disk format,
	// not chosen here, and apk itself will not accept anything else. It is an
	// index integrity field; package authenticity comes from Alpine's own
	// signatures. Not compiled in a FIPS build — see apk_checksum_fips.go.
	"crypto/sha1"
	"hash"
)

// newAPKChecksumHasher returns the hasher for an APKINDEX "Q1" checksum.
func newAPKChecksumHasher() (hash.Hash, error) { return sha1.New(), nil }

// isFIPSChecksumRefusal is never true in a non-FIPS build: the checksum is
// always computable, so any extraction error is a genuinely malformed package
// and skipping it is correct.
func isFIPSChecksumRefusal(error) bool { return false }
