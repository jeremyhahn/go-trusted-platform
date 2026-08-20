// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build !fips

package secureboot

import (
	// #nosec G505 -- RFC 5280 §4.2.1.2 method (1) derives the Subject Key
	// Identifier as the SHA-1 digest of the subjectPublicKey. This is an
	// IDENTIFIER used to match a certificate to a key, not a security function:
	// nothing here relies on collision resistance. It mirrors the kernel's
	// x509.genkey (subjectKeyIdentifier=hash) so module-signing certificates
	// look the way the kernel's tooling produces them. A FIPS build uses
	// ski_fips.go instead.
	"crypto/sha1"
)

// subjectKeyIdentifier derives the SKI from a marshalled SPKI using RFC 5280
// method (1).
func subjectKeyIdentifier(spki []byte) []byte {
	sum := sha1.Sum(spki)
	return sum[:]
}
