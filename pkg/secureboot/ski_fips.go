// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build fips

package secureboot

import "crypto/sha256"

// subjectKeyIdentifier derives the SKI with SHA-256, truncated to 20 bytes.
//
// RFC 5280 §4.2.1.2 describes two SHA-1 methods but explicitly permits others:
// "Other methods of generating unique numbers are also acceptable." The SKI is
// an identifier used to match a certificate to its key, so any collision-free
// derivation satisfies it, and truncating to 20 bytes keeps the field the width
// every tool expects.
//
// This is gated rather than applied to ALL builds deliberately. Module-signing
// certificates are hardware-adjacent — a mismatch between the signature's
// signer identity and the certificate's SKI means modules fail to load — so the
// non-FIPS path stays byte-identical to what has already been deployed, and
// only a FIPS build takes the new derivation. Both are self-consistent: the
// kernel reads the SKI from the certificate it was given.
func subjectKeyIdentifier(spki []byte) []byte {
	sum := sha256.Sum256(spki)
	return sum[:20]
}
