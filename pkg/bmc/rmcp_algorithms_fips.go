// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build fips

// FIPS build: RMCP+ negotiates HMAC-SHA256 ONLY.
//
// BMC is NOT compiled out. IPMI 2.0 already defines the approved algorithms —
// auth 0x03 (RAKP-HMAC-SHA256) and integrity 0x04 (HMAC_SHA256_128) — and this
// package already preferred them; MD5 and SHA-1 existed purely as negotiation
// fallbacks for older controllers. Under FIPS those fallbacks are removed from
// the offer entirely, and crypto/md5 and crypto/sha1 are not imported, so they
// cannot appear in the binary.
//
// A controller that refuses SHA-256 is unreachable over IPMI in a FIPS build.
// That is the correct outcome: the alternative is a silent downgrade to a
// non-approved algorithm, which is exactly what a compliance gate exists to
// prevent. Redfish (HTTPS/TLS, no IPMI crypto) remains available for those
// controllers.

package bmc

import (
	"crypto/sha256"
	"hash"
)

// rmcpCipherSuites offers the approved suite only. There is no fallback entry:
// under FIPS a downgrade is a failure, not a compatibility path.
func rmcpCipherSuites() []rmcpCipherSuite {
	return []rmcpCipherSuite{
		{authAlgoHMACSHA256, integrityAlgoHMACSHA256_128, "SHA256"},
	}
}

// rmcpAuthHash returns SHA-256 unconditionally. Only SHA-256 can be negotiated
// in this build, and rmcpValidateNegotiated rejects anything else before a
// session key is derived, so no other algorithm can reach here.
func rmcpAuthHash(_ uint8) (func() hash.Hash, int) {
	return sha256.New, sha256.Size
}

// rmcpIntegrityHash returns SHA-256-128 unconditionally, for the same reason.
func rmcpIntegrityHash(_ uint8) (func() hash.Hash, int) {
	return sha256.New, 16
}

// rmcpValidateNegotiated fails closed on any algorithm pair the FIPS build did
// not offer. This is defence in depth rather than belt-and-braces: a
// misbehaving or hostile BMC can echo an algorithm that was never offered, and
// without this check the session would proceed using the SHA-256 constructors
// above while both peers believed a different algorithm was in force.
func rmcpValidateNegotiated(authAlgo uint8, integrityAlgo uint8) error {
	if authAlgo != authAlgoHMACSHA256 {
		return ErrFIPSAlgorithmNotApproved{
			Field:     "authentication",
			Algorithm: authAlgo,
			Approved:  authAlgoHMACSHA256,
		}
	}
	if integrityAlgo != integrityAlgoHMACSHA256_128 {
		return ErrFIPSAlgorithmNotApproved{
			Field:     "integrity",
			Algorithm: integrityAlgo,
			Approved:  integrityAlgoHMACSHA256_128,
		}
	}
	return nil
}
