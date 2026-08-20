// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build !fips

// This file carries the RMCP+ algorithm table for a NON-FIPS build. The FIPS
// build gets rmcp_algorithms_fips.go instead, which offers SHA-256 only and
// refuses anything else. Keeping the selection here — rather than switching on
// GODEBUG at runtime — is what actually removes MD5 and SHA-1 from a FIPS
// binary: GODEBUG=fips140=only is a runtime restriction and compiles nothing
// out, so it can verify the gate but cannot be the gate (company ruling D4).

package bmc

import (
	// #nosec G501 -- IPMI 2.0 mandates HMAC-MD5. RMCP+ RAKP negotiates the
	// authentication and integrity algorithm with the BMC, and
	// RAKP-HMAC-MD5 / HMAC-MD5-128 are two of the values the spec defines
	// (IPMI v2.0 rev 1.1, table 13-17). MD5 is used only as the HMAC hash
	// against a per-session key, never as a bare digest, and never for
	// anything whose security rests on collision resistance. A BMC that
	// offers SHA-256 gets SHA-256; this is the floor for the ones that
	// don't. A FIPS build does not compile this file at all.
	"crypto/md5"
	// #nosec G505 -- same rationale: RAKP-HMAC-SHA1 / HMAC-SHA1-96 are
	// spec-defined negotiable algorithms used as an HMAC hash, not a bare
	// digest. Offered only after SHA-256 is refused, and never in a FIPS build.
	"crypto/sha1"
	"crypto/sha256"
	"hash"
)

// rmcpCipherSuites returns the RAKP cipher suites to offer, in preference
// order. SHA-256 first: IPMI 2.0 defines auth algorithm 0x03
// (RAKP-HMAC-SHA256) and integrity 0x04 (HMAC_SHA256_128), and modern BMCs
// speak it. The SHA-1 entry is the compatibility floor for older controllers
// that refuse the SHA-256 open-session request (status 0x11).
func rmcpCipherSuites() []rmcpCipherSuite {
	return []rmcpCipherSuite{
		{authAlgoHMACSHA256, integrityAlgoHMACSHA256_128, "SHA256"},
		{authAlgoHMACSHA1, integrityAlgoHMACSHA1_96, "SHA1"},
	}
}

// rmcpAuthHash returns the hash constructor and full digest size for an RAKP
// authentication algorithm.
func rmcpAuthHash(authAlgo uint8) (func() hash.Hash, int) {
	switch authAlgo {
	case authAlgoHMACSHA256:
		return sha256.New, sha256.Size
	case authAlgoHMACMD5:
		return md5.New, md5.Size
	default:
		return sha1.New, sha1.Size
	}
}

// rmcpIntegrityHash returns the hash constructor and truncated authcode length
// for an RMCP+ integrity algorithm.
func rmcpIntegrityHash(integrityAlgo uint8) (func() hash.Hash, int) {
	switch integrityAlgo {
	case integrityAlgoHMACSHA256_128:
		return sha256.New, 16
	case integrityAlgoHMACMD5_128:
		return md5.New, 16
	default: // HMAC-SHA1-96
		return sha1.New, 12
	}
}

// rmcpValidateNegotiated accepts whatever the BMC agreed to. A non-FIPS build
// deliberately tolerates the legacy algorithms it just offered.
func rmcpValidateNegotiated(_ uint8, _ uint8) error {
	return nil
}
