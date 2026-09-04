// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build !fips

// The HMAC known-answer vectors live here because RFC 4231's keys are shorter
// than FIPS 140-3 permits for an HMAC key, and crypto/hmac PANICS rather than
// erroring on a short key under GODEBUG=fips140=only. Test Case 2 keys on
// "Jefe" — four bytes — so the vector cannot be reproduced in a FIPS build at
// all, and lengthening the key would destroy the only thing a known-answer test
// is for.
//
// Nothing is lost by excluding it there: in a FIPS build HMAC-SHA256 is the Go
// Cryptographic Module's own CAVP-validated implementation, and this package
// only calls it. The same reasoning already puts the MD5 and SHA-1 vectors in
// rmcp_legacy_algorithms_test.go (#209).

package bmc

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"testing"
)

func TestHMACSHA256_KnownVector(t *testing.T) {
	// RFC 4231 Test Case 2
	key := []byte("Jefe")
	data := []byte("what do ya want for nothing?")

	h := hmac.New(sha256.New, key)
	h.Write(data)
	result := h.Sum(nil)

	// Expected from RFC 4231
	expected := []byte{
		0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
		0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
		0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
		0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
	}
	if !bytes.Equal(result, expected) {
		t.Errorf("HMAC-SHA256 known vector mismatch:\n  got:  %x\n  want: %x", result, expected)
	}

	s := &rmcpSession{authAlgo: authAlgoHMACSHA256}
	wrapper := s.computeAuthHMAC(key, data)
	if !bytes.Equal(wrapper, expected) {
		t.Errorf("computeAuthHMAC wrapper mismatch:\n  got:  %x\n  want: %x", wrapper, expected)
	}
}

// --- AES-CBC-128 Known Test Vector ---
