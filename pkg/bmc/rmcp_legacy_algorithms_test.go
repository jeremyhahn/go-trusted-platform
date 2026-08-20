// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build !fips

// Tests for the LEGACY RMCP+ algorithms (RAKP-HMAC-SHA1, HMAC-SHA1-96,
// HMAC-MD5). They assert behaviour that a FIPS build deliberately does not
// have — rmcp_algorithms_fips.go offers HMAC-SHA256 alone — so they are tagged
// !fips and their FIPS counterparts live in rmcp_algorithms_fips_test.go.
//
// They stay in a separate file rather than being deleted or skipped: the
// legacy path is still the default build's behaviour against older BMCs, and
// it needs the same coverage it always had. A skip guard would have hidden
// that; a build tag states it.

package bmc

import (
	"bytes"
	"crypto/hmac"
	// #nosec G505 -- these tests exist precisely to pin the legacy
	// negotiation path's behaviour; they are not compiled in a FIPS build.
	"crypto/sha1"
	"crypto/sha256"
	"testing"
)

func TestDeriveKeys_HMACSHA1(t *testing.T) {
	s := &rmcpSession{
		authAlgo:      authAlgoHMACSHA1,
		integrityAlgo: integrityAlgoHMACSHA1_96,
		cryptoAlgo:    cryptoAlgoAESCBC128,
		password:      "test_password",
		username:      "admin",
		privilege:     privilegeAdministrator,
	}

	// Set deterministic values for testing.
	for i := range s.clientRand {
		s.clientRand[i] = byte(i)
	}
	for i := range s.bmcRand {
		s.bmcRand[i] = byte(i + 0x10)
	}

	if err := s.deriveKeys(); err != nil {
		t.Fatalf("deriveKeys() error: %v", err)
	}

	// Verify SIK is computed correctly.
	// SIK = HMAC-SHA1(password, clientRand || bmcRand || privilege || userLen || username)
	sikData := make([]byte, 0, 34+len("admin"))
	sikData = append(sikData, s.clientRand[:]...)
	sikData = append(sikData, s.bmcRand[:]...)
	sikData = append(sikData, s.privilege)
	sikData = append(sikData, byte(len("admin")))
	sikData = append(sikData, []byte("admin")...)

	mac := hmac.New(sha1.New, []byte("test_password"))
	mac.Write(sikData)
	expectedSIK := mac.Sum(nil)

	if !bytes.Equal(s.sik, expectedSIK) {
		t.Errorf("SIK mismatch:\n  got:  %x\n  want: %x", s.sik, expectedSIK)
	}

	// Verify K1 = HMAC-SHA1(SIK, 0x01 * 20)
	k1Input := bytes.Repeat([]byte{0x01}, 20)
	mac = hmac.New(sha1.New, expectedSIK)
	mac.Write(k1Input)
	expectedK1 := mac.Sum(nil)

	if !bytes.Equal(s.k1, expectedK1) {
		t.Errorf("K1 mismatch:\n  got:  %x\n  want: %x", s.k1, expectedK1)
	}

	// Verify K2 = HMAC-SHA1(SIK, 0x02 * 20)
	k2Input := bytes.Repeat([]byte{0x02}, 20)
	mac = hmac.New(sha1.New, expectedSIK)
	mac.Write(k2Input)
	expectedK2 := mac.Sum(nil)

	if !bytes.Equal(s.k2, expectedK2) {
		t.Errorf("K2 mismatch:\n  got:  %x\n  want: %x", s.k2, expectedK2)
	}

	// Verify keys are non-nil and non-empty.
	if len(s.sik) != sha1.Size {
		t.Errorf("SIK length = %d, want %d", len(s.sik), sha1.Size)
	}
	if len(s.k1) != sha1.Size {
		t.Errorf("K1 length = %d, want %d", len(s.k1), sha1.Size)
	}
	if len(s.k2) != sha1.Size {
		t.Errorf("K2 length = %d, want %d", len(s.k2), sha1.Size)
	}
}

func TestComputeAuthHMAC_SHA1(t *testing.T) {
	s := &rmcpSession{authAlgo: authAlgoHMACSHA1}
	key := []byte("test_key")
	data := []byte("test_data")

	result := s.computeAuthHMAC(key, data)

	mac := hmac.New(sha1.New, key)
	mac.Write(data)
	expected := mac.Sum(nil)

	if !bytes.Equal(result, expected) {
		t.Errorf("HMAC-SHA1 mismatch:\n  got:  %x\n  want: %x", result, expected)
	}
}

func TestAuthHMACLen(t *testing.T) {
	tests := []struct {
		name     string
		algo     uint8
		expected int
	}{
		{"SHA1", authAlgoHMACSHA1, sha1.Size},
		{"SHA256", authAlgoHMACSHA256, sha256.Size},
		{"None defaults to SHA1", authAlgoNone, sha1.Size},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &rmcpSession{authAlgo: tt.algo}
			if got := s.authHMACLen(); got != tt.expected {
				t.Errorf("authHMACLen() = %d, want %d", got, tt.expected)
			}
		})
	}
}

func TestComputeIntegrity_SHA1_96(t *testing.T) {
	s := &rmcpSession{
		integrityAlgo: integrityAlgoHMACSHA1_96,
		k1:            bytes.Repeat([]byte{0xAA}, 20),
	}
	data := []byte("integrity test data")

	result := s.computeIntegrity(data)

	// Should be truncated to 12 bytes.
	if len(result) != 12 {
		t.Fatalf("integrity HMAC length = %d, want 12", len(result))
	}

	// Verify against manual computation.
	mac := hmac.New(sha1.New, s.k1)
	mac.Write(data)
	full := mac.Sum(nil)
	expected := full[:12]

	if !bytes.Equal(result, expected) {
		t.Errorf("integrity HMAC mismatch:\n  got:  %x\n  want: %x", result, expected)
	}
}

func TestIntegrityHMACTruncLen(t *testing.T) {
	tests := []struct {
		name     string
		algo     uint8
		expected int
	}{
		{"SHA1-96", integrityAlgoHMACSHA1_96, 12},
		{"SHA256-128", integrityAlgoHMACSHA256_128, 16},
		{"None defaults to 12", integrityAlgoNone, 12},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &rmcpSession{integrityAlgo: tt.algo}
			if got := s.integrityHMACTruncLen(); got != tt.expected {
				t.Errorf("integrityHMACTruncLen() = %d, want %d", got, tt.expected)
			}
		})
	}
}

func TestHMACCrossValidation(t *testing.T) {
	// Verify our HMAC computations match Go stdlib directly.
	key := []byte("cross_validation_key")
	data := []byte("cross_validation_data")

	t.Run("SHA1 matches stdlib", func(t *testing.T) {
		s := &rmcpSession{authAlgo: authAlgoHMACSHA1}
		got := s.computeAuthHMAC(key, data)

		h := hmac.New(sha1.New, key)
		h.Write(data)
		want := h.Sum(nil)

		if !hmac.Equal(got, want) {
			t.Errorf("HMAC mismatch:\n  got:  %x\n  want: %x", got, want)
		}
	})

	t.Run("SHA256 matches stdlib", func(t *testing.T) {
		s := &rmcpSession{authAlgo: authAlgoHMACSHA256}
		got := s.computeAuthHMAC(key, data)

		h := hmac.New(sha256.New, key)
		h.Write(data)
		want := h.Sum(nil)

		if !hmac.Equal(got, want) {
			t.Errorf("HMAC mismatch:\n  got:  %x\n  want: %x", got, want)
		}
	})
}

func TestHMACSHA1_KnownVector(t *testing.T) {
	// RFC 2202 Test Case 1
	key := bytes.Repeat([]byte{0x0B}, 20)
	data := []byte("Hi There")

	h := hmac.New(sha1.New, key)
	h.Write(data)
	result := h.Sum(nil)

	// Expected: b617318655057264e28bc0b6fb378c8ef146be00
	expected := []byte{
		0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64,
		0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37, 0x8c, 0x8e,
		0xf1, 0x46, 0xbe, 0x00,
	}
	if !bytes.Equal(result, expected) {
		t.Errorf("HMAC-SHA1 known vector mismatch:\n  got:  %x\n  want: %x", result, expected)
	}

	// Verify our wrapper produces the same.
	s := &rmcpSession{authAlgo: authAlgoHMACSHA1}
	wrapper := s.computeAuthHMAC(key, data)
	if !bytes.Equal(wrapper, expected) {
		t.Errorf("computeAuthHMAC wrapper mismatch:\n  got:  %x\n  want: %x", wrapper, expected)
	}
}
