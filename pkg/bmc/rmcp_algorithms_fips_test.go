// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build fips

package bmc

import (
	"crypto/sha256"
	"errors"
	"net"
	"testing"
)

// TestFIPSCipherSuitesOfferApprovedOnly is the load-bearing assertion of the
// FIPS gate: the offer must contain HMAC-SHA256 and nothing else. If a legacy
// suite ever reappears here, a FIPS build would negotiate a non-approved
// algorithm with a controller that asks for one.
func TestFIPSCipherSuitesOfferApprovedOnly(t *testing.T) {
	suites := rmcpCipherSuites()
	if len(suites) != 1 {
		t.Fatalf("FIPS build must offer exactly one cipher suite, got %d: %+v", len(suites), suites)
	}
	if suites[0].auth != authAlgoHMACSHA256 {
		t.Errorf("auth algorithm = 0x%02x, want 0x%02x (RAKP-HMAC-SHA256)",
			suites[0].auth, authAlgoHMACSHA256)
	}
	if suites[0].integrity != integrityAlgoHMACSHA256_128 {
		t.Errorf("integrity algorithm = 0x%02x, want 0x%02x (HMAC_SHA256_128)",
			suites[0].integrity, integrityAlgoHMACSHA256_128)
	}
	for _, s := range suites {
		if s.auth == authAlgoHMACSHA1 || s.auth == authAlgoHMACMD5 {
			t.Errorf("FIPS build offers non-approved auth algorithm 0x%02x", s.auth)
		}
		if s.integrity == integrityAlgoHMACSHA1_96 || s.integrity == integrityAlgoHMACMD5_128 {
			t.Errorf("FIPS build offers non-approved integrity algorithm 0x%02x", s.integrity)
		}
	}
}

// TestFIPSAuthHashAlwaysSHA256 proves the selector cannot yield MD5 or SHA-1
// even if a legacy identifier reaches it.
func TestFIPSAuthHashAlwaysSHA256(t *testing.T) {
	for _, algo := range []uint8{authAlgoHMACSHA256, authAlgoHMACSHA1, authAlgoHMACMD5, 0xFF} {
		h, size := rmcpAuthHash(algo)
		if size != sha256.Size {
			t.Errorf("algo 0x%02x: digest size = %d, want %d", algo, size, sha256.Size)
		}
		if got := h().Size(); got != sha256.Size {
			t.Errorf("algo 0x%02x: constructed hash size = %d, want %d", algo, got, sha256.Size)
		}
	}
}

// TestFIPSIntegrityHashAlwaysSHA256 is the integrity-side equivalent.
func TestFIPSIntegrityHashAlwaysSHA256(t *testing.T) {
	for _, algo := range []uint8{integrityAlgoHMACSHA256_128, integrityAlgoHMACSHA1_96, integrityAlgoHMACMD5_128, 0xFF} {
		h, truncLen := rmcpIntegrityHash(algo)
		if truncLen != 16 {
			t.Errorf("algo 0x%02x: truncation = %d, want 16", algo, truncLen)
		}
		if got := h().Size(); got != sha256.Size {
			t.Errorf("algo 0x%02x: constructed hash size = %d, want %d", algo, got, sha256.Size)
		}
	}
}

// TestFIPSValidateNegotiatedRejectsDowngrade covers the fail-closed path: a
// controller echoing an algorithm that was never offered must abort the
// session rather than silently proceeding under SHA-256 while the peer
// believes something else is in force.
func TestFIPSValidateNegotiatedRejectsDowngrade(t *testing.T) {
	tests := []struct {
		name      string
		auth      uint8
		integrity uint8
		wantField string
	}{
		{"sha1 auth", authAlgoHMACSHA1, integrityAlgoHMACSHA256_128, "authentication"},
		{"md5 auth", authAlgoHMACMD5, integrityAlgoHMACSHA256_128, "authentication"},
		{"sha1 integrity", authAlgoHMACSHA256, integrityAlgoHMACSHA1_96, "integrity"},
		{"md5 integrity", authAlgoHMACSHA256, integrityAlgoHMACMD5_128, "integrity"},
		{"unknown auth", 0xFF, integrityAlgoHMACSHA256_128, "authentication"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := rmcpValidateNegotiated(tc.auth, tc.integrity)
			if err == nil {
				t.Fatal("expected a downgrade to be refused, got nil")
			}
			var fipsErr ErrFIPSAlgorithmNotApproved
			if !errors.As(err, &fipsErr) {
				t.Fatalf("expected ErrFIPSAlgorithmNotApproved, got %T: %v", err, err)
			}
			if fipsErr.Field != tc.wantField {
				t.Errorf("Field = %q, want %q", fipsErr.Field, tc.wantField)
			}
			if fipsErr.Error() == "" {
				t.Error("typed error must carry a message")
			}
		})
	}
}

// TestFIPSValidateNegotiatedAcceptsApproved is the happy path — the approved
// pairing must not be rejected, or a FIPS build could reach no BMC at all.
func TestFIPSValidateNegotiatedAcceptsApproved(t *testing.T) {
	if err := rmcpValidateNegotiated(authAlgoHMACSHA256, integrityAlgoHMACSHA256_128); err != nil {
		t.Fatalf("approved pairing rejected: %v", err)
	}
}

// TestFIPSNegotiationRejectionClosesConnection is the regression test for the
// resource leak the hosted review caught on PR #27: the validation branch
// returned without closing the UDP socket, and production callers return on
// Open failure without calling Close — so a controller repeatedly offering a
// downgrade would accumulate sockets until the process ran out.
//
// It drives acceptNegotiated, the real branch Connect takes, and proves the
// socket is unusable afterwards by writing to it.
func TestFIPSNegotiationRejectionClosesConnection(t *testing.T) {
	c, err := net.Dial("udp4", "127.0.0.1:9")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	s := &rmcpSession{
		conn:          c.(*net.UDPConn),
		authAlgo:      authAlgoHMACSHA1, // a downgrade this build never offered
		integrityAlgo: integrityAlgoHMACSHA256_128,
	}

	err = s.acceptNegotiated()
	if err == nil {
		t.Fatal("expected the downgrade to be refused")
	}
	var fipsErr ErrFIPSAlgorithmNotApproved
	if !errors.As(err, &fipsErr) {
		t.Fatalf("expected ErrFIPSAlgorithmNotApproved, got %T: %v", err, err)
	}

	if _, wErr := s.conn.Write([]byte("x")); wErr == nil {
		t.Error("socket still usable after a refused negotiation — it was leaked")
	}
}

// TestFIPSNegotiationAcceptedKeepsConnection guards the other direction: the
// approved pairing must NOT close the socket, or every FIPS session would die
// immediately after negotiating successfully.
func TestFIPSNegotiationAcceptedKeepsConnection(t *testing.T) {
	c, err := net.Dial("udp4", "127.0.0.1:9")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	s := &rmcpSession{
		conn:          c.(*net.UDPConn),
		authAlgo:      authAlgoHMACSHA256,
		integrityAlgo: integrityAlgoHMACSHA256_128,
	}

	if err := s.acceptNegotiated(); err != nil {
		t.Fatalf("approved pairing rejected: %v", err)
	}
	if _, wErr := s.conn.Write([]byte("x")); wErr != nil {
		t.Errorf("socket must stay open after a successful negotiation: %v", wErr)
	}
}
