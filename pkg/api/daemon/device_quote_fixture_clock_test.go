// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

// TestQuoteFixture_CertificatesAreValidAtRealTime guards against the fixture
// clock drifting back to a constant. The reporting verifier and the collector
// validate the attestation-key chain against the production clock, so every
// fixture certificate must be valid at time.Now(), not only at the fixture's
// own instant (#506: a pinned 2026-09-05 clock expired the AK leaf at
// midnight and turned main red).
func TestQuoteFixture_CertificatesAreValidAtRealTime(t *testing.T) {
	f := newQuoteFixture(t)
	now := time.Now().UTC()

	block, _ := pem.Decode([]byte(f.device.AttestCert))
	if block == nil {
		t.Fatal("fixture AttestCert is not PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse fixture AK certificate: %v", err)
	}

	for _, c := range []struct {
		name string
		cert *x509.Certificate
	}{
		{"root", f.ca.root},
		{"intermediate", f.ca.intermediate},
		{"ak leaf", leaf},
	} {
		if now.Before(c.cert.NotBefore) || now.After(c.cert.NotAfter) {
			t.Errorf("fixture %s certificate is not valid at %s (NotBefore %s, NotAfter %s): the fixture clock must derive from time.Now() (#506)",
				c.name, now.Format(time.RFC3339), c.cert.NotBefore.Format(time.RFC3339), c.cert.NotAfter.Format(time.RFC3339))
		}
	}

	intermediates := x509.NewCertPool()
	intermediates.AddCert(f.ca.intermediate)
	roots := x509.NewCertPool()
	roots.AddCert(f.ca.root)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Errorf("fixture AK chain does not verify at real time: %v (#506)", err)
	}
}
