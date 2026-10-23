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

package testutil

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"
)

// PSSQuoteScheme is the scheme name SignPSSQuote signs under, as a quote
// response declares it in signature_algorithm.
var PSSQuoteScheme = x509.SHA256WithRSAPSS.String()

// SignPSSQuote signs quote the way an RSA-PSS attestation key does and
// returns the signature with the key's PKIX DER public half. A verifier
// that infers PKCS#1 v1.5 from an RSA key rejects it, so it tells a
// transport that honours the declared scheme from one that does not.
func SignPSSQuote(t testing.TB, quote []byte) (signature, akPublic []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("testutil: failed to generate RSA key: %v", err)
	}
	digest := sha256.Sum256(quote)
	signature, err = rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest[:], nil)
	if err != nil {
		t.Fatalf("testutil: failed to sign quote: %v", err)
	}
	akPublic, err = x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("testutil: failed to marshal AK public key: %v", err)
	}
	return signature, akPublic
}
