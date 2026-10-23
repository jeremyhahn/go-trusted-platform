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

package testutil_test

import (
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/vm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
)

func TestSignPSSQuote_VerifiesUnderTheDeclaredScheme(t *testing.T) {
	quote := []byte("quoted-attest")
	signature, akPublic := testutil.SignPSSQuote(t, quote)

	if err := vm.VerifyQuoteSignatureWithAlgorithm(akPublic, quote, signature, testutil.PSSQuoteScheme); err != nil {
		t.Fatalf("PSS quote did not verify under %s: %v", testutil.PSSQuoteScheme, err)
	}
}

func TestSignPSSQuote_FailsUnderPKCS1v15(t *testing.T) {
	quote := []byte("quoted-attest")
	signature, akPublic := testutil.SignPSSQuote(t, quote)

	err := vm.VerifyQuoteSignatureWithAlgorithm(akPublic, quote, signature, x509.SHA256WithRSA.String())
	var invalid vm.ErrSignatureInvalid
	if !errors.As(err, &invalid) {
		t.Fatalf("PSS quote checked as PKCS#1 v1.5: want ErrSignatureInvalid, got %v", err)
	}
}
