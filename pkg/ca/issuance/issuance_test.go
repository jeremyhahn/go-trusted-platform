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

package issuance

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"net"
	"net/url"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ca/issuance/issuancetest"
)

func TestStoreType_NamesEveryStore(t *testing.T) {
	cases := map[string]xkmssdk.StoreType{
		"":         xkmssdk.StoreSoftware,
		"software": xkmssdk.StoreSoftware,
		"pkcs8":    xkmssdk.StoreSoftware,
		"PKCS8":    xkmssdk.StoreSoftware,
		"pkcs11":   xkmssdk.StorePKCS11,
		"tpm":      xkmssdk.StoreTPM2,
		"tpm2":     xkmssdk.StoreTPM2,
		"vault":    xkmssdk.StoreVault,
	}
	for name, want := range cases {
		got, err := StoreType(name)
		if err != nil {
			t.Errorf("StoreType(%q): %v", name, err)
			continue
		}
		if got != want {
			t.Errorf("StoreType(%q) = %v, want %v", name, got, want)
		}
	}
}

// "kms" was the runbook's store for the fleet key: it names no store, and
// used to fall back to a fresh software key without a word.
func TestStoreType_RejectsAnUnknownStore(t *testing.T) {
	for _, name := range []string{"kms", "hsm", "softwares"} {
		_, err := StoreType(name)
		var unknown *UnknownStoreTypeError
		if !errors.As(err, &unknown) || unknown.Name != name {
			t.Fatalf("StoreType(%q) = %v, want UnknownStoreTypeError", name, err)
		}
		if !IsInvalidRequest(err) {
			t.Errorf("StoreType(%q): an unknown store is the caller's error", name)
		}
	}
}

// The certificate certifies the KMS key for code signing and nothing else,
// whatever the CA would default to.
func TestSignCSR_CertifiesTheKMSKeyForCodeSigningOnly(t *testing.T) {
	ca := issuancetest.NewCA(t)
	key := issuancetest.RSAKey(t)
	kms := issuancetest.NewKMS(t, "rpi/fleet", &key.PublicKey)
	cert, err := SignCSR(context.Background(), ca, kms, &CSR{
		PEM:       issuancetest.CSR(t, key, "rpi/fleet"),
		ValidDays: 30,
	})
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		t.Fatal("the certificate does not certify the CSR's key")
	}
	if cert.Subject.CommonName != "rpi/fleet" {
		t.Errorf("CN = %q", cert.Subject.CommonName)
	}
	if ca.Opts.ValidityDays != 30 || ca.Opts.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("sign options = %+v", ca.Opts)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageCodeSigning {
		t.Errorf("EKU = %v, want codeSigning only", cert.ExtKeyUsage)
	}
}

// A code-signing certificate cannot authenticate a TLS client, so even a
// certificate this path issues is no mTLS identity.
func TestSignCSR_CertificateIsNoClientIdentity(t *testing.T) {
	ca := issuancetest.NewCA(t)
	key := issuancetest.RSAKey(t)
	cert, err := SignCSR(context.Background(), ca, issuancetest.NewKMS(t, "admin", &key.PublicKey),
		&CSR{PEM: issuancetest.CSR(t, key, "admin")})
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Root)
	_, err = cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err == nil {
		t.Fatal("the certificate verifies as a TLS client")
	}
}

func TestSignCSR_RejectsAMalformedCSR(t *testing.T) {
	key := issuancetest.RSAKey(t)
	good := issuancetest.CSR(t, key, "rpi/fleet")

	// A CSR whose signature does not verify: the signature is the last
	// bytes of the DER, so flip one.
	block, _ := pem.Decode(good)
	forged := append([]byte(nil), block.Bytes...)
	forged[len(forged)-1] ^= 0xff

	cases := map[string][]byte{
		"no PEM":         []byte("not a csr"),
		"wrong PEM type": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes}),
		"garbage DER":    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte{0x30, 0x01}}),
		"bad signature":  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: forged}),
		"no common name": issuancetest.CSR(t, key, ""),
	}
	for name, csr := range cases {
		t.Run(name, func(t *testing.T) {
			err := refused(t, issuancetest.NewKMS(t, "rpi/fleet", &key.PublicKey), csr)
			var csrErr *CSRError
			if !errors.As(err, &csrErr) {
				t.Fatalf("err = %T %v, want CSRError", err, err)
			}
		})
	}
}

// The CA copies the CSR's subject into the certificate, and the platform
// takes a tenant from O: nothing but the key's name may reach it.
func TestSignCSR_RefusesASubjectOtherThanTheCommonName(t *testing.T) {
	key := issuancetest.RSAKey(t)
	kms := issuancetest.NewKMS(t, "rpi/fleet", &key.PublicKey)
	twoCNs, err := asn1.Marshal(pkix.RDNSequence{
		{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "rpi/fleet"}},
		{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "admin"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		subject pkix.Name
		raw     []byte
		want    string
	}{
		{name: "organization", subject: pkix.Name{CommonName: "rpi/fleet", Organization: []string{"tenant-a"}}, want: "O"},
		{name: "organizational unit", subject: pkix.Name{CommonName: "rpi/fleet", OrganizationalUnit: []string{"ops"}}, want: "OU"},
		{name: "country", subject: pkix.Name{CommonName: "rpi/fleet", Country: []string{"US"}}, want: "C"},
		{name: "serial number", subject: pkix.Name{CommonName: "rpi/fleet", SerialNumber: "1"}, want: "serialNumber"},
		{name: "unnamed attribute", subject: pkix.Name{CommonName: "rpi/fleet", ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}, Value: "uid"},
			{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "rpi/fleet"},
		}}, want: "0.9.2342.19200300.100.1.1"},
		{name: "second common name", raw: twoCNs, want: "CN"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			csr := issuancetest.CSRFrom(t, key, &x509.CertificateRequest{Subject: tc.subject, RawSubject: tc.raw})
			err := refused(t, kms, csr)
			var subjectErr *CSRSubjectError
			if !errors.As(err, &subjectErr) {
				t.Fatalf("err = %T %v, want CSRSubjectError", err, err)
			}
			if len(subjectErr.Attributes) != 1 || subjectErr.Attributes[0] != tc.want {
				t.Errorf("attributes = %v, want [%s]", subjectErr.Attributes, tc.want)
			}
		})
	}
}

// Every extra attribute is named, so the caller can fix them at once.
func TestCSRSubjectError_NamesEveryAttribute(t *testing.T) {
	key := issuancetest.RSAKey(t)
	csr := issuancetest.CSRFrom(t, key, &x509.CertificateRequest{Subject: pkix.Name{
		CommonName: "rpi/fleet", Organization: []string{"a"}, OrganizationalUnit: []string{"b"},
	}})
	err := refused(t, issuancetest.NewKMS(t, "rpi/fleet", &key.PublicKey), csr)
	want := "a code-signing CSR's subject must be its common name alone, but it also carries O, OU"
	if err.Error() != want {
		t.Errorf("err = %q", err)
	}
}

// Subject alternative names would put a host or a person beside the key's
// name; the CA copies them, so they are refused rather than dropped.
func TestSignCSR_RefusesSubjectAlternativeNames(t *testing.T) {
	key := issuancetest.RSAKey(t)
	kms := issuancetest.NewKMS(t, "rpi/fleet", &key.PublicKey)
	cases := map[string]*x509.CertificateRequest{
		"DNS":   {DNSNames: []string{"api.example.com"}},
		"IP":    {IPAddresses: []net.IP{net.ParseIP("10.0.0.1")}},
		"URI":   {URIs: []*url.URL{{Scheme: "spiffe", Host: "example.org", Path: "/admin"}}},
		"email": {EmailAddresses: []string{"admin@example.com"}},
	}
	for name, tmpl := range cases {
		t.Run(name, func(t *testing.T) {
			tmpl.Subject = pkix.Name{CommonName: "rpi/fleet"}
			err := refused(t, kms, issuancetest.CSRFrom(t, key, tmpl))
			var sanErr *CSRSANError
			if !errors.As(err, &sanErr) {
				t.Fatalf("err = %T %v, want CSRSANError", err, err)
			}
		})
	}
}

// A CSR may only certify a key the KMS holds, named by its common name.
func TestSignCSR_RefusesACommonNameThatNamesNoKMSKey(t *testing.T) {
	key := issuancetest.RSAKey(t)
	err := refused(t, issuancetest.NewKMS(t, "rpi/fleet", &key.PublicKey), issuancetest.CSR(t, key, "admin"))
	var keyErr *CSRKeyError
	if !errors.As(err, &keyErr) || keyErr.KeyID != "admin" {
		t.Fatalf("err = %T %v, want CSRKeyError for admin", err, err)
	}
	if !errors.Is(err, issuancetest.ErrKeyNotFound) {
		t.Errorf("err = %v, want the KMS's error wrapped", err)
	}
}

// Naming a KMS key is not enough: the CSR's key must be that key, or a
// caller could certify their own key under the fleet key's name.
func TestSignCSR_RefusesAKeyThatIsNotTheNamedKMSKey(t *testing.T) {
	kmsKey := issuancetest.RSAKey(t)
	callerKey := issuancetest.RSAKey(t)
	err := refused(t, issuancetest.NewKMS(t, "rpi/fleet", &kmsKey.PublicKey), issuancetest.CSR(t, callerKey, "rpi/fleet"))
	var mismatch *CSRKeyMismatchError
	if !errors.As(err, &mismatch) || mismatch.KeyID != "rpi/fleet" {
		t.Fatalf("err = %T %v, want CSRKeyMismatchError", err, err)
	}
}

// Without a KMS the key cannot be checked, so nothing is certified.
func TestSignCSR_FailsClosedWithoutAKMS(t *testing.T) {
	ca := issuancetest.NewCA(t)
	key := issuancetest.RSAKey(t)
	_, err := SignCSR(context.Background(), ca, nil, &CSR{PEM: issuancetest.CSR(t, key, "rpi/fleet")})
	var unavailable *KMSUnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("err = %T %v, want KMSUnavailableError", err, err)
	}
	if IsInvalidRequest(err) {
		t.Error("a missing KMS is not the caller's error")
	}
	if ca.Opts != nil {
		t.Error("the CSR reached the CA")
	}
}

func TestSignCSR_ReportsAKMSKeyThatDoesNotParse(t *testing.T) {
	ca := issuancetest.NewCA(t)
	key := issuancetest.RSAKey(t)
	kms := &issuancetest.KMS{Keys: map[string][]byte{"rpi/fleet": []byte("not a key")}}
	_, err := SignCSR(context.Background(), ca, kms, &CSR{PEM: issuancetest.CSR(t, key, "rpi/fleet")})
	var publicErr *KMSPublicKeyError
	if !errors.As(err, &publicErr) || publicErr.KeyID != "rpi/fleet" {
		t.Fatalf("err = %T %v, want KMSPublicKeyError", err, err)
	}
	if IsInvalidRequest(err) {
		t.Error("an unreadable KMS key is not the caller's error")
	}
	if ca.Opts != nil {
		t.Error("the CSR reached the CA")
	}
}

func TestSignCSR_ReportsACAFailure(t *testing.T) {
	ca := issuancetest.NewCA(t)
	ca.Err = errors.New("the CA is sealed")
	key := issuancetest.RSAKey(t)
	_, err := SignCSR(context.Background(), ca, issuancetest.NewKMS(t, "rpi/fleet", &key.PublicKey),
		&CSR{PEM: issuancetest.CSR(t, key, "rpi/fleet")})
	var signErr *SignCSRError
	if !errors.As(err, &signErr) || signErr.CommonName != "rpi/fleet" || !errors.Is(err, ca.Err) {
		t.Fatalf("err = %v, want SignCSRError wrapping the CA's", err)
	}
	if IsInvalidRequest(err) {
		t.Error("a CA failure is not the caller's error")
	}
}

// Certifying a key for code signing needs ca:sign-csr; ca:write, which
// issues ordinary certificates, and a caller with no platform token at all
// (mTLS, a legacy validator) are refused.
func TestAuthorizeSignCSR(t *testing.T) {
	cases := []struct {
		name    string
		authCtx *platformtoken.AuthorizedContext
		allowed bool
	}{
		{"no platform token", nil, false},
		{"ca:write", &platformtoken.AuthorizedContext{Scopes: []string{"ca:write"}}, false},
		{"every other ca scope", &platformtoken.AuthorizedContext{Scopes: []string{"ca:read", "ca:write", "ca:delete", "kms:write"}}, false},
		{"*:write", &platformtoken.AuthorizedContext{Scopes: []string{"*:write"}}, false},
		{"ca:sign-csr", &platformtoken.AuthorizedContext{Scopes: []string{"ca:sign-csr"}}, true},
		{"ca:*", &platformtoken.AuthorizedContext{Scopes: []string{"ca:*"}}, true},
		{"*:*", &platformtoken.AuthorizedContext{Scopes: []string{"*:*"}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := AuthorizeSignCSR(tc.authCtx)
			if tc.allowed {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			var denied *SignCSRScopeError
			if !errors.As(err, &denied) {
				t.Fatalf("err = %T %v, want SignCSRScopeError", err, err)
			}
			if IsInvalidRequest(err) {
				t.Error("a missing scope is not a request the caller can fix by changing it")
			}
		})
	}
}

func TestSignCSRScopeError_NamesTheScope(t *testing.T) {
	err := AuthorizeSignCSR(nil)
	if want := "signing a CSR requires a platform token granting ca:sign-csr: the caller presented no platform token"; err.Error() != want {
		t.Errorf("Error() = %q, want %q", err, want)
	}
}

// refused signs csr, requires the caller's error, and requires that the CSR
// never reached the CA.
func refused(t *testing.T, kms KMS, csr []byte) error {
	t.Helper()
	ca := issuancetest.NewCA(t)
	_, err := SignCSR(context.Background(), ca, kms, &CSR{PEM: csr})
	if err == nil {
		t.Fatal("want an error")
	}
	if !IsInvalidRequest(err) {
		t.Errorf("%v: a refused CSR is the caller's error", err)
	}
	if ca.Opts != nil {
		t.Error("a refused CSR reached the CA")
	}
	return err
}
