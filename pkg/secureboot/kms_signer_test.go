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

package secureboot

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc"

	"github.com/jeremyhahn/go-trusted-platform/pkg/secureboot/secureboottest"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestNewKMSSigner_RoundTripsDigest proves the digest reaches the KMS as
// given (PreHashed, no second hash) and the signature verifies against the
// certificate the CA holds for the key.
func TestNewKMSSigner_RoundTripsDigest(t *testing.T) {
	key, dbCert := secureboottest.KeyPair(t, "db")
	kms, ca := &secureboottest.KMS{Key: key}, &secureboottest.CA{Certs: map[string]*x509.Certificate{"platform/secureboot/db": dbCert, "certs/db": dbCert}}

	signer, cert, err := NewKMSSigner(context.Background(), kms, ca, "KMS://platform/secureboot/db", "")
	if err != nil {
		t.Fatal(err)
	}
	if ca.LastRef != "platform/secureboot/db" {
		t.Errorf("certificate fetched by %q, want the key id when no cert-uri is set", ca.LastRef)
	}
	digest := sha256.Sum256([]byte("uki"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	req := kms.LastReq
	if req.GetKeyId() != "platform/secureboot/db" || !bytes.Equal(req.GetMessage(), digest[:]) ||
		req.GetHashAlgorithm() != platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256 || !req.GetPreHashed() {
		t.Errorf("sign request = %v", req)
	}
	if err := rsa.VerifyPKCS1v15(cert.PublicKey.(*rsa.PublicKey), crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("signature does not verify against the certificate: %v", err)
	}
	if pub, ok := signer.Public().(*rsa.PublicKey); !ok || !pub.Equal(cert.PublicKey) {
		t.Error("Public() is not the certificate's key")
	}

	if _, _, err := NewKMSSigner(context.Background(), kms, ca, "kms://db", "kms://certs/db"); err != nil || ca.LastRef != "certs/db" {
		t.Errorf("an explicit cert-uri fetched %q, err %v", ca.LastRef, err)
	}
}

func TestNewKMSSigner_Errors(t *testing.T) {
	key, dbCert := secureboottest.KeyPair(t, "db")
	good := func() *secureboottest.CA {
		return &secureboottest.CA{Certs: map[string]*x509.Certificate{"db": dbCert}}
	}
	digest := sha256.Sum256([]byte("x"))

	var refErr *KMSKeyRefError
	if _, _, err := NewKMSSigner(context.Background(), &secureboottest.KMS{Key: key}, good(), "", ""); !errors.As(err, &refErr) {
		t.Errorf("empty key-uri: %v", err)
	}
	for name, ca := range map[string]*secureboottest.CA{
		"rpc error":  {Err: errors.New("boom")},
		"no cert":    {Raw: map[string][]byte{"db": nil}},
		"not pem":    {Raw: map[string][]byte{"db": []byte("not a pem")}},
		"not a cert": {Raw: map[string][]byte{"db": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")})}},
	} {
		var certErr *KMSCertificateError
		if _, _, err := NewKMSSigner(context.Background(), &secureboottest.KMS{Key: key}, ca, "kms://db", ""); !errors.As(err, &certErr) {
			t.Errorf("%s: %v", name, err)
		}
	}

	var signErr *KMSSignError
	for name, kms := range map[string]*secureboottest.KMS{
		"kms error":       {Key: key, Err: errors.New("kms down")},
		"empty signature": {Key: key, Empty: true},
	} {
		signer, _, err := NewKMSSigner(context.Background(), kms, good(), "kms://db", "")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256); !errors.As(err, &signErr) {
			t.Errorf("%s: %v", name, err)
		}
	}
	signer, _, err := NewKMSSigner(context.Background(), &secureboottest.KMS{Key: key}, good(), "kms://db", "")
	if err != nil {
		t.Fatal(err)
	}
	var hashErr *UnsupportedHashError
	if _, err := signer.Sign(rand.Reader, digest[:], crypto.MD5); !errors.As(err, &hashErr) {
		t.Errorf("unsupported hash: %v", err)
	}
}

// ed25519KMS signs the request's message with an Ed25519 key, as a KMS does
// for a pure Ed25519 key.
type ed25519KMS struct {
	key     ed25519.PrivateKey
	LastReq *platformv1.SignRequest
}

func (k *ed25519KMS) Sign(_ context.Context, in *platformv1.SignRequest, _ ...grpc.CallOption) (*platformv1.SignResponse, error) {
	k.LastReq = in
	return &platformv1.SignResponse{Signature: ed25519.Sign(k.key, in.GetMessage())}, nil
}

// TestNewKMSKeySigner_Ed25519SignsTheMessage: x509.CreateCertificateRequest
// hands an Ed25519 signer the whole request with no hash function, which the
// KMS has to receive as the message, not as a digest.
func TestNewKMSKeySigner_Ed25519SignsTheMessage(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kms := &ed25519KMS{key: private}
	signer, err := NewKMSKeySigner(kms, "kms://rpi/fleet", public)
	if err != nil {
		t.Fatal(err)
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "rpi/fleet"}}, signer)
	if err != nil {
		t.Fatalf("a CSR for an Ed25519 KMS key: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Errorf("the KMS's signature does not verify: %v", err)
	}
	if kms.LastReq.GetPreHashed() || kms.LastReq.GetHashAlgorithm() != platformv1.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED ||
		!bytes.Equal(kms.LastReq.GetMessage(), csr.RawTBSCertificateRequest) {
		t.Errorf("sign request = %v, want the request's TBS bytes, not pre-hashed", kms.LastReq)
	}
}

// A key that is not Ed25519 still needs a hash function: without one there is
// no digest to send PreHashed.
func TestNewKMSKeySigner_NoHashIsRefusedForOtherKeys(t *testing.T) {
	key, _ := secureboottest.KeyPair(t, "db")
	kms := &secureboottest.KMS{Key: key}
	signer, err := NewKMSKeySigner(kms, "kms://db", &key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	var hashErr *UnsupportedHashError
	if _, err := signer.Sign(rand.Reader, []byte("message"), crypto.Hash(0)); !errors.As(err, &hashErr) {
		t.Errorf("no hash function with an RSA key: %v", err)
	}
	if kms.LastReq != nil {
		t.Error("the KMS was contacted")
	}
}

// A cert-uri pinned with #sha256= signs only with the certificate whose
// DER has that fingerprint, in the forms the CLI and openssl print it, and
// refuses any other certificate the CA returns for the reference.
func TestNewKMSSigner_PinnedCertificate(t *testing.T) {
	key, dbCert := secureboottest.KeyPair(t, "db")
	_, otherCert := secureboottest.KeyPair(t, "db")
	sum := sha256.Sum256(dbCert.Raw)
	pin := hex.EncodeToString(sum[:])

	for name, certURI := range map[string]string{
		"lowercase hex":      "kms://certs/db#sha256=" + pin,
		"openssl colon form": "kms://certs/db#sha256=" + strings.ToUpper(colonHex(sum[:])),
	} {
		t.Run(name, func(t *testing.T) {
			ca := &secureboottest.CA{Certs: map[string]*x509.Certificate{"certs/db": dbCert}}
			_, cert, err := NewKMSSigner(context.Background(), &secureboottest.KMS{Key: key}, ca, "kms://db", certURI)
			if err != nil {
				t.Fatal(err)
			}
			if ca.LastRef != "certs/db" || !cert.Equal(dbCert) {
				t.Errorf("fetched %q, got the pinned certificate = %v", ca.LastRef, cert.Equal(dbCert))
			}
		})
	}

	t.Run("another certificate under the reference", func(t *testing.T) {
		ca := &secureboottest.CA{Certs: map[string]*x509.Certificate{"db": otherCert}}
		var pinErr *CertPinError
		_, _, err := NewKMSSigner(context.Background(), &secureboottest.KMS{Key: key}, ca, "kms://db", "kms://db#sha256="+pin)
		if !errors.As(err, &pinErr) || pinErr.Ref != "db" || pinErr.Want != pin {
			t.Fatalf("err = %v, want a CertPinError for db", err)
		}
	})

	for name, certURI := range map[string]string{
		"empty pin":    "kms://db#sha256=",
		"not hex":      "kms://db#sha256=" + strings.Repeat("zz", sha256.Size),
		"short":        "kms://db#sha256=" + pin[:10],
		"no reference": "#sha256=" + pin,
	} {
		t.Run(name, func(t *testing.T) {
			ca := &secureboottest.CA{Certs: map[string]*x509.Certificate{"db": dbCert}}
			var formatErr *CertPinFormatError
			if _, _, err := NewKMSSigner(context.Background(), &secureboottest.KMS{Key: key}, ca, "kms://db", certURI); !errors.As(err, &formatErr) {
				t.Fatalf("err = %v, want a CertPinFormatError", err)
			}
			if ca.LastRef != "" {
				t.Errorf("a malformed pin still fetched %q from the CA", ca.LastRef)
			}
		})
	}
}

// colonHex is b as colon-separated hex pairs, the form openssl prints a
// fingerprint in.
func colonHex(b []byte) string {
	pairs := make([]string, len(b))
	for i, c := range b {
		pairs[i] = hex.EncodeToString([]byte{c})
	}
	return strings.Join(pairs, ":")
}

func TestCertPinErrors_Name(t *testing.T) {
	if msg := (&CertPinError{Ref: "rpi/fleet", Want: "aa", Got: "bb"}).Error(); !strings.Contains(msg, "rpi/fleet") || !strings.Contains(msg, "aa") || !strings.Contains(msg, "bb") {
		t.Errorf("CertPinError = %q", msg)
	}
	if msg := (&CertPinFormatError{CertURI: "kms://x#sha256=q"}).Error(); !strings.Contains(msg, "kms://x#sha256=q") {
		t.Errorf("CertPinFormatError = %q", msg)
	}
}

// A key with no certificate yet signs with the public key the caller holds.
func TestNewKMSKeySigner_SignsWithTheGivenKey(t *testing.T) {
	key, _ := secureboottest.KeyPair(t, "fleet")
	kms := &secureboottest.KMS{Key: key}

	signer, err := NewKMSKeySigner(kms, "kms://rpi/fleet", &key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("boot.img"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if kms.LastReq.GetKeyId() != "rpi/fleet" {
		t.Errorf("signed with key %q, want rpi/fleet", kms.LastReq.GetKeyId())
	}
	if err := rsa.VerifyPKCS1v15(signer.Public().(*rsa.PublicKey), crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("signature does not verify against Public(): %v", err)
	}
}

func TestNewKMSKeySigner_Errors(t *testing.T) {
	key, _ := secureboottest.KeyPair(t, "fleet")
	kms := &secureboottest.KMS{Key: key}

	var refErr *KMSKeyRefError
	if _, err := NewKMSKeySigner(kms, "kms://", &key.PublicKey); !errors.As(err, &refErr) {
		t.Errorf("empty key-uri: %v", err)
	}
	var pubErr *KMSPublicKeyError
	if _, err := NewKMSKeySigner(kms, "rpi/fleet", nil); !errors.As(err, &pubErr) {
		t.Errorf("no public key: %v", err)
	}
}

func TestKMSHashAlgorithm(t *testing.T) {
	for h, want := range map[crypto.Hash]platformv1.HashAlgorithm{
		crypto.SHA256: platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256,
		crypto.SHA384: platformv1.HashAlgorithm_HASH_ALGORITHM_SHA384,
		crypto.SHA512: platformv1.HashAlgorithm_HASH_ALGORITHM_SHA512,
	} {
		if got, err := kmsHashAlgorithm(h); err != nil || got != want {
			t.Errorf("kmsHashAlgorithm(%v) = %v, %v", h, got, err)
		}
	}
	if _, err := kmsHashAlgorithm(crypto.SHA1); err == nil {
		t.Error("SHA-1 was accepted")
	}
}

func TestKMSKeyID(t *testing.T) {
	for in, want := range map[string]string{
		"kms://platform/secureboot/db": "platform/secureboot/db",
		"KMS://platform/db":            "platform/db",
		"platform/db":                  "platform/db",
		"":                             "",
	} {
		if got := KMSKeyID(in); got != want {
			t.Errorf("KMSKeyID(%q) = %q, want %q", in, got, want)
		}
	}
}
