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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

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
