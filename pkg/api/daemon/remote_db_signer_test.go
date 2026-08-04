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

package daemon

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"testing"
	"time"

	cryptoclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/crypto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// fakeDigestSigner emulates the server-side KMS crypto client: it signs the
// supplied (pre-hashed) digest with a known RSA key so the test can verify the
// result against the companion certificate.
type fakeDigestSigner struct {
	key     *rsa.PrivateKey
	calls   int
	lastReq *cryptoclient.SignRequest
	err     error
}

func (f *fakeDigestSigner) Sign(_ context.Context, req *cryptoclient.SignRequest) (*cryptoclient.SignResponse, error) {
	f.calls++
	f.lastReq = req
	if f.err != nil {
		return nil, f.err
	}
	var h crypto.Hash
	switch req.HashAlg {
	case cryptoclient.HashSHA256:
		h = crypto.SHA256
	case cryptoclient.HashSHA384:
		h = crypto.SHA384
	case cryptoclient.HashSHA512:
		h = crypto.SHA512
	default:
		return nil, errors.New("unexpected hash algorithm")
	}
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, h, req.Data)
	if err != nil {
		return nil, err
	}
	return &cryptoclient.SignResponse{Signature: sig}, nil
}

// fakeCertResolver returns a fixed certificate (or error) for any common name.
type fakeCertResolver struct {
	cert   *x509.Certificate
	err    error
	lastCN string
}

func (f *fakeCertResolver) GetCertificate(cn string) (*x509.Certificate, error) {
	f.lastCN = cn
	if f.err != nil {
		return nil, f.err
	}
	return f.cert, nil
}

func dbSignerTestLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelError, nil)
}

// newDBSignerKeyAndCert generates an RSA key and a self-signed certificate over
// it, mirroring how a Secure Boot DB keypair is provisioned in the CP-KMS.
func newDBSignerKeyAndCert(t *testing.T, cn string) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return key, cert
}

// TestRemoteDBKeySigner_SignAndVerify verifies the signer strips the kms://
// scheme, signs the pre-hashed digest with PreHashed=true, and returns a
// signature that verifies against the certificate it hands back.
func TestRemoteDBKeySigner_SignAndVerify(t *testing.T) {
	const cn = "Trusted Platform Secure Boot DB"
	key, cert := newDBSignerKeyAndCert(t, cn)
	signer := &fakeDigestSigner{key: key}
	certs := &fakeCertResolver{cert: cert}
	s := NewRemoteDBKeySigner(signer, certs, dbSignerTestLogger())

	digest := sha256.Sum256([]byte("the UKI authenticode hash"))
	sig, err := s.SignDigest(context.Background(), "kms://platform/secureboot/db", digest[:])
	if err != nil {
		t.Fatalf("unexpected sign error: %v", err)
	}
	if signer.calls != 1 {
		t.Fatalf("expected 1 sign call, got %d", signer.calls)
	}
	if signer.lastReq.KeyID != "platform/secureboot/db" {
		t.Fatalf("expected stripped key id, got %q", signer.lastReq.KeyID)
	}
	if !signer.lastReq.PreHashed {
		t.Fatal("expected PreHashed=true for digest signing")
	}
	if signer.lastReq.HashAlg != cryptoclient.HashSHA256 {
		t.Fatalf("expected SHA-256 hash alg, got %v", signer.lastReq.HashAlg)
	}

	// The signature must verify against the returned certificate's public key.
	pemBytes, err := s.Certificate(context.Background(), cn)
	if err != nil {
		t.Fatalf("unexpected certificate error: %v", err)
	}
	if certs.lastCN != cn {
		t.Fatalf("certificate resolved by %q, want %q", certs.lastCN, cn)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("returned certificate is not valid PEM")
	}
	returned, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse returned cert: %v", err)
	}
	pub, ok := returned.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("returned cert public key is %T, want *rsa.PublicKey", returned.PublicKey)
	}
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("signature did not verify against returned certificate: %v", err)
	}
}

// TestRemoteDBKeySigner_SignErrors covers the SignDigest error paths: empty key
// reference, unsupported digest length, and an underlying KMS failure.
func TestRemoteDBKeySigner_SignErrors(t *testing.T) {
	key, cert := newDBSignerKeyAndCert(t, "db")

	t.Run("empty key ref", func(t *testing.T) {
		s := NewRemoteDBKeySigner(&fakeDigestSigner{key: key}, &fakeCertResolver{cert: cert}, dbSignerTestLogger())
		_, err := s.SignDigest(context.Background(), "kms://", sha256.New().Sum(nil))
		var keyRefErr ErrDBSignerKeyRef
		if !errors.As(err, &keyRefErr) {
			t.Fatalf("expected ErrDBSignerKeyRef, got %T: %v", err, err)
		}
	})

	t.Run("unsupported digest length", func(t *testing.T) {
		s := NewRemoteDBKeySigner(&fakeDigestSigner{key: key}, &fakeCertResolver{cert: cert}, dbSignerTestLogger())
		_, err := s.SignDigest(context.Background(), "kms://platform/secureboot/db", []byte("short"))
		var unsupported ErrUnsupportedDigest
		if !errors.As(err, &unsupported) {
			t.Fatalf("expected ErrUnsupportedDigest, got %T: %v", err, err)
		}
	})

	t.Run("kms failure", func(t *testing.T) {
		signer := &fakeDigestSigner{key: key, err: errors.New("kms down")}
		s := NewRemoteDBKeySigner(signer, &fakeCertResolver{cert: cert}, dbSignerTestLogger())
		digest := sha256.Sum256([]byte("x"))
		_, err := s.SignDigest(context.Background(), "kms://platform/secureboot/db", digest[:])
		var signErr ErrDBSign
		if !errors.As(err, &signErr) {
			t.Fatalf("expected ErrDBSign, got %T: %v", err, err)
		}
	})
}

// TestRemoteDBKeySigner_CertificateErrors covers the Certificate error paths:
// empty reference and an unknown certificate in the store.
func TestRemoteDBKeySigner_CertificateErrors(t *testing.T) {
	key, _ := newDBSignerKeyAndCert(t, "db")

	t.Run("empty cert ref", func(t *testing.T) {
		s := NewRemoteDBKeySigner(&fakeDigestSigner{key: key}, &fakeCertResolver{}, dbSignerTestLogger())
		_, err := s.Certificate(context.Background(), "")
		var certErr ErrDBCert
		if !errors.As(err, &certErr) {
			t.Fatalf("expected ErrDBCert, got %T: %v", err, err)
		}
	})

	t.Run("unknown certificate", func(t *testing.T) {
		certs := &fakeCertResolver{err: errors.New("not found")}
		s := NewRemoteDBKeySigner(&fakeDigestSigner{key: key}, certs, dbSignerTestLogger())
		_, err := s.Certificate(context.Background(), "missing-cn")
		var certErr ErrDBCert
		if !errors.As(err, &certErr) {
			t.Fatalf("expected ErrDBCert, got %T: %v", err, err)
		}
	})
}

// TestNewRemoteDBKeySignerFromApp_NilApp verifies the convenience constructor
// reports unavailability rather than panicking when no app is provided.
func TestNewRemoteDBKeySignerFromApp_NilApp(t *testing.T) {
	_, err := NewRemoteDBKeySignerFromApp(nil, dbSignerTestLogger())
	var unavailable ErrDBSignerUnavailable
	if !errors.As(err, &unavailable) {
		t.Fatalf("expected ErrDBSignerUnavailable, got %T: %v", err, err)
	}
}
