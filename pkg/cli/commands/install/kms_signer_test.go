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

package install

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// fakeKMSClient is a test double for the platform KMS Sign RPC. It signs the
// request Message (already a digest, PreHashed semantics) with an in-memory RSA
// key so the resulting signature can be verified against the companion
// certificate's public key.
type fakeKMSClient struct {
	key      *rsa.PrivateKey
	lastReq  *platformv1.SignRequest
	signErr  error
	emptySig bool
}

func (f *fakeKMSClient) Sign(_ context.Context, in *platformv1.SignRequest, _ ...grpc.CallOption) (*platformv1.SignResponse, error) {
	f.lastReq = in
	if f.signErr != nil {
		return nil, f.signErr
	}
	if f.emptySig {
		return &platformv1.SignResponse{}, nil
	}
	h, err := goHashForProto(in.GetHashAlgorithm())
	if err != nil {
		return nil, err
	}
	// PreHashed: the KMS signs the supplied digest directly (Message IS the
	// already-computed Authenticode hash), never re-hashing it.
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, h, in.GetMessage())
	if err != nil {
		return nil, err
	}
	return &platformv1.SignResponse{Signature: sig}, nil
}

func goHashForProto(a platformv1.HashAlgorithm) (crypto.Hash, error) {
	switch a {
	case platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256:
		return crypto.SHA256, nil
	case platformv1.HashAlgorithm_HASH_ALGORITHM_SHA384:
		return crypto.SHA384, nil
	case platformv1.HashAlgorithm_HASH_ALGORITHM_SHA512:
		return crypto.SHA512, nil
	default:
		return 0, errors.New("unsupported hash")
	}
}

// fakeCAClient is a test double for the platform CA GetCertificate RPC.
type fakeCAClient struct {
	pem    []byte
	getErr error
	nilSet bool
}

func (f *fakeCAClient) GetCertificate(_ context.Context, _ *platformv1.GetCertificateRequest, _ ...grpc.CallOption) (*platformv1.GetCertificateResponse, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	if f.nilSet {
		return &platformv1.GetCertificateResponse{}, nil
	}
	return &platformv1.GetCertificateResponse{
		Certificate: &platformv1.Certificate{Pem: f.pem},
	}, nil
}

func genSignerCert(t *testing.T, cn string) (*rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// TestKMSDBSigner_RoundTripsDigest verifies the post-install KMS-backed signer
// sends the pre-computed digest as the Sign request Message (PreHashed
// semantics), threads the key id and hash algorithm, and returns a signature
// that verifies against the DB certificate's public key.
func TestKMSDBSigner_RoundTripsDigest(t *testing.T) {
	key, certPEM := genSignerCert(t, "db")
	cert, err := parseCertPEMBytes(certPEM)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	fake := &fakeKMSClient{key: key}
	signer := &kmsDBSigner{kms: fake, keyID: "platform/secureboot/db", public: cert.PublicKey}

	digest := sha256.Sum256([]byte("rebuilt-uki"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Request shape: key id, the digest as Message, SHA-256 hash algorithm.
	if fake.lastReq.GetKeyId() != "platform/secureboot/db" {
		t.Errorf("KeyId = %q, want platform/secureboot/db", fake.lastReq.GetKeyId())
	}
	if !bytes.Equal(fake.lastReq.GetMessage(), digest[:]) {
		t.Errorf("Message = %x, want the digest %x", fake.lastReq.GetMessage(), digest[:])
	}
	if fake.lastReq.GetHashAlgorithm() != platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256 {
		t.Errorf("HashAlgorithm = %v, want SHA256", fake.lastReq.GetHashAlgorithm())
	}
	if !fake.lastReq.GetPreHashed() {
		t.Error("PreHashed = false, want true: the KMS would double-hash the digest")
	}

	// The signature must verify against the DB certificate over the SAME digest,
	// proving the digest round-tripped without a double hash.
	if err := rsa.VerifyPKCS1v15(cert.PublicKey.(*rsa.PublicKey), crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("signature does not verify against the DB certificate: %v", err)
	}

	// Public() must match the DB certificate.
	if sp, ok := signer.Public().(*rsa.PublicKey); !ok || !sp.Equal(cert.PublicKey) {
		t.Error("Public() does not match the DB certificate")
	}
}

// TestKMSDBSigner_Errors verifies a KMS failure and an empty signature are mapped
// to distinct typed errors.
func TestKMSDBSigner_Errors(t *testing.T) {
	key, _ := genSignerCert(t, "db")
	digest := sha256.Sum256([]byte("x"))

	t.Run("kms error", func(t *testing.T) {
		signer := &kmsDBSigner{kms: &fakeKMSClient{key: key, signErr: errors.New("kms down")}, keyID: "k", public: &key.PublicKey}
		_, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
		var rse ErrRemoteSignFailed
		if !errors.As(err, &rse) {
			t.Fatalf("expected ErrRemoteSignFailed, got %T: %v", err, err)
		}
	})

	t.Run("empty signature", func(t *testing.T) {
		signer := &kmsDBSigner{kms: &fakeKMSClient{key: key, emptySig: true}, keyID: "k", public: &key.PublicKey}
		_, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
		var rse ErrRemoteSignEmpty
		if !errors.As(err, &rse) {
			t.Fatalf("expected ErrRemoteSignEmpty, got %T: %v", err, err)
		}
	})

	t.Run("unsupported hash", func(t *testing.T) {
		signer := &kmsDBSigner{kms: &fakeKMSClient{key: key}, keyID: "k", public: &key.PublicKey}
		_, err := signer.Sign(rand.Reader, digest[:], crypto.MD5)
		var uh ErrUnsupportedHash
		if !errors.As(err, &uh) {
			t.Fatalf("expected ErrUnsupportedHash, got %T: %v", err, err)
		}
	})
}

// TestProtoHashAlgorithm verifies the crypto.Hash -> platform HashAlgorithm map
// covers the SHA-2 family and rejects everything else.
func TestProtoHashAlgorithm(t *testing.T) {
	cases := []struct {
		in   crypto.Hash
		want platformv1.HashAlgorithm
	}{
		{crypto.SHA256, platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256},
		{crypto.SHA384, platformv1.HashAlgorithm_HASH_ALGORITHM_SHA384},
		{crypto.SHA512, platformv1.HashAlgorithm_HASH_ALGORITHM_SHA512},
	}
	for _, c := range cases {
		got, err := protoHashAlgorithm(c.in)
		if err != nil {
			t.Errorf("protoHashAlgorithm(%v) error: %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("protoHashAlgorithm(%v) = %v, want %v", c.in, got, c.want)
		}
	}
	if _, err := protoHashAlgorithm(crypto.SHA1); err == nil {
		t.Error("expected an error for SHA1")
	}
}

// TestFetchDBCertificate verifies certificate fetch+parse, plus the empty and
// malformed responses.
func TestFetchDBCertificate(t *testing.T) {
	_, certPEM := genSignerCert(t, "db")

	t.Run("ok", func(t *testing.T) {
		cert, err := fetchDBCertificate(context.Background(), &fakeCAClient{pem: certPEM}, "ref")
		if err != nil {
			t.Fatalf("fetchDBCertificate: %v", err)
		}
		if cert == nil || cert.Subject.CommonName != "db" {
			t.Fatalf("unexpected certificate %v", cert)
		}
	})

	t.Run("empty", func(t *testing.T) {
		_, err := fetchDBCertificate(context.Background(), &fakeCAClient{nilSet: true}, "ref")
		var e ErrRemoteCertEmpty
		if !errors.As(err, &e) {
			t.Fatalf("expected ErrRemoteCertEmpty, got %T: %v", err, err)
		}
	})

	t.Run("malformed pem", func(t *testing.T) {
		_, err := fetchDBCertificate(context.Background(), &fakeCAClient{pem: []byte("not a pem")}, "ref")
		var e ErrRemoteCertDecode
		if !errors.As(err, &e) {
			t.Fatalf("expected ErrRemoteCertDecode, got %T: %v", err, err)
		}
	})

	t.Run("rpc error", func(t *testing.T) {
		_, err := fetchDBCertificate(context.Background(), &fakeCAClient{getErr: errors.New("boom")}, "ref")
		if err == nil {
			t.Fatal("expected an error from a failing CA RPC")
		}
	})
}

// TestStripKMSScheme verifies the kms:// scheme is stripped case-insensitively.
func TestStripKMSScheme(t *testing.T) {
	cases := map[string]string{
		"kms://platform/secureboot/db": "platform/secureboot/db",
		"KMS://platform/db":            "platform/db",
		"platform/db":                  "platform/db",
		"":                             "",
	}
	for in, want := range cases {
		if got := stripKMSScheme(in); got != want {
			t.Errorf("stripKMSScheme(%q) = %q, want %q", in, got, want)
		}
	}
}

// parseCertPEMBytes is a small test helper mirroring the production PEM parse.
func parseCertPEMBytes(p []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(p)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

// TestNewRemoteSignerSeam_EmptyKeyURI verifies the seam constructor rejects a DB
// key URI that yields no KMS key identifier before opening any SDK connection.
func TestNewRemoteSignerSeam_EmptyKeyURI(t *testing.T) {
	sb := &installer.SecureBootConfig{Enabled: true, ResignMode: installer.SecureBootResignModeRemote}
	_, _, err := newRemoteSignerSeam(&cli.CommonFlags{}, sb)
	var e ErrRemoteSignKeyRef
	if !errors.As(err, &e) {
		t.Fatalf("expected ErrRemoteSignKeyRef, got %T: %v", err, err)
	}
}
