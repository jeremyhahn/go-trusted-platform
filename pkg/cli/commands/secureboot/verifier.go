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
	"context"
	"crypto"
	"crypto/x509"
	"io"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/authenticode"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/uefi"
)

// newUKIVerifier builds an Authenticode verifier bound to the Secure Boot DB
// certificate. Verification requires no private key, so the signer is backed
// by a verify-only keystore backend; every signing operation on it fails with
// a typed error.
func newUKIVerifier(ctx context.Context, dbCert *x509.Certificate, logger *logging.Logger) (uefi.UKIVerifier, error) {
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	signer, err := authenticode.NewSigner(ctx, &authenticode.SignerOptions{
		KeyStore:      &verifyOnlyBackend{public: dbCert.PublicKey},
		KeyAttributes: &xkmssdk.KeyAttributes{CN: "secure-boot-verify"},
		Certificate:   dbCert,
		Logger:        logger,
	})
	if err != nil {
		return nil, ErrVerifierBuild{Cause: err}
	}
	return signer, nil
}

// verifyOnlyBackend is a keystore backend that supports only signature
// verification. It intentionally holds no private key material: the CLI never
// needs the DB private key to verify a signed UKI against the DB certificate.
// Its Signer exposes the DB certificate public key so the Authenticode signer
// constructs, while any signing attempt fails with a typed error.
type verifyOnlyBackend struct {
	public crypto.PublicKey
}

// verifyOnlySigner is the crypto.Signer returned by verifyOnlyBackend. It
// carries only the public half; Sign always fails with a typed error.
type verifyOnlySigner struct {
	public crypto.PublicKey
}

func (s *verifyOnlySigner) Public() crypto.PublicKey { return s.public }

func (s *verifyOnlySigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return nil, ErrVerifyOnlyBackend{Operation: "Sign"}
}

func (b *verifyOnlyBackend) Type() xkmssdk.BackendType {
	return "verify"
}

func (b *verifyOnlyBackend) Capabilities() xkmssdk.Capabilities {
	return xkmssdk.Capabilities{}
}

func (b *verifyOnlyBackend) Signer(ctx context.Context, attrs *xkmssdk.KeyAttributes) (crypto.Signer, error) {
	return &verifyOnlySigner{public: b.public}, nil
}

func (b *verifyOnlyBackend) GenerateKey(ctx context.Context, attrs *xkmssdk.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, ErrVerifyOnlyBackend{Operation: "GenerateKey"}
}

func (b *verifyOnlyBackend) GetKey(ctx context.Context, attrs *xkmssdk.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, ErrVerifyOnlyBackend{Operation: "GetKey"}
}

func (b *verifyOnlyBackend) DeleteKey(ctx context.Context, attrs *xkmssdk.KeyAttributes) error {
	return ErrVerifyOnlyBackend{Operation: "DeleteKey"}
}

func (b *verifyOnlyBackend) ListKeys(ctx context.Context) ([]*xkmssdk.KeyAttributes, error) {
	return nil, nil
}

func (b *verifyOnlyBackend) Decrypter(ctx context.Context, attrs *xkmssdk.KeyAttributes) (crypto.Decrypter, error) {
	return nil, ErrVerifyOnlyBackend{Operation: "Decrypter"}
}

func (b *verifyOnlyBackend) RotateKey(ctx context.Context, attrs *xkmssdk.KeyAttributes) error {
	return ErrVerifyOnlyBackend{Operation: "RotateKey"}
}

func (b *verifyOnlyBackend) Close() error {
	return nil
}
