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

package authenticode

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// KeyFileStage names the step at which loading a PEM key or certificate
// failed.
type KeyFileStage string

const (
	KeyFileRead   KeyFileStage = "read"
	KeyFileDecode KeyFileStage = "decode"
	KeyFileParse  KeyFileStage = "parse"
)

// KeyFileError reports a PEM private key that could not be loaded.
type KeyFileError struct {
	Path  string
	Stage KeyFileStage
	Err   error
}

func (e *KeyFileError) Error() string {
	return fmt.Sprintf("authenticode: %s private key %s: %v", e.Stage, e.Path, e.Err)
}

func (e *KeyFileError) Unwrap() error { return e.Err }

// CertFileError reports a PEM certificate that could not be loaded.
type CertFileError struct {
	Path  string
	Stage KeyFileStage
	Err   error
}

func (e *CertFileError) Error() string {
	return fmt.Sprintf("authenticode: %s certificate %s: %v", e.Stage, e.Path, e.Err)
}

func (e *CertFileError) Unwrap() error { return e.Err }

// errNoPEMBlock is the decode-stage cause when a file holds no PEM block.
var errNoPEMBlock = &MessageError{Msg: "no PEM block"}

// errNotASigner is the cause when a parsed key cannot sign.
var errNotASigner = &MessageError{Msg: "private key does not implement crypto.Signer"}

// LoadPrivateKeyPEM reads a PKCS#1 or PKCS#8 private key from a PEM file.
func LoadPrivateKeyPEM(path string) (crypto.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &KeyFileError{Path: path, Stage: KeyFileRead, Err: err}
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, &KeyFileError{Path: path, Stage: KeyFileDecode, Err: errNoPEMBlock}
	}
	var key crypto.PrivateKey
	if block.Type == "RSA PRIVATE KEY" {
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	} else {
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	if err != nil {
		return nil, &KeyFileError{Path: path, Stage: KeyFileParse, Err: err}
	}
	if _, ok := key.(crypto.Signer); !ok {
		return nil, &KeyFileError{Path: path, Stage: KeyFileParse, Err: errNotASigner}
	}
	return key, nil
}

// LoadCertificate reads an X.509 certificate from a PEM or raw DER file.
func LoadCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &CertFileError{Path: path, Stage: KeyFileRead, Err: err}
	}
	der := data
	if block, _ := pem.Decode(data); block != nil {
		der = block.Bytes
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, &CertFileError{Path: path, Stage: KeyFileParse, Err: err}
	}
	return cert, nil
}

// KeyCertMismatchError reports a signing key whose public key is not the
// certificate's: a signature it made would not verify against that
// certificate.
type KeyCertMismatchError struct{}

func (e *KeyCertMismatchError) Error() string {
	return "authenticode: the certificate's public key does not match the signing key"
}

// LoadSigningPair reads a PEM private key and its certificate (PEM or DER)
// and checks that they belong together.
func LoadSigningPair(keyPath, certPath string) (crypto.Signer, *x509.Certificate, error) {
	key, err := LoadPrivateKeyPEM(keyPath)
	if err != nil {
		return nil, nil, err
	}
	cert, err := LoadCertificate(certPath)
	if err != nil {
		return nil, nil, err
	}
	signer := key.(crypto.Signer)
	if err := checkPair(signer, cert); err != nil {
		return nil, nil, err
	}
	return signer, cert, nil
}

// checkPair verifies that cert certifies signer's public key.
func checkPair(signer crypto.Signer, cert *x509.Certificate) error {
	pub, ok := signer.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(cert.PublicKey) {
		return &KeyCertMismatchError{}
	}
	return nil
}

// NewFileSigner builds an Authenticode signer from a PEM private key and its
// certificate on disk: the Secure Boot db key pair a build host keeps
// (`DB.key` / `DB.crt`).
func NewFileSigner(ctx context.Context, keyPath, certPath string, logger *logging.Logger) (Authenticode, error) {
	signer, cert, err := LoadSigningPair(keyPath, certPath)
	if err != nil {
		return nil, err
	}
	return NewCryptoSigner(ctx, signer, cert, logger)
}

// NewCryptoSigner builds an Authenticode signer over any crypto.Signer and
// the certificate that certifies it: a key loaded from a file, a KMS-held key
// that only ever sees digests (secureboot.NewKMSSigner), or a key resolved by
// the installer. It refuses a certificate that does not certify the key.
func NewCryptoSigner(ctx context.Context, signer crypto.Signer, cert *x509.Certificate, logger *logging.Logger) (Authenticode, error) {
	if signer == nil {
		return nil, &MessageError{Msg: "authenticode: no signing key"}
	}
	if cert == nil {
		return nil, &MessageError{Msg: "authenticode: no certificate"}
	}
	if err := checkPair(signer, cert); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	return NewSigner(ctx, &SignerOptions{
		KeyStore:      &signerBackend{signer: signer},
		KeyAttributes: &xkmssdk.KeyAttributes{CN: "secure-boot-db"},
		Certificate:   cert,
		Logger:        logger,
	})
}

// signerBackend is the KeyProvider over one crypto.Signer. It signs and hands
// back that key; every other key operation is refused.
type signerBackend struct {
	signer crypto.Signer
}

func (b *signerBackend) Type() xkmssdk.BackendType { return "crypto-signer" }

func (b *signerBackend) Capabilities() xkmssdk.Capabilities {
	return xkmssdk.Capabilities{Keys: true, Signing: true}
}

func (b *signerBackend) Signer(_ context.Context, _ *xkmssdk.KeyAttributes) (crypto.Signer, error) {
	return b.signer, nil
}

func (b *signerBackend) GetKey(_ context.Context, _ *xkmssdk.KeyAttributes) (crypto.PrivateKey, error) {
	return b.signer, nil
}

func (b *signerBackend) GenerateKey(_ context.Context, _ *xkmssdk.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, &MessageError{Msg: "crypto-signer backend: keys are not generated here"}
}

func (b *signerBackend) DeleteKey(_ context.Context, _ *xkmssdk.KeyAttributes) error {
	return &MessageError{Msg: "crypto-signer backend: keys are not deleted here"}
}

func (b *signerBackend) ListKeys(_ context.Context) ([]*xkmssdk.KeyAttributes, error) {
	return nil, nil
}

func (b *signerBackend) Decrypter(_ context.Context, _ *xkmssdk.KeyAttributes) (crypto.Decrypter, error) {
	return nil, &MessageError{Msg: "crypto-signer backend: decryption is not offered"}
}

func (b *signerBackend) RotateKey(_ context.Context, _ *xkmssdk.KeyAttributes) error {
	return &MessageError{Msg: "crypto-signer backend: keys are not rotated here"}
}

func (b *signerBackend) Close() error { return nil }
