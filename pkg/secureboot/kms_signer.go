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
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"io"
	"strings"

	"google.golang.org/grpc"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// KMSSignClient is the slice of the platform KeyManagementService client a
// KMS-held Secure Boot key signs through. platform.Client.KMS() satisfies it.
type KMSSignClient interface {
	Sign(ctx context.Context, in *platformv1.SignRequest, opts ...grpc.CallOption) (*platformv1.SignResponse, error)
}

// CertificateGetter is the slice of the platform CA service client a KMS-held
// key's certificate is fetched through. platform.Client.CA() satisfies it.
type CertificateGetter interface {
	GetCertificate(ctx context.Context, in *platformv1.GetCertificateRequest, opts ...grpc.CallOption) (*platformv1.GetCertificateResponse, error)
}

// NewKMSSigner resolves a Secure Boot key held in the platform KMS — the DB
// key, for resign-mode remote — over an authenticated platform client: a
// node's IDevID mTLS client after install, an operator's client at build
// time. The certificate is fetched from the CA by certURI, or by the key's
// identifier when certURI is empty. A certURI of the form
// kms://<ref>#sha256=<fingerprint> pins the certificate: one whose DER has
// another SHA-256 fingerprint is refused. The signer sends only digests to
// the KMS; the private key never leaves it.
func NewKMSSigner(ctx context.Context, kms KMSSignClient, ca CertificateGetter, keyURI, certURI string) (crypto.Signer, *x509.Certificate, error) {
	keyID := KMSKeyID(keyURI)
	if keyID == "" {
		return nil, nil, &KMSKeyRefError{KeyURI: keyURI}
	}
	certRef, pin, err := splitCertPin(certURI)
	if err != nil {
		return nil, nil, err
	}
	if certRef == "" {
		certRef = keyID
	}
	cert, err := FetchKMSCertificate(ctx, ca, certRef)
	if err != nil {
		return nil, nil, err
	}
	if err := checkCertPin(cert, certRef, pin); err != nil {
		return nil, nil, err
	}
	signer, err := NewKMSKeySigner(kms, keyID, cert.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return signer, cert, nil
}

// NewKMSKeySigner is a signer for the KMS-held key keyURI whose public key
// the caller already holds — the KMS's own report of it, for a key that has
// no certificate yet and signs its own certificate signing request. The
// signer sends only digests to the KMS; the private key never leaves it.
func NewKMSKeySigner(kms KMSSignClient, keyURI string, public crypto.PublicKey) (crypto.Signer, error) {
	keyID := KMSKeyID(keyURI)
	if keyID == "" {
		return nil, &KMSKeyRefError{KeyURI: keyURI}
	}
	if public == nil {
		return nil, &KMSPublicKeyError{KeyID: keyID}
	}
	return &kmsSigner{kms: kms, keyID: keyID, public: public}, nil
}

// FetchKMSCertificate fetches and parses the certificate the platform CA
// holds for ref.
func FetchKMSCertificate(ctx context.Context, ca CertificateGetter, ref string) (*x509.Certificate, error) {
	resp, err := ca.GetCertificate(ctx, &platformv1.GetCertificateRequest{Serial: ref, IncludePem: true})
	if err != nil {
		return nil, &KMSCertificateError{Ref: ref, Err: err}
	}
	if resp.GetCertificate() == nil || len(resp.GetCertificate().GetPem()) == 0 {
		return nil, &KMSCertificateError{Ref: ref, Err: &MessageError{Msg: "the CA returned no certificate"}}
	}
	block, _ := pem.Decode(resp.GetCertificate().GetPem())
	if block == nil {
		return nil, &KMSCertificateError{Ref: ref, Err: &MessageError{Msg: "the certificate is not PEM"}}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, &KMSCertificateError{Ref: ref, Err: err}
	}
	return cert, nil
}

// KMSKeyID is ref without a leading kms:// scheme (case-insensitive): the
// KMS key identifier. Any other ref is returned unchanged.
func KMSKeyID(ref string) string {
	const scheme = "kms://"
	if len(ref) >= len(scheme) && strings.EqualFold(ref[:len(scheme)], scheme) {
		return ref[len(scheme):]
	}
	return ref
}

// certPinMarker separates a cert-uri's reference from its pin.
const certPinMarker = "#sha256="

// splitCertPin splits certURI into the CA reference, without its kms://
// scheme, and the pinned SHA-256 fingerprint as lowercase hex. The pin may be
// written with or without colons, in either case — as `platformctl ca` and
// `openssl x509 -fingerprint -sha256` print it. A certURI without a pin has
// an empty one.
func splitCertPin(certURI string) (ref, pin string, err error) {
	ref, pin, pinned := strings.Cut(certURI, certPinMarker)
	ref = KMSKeyID(ref)
	if !pinned {
		return ref, "", nil
	}
	pin = strings.ToLower(strings.ReplaceAll(pin, ":", ""))
	sum, decodeErr := hex.DecodeString(pin)
	if ref == "" || decodeErr != nil || len(sum) != sha256.Size {
		return "", "", &CertPinFormatError{CertURI: certURI}
	}
	return ref, pin, nil
}

// checkCertPin requires that cert's DER has the SHA-256 fingerprint pin. An
// empty pin pins nothing.
func checkCertPin(cert *x509.Certificate, ref, pin string) error {
	if pin == "" {
		return nil
	}
	sum := sha256.Sum256(cert.Raw)
	if got := hex.EncodeToString(sum[:]); got != pin {
		return &CertPinError{Ref: ref, Want: pin, Got: got}
	}
	return nil
}

// kmsSigner is a crypto.Signer whose key stays in the platform KMS.
type kmsSigner struct {
	kms    KMSSignClient
	keyID  string
	public crypto.PublicKey
}

var _ crypto.Signer = (*kmsSigner)(nil)

// Public is the KMS-held key's public key.
func (s *kmsSigner) Public() crypto.PublicKey { return s.public }

// Sign sends the digest to the KMS with PreHashed set, so the KMS signs it
// as given instead of hashing it a second time. An Ed25519 key signs the
// message itself, which is sent as is.
func (s *kmsSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	req := &platformv1.SignRequest{KeyId: s.keyID, Message: digest}
	if _, pure := s.public.(ed25519.PublicKey); !pure || opts.HashFunc() != 0 {
		// Pure Ed25519 is the one signature crypto.Signer asks for without a
		// hash function: it signs the message itself, so there is no digest
		// to send PreHashed.
		hashAlg, err := kmsHashAlgorithm(opts.HashFunc())
		if err != nil {
			return nil, err
		}
		req.HashAlgorithm = hashAlg
		req.PreHashed = true
	}
	resp, err := s.kms.Sign(context.Background(), req)
	if err != nil {
		return nil, &KMSSignError{KeyID: s.keyID, Err: err}
	}
	if len(resp.GetSignature()) == 0 {
		return nil, &KMSSignError{KeyID: s.keyID, Err: &MessageError{Msg: "the KMS returned an empty signature"}}
	}
	return resp.GetSignature(), nil
}

// kmsHashAlgorithm maps the Authenticode digest's hash to the KMS's.
func kmsHashAlgorithm(h crypto.Hash) (platformv1.HashAlgorithm, error) {
	switch h {
	case crypto.SHA256:
		return platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256, nil
	case crypto.SHA384:
		return platformv1.HashAlgorithm_HASH_ALGORITHM_SHA384, nil
	case crypto.SHA512:
		return platformv1.HashAlgorithm_HASH_ALGORITHM_SHA512, nil
	}
	return platformv1.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED, &UnsupportedHashError{Hash: h.String()}
}
