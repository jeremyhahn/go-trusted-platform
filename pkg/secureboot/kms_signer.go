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
// identifier when certURI is empty. The signer sends only digests to the
// KMS; the private key never leaves it.
func NewKMSSigner(ctx context.Context, kms KMSSignClient, ca CertificateGetter, keyURI, certURI string) (crypto.Signer, *x509.Certificate, error) {
	keyID := KMSKeyID(keyURI)
	if keyID == "" {
		return nil, nil, &KMSKeyRefError{KeyURI: keyURI}
	}
	certRef := KMSKeyID(certURI)
	if certRef == "" {
		certRef = keyID
	}
	cert, err := FetchKMSCertificate(ctx, ca, certRef)
	if err != nil {
		return nil, nil, err
	}
	return &kmsSigner{kms: kms, keyID: keyID, public: cert.PublicKey}, cert, nil
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

// kmsSigner is a crypto.Signer whose key stays in the platform KMS.
type kmsSigner struct {
	kms    KMSSignClient
	keyID  string
	public crypto.PublicKey
}

var _ crypto.Signer = (*kmsSigner)(nil)

// Public is the public key of the key's certificate.
func (s *kmsSigner) Public() crypto.PublicKey { return s.public }

// Sign sends the digest to the KMS with PreHashed set, so the KMS signs it
// as given instead of hashing it a second time.
func (s *kmsSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hashAlg, err := kmsHashAlgorithm(opts.HashFunc())
	if err != nil {
		return nil, err
	}
	resp, err := s.kms.Sign(context.Background(), &platformv1.SignRequest{
		KeyId:         s.keyID,
		Message:       digest,
		HashAlgorithm: hashAlg,
		PreHashed:     true,
	})
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
