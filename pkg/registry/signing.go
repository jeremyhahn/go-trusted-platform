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

package registry

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"regexp"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

const (
	// DefaultSigningKeyID is the key a signed push uses when it names none.
	DefaultSigningKeyID = "registry-default-signer"

	// SignatureAlgorithm names the only manifest signature scheme: ECDSA
	// over P-256 with a SHA-256 digest, ASN.1 DER encoded.
	SignatureAlgorithm = "ECDSA-P256-SHA256"

	// ManifestAnnotationSignature carries the base64 manifest signature.
	ManifestAnnotationSignature = "org.letstrust.registry.signature"
	// ManifestAnnotationSigningKeyID names the key that signed the manifest.
	ManifestAnnotationSigningKeyID = "org.letstrust.registry.signing-key-id"
	// ManifestAnnotationSignatureAlgorithm names the signature scheme.
	ManifestAnnotationSignatureAlgorithm = "org.letstrust.registry.signature-algorithm"
)

// signingKeyIDPattern keeps key IDs to plain names: they name files in the
// key store.
var signingKeyIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// SigningKeyStore holds the manifest signing keys. The xkms PKCS#8 backend
// (xkmssdk.NewPKCS8Backend) satisfies it.
type SigningKeyStore interface {
	GenerateKey(ctx context.Context, attrs *xkmssdk.KeyAttributes) (crypto.PrivateKey, error)
	Signer(ctx context.Context, attrs *xkmssdk.KeyAttributes) (crypto.Signer, error)
}

// ManifestSigner signs image manifests on push and verifies them on pull.
// Each key ID names an ECDSA P-256 key in the key store; a push naming a key
// that does not exist yet creates it.
type ManifestSigner struct {
	keys SigningKeyStore
}

// NewManifestSigner returns a signer whose keys live in keys.
func NewManifestSigner(keys SigningKeyStore) (*ManifestSigner, error) {
	if keys == nil {
		return nil, ErrSigningKeyStoreRequired{}
	}
	return &ManifestSigner{keys: keys}, nil
}

// Sign signs m with keyID (DefaultSigningKeyID when empty) and records the
// signature, key ID and algorithm as manifest annotations. m.Reference must
// already be set: the signature binds the manifest to its reference.
func (s *ManifestSigner) Sign(ctx context.Context, m *ImageManifest, keyID string) error {
	if keyID == "" {
		keyID = DefaultSigningKeyID
	}
	signer, err := s.signerFor(ctx, keyID, true)
	if err != nil {
		return err
	}
	if m.Annotations == nil {
		m.Annotations = make(map[string]string)
	}
	m.Annotations[ManifestAnnotationSigningKeyID] = keyID
	m.Annotations[ManifestAnnotationSignatureAlgorithm] = SignatureAlgorithm

	digest, err := manifestDigest(m)
	if err != nil {
		return ErrManifestSigningFailed{Reference: m.Reference, KeyID: keyID, Cause: err}
	}
	sig, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		return ErrManifestSigningFailed{Reference: m.Reference, KeyID: keyID, Cause: err}
	}
	m.Annotations[ManifestAnnotationSignature] = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// Verify checks the signature m carries against the key it names. A key the
// store does not hold, an unknown algorithm, or a manifest changed since it
// was signed all fail.
func (s *ManifestSigner) Verify(ctx context.Context, m *ImageManifest) error {
	keyID := m.Annotations[ManifestAnnotationSigningKeyID]
	if alg := m.Annotations[ManifestAnnotationSignatureAlgorithm]; alg != SignatureAlgorithm {
		return ErrSignatureInvalid{Reference: m.Reference, KeyID: keyID, Reason: "unsupported algorithm " + alg}
	}
	sig, err := base64.StdEncoding.DecodeString(m.Annotations[ManifestAnnotationSignature])
	if err != nil {
		return ErrSignatureInvalid{Reference: m.Reference, KeyID: keyID, Reason: "signature is not base64"}
	}
	signer, err := s.signerFor(ctx, keyID, false)
	if err != nil {
		return err
	}
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		return ErrSignatureInvalid{Reference: m.Reference, KeyID: keyID, Reason: "signing key is not ECDSA"}
	}
	digest, err := manifestDigest(m)
	if err != nil {
		return ErrSignatureInvalid{Reference: m.Reference, KeyID: keyID, Reason: err.Error()}
	}
	if !ecdsa.VerifyASN1(pub, digest, sig) {
		return ErrSignatureInvalid{Reference: m.Reference, KeyID: keyID, Reason: "signature does not match the manifest"}
	}
	return nil
}

// signerFor loads keyID's signer. With create set, a key the store does not
// hold is generated; a concurrent push that created it first is picked up by
// the second lookup.
func (s *ManifestSigner) signerFor(ctx context.Context, keyID string, create bool) (crypto.Signer, error) {
	if !signingKeyIDPattern.MatchString(keyID) {
		return nil, ErrInvalidSigningKeyID{KeyID: keyID}
	}
	attrs := signingKeyAttributes(keyID)
	signer, lookupErr := s.keys.Signer(ctx, attrs)
	if lookupErr == nil {
		return signer, nil
	}
	if !create {
		return nil, ErrSigningKeyUnavailable{KeyID: keyID, Cause: lookupErr}
	}
	if _, genErr := s.keys.GenerateKey(ctx, attrs); genErr != nil {
		if signer, err := s.keys.Signer(ctx, attrs); err == nil {
			return signer, nil
		}
		return nil, ErrSigningKeyUnavailable{KeyID: keyID, Cause: genErr}
	}
	signer, err := s.keys.Signer(ctx, attrs)
	if err != nil {
		return nil, ErrSigningKeyUnavailable{KeyID: keyID, Cause: err}
	}
	return signer, nil
}

// signingKeyAttributes describes the software ECDSA P-256 key named keyID.
func signingKeyAttributes(keyID string) *xkmssdk.KeyAttributes {
	return &xkmssdk.KeyAttributes{
		CN:            keyID,
		KeyAlgorithm:  x509.ECDSA,
		KeyType:       xkmssdk.KeyTypeSigning,
		StoreType:     xkmssdk.StoreSoftware,
		ECCAttributes: &xkmssdk.ECCAttributes{Curve: elliptic.P256()},
		Hash:          crypto.SHA256,
	}
}

// signedManifest is what a signature covers: the manifest's content and
// reference, and every annotation except the signature itself. Timestamps
// are left out; Push sets them after signing.
type signedManifest struct {
	Reference     string            `json:"reference"`
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType"`
	Config        Descriptor        `json:"config"`
	Layers        []Descriptor      `json:"layers"`
	Annotations   map[string]string `json:"annotations"`
}

// manifestDigest is the SHA-256 of the canonical JSON of m's signed fields.
// encoding/json writes map keys in sorted order, so the encoding is stable.
func manifestDigest(m *ImageManifest) ([]byte, error) {
	annotations := make(map[string]string, len(m.Annotations))
	for k, v := range m.Annotations {
		if k != ManifestAnnotationSignature {
			annotations[k] = v
		}
	}
	data, err := json.Marshal(signedManifest{
		Reference:     m.Reference,
		SchemaVersion: m.SchemaVersion,
		MediaType:     m.MediaType,
		Config:        m.Config,
		Layers:        m.Layers,
		Annotations:   annotations,
	})
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	return sum[:], nil
}

// isSigned reports whether m carries a manifest signature.
func isSigned(m *ImageManifest) bool {
	return m.Annotations[ManifestAnnotationSignature] != ""
}

// clearSignature removes every signature annotation from m.
func clearSignature(m *ImageManifest) {
	delete(m.Annotations, ManifestAnnotationSignature)
	delete(m.Annotations, ManifestAnnotationSigningKeyID)
	delete(m.Annotations, ManifestAnnotationSignatureAlgorithm)
}
