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

package image

import "fmt"

// ErrImageNotFound is returned when the specified image cannot be found in the registry.
type ErrImageNotFound struct {
	Reference string
	Err       error
}

func (e ErrImageNotFound) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("image not found: %s: %v", e.Reference, e.Err)
	}
	if e.Reference != "" {
		return fmt.Sprintf("image not found: %s", e.Reference)
	}
	return "image not found"
}

func (e ErrImageNotFound) Unwrap() error {
	return e.Err
}

// ErrSignatureNotFound is returned when no signature exists for the specified image.
type ErrSignatureNotFound struct {
	ImageDigest string
	Err         error
}

func (e ErrSignatureNotFound) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("signature not found for image %s: %v", e.ImageDigest, e.Err)
	}
	if e.ImageDigest != "" {
		return fmt.Sprintf("signature not found for image %s", e.ImageDigest)
	}
	return "signature not found"
}

func (e ErrSignatureNotFound) Unwrap() error {
	return e.Err
}

// ErrInvalidSignature is returned when the signature is malformed or cannot be parsed.
type ErrInvalidSignature struct {
	Reason string
	Err    error
}

func (e ErrInvalidSignature) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("invalid signature: %s: %v", e.Reason, e.Err)
	}
	if e.Reason != "" {
		return fmt.Sprintf("invalid signature: %s", e.Reason)
	}
	return "invalid signature"
}

func (e ErrInvalidSignature) Unwrap() error {
	return e.Err
}

// ErrCertificateExpired is returned when the signing certificate has expired.
type ErrCertificateExpired struct {
	Subject   string
	ExpiredAt string
}

func (e ErrCertificateExpired) Error() string {
	if e.Subject != "" && e.ExpiredAt != "" {
		return fmt.Sprintf("certificate expired: %s expired at %s", e.Subject, e.ExpiredAt)
	}
	if e.Subject != "" {
		return fmt.Sprintf("certificate expired: %s", e.Subject)
	}
	return "certificate has expired"
}

// ErrCertificateRevoked is returned when the signing certificate has been revoked.
type ErrCertificateRevoked struct {
	Subject    string
	SerialNum  string
	RevokedAt  string
	RevokeType string
}

func (e ErrCertificateRevoked) Error() string {
	if e.Subject != "" && e.RevokedAt != "" {
		return fmt.Sprintf("certificate revoked: %s revoked at %s", e.Subject, e.RevokedAt)
	}
	if e.Subject != "" {
		return fmt.Sprintf("certificate revoked: %s", e.Subject)
	}
	return "certificate has been revoked"
}

// ErrUntrustedSigner is returned when the signer is not in the trust chain.
type ErrUntrustedSigner struct {
	SignerIdentity string
	Reason         string
}

func (e ErrUntrustedSigner) Error() string {
	if e.SignerIdentity != "" && e.Reason != "" {
		return fmt.Sprintf("untrusted signer %s: %s", e.SignerIdentity, e.Reason)
	}
	if e.SignerIdentity != "" {
		return fmt.Sprintf("untrusted signer: %s", e.SignerIdentity)
	}
	if e.Reason != "" {
		return fmt.Sprintf("untrusted signer: %s", e.Reason)
	}
	return "signer is not trusted"
}

// ErrInvalidImageReference is returned when the image reference cannot be parsed.
type ErrInvalidImageReference struct {
	Reference string
	Reason    string
}

func (e ErrInvalidImageReference) Error() string {
	if e.Reference != "" && e.Reason != "" {
		return fmt.Sprintf("invalid image reference %s: %s", e.Reference, e.Reason)
	}
	if e.Reference != "" {
		return fmt.Sprintf("invalid image reference: %s", e.Reference)
	}
	if e.Reason != "" {
		return fmt.Sprintf("invalid image reference: %s", e.Reason)
	}
	return "invalid image reference"
}

// ErrSigningFailed is returned when the signing operation fails.
type ErrSigningFailed struct {
	ImageDigest string
	Reason      string
	Err         error
}

func (e ErrSigningFailed) Error() string {
	msg := "signing failed"
	if e.ImageDigest != "" {
		msg = fmt.Sprintf("signing failed for image %s", e.ImageDigest)
	}
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	if e.Err != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Err)
	}
	return msg
}

func (e ErrSigningFailed) Unwrap() error {
	return e.Err
}

// ErrVerificationFailed is returned when signature verification fails.
type ErrVerificationFailed struct {
	ImageDigest string
	Step        string
	Reason      string
	Err         error
}

func (e ErrVerificationFailed) Error() string {
	msg := "verification failed"
	if e.ImageDigest != "" {
		msg = fmt.Sprintf("verification failed for image %s", e.ImageDigest)
	}
	if e.Step != "" {
		msg = fmt.Sprintf("%s at step %s", msg, e.Step)
	}
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	if e.Err != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Err)
	}
	return msg
}

func (e ErrVerificationFailed) Unwrap() error {
	return e.Err
}

// ErrRegistryAccessDenied is returned when access to the registry is denied.
type ErrRegistryAccessDenied struct {
	Registry string
	Reason   string
	Err      error
}

func (e ErrRegistryAccessDenied) Error() string {
	if e.Registry != "" && e.Reason != "" {
		return fmt.Sprintf("access denied to registry %s: %s", e.Registry, e.Reason)
	}
	if e.Registry != "" {
		return fmt.Sprintf("access denied to registry %s", e.Registry)
	}
	if e.Reason != "" {
		return fmt.Sprintf("registry access denied: %s", e.Reason)
	}
	return "registry access denied"
}

func (e ErrRegistryAccessDenied) Unwrap() error {
	return e.Err
}

// ErrRegistryUnavailable is returned when the registry is unavailable.
type ErrRegistryUnavailable struct {
	Registry string
	Reason   string
	Err      error
}

func (e ErrRegistryUnavailable) Error() string {
	if e.Registry != "" && e.Reason != "" {
		return fmt.Sprintf("registry unavailable %s: %s", e.Registry, e.Reason)
	}
	if e.Registry != "" {
		return fmt.Sprintf("registry unavailable: %s", e.Registry)
	}
	if e.Reason != "" {
		return fmt.Sprintf("registry unavailable: %s", e.Reason)
	}
	return "registry unavailable"
}

func (e ErrRegistryUnavailable) Unwrap() error {
	return e.Err
}

// ErrInvalidManifest is returned when the image manifest is invalid.
type ErrInvalidManifest struct {
	ImageDigest string
	Reason      string
	Err         error
}

func (e ErrInvalidManifest) Error() string {
	if e.ImageDigest != "" && e.Reason != "" {
		return fmt.Sprintf("invalid manifest for image %s: %s", e.ImageDigest, e.Reason)
	}
	if e.ImageDigest != "" {
		return fmt.Sprintf("invalid manifest for image %s", e.ImageDigest)
	}
	if e.Reason != "" {
		return fmt.Sprintf("invalid manifest: %s", e.Reason)
	}
	return "invalid manifest"
}

func (e ErrInvalidManifest) Unwrap() error {
	return e.Err
}

// ErrKeyNotFound is returned when the signing key cannot be found.
type ErrKeyNotFound struct {
	KeyPath string
	Reason  string
	Err     error
}

func (e ErrKeyNotFound) Error() string {
	if e.KeyPath != "" && e.Reason != "" {
		return fmt.Sprintf("key not found at %s: %s", e.KeyPath, e.Reason)
	}
	if e.KeyPath != "" {
		return fmt.Sprintf("key not found: %s", e.KeyPath)
	}
	if e.Reason != "" {
		return fmt.Sprintf("key not found: %s", e.Reason)
	}
	return "signing key not found"
}

func (e ErrKeyNotFound) Unwrap() error {
	return e.Err
}

// ErrCertificateNotFound is returned when the signing certificate cannot be found.
type ErrCertificateNotFound struct {
	CertPath string
	Reason   string
	Err      error
}

func (e ErrCertificateNotFound) Error() string {
	if e.CertPath != "" && e.Reason != "" {
		return fmt.Sprintf("certificate not found at %s: %s", e.CertPath, e.Reason)
	}
	if e.CertPath != "" {
		return fmt.Sprintf("certificate not found: %s", e.CertPath)
	}
	if e.Reason != "" {
		return fmt.Sprintf("certificate not found: %s", e.Reason)
	}
	return "signing certificate not found"
}

func (e ErrCertificateNotFound) Unwrap() error {
	return e.Err
}

// ErrInvalidKeyType is returned when the key type is not supported.
type ErrInvalidKeyType struct {
	KeyType  string
	Expected string
}

func (e ErrInvalidKeyType) Error() string {
	if e.KeyType != "" && e.Expected != "" {
		return fmt.Sprintf("invalid key type %s, expected %s", e.KeyType, e.Expected)
	}
	if e.KeyType != "" {
		return fmt.Sprintf("invalid key type: %s", e.KeyType)
	}
	return "invalid key type"
}

// ErrTimestampFailed is returned when the timestamp operation fails.
type ErrTimestampFailed struct {
	TSAUrl string
	Reason string
	Err    error
}

func (e ErrTimestampFailed) Error() string {
	if e.TSAUrl != "" && e.Reason != "" {
		return fmt.Sprintf("timestamp failed from %s: %s", e.TSAUrl, e.Reason)
	}
	if e.TSAUrl != "" {
		return fmt.Sprintf("timestamp failed from %s", e.TSAUrl)
	}
	if e.Reason != "" {
		return fmt.Sprintf("timestamp failed: %s", e.Reason)
	}
	return "timestamp operation failed"
}

func (e ErrTimestampFailed) Unwrap() error {
	return e.Err
}

// ErrTimestampVerificationFailed is returned when timestamp token verification fails.
type ErrTimestampVerificationFailed struct {
	Step   string
	Reason string
	Err    error
}

func (e ErrTimestampVerificationFailed) Error() string {
	msg := "timestamp verification failed"
	if e.Step != "" {
		msg = fmt.Sprintf("%s at step %s", msg, e.Step)
	}
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	if e.Err != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Err)
	}
	return msg
}

func (e ErrTimestampVerificationFailed) Unwrap() error {
	return e.Err
}

// ErrInvalidTimestampToken is returned when the timestamp token is malformed.
type ErrInvalidTimestampToken struct {
	Reason string
	Err    error
}

func (e ErrInvalidTimestampToken) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("invalid timestamp token: %s: %v", e.Reason, e.Err)
	}
	if e.Reason != "" {
		return fmt.Sprintf("invalid timestamp token: %s", e.Reason)
	}
	return "invalid timestamp token"
}

func (e ErrInvalidTimestampToken) Unwrap() error {
	return e.Err
}

// ErrMessageImprintMismatch is returned when the message imprint does not match.
type ErrMessageImprintMismatch struct {
	Expected string
	Actual   string
}

func (e ErrMessageImprintMismatch) Error() string {
	if e.Expected != "" && e.Actual != "" {
		return fmt.Sprintf("message imprint mismatch: expected %s, got %s", e.Expected, e.Actual)
	}
	return "message imprint does not match original data"
}

// ErrNilParameter is returned when a required parameter is nil.
type ErrNilParameter struct {
	Parameter string
}

func (e ErrNilParameter) Error() string {
	if e.Parameter != "" {
		return fmt.Sprintf("nil parameter: %s", e.Parameter)
	}
	return "nil parameter provided"
}

// ErrInvalidDigest is returned when an image digest is invalid.
type ErrInvalidDigest struct {
	Digest string
	Reason string
}

func (e ErrInvalidDigest) Error() string {
	if e.Digest != "" && e.Reason != "" {
		return fmt.Sprintf("invalid digest %s: %s", e.Digest, e.Reason)
	}
	if e.Digest != "" {
		return fmt.Sprintf("invalid digest: %s", e.Digest)
	}
	if e.Reason != "" {
		return fmt.Sprintf("invalid digest: %s", e.Reason)
	}
	return "invalid digest"
}

// ErrUnsupportedAlgorithm is returned when an unsupported algorithm is specified.
type ErrUnsupportedAlgorithm struct {
	Algorithm string
	Supported []string
}

func (e ErrUnsupportedAlgorithm) Error() string {
	if e.Algorithm != "" && len(e.Supported) > 0 {
		return fmt.Sprintf("unsupported algorithm %s, supported: %v", e.Algorithm, e.Supported)
	}
	if e.Algorithm != "" {
		return fmt.Sprintf("unsupported algorithm: %s", e.Algorithm)
	}
	return "unsupported algorithm"
}
