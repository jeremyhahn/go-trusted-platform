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

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrImageNotFound(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrImageNotFound
		expected string
	}{
		{
			name:     "with reference and cause",
			err:      ErrImageNotFound{Reference: "nginx:latest", Err: errors.New("404 not found")},
			expected: "image not found: nginx:latest: 404 not found",
		},
		{
			name:     "with reference only",
			err:      ErrImageNotFound{Reference: "nginx:latest"},
			expected: "image not found: nginx:latest",
		},
		{
			name:     "empty",
			err:      ErrImageNotFound{},
			expected: "image not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrImageNotFound_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := ErrImageNotFound{Reference: "test", Err: cause}

	unwrapped := err.Unwrap()
	assert.Equal(t, cause, unwrapped)
	assert.True(t, errors.Is(err, cause))

	errNoCause := ErrImageNotFound{Reference: "test"}
	assert.Nil(t, errNoCause.Unwrap())
}

func TestErrSignatureNotFound(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrSignatureNotFound
		expected string
	}{
		{
			name:     "with digest and cause",
			err:      ErrSignatureNotFound{ImageDigest: "sha256:abc123", Err: errors.New("not found")},
			expected: "signature not found for image sha256:abc123: not found",
		},
		{
			name:     "with digest only",
			err:      ErrSignatureNotFound{ImageDigest: "sha256:abc123"},
			expected: "signature not found for image sha256:abc123",
		},
		{
			name:     "empty",
			err:      ErrSignatureNotFound{},
			expected: "signature not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrSignatureNotFound_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := ErrSignatureNotFound{ImageDigest: "sha256:test", Err: cause}

	unwrapped := err.Unwrap()
	assert.Equal(t, cause, unwrapped)
	assert.True(t, errors.Is(err, cause))
}

func TestErrInvalidSignature(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrInvalidSignature
		expected string
	}{
		{
			name:     "with reason and cause",
			err:      ErrInvalidSignature{Reason: "malformed", Err: errors.New("parse error")},
			expected: "invalid signature: malformed: parse error",
		},
		{
			name:     "with reason only",
			err:      ErrInvalidSignature{Reason: "malformed"},
			expected: "invalid signature: malformed",
		},
		{
			name:     "empty",
			err:      ErrInvalidSignature{},
			expected: "invalid signature",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrInvalidSignature_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := ErrInvalidSignature{Reason: "test", Err: cause}

	unwrapped := err.Unwrap()
	assert.Equal(t, cause, unwrapped)
	assert.True(t, errors.Is(err, cause))
}

func TestErrCertificateExpired(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrCertificateExpired
		expected string
	}{
		{
			name:     "with subject and expiry",
			err:      ErrCertificateExpired{Subject: "CN=test", ExpiredAt: "2024-01-01"},
			expected: "certificate expired: CN=test expired at 2024-01-01",
		},
		{
			name:     "with subject only",
			err:      ErrCertificateExpired{Subject: "CN=test"},
			expected: "certificate expired: CN=test",
		},
		{
			name:     "empty",
			err:      ErrCertificateExpired{},
			expected: "certificate has expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrCertificateRevoked(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrCertificateRevoked
		expected string
	}{
		{
			name:     "with subject and revocation time",
			err:      ErrCertificateRevoked{Subject: "CN=test", RevokedAt: "2024-01-01"},
			expected: "certificate revoked: CN=test revoked at 2024-01-01",
		},
		{
			name:     "with subject only",
			err:      ErrCertificateRevoked{Subject: "CN=test"},
			expected: "certificate revoked: CN=test",
		},
		{
			name:     "empty",
			err:      ErrCertificateRevoked{},
			expected: "certificate has been revoked",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrUntrustedSigner(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrUntrustedSigner
		expected string
	}{
		{
			name:     "with identity and reason",
			err:      ErrUntrustedSigner{SignerIdentity: "CN=attacker", Reason: "not in trust store"},
			expected: "untrusted signer CN=attacker: not in trust store",
		},
		{
			name:     "with identity only",
			err:      ErrUntrustedSigner{SignerIdentity: "CN=attacker"},
			expected: "untrusted signer: CN=attacker",
		},
		{
			name:     "with reason only",
			err:      ErrUntrustedSigner{Reason: "not in trust store"},
			expected: "untrusted signer: not in trust store",
		},
		{
			name:     "empty",
			err:      ErrUntrustedSigner{},
			expected: "signer is not trusted",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrInvalidImageReference(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrInvalidImageReference
		expected string
	}{
		{
			name:     "with reference and reason",
			err:      ErrInvalidImageReference{Reference: "invalid::ref", Reason: "too many colons"},
			expected: "invalid image reference invalid::ref: too many colons",
		},
		{
			name:     "with reference only",
			err:      ErrInvalidImageReference{Reference: "invalid::ref"},
			expected: "invalid image reference: invalid::ref",
		},
		{
			name:     "with reason only",
			err:      ErrInvalidImageReference{Reason: "empty reference"},
			expected: "invalid image reference: empty reference",
		},
		{
			name:     "empty",
			err:      ErrInvalidImageReference{},
			expected: "invalid image reference",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrSigningFailed(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrSigningFailed
		expected string
	}{
		{
			name:     "with all fields",
			err:      ErrSigningFailed{ImageDigest: "sha256:abc", Reason: "key error", Err: errors.New("permission denied")},
			expected: "signing failed for image sha256:abc: key error: permission denied",
		},
		{
			name:     "with digest and reason",
			err:      ErrSigningFailed{ImageDigest: "sha256:abc", Reason: "key error"},
			expected: "signing failed for image sha256:abc: key error",
		},
		{
			name:     "with digest only",
			err:      ErrSigningFailed{ImageDigest: "sha256:abc"},
			expected: "signing failed for image sha256:abc",
		},
		{
			name:     "with reason only",
			err:      ErrSigningFailed{Reason: "key error"},
			expected: "signing failed: key error",
		},
		{
			name:     "empty",
			err:      ErrSigningFailed{},
			expected: "signing failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrSigningFailed_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := ErrSigningFailed{Reason: "test", Err: cause}

	unwrapped := err.Unwrap()
	assert.Equal(t, cause, unwrapped)
	assert.True(t, errors.Is(err, cause))
}

func TestErrVerificationFailed(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrVerificationFailed
		expected string
	}{
		{
			name:     "with all fields",
			err:      ErrVerificationFailed{ImageDigest: "sha256:abc", Step: "signature_check", Reason: "mismatch", Err: errors.New("crypto error")},
			expected: "verification failed for image sha256:abc at step signature_check: mismatch: crypto error",
		},
		{
			name:     "with digest, step, and reason",
			err:      ErrVerificationFailed{ImageDigest: "sha256:abc", Step: "signature_check", Reason: "mismatch"},
			expected: "verification failed for image sha256:abc at step signature_check: mismatch",
		},
		{
			name:     "with digest and step",
			err:      ErrVerificationFailed{ImageDigest: "sha256:abc", Step: "signature_check"},
			expected: "verification failed for image sha256:abc at step signature_check",
		},
		{
			name:     "with digest and reason",
			err:      ErrVerificationFailed{ImageDigest: "sha256:abc", Reason: "mismatch"},
			expected: "verification failed for image sha256:abc: mismatch",
		},
		{
			name:     "empty",
			err:      ErrVerificationFailed{},
			expected: "verification failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrVerificationFailed_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := ErrVerificationFailed{Step: "test", Err: cause}

	unwrapped := err.Unwrap()
	assert.Equal(t, cause, unwrapped)
	assert.True(t, errors.Is(err, cause))
}

func TestErrRegistryAccessDenied(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrRegistryAccessDenied
		expected string
	}{
		{
			name:     "with registry and reason",
			err:      ErrRegistryAccessDenied{Registry: "docker.io", Reason: "invalid credentials"},
			expected: "access denied to registry docker.io: invalid credentials",
		},
		{
			name:     "with registry only",
			err:      ErrRegistryAccessDenied{Registry: "docker.io"},
			expected: "access denied to registry docker.io",
		},
		{
			name:     "with reason only",
			err:      ErrRegistryAccessDenied{Reason: "invalid credentials"},
			expected: "registry access denied: invalid credentials",
		},
		{
			name:     "empty",
			err:      ErrRegistryAccessDenied{},
			expected: "registry access denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrRegistryAccessDenied_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := ErrRegistryAccessDenied{Registry: "test", Err: cause}

	unwrapped := err.Unwrap()
	assert.Equal(t, cause, unwrapped)
	assert.True(t, errors.Is(err, cause))
}

func TestErrRegistryUnavailable(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrRegistryUnavailable
		expected string
	}{
		{
			name:     "with registry and reason",
			err:      ErrRegistryUnavailable{Registry: "docker.io", Reason: "connection timeout"},
			expected: "registry unavailable docker.io: connection timeout",
		},
		{
			name:     "with registry only",
			err:      ErrRegistryUnavailable{Registry: "docker.io"},
			expected: "registry unavailable: docker.io",
		},
		{
			name:     "with reason only",
			err:      ErrRegistryUnavailable{Reason: "connection timeout"},
			expected: "registry unavailable: connection timeout",
		},
		{
			name:     "empty",
			err:      ErrRegistryUnavailable{},
			expected: "registry unavailable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrRegistryUnavailable_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := ErrRegistryUnavailable{Registry: "test", Err: cause}

	unwrapped := err.Unwrap()
	assert.Equal(t, cause, unwrapped)
	assert.True(t, errors.Is(err, cause))
}

func TestErrInvalidManifest(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrInvalidManifest
		expected string
	}{
		{
			name:     "with digest and reason",
			err:      ErrInvalidManifest{ImageDigest: "sha256:abc", Reason: "malformed JSON"},
			expected: "invalid manifest for image sha256:abc: malformed JSON",
		},
		{
			name:     "with digest only",
			err:      ErrInvalidManifest{ImageDigest: "sha256:abc"},
			expected: "invalid manifest for image sha256:abc",
		},
		{
			name:     "with reason only",
			err:      ErrInvalidManifest{Reason: "malformed JSON"},
			expected: "invalid manifest: malformed JSON",
		},
		{
			name:     "empty",
			err:      ErrInvalidManifest{},
			expected: "invalid manifest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrInvalidManifest_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := ErrInvalidManifest{ImageDigest: "test", Err: cause}

	unwrapped := err.Unwrap()
	assert.Equal(t, cause, unwrapped)
	assert.True(t, errors.Is(err, cause))
}

func TestErrKeyNotFound(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrKeyNotFound
		expected string
	}{
		{
			name:     "with path and reason",
			err:      ErrKeyNotFound{KeyPath: "/path/to/key", Reason: "file not found"},
			expected: "key not found at /path/to/key: file not found",
		},
		{
			name:     "with path only",
			err:      ErrKeyNotFound{KeyPath: "/path/to/key"},
			expected: "key not found: /path/to/key",
		},
		{
			name:     "with reason only",
			err:      ErrKeyNotFound{Reason: "file not found"},
			expected: "key not found: file not found",
		},
		{
			name:     "empty",
			err:      ErrKeyNotFound{},
			expected: "signing key not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrKeyNotFound_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := ErrKeyNotFound{KeyPath: "test", Err: cause}

	unwrapped := err.Unwrap()
	assert.Equal(t, cause, unwrapped)
	assert.True(t, errors.Is(err, cause))
}

func TestErrCertificateNotFound(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrCertificateNotFound
		expected string
	}{
		{
			name:     "with path and reason",
			err:      ErrCertificateNotFound{CertPath: "/path/to/cert", Reason: "file not found"},
			expected: "certificate not found at /path/to/cert: file not found",
		},
		{
			name:     "with path only",
			err:      ErrCertificateNotFound{CertPath: "/path/to/cert"},
			expected: "certificate not found: /path/to/cert",
		},
		{
			name:     "with reason only",
			err:      ErrCertificateNotFound{Reason: "file not found"},
			expected: "certificate not found: file not found",
		},
		{
			name:     "empty",
			err:      ErrCertificateNotFound{},
			expected: "signing certificate not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrCertificateNotFound_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := ErrCertificateNotFound{CertPath: "test", Err: cause}

	unwrapped := err.Unwrap()
	assert.Equal(t, cause, unwrapped)
	assert.True(t, errors.Is(err, cause))
}

func TestErrInvalidKeyType(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrInvalidKeyType
		expected string
	}{
		{
			name:     "with type and expected",
			err:      ErrInvalidKeyType{KeyType: "DSA", Expected: "RSA or ECDSA"},
			expected: "invalid key type DSA, expected RSA or ECDSA",
		},
		{
			name:     "with type only",
			err:      ErrInvalidKeyType{KeyType: "DSA"},
			expected: "invalid key type: DSA",
		},
		{
			name:     "empty",
			err:      ErrInvalidKeyType{},
			expected: "invalid key type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrTimestampFailed(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrTimestampFailed
		expected string
	}{
		{
			name:     "with URL and reason",
			err:      ErrTimestampFailed{TSAUrl: "https://tsa.example.com", Reason: "connection refused"},
			expected: "timestamp failed from https://tsa.example.com: connection refused",
		},
		{
			name:     "with URL only",
			err:      ErrTimestampFailed{TSAUrl: "https://tsa.example.com"},
			expected: "timestamp failed from https://tsa.example.com",
		},
		{
			name:     "with reason only",
			err:      ErrTimestampFailed{Reason: "connection refused"},
			expected: "timestamp failed: connection refused",
		},
		{
			name:     "empty",
			err:      ErrTimestampFailed{},
			expected: "timestamp operation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrTimestampFailed_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := ErrTimestampFailed{TSAUrl: "test", Err: cause}

	unwrapped := err.Unwrap()
	assert.Equal(t, cause, unwrapped)
	assert.True(t, errors.Is(err, cause))
}

func TestErrNilParameter(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrNilParameter
		expected string
	}{
		{
			name:     "with parameter name",
			err:      ErrNilParameter{Parameter: "opts"},
			expected: "nil parameter: opts",
		},
		{
			name:     "empty",
			err:      ErrNilParameter{},
			expected: "nil parameter provided",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrInvalidDigest(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrInvalidDigest
		expected string
	}{
		{
			name:     "with digest and reason",
			err:      ErrInvalidDigest{Digest: "sha256:invalid", Reason: "invalid hex characters"},
			expected: "invalid digest sha256:invalid: invalid hex characters",
		},
		{
			name:     "with digest only",
			err:      ErrInvalidDigest{Digest: "sha256:invalid"},
			expected: "invalid digest: sha256:invalid",
		},
		{
			name:     "with reason only",
			err:      ErrInvalidDigest{Reason: "missing algorithm prefix"},
			expected: "invalid digest: missing algorithm prefix",
		},
		{
			name:     "empty",
			err:      ErrInvalidDigest{},
			expected: "invalid digest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrUnsupportedAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrUnsupportedAlgorithm
		expected string
	}{
		{
			name:     "with algorithm and supported list",
			err:      ErrUnsupportedAlgorithm{Algorithm: "MD5", Supported: []string{"SHA256", "SHA384", "SHA512"}},
			expected: "unsupported algorithm MD5, supported: [SHA256 SHA384 SHA512]",
		},
		{
			name:     "with algorithm only",
			err:      ErrUnsupportedAlgorithm{Algorithm: "MD5"},
			expected: "unsupported algorithm: MD5",
		},
		{
			name:     "empty",
			err:      ErrUnsupportedAlgorithm{},
			expected: "unsupported algorithm",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrorsImplementError(t *testing.T) {
	// Verify all error types implement the error interface
	var _ error = ErrImageNotFound{}
	var _ error = ErrSignatureNotFound{}
	var _ error = ErrInvalidSignature{}
	var _ error = ErrCertificateExpired{}
	var _ error = ErrCertificateRevoked{}
	var _ error = ErrUntrustedSigner{}
	var _ error = ErrInvalidImageReference{}
	var _ error = ErrSigningFailed{}
	var _ error = ErrVerificationFailed{}
	var _ error = ErrRegistryAccessDenied{}
	var _ error = ErrRegistryUnavailable{}
	var _ error = ErrInvalidManifest{}
	var _ error = ErrKeyNotFound{}
	var _ error = ErrCertificateNotFound{}
	var _ error = ErrInvalidKeyType{}
	var _ error = ErrTimestampFailed{}
	var _ error = ErrNilParameter{}
	var _ error = ErrInvalidDigest{}
	var _ error = ErrUnsupportedAlgorithm{}
}
