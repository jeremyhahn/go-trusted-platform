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
	"crypto"
	"crypto/x509"
	"time"
)

// SignatureFormat represents the format of the image signature.
type SignatureFormat string

const (
	// FormatCosign is the cosign signature format.
	FormatCosign SignatureFormat = "cosign"
	// FormatSigstore is the sigstore signature format.
	FormatSigstore SignatureFormat = "sigstore"
	// FormatNotation is the notation signature format.
	FormatNotation SignatureFormat = "notation"
)

// SignatureAlgorithm represents the cryptographic algorithm used for signing.
type SignatureAlgorithm string

const (
	// AlgorithmRSA256 is RSA with SHA-256.
	AlgorithmRSA256 SignatureAlgorithm = "RS256"
	// AlgorithmRSA384 is RSA with SHA-384.
	AlgorithmRSA384 SignatureAlgorithm = "RS384"
	// AlgorithmRSA512 is RSA with SHA-512.
	AlgorithmRSA512 SignatureAlgorithm = "RS512"
	// AlgorithmECDSA256 is ECDSA with P-256 and SHA-256.
	AlgorithmECDSA256 SignatureAlgorithm = "ES256"
	// AlgorithmECDSA384 is ECDSA with P-384 and SHA-384.
	AlgorithmECDSA384 SignatureAlgorithm = "ES384"
	// AlgorithmECDSA512 is ECDSA with P-521 and SHA-512.
	AlgorithmECDSA512 SignatureAlgorithm = "ES512"
)

// DigestAlgorithm represents the hash algorithm for image digests.
type DigestAlgorithm string

const (
	// DigestSHA256 is SHA-256 digest algorithm.
	DigestSHA256 DigestAlgorithm = "sha256"
	// DigestSHA384 is SHA-384 digest algorithm.
	DigestSHA384 DigestAlgorithm = "sha384"
	// DigestSHA512 is SHA-512 digest algorithm.
	DigestSHA512 DigestAlgorithm = "sha512"
)

// DefaultRegistry is the default container registry.
const DefaultRegistry = "docker.io"

// DefaultTag is the default image tag.
const DefaultTag = "latest"

// ImageReference represents a container image reference.
type ImageReference struct {
	// Registry is the container registry (e.g., "docker.io", "gcr.io").
	Registry string `json:"registry"`
	// Repository is the image repository (e.g., "library/nginx").
	Repository string `json:"repository"`
	// Tag is the image tag (e.g., "latest", "v1.0.0").
	Tag string `json:"tag,omitempty"`
	// Digest is the image digest (e.g., "sha256:abc123...").
	Digest string `json:"digest,omitempty"`
}

// ImageSignature represents a signature for a container image.
type ImageSignature struct {
	// ImageDigest is the digest of the signed image.
	ImageDigest string `json:"image_digest"`
	// SignerCert is the certificate of the signer.
	SignerCert *x509.Certificate `json:"-"`
	// SignerCertPEM is the PEM-encoded signer certificate.
	SignerCertPEM []byte `json:"signer_cert_pem,omitempty"`
	// CertChain is the certificate chain for validation.
	CertChain []*x509.Certificate `json:"-"`
	// CertChainPEM is the PEM-encoded certificate chain.
	CertChainPEM []byte `json:"cert_chain_pem,omitempty"`
	// Timestamp is when the signature was created.
	Timestamp time.Time `json:"timestamp"`
	// Signature is the raw signature bytes.
	Signature []byte `json:"signature"`
	// SignatureFormat is the format of the signature.
	SignatureFormat SignatureFormat `json:"signature_format"`
	// SignatureAlgorithm is the algorithm used for signing.
	SignatureAlgorithm SignatureAlgorithm `json:"signature_algorithm"`
	// Annotations are optional metadata attached to the signature.
	Annotations map[string]string `json:"annotations,omitempty"`
	// TimestampToken is the RFC3161 timestamp token, if present.
	TimestampToken []byte `json:"timestamp_token,omitempty"`
	// Payload is the raw payload bytes that were signed.
	// This is needed for signature verification.
	Payload []byte `json:"payload"`
	// PayloadDigest is the digest of the signed payload.
	PayloadDigest []byte `json:"payload_digest"`
	// PayloadDigestAlgorithm is the algorithm used for the payload digest.
	PayloadDigestAlgorithm DigestAlgorithm `json:"payload_digest_algorithm"`
}

// VerificationResult represents the result of signature verification.
type VerificationResult struct {
	// Verified indicates whether the signature was successfully verified.
	Verified bool `json:"verified"`
	// ImageDigest is the digest of the verified image.
	ImageDigest string `json:"image_digest"`
	// SignerIdentity is the identity of the signer (subject DN or email).
	SignerIdentity string `json:"signer_identity"`
	// SignedAt is when the image was signed.
	SignedAt time.Time `json:"signed_at"`
	// CertChain is the verified certificate chain.
	CertChain []*x509.Certificate `json:"-"`
	// CertChainSubjects are the subjects of the certificates in the chain.
	CertChainSubjects []string `json:"cert_chain_subjects,omitempty"`
	// Errors contains any non-fatal errors encountered during verification.
	Errors []string `json:"errors,omitempty"`
	// Warnings contains any warnings from the verification process.
	Warnings []string `json:"warnings,omitempty"`
	// SignatureFormat is the format of the verified signature.
	SignatureFormat SignatureFormat `json:"signature_format,omitempty"`
	// SignatureAlgorithm is the algorithm used in the signature.
	SignatureAlgorithm SignatureAlgorithm `json:"signature_algorithm,omitempty"`
	// TimestampVerified indicates if a timestamp was present and verified.
	TimestampVerified bool `json:"timestamp_verified,omitempty"`
	// TimestampedAt is the time from the verified timestamp, if present.
	TimestampedAt *time.Time `json:"timestamped_at,omitempty"`
	// Annotations are the annotations from the signature.
	Annotations map[string]string `json:"annotations,omitempty"`
}

// SigningOptions configures the image signing operation.
type SigningOptions struct {
	// KeyPath is the path to the private key file.
	KeyPath string `json:"key_path,omitempty"`
	// CertPath is the path to the signing certificate file.
	CertPath string `json:"cert_path,omitempty"`
	// CertChainPath is the path to the certificate chain file.
	CertChainPath string `json:"cert_chain_path,omitempty"`
	// PrivateKey is the private key for signing (alternative to KeyPath).
	PrivateKey crypto.PrivateKey `json:"-"`
	// Certificate is the signing certificate (alternative to CertPath).
	Certificate *x509.Certificate `json:"-"`
	// CertChain is the certificate chain (alternative to CertChainPath).
	CertChain []*x509.Certificate `json:"-"`
	// TimestampServer is the optional RFC3161 timestamp server URL.
	TimestampServer string `json:"timestamp_server,omitempty"`
	// Annotations are optional metadata to attach to the signature.
	Annotations map[string]string `json:"annotations,omitempty"`
	// SignatureFormat specifies the signature format to use.
	SignatureFormat SignatureFormat `json:"signature_format,omitempty"`
	// HashAlgorithm specifies the hash algorithm for the signature.
	HashAlgorithm crypto.Hash `json:"-"`
	// Upload indicates whether to upload the signature to the registry.
	Upload bool `json:"upload,omitempty"`
}

// VerificationOptions configures the image verification operation.
type VerificationOptions struct {
	// TrustAnchors are the root certificates to trust.
	TrustAnchors []*x509.Certificate `json:"-"`
	// TrustAnchorsPEM are PEM-encoded trust anchor certificates.
	TrustAnchorsPEM []byte `json:"trust_anchors_pem,omitempty"`
	// IntermediateCerts are intermediate certificates for chain building.
	IntermediateCerts []*x509.Certificate `json:"-"`
	// IntermediateCertsPEM are PEM-encoded intermediate certificates.
	IntermediateCertsPEM []byte `json:"intermediate_certs_pem,omitempty"`
	// AllowExpired allows verification with expired certificates.
	AllowExpired bool `json:"allow_expired,omitempty"`
	// RequireTimestamp requires a valid timestamp on the signature.
	RequireTimestamp bool `json:"require_timestamp,omitempty"`
	// VerifyAnnotations are annotations that must be present and match.
	VerifyAnnotations map[string]string `json:"verify_annotations,omitempty"`
	// RequiredSignerIdentity is the required signer identity (subject DN or email).
	RequiredSignerIdentity string `json:"required_signer_identity,omitempty"`
	// CheckRevocation enables certificate revocation checking.
	CheckRevocation bool `json:"check_revocation,omitempty"`
	// CRLEndpoints are URLs for CRL distribution points.
	CRLEndpoints []string `json:"crl_endpoints,omitempty"`
	// OCSPEndpoints are URLs for OCSP responders.
	OCSPEndpoints []string `json:"ocsp_endpoints,omitempty"`
	// AcceptedFormats limits accepted signature formats.
	AcceptedFormats []SignatureFormat `json:"accepted_formats,omitempty"`
	// VerificationTime is the time to use for certificate validation (for testing).
	VerificationTime *time.Time `json:"-"`
}

// RegistryAuth contains authentication credentials for a registry.
type RegistryAuth struct {
	// Username for registry authentication.
	Username string `json:"username,omitempty"`
	// Password for registry authentication.
	Password string `json:"password,omitempty" secret:"true"`
	// Token for bearer token authentication.
	Token string `json:"token,omitempty" secret:"true"`
	// IdentityToken for identity-based authentication.
	IdentityToken string `json:"identity_token,omitempty" secret:"true"`
	// Insecure allows insecure (HTTP) registry connections.
	Insecure bool `json:"insecure,omitempty"`
}

// RegistryOptions configures the registry client.
type RegistryOptions struct {
	// Auth contains authentication credentials.
	Auth *RegistryAuth `json:"auth,omitempty"`
	// Timeout is the connection timeout.
	Timeout time.Duration `json:"timeout,omitempty"`
	// MaxRetries is the maximum number of retries for failed requests.
	MaxRetries int `json:"max_retries,omitempty"`
	// RetryDelay is the delay between retries.
	RetryDelay time.Duration `json:"retry_delay,omitempty"`
	// UserAgent is the user agent string for registry requests.
	UserAgent string `json:"user_agent,omitempty"`
	// CACertPool is the CA certificate pool for verifying private registry
	// TLS certificates. If nil, the system certificate pool is used.
	CACertPool *x509.CertPool `json:"-"`
}

// ManifestDescriptor describes an OCI manifest.
type ManifestDescriptor struct {
	// MediaType is the media type of the manifest.
	MediaType string `json:"mediaType"`
	// Digest is the digest of the manifest.
	Digest string `json:"digest"`
	// Size is the size of the manifest in bytes.
	Size int64 `json:"size"`
	// Annotations are optional annotations on the manifest.
	Annotations map[string]string `json:"annotations,omitempty"`
}

// SignaturePayload is the payload that gets signed.
type SignaturePayload struct {
	// Critical contains critical data that must be verified.
	Critical CriticalData `json:"critical"`
	// Optional contains optional data.
	Optional map[string]interface{} `json:"optional,omitempty"`
}

// CriticalData contains the critical data in a signature payload.
type CriticalData struct {
	// Type is the payload type.
	Type string `json:"type"`
	// Image contains the image identity.
	Image ImageIdentity `json:"image"`
	// Identity contains the signer identity.
	Identity SignerIdentity `json:"identity"`
}

// ImageIdentity identifies the signed image.
type ImageIdentity struct {
	// DockerReference is the docker reference for the image.
	DockerReference string `json:"docker-reference"`
}

// SignerIdentity identifies the signer.
type SignerIdentity struct {
	// DockerReference is the docker reference for identity verification.
	DockerReference string `json:"docker-reference,omitempty"`
}

// SignerConfig holds configuration for an image signer.
type SignerConfig struct {
	// PrivateKey is the private key for signing.
	PrivateKey crypto.PrivateKey
	// Certificate is the signing certificate.
	Certificate *x509.Certificate
	// CertChain is the certificate chain.
	CertChain []*x509.Certificate
	// HashAlgorithm is the hash algorithm for signatures.
	HashAlgorithm crypto.Hash
	// SignatureFormat is the signature format to produce.
	SignatureFormat SignatureFormat
	// TimestampServer is the optional timestamp server URL.
	TimestampServer string
}

// VerifierConfig holds configuration for an image verifier.
type VerifierConfig struct {
	// TrustAnchors are the trusted root certificates.
	TrustAnchors []*x509.Certificate
	// IntermediateCerts are intermediate certificates for chain building.
	IntermediateCerts []*x509.Certificate
	// AllowExpired allows expired certificates.
	AllowExpired bool
	// RequireTimestamp requires timestamp verification.
	RequireTimestamp bool
	// CheckRevocation enables revocation checking.
	CheckRevocation bool
}

// CacheEntry represents a cached signature or verification result.
type CacheEntry struct {
	// Key is the cache key.
	Key string `json:"key"`
	// Value is the cached value.
	Value interface{} `json:"value"`
	// ExpiresAt is when the entry expires.
	ExpiresAt time.Time `json:"expires_at"`
	// CreatedAt is when the entry was created.
	CreatedAt time.Time `json:"created_at"`
}
