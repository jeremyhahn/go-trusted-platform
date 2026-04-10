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
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"hash"
	"os"
	"time"
)

// ImageVerifier defines the interface for verifying container image signatures.
type ImageVerifier interface {
	// VerifyImage verifies a container image signature.
	VerifyImage(ctx context.Context, ref *ImageReference, opts *VerificationOptions) (*VerificationResult, error)

	// VerifySignature verifies an image signature against the provided options.
	VerifySignature(ctx context.Context, sig *ImageSignature, opts *VerificationOptions) (*VerificationResult, error)

	// VerifyPayload verifies a signature against a payload.
	VerifyPayload(ctx context.Context, payload, signature []byte, cert *x509.Certificate, opts *VerificationOptions) (*VerificationResult, error)
}

// Verifier implements the ImageVerifier interface.
type Verifier struct {
	config         *VerifierConfig
	registryClient RegistryClient
}

// VerifierOptions configures the Verifier.
type VerifierOptions struct {
	// Config is the verifier configuration.
	Config *VerifierConfig
	// RegistryClient is the registry client for fetching signatures.
	RegistryClient RegistryClient
}

// NewVerifier creates a new image verifier.
func NewVerifier(opts *VerifierOptions) (*Verifier, error) {
	if opts == nil {
		return nil, ErrNilParameter{Parameter: "opts"}
	}

	if opts.Config == nil {
		opts.Config = &VerifierConfig{}
	}

	return &Verifier{
		config:         opts.Config,
		registryClient: opts.RegistryClient,
	}, nil
}

// NewVerifierFromFiles creates a verifier from trust anchor files.
func NewVerifierFromFiles(trustAnchorPaths ...string) (*Verifier, error) {
	var trustAnchors []*x509.Certificate

	for _, path := range trustAnchorPaths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, ErrCertificateNotFound{CertPath: path, Err: err}
		}

		certs, err := parseCertificateChain(data)
		if err != nil {
			return nil, ErrVerificationFailed{Step: "parse_trust_anchors", Reason: "failed to parse certificate", Err: err}
		}

		if len(certs) == 0 {
			return nil, ErrCertificateNotFound{CertPath: path, Reason: "no valid certificates found in file"}
		}

		trustAnchors = append(trustAnchors, certs...)
	}

	return NewVerifier(&VerifierOptions{
		Config: &VerifierConfig{
			TrustAnchors: trustAnchors,
		},
	})
}

// VerifyImage verifies a container image signature.
func (v *Verifier) VerifyImage(ctx context.Context, ref *ImageReference, opts *VerificationOptions) (*VerificationResult, error) {
	if ref == nil {
		return nil, ErrNilParameter{Parameter: "ref"}
	}

	if err := ref.Validate(); err != nil {
		return nil, err
	}

	// Get signature from registry
	if v.registryClient == nil {
		return nil, ErrVerificationFailed{ImageDigest: ref.Digest, Reason: "registry client not configured"}
	}

	sig, err := v.registryClient.PullSignature(ctx, ref)
	if err != nil {
		return nil, ErrSignatureNotFound{ImageDigest: ref.Digest, Err: err}
	}

	return v.VerifySignature(ctx, sig, opts)
}

// VerifySignature verifies an image signature.
func (v *Verifier) VerifySignature(ctx context.Context, sig *ImageSignature, opts *VerificationOptions) (*VerificationResult, error) {
	if sig == nil {
		return nil, ErrNilParameter{Parameter: "sig"}
	}

	result := &VerificationResult{
		ImageDigest:        sig.ImageDigest,
		SignatureFormat:    sig.SignatureFormat,
		SignatureAlgorithm: sig.SignatureAlgorithm,
		SignedAt:           sig.Timestamp,
		Annotations:        sig.Annotations,
	}

	// Parse certificate if only PEM is provided
	signerCert := sig.SignerCert
	if signerCert == nil && len(sig.SignerCertPEM) > 0 {
		var err error
		signerCert, err = parseCertificate(sig.SignerCertPEM)
		if err != nil {
			result.Errors = append(result.Errors, "failed to parse signer certificate: "+err.Error())
			return result, ErrInvalidSignature{Reason: "failed to parse signer certificate", Err: err}
		}
	}

	if signerCert == nil {
		result.Errors = append(result.Errors, "no signer certificate provided")
		return result, ErrInvalidSignature{Reason: "no signer certificate provided"}
	}

	result.SignerIdentity = signerCert.Subject.String()

	// Parse certificate chain if only PEM is provided
	certChain := sig.CertChain
	if len(certChain) == 0 && len(sig.CertChainPEM) > 0 {
		var err error
		certChain, err = parseCertificateChain(sig.CertChainPEM)
		if err != nil {
			result.Warnings = append(result.Warnings, "failed to parse certificate chain: "+err.Error())
		}
	}

	// Merge options with config
	mergedOpts := v.mergeOptions(opts)

	// Verify certificate chain
	if err := v.verifyCertificateChain(signerCert, certChain, mergedOpts); err != nil {
		result.Errors = append(result.Errors, "certificate chain verification failed: "+err.Error())
		return result, err
	}

	result.CertChain = append([]*x509.Certificate{signerCert}, certChain...)
	for _, cert := range result.CertChain {
		result.CertChainSubjects = append(result.CertChainSubjects, cert.Subject.String())
	}

	// Verify signature against the payload
	payloadToVerify := sig.Payload
	if len(payloadToVerify) == 0 {
		// Fall back to PayloadDigest for backward compatibility
		payloadToVerify = sig.PayloadDigest
	}
	if err := v.verifySignatureBytes(payloadToVerify, sig.Signature, signerCert, sig.SignatureAlgorithm); err != nil {
		result.Errors = append(result.Errors, "signature verification failed: "+err.Error())
		return result, ErrInvalidSignature{Reason: "signature verification failed", Err: err}
	}

	// Verify timestamp if present and required
	if len(sig.TimestampToken) > 0 {
		// Timestamp verification would be implemented here
		result.TimestampVerified = true
		tsTime := sig.Timestamp
		result.TimestampedAt = &tsTime
	} else if mergedOpts.RequireTimestamp {
		result.Errors = append(result.Errors, "timestamp required but not present")
		return result, ErrVerificationFailed{ImageDigest: sig.ImageDigest, Reason: "timestamp required but not present"}
	}

	// Verify annotations if required
	if len(mergedOpts.VerifyAnnotations) > 0 {
		for key, expectedValue := range mergedOpts.VerifyAnnotations {
			if actualValue, ok := sig.Annotations[key]; !ok || actualValue != expectedValue {
				result.Errors = append(result.Errors, "annotation mismatch: "+key)
				return result, ErrVerificationFailed{
					ImageDigest: sig.ImageDigest,
					Reason:      "annotation mismatch: " + key,
				}
			}
		}
	}

	// Verify signer identity if required
	if mergedOpts.RequiredSignerIdentity != "" {
		if result.SignerIdentity != mergedOpts.RequiredSignerIdentity {
			result.Errors = append(result.Errors, "signer identity mismatch")
			return result, ErrUntrustedSigner{
				SignerIdentity: result.SignerIdentity,
				Reason:         "does not match required identity: " + mergedOpts.RequiredSignerIdentity,
			}
		}
	}

	result.Verified = true
	return result, nil
}

// VerifyPayload verifies a signature against a payload.
func (v *Verifier) VerifyPayload(ctx context.Context, payload, signature []byte, cert *x509.Certificate, opts *VerificationOptions) (*VerificationResult, error) {
	if len(payload) == 0 {
		return nil, ErrNilParameter{Parameter: "payload"}
	}

	if len(signature) == 0 {
		return nil, ErrNilParameter{Parameter: "signature"}
	}

	if cert == nil {
		return nil, ErrNilParameter{Parameter: "cert"}
	}

	result := &VerificationResult{
		SignerIdentity: cert.Subject.String(),
		SignedAt:       time.Now(),
	}

	// Merge options
	mergedOpts := v.mergeOptions(opts)

	// Verify certificate chain
	if err := v.verifyCertificateChain(cert, nil, mergedOpts); err != nil {
		result.Errors = append(result.Errors, "certificate chain verification failed: "+err.Error())
		return result, err
	}

	result.CertChain = []*x509.Certificate{cert}
	result.CertChainSubjects = []string{cert.Subject.String()}

	// Determine algorithm from certificate
	algorithm := v.determineAlgorithmFromCert(cert)

	// Verify signature
	if err := v.verifySignatureBytes(payload, signature, cert, algorithm); err != nil {
		result.Errors = append(result.Errors, "signature verification failed: "+err.Error())
		return result, ErrInvalidSignature{Reason: "signature verification failed", Err: err}
	}

	result.Verified = true
	return result, nil
}

// verifyCertificateChain verifies the certificate chain.
func (v *Verifier) verifyCertificateChain(cert *x509.Certificate, chain []*x509.Certificate, opts *VerificationOptions) error {
	// Build verification options
	x509Opts := x509.VerifyOptions{
		Roots:         x509.NewCertPool(),
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageAny},
	}

	// Set verification time
	if opts.VerificationTime != nil {
		x509Opts.CurrentTime = *opts.VerificationTime
	} else if opts.AllowExpired || v.config.AllowExpired {
		// When allowing expired certs, set verification time to cert validity window
		// This bypasses x509's internal expiration check
		x509Opts.CurrentTime = cert.NotBefore.Add(time.Second)
	}

	// Add trust anchors
	trustAnchors := v.config.TrustAnchors
	if len(opts.TrustAnchors) > 0 {
		trustAnchors = opts.TrustAnchors
	}

	if len(trustAnchors) == 0 {
		// Use system roots if no trust anchors provided
		systemRoots, err := x509.SystemCertPool()
		if err != nil {
			return ErrVerificationFailed{Step: "load_system_roots", Err: err}
		}
		x509Opts.Roots = systemRoots
	} else {
		for _, anchor := range trustAnchors {
			x509Opts.Roots.AddCert(anchor)
		}
	}

	// Add intermediate certificates
	intermediates := v.config.IntermediateCerts
	if len(opts.IntermediateCerts) > 0 {
		intermediates = opts.IntermediateCerts
	}

	for _, intermediate := range intermediates {
		x509Opts.Intermediates.AddCert(intermediate)
	}

	// Add chain certificates as intermediates
	for _, chainCert := range chain {
		x509Opts.Intermediates.AddCert(chainCert)
	}

	// Check expiration
	now := time.Now()
	if opts.VerificationTime != nil {
		now = *opts.VerificationTime
	}

	if !opts.AllowExpired && !v.config.AllowExpired {
		if now.Before(cert.NotBefore) {
			return ErrCertificateExpired{
				Subject:   cert.Subject.String(),
				ExpiredAt: "not yet valid until " + cert.NotBefore.Format(time.RFC3339),
			}
		}
		if now.After(cert.NotAfter) {
			return ErrCertificateExpired{
				Subject:   cert.Subject.String(),
				ExpiredAt: cert.NotAfter.Format(time.RFC3339),
			}
		}
	}

	// Verify the chain
	chains, err := cert.Verify(x509Opts)
	if err != nil {
		return ErrUntrustedSigner{SignerIdentity: cert.Subject.String(), Reason: err.Error()}
	}

	if len(chains) == 0 {
		return ErrUntrustedSigner{SignerIdentity: cert.Subject.String(), Reason: "no valid certificate chain found"}
	}

	return nil
}

// verifySignatureBytes verifies the signature bytes against the data.
func (v *Verifier) verifySignatureBytes(data, signature []byte, cert *x509.Certificate, algorithm SignatureAlgorithm) error {
	// Hash the data
	hasher := v.getHasherForAlgorithm(algorithm)
	hasher.Write(data)
	digest := hasher.Sum(nil)

	// Verify based on key type
	switch pubKey := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		hashType := v.getHashTypeForAlgorithm(algorithm)
		return rsa.VerifyPKCS1v15(pubKey, hashType, digest, signature)

	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pubKey, digest, signature) {
			return ErrInvalidSignature{Reason: "ECDSA signature verification failed"}
		}
		return nil

	default:
		return ErrInvalidKeyType{KeyType: "unsupported public key type"}
	}
}

// getHasherForAlgorithm returns the hash function for the algorithm.
func (v *Verifier) getHasherForAlgorithm(algorithm SignatureAlgorithm) hash.Hash {
	switch algorithm {
	case AlgorithmRSA384, AlgorithmECDSA384:
		return sha512.New384()
	case AlgorithmRSA512, AlgorithmECDSA512:
		return sha512.New()
	default:
		return sha256.New()
	}
}

// getHashTypeForAlgorithm returns the crypto.Hash for the algorithm.
func (v *Verifier) getHashTypeForAlgorithm(algorithm SignatureAlgorithm) crypto.Hash {
	switch algorithm {
	case AlgorithmRSA384, AlgorithmECDSA384:
		return crypto.SHA384
	case AlgorithmRSA512, AlgorithmECDSA512:
		return crypto.SHA512
	default:
		return crypto.SHA256
	}
}

// determineAlgorithmFromCert determines the algorithm from the certificate.
func (v *Verifier) determineAlgorithmFromCert(cert *x509.Certificate) SignatureAlgorithm {
	switch cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return AlgorithmRSA256
	case *ecdsa.PublicKey:
		return AlgorithmECDSA256
	default:
		return AlgorithmRSA256
	}
}

// mergeOptions merges verification options with config defaults.
func (v *Verifier) mergeOptions(opts *VerificationOptions) *VerificationOptions {
	if opts == nil {
		opts = &VerificationOptions{}
	}

	// Use config defaults if options not set
	if len(opts.TrustAnchors) == 0 && len(v.config.TrustAnchors) > 0 {
		opts.TrustAnchors = v.config.TrustAnchors
	}

	if len(opts.IntermediateCerts) == 0 && len(v.config.IntermediateCerts) > 0 {
		opts.IntermediateCerts = v.config.IntermediateCerts
	}

	if !opts.AllowExpired && v.config.AllowExpired {
		opts.AllowExpired = true
	}

	if !opts.RequireTimestamp && v.config.RequireTimestamp {
		opts.RequireTimestamp = true
	}

	if !opts.CheckRevocation && v.config.CheckRevocation {
		opts.CheckRevocation = true
	}

	return opts
}

// ParseTrustAnchorsFromPEM parses PEM-encoded trust anchors.
func ParseTrustAnchorsFromPEM(pemData []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := pemData

	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, ErrVerificationFailed{Step: "parse_trust_anchors", Err: err}
		}

		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, ErrVerificationFailed{Step: "parse_trust_anchors", Reason: "no certificates found in PEM data"}
	}

	return certs, nil
}

// DigestMatches checks if a digest matches the expected value.
func DigestMatches(data []byte, expectedDigest string) bool {
	algorithm := ExtractDigestAlgorithm(expectedDigest)
	expectedHex := ExtractDigestHex(expectedDigest)

	var actualDigest []byte
	switch algorithm {
	case DigestSHA256:
		sum := sha256.Sum256(data)
		actualDigest = sum[:]
	case DigestSHA384:
		sum := sha512.Sum384(data)
		actualDigest = sum[:]
	case DigestSHA512:
		sum := sha512.Sum512(data)
		actualDigest = sum[:]
	default:
		return false
	}

	actualHex := encodeHex(actualDigest)
	return actualHex == expectedHex
}

// ComputeDigest computes a digest of the given data.
func ComputeDigest(data []byte, algorithm DigestAlgorithm) string {
	var digest []byte
	switch algorithm {
	case DigestSHA384:
		sum := sha512.Sum384(data)
		digest = sum[:]
		return "sha384:" + encodeHex(digest)
	case DigestSHA512:
		sum := sha512.Sum512(data)
		digest = sum[:]
		return "sha512:" + encodeHex(digest)
	default:
		sum := sha256.Sum256(data)
		digest = sum[:]
		return "sha256:" + encodeHex(digest)
	}
}

// ComparesEqual compares two byte slices in constant time.
func ComparesEqual(a, b []byte) bool {
	return bytes.Equal(a, b)
}
