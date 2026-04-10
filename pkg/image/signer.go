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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"hash"
	"os"
	"time"
)

// ImageSigner defines the interface for signing container images.
type ImageSigner interface {
	// SignImage signs a container image and returns the signature.
	SignImage(ctx context.Context, ref *ImageReference, opts *SigningOptions) (*ImageSignature, error)

	// SignManifest signs an image manifest and returns the signature.
	SignManifest(ctx context.Context, manifest []byte, opts *SigningOptions) (*ImageSignature, error)

	// SignPayload signs a raw payload and returns the signature bytes.
	SignPayload(ctx context.Context, payload []byte, opts *SigningOptions) ([]byte, error)
}

// Signer implements the ImageSigner interface.
type Signer struct {
	config          *SignerConfig
	registryClient  RegistryClient
	timestampClient TimestampClient
}

// SignerOptions configures the Signer.
type SignerOptions struct {
	// Config is the signer configuration.
	Config *SignerConfig
	// RegistryClient is the registry client for pushing signatures.
	RegistryClient RegistryClient
	// TimestampClient is the optional timestamp client.
	TimestampClient TimestampClient
}

// NewSigner creates a new image signer.
func NewSigner(opts *SignerOptions) (*Signer, error) {
	if opts == nil {
		return nil, ErrNilParameter{Parameter: "opts"}
	}

	if opts.Config == nil {
		return nil, ErrNilParameter{Parameter: "opts.Config"}
	}

	if opts.Config.PrivateKey == nil {
		return nil, ErrNilParameter{Parameter: "opts.Config.PrivateKey"}
	}

	if opts.Config.Certificate == nil {
		return nil, ErrNilParameter{Parameter: "opts.Config.Certificate"}
	}

	// Default hash algorithm
	if opts.Config.HashAlgorithm == 0 {
		opts.Config.HashAlgorithm = crypto.SHA256
	}

	// Default signature format
	if opts.Config.SignatureFormat == "" {
		opts.Config.SignatureFormat = FormatCosign
	}

	return &Signer{
		config:          opts.Config,
		registryClient:  opts.RegistryClient,
		timestampClient: opts.TimestampClient,
	}, nil
}

// NewSignerFromFiles creates a signer from key and certificate files.
func NewSignerFromFiles(keyPath, certPath, chainPath string) (*Signer, error) {
	// Load private key
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, ErrKeyNotFound{KeyPath: keyPath, Err: err}
	}

	privateKey, err := parsePrivateKey(keyData)
	if err != nil {
		return nil, ErrSigningFailed{Reason: "failed to parse private key", Err: err}
	}

	// Load certificate
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, ErrCertificateNotFound{CertPath: certPath, Err: err}
	}

	cert, err := parseCertificate(certData)
	if err != nil {
		return nil, ErrSigningFailed{Reason: "failed to parse certificate", Err: err}
	}

	// Load certificate chain if provided
	var certChain []*x509.Certificate
	if chainPath != "" {
		chainData, err := os.ReadFile(chainPath)
		if err != nil {
			return nil, ErrCertificateNotFound{CertPath: chainPath, Err: err}
		}

		certChain, err = parseCertificateChain(chainData)
		if err != nil {
			return nil, ErrSigningFailed{Reason: "failed to parse certificate chain", Err: err}
		}
	}

	return NewSigner(&SignerOptions{
		Config: &SignerConfig{
			PrivateKey:      privateKey,
			Certificate:     cert,
			CertChain:       certChain,
			HashAlgorithm:   crypto.SHA256,
			SignatureFormat: FormatCosign,
		},
	})
}

// SignImage signs a container image.
func (s *Signer) SignImage(ctx context.Context, ref *ImageReference, opts *SigningOptions) (*ImageSignature, error) {
	if ref == nil {
		return nil, ErrNilParameter{Parameter: "ref"}
	}

	if err := ref.Validate(); err != nil {
		return nil, err
	}

	// Get manifest from registry
	if s.registryClient == nil {
		return nil, ErrSigningFailed{ImageDigest: ref.Digest, Reason: "registry client not configured"}
	}

	manifest, err := s.registryClient.GetImageManifest(ctx, ref)
	if err != nil {
		return nil, ErrSigningFailed{ImageDigest: ref.Digest, Reason: "failed to get manifest", Err: err}
	}

	return s.SignManifest(ctx, manifest, opts)
}

// SignManifest signs an image manifest.
func (s *Signer) SignManifest(ctx context.Context, manifest []byte, opts *SigningOptions) (*ImageSignature, error) {
	if len(manifest) == 0 {
		return nil, ErrNilParameter{Parameter: "manifest"}
	}

	// Compute manifest digest
	digestBytes := sha256.Sum256(manifest)
	digest := "sha256:" + encodeHex(digestBytes[:])

	// Create signature payload
	payload := s.createPayload(digest, opts)

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, ErrSigningFailed{ImageDigest: digest, Reason: "failed to marshal payload", Err: err}
	}

	// Sign the payload
	signature, err := s.signData(payloadBytes)
	if err != nil {
		return nil, ErrSigningFailed{ImageDigest: digest, Reason: "failed to sign payload", Err: err}
	}

	// Create image signature
	imgSig := &ImageSignature{
		ImageDigest:            digest,
		SignerCert:             s.config.Certificate,
		CertChain:              s.config.CertChain,
		Timestamp:              time.Now().UTC(),
		Signature:              signature,
		SignatureFormat:        s.config.SignatureFormat,
		SignatureAlgorithm:     s.determineAlgorithm(),
		Payload:                payloadBytes,
		PayloadDigest:          digestBytes[:],
		PayloadDigestAlgorithm: DigestSHA256,
	}

	// Add annotations if provided
	if opts != nil && len(opts.Annotations) > 0 {
		imgSig.Annotations = opts.Annotations
	}

	// Add timestamp if configured
	if s.timestampClient != nil {
		token, err := s.timestampClient.Timestamp(ctx, signature)
		if err != nil {
			// Non-fatal: log warning but continue
			imgSig.Annotations["timestamp_error"] = err.Error()
		} else {
			imgSig.TimestampToken = token
		}
	}

	// Encode certificate as PEM
	imgSig.SignerCertPEM = encodeCertificatePEM(s.config.Certificate)

	// Encode certificate chain as PEM
	if len(s.config.CertChain) > 0 {
		imgSig.CertChainPEM = encodeCertificateChainPEM(s.config.CertChain)
	}

	return imgSig, nil
}

// SignPayload signs a raw payload.
func (s *Signer) SignPayload(ctx context.Context, payload []byte, opts *SigningOptions) ([]byte, error) {
	if len(payload) == 0 {
		return nil, ErrNilParameter{Parameter: "payload"}
	}

	return s.signData(payload)
}

// signData signs data using the configured private key.
func (s *Signer) signData(data []byte) ([]byte, error) {
	// Hash the data
	hasher := s.getHasher()
	hasher.Write(data)
	digest := hasher.Sum(nil)

	// Sign based on key type
	switch key := s.config.PrivateKey.(type) {
	case *rsa.PrivateKey:
		return rsa.SignPKCS1v15(rand.Reader, key, s.config.HashAlgorithm, digest)

	case *ecdsa.PrivateKey:
		return ecdsa.SignASN1(rand.Reader, key, digest)

	default:
		return nil, ErrInvalidKeyType{KeyType: "unknown"}
	}
}

// getHasher returns the appropriate hash function.
func (s *Signer) getHasher() hash.Hash {
	switch s.config.HashAlgorithm {
	case crypto.SHA384:
		return sha512.New384()
	case crypto.SHA512:
		return sha512.New()
	default:
		return sha256.New()
	}
}

// determineAlgorithm determines the signature algorithm based on key type and hash.
func (s *Signer) determineAlgorithm() SignatureAlgorithm {
	switch s.config.PrivateKey.(type) {
	case *rsa.PrivateKey:
		switch s.config.HashAlgorithm {
		case crypto.SHA384:
			return AlgorithmRSA384
		case crypto.SHA512:
			return AlgorithmRSA512
		default:
			return AlgorithmRSA256
		}

	case *ecdsa.PrivateKey:
		switch s.config.HashAlgorithm {
		case crypto.SHA384:
			return AlgorithmECDSA384
		case crypto.SHA512:
			return AlgorithmECDSA512
		default:
			return AlgorithmECDSA256
		}

	default:
		return ""
	}
}

// createPayload creates the signature payload.
func (s *Signer) createPayload(digest string, opts *SigningOptions) *SignaturePayload {
	payload := &SignaturePayload{
		Critical: CriticalData{
			Type: "atomic container signature",
			Image: ImageIdentity{
				DockerReference: digest,
			},
			Identity: SignerIdentity{},
		},
	}

	if opts != nil && len(opts.Annotations) > 0 {
		payload.Optional = make(map[string]interface{})
		for k, v := range opts.Annotations {
			payload.Optional[k] = v
		}
	}

	return payload
}

// parsePrivateKey parses a PEM-encoded private key.
func parsePrivateKey(data []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, ErrSigningFailed{Reason: "failed to decode PEM block"}
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)

	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)

	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return key, nil

	default:
		return nil, ErrInvalidKeyType{KeyType: block.Type}
	}
}

// parseCertificate parses a PEM-encoded certificate.
func parseCertificate(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, ErrSigningFailed{Reason: "failed to decode PEM block"}
	}

	return x509.ParseCertificate(block.Bytes)
}

// parseCertificateChain parses a PEM-encoded certificate chain.
func parseCertificateChain(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			certs = append(certs, cert)
		}

		data = rest
	}

	return certs, nil
}

// encodeCertificatePEM encodes a certificate as PEM.
func encodeCertificatePEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}

// encodeCertificateChainPEM encodes a certificate chain as PEM.
func encodeCertificateChainPEM(chain []*x509.Certificate) []byte {
	var result []byte
	for _, cert := range chain {
		result = append(result, encodeCertificatePEM(cert)...)
	}
	return result
}

// encodeHex encodes bytes as lowercase hex string.
func encodeHex(data []byte) string {
	const hexTable = "0123456789abcdef"
	buf := make([]byte, len(data)*2)
	for i, b := range data {
		buf[i*2] = hexTable[b>>4]
		buf[i*2+1] = hexTable[b&0x0f]
	}
	return string(buf)
}

// EncodeSignatureBase64 encodes a signature as base64.
func EncodeSignatureBase64(sig []byte) string {
	return base64.StdEncoding.EncodeToString(sig)
}

// DecodeSignatureBase64 decodes a base64-encoded signature.
func DecodeSignatureBase64(encoded string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(encoded)
}
