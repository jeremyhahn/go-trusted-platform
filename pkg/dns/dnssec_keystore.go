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

package dns

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"strings"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	xkmsadapter "github.com/jeremyhahn/go-trusted-platform/internal/xkms"
	"github.com/miekg/dns"
)

// KeyType represents the type of DNSSEC key.
type KeyType string

const (
	// KeyTypeKSK is the Key Signing Key.
	KeyTypeKSK KeyType = "ksk"
	// KeyTypeZSK is the Zone Signing Key.
	KeyTypeZSK KeyType = "zsk"

	// defaultBackend is the default XKMS backend for DNSSEC keys.
	defaultBackend = "software"
)

// DNSSECKeyStore provides an interface for DNSSEC key storage operations.
// Implementations can use various backends including file-based storage,
// TPM 2.0, PKCS#11, cloud KMS services, or HashiCorp Vault.
// All methods require a tenantID to ensure proper key isolation in multi-tenant environments.
type DNSSECKeyStore interface {
	// GenerateKSK generates a new Key Signing Key for the specified tenant and zone.
	GenerateKSK(ctx context.Context, tenantID, zoneName string, algorithm uint8) (*dns.DNSKEY, error)

	// GenerateZSK generates a new Zone Signing Key for the specified tenant and zone.
	GenerateZSK(ctx context.Context, tenantID, zoneName string, algorithm uint8) (*dns.DNSKEY, error)

	// GetSigner returns a crypto.Signer for the specified tenant, zone, and key type.
	GetSigner(ctx context.Context, tenantID, zoneName string, keyType KeyType) (crypto.Signer, error)

	// GetDNSKEY retrieves the DNSKEY record for the specified tenant, zone, and key type.
	GetDNSKEY(ctx context.Context, tenantID, zoneName string, keyType KeyType) (*dns.DNSKEY, error)

	// KeyExists checks if a key exists for the specified tenant, zone, and key type.
	KeyExists(ctx context.Context, tenantID, zoneName string, keyType KeyType) bool

	// DeleteKey removes a key from the store for the specified tenant.
	DeleteKey(ctx context.Context, tenantID, zoneName string, keyType KeyType) error
}

// XKMSKeyStore implements DNSSECKeyStore using the internal XKMS adapter.
// This implementation uses the go-xkms SDK for all key operations.
type XKMSKeyStore struct {
	adapter *xkmsadapter.Adapter
	backend string
}

// NewXKMSKeyStore creates a new XKMS-backed DNSSEC key store.
func NewXKMSKeyStore(adapter *xkmsadapter.Adapter) (*XKMSKeyStore, error) {
	if adapter == nil {
		return nil, ErrKeyStoreNil
	}
	return &XKMSKeyStore{
		adapter: adapter,
		backend: defaultBackend,
	}, nil
}

// NewXKMSKeyStoreWithBackend creates a new XKMS-backed DNSSEC key store with a specific backend.
func NewXKMSKeyStoreWithBackend(adapter *xkmsadapter.Adapter, backend string) (*XKMSKeyStore, error) {
	if adapter == nil {
		return nil, ErrKeyStoreNil
	}
	if backend == "" {
		backend = defaultBackend
	}
	return &XKMSKeyStore{
		adapter: adapter,
		backend: backend,
	}, nil
}

// makeKeyID creates a unique key identifier for a DNSSEC key with tenant scoping.
// Format: "dnssec_{tenantID}_{zoneName}_{keyType}"
// Zone dots are replaced with hyphens since key IDs only allow: a-z, A-Z, 0-9, -, _
func makeKeyID(tenantID, zoneName string, keyType KeyType) string {
	// Normalize zone name: remove trailing dot and replace internal dots with hyphens
	normalized := strings.TrimSuffix(zoneName, ".")
	normalized = strings.ReplaceAll(normalized, ".", "-")
	return fmt.Sprintf("dnssec_%s_%s_%s", tenantID, normalized, keyType)
}

// =============================================================================
// XKMSKeyStore Implementation
// =============================================================================

// GenerateKSK generates a new Key Signing Key for the specified tenant and zone.
func (s *XKMSKeyStore) GenerateKSK(ctx context.Context, tenantID, zoneName string, algorithm uint8) (*dns.DNSKEY, error) {
	return s.generateKey(ctx, tenantID, zoneName, KeyTypeKSK, algorithm, 257)
}

// GenerateZSK generates a new Zone Signing Key for the specified tenant and zone.
func (s *XKMSKeyStore) GenerateZSK(ctx context.Context, tenantID, zoneName string, algorithm uint8) (*dns.DNSKEY, error) {
	return s.generateKey(ctx, tenantID, zoneName, KeyTypeZSK, algorithm, 256)
}

// generateKey generates a DNSSEC key with the specified parameters using the XKMS adapter.
func (s *XKMSKeyStore) generateKey(ctx context.Context, tenantID, zoneName string, keyType KeyType, algorithm uint8, flags uint16) (*dns.DNSKEY, error) {
	keyID := makeKeyID(tenantID, zoneName, keyType)

	// Map DNSSEC algorithm to XKMS parameters
	keyAlg, keySize, curve, err := dnssecAlgorithmToXKMSParams(algorithm)
	if err != nil {
		return nil, &DNSSECError{
			Op:   "GenerateKey",
			Zone: zoneName,
			Err:  err,
		}
	}

	// Create the key generation request
	req := &xkmssdk.GenerateKeyRequest{
		Backend: s.backend,
		KeyID:   keyID,
		KeyType: keyAlg,
		KeySize: keySize,
		Curve:   curve,
	}

	resp, err := s.adapter.GenerateKey(ctx, req)
	if err != nil {
		return nil, &DNSSECError{
			Op:   "GenerateKey",
			Zone: zoneName,
			Err:  &SentinelCauseError{Sentinel: ErrKMSKeyGeneration, Cause: &DetailError{Err: err, Detail: fmt.Sprintf(" (algorithm: %s)", keyAlg)}},
		}
	}

	// Parse the public key from the PEM response
	pubKey, err := parsePublicKeyFromPEM(resp.PublicKeyPEM, keyAlg)
	if err != nil {
		return nil, &DNSSECError{
			Op:   "GenerateKey",
			Zone: zoneName,
			Err:  &WrappedError{Msg: "failed to parse public key", Err: err},
		}
	}

	// Build the DNSKEY record
	dnskey, err := buildDNSKEY(zoneName, pubKey, algorithm, flags)
	if err != nil {
		return nil, &DNSSECError{
			Op:   "GenerateKey",
			Zone: zoneName,
			Err:  &WrappedError{Msg: "failed to build DNSKEY", Err: err},
		}
	}

	return dnskey, nil
}

// GetSigner returns a crypto.Signer for the specified tenant, zone, and key type.
func (s *XKMSKeyStore) GetSigner(ctx context.Context, tenantID, zoneName string, keyType KeyType) (crypto.Signer, error) {
	keyID := makeKeyID(tenantID, zoneName, keyType)

	// Verify the key exists
	resp, err := s.adapter.GetKey(ctx, s.backend, keyID)
	if err != nil {
		return nil, &DNSSECError{
			Op:   "GetSigner",
			Zone: zoneName,
			Err:  &SentinelCauseError{Sentinel: ErrKMSKeyNotFound, Cause: err},
		}
	}

	if resp == nil {
		return nil, &DNSSECError{
			Op:   "GetSigner",
			Zone: zoneName,
			Err:  ErrKMSKeyNotFound,
		}
	}

	// Determine algorithm from key info
	alg := resp.Algorithm
	if alg == "" {
		alg = resp.KeyType
	}

	// Parse the public key from PEM
	pubKey, err := parsePublicKeyFromPEM(resp.PublicKeyPEM, alg)
	if err != nil {
		return nil, &DNSSECError{
			Op:   "GetSigner",
			Zone: zoneName,
			Err:  &WrappedError{Msg: "failed to parse public key", Err: err},
		}
	}

	// Create a signer wrapper that uses the XKMS adapter
	signer := &xkmsSigner{
		adapter:   s.adapter,
		backend:   s.backend,
		keyID:     keyID,
		publicKey: pubKey,
		algorithm: alg,
	}

	return signer, nil
}

// GetDNSKEY retrieves the DNSKEY record for the specified tenant, zone, and key type.
func (s *XKMSKeyStore) GetDNSKEY(ctx context.Context, tenantID, zoneName string, keyType KeyType) (*dns.DNSKEY, error) {
	keyID := makeKeyID(tenantID, zoneName, keyType)

	// Get key info
	resp, err := s.adapter.GetKey(ctx, s.backend, keyID)
	if err != nil {
		return nil, &DNSSECError{
			Op:   "GetDNSKEY",
			Zone: zoneName,
			Err:  &SentinelCauseError{Sentinel: ErrKMSKeyNotFound, Cause: err},
		}
	}

	if resp == nil {
		return nil, &DNSSECError{
			Op:   "GetDNSKEY",
			Zone: zoneName,
			Err:  ErrKMSKeyNotFound,
		}
	}

	// Determine algorithm from key info
	alg := resp.Algorithm
	if alg == "" {
		alg = resp.KeyType
	}

	// Parse the public key from PEM
	pubKey, err := parsePublicKeyFromPEM(resp.PublicKeyPEM, alg)
	if err != nil {
		return nil, &DNSSECError{
			Op:   "GetDNSKEY",
			Zone: zoneName,
			Err:  &WrappedError{Msg: "failed to parse public key", Err: err},
		}
	}

	// Determine DNSSEC algorithm
	algorithm, err := xkmsAlgorithmToDNSSEC(alg)
	if err != nil {
		return nil, &DNSSECError{
			Op:   "GetDNSKEY",
			Zone: zoneName,
			Err:  err,
		}
	}

	var flags uint16
	if keyType == KeyTypeKSK {
		flags = 257
	} else {
		flags = 256
	}

	dnskey, err := buildDNSKEY(zoneName, pubKey, algorithm, flags)
	if err != nil {
		return nil, &DNSSECError{
			Op:   "GetDNSKEY",
			Zone: zoneName,
			Err:  err,
		}
	}

	return dnskey, nil
}

// KeyExists checks if a key exists for the specified tenant, zone, and key type.
func (s *XKMSKeyStore) KeyExists(ctx context.Context, tenantID, zoneName string, keyType KeyType) bool {
	keyID := makeKeyID(tenantID, zoneName, keyType)

	resp, err := s.adapter.GetKey(ctx, s.backend, keyID)
	if err != nil {
		return false
	}

	return resp != nil
}

// DeleteKey removes a key from the store for the specified tenant.
func (s *XKMSKeyStore) DeleteKey(ctx context.Context, tenantID, zoneName string, keyType KeyType) error {
	keyID := makeKeyID(tenantID, zoneName, keyType)

	_, err := s.adapter.DeleteKey(ctx, s.backend, keyID)
	if err != nil {
		return &DNSSECError{
			Op:   "DeleteKey",
			Zone: zoneName,
			Err:  &WrappedError{Msg: "failed to delete key", Err: err},
		}
	}

	return nil
}

// =============================================================================
// xkmsSigner implements crypto.Signer using the XKMS adapter
// =============================================================================

// xkmsSigner wraps the XKMS adapter to implement crypto.Signer.
type xkmsSigner struct {
	adapter   *xkmsadapter.Adapter
	backend   string
	keyID     string
	publicKey crypto.PublicKey
	algorithm string
}

// Public returns the public key.
func (s *xkmsSigner) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign signs the digest using the XKMS adapter.
func (s *xkmsSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	ctx := context.Background()

	// Determine hash algorithm
	hashAlg := "SHA256"
	if opts != nil {
		switch opts.HashFunc() {
		case crypto.SHA256:
			hashAlg = "SHA256"
		case crypto.SHA384:
			hashAlg = "SHA384"
		case crypto.SHA512:
			hashAlg = "SHA512"
		}
	}

	req := &xkmssdk.SignRequest{
		Backend: s.backend,
		KeyID:   s.keyID,
		Data:    digest,
		Hash:    hashAlg,
	}

	resp, err := s.adapter.Sign(ctx, req)
	if err != nil {
		return nil, &WrappedError{Msg: "xkms sign failed", Err: err}
	}

	return resp.Signature, nil
}

// =============================================================================
// Algorithm conversion helpers
// =============================================================================

// dnssecAlgorithmToXKMSParams maps a DNSSEC algorithm to XKMS SDK parameters.
func dnssecAlgorithmToXKMSParams(algorithm uint8) (keyType string, keySize int, curve string, err error) {
	switch algorithm {
	case dns.RSASHA256:
		return "RSA", 2048, "", nil
	case dns.RSASHA512:
		return "RSA", 2048, "", nil
	case dns.ECDSAP256SHA256:
		return "ECDSA", 0, "P-256", nil
	case dns.ECDSAP384SHA384:
		return "ECDSA", 0, "P-384", nil
	case dns.ED25519:
		return "ED25519", 0, "", nil
	default:
		return "", 0, "", &SentinelCauseError{Sentinel: ErrUnsupportedAlgorithm, Cause: &MessageError{Msg: fmt.Sprintf("algorithm %d (%s)", algorithm, dns.AlgorithmToString[algorithm])}}
	}
}

// xkmsAlgorithmToDNSSEC maps a xkms algorithm string to DNSSEC algorithm.
func xkmsAlgorithmToDNSSEC(algorithm string) (uint8, error) {
	switch strings.ToUpper(algorithm) {
	case "RSA", "RSA2048", "RSA3072", "RSA4096":
		return dns.RSASHA256, nil
	case "ECDSA", "ECDSA-P256", "P256", "P-256":
		return dns.ECDSAP256SHA256, nil
	case "ECDSA-P384", "P384", "P-384":
		return dns.ECDSAP384SHA384, nil
	case "ED25519":
		return dns.ED25519, nil
	default:
		return 0, &SentinelCauseError{Sentinel: ErrUnsupportedAlgorithm, Cause: &MessageError{Msg: fmt.Sprintf("xkms algorithm %s", algorithm)}}
	}
}

// parsePublicKeyFromPEM parses a public key from PEM format.
func parsePublicKeyFromPEM(pemData string, algorithm string) (crypto.PublicKey, error) {
	if pemData == "" {
		return nil, &MessageError{Msg: "empty public key PEM"}
	}

	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, &MessageError{Msg: "failed to decode PEM block"}
	}

	// Try to parse as PKIX/X.509 SubjectPublicKeyInfo
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err == nil {
		return pubKey, nil
	}

	// Try algorithm-specific parsing
	switch strings.ToUpper(algorithm) {
	case "ED25519":
		if len(block.Bytes) == ed25519.PublicKeySize {
			return ed25519.PublicKey(block.Bytes), nil
		}
	case "RSA", "RSA2048", "RSA3072", "RSA4096":
		// Try PKCS1 format
		rsaPubKey, parseErr := x509.ParsePKCS1PublicKey(block.Bytes)
		if parseErr == nil {
			return rsaPubKey, nil
		}
	}

	return nil, &WrappedError{Msg: fmt.Sprintf("failed to parse public key for algorithm %s", algorithm), Err: err}
}

// parsePublicKeyFromXKMS parses a public key from XKMS SDK response bytes.
func parsePublicKeyFromXKMS(pubKeyBytes []byte, algorithm string) (crypto.PublicKey, error) {
	if len(pubKeyBytes) == 0 {
		return nil, &MessageError{Msg: "empty public key bytes"}
	}

	// Try to parse as PKIX/X.509 SubjectPublicKeyInfo
	pubKey, err := x509.ParsePKIXPublicKey(pubKeyBytes)
	if err == nil {
		return pubKey, nil
	}

	// Try algorithm-specific parsing
	switch strings.ToUpper(algorithm) {
	case "ED25519":
		if len(pubKeyBytes) == ed25519.PublicKeySize {
			return ed25519.PublicKey(pubKeyBytes), nil
		}
	case "RSA", "RSA2048", "RSA3072", "RSA4096":
		// Try PKCS1 format
		rsaPubKey, parseErr := x509.ParsePKCS1PublicKey(pubKeyBytes)
		if parseErr == nil {
			return rsaPubKey, nil
		}
	}

	return nil, &MessageError{Msg: fmt.Sprintf("failed to parse public key for algorithm %s", algorithm)}
}

// =============================================================================
// DNSKEY building helpers
// =============================================================================

// buildDNSKEY constructs a DNSKEY record from a public key.
func buildDNSKEY(zoneName string, pubKey crypto.PublicKey, algorithm uint8, flags uint16) (*dns.DNSKEY, error) {
	dnskey := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(zoneName),
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    86400,
		},
		Flags:     flags,
		Protocol:  3,
		Algorithm: algorithm,
	}

	// Set the public key based on the key type
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		dnskey.PublicKey = rsaPublicKeyToBase64(key)
	case *ecdsa.PublicKey:
		dnskey.PublicKey = ecdsaPublicKeyToBase64(key)
	case ed25519.PublicKey:
		dnskey.PublicKey = ed25519PublicKeyToBase64(key)
	default:
		return nil, &MessageError{Msg: fmt.Sprintf("unsupported public key type: %T", pubKey)}
	}

	return dnskey, nil
}

// rsaPublicKeyToBase64 encodes an RSA public key for DNSKEY.
// RFC 3110 format: exponent length (1 or 3 bytes) + exponent + modulus
func rsaPublicKeyToBase64(key *rsa.PublicKey) string {
	exponent := big.NewInt(int64(key.E))
	expBytes := exponent.Bytes()
	modBytes := key.N.Bytes()

	var buf []byte
	if len(expBytes) <= 255 {
		// 1-byte exponent length
		buf = make([]byte, 1+len(expBytes)+len(modBytes))
		buf[0] = byte(len(expBytes))
		copy(buf[1:], expBytes)
		copy(buf[1+len(expBytes):], modBytes)
	} else {
		// 3-byte exponent length (0 + 2-byte big-endian length)
		buf = make([]byte, 3+len(expBytes)+len(modBytes))
		buf[0] = 0
		buf[1] = byte(len(expBytes) >> 8)
		buf[2] = byte(len(expBytes))
		copy(buf[3:], expBytes)
		copy(buf[3+len(expBytes):], modBytes)
	}

	return base64.StdEncoding.EncodeToString(buf)
}

// ecdsaPublicKeyToBase64 encodes an ECDSA public key for DNSKEY.
// RFC 6605 format: concatenate X and Y coordinates (fixed length based on curve).
// Uses PublicKey.Bytes() (Go 1.26+) which returns SEC 1 uncompressed format (0x04 || X || Y),
// then strips the 0x04 prefix to get raw X||Y coordinates.
func ecdsaPublicKeyToBase64(key *ecdsa.PublicKey) string {
	uncompressed, err := key.Bytes()
	if err != nil {
		// Fallback should not happen for valid P-224/P-256/P-384/P-521 keys
		return ""
	}
	// Bytes() returns 0x04 || X || Y; strip the leading 0x04 prefix
	pubBytes := uncompressed[1:]

	return base64.StdEncoding.EncodeToString(pubBytes)
}

// ed25519PublicKeyToBase64 encodes an Ed25519 public key for DNSKEY.
// RFC 8080 format: raw 32-byte public key
func ed25519PublicKeyToBase64(key ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString([]byte(key))
}

// =============================================================================
// Legacy key attribute helpers (for backward compatibility)
// =============================================================================

// keyAttributes holds key attributes for legacy compatibility.
type keyAttributes struct {
	CN           string
	keyAlgorithm x509.PublicKeyAlgorithm
	curve        elliptic.Curve
}

// buildKeyAttrsFromXKMSAlgorithm creates key attributes from a key ID and xkms algorithm.
func buildKeyAttrsFromXKMSAlgorithm(keyID string, algorithm string) *keyAttributes {
	attrs := &keyAttributes{
		CN:           keyID,
		keyAlgorithm: x509.UnknownPublicKeyAlgorithm,
	}

	switch strings.ToUpper(algorithm) {
	case "RSA", "RSA2048", "RSA3072", "RSA4096":
		attrs.keyAlgorithm = x509.RSA
	case "ECDSA", "ECDSA-P256", "P256", "P-256":
		attrs.keyAlgorithm = x509.ECDSA
		attrs.curve = elliptic.P256()
	case "ECDSA-P384", "P384", "P-384":
		attrs.keyAlgorithm = x509.ECDSA
		attrs.curve = elliptic.P384()
	case "ECDSA-P521", "P521", "P-521":
		attrs.keyAlgorithm = x509.ECDSA
		attrs.curve = elliptic.P521()
	case "ED25519":
		attrs.keyAlgorithm = x509.Ed25519
	}

	return attrs
}
