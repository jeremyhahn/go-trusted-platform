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
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	ddbcrypto "github.com/jeremyhahn/go-quicbaas/sdk/go/client/crypto"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	"github.com/miekg/dns"
)

const (
	// dnssecKeyMetadataEntityType is the entity type for DNSSEC key metadata in QuicBaaS.
	dnssecKeyMetadataEntityType = "dnssec_key_metadata"
)

// QuicBaaSKMSKeyStore implements DNSSECKeyStore using QuicBaaS's KMS service.
// This implementation uses the QuicBaaS SDK for all key operations, providing
// enterprise-grade key management with support for HSM-backed keys.
//
// Architecture:
//   - Key generation: Uses QuicBaaS KMS for secure key generation and storage
//   - Signing operations: Uses QuicBaaS Crypto client for signing
//   - Public key storage: Stores public key metadata in QuicBaaS KV for DNSKEY construction
//
// Note: This implementation requires that the public key be provided externally
// during key generation since the QuicBaaS KMS SDK does not currently expose
// public key retrieval. The public key is stored in the KV store alongside the
// KMS key reference.
type QuicBaaSKMSKeyStore struct {
	client quicbaas.Client
}

// dnssecKeyMetadata stores public key information for DNSKEY construction.
// This metadata is stored in QuicBaaS's KV store and linked to the KMS key.
type dnssecKeyMetadata struct {
	KeyID        string           `json:"key_id"`
	Algorithm    kms.KeyAlgorithm `json:"algorithm"`
	DNSSECAlg    uint8            `json:"dnssec_algorithm"`
	Flags        uint16           `json:"flags"`
	PublicKeyPEM string           `json:"public_key_pem"`
	ZoneName     string           `json:"zone_name"`
	TenantID     string           `json:"tenant_id"`
	KeyType      KeyType          `json:"key_type"`
}

// NewQuicBaaSKMSKeyStore creates a new QuicBaaS KMS-backed DNSSEC key store.
func NewQuicBaaSKMSKeyStore(client quicbaas.Client) (*QuicBaaSKMSKeyStore, error) {
	if client == nil {
		return nil, ErrKeyStoreNil
	}
	return &QuicBaaSKMSKeyStore{
		client: client,
	}, nil
}

// abandonKey deletes the KMS key a failed generation step left behind and
// returns cause. A failed delete is joined to cause as a CleanupError, so an
// orphaned KMS key is reported to the caller rather than silently kept.
func (s *QuicBaaSKMSKeyStore) abandonKey(ctx context.Context, keyID string, cause error) error {
	if err := s.client.Security().KMS().DeleteKey(ctx, keyID); err != nil {
		return &CleanupError{
			Err:     cause,
			Cleanup: &WrappedError{Msg: "failed to delete KMS key " + keyID, Err: err},
		}
	}
	return cause
}

// =============================================================================
// QuicBaaSKMSKeyStore Implementation
// =============================================================================

// GenerateKSK generates a new Key Signing Key for the specified tenant and zone.
func (s *QuicBaaSKMSKeyStore) GenerateKSK(ctx context.Context, tenantID, zoneName string, algorithm uint8) (*dns.DNSKEY, error) {
	return s.generateKey(ctx, tenantID, zoneName, KeyTypeKSK, algorithm, 257)
}

// GenerateZSK generates a new Zone Signing Key for the specified tenant and zone.
func (s *QuicBaaSKMSKeyStore) GenerateZSK(ctx context.Context, tenantID, zoneName string, algorithm uint8) (*dns.DNSKEY, error) {
	return s.generateKey(ctx, tenantID, zoneName, KeyTypeZSK, algorithm, 256)
}

// generateKey generates a DNSSEC key with the specified parameters using QuicBaaS KMS.
func (s *QuicBaaSKMSKeyStore) generateKey(ctx context.Context, tenantID, zoneName string, keyType KeyType, algorithm uint8, flags uint16) (*dns.DNSKEY, error) {
	const op = "GenerateKey"
	keyID := makeKeyID(tenantID, zoneName, keyType)

	genResp, err := s.generateKMSKey(ctx, keyID, algorithm)
	if err != nil {
		return nil, &DNSSECError{Op: op, Zone: zoneName, Err: err}
	}

	// The DNSKEY must carry the public half of the key the KMS signs with.
	pubKey, err := s.kmsPublicKey(ctx, keyID)
	if err != nil {
		return nil, &DNSSECError{Op: op, Zone: zoneName, Err: s.abandonKey(ctx, keyID, err)}
	}

	dnskey, err := s.publishKey(ctx, keyID, newKeyMetadata(genResp, tenantID, zoneName, keyType, algorithm, flags), pubKey)
	if err != nil {
		return nil, &DNSSECError{Op: op, Zone: zoneName, Err: s.abandonKey(ctx, keyID, err)}
	}
	return dnskey, nil
}

// generateKMSKey asks the KMS for a signing key named keyID of the algorithm
// that matches the DNSSEC algorithm.
func (s *QuicBaaSKMSKeyStore) generateKMSKey(ctx context.Context, keyID string, algorithm uint8) (*kms.GenerateKeyResponse, error) {
	keyAlg, err := dnssecAlgorithmToQuicBaaSAlgorithm(algorithm)
	if err != nil {
		return nil, err
	}

	genResp, err := s.client.Security().KMS().GenerateKey(ctx, &kms.GenerateKeyRequest{
		Name:      keyID,
		Algorithm: keyAlg,
		Usage:     []kms.KeyUsage{kms.KeyUsageSign, kms.KeyUsageVerify},
	})
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrKMSKeyGeneration, Cause: &DetailError{Err: err, Detail: " (algorithm: " + keyAlg.String() + ")"}}
	}
	return genResp, nil
}

// kmsPublicKey returns the public half of the KMS key keyID, which the KMS
// returns DER-encoded (RFC 5280 SubjectPublicKeyInfo).
func (s *QuicBaaSKMSKeyStore) kmsPublicKey(ctx context.Context, keyID string) (crypto.PublicKey, error) {
	resp, err := s.client.Security().KMS().GetPublicKey(ctx, keyID)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrKMSKeyNotFound, Cause: err}
	}
	if resp == nil || len(resp.PublicKey) == 0 {
		return nil, &DetailError{Err: ErrKMSKeyNotFound, Detail: ": no public key for " + keyID}
	}

	pubKey, err := x509.ParsePKIXPublicKey(resp.PublicKey)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to parse the KMS public key of " + keyID, Err: err}
	}
	return pubKey, nil
}

// newKeyMetadata describes a key the KMS has just generated; publishKey adds
// its public key.
func newKeyMetadata(genResp *kms.GenerateKeyResponse, tenantID, zoneName string, keyType KeyType, algorithm uint8, flags uint16) *dnssecKeyMetadata {
	return &dnssecKeyMetadata{
		KeyID:     genResp.KeyID,
		Algorithm: genResp.Algorithm,
		DNSSECAlg: algorithm,
		Flags:     flags,
		ZoneName:  zoneName,
		TenantID:  tenantID,
		KeyType:   keyType,
	}
}

// publishKey builds the DNSKEY for pubKey and then stores the key's metadata.
// The DNSKEY is built first, so no step can fail after the metadata is
// written: on an error nothing is stored and the caller deletes the KMS key.
func (s *QuicBaaSKMSKeyStore) publishKey(ctx context.Context, keyID string, metadata *dnssecKeyMetadata, pubKey crypto.PublicKey) (*dns.DNSKEY, error) {
	dnskey, err := buildDNSKEY(metadata.ZoneName, pubKey, metadata.DNSSECAlg, metadata.Flags)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to build DNSKEY", Err: err}
	}

	metadata.PublicKeyPEM, err = encodePublicKeyToPEM(pubKey)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to encode public key", Err: err}
	}

	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to marshal metadata", Err: err}
	}

	_, err = s.client.KV().Put(ctx, &service.PutRequest{
		EntityType: dnssecKeyMetadataEntityType,
		ID:         keyIDToEntityID(keyID),
		Data:       metadataJSON,
	})
	if err != nil {
		return nil, &WrappedError{Msg: "failed to store key metadata", Err: err}
	}
	return dnskey, nil
}

// GetSigner returns a crypto.Signer for the specified tenant, zone, and key type.
func (s *QuicBaaSKMSKeyStore) GetSigner(ctx context.Context, tenantID, zoneName string, keyType KeyType) (crypto.Signer, error) {
	keyID := makeKeyID(tenantID, zoneName, keyType)

	// Verify the key exists
	keyInfo, err := s.client.Security().KMS().GetKey(ctx, keyID)
	if err != nil {
		return nil, &DNSSECError{
			Op:   "GetSigner",
			Zone: zoneName,
			Err:  &SentinelCauseError{Sentinel: ErrKMSKeyNotFound, Cause: err},
		}
	}

	if keyInfo == nil {
		return nil, &DNSSECError{
			Op:   "GetSigner",
			Zone: zoneName,
			Err:  ErrKMSKeyNotFound,
		}
	}

	// Get the stored metadata to retrieve the public key
	metadata, err := s.getKeyMetadata(ctx, keyID)
	if err != nil {
		return nil, &DNSSECError{
			Op:   "GetSigner",
			Zone: zoneName,
			Err:  &WrappedError{Msg: "failed to get key metadata", Err: err},
		}
	}

	// Parse the public key from PEM
	pubKey, err := parsePublicKeyFromPEM(metadata.PublicKeyPEM, quicbaasAlgorithmToString(metadata.Algorithm))
	if err != nil {
		return nil, &DNSSECError{
			Op:   "GetSigner",
			Zone: zoneName,
			Err:  &WrappedError{Msg: "failed to parse public key", Err: err},
		}
	}

	// Create a signer wrapper that uses the QuicBaaS Crypto client
	signer := &quicbaasKMSSigner{
		client:    s.client,
		keyID:     keyID,
		algorithm: keyInfo.Algorithm,
		publicKey: pubKey,
	}

	return signer, nil
}

// GetDNSKEY retrieves the DNSKEY record for the specified tenant, zone, and key type.
func (s *QuicBaaSKMSKeyStore) GetDNSKEY(ctx context.Context, tenantID, zoneName string, keyType KeyType) (*dns.DNSKEY, error) {
	keyID := makeKeyID(tenantID, zoneName, keyType)

	// Get key metadata
	metadata, err := s.getKeyMetadata(ctx, keyID)
	if err != nil {
		return nil, &DNSSECError{
			Op:   "GetDNSKEY",
			Zone: zoneName,
			Err:  &SentinelCauseError{Sentinel: ErrKMSKeyNotFound, Cause: err},
		}
	}

	// Parse the public key from PEM
	pubKey, err := parsePublicKeyFromPEM(metadata.PublicKeyPEM, quicbaasAlgorithmToString(metadata.Algorithm))
	if err != nil {
		return nil, &DNSSECError{
			Op:   "GetDNSKEY",
			Zone: zoneName,
			Err:  &WrappedError{Msg: "failed to parse public key", Err: err},
		}
	}

	// Build the DNSKEY record using stored metadata
	dnskey, err := buildDNSKEY(zoneName, pubKey, metadata.DNSSECAlg, metadata.Flags)
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
func (s *QuicBaaSKMSKeyStore) KeyExists(ctx context.Context, tenantID, zoneName string, keyType KeyType) bool {
	keyID := makeKeyID(tenantID, zoneName, keyType)

	keyInfo, err := s.client.Security().KMS().GetKey(ctx, keyID)
	if err != nil {
		return false
	}

	return keyInfo != nil
}

// DeleteKey removes a key from the store for the specified tenant.
func (s *QuicBaaSKMSKeyStore) DeleteKey(ctx context.Context, tenantID, zoneName string, keyType KeyType) error {
	keyID := makeKeyID(tenantID, zoneName, keyType)

	// Delete the KMS key
	err := s.client.Security().KMS().DeleteKey(ctx, keyID)
	if err != nil {
		return &DNSSECError{
			Op:   "DeleteKey",
			Zone: zoneName,
			Err:  &WrappedError{Msg: "failed to delete KMS key", Err: err},
		}
	}

	// Delete the metadata from KV store
	entityID := keyIDToEntityID(keyID)
	_, err = s.client.KV().Delete(ctx, &service.DeleteRequest{
		EntityType: dnssecKeyMetadataEntityType,
		ID:         entityID,
	})
	if err != nil {
		// Log but don't fail - the KMS key is already deleted
		// Orphaned metadata can be cleaned up later
		return &DNSSECError{
			Op:   "DeleteKey",
			Zone: zoneName,
			Err:  &WrappedError{Msg: "KMS key deleted but failed to delete metadata", Err: err},
		}
	}

	return nil
}

// =============================================================================
// Helper methods
// =============================================================================

// keyIDToEntityID converts a string key ID to a numeric entity ID using a hash.
func keyIDToEntityID(keyID string) uint64 {
	hash := sha256.Sum256([]byte(keyID))
	return binary.BigEndian.Uint64(hash[:8])
}

// getKeyMetadata retrieves the key metadata from KV store.
func (s *QuicBaaSKMSKeyStore) getKeyMetadata(ctx context.Context, keyID string) (*dnssecKeyMetadata, error) {
	entityID := keyIDToEntityID(keyID)

	resp, err := s.client.KV().Get(ctx, &service.GetRequest{
		EntityType: dnssecKeyMetadataEntityType,
		ID:         entityID,
	})
	if err != nil {
		return nil, &WrappedError{Msg: "failed to get key metadata", Err: err}
	}

	if resp == nil || !resp.Found || len(resp.Data) == 0 {
		return nil, &MessageError{Msg: "key metadata not found"}
	}

	var metadata dnssecKeyMetadata
	if err := json.Unmarshal(resp.Data, &metadata); err != nil {
		return nil, &WrappedError{Msg: "failed to unmarshal metadata", Err: err}
	}

	return &metadata, nil
}

// =============================================================================
// quicbaasKMSSigner implements crypto.Signer using the QuicBaaS Crypto client
// =============================================================================

// quicbaasKMSSigner wraps the QuicBaaS Crypto client to implement crypto.Signer.
type quicbaasKMSSigner struct {
	client    quicbaas.Client
	keyID     string
	algorithm kms.KeyAlgorithm
	publicKey crypto.PublicKey
}

// Public returns the public key.
func (s *quicbaasKMSSigner) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign signs the digest using the QuicBaaS Crypto client.
func (s *quicbaasKMSSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	ctx := context.Background()

	// Determine hash algorithm from SignerOpts
	hashAlg := ddbcrypto.HashSHA256
	if opts != nil {
		switch opts.HashFunc() {
		case crypto.SHA256:
			hashAlg = ddbcrypto.HashSHA256
		case crypto.SHA384:
			hashAlg = ddbcrypto.HashSHA384
		case crypto.SHA512:
			hashAlg = ddbcrypto.HashSHA512
		}
	}

	req := &ddbcrypto.SignRequest{
		KeyID:   s.keyID,
		Data:    digest,
		HashAlg: hashAlg,
	}

	resp, err := s.client.Security().Crypto().Sign(ctx, req)
	if err != nil {
		return nil, &WrappedError{Msg: "quicbaas sign failed", Err: err}
	}

	return resp.Signature, nil
}

// =============================================================================
// Algorithm conversion helpers for QuicBaaS
// =============================================================================

// dnssecAlgorithmToQuicBaaSAlgorithm maps a DNSSEC algorithm to QuicBaaS KMS algorithm.
func dnssecAlgorithmToQuicBaaSAlgorithm(algorithm uint8) (kms.KeyAlgorithm, error) {
	switch algorithm {
	case dns.RSASHA256, dns.RSASHA512:
		return kms.AlgorithmRSA2048, nil
	case dns.ECDSAP256SHA256:
		return kms.AlgorithmECDSAP256, nil
	case dns.ECDSAP384SHA384:
		return kms.AlgorithmECDSAP384, nil
	case dns.ED25519:
		return kms.AlgorithmED25519, nil
	default:
		return 0, &SentinelCauseError{Sentinel: ErrUnsupportedAlgorithm, Cause: &MessageError{Msg: fmt.Sprintf("algorithm %d (%s)", algorithm, dns.AlgorithmToString[algorithm])}}
	}
}

// quicbaasAlgorithmToString returns the string representation of a QuicBaaS algorithm.
func quicbaasAlgorithmToString(algorithm kms.KeyAlgorithm) string {
	switch algorithm {
	case kms.AlgorithmRSA2048:
		return "RSA2048"
	case kms.AlgorithmRSA4096:
		return "RSA4096"
	case kms.AlgorithmECDSAP256:
		return "ECDSA-P256"
	case kms.AlgorithmECDSAP384:
		return "ECDSA-P384"
	case kms.AlgorithmED25519:
		return "ED25519"
	default:
		return "UNKNOWN"
	}
}

// =============================================================================
// Public key generation and encoding helpers
// =============================================================================

// generateLocalPublicKey generates a local key pair and returns the public key.
// This is a temporary solution for testing and development.
// In production, the QuicBaaS KMS SDK should be extended to return the public key.
// encodePublicKeyToPEM encodes a public key to PEM format.
func encodePublicKeyToPEM(pubKey crypto.PublicKey) (string, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", &WrappedError{Msg: "failed to marshal public key", Err: err}
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	return string(pem.EncodeToMemory(block)), nil
}

// =============================================================================
// Interface compliance verification
// =============================================================================

// Ensure QuicBaaSKMSKeyStore implements DNSSECKeyStore
var _ DNSSECKeyStore = (*QuicBaaSKMSKeyStore)(nil)
