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
	"fmt"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/miekg/dns"
)

// SDKKeyStore implements DNSSECKeyStore using the xkms SDK package-level
// functions directly. This avoids the need for an Adapter and Client,
// operating against the already-initialized global xkms service.
type SDKKeyStore struct {
	backend string
}

// NewSDKKeyStore creates a new SDK-backed DNSSEC key store.
// The xkms SDK must already be initialized via xkmssdk.ServiceInitialize
// before calling any methods on this keystore.
func NewSDKKeyStore() *SDKKeyStore {
	return &SDKKeyStore{
		backend: defaultBackend,
	}
}

// NewSDKKeyStoreWithBackend creates a new SDK-backed DNSSEC key store
// targeting a specific backend.
func NewSDKKeyStoreWithBackend(backend string) *SDKKeyStore {
	if backend == "" {
		backend = defaultBackend
	}
	return &SDKKeyStore{
		backend: backend,
	}
}

// GenerateKSK generates a new Key Signing Key for the specified tenant and zone.
func (s *SDKKeyStore) GenerateKSK(ctx context.Context, tenantID, zoneName string, algorithm uint8) (*dns.DNSKEY, error) {
	return s.generateKey(ctx, tenantID, zoneName, KeyTypeKSK, algorithm, 257)
}

// GenerateZSK generates a new Zone Signing Key for the specified tenant and zone.
func (s *SDKKeyStore) GenerateZSK(ctx context.Context, tenantID, zoneName string, algorithm uint8) (*dns.DNSKEY, error) {
	return s.generateKey(ctx, tenantID, zoneName, KeyTypeZSK, algorithm, 256)
}

// generateKey generates a DNSSEC key using the xkms SDK package-level functions.
func (s *SDKKeyStore) generateKey(ctx context.Context, tenantID, zoneName string, keyType KeyType, algorithm uint8, flags uint16) (*dns.DNSKEY, error) {
	keyID := makeKeyID(tenantID, zoneName, keyType)

	attrs, err := s.buildKeyAttributes(keyID, algorithm)
	if err != nil {
		return nil, &DNSSECError{
			Op:   "GenerateKey",
			Zone: zoneName,
			Err:  err,
		}
	}

	privKey, err := xkmssdk.ServiceGenerateKeyWithBackend(ctx, s.backend, attrs)
	if err != nil {
		return nil, &DNSSECError{
			Op:   "GenerateKey",
			Zone: zoneName,
			Err:  &SentinelCauseError{Sentinel: ErrKMSKeyGeneration, Cause: err},
		}
	}

	pubKey, err := extractPublicKey(privKey)
	if err != nil {
		return nil, &DNSSECError{
			Op:   "GenerateKey",
			Zone: zoneName,
			Err:  err,
		}
	}

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
func (s *SDKKeyStore) GetSigner(ctx context.Context, tenantID, zoneName string, keyType KeyType) (crypto.Signer, error) {
	keyID := makeKeyID(tenantID, zoneName, keyType)

	signer, err := xkmssdk.ServiceSignerByID(ctx, keyID)
	if err != nil {
		return nil, &DNSSECError{
			Op:   "GetSigner",
			Zone: zoneName,
			Err:  &SentinelCauseError{Sentinel: ErrKMSKeyNotFound, Cause: err},
		}
	}

	return signer, nil
}

// GetDNSKEY retrieves the DNSKEY record for the specified tenant, zone, and key type.
func (s *SDKKeyStore) GetDNSKEY(ctx context.Context, tenantID, zoneName string, keyType KeyType) (*dns.DNSKEY, error) {
	keyID := makeKeyID(tenantID, zoneName, keyType)

	privKey, err := xkmssdk.ServiceKeyByID(ctx, keyID)
	if err != nil {
		return nil, &DNSSECError{
			Op:   "GetDNSKEY",
			Zone: zoneName,
			Err:  &SentinelCauseError{Sentinel: ErrKMSKeyNotFound, Cause: err},
		}
	}

	pubKey, err := extractPublicKey(privKey)
	if err != nil {
		return nil, &DNSSECError{
			Op:   "GetDNSKEY",
			Zone: zoneName,
			Err:  err,
		}
	}

	algorithm, err := publicKeyToDNSSECAlgorithm(pubKey)
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
func (s *SDKKeyStore) KeyExists(ctx context.Context, tenantID, zoneName string, keyType KeyType) bool {
	keyID := makeKeyID(tenantID, zoneName, keyType)
	_, err := xkmssdk.ServiceKeyByID(ctx, keyID)
	return err == nil
}

// DeleteKey removes a key from the store for the specified tenant.
func (s *SDKKeyStore) DeleteKey(ctx context.Context, tenantID, zoneName string, keyType KeyType) error {
	keyID := makeKeyID(tenantID, zoneName, keyType)

	if err := xkmssdk.ServiceDeleteKeyByID(ctx, keyID); err != nil {
		return &DNSSECError{
			Op:   "DeleteKey",
			Zone: zoneName,
			Err:  &WrappedError{Msg: "failed to delete key", Err: err},
		}
	}

	return nil
}

// buildKeyAttributes creates xkms KeyAttributes from DNSSEC algorithm parameters.
func (s *SDKKeyStore) buildKeyAttributes(keyID string, algorithm uint8) (*xkmssdk.KeyAttributes, error) {
	attrs := &xkmssdk.KeyAttributes{
		CN:        keyID,
		StoreType: xkmssdk.StoreSoftware,
	}

	switch algorithm {
	case dns.RSASHA256, dns.RSASHA512:
		attrs.KeyAlgorithm = x509.RSA
		attrs.RSAAttributes = &xkmssdk.RSAAttributes{
			KeySize: 2048,
		}
		if algorithm == dns.RSASHA256 {
			attrs.Hash = crypto.SHA256
		} else {
			attrs.Hash = crypto.SHA512
		}
	case dns.ECDSAP256SHA256:
		attrs.KeyAlgorithm = x509.ECDSA
		attrs.ECCAttributes = &xkmssdk.ECCAttributes{
			Curve: elliptic.P256(),
		}
		attrs.Hash = crypto.SHA256
	case dns.ECDSAP384SHA384:
		attrs.KeyAlgorithm = x509.ECDSA
		attrs.ECCAttributes = &xkmssdk.ECCAttributes{
			Curve: elliptic.P384(),
		}
		attrs.Hash = crypto.SHA384
	case dns.ED25519:
		attrs.KeyAlgorithm = x509.Ed25519
	default:
		return nil, &SentinelCauseError{Sentinel: ErrUnsupportedAlgorithm, Cause: &MessageError{Msg: fmt.Sprintf("algorithm %d (%s)", algorithm, dns.AlgorithmToString[algorithm])}}
	}

	return attrs, nil
}

// extractPublicKey extracts the public key from a crypto.PrivateKey.
func extractPublicKey(privKey crypto.PrivateKey) (crypto.PublicKey, error) {
	switch k := privKey.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &k.PublicKey, nil
	case ed25519.PrivateKey:
		return k.Public(), nil
	case crypto.Signer:
		return k.Public(), nil
	default:
		return nil, &MessageError{Msg: fmt.Sprintf("unsupported private key type: %T", privKey)}
	}
}

// publicKeyToDNSSECAlgorithm determines the DNSSEC algorithm from a public key type.
func publicKeyToDNSSECAlgorithm(pubKey crypto.PublicKey) (uint8, error) {
	switch k := pubKey.(type) {
	case *rsa.PublicKey:
		return dns.RSASHA256, nil
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return dns.ECDSAP256SHA256, nil
		case elliptic.P384():
			return dns.ECDSAP384SHA384, nil
		default:
			return 0, &SentinelCauseError{Sentinel: ErrUnsupportedAlgorithm, Cause: &MessageError{Msg: fmt.Sprintf("unsupported ECDSA curve %v", k.Curve.Params().Name)}}
		}
	case ed25519.PublicKey:
		return dns.ED25519, nil
	default:
		return 0, &SentinelCauseError{Sentinel: ErrUnsupportedAlgorithm, Cause: &MessageError{Msg: fmt.Sprintf("unsupported public key type %T", pubKey)}}
	}
}
