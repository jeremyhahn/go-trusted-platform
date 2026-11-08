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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
)

// MockKeyStore implements DNSSECKeyStore for testing.
type MockKeyStore struct {
	keys map[string]*mockKeyEntry
}

type mockKeyEntry struct {
	dnskey *dns.DNSKEY
	signer crypto.Signer
}

// NewMockKeyStore creates a new mock key store for testing.
func NewMockKeyStore() *MockKeyStore {
	return &MockKeyStore{
		keys: make(map[string]*mockKeyEntry),
	}
}

func (m *MockKeyStore) GenerateKSK(ctx context.Context, tenantID, zoneName string, algorithm uint8) (*dns.DNSKEY, error) {
	return m.generateKey(ctx, tenantID, zoneName, KeyTypeKSK, algorithm, 257)
}

func (m *MockKeyStore) GenerateZSK(ctx context.Context, tenantID, zoneName string, algorithm uint8) (*dns.DNSKEY, error) {
	return m.generateKey(ctx, tenantID, zoneName, KeyTypeZSK, algorithm, 256)
}

func (m *MockKeyStore) generateKey(ctx context.Context, tenantID, zoneName string, keyType KeyType, algorithm uint8, flags uint16) (*dns.DNSKEY, error) {
	// Generate a real ECDSA key for testing
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

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
		PublicKey: ecdsaPublicKeyToBase64(&privateKey.PublicKey),
	}

	keyID := makeKeyID(tenantID, zoneName, keyType)
	m.keys[keyID] = &mockKeyEntry{
		dnskey: dnskey,
		signer: privateKey,
	}

	return dnskey, nil
}

func (m *MockKeyStore) GetSigner(ctx context.Context, tenantID, zoneName string, keyType KeyType) (crypto.Signer, error) {
	keyID := makeKeyID(tenantID, zoneName, keyType)
	entry, ok := m.keys[keyID]
	if !ok {
		return nil, &DNSSECError{
			Op:   "GetSigner",
			Zone: zoneName,
			Err:  ErrKMSKeyNotFound,
		}
	}
	return entry.signer, nil
}

func (m *MockKeyStore) GetDNSKEY(ctx context.Context, tenantID, zoneName string, keyType KeyType) (*dns.DNSKEY, error) {
	keyID := makeKeyID(tenantID, zoneName, keyType)
	entry, ok := m.keys[keyID]
	if !ok {
		return nil, &DNSSECError{
			Op:   "GetDNSKEY",
			Zone: zoneName,
			Err:  ErrKMSKeyNotFound,
		}
	}
	return entry.dnskey, nil
}

func (m *MockKeyStore) KeyExists(ctx context.Context, tenantID, zoneName string, keyType KeyType) bool {
	keyID := makeKeyID(tenantID, zoneName, keyType)
	_, ok := m.keys[keyID]
	return ok
}

func (m *MockKeyStore) DeleteKey(ctx context.Context, tenantID, zoneName string, keyType KeyType) error {
	keyID := makeKeyID(tenantID, zoneName, keyType)
	delete(m.keys, keyID)
	return nil
}

// Verify MockKeyStore implements DNSSECKeyStore.
var _ DNSSECKeyStore = (*MockKeyStore)(nil)

func TestMakeKeyID(t *testing.T) {
	tests := []struct {
		name     string
		tenantID string
		zoneName string
		keyType  KeyType
		expected string
	}{
		{
			name:     "KSK with trailing dot",
			tenantID: "test-tenant",
			zoneName: "example.com.",
			keyType:  KeyTypeKSK,
			expected: "dnssec_test-tenant_example-com_ksk",
		},
		{
			name:     "ZSK without trailing dot",
			tenantID: "test-tenant",
			zoneName: "example.com",
			keyType:  KeyTypeZSK,
			expected: "dnssec_test-tenant_example-com_zsk",
		},
		{
			name:     "subdomain",
			tenantID: "platform",
			zoneName: "sub.example.com.",
			keyType:  KeyTypeKSK,
			expected: "dnssec_platform_sub-example-com_ksk",
		},
		{
			name:     "deep subdomain",
			tenantID: "platform",
			zoneName: "a.b.c.example.com.",
			keyType:  KeyTypeKSK,
			expected: "dnssec_platform_a-b-c-example-com_ksk",
		},
		{
			name:     "single label",
			tenantID: "acme-corp",
			zoneName: "localhost.",
			keyType:  KeyTypeZSK,
			expected: "dnssec_acme-corp_localhost_zsk",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := makeKeyID(tt.tenantID, tt.zoneName, tt.keyType)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMockKeyStore_GenerateAndLoadKeys(t *testing.T) {
	store := NewMockKeyStore()
	ctx := context.Background()

	// Generate KSK
	ksk, err := store.GenerateKSK(ctx, "test-tenant", "example.com.", dns.ECDSAP256SHA256)
	require.NoError(t, err)
	require.NotNil(t, ksk)
	assert.Equal(t, uint16(257), ksk.Flags)
	assert.Equal(t, dns.ECDSAP256SHA256, ksk.Algorithm)

	// Generate ZSK
	zsk, err := store.GenerateZSK(ctx, "test-tenant", "example.com.", dns.ECDSAP256SHA256)
	require.NoError(t, err)
	require.NotNil(t, zsk)
	assert.Equal(t, uint16(256), zsk.Flags)

	// Verify keys exist
	assert.True(t, store.KeyExists(ctx, "test-tenant", "example.com.", KeyTypeKSK))
	assert.True(t, store.KeyExists(ctx, "test-tenant", "example.com.", KeyTypeZSK))

	// Get signers
	kskSigner, err := store.GetSigner(ctx, "test-tenant", "example.com.", KeyTypeKSK)
	require.NoError(t, err)
	require.NotNil(t, kskSigner)

	zskSigner, err := store.GetSigner(ctx, "test-tenant", "example.com.", KeyTypeZSK)
	require.NoError(t, err)
	require.NotNil(t, zskSigner)

	// Get DNSKEY records
	loadedKSK, err := store.GetDNSKEY(ctx, "test-tenant", "example.com.", KeyTypeKSK)
	require.NoError(t, err)
	assert.Equal(t, ksk.KeyTag(), loadedKSK.KeyTag())

	loadedZSK, err := store.GetDNSKEY(ctx, "test-tenant", "example.com.", KeyTypeZSK)
	require.NoError(t, err)
	assert.Equal(t, zsk.KeyTag(), loadedZSK.KeyTag())
}

func TestMockKeyStore_KeyNotFound(t *testing.T) {
	store := NewMockKeyStore()
	ctx := context.Background()

	// Try to get non-existent key
	_, err := store.GetSigner(ctx, "test-tenant", "nonexistent.com.", KeyTypeKSK)
	require.Error(t, err)

	_, err = store.GetDNSKEY(ctx, "test-tenant", "nonexistent.com.", KeyTypeKSK)
	require.Error(t, err)

	assert.False(t, store.KeyExists(ctx, "test-tenant", "nonexistent.com.", KeyTypeKSK))
}

func TestMockKeyStore_DeleteKey(t *testing.T) {
	store := NewMockKeyStore()
	ctx := context.Background()

	// Generate key
	_, err := store.GenerateKSK(ctx, "test-tenant", "example.com.", dns.ECDSAP256SHA256)
	require.NoError(t, err)
	assert.True(t, store.KeyExists(ctx, "test-tenant", "example.com.", KeyTypeKSK))

	// Delete key
	err = store.DeleteKey(ctx, "test-tenant", "example.com.", KeyTypeKSK)
	require.NoError(t, err)
	assert.False(t, store.KeyExists(ctx, "test-tenant", "example.com.", KeyTypeKSK))
}

func TestDNSSECService_WithMockKeyStore(t *testing.T) {
	logger := createTestLogger()
	config := &DNSSECConfig{
		Enabled: true,
		DefaultKey: &common.KeyConfig{
			KeyAlgorithm: "ECDSA",
			ECCConfig:    &common.ECCConfig{Curve: "P-256"},
		},
		SignatureExpiry: "30d",
		NSECMode:        "nsec",
	}

	store := NewMockKeyStore()

	// Create the service directly with the mock store
	svc := &DNSSECService{
		config:   config,
		logger:   logger,
		keyStore: store,
	}
	require.NotNil(t, svc)

	// Generate keys through the service
	ksk, zsk, err := svc.GenerateKeys("test-tenant", "example.com.")
	require.NoError(t, err)
	require.NotNil(t, ksk)
	require.NotNil(t, zsk)
	assert.Equal(t, uint16(257), ksk.Flags)
	assert.Equal(t, uint16(256), zsk.Flags)

	// Keys should exist
	assert.True(t, svc.KeysExist("test-tenant", "example.com."))

	// Load keys
	kskPair, zskPair, err := svc.LoadKeys("test-tenant", "example.com.")
	require.NoError(t, err)
	require.NotNil(t, kskPair)
	require.NotNil(t, zskPair)
	assert.Equal(t, ksk.KeyTag(), kskPair.DNSKEY.KeyTag())
	assert.Equal(t, zsk.KeyTag(), zskPair.DNSKEY.KeyTag())
}

func TestDNSSECService_SignZoneWithMockKeyStore(t *testing.T) {
	logger := createTestLogger()
	config := &DNSSECConfig{
		Enabled: true,
		DefaultKey: &common.KeyConfig{
			KeyAlgorithm: "ECDSA",
			ECCConfig:    &common.ECCConfig{Curve: "P-256"},
		},
		SignatureExpiry: "30d",
		NSECMode:        "nsec",
	}

	store := NewMockKeyStore()

	// Create the service directly with the mock store
	svc := &DNSSECService{
		config:   config,
		logger:   logger,
		keyStore: store,
	}

	zone := createTestZone()

	// Sign the zone (will generate keys via mock store)
	err := svc.SignZone(zone)
	require.NoError(t, err)

	// Verify DNSKEY records were added
	assert.GreaterOrEqual(t, len(zone.RecordSet.DNSKEYRecords), 2)

	// Verify RRSIG records were created
	assert.Greater(t, len(zone.RecordSet.RRSIGRecords), 0)

	// Verify NSEC records were created
	assert.Greater(t, len(zone.RecordSet.NSECRecords), 0)

	// Verify DS record was created
	assert.GreaterOrEqual(t, len(zone.RecordSet.DSRecords), 1)
}

func TestNewXKMSKeyStore_NilAdapter(t *testing.T) {
	_, err := NewXKMSKeyStore(nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrKeyStoreNil)
}

func TestNewXKMSKeyStoreWithBackend_NilAdapter(t *testing.T) {
	_, err := NewXKMSKeyStoreWithBackend(nil, "software")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrKeyStoreNil)
}

func TestNewXKMSKeyStoreWithBackend_EmptyBackend(t *testing.T) {
	// This test verifies that an empty backend defaults to "software"
	// We can't test this without a real adapter, so we just verify the error
	// when adapter is nil
	_, err := NewXKMSKeyStoreWithBackend(nil, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrKeyStoreNil)
}

func TestDnssecAlgorithmToXKMSParams(t *testing.T) {
	tests := []struct {
		name      string
		algorithm uint8
		wantAlg   string
		wantSize  int
		wantCurve string
		wantErr   bool
	}{
		{"RSASHA256", dns.RSASHA256, "RSA", 2048, "", false},
		{"RSASHA512", dns.RSASHA512, "RSA", 2048, "", false},
		{"ECDSAP256SHA256", dns.ECDSAP256SHA256, "ECDSA", 0, "P-256", false},
		{"ECDSAP384SHA384", dns.ECDSAP384SHA384, "ECDSA", 0, "P-384", false},
		{"ED25519", dns.ED25519, "ED25519", 0, "", false},
		{"Unknown", 0, "", 0, "", true},
		{"RSASHA1", dns.RSASHA1, "", 0, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alg, size, curve, err := dnssecAlgorithmToXKMSParams(tt.algorithm)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantAlg, alg)
				assert.Equal(t, tt.wantSize, size)
				assert.Equal(t, tt.wantCurve, curve)
			}
		})
	}
}

func TestXKMSAlgorithmToDNSSEC(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
		wantAlg   uint8
		wantErr   bool
	}{
		{"RSA", "RSA", dns.RSASHA256, false},
		{"RSA2048", "RSA2048", dns.RSASHA256, false},
		{"RSA3072", "RSA3072", dns.RSASHA256, false},
		{"RSA4096", "RSA4096", dns.RSASHA256, false},
		{"ECDSA", "ECDSA", dns.ECDSAP256SHA256, false},
		{"ECDSA-P256", "ECDSA-P256", dns.ECDSAP256SHA256, false},
		{"P256", "P256", dns.ECDSAP256SHA256, false},
		{"P-256", "P-256", dns.ECDSAP256SHA256, false},
		{"ECDSA-P384", "ECDSA-P384", dns.ECDSAP384SHA384, false},
		{"P384", "P384", dns.ECDSAP384SHA384, false},
		{"P-384", "P-384", dns.ECDSAP384SHA384, false},
		{"ED25519", "ED25519", dns.ED25519, false},
		{"lowercase rsa", "rsa", dns.RSASHA256, false},
		{"lowercase ecdsa", "ecdsa", dns.ECDSAP256SHA256, false},
		{"lowercase ed25519", "ed25519", dns.ED25519, false},
		{"unsupported", "UNSUPPORTED", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := xkmsAlgorithmToDNSSEC(tt.algorithm)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "not supported")
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantAlg, result)
			}
		})
	}
}

func TestEcdsaPublicKeyToBase64(t *testing.T) {
	// Generate a test key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	encoded := ecdsaPublicKeyToBase64(&privateKey.PublicKey)
	assert.NotEmpty(t, encoded)
	// P-256 public key should be 64 bytes (32 bytes each for X and Y)
	// Base64 of 64 bytes = 88 characters
	assert.Equal(t, 88, len(encoded))
}

func TestEcdsaPublicKeyToBase64_P384(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	encoded := ecdsaPublicKeyToBase64(&privateKey.PublicKey)
	assert.NotEmpty(t, encoded)
	// P-384 public key should be 96 bytes (48 bytes each for X and Y)
	// Base64 of 96 bytes = 128 characters
	assert.Equal(t, 128, len(encoded))
}

func TestEcdsaPublicKeyToBase64_P521(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	encoded := ecdsaPublicKeyToBase64(&privateKey.PublicKey)
	assert.NotEmpty(t, encoded)
	// P-521 public key should be 132 bytes (66 bytes each for X and Y)
	// Base64 of 132 bytes = 176 characters
	assert.Equal(t, 176, len(encoded))
}

func TestRsaPublicKeyToBase64(t *testing.T) {
	// Test with a small key for speed
	key, err := sharedRSAKey()
	require.NoError(t, err)

	encoded := rsaPublicKeyToBase64(&key.PublicKey)
	assert.NotEmpty(t, encoded)
	// Verify it doesn't contain newlines or spaces
	assert.NotContains(t, encoded, "\n")
	assert.NotContains(t, encoded, " ")
}

func TestRsaPublicKeyToBase64_LargeExponent(t *testing.T) {
	// Create a key with standard exponent 65537
	key := &rsa.PublicKey{
		N: new(big.Int).SetBytes(make([]byte, 256)), // 2048-bit modulus
		E: 65537,
	}
	// Set some value for N to avoid issues
	key.N.SetString("12345678901234567890", 10)

	encoded := rsaPublicKeyToBase64(key)
	assert.NotEmpty(t, encoded)
}

func TestEd25519PublicKeyToBase64(t *testing.T) {
	// Ed25519 public key is 32 bytes
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	encoded := ed25519PublicKeyToBase64(key)
	assert.NotEmpty(t, encoded)
	// Base64 of 32 bytes = 44 characters
	assert.Equal(t, 44, len(encoded))
}

func TestEd25519PublicKeyToBase64_Generated(t *testing.T) {
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	encoded := ed25519PublicKeyToBase64(pubKey)
	assert.NotEmpty(t, encoded)
	assert.Equal(t, 44, len(encoded))
}

func TestDNSSECService_KeysExist(t *testing.T) {
	logger := createTestLogger()
	config := &DNSSECConfig{
		Enabled: true,
		DefaultKey: &common.KeyConfig{
			KeyAlgorithm: "ECDSA",
			ECCConfig:    &common.ECCConfig{Curve: "P-256"},
		},
	}

	store := NewMockKeyStore()
	svc := &DNSSECService{
		config:   config,
		logger:   logger,
		keyStore: store,
	}

	// No keys yet
	assert.False(t, svc.KeysExist("test-tenant", "example.com."))

	// Generate keys
	_, _, err := svc.GenerateKeys("test-tenant", "example.com.")
	require.NoError(t, err)

	// Keys should exist now
	assert.True(t, svc.KeysExist("test-tenant", "example.com."))
}

// TestBuildKeyAttrsFromXKMSAlgorithm tests key attribute building from xkms algorithm.
func TestBuildKeyAttrsFromXKMSAlgorithm(t *testing.T) {
	tests := []struct {
		name      string
		keyID     string
		algorithm string
		wantAlg   x509.PublicKeyAlgorithm
	}{
		{
			name:      "RSA",
			keyID:     "test-rsa-key",
			algorithm: "RSA",
			wantAlg:   x509.RSA,
		},
		{
			name:      "RSA2048",
			keyID:     "test-rsa2048-key",
			algorithm: "RSA2048",
			wantAlg:   x509.RSA,
		},
		{
			name:      "RSA3072",
			keyID:     "test-rsa3072-key",
			algorithm: "RSA3072",
			wantAlg:   x509.RSA,
		},
		{
			name:      "RSA4096",
			keyID:     "test-rsa4096-key",
			algorithm: "RSA4096",
			wantAlg:   x509.RSA,
		},
		{
			name:      "ECDSA-P256",
			keyID:     "test-ecdsa-key",
			algorithm: "ECDSA-P256",
			wantAlg:   x509.ECDSA,
		},
		{
			name:      "ECDSA-P384",
			keyID:     "test-ecdsa384-key",
			algorithm: "ECDSA-P384",
			wantAlg:   x509.ECDSA,
		},
		{
			name:      "ECDSA-P521",
			keyID:     "test-ecdsa521-key",
			algorithm: "ECDSA-P521",
			wantAlg:   x509.ECDSA,
		},
		{
			name:      "Ed25519",
			keyID:     "test-ed25519-key",
			algorithm: "ED25519",
			wantAlg:   x509.Ed25519,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := buildKeyAttrsFromXKMSAlgorithm(tt.keyID, tt.algorithm)

			assert.NotNil(t, attrs)
			assert.Equal(t, tt.keyID, attrs.CN)
			assert.Equal(t, tt.wantAlg, attrs.keyAlgorithm)
		})
	}
}

// TestBuildDNSKEY tests the DNSKEY record building function.
func TestBuildDNSKEY(t *testing.T) {
	// Generate test keys
	rsaKey, err := sharedRSAKey()
	require.NoError(t, err)

	ecdsaP256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ecdsaP384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	// For ed25519, the first return value is the public key
	ed25519PubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name      string
		zoneName  string
		pubKey    interface{}
		algorithm uint8
		flags     uint16
		wantErr   bool
	}{
		{
			name:      "RSA KSK",
			zoneName:  "example.com.",
			pubKey:    &rsaKey.PublicKey,
			algorithm: dns.RSASHA256,
			flags:     257,
			wantErr:   false,
		},
		{
			name:      "RSA ZSK",
			zoneName:  "example.com.",
			pubKey:    &rsaKey.PublicKey,
			algorithm: dns.RSASHA256,
			flags:     256,
			wantErr:   false,
		},
		{
			name:      "ECDSA P256",
			zoneName:  "test.org.",
			pubKey:    &ecdsaP256Key.PublicKey,
			algorithm: dns.ECDSAP256SHA256,
			flags:     257,
			wantErr:   false,
		},
		{
			name:      "ECDSA P384",
			zoneName:  "test.net.",
			pubKey:    &ecdsaP384Key.PublicKey,
			algorithm: dns.ECDSAP384SHA384,
			flags:     256,
			wantErr:   false,
		},
		{
			name:      "Ed25519",
			zoneName:  "ed.example.",
			pubKey:    ed25519PubKey,
			algorithm: dns.ED25519,
			flags:     257,
			wantErr:   false,
		},
		{
			name:      "zone without trailing dot",
			zoneName:  "example.com",
			pubKey:    &rsaKey.PublicKey,
			algorithm: dns.RSASHA256,
			flags:     257,
			wantErr:   false,
		},
		{
			name:      "unsupported key type",
			zoneName:  "example.com.",
			pubKey:    "invalid-key",
			algorithm: dns.RSASHA256,
			flags:     257,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dnskey, err := buildDNSKEY(tt.zoneName, tt.pubKey, tt.algorithm, tt.flags)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, dnskey)
			} else {
				require.NoError(t, err)
				require.NotNil(t, dnskey)

				// Verify the DNSKEY record
				assert.Equal(t, dns.Fqdn(tt.zoneName), dnskey.Hdr.Name)
				assert.Equal(t, dns.TypeDNSKEY, dnskey.Hdr.Rrtype)
				assert.Equal(t, uint16(dns.ClassINET), dnskey.Hdr.Class)
				assert.Equal(t, uint32(86400), dnskey.Hdr.Ttl)
				assert.Equal(t, tt.flags, dnskey.Flags)
				assert.Equal(t, uint8(3), dnskey.Protocol)
				assert.Equal(t, tt.algorithm, dnskey.Algorithm)
				assert.NotEmpty(t, dnskey.PublicKey)
			}
		})
	}
}

// TestKeyTypeConstants tests that key type constants are correctly defined.
func TestKeyTypeConstants(t *testing.T) {
	assert.Equal(t, KeyType("ksk"), KeyTypeKSK)
	assert.Equal(t, KeyType("zsk"), KeyTypeZSK)
}

// TestParsePublicKeyFromXKMS tests parsing public keys from XKMS format.
func TestParsePublicKeyFromXKMS(t *testing.T) {
	// Test with empty bytes
	_, err := parsePublicKeyFromXKMS(nil, "RSA")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty public key bytes")

	_, err = parsePublicKeyFromXKMS([]byte{}, "RSA")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty public key bytes")

	// Test with Ed25519 raw public key
	ed25519PubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	parsedKey, err := parsePublicKeyFromXKMS([]byte(ed25519PubKey), "ED25519")
	require.NoError(t, err)
	assert.IsType(t, ed25519.PublicKey{}, parsedKey)

	// Test with PKIX encoded RSA key
	rsaKey, err := sharedRSAKey()
	require.NoError(t, err)

	pkixBytes, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	require.NoError(t, err)

	parsedRSA, err := parsePublicKeyFromXKMS(pkixBytes, "RSA")
	require.NoError(t, err)
	assert.IsType(t, &rsa.PublicKey{}, parsedRSA)

	// Test with PKIX encoded ECDSA key
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ecdsaPkixBytes, err := x509.MarshalPKIXPublicKey(&ecdsaKey.PublicKey)
	require.NoError(t, err)

	parsedECDSA, err := parsePublicKeyFromXKMS(ecdsaPkixBytes, "ECDSA")
	require.NoError(t, err)
	assert.IsType(t, &ecdsa.PublicKey{}, parsedECDSA)

	// Test with invalid bytes
	_, err = parsePublicKeyFromXKMS([]byte{0x01, 0x02, 0x03}, "RSA")
	assert.Error(t, err)
}

// TestParsePublicKeyFromPEM tests parsing public keys from PEM format.
func TestParsePublicKeyFromPEM(t *testing.T) {
	// Test with empty PEM
	_, err := parsePublicKeyFromPEM("", "RSA")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty public key PEM")

	// Test with invalid PEM
	_, err = parsePublicKeyFromPEM("not a pem", "RSA")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode PEM block")

	// Test with valid RSA key in PEM
	rsaKey, err := sharedRSAKey()
	require.NoError(t, err)

	pkixBytes, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	require.NoError(t, err)

	pemBlock := "-----BEGIN PUBLIC KEY-----\n" +
		base64Encode(pkixBytes) +
		"\n-----END PUBLIC KEY-----"

	parsedRSA, err := parsePublicKeyFromPEM(pemBlock, "RSA")
	require.NoError(t, err)
	assert.IsType(t, &rsa.PublicKey{}, parsedRSA)

	// Test with valid ECDSA key in PEM
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ecdsaPkixBytes, err := x509.MarshalPKIXPublicKey(&ecdsaKey.PublicKey)
	require.NoError(t, err)

	ecdsaPemBlock := "-----BEGIN PUBLIC KEY-----\n" +
		base64Encode(ecdsaPkixBytes) +
		"\n-----END PUBLIC KEY-----"

	parsedECDSA, err := parsePublicKeyFromPEM(ecdsaPemBlock, "ECDSA")
	require.NoError(t, err)
	assert.IsType(t, &ecdsa.PublicKey{}, parsedECDSA)
}

// base64Encode is a helper for encoding bytes to base64 with line breaks.
func base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// TestDefaultBackend tests that the default backend constant is set correctly.
func TestDefaultBackend(t *testing.T) {
	assert.Equal(t, "software", defaultBackend)
}

// Verify XKMSKeyStore implements DNSSECKeyStore.
var _ DNSSECKeyStore = (*XKMSKeyStore)(nil)
