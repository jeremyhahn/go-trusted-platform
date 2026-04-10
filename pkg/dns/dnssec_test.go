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
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test fixtures
func createTestLogger() *logging.Logger {
	return logging.DefaultLogger()
}

func createTestDNSSECConfig() *DNSSECConfig {
	return &DNSSECConfig{
		Enabled: true,
		DefaultKey: &common.KeyConfig{
			KeyAlgorithm:       "ECDSA",
			SignatureAlgorithm: "ECDSA-SHA256",
			Hash:               "SHA-256",
			StoreType:          "software",
			ECCConfig: &common.ECCConfig{
				Curve: "P-256",
			},
		},
		SignatureExpiry: "30d",
		NSECMode:        "nsec",
		NSEC3Iterations: 0,
		NSEC3Salt:       "",
	}
}

// createTestDNSSECServiceWithMock creates a DNSSEC service with a mock key store for testing.
func createTestDNSSECServiceWithMock(t *testing.T) (*DNSSECService, *MockKeyStore) {
	t.Helper()
	logger := createTestLogger()
	config := createTestDNSSECConfig()
	store := NewMockKeyStore()

	svc := &DNSSECService{
		config:   config,
		logger:   logger,
		keyStore: store,
	}

	return svc, store
}

func createTestZone() *entities.Zone {
	return &entities.Zone{
		ID:          1,
		Name:        "example.com.",
		TenantID:    "test-tenant",
		TTL:         3600,
		Description: "Test zone",
		Internal:    false,
		RecordSet: entities.RecordSet{
			SOARecord: entities.SOARecord{
				Name:       "example.com.",
				MName:      "ns1.example.com.",
				RName:      "hostmaster.example.com.",
				Serial:     2024010101,
				Refresh:    86400,
				Retry:      7200,
				Expire:     3600000,
				MinimumTTL: 3600,
				TTL:        3600,
			},
			NSRecords: []*entities.NSRecord{
				{Name: "example.com.", Value: "ns1.example.com.", TTL: 3600},
				{Name: "example.com.", Value: "ns2.example.com.", TTL: 3600},
			},
			ARecords: []*entities.ARecord{
				{Name: "@", Value: "192.0.2.1", TTL: 3600},
				{Name: "www", Value: "192.0.2.2", TTL: 3600},
				{Name: "mail", Value: "192.0.2.3", TTL: 3600},
			},
			MXRecords: []*entities.MXRecord{
				{Name: "example.com.", Value: "mail.example.com.", Priority: 10, TTL: 3600},
			},
			TXTRecords: []*entities.TXTRecord{
				{Name: "example.com.", Value: "v=spf1 include:_spf.example.com ~all", TTL: 3600},
			},
		},
	}
}

// TestNewDNSSECServiceWithKeyStore tests DNSSECService creation with mock key store
func TestNewDNSSECServiceWithKeyStore(t *testing.T) {
	service, _ := createTestDNSSECServiceWithMock(t)
	require.NotNil(t, service)
	assert.True(t, service.IsEnabled())
}

// TestNewDNSSECServiceWithKeyStore_NilConfig tests error handling for nil config
func TestNewDNSSECServiceWithKeyStore_NilConfig(t *testing.T) {
	logger := createTestLogger()
	store := NewMockKeyStore()

	service, err := NewDNSSECServiceWithKeyStore(nil, logger, store)
	require.Error(t, err)
	require.Nil(t, service)
	assert.ErrorIs(t, err, ErrDNSSECConfigNil)
}

// TestNewDNSSECServiceWithKeyStore_NilLogger tests error handling for nil logger
func TestNewDNSSECServiceWithKeyStore_NilLogger(t *testing.T) {
	config := createTestDNSSECConfig()
	store := NewMockKeyStore()

	service, err := NewDNSSECServiceWithKeyStore(config, nil, store)
	require.Error(t, err)
	require.Nil(t, service)
	assert.ErrorIs(t, err, ErrLoggerNil)
}

// TestNewDNSSECServiceWithKeyStore_NilKeyStore tests error handling for nil key store
func TestNewDNSSECServiceWithKeyStore_NilKeyStore(t *testing.T) {
	logger := createTestLogger()
	config := createTestDNSSECConfig()

	service, err := NewDNSSECServiceWithKeyStore(config, logger, nil)
	require.Error(t, err)
	require.Nil(t, service)
	assert.ErrorIs(t, err, ErrKeyStoreNil)
}

// TestGenerateKeys_EmptyZoneName tests error handling for empty zone name
func TestGenerateKeys_EmptyZoneName(t *testing.T) {
	service, _ := createTestDNSSECServiceWithMock(t)

	ksk, zsk, err := service.GenerateKeys("test-tenant", "")
	require.Error(t, err)
	require.Nil(t, ksk)
	require.Nil(t, zsk)
	assert.ErrorIs(t, err, ErrZoneNameEmpty)
}

// TestLoadKeys_KeyNotFound tests error handling when keys don't exist
func TestLoadKeys_KeyNotFound(t *testing.T) {
	service, _ := createTestDNSSECServiceWithMock(t)

	// Try to load keys that don't exist
	kskPair, zskPair, err := service.LoadKeys("test-tenant", "nonexistent.com.")
	require.Error(t, err)
	require.Nil(t, kskPair)
	require.Nil(t, zskPair)

	// Error should be a DNSSECError
	var dnsError *DNSSECError
	assert.True(t, errors.As(err, &dnsError))
	assert.Equal(t, "LoadKeys", dnsError.Op)
}

// TestGenerateKeys tests key generation
func TestGenerateKeys(t *testing.T) {
	service, _ := createTestDNSSECServiceWithMock(t)

	ksk, zsk, err := service.GenerateKeys("test-tenant", "example.com.")
	require.NoError(t, err)
	require.NotNil(t, ksk)
	require.NotNil(t, zsk)

	// Verify KSK properties
	assert.Equal(t, uint16(257), ksk.Flags, "KSK should have flags 257")
	assert.Equal(t, uint8(3), ksk.Protocol, "KSK should have protocol 3")
	assert.Equal(t, dns.ECDSAP256SHA256, ksk.Algorithm, "KSK should have correct algorithm")
	assert.Equal(t, "example.com.", ksk.Hdr.Name, "KSK should have correct zone name")

	// Verify ZSK properties
	assert.Equal(t, uint16(256), zsk.Flags, "ZSK should have flags 256")
	assert.Equal(t, uint8(3), zsk.Protocol, "ZSK should have protocol 3")
	assert.Equal(t, dns.ECDSAP256SHA256, zsk.Algorithm, "ZSK should have correct algorithm")
	assert.Equal(t, "example.com.", zsk.Hdr.Name, "ZSK should have correct zone name")
}

// TestLoadKeys tests loading existing keys
func TestLoadKeys(t *testing.T) {
	service, _ := createTestDNSSECServiceWithMock(t)

	// First generate keys
	_, _, err := service.GenerateKeys("test-tenant", "example.com.")
	require.NoError(t, err)

	// Now load them
	kskPair, zskPair, err := service.LoadKeys("test-tenant", "example.com.")
	require.NoError(t, err)
	require.NotNil(t, kskPair)
	require.NotNil(t, zskPair)
	require.NotNil(t, kskPair.DNSKEY)
	require.NotNil(t, kskPair.PrivateKey)
	require.NotNil(t, zskPair.DNSKEY)
	require.NotNil(t, zskPair.PrivateKey)

	// Verify loaded keys have correct properties
	assert.Equal(t, uint16(257), kskPair.DNSKEY.Flags, "Loaded KSK should have flags 257")
	assert.Equal(t, uint16(256), zskPair.DNSKEY.Flags, "Loaded ZSK should have flags 256")
}

// TestLoadKeys_NotFound tests error when keys don't exist
func TestLoadKeys_NotFound(t *testing.T) {
	service, _ := createTestDNSSECServiceWithMock(t)

	// Try to load non-existent keys
	kskPair, zskPair, err := service.LoadKeys("test-tenant", "nonexistent.com.")
	require.Error(t, err)
	require.Nil(t, kskPair)
	require.Nil(t, zskPair)
}

// TestSignZone tests zone signing
func TestSignZone(t *testing.T) {
	service, _ := createTestDNSSECServiceWithMock(t)

	zone := createTestZone()

	// Sign the zone
	err := service.SignZone(zone)
	require.NoError(t, err)

	// Verify DNSKEY records were added
	assert.GreaterOrEqual(t, len(zone.RecordSet.DNSKEYRecords), 2, "Should have at least 2 DNSKEY records (KSK and ZSK)")

	// Verify RRSIG records were created
	assert.Greater(t, len(zone.RecordSet.RRSIGRecords), 0, "Should have RRSIG records")

	// Verify NSEC records were created (default mode is nsec)
	assert.Greater(t, len(zone.RecordSet.NSECRecords), 0, "Should have NSEC records")

	// Verify DS record was created
	assert.GreaterOrEqual(t, len(zone.RecordSet.DSRecords), 1, "Should have at least 1 DS record")
}

// TestSignZone_NilZone tests error handling for nil zone
func TestSignZone_NilZone(t *testing.T) {
	service, _ := createTestDNSSECServiceWithMock(t)

	err := service.SignZone(nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrZoneNil)
}

// TestSignZone_NSEC3Mode tests signing with NSEC3
func TestSignZone_NSEC3Mode(t *testing.T) {
	logger := createTestLogger()
	config := &DNSSECConfig{
		Enabled: true,
		DefaultKey: &common.KeyConfig{
			KeyAlgorithm: "ECDSA",
			ECCConfig:    &common.ECCConfig{Curve: "P-256"},
		},
		SignatureExpiry: "30d",
		NSECMode:        "nsec3",
		NSEC3Iterations: 0,
		NSEC3Salt:       "aabb",
	}

	store := NewMockKeyStore()
	service := &DNSSECService{
		config:   config,
		logger:   logger,
		keyStore: store,
	}

	zone := createTestZone()

	err := service.SignZone(zone)
	require.NoError(t, err)

	// Verify NSEC3 records were created
	assert.Greater(t, len(zone.RecordSet.NSEC3Records), 0, "Should have NSEC3 records")

	// Verify NSEC3PARAM record was created
	assert.GreaterOrEqual(t, len(zone.RecordSet.NSEC3PARAMRecords), 1, "Should have NSEC3PARAM record")

	// Should not have NSEC records
	assert.Equal(t, 0, len(zone.RecordSet.NSECRecords), "Should not have NSEC records when using NSEC3")
}

// TestGenerateDS tests DS record generation
func TestGenerateDS(t *testing.T) {
	service, _ := createTestDNSSECServiceWithMock(t)

	ksk, _, err := service.GenerateKeys("test-tenant", "example.com.")
	require.NoError(t, err)

	ds := service.GenerateDS(ksk)
	require.NotNil(t, ds)

	assert.Equal(t, dns.SHA256, ds.DigestType, "DS should use SHA-256 digest")
	assert.Equal(t, ksk.KeyTag(), ds.KeyTag, "DS key tag should match DNSKEY")
	assert.Equal(t, ksk.Algorithm, ds.Algorithm, "DS algorithm should match DNSKEY")
	assert.NotEmpty(t, ds.Digest, "DS digest should not be empty")
}

// TestGenerateNSECChain tests NSEC chain generation
func TestGenerateNSECChain(t *testing.T) {
	service, _ := createTestDNSSECServiceWithMock(t)

	zone := createTestZone()

	nsecRecords := service.GenerateNSECChain(zone)
	require.NotNil(t, nsecRecords)
	assert.Greater(t, len(nsecRecords), 0, "Should generate NSEC records")

	// Verify chain is circular (last points back to first)
	if len(nsecRecords) > 1 {
		last := nsecRecords[len(nsecRecords)-1]
		first := nsecRecords[0]
		assert.Equal(t, first.Hdr.Name, last.NextDomain, "NSEC chain should be circular")
	}

	// Verify each NSEC has correct structure
	for _, nsec := range nsecRecords {
		assert.NotEmpty(t, nsec.Hdr.Name, "NSEC should have owner name")
		assert.NotEmpty(t, nsec.NextDomain, "NSEC should have next domain")
		assert.Greater(t, len(nsec.TypeBitMap), 0, "NSEC should have type bitmap")
	}
}

// TestPrepareKeyRollover tests key rollover preparation
func TestPrepareKeyRollover(t *testing.T) {
	service, _ := createTestDNSSECServiceWithMock(t)

	// First generate initial keys
	_, _, err := service.GenerateKeys("test-tenant", "example.com.")
	require.NoError(t, err)

	// Prepare key rollover for ZSK
	newZSK, err := service.PrepareKeyRollover("test-tenant", "example.com.", "zsk")
	require.NoError(t, err)
	require.NotNil(t, newZSK)

	assert.Equal(t, uint16(256), newZSK.Flags, "New ZSK should have flags 256")
	assert.Equal(t, "example.com.", newZSK.Hdr.Name, "New ZSK should have correct zone name")
}

// TestPrepareKeyRollover_KSK tests key rollover preparation for KSK
func TestPrepareKeyRollover_KSK(t *testing.T) {
	service, _ := createTestDNSSECServiceWithMock(t)

	newKSK, err := service.PrepareKeyRollover("test-tenant", "example.com.", "ksk")
	require.NoError(t, err)
	require.NotNil(t, newKSK)

	assert.Equal(t, uint16(257), newKSK.Flags, "New KSK should have flags 257")
}

// TestPrepareKeyRollover_InvalidKeyType tests error handling for invalid key type
func TestPrepareKeyRollover_InvalidKeyType(t *testing.T) {
	service, _ := createTestDNSSECServiceWithMock(t)

	_, err := service.PrepareKeyRollover("test-tenant", "example.com.", "invalid")
	require.Error(t, err)

	var dnssecErr *DNSSECError
	assert.ErrorAs(t, err, &dnssecErr)
}

// TestKeyBitsForAlgorithm tests key bit size selection
func TestKeyBitsForAlgorithm(t *testing.T) {
	tests := []struct {
		algorithm uint8
		expected  int
	}{
		{dns.RSASHA256, 2048},
		{dns.RSASHA512, 2048},
		{dns.ECDSAP256SHA256, 256},
		{dns.ECDSAP384SHA384, 384},
		{dns.ED25519, 256},
		{0, 256}, // Default
	}

	for _, tt := range tests {
		t.Run(dns.AlgorithmToString[tt.algorithm], func(t *testing.T) {
			bits := keyBitsForAlgorithm(tt.algorithm)
			assert.Equal(t, tt.expected, bits)
		})
	}
}

// TestParseDuration tests duration parsing
func TestParseDuration(t *testing.T) {
	tests := []struct {
		input    string
		expected int64 // in seconds
		wantErr  bool
	}{
		{"30d", 30 * 24 * 3600, false},
		{"24h", 24 * 3600, false},
		{"60m", 60 * 60, false},
		{"30s", 30, false},
		{"1D", 24 * 3600, false},
		{"invalid", 0, true},
		{"", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			d, err := parseDuration(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, int64(d.Seconds()))
			}
		})
	}
}

// TestDNSSECError tests error types
func TestDNSSECError(t *testing.T) {
	err := &DNSSECError{
		Op:   "TestOp",
		Zone: "example.com.",
		Err:  ErrKeyNotFound,
	}

	// Test Error()
	errStr := err.Error()
	assert.Contains(t, errStr, "TestOp")
	assert.Contains(t, errStr, "example.com.")
	assert.Contains(t, errStr, "key not found")

	// Test Unwrap()
	assert.Equal(t, ErrKeyNotFound, err.Unwrap())

	// Test Is()
	assert.True(t, err.Is(ErrKeyNotFound))
	assert.False(t, err.Is(ErrZoneNil))
}

// TestDNSSECError_NoZone tests error formatting without zone
func TestDNSSECError_NoZone(t *testing.T) {
	err := &DNSSECError{
		Op:  "TestOp",
		Err: ErrLoggerNil,
	}

	errStr := err.Error()
	assert.Contains(t, errStr, "TestOp")
	assert.NotContains(t, errStr, "[")
}

// TestIsEnabled tests the IsEnabled method
func TestIsEnabled(t *testing.T) {
	t.Run("enabled", func(t *testing.T) {
		config := &DNSSECConfig{
			Enabled: true,
		}
		service := &DNSSECService{
			config:   config,
			logger:   createTestLogger(),
			keyStore: NewMockKeyStore(),
		}
		assert.True(t, service.IsEnabled())
	})

	t.Run("disabled", func(t *testing.T) {
		config := &DNSSECConfig{
			Enabled: false,
		}
		service := &DNSSECService{
			config:   config,
			logger:   createTestLogger(),
			keyStore: NewMockKeyStore(),
		}
		assert.False(t, service.IsEnabled())
	})
}

// TestSignZone_MultipleAlgorithms tests signing with different algorithms
func TestSignZone_MultipleAlgorithms(t *testing.T) {
	testCases := []struct {
		name      string
		keyConfig *common.KeyConfig
		expected  uint8
	}{
		{
			name: "ECDSA P-256",
			keyConfig: &common.KeyConfig{
				KeyAlgorithm: "ECDSA",
				ECCConfig:    &common.ECCConfig{Curve: "P-256"},
			},
			expected: dns.ECDSAP256SHA256,
		},
		{
			name: "ECDSA P-384",
			keyConfig: &common.KeyConfig{
				KeyAlgorithm: "ECDSA",
				ECCConfig:    &common.ECCConfig{Curve: "P-384"},
			},
			expected: dns.ECDSAP384SHA384,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logger := createTestLogger()
			config := &DNSSECConfig{
				Enabled:         true,
				DefaultKey:      tc.keyConfig,
				SignatureExpiry: "30d",
				NSECMode:        "nsec",
			}

			store := NewMockKeyStore()
			service := &DNSSECService{
				config:   config,
				logger:   logger,
				keyStore: store,
			}

			zone := createTestZone()
			err := service.SignZone(zone)
			require.NoError(t, err)

			// Verify keys use correct algorithm
			for _, dnskey := range zone.RecordSet.DNSKEYRecords {
				assert.Equal(t, tc.expected, dnskey.Algorithm)
			}
		})
	}
}

// TestKSKZSKKeyOverride tests that KSK/ZSK can override the default-key configuration
func TestKSKZSKKeyOverride(t *testing.T) {
	testCases := []struct {
		name           string
		defaultKey     *common.KeyConfig
		kskKey         *common.KeyConfig
		zskKey         *common.KeyConfig
		expectedAlgKSK uint8
		expectedAlgZSK uint8
	}{
		{
			name: "Default key only - P-256",
			defaultKey: &common.KeyConfig{
				KeyAlgorithm: "ECDSA",
				ECCConfig:    &common.ECCConfig{Curve: "P-256"},
			},
			kskKey:         nil,
			zskKey:         nil,
			expectedAlgKSK: dns.ECDSAP256SHA256,
			expectedAlgZSK: dns.ECDSAP256SHA256,
		},
		{
			name: "KSK override - P-384, ZSK inherits default P-256",
			defaultKey: &common.KeyConfig{
				KeyAlgorithm: "ECDSA",
				ECCConfig:    &common.ECCConfig{Curve: "P-256"},
			},
			kskKey: &common.KeyConfig{
				KeyAlgorithm: "ECDSA",
				ECCConfig:    &common.ECCConfig{Curve: "P-384"},
			},
			zskKey:         nil,
			expectedAlgKSK: dns.ECDSAP384SHA384,
			expectedAlgZSK: dns.ECDSAP256SHA256,
		},
		{
			name: "ZSK override - P-384, KSK inherits default P-256",
			defaultKey: &common.KeyConfig{
				KeyAlgorithm: "ECDSA",
				ECCConfig:    &common.ECCConfig{Curve: "P-256"},
			},
			kskKey: nil,
			zskKey: &common.KeyConfig{
				KeyAlgorithm: "ECDSA",
				ECCConfig:    &common.ECCConfig{Curve: "P-384"},
			},
			expectedAlgKSK: dns.ECDSAP256SHA256,
			expectedAlgZSK: dns.ECDSAP384SHA384,
		},
		{
			name: "Both override - KSK P-384, ZSK Ed25519",
			defaultKey: &common.KeyConfig{
				KeyAlgorithm: "ECDSA",
				ECCConfig:    &common.ECCConfig{Curve: "P-256"},
			},
			kskKey: &common.KeyConfig{
				KeyAlgorithm: "ECDSA",
				ECCConfig:    &common.ECCConfig{Curve: "P-384"},
			},
			zskKey: &common.KeyConfig{
				KeyAlgorithm: "Ed25519",
			},
			expectedAlgKSK: dns.ECDSAP384SHA384,
			expectedAlgZSK: dns.ED25519,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logger := createTestLogger()

			var kskConfig *DNSSECKeyConfig
			if tc.kskKey != nil {
				kskConfig = &DNSSECKeyConfig{
					Key:      tc.kskKey,
					Lifetime: "365d",
					TTL:      86400,
				}
			}

			var zskConfig *DNSSECKeyConfig
			if tc.zskKey != nil {
				zskConfig = &DNSSECKeyConfig{
					Key:      tc.zskKey,
					Lifetime: "30d",
					TTL:      3600,
				}
			}

			config := &DNSSECConfig{
				Enabled:         true,
				DefaultKey:      tc.defaultKey,
				SignatureExpiry: "30d",
				NSECMode:        "nsec",
				KSK:             kskConfig,
				ZSK:             zskConfig,
			}

			store := NewMockKeyStore()
			service := &DNSSECService{
				config:   config,
				logger:   logger,
				keyStore: store,
			}

			// Test getEffectiveKeyConfig for KSK
			kskEffective := service.getEffectiveKeyConfig(config.KSK)
			if tc.kskKey != nil {
				assert.Equal(t, tc.kskKey, kskEffective, "KSK should use override key")
			} else {
				assert.Equal(t, tc.defaultKey, kskEffective, "KSK should inherit default key")
			}

			// Test getEffectiveKeyConfig for ZSK
			zskEffective := service.getEffectiveKeyConfig(config.ZSK)
			if tc.zskKey != nil {
				assert.Equal(t, tc.zskKey, zskEffective, "ZSK should use override key")
			} else {
				assert.Equal(t, tc.defaultKey, zskEffective, "ZSK should inherit default key")
			}

			// Test algorithm derivation
			kskAlg := keyConfigToDNSSECAlgorithm(kskEffective)
			assert.Equal(t, tc.expectedAlgKSK, kskAlg, "KSK algorithm mismatch")

			zskAlg := keyConfigToDNSSECAlgorithm(zskEffective)
			assert.Equal(t, tc.expectedAlgZSK, zskAlg, "ZSK algorithm mismatch")
		})
	}
}

// TestKeyConfigToDNSSECAlgorithm tests the algorithm mapping function
func TestKeyConfigToDNSSECAlgorithm(t *testing.T) {
	testCases := []struct {
		name      string
		keyConfig *common.KeyConfig
		expected  uint8
	}{
		{
			name:      "nil config defaults to ECDSA P-256",
			keyConfig: nil,
			expected:  dns.ECDSAP256SHA256,
		},
		{
			name: "ECDSA P-256",
			keyConfig: &common.KeyConfig{
				KeyAlgorithm: "ECDSA",
				ECCConfig:    &common.ECCConfig{Curve: "P-256"},
			},
			expected: dns.ECDSAP256SHA256,
		},
		{
			name: "ECDSA P-384",
			keyConfig: &common.KeyConfig{
				KeyAlgorithm: "ECDSA",
				ECCConfig:    &common.ECCConfig{Curve: "P-384"},
			},
			expected: dns.ECDSAP384SHA384,
		},
		{
			name: "ECDSA P384 (no hyphen)",
			keyConfig: &common.KeyConfig{
				KeyAlgorithm: "ECDSA",
				ECCConfig:    &common.ECCConfig{Curve: "P384"},
			},
			expected: dns.ECDSAP384SHA384,
		},
		{
			name: "Ed25519",
			keyConfig: &common.KeyConfig{
				KeyAlgorithm: "Ed25519",
			},
			expected: dns.ED25519,
		},
		{
			name: "RSA with SHA256",
			keyConfig: &common.KeyConfig{
				KeyAlgorithm:       "RSA",
				SignatureAlgorithm: "SHA256-RSA",
			},
			expected: dns.RSASHA256,
		},
		{
			name: "RSA with SHA512",
			keyConfig: &common.KeyConfig{
				KeyAlgorithm:       "RSA",
				SignatureAlgorithm: "SHA512-RSA",
			},
			expected: dns.RSASHA512,
		},
		{
			name: "RSA without signature algorithm defaults to SHA256",
			keyConfig: &common.KeyConfig{
				KeyAlgorithm: "RSA",
			},
			expected: dns.RSASHA256,
		},
		{
			name: "Unknown algorithm defaults to ECDSA P-256",
			keyConfig: &common.KeyConfig{
				KeyAlgorithm: "UNKNOWN",
			},
			expected: dns.ECDSAP256SHA256,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := keyConfigToDNSSECAlgorithm(tc.keyConfig)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// TestSignZone_ResignsWithExistingKeys tests that signing uses existing keys
func TestSignZone_ResignsWithExistingKeys(t *testing.T) {
	service, _ := createTestDNSSECServiceWithMock(t)

	zone := createTestZone()

	// Sign first time
	err := service.SignZone(zone)
	require.NoError(t, err)

	firstKSKKeyTag := zone.RecordSet.DNSKEYRecords[0].ID

	// Modify zone and resign
	zone.RecordSet.ARecords = append(zone.RecordSet.ARecords, &entities.ARecord{
		Name:  "new",
		Value: "192.0.2.100",
		TTL:   3600,
	})

	err = service.SignZone(zone)
	require.NoError(t, err)

	// Should have same key tags (keys were reused)
	assert.Equal(t, firstKSKKeyTag, zone.RecordSet.DNSKEYRecords[0].ID, "Should reuse existing keys")
}

// TestSignZone_DefaultAlgorithm tests that default algorithm is used when not specified
func TestSignZone_DefaultAlgorithm(t *testing.T) {
	logger := createTestLogger()
	config := &DNSSECConfig{
		Enabled: true,
		// No DefaultKey specified, should default to ECDSAP256SHA256
		SignatureExpiry: "30d",
		NSECMode:        "nsec",
	}

	store := NewMockKeyStore()
	service := &DNSSECService{
		config:   config,
		logger:   logger,
		keyStore: store,
	}

	zone := createTestZone()
	err := service.SignZone(zone)
	require.NoError(t, err)

	// Should use default algorithm
	for _, dnskey := range zone.RecordSet.DNSKEYRecords {
		assert.Equal(t, dns.ECDSAP256SHA256, dnskey.Algorithm, "Should use default algorithm")
	}
}

// TestSignZone_DefaultExpiry tests that default expiry is used when not specified
func TestSignZone_DefaultExpiry(t *testing.T) {
	logger := createTestLogger()
	config := &DNSSECConfig{
		Enabled: true,
		DefaultKey: &common.KeyConfig{
			KeyAlgorithm: "ECDSA",
			ECCConfig:    &common.ECCConfig{Curve: "P-256"},
		},
		SignatureExpiry: "", // Not specified, should default to 30 days
		NSECMode:        "nsec",
	}

	store := NewMockKeyStore()
	service := &DNSSECService{
		config:   config,
		logger:   logger,
		keyStore: store,
	}

	zone := createTestZone()
	err := service.SignZone(zone)
	require.NoError(t, err)

	// Verify zone was signed (has RRSIG records)
	assert.Greater(t, len(zone.RecordSet.RRSIGRecords), 0, "Zone should be signed")
}

// TestGenerateNSECChain_EmptyZone tests NSEC chain for zone with minimal records
func TestGenerateNSECChain_EmptyZone(t *testing.T) {
	service, _ := createTestDNSSECServiceWithMock(t)

	zone := &entities.Zone{
		ID:   1,
		Name: "minimal.com.",
		TTL:  3600,
		RecordSet: entities.RecordSet{
			SOARecord: entities.SOARecord{
				Name:       "minimal.com.",
				MName:      "ns1.minimal.com.",
				RName:      "hostmaster.minimal.com.",
				Serial:     1,
				Refresh:    86400,
				Retry:      7200,
				Expire:     3600000,
				MinimumTTL: 3600,
				TTL:        3600,
			},
		},
	}

	nsecRecords := service.GenerateNSECChain(zone)
	require.NotNil(t, nsecRecords)
	assert.GreaterOrEqual(t, len(nsecRecords), 1, "Should have at least one NSEC record")
}

// TestSignZone_WithAllRecordTypes tests signing a zone with all record types
func TestSignZone_WithAllRecordTypes(t *testing.T) {
	service, _ := createTestDNSSECServiceWithMock(t)

	zone := &entities.Zone{
		ID:       1,
		Name:     "complete.com.",
		TenantID: "test-tenant",
		TTL:      3600,
		RecordSet: entities.RecordSet{
			SOARecord: entities.SOARecord{
				Name:       "complete.com.",
				MName:      "ns1.complete.com.",
				RName:      "hostmaster.complete.com.",
				Serial:     1,
				Refresh:    86400,
				Retry:      7200,
				Expire:     3600000,
				MinimumTTL: 3600,
				TTL:        3600,
			},
			NSRecords: []*entities.NSRecord{
				{Name: "complete.com.", Value: "ns1.complete.com.", TTL: 3600},
			},
			ARecords: []*entities.ARecord{
				{Name: "@", Value: "192.0.2.1", TTL: 3600},
			},
			AAAARecords: []*entities.AAAARecord{
				{Name: "ipv6", Value: "2001:db8::1", TTL: 3600},
			},
			CNAMERecords: []*entities.CNAMERecord{
				{Name: "alias", Value: "complete.com.", TTL: 3600},
			},
			MXRecords: []*entities.MXRecord{
				{Name: "complete.com.", Value: "mail.complete.com.", Priority: 10, TTL: 3600},
			},
			TXTRecords: []*entities.TXTRecord{
				{Name: "complete.com.", Value: "v=spf1 -all", TTL: 3600},
			},
			SRVRecords: []*entities.SRVRecord{
				{Name: "_http._tcp.complete.com.", Target: "www.complete.com.", Port: 80, Priority: 10, Weight: 100, TTL: 3600},
			},
			CAARecords: []*entities.CAARecord{
				{Name: "complete.com.", Flags: 0, Tag: "issue", Value: "letsencrypt.org", TTL: 3600},
			},
			TLSARecords: []*entities.TLSARecord{
				{Name: "_443._tcp.complete.com.", Usage: 3, Selector: 1, MatchingType: 1, Data: "abcdef1234567890", TTL: 3600},
			},
		},
	}

	err := service.SignZone(zone)
	require.NoError(t, err)

	// Verify all record types resulted in signatures
	assert.Greater(t, len(zone.RecordSet.RRSIGRecords), 5, "Should have multiple RRSIG records")
	assert.GreaterOrEqual(t, len(zone.RecordSet.DNSKEYRecords), 2, "Should have DNSKEY records")
}

// TestDNSSECError_Is tests the Is method
func TestDNSSECError_Is_Nil(t *testing.T) {
	err := &DNSSECError{
		Op:  "test",
		Err: ErrKeyNotFound,
	}

	assert.False(t, err.Is(nil))
}

// TestSignZone_ZoneWithSubdomains tests signing a zone with subdomain records
func TestSignZone_ZoneWithSubdomains(t *testing.T) {
	service, _ := createTestDNSSECServiceWithMock(t)

	zone := &entities.Zone{
		ID:       1,
		Name:     "example.com.",
		TenantID: "test-tenant",
		TTL:      3600,
		RecordSet: entities.RecordSet{
			SOARecord: entities.SOARecord{
				Name:       "example.com.",
				MName:      "ns1.example.com.",
				RName:      "hostmaster.example.com.",
				Serial:     1,
				Refresh:    86400,
				Retry:      7200,
				Expire:     3600000,
				MinimumTTL: 3600,
				TTL:        3600,
			},
			ARecords: []*entities.ARecord{
				{Name: "@", Value: "192.0.2.1", TTL: 3600},
				{Name: "www", Value: "192.0.2.2", TTL: 3600},
				{Name: "mail", Value: "192.0.2.3", TTL: 3600},
				{Name: "api", Value: "192.0.2.4", TTL: 3600},
				{Name: "dev.api", Value: "192.0.2.5", TTL: 3600}, // nested subdomain
			},
		},
	}

	err := service.SignZone(zone)
	require.NoError(t, err)

	// Verify NSEC chain was generated
	assert.Greater(t, len(zone.RecordSet.NSECRecords), 0, "Should have NSEC records")

	// Verify zone apex has SOA and DNSKEY in type bitmap
	apexFound := false
	for _, nsec := range zone.RecordSet.NSECRecords {
		if nsec.Name == "example.com." {
			apexFound = true
			break
		}
	}
	assert.True(t, apexFound, "Should have NSEC for zone apex")
}

// TestKeysExist tests the KeysExist method
func TestKeysExist(t *testing.T) {
	service, _ := createTestDNSSECServiceWithMock(t)

	// No keys yet
	assert.False(t, service.KeysExist("test-tenant", "example.com."))

	// Generate keys
	_, _, err := service.GenerateKeys("test-tenant", "example.com.")
	require.NoError(t, err)

	// Keys should exist now
	assert.True(t, service.KeysExist("test-tenant", "example.com."))
}

// TestSignZone_MissingTenantID tests that SignZone returns error for missing tenant
func TestSignZone_MissingTenantID(t *testing.T) {
	service, _ := createTestDNSSECServiceWithMock(t)

	zone := &entities.Zone{
		ID:   1,
		Name: "example.com.",
		// TenantID intentionally missing
		TTL: 3600,
		RecordSet: entities.RecordSet{
			SOARecord: entities.SOARecord{
				Name:       "example.com.",
				MName:      "ns1.example.com.",
				RName:      "hostmaster.example.com.",
				Serial:     1,
				Refresh:    86400,
				Retry:      7200,
				Expire:     3600000,
				MinimumTTL: 3600,
				TTL:        3600,
			},
		},
	}

	err := service.SignZone(zone)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMissingTenantContext)
}

// TestSignZone_EmptyTenantID tests that SignZone returns error for empty tenant
func TestSignZone_EmptyTenantID(t *testing.T) {
	service, _ := createTestDNSSECServiceWithMock(t)

	zone := &entities.Zone{
		ID:       1,
		Name:     "example.com.",
		TenantID: "", // Empty string
		TTL:      3600,
		RecordSet: entities.RecordSet{
			SOARecord: entities.SOARecord{
				Name:       "example.com.",
				MName:      "ns1.example.com.",
				RName:      "hostmaster.example.com.",
				Serial:     1,
				Refresh:    86400,
				Retry:      7200,
				Expire:     3600000,
				MinimumTTL: 3600,
				TTL:        3600,
			},
		},
	}

	err := service.SignZone(zone)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMissingTenantContext)
}

// TestGenerateKeys_WithTenantID tests key generation with tenant isolation
func TestGenerateKeys_WithTenantID(t *testing.T) {
	service, _ := createTestDNSSECServiceWithMock(t)

	// Generate keys for tenant-a
	kskA, zskA, err := service.GenerateKeys("tenant-a", "example.com.")
	require.NoError(t, err)
	require.NotNil(t, kskA)
	require.NotNil(t, zskA)

	// Verify keys exist for tenant-a
	assert.True(t, service.KeysExist("tenant-a", "example.com."))

	// Verify keys don't exist for tenant-b (isolation)
	assert.False(t, service.KeysExist("tenant-b", "example.com."))

	// Generate keys for tenant-b
	kskB, zskB, err := service.GenerateKeys("tenant-b", "example.com.")
	require.NoError(t, err)
	require.NotNil(t, kskB)
	require.NotNil(t, zskB)

	// Verify both tenants now have keys
	assert.True(t, service.KeysExist("tenant-a", "example.com."))
	assert.True(t, service.KeysExist("tenant-b", "example.com."))

	// Keys should be different between tenants
	assert.NotEqual(t, kskA.KeyTag(), kskB.KeyTag(), "KSK should be different for different tenants")
}

// TestLoadKeys_WithTenantID tests key loading with tenant isolation
func TestLoadKeys_WithTenantID(t *testing.T) {
	service, _ := createTestDNSSECServiceWithMock(t)

	// Generate keys for tenant-a
	ksk, zsk, err := service.GenerateKeys("tenant-a", "example.com.")
	require.NoError(t, err)

	// Load keys for tenant-a
	loadedKSK, loadedZSK, err := service.LoadKeys("tenant-a", "example.com.")
	require.NoError(t, err)
	require.NotNil(t, loadedKSK)
	require.NotNil(t, loadedZSK)

	// Verify loaded keys match generated keys
	assert.Equal(t, ksk.KeyTag(), loadedKSK.DNSKEY.KeyTag())
	assert.Equal(t, zsk.KeyTag(), loadedZSK.DNSKEY.KeyTag())

	// Loading keys for tenant-b should fail (they don't exist)
	_, _, err = service.LoadKeys("tenant-b", "example.com.")
	require.Error(t, err)
}

// TestPrepareKeyRollover_WithTenantID tests key rollover with tenant isolation
func TestPrepareKeyRollover_WithTenantID(t *testing.T) {
	service, _ := createTestDNSSECServiceWithMock(t)

	// Generate initial keys for tenant-a
	originalKSK, _, err := service.GenerateKeys("tenant-a", "example.com.")
	require.NoError(t, err)

	// Prepare key rollover for tenant-a
	newKSK, err := service.PrepareKeyRollover("tenant-a", "example.com.", "ksk")
	require.NoError(t, err)
	require.NotNil(t, newKSK)

	// New key should be different from original
	assert.NotEqual(t, originalKSK.KeyTag(), newKSK.KeyTag())

	// Prepare ZSK rollover
	newZSK, err := service.PrepareKeyRollover("tenant-a", "example.com.", "zsk")
	require.NoError(t, err)
	require.NotNil(t, newZSK)
}

// TestPrepareKeyRollover_InvalidKeyType_TenantScoped tests error handling for invalid key type with tenant
func TestPrepareKeyRollover_InvalidKeyType_TenantScoped(t *testing.T) {
	service, _ := createTestDNSSECServiceWithMock(t)

	// Generate initial keys
	_, _, err := service.GenerateKeys("tenant-a", "example.com.")
	require.NoError(t, err)

	// Invalid key type should return error
	_, err = service.PrepareKeyRollover("tenant-a", "example.com.", "invalid")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidKeyType)
}

// TestSignZone_TenantIsolation tests that zones are signed with tenant-specific keys
func TestSignZone_TenantIsolation(t *testing.T) {
	service, _ := createTestDNSSECServiceWithMock(t)

	// Create zones for two different tenants
	zoneA := &entities.Zone{
		ID:       1,
		Name:     "example.com.",
		TenantID: "tenant-a",
		TTL:      3600,
		RecordSet: entities.RecordSet{
			SOARecord: entities.SOARecord{
				Name:       "example.com.",
				MName:      "ns1.example.com.",
				RName:      "hostmaster.example.com.",
				Serial:     1,
				Refresh:    86400,
				Retry:      7200,
				Expire:     3600000,
				MinimumTTL: 3600,
				TTL:        3600,
			},
			NSRecords: []*entities.NSRecord{
				{Name: "example.com.", Value: "ns1.example.com.", TTL: 3600},
			},
			ARecords: []*entities.ARecord{
				{Name: "@", Value: "192.0.2.1", TTL: 3600},
			},
		},
	}

	zoneB := &entities.Zone{
		ID:       2,
		Name:     "example.com.",
		TenantID: "tenant-b",
		TTL:      3600,
		RecordSet: entities.RecordSet{
			SOARecord: entities.SOARecord{
				Name:       "example.com.",
				MName:      "ns1.example.com.",
				RName:      "hostmaster.example.com.",
				Serial:     1,
				Refresh:    86400,
				Retry:      7200,
				Expire:     3600000,
				MinimumTTL: 3600,
				TTL:        3600,
			},
			NSRecords: []*entities.NSRecord{
				{Name: "example.com.", Value: "ns1.example.com.", TTL: 3600},
			},
			ARecords: []*entities.ARecord{
				{Name: "@", Value: "192.0.2.2", TTL: 3600},
			},
		},
	}

	// Sign zone A
	err := service.SignZone(zoneA)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(zoneA.RecordSet.DNSKEYRecords), 2)

	// Sign zone B
	err = service.SignZone(zoneB)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(zoneB.RecordSet.DNSKEYRecords), 2)

	// Each tenant should have their own keys
	assert.True(t, service.KeysExist("tenant-a", "example.com."))
	assert.True(t, service.KeysExist("tenant-b", "example.com."))

	// Get the public keys from DNSKEY records
	var kskKeyA, kskKeyB string
	for _, key := range zoneA.RecordSet.DNSKEYRecords {
		if key.Flags == 257 { // KSK
			kskKeyA = key.Key
			break
		}
	}
	for _, key := range zoneB.RecordSet.DNSKEYRecords {
		if key.Flags == 257 { // KSK
			kskKeyB = key.Key
			break
		}
	}

	// KSKs should be different for different tenants
	assert.NotEqual(t, kskKeyA, kskKeyB, "Tenants should have different KSKs")
}

// TestKeysExist_DifferentTenantsAndZones tests KeysExist with multiple tenants and zones
func TestKeysExist_DifferentTenantsAndZones(t *testing.T) {
	service, _ := createTestDNSSECServiceWithMock(t)

	// Generate keys for different tenant/zone combinations
	_, _, err := service.GenerateKeys("tenant-a", "zone1.com.")
	require.NoError(t, err)

	_, _, err = service.GenerateKeys("tenant-a", "zone2.com.")
	require.NoError(t, err)

	_, _, err = service.GenerateKeys("tenant-b", "zone1.com.")
	require.NoError(t, err)

	// Verify correct tenant/zone combinations exist
	assert.True(t, service.KeysExist("tenant-a", "zone1.com."))
	assert.True(t, service.KeysExist("tenant-a", "zone2.com."))
	assert.True(t, service.KeysExist("tenant-b", "zone1.com."))

	// Verify non-existent combinations return false
	assert.False(t, service.KeysExist("tenant-b", "zone2.com."))
	assert.False(t, service.KeysExist("tenant-c", "zone1.com."))
}
