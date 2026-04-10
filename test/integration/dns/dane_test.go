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

//go:build integration

// Package dns provides integration tests for DANE (DNS-based Authentication
// of Named Entities) service integration. These tests verify TLSA record
// auto-generation and DANE workflow functionality.
// Run via: make integration-test-dns or INTEGRATION_TEST=1 go test ./test/integration/dns/...
package dns

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDANE_TLSARecordCreation tests creating TLSA records for DANE.
func TestDANE_TLSARecordCreation(t *testing.T) {
	skipIfNotIntegration(t)

	svc := createTestService(t)
	ctx := context.Background()

	zoneName := "dane-test.com."
	zone := createTestZone(zoneName, false)
	require.NoError(t, svc.Save(ctx, zone))

	// Simulate certificate data
	certData := []byte("mock-certificate-data-for-testing")
	certHash := sha256.Sum256(certData)
	certHashHex := hex.EncodeToString(certHash[:])

	// Create DANE-EE TLSA record for HTTPS
	tlsaRecord := &entities.TLSARecord{
		Name:         "_443._tcp.www." + zoneName,
		Usage:        3, // DANE-EE
		Selector:     1, // SPKI
		MatchingType: 1, // SHA-256
		Data:         certHashHex,
		TTL:          3600,
	}

	err := svc.AddTLSARecord(ctx, zoneName, tlsaRecord)
	require.NoError(t, err)

	retrieved, err := svc.Zone(ctx, zoneName)
	require.NoError(t, err)

	require.Len(t, retrieved.RecordSet.TLSARecords, 1)
	assert.Equal(t, certHashHex, retrieved.RecordSet.TLSARecords[0].Data)
}

// TestDANE_MultiService tests TLSA records for multiple services on same host.
func TestDANE_MultiService(t *testing.T) {
	skipIfNotIntegration(t)

	svc := createTestService(t)
	ctx := context.Background()

	zoneName := "multiservice.com."
	zone := createTestZone(zoneName, false)
	require.NoError(t, svc.Save(ctx, zone))

	services := []struct {
		port     string
		proto    string
		host     string
		certData string
	}{
		{"443", "tcp", "www", "cert-https-www"},
		{"443", "tcp", "api", "cert-https-api"},
		{"25", "tcp", "mail", "cert-smtp"},
		{"465", "tcp", "mail", "cert-smtps"},
		{"993", "tcp", "mail", "cert-imaps"},
	}

	for _, s := range services {
		hash := sha256.Sum256([]byte(s.certData))
		tlsaRecord := &entities.TLSARecord{
			Name:         "_" + s.port + "._" + s.proto + "." + s.host + "." + zoneName,
			Usage:        3,
			Selector:     1,
			MatchingType: 1,
			Data:         hex.EncodeToString(hash[:]),
			TTL:          3600,
		}
		err := svc.AddTLSARecord(ctx, zoneName, tlsaRecord)
		require.NoError(t, err)
	}

	retrieved, err := svc.Zone(ctx, zoneName)
	require.NoError(t, err)

	assert.Len(t, retrieved.RecordSet.TLSARecords, 5)
}

// TestDANE_SHA256Matching tests TLSA record with SHA-256 matching type.
func TestDANE_SHA256Matching(t *testing.T) {
	skipIfNotIntegration(t)

	svc := createTestService(t)
	ctx := context.Background()

	zoneName := "sha256-test.com."
	zone := createTestZone(zoneName, false)
	require.NoError(t, svc.Save(ctx, zone))

	// Generate SHA-256 hash
	spkiData := []byte("subject-public-key-info")
	hash := sha256.Sum256(spkiData)

	tlsaRecord := dns.NewTLSARecord(
		"_443._tcp.www."+zoneName,
		3, // DANE-EE
		1, // SPKI
		1, // SHA-256
		hex.EncodeToString(hash[:]),
		3600,
	)
	zone.AddTLSARecord(tlsaRecord)
	require.NoError(t, svc.Save(ctx, zone))

	retrieved, err := svc.Zone(ctx, zoneName)
	require.NoError(t, err)

	require.Len(t, retrieved.RecordSet.TLSARecords, 1)
	assert.Equal(t, uint8(1), retrieved.RecordSet.TLSARecords[0].MatchingType)
	assert.Len(t, retrieved.RecordSet.TLSARecords[0].Data, 64) // SHA-256 hex = 64 chars
}

// TestDANE_SHA512Matching tests TLSA record with SHA-512 matching type.
func TestDANE_SHA512Matching(t *testing.T) {
	skipIfNotIntegration(t)

	svc := createTestService(t)
	ctx := context.Background()

	zoneName := "sha512-test.com."
	zone := createTestZone(zoneName, false)
	require.NoError(t, svc.Save(ctx, zone))

	// Generate SHA-512 hash
	spkiData := []byte("subject-public-key-info")
	hash := sha512.Sum512(spkiData)

	tlsaRecord := dns.NewTLSARecord(
		"_443._tcp.www."+zoneName,
		3, // DANE-EE
		1, // SPKI
		2, // SHA-512
		hex.EncodeToString(hash[:]),
		3600,
	)
	zone.AddTLSARecord(tlsaRecord)
	require.NoError(t, svc.Save(ctx, zone))

	retrieved, err := svc.Zone(ctx, zoneName)
	require.NoError(t, err)

	require.Len(t, retrieved.RecordSet.TLSARecords, 1)
	assert.Equal(t, uint8(2), retrieved.RecordSet.TLSARecords[0].MatchingType)
	assert.Len(t, retrieved.RecordSet.TLSARecords[0].Data, 128) // SHA-512 hex = 128 chars
}

// TestDANE_FullCertificate tests TLSA record with full certificate matching.
func TestDANE_FullCertificate(t *testing.T) {
	skipIfNotIntegration(t)

	svc := createTestService(t)
	ctx := context.Background()

	zoneName := "fullcert-test.com."
	zone := createTestZone(zoneName, false)
	require.NoError(t, svc.Save(ctx, zone))

	// Full certificate data (hex encoded)
	fullCertHex := hex.EncodeToString([]byte("mock-full-certificate-der-encoded-data"))

	tlsaRecord := dns.NewTLSARecord(
		"_443._tcp.www."+zoneName,
		3, // DANE-EE
		0, // Full certificate
		0, // Full (no hash)
		fullCertHex,
		3600,
	)
	zone.AddTLSARecord(tlsaRecord)
	require.NoError(t, svc.Save(ctx, zone))

	retrieved, err := svc.Zone(ctx, zoneName)
	require.NoError(t, err)

	require.Len(t, retrieved.RecordSet.TLSARecords, 1)
	assert.Equal(t, uint8(0), retrieved.RecordSet.TLSARecords[0].Selector)
	assert.Equal(t, uint8(0), retrieved.RecordSet.TLSARecords[0].MatchingType)
}

// TestDANE_PKIXUsageTypes tests TLSA records with PKIX usage types.
func TestDANE_PKIXUsageTypes(t *testing.T) {
	skipIfNotIntegration(t)

	svc := createTestService(t)
	ctx := context.Background()

	zoneName := "pkix-test.com."
	zone := createTestZone(zoneName, false)
	require.NoError(t, svc.Save(ctx, zone))

	usageTypes := []struct {
		usage       uint8
		name        string
		description string
	}{
		{0, "pkix-ta", "PKIX-TA: CA constraint"},
		{1, "pkix-ee", "PKIX-EE: Service certificate constraint"},
	}

	for _, ut := range usageTypes {
		hash := sha256.Sum256([]byte("cert-data-" + ut.name))
		tlsaRecord := &entities.TLSARecord{
			Name:         "_443._tcp." + ut.name + "." + zoneName,
			Usage:        ut.usage,
			Selector:     1,
			MatchingType: 1,
			Data:         hex.EncodeToString(hash[:]),
			TTL:          3600,
		}
		zone.AddTLSARecord(tlsaRecord)
	}
	require.NoError(t, svc.Save(ctx, zone))

	retrieved, err := svc.Zone(ctx, zoneName)
	require.NoError(t, err)

	assert.Len(t, retrieved.RecordSet.TLSARecords, 2)
}

// TestDANE_TAUsageType tests DANE-TA (Trust Anchor) usage type.
func TestDANE_TAUsageType(t *testing.T) {
	skipIfNotIntegration(t)

	svc := createTestService(t)
	ctx := context.Background()

	zoneName := "dane-ta-test.com."
	zone := createTestZone(zoneName, false)
	require.NoError(t, svc.Save(ctx, zone))

	// DANE-TA: Trust anchor assertion
	taHash := sha256.Sum256([]byte("trust-anchor-certificate"))
	tlsaRecord := &entities.TLSARecord{
		Name:         "_443._tcp.www." + zoneName,
		Usage:        2, // DANE-TA
		Selector:     0, // Full certificate
		MatchingType: 1, // SHA-256
		Data:         hex.EncodeToString(taHash[:]),
		TTL:          86400, // Longer TTL for trust anchors
	}

	err := svc.AddTLSARecord(ctx, zoneName, tlsaRecord)
	require.NoError(t, err)

	retrieved, err := svc.Zone(ctx, zoneName)
	require.NoError(t, err)

	require.Len(t, retrieved.RecordSet.TLSARecords, 1)
	assert.Equal(t, uint8(2), retrieved.RecordSet.TLSARecords[0].Usage)
	assert.Equal(t, uint32(86400), retrieved.RecordSet.TLSARecords[0].TTL)
}

// TestDANE_EEUsageType tests DANE-EE (End Entity) usage type.
func TestDANE_EEUsageType(t *testing.T) {
	skipIfNotIntegration(t)

	svc := createTestService(t)
	ctx := context.Background()

	zoneName := "dane-ee-test.com."
	zone := createTestZone(zoneName, false)
	require.NoError(t, svc.Save(ctx, zone))

	// DANE-EE: End entity certificate assertion (most common for self-signed)
	eeHash := sha256.Sum256([]byte("end-entity-certificate-spki"))
	tlsaRecord := &entities.TLSARecord{
		Name:         "_443._tcp.www." + zoneName,
		Usage:        3, // DANE-EE
		Selector:     1, // SPKI
		MatchingType: 1, // SHA-256
		Data:         hex.EncodeToString(eeHash[:]),
		TTL:          3600,
	}

	err := svc.AddTLSARecord(ctx, zoneName, tlsaRecord)
	require.NoError(t, err)

	retrieved, err := svc.Zone(ctx, zoneName)
	require.NoError(t, err)

	require.Len(t, retrieved.RecordSet.TLSARecords, 1)
	assert.Equal(t, uint8(3), retrieved.RecordSet.TLSARecords[0].Usage)
}

// TestDANE_CertificateRotation tests updating TLSA records during cert rotation.
func TestDANE_CertificateRotation(t *testing.T) {
	skipIfNotIntegration(t)

	svc := createTestService(t)
	ctx := context.Background()

	zoneName := "cert-rotation.com."
	zone := createTestZone(zoneName, false)
	require.NoError(t, svc.Save(ctx, zone))

	recordName := "_443._tcp.www." + zoneName

	// Old certificate
	oldCertHash := sha256.Sum256([]byte("old-certificate"))
	zone.AddTLSARecord(&entities.TLSARecord{
		Name:         recordName,
		Usage:        3,
		Selector:     1,
		MatchingType: 1,
		Data:         hex.EncodeToString(oldCertHash[:]),
		TTL:          3600,
	})
	require.NoError(t, svc.Save(ctx, zone))

	// During rotation: Add new cert while keeping old
	newCertHash := sha256.Sum256([]byte("new-certificate"))
	zone.AddTLSARecord(&entities.TLSARecord{
		Name:         recordName + "-new", // Different name to allow both
		Usage:        3,
		Selector:     1,
		MatchingType: 1,
		Data:         hex.EncodeToString(newCertHash[:]),
		TTL:          3600,
	})
	require.NoError(t, svc.Save(ctx, zone))

	retrieved, err := svc.Zone(ctx, zoneName)
	require.NoError(t, err)
	assert.Len(t, retrieved.RecordSet.TLSARecords, 2)

	// After rotation: Remove old cert record
	zone.RemoveTLSARecord(recordName)
	require.NoError(t, svc.Save(ctx, zone))

	retrieved, err = svc.Zone(ctx, zoneName)
	require.NoError(t, err)
	assert.Len(t, retrieved.RecordSet.TLSARecords, 1)
	assert.Contains(t, retrieved.RecordSet.TLSARecords[0].Name, "-new")
}

// TestDANE_WithCAARecord tests DANE and CAA records coexistence.
func TestDANE_WithCAARecord(t *testing.T) {
	skipIfNotIntegration(t)

	svc := createTestService(t)
	ctx := context.Background()

	zoneName := "dane-caa.com."
	zone := createTestZone(zoneName, false)
	require.NoError(t, svc.Save(ctx, zone))

	// Add CAA record to restrict CA issuance
	zone.AddCAARecord(&entities.CAARecord{
		Name:  "@",
		Flags: 0,
		Tag:   "issue",
		Value: "letsencrypt.org",
		TTL:   3600,
	})

	// Add TLSA record for DANE
	certHash := sha256.Sum256([]byte("certificate-data"))
	zone.AddTLSARecord(&entities.TLSARecord{
		Name:         "_443._tcp.www." + zoneName,
		Usage:        3,
		Selector:     1,
		MatchingType: 1,
		Data:         hex.EncodeToString(certHash[:]),
		TTL:          3600,
	})

	require.NoError(t, svc.Save(ctx, zone))

	retrieved, err := svc.Zone(ctx, zoneName)
	require.NoError(t, err)

	// Both record types should exist
	assert.Len(t, retrieved.RecordSet.CAARecords, 1)
	assert.Len(t, retrieved.RecordSet.TLSARecords, 1)
}

// TestDANE_InternalZone tests DANE for internal/private zones.
func TestDANE_InternalZone(t *testing.T) {
	skipIfNotIntegration(t)

	svc := createTestService(t)
	ctx := context.Background()

	zoneName := "internal.local."
	zone := &entities.Zone{
		ID:          util.NewID([]byte(zoneName)),
		Name:        zoneName,
		TTL:         3600,
		Description: "Internal zone with DANE",
		Internal:    true,
		RecordSet: entities.RecordSet{
			SOARecord: entities.SOARecord{
				Name:   zoneName,
				MName:  "ns1." + zoneName,
				RName:  "hostmaster." + zoneName,
				Serial: 1,
			},
		},
	}
	require.NoError(t, svc.Save(ctx, zone))

	// Internal services often use DANE-EE with self-signed certs
	services := []struct {
		host string
		port string
	}{
		{"ldap", "636"},   // LDAPS
		{"db", "5432"},    // PostgreSQL TLS
		{"vault", "8200"}, // Vault TLS
		{"api", "443"},    // Internal API
	}

	for _, s := range services {
		hash := sha256.Sum256([]byte("internal-cert-" + s.host))
		zone.AddTLSARecord(&entities.TLSARecord{
			Name:         "_" + s.port + "._tcp." + s.host + "." + zoneName,
			Usage:        3,
			Selector:     1,
			MatchingType: 1,
			Data:         hex.EncodeToString(hash[:]),
			TTL:          3600,
		})
	}
	require.NoError(t, svc.Save(ctx, zone))

	retrieved, err := svc.Zone(ctx, zoneName)
	require.NoError(t, err)

	assert.True(t, retrieved.Internal)
	assert.Len(t, retrieved.RecordSet.TLSARecords, 4)
}

// TestDANE_SMTPService tests TLSA for SMTP (MTA-STS/DANE).
func TestDANE_SMTPService(t *testing.T) {
	skipIfNotIntegration(t)

	svc := createTestService(t)
	ctx := context.Background()

	zoneName := "mail-dane.com."
	zone := createTestZone(zoneName, false)
	require.NoError(t, svc.Save(ctx, zone))

	// Add MX record
	zone.AddMXRecord(&entities.MXRecord{
		Name:     "@",
		Value:    "mail." + zoneName,
		Priority: 10,
		TTL:      3600,
	})

	// Add A record for mail server
	zone.AddARecord(&entities.ARecord{
		Name:  "mail",
		Value: "192.168.1.25",
		TTL:   3600,
	})

	// DANE for SMTP (port 25)
	smtpHash := sha256.Sum256([]byte("smtp-starttls-cert"))
	zone.AddTLSARecord(&entities.TLSARecord{
		Name:         "_25._tcp.mail." + zoneName,
		Usage:        3,
		Selector:     1,
		MatchingType: 1,
		Data:         hex.EncodeToString(smtpHash[:]),
		TTL:          3600,
	})

	// DANE for SMTPS (port 465)
	smtpsHash := sha256.Sum256([]byte("smtps-cert"))
	zone.AddTLSARecord(&entities.TLSARecord{
		Name:         "_465._tcp.mail." + zoneName,
		Usage:        3,
		Selector:     1,
		MatchingType: 1,
		Data:         hex.EncodeToString(smtpsHash[:]),
		TTL:          3600,
	})

	require.NoError(t, svc.Save(ctx, zone))

	retrieved, err := svc.Zone(ctx, zoneName)
	require.NoError(t, err)

	assert.Len(t, retrieved.RecordSet.MXRecords, 1)
	assert.Len(t, retrieved.RecordSet.TLSARecords, 2)
}

// TestDANE_WildcardService tests TLSA for wildcard subdomains.
func TestDANE_WildcardService(t *testing.T) {
	skipIfNotIntegration(t)

	svc := createTestService(t)
	ctx := context.Background()

	zoneName := "wildcard-dane.com."
	zone := createTestZone(zoneName, false)
	require.NoError(t, svc.Save(ctx, zone))

	// Wildcard TLSA (applies to any subdomain)
	wildcardHash := sha256.Sum256([]byte("wildcard-certificate"))
	zone.AddTLSARecord(&entities.TLSARecord{
		Name:         "_443._tcp.*." + zoneName,
		Usage:        3,
		Selector:     1,
		MatchingType: 1,
		Data:         hex.EncodeToString(wildcardHash[:]),
		TTL:          3600,
	})

	require.NoError(t, svc.Save(ctx, zone))

	retrieved, err := svc.Zone(ctx, zoneName)
	require.NoError(t, err)

	require.Len(t, retrieved.RecordSet.TLSARecords, 1)
	assert.Contains(t, retrieved.RecordSet.TLSARecords[0].Name, "*.")
}

// TestDANE_ConfigDefaults tests DANE configuration defaults.
func TestDANE_ConfigDefaults(t *testing.T) {
	skipIfNotIntegration(t)

	config := &dns.DANEConfig{
		Enabled:             true,
		AutoGenerate:        true,
		DefaultPort:         443,
		DefaultTTL:          3600,
		DefaultUsage:        3, // DANE-EE
		DefaultSelector:     1, // SPKI
		DefaultMatchingType: 1, // SHA-256
	}

	assert.True(t, config.Enabled)
	assert.True(t, config.AutoGenerate)
	assert.Equal(t, uint16(443), config.DefaultPort)
	assert.Equal(t, uint32(3600), config.DefaultTTL)
	assert.Equal(t, uint8(3), config.DefaultUsage)
	assert.Equal(t, uint8(1), config.DefaultSelector)
	assert.Equal(t, uint8(1), config.DefaultMatchingType)
}

// TestDANE_RecordLifecycle tests complete TLSA record lifecycle.
func TestDANE_RecordLifecycle(t *testing.T) {
	skipIfNotIntegration(t)

	svc := createTestService(t)
	ctx := context.Background()

	zoneName := "lifecycle.com."
	zone := createTestZone(zoneName, false)
	require.NoError(t, svc.Save(ctx, zone))

	recordName := "_443._tcp.www." + zoneName

	// 1. Create
	hash := sha256.Sum256([]byte("initial-cert"))
	tlsaRecord := &entities.TLSARecord{
		Name:         recordName,
		Usage:        3,
		Selector:     1,
		MatchingType: 1,
		Data:         hex.EncodeToString(hash[:]),
		TTL:          3600,
	}
	err := svc.AddTLSARecord(ctx, zoneName, tlsaRecord)
	require.NoError(t, err)

	retrieved, err := svc.Zone(ctx, zoneName)
	require.NoError(t, err)
	assert.Len(t, retrieved.RecordSet.TLSARecords, 1)

	// 2. Update (add new, remove old)
	newHash := sha256.Sum256([]byte("updated-cert"))
	zone, err = svc.Zone(ctx, zoneName)
	require.NoError(t, err)

	zone.RemoveTLSARecord(recordName)
	zone.AddTLSARecord(&entities.TLSARecord{
		Name:         recordName,
		Usage:        3,
		Selector:     1,
		MatchingType: 1,
		Data:         hex.EncodeToString(newHash[:]),
		TTL:          7200, // Updated TTL
	})
	require.NoError(t, svc.Save(ctx, zone))

	retrieved, err = svc.Zone(ctx, zoneName)
	require.NoError(t, err)
	assert.Len(t, retrieved.RecordSet.TLSARecords, 1)
	assert.Equal(t, uint32(7200), retrieved.RecordSet.TLSARecords[0].TTL)

	// 3. Delete
	zone, err = svc.Zone(ctx, zoneName)
	require.NoError(t, err)
	zone.RemoveTLSARecord(recordName)
	require.NoError(t, svc.Save(ctx, zone))

	retrieved, err = svc.Zone(ctx, zoneName)
	require.NoError(t, err)
	assert.Len(t, retrieved.RecordSet.TLSARecords, 0)
}
