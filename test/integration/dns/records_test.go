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

// Package dns provides integration tests for DNS record type operations.
// These tests verify CAA, TLSA, and other record type functionality.
// Run via: make integration-test-dns or INTEGRATION_TEST=1 go test ./test/integration/dns/...
package dns

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCAARecord_Create_Success tests successful CAA record creation.
func TestCAARecord_Create_Success(t *testing.T) {
	skipIfNotIntegration(t)

	svc := createTestService(t)
	ctx := context.Background()

	zoneName := "caa-test.com."
	zone := createTestZone(zoneName, false)
	require.NoError(t, svc.Save(ctx, zone))

	// Add CAA record
	caaRecord := &entities.CAARecord{
		Name:  "@",
		Flags: 0,
		Tag:   "issue",
		Value: "letsencrypt.org",
		TTL:   3600,
	}
	zone.AddCAARecord(caaRecord)
	require.NoError(t, svc.Save(ctx, zone))

	retrieved, err := svc.Zone(ctx, zoneName)
	require.NoError(t, err)

	assert.Len(t, retrieved.RecordSet.CAARecords, 1)
	assert.Equal(t, "issue", retrieved.RecordSet.CAARecords[0].Tag)
	assert.Equal(t, "letsencrypt.org", retrieved.RecordSet.CAARecords[0].Value)
	assert.Equal(t, uint8(0), retrieved.RecordSet.CAARecords[0].Flags)
}

// TestCAARecord_MultipleTags tests creating CAA records with different tags.
func TestCAARecord_MultipleTags(t *testing.T) {
	skipIfNotIntegration(t)

	svc := createTestService(t)
	ctx := context.Background()

	zoneName := "caa-multitag.com."
	zone := createTestZone(zoneName, false)
	require.NoError(t, svc.Save(ctx, zone))

	// Add multiple CAA records with different tags
	caaRecords := []*entities.CAARecord{
		{Name: "@", Flags: 0, Tag: "issue", Value: "letsencrypt.org", TTL: 3600},
		{Name: "@", Flags: 0, Tag: "issuewild", Value: "digicert.com", TTL: 3600},
		{Name: "@", Flags: 0, Tag: "iodef", Value: "mailto:security@caa-multitag.com", TTL: 3600},
	}

	for _, caa := range caaRecords {
		zone.AddCAARecord(caa)
	}
	require.NoError(t, svc.Save(ctx, zone))

	retrieved, err := svc.Zone(ctx, zoneName)
	require.NoError(t, err)

	assert.Len(t, retrieved.RecordSet.CAARecords, 3)

	// Verify all tags are present
	tags := make(map[string]bool)
	for _, caa := range retrieved.RecordSet.CAARecords {
		tags[caa.Tag] = true
	}
	assert.True(t, tags["issue"])
	assert.True(t, tags["issuewild"])
	assert.True(t, tags["iodef"])
}

// TestCAARecord_CriticalFlag tests CAA record with critical flag set.
func TestCAARecord_CriticalFlag(t *testing.T) {
	skipIfNotIntegration(t)

	svc := createTestService(t)
	ctx := context.Background()

	zoneName := "caa-critical.com."
	zone := createTestZone(zoneName, false)
	require.NoError(t, svc.Save(ctx, zone))

	// Add CAA record with critical flag
	caaRecord := &entities.CAARecord{
		Name:  "@",
		Flags: 128, // Critical
		Tag:   "issue",
		Value: "privateca.example.com",
		TTL:   3600,
	}
	zone.AddCAARecord(caaRecord)
	require.NoError(t, svc.Save(ctx, zone))

	retrieved, err := svc.Zone(ctx, zoneName)
	require.NoError(t, err)

	assert.Len(t, retrieved.RecordSet.CAARecords, 1)
	assert.Equal(t, uint8(128), retrieved.RecordSet.CAARecords[0].Flags)
}

// TestCAARecord_Remove tests removing a CAA record.
func TestCAARecord_Remove(t *testing.T) {
	skipIfNotIntegration(t)

	svc := createTestService(t)
	ctx := context.Background()

	zoneName := "caa-remove.com."
	zone := createTestZone(zoneName, false)

	zone.AddCAARecord(&entities.CAARecord{
		Name:  "@",
		Flags: 0,
		Tag:   "issue",
		Value: "letsencrypt.org",
		TTL:   3600,
	})
	zone.AddCAARecord(&entities.CAARecord{
		Name:  "subdomain",
		Flags: 0,
		Tag:   "issue",
		Value: "digicert.com",
		TTL:   3600,
	})
	require.NoError(t, svc.Save(ctx, zone))

	// Remove one CAA record
	zone.RemoveCAARecord("@")
	require.NoError(t, svc.Save(ctx, zone))

	retrieved, err := svc.Zone(ctx, zoneName)
	require.NoError(t, err)

	assert.Len(t, retrieved.RecordSet.CAARecords, 1)
	assert.Equal(t, "subdomain", retrieved.RecordSet.CAARecords[0].Name)
}

// TestTLSARecord_Create_Success tests successful TLSA record creation.
func TestTLSARecord_Create_Success(t *testing.T) {
	skipIfNotIntegration(t)

	svc := createTestService(t)
	ctx := context.Background()

	zoneName := "tlsa-test.com."
	zone := createTestZone(zoneName, false)
	require.NoError(t, svc.Save(ctx, zone))

	// Add TLSA record via AddTLSARecord service method
	tlsaRecord := &entities.TLSARecord{
		Name:         "_443._tcp.www." + zoneName,
		Usage:        3, // DANE-EE
		Selector:     1, // SPKI
		MatchingType: 1, // SHA-256
		Data:         "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		TTL:          3600,
	}

	err := svc.AddTLSARecord(ctx, zoneName, tlsaRecord)
	require.NoError(t, err)

	retrieved, err := svc.Zone(ctx, zoneName)
	require.NoError(t, err)

	assert.Len(t, retrieved.RecordSet.TLSARecords, 1)
	assert.Equal(t, uint8(3), retrieved.RecordSet.TLSARecords[0].Usage)
	assert.Equal(t, uint8(1), retrieved.RecordSet.TLSARecords[0].Selector)
	assert.Equal(t, uint8(1), retrieved.RecordSet.TLSARecords[0].MatchingType)
}

// TestTLSARecord_MultipleRecords tests creating multiple TLSA records.
func TestTLSARecord_MultipleRecords(t *testing.T) {
	skipIfNotIntegration(t)

	svc := createTestService(t)
	ctx := context.Background()

	zoneName := "tlsa-multiple.com."
	zone := createTestZone(zoneName, false)
	require.NoError(t, svc.Save(ctx, zone))

	tlsaRecords := []*entities.TLSARecord{
		{
			Name:         "_443._tcp.www." + zoneName,
			Usage:        3,
			Selector:     1,
			MatchingType: 1,
			Data:         "aaaa1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			TTL:          3600,
		},
		{
			Name:         "_443._tcp.api." + zoneName,
			Usage:        3,
			Selector:     1,
			MatchingType: 1,
			Data:         "bbbb1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			TTL:          3600,
		},
		{
			Name:         "_25._tcp.mail." + zoneName,
			Usage:        2, // DANE-TA
			Selector:     1,
			MatchingType: 1,
			Data:         "cccc1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			TTL:          7200,
		},
	}

	for _, record := range tlsaRecords {
		err := svc.AddTLSARecord(ctx, zoneName, record)
		require.NoError(t, err)
	}

	retrieved, err := svc.Zone(ctx, zoneName)
	require.NoError(t, err)

	assert.Len(t, retrieved.RecordSet.TLSARecords, 3)
}

// TestTLSARecord_DANEUsageTypes tests TLSA records with different usage types.
func TestTLSARecord_DANEUsageTypes(t *testing.T) {
	skipIfNotIntegration(t)

	svc := createTestService(t)
	ctx := context.Background()

	zoneName := "tlsa-usage.com."
	zone := createTestZone(zoneName, false)
	require.NoError(t, svc.Save(ctx, zone))

	usageTypes := []struct {
		usage       uint8
		description string
	}{
		{0, "PKIX-TA"},
		{1, "PKIX-EE"},
		{2, "DANE-TA"},
		{3, "DANE-EE"},
	}

	for i, ut := range usageTypes {
		tlsaRecord := &entities.TLSARecord{
			Name:         "_443._tcp.host" + string(rune('a'+i)) + "." + zoneName,
			Usage:        ut.usage,
			Selector:     1,
			MatchingType: 1,
			Data:         "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			TTL:          3600,
		}
		zone.AddTLSARecord(tlsaRecord)
	}
	require.NoError(t, svc.Save(ctx, zone))

	retrieved, err := svc.Zone(ctx, zoneName)
	require.NoError(t, err)

	assert.Len(t, retrieved.RecordSet.TLSARecords, 4)

	// Verify each usage type is present
	usageMap := make(map[uint8]bool)
	for _, tlsa := range retrieved.RecordSet.TLSARecords {
		usageMap[tlsa.Usage] = true
	}
	for _, ut := range usageTypes {
		assert.True(t, usageMap[ut.usage], "usage type %d (%s) not found", ut.usage, ut.description)
	}
}

// TestTLSARecord_MatchingTypes tests TLSA records with different matching types.
func TestTLSARecord_MatchingTypes(t *testing.T) {
	skipIfNotIntegration(t)

	svc := createTestService(t)
	ctx := context.Background()

	zoneName := "tlsa-matching.com."
	zone := createTestZone(zoneName, false)
	require.NoError(t, svc.Save(ctx, zone))

	matchingTypes := []struct {
		matchingType uint8
		description  string
	}{
		{0, "Full"},
		{1, "SHA-256"},
		{2, "SHA-512"},
	}

	for i, mt := range matchingTypes {
		tlsaRecord := &entities.TLSARecord{
			Name:         "_443._tcp.match" + string(rune('a'+i)) + "." + zoneName,
			Usage:        3,
			Selector:     1,
			MatchingType: mt.matchingType,
			Data:         "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			TTL:          3600,
		}
		zone.AddTLSARecord(tlsaRecord)
	}
	require.NoError(t, svc.Save(ctx, zone))

	retrieved, err := svc.Zone(ctx, zoneName)
	require.NoError(t, err)

	assert.Len(t, retrieved.RecordSet.TLSARecords, 3)
}

// TestTLSARecord_Remove tests removing a TLSA record.
func TestTLSARecord_Remove(t *testing.T) {
	skipIfNotIntegration(t)

	svc := createTestService(t)
	ctx := context.Background()

	zoneName := "tlsa-remove.com."
	zone := createTestZone(zoneName, false)

	zone.AddTLSARecord(&entities.TLSARecord{
		Name:         "_443._tcp.www." + zoneName,
		Usage:        3,
		Selector:     1,
		MatchingType: 1,
		Data:         "aaaa1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		TTL:          3600,
	})
	zone.AddTLSARecord(&entities.TLSARecord{
		Name:         "_443._tcp.api." + zoneName,
		Usage:        3,
		Selector:     1,
		MatchingType: 1,
		Data:         "bbbb1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		TTL:          3600,
	})
	require.NoError(t, svc.Save(ctx, zone))

	// Remove one TLSA record
	zone.RemoveTLSARecord("_443._tcp.www." + zoneName)
	require.NoError(t, svc.Save(ctx, zone))

	retrieved, err := svc.Zone(ctx, zoneName)
	require.NoError(t, err)

	assert.Len(t, retrieved.RecordSet.TLSARecords, 1)
	assert.Equal(t, "_443._tcp.api."+zoneName, retrieved.RecordSet.TLSARecords[0].Name)
}

// TestTLSARecord_ZoneNotFound tests adding TLSA record to non-existent zone.
func TestTLSARecord_ZoneNotFound(t *testing.T) {
	skipIfNotIntegration(t)

	svc := createTestService(t)
	ctx := context.Background()

	tlsaRecord := &entities.TLSARecord{
		Name:         "_443._tcp.www.nonexistent.com.",
		Usage:        3,
		Selector:     1,
		MatchingType: 1,
		Data:         "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		TTL:          3600,
	}

	err := svc.AddTLSARecord(ctx, "nonexistent.com.", tlsaRecord)
	assert.Error(t, err)
}

// TestTLSARecord_PreservesExistingRecords tests that adding TLSA preserves other records.
func TestTLSARecord_PreservesExistingRecords(t *testing.T) {
	skipIfNotIntegration(t)

	svc := createTestService(t)
	ctx := context.Background()

	zoneName := "tlsa-preserve.com."
	zone := createTestZone(zoneName, false)

	// Add some existing records
	zone.AddCAARecord(&entities.CAARecord{
		Name:  "@",
		Flags: 0,
		Tag:   "issue",
		Value: "letsencrypt.org",
		TTL:   3600,
	})
	zone.AddTXTRecord(&entities.TXTRecord{
		Name:  "@",
		Value: "v=spf1 include:_spf.example.com ~all",
		TTL:   3600,
	})
	require.NoError(t, svc.Save(ctx, zone))

	// Add TLSA record
	tlsaRecord := &entities.TLSARecord{
		Name:         "_443._tcp.www." + zoneName,
		Usage:        3,
		Selector:     1,
		MatchingType: 1,
		Data:         "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		TTL:          3600,
	}
	err := svc.AddTLSARecord(ctx, zoneName, tlsaRecord)
	require.NoError(t, err)

	retrieved, err := svc.Zone(ctx, zoneName)
	require.NoError(t, err)

	// Verify TLSA record added
	assert.Len(t, retrieved.RecordSet.TLSARecords, 1)

	// Verify existing records preserved
	assert.Len(t, retrieved.RecordSet.CAARecords, 1)
	assert.Len(t, retrieved.RecordSet.TXTRecords, 1)
	assert.Len(t, retrieved.RecordSet.ARecords, 2)  // From createTestZone
	assert.Len(t, retrieved.RecordSet.NSRecords, 2) // From createTestZone
}

// TestARecord_Operations tests A record operations.
func TestARecord_Operations(t *testing.T) {
	skipIfNotIntegration(t)

	svc := createTestService(t)
	ctx := context.Background()

	zoneName := "a-record-test.com."
	zone := &entities.Zone{
		ID:   util.NewID([]byte(zoneName)),
		Name: zoneName,
		TTL:  3600,
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

	// Add A records
	aRecords := []*entities.ARecord{
		{Name: "www", Value: "192.168.1.1", TTL: 300},
		{Name: "api", Value: "192.168.1.2", TTL: 300},
		{Name: "mail", Value: "192.168.1.3", TTL: 3600},
		{Name: "@", Value: "192.168.1.100", TTL: 3600},
	}

	for _, r := range aRecords {
		zone.AddARecord(r)
	}
	require.NoError(t, svc.Save(ctx, zone))

	retrieved, err := svc.Zone(ctx, zoneName)
	require.NoError(t, err)

	assert.Len(t, retrieved.RecordSet.ARecords, 4)

	// Verify @ record (apex)
	found := false
	for _, r := range retrieved.RecordSet.ARecords {
		if r.Name == "@" {
			found = true
			assert.Equal(t, "192.168.1.100", r.Value)
		}
	}
	assert.True(t, found, "apex record not found")
}

// TestAAAARecord_Operations tests AAAA record operations.
func TestAAAARecord_Operations(t *testing.T) {
	skipIfNotIntegration(t)

	svc := createTestService(t)
	ctx := context.Background()

	zoneName := "aaaa-record-test.com."
	zone := &entities.Zone{
		ID:   util.NewID([]byte(zoneName)),
		Name: zoneName,
		TTL:  3600,
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

	// Add AAAA records
	aaaaRecords := []*entities.AAAARecord{
		{Name: "www", Value: "2001:db8::1", TTL: 300},
		{Name: "api", Value: "2001:db8::2", TTL: 300},
		{Name: "@", Value: "2001:db8::100", TTL: 3600},
	}

	for _, r := range aaaaRecords {
		zone.AddAAAARecord(r)
	}
	require.NoError(t, svc.Save(ctx, zone))

	retrieved, err := svc.Zone(ctx, zoneName)
	require.NoError(t, err)

	assert.Len(t, retrieved.RecordSet.AAAARecords, 3)
}

// TestCNAMERecord_Operations tests CNAME record operations.
func TestCNAMERecord_Operations(t *testing.T) {
	skipIfNotIntegration(t)

	svc := createTestService(t)
	ctx := context.Background()

	zoneName := "cname-test.com."
	zone := createTestZone(zoneName, false)
	require.NoError(t, svc.Save(ctx, zone))

	// Add CNAME records
	cnameRecords := []*entities.CNAMERecord{
		{Name: "www", Value: zoneName, TTL: 300},
		{Name: "blog", Value: "wordpress.example.com.", TTL: 300},
		{Name: "shop", Value: "store.example.com.", TTL: 3600},
	}

	for _, r := range cnameRecords {
		zone.AddCNAMERecord(r)
	}
	require.NoError(t, svc.Save(ctx, zone))

	retrieved, err := svc.Zone(ctx, zoneName)
	require.NoError(t, err)

	assert.Len(t, retrieved.RecordSet.CNAMERecords, 3)

	// Remove a CNAME
	zone.RemoveCNAMERecord("blog")
	require.NoError(t, svc.Save(ctx, zone))

	retrieved, err = svc.Zone(ctx, zoneName)
	require.NoError(t, err)
	assert.Len(t, retrieved.RecordSet.CNAMERecords, 2)
}

// TestMXRecord_Operations tests MX record operations.
func TestMXRecord_Operations(t *testing.T) {
	skipIfNotIntegration(t)

	svc := createTestService(t)
	ctx := context.Background()

	zoneName := "mx-test.com."
	zone := createTestZone(zoneName, false)
	require.NoError(t, svc.Save(ctx, zone))

	// Add MX records with different priorities
	mxRecords := []*entities.MXRecord{
		{Name: "@", Value: "mail1." + zoneName, Priority: 10, TTL: 3600},
		{Name: "@", Value: "mail2." + zoneName, Priority: 20, TTL: 3600},
		{Name: "@", Value: "backup." + zoneName, Priority: 50, TTL: 3600},
	}

	for _, r := range mxRecords {
		zone.AddMXRecord(r)
	}
	require.NoError(t, svc.Save(ctx, zone))

	retrieved, err := svc.Zone(ctx, zoneName)
	require.NoError(t, err)

	assert.Len(t, retrieved.RecordSet.MXRecords, 3)

	// Verify priority ordering is preserved
	priorities := make([]uint16, 0)
	for _, mx := range retrieved.RecordSet.MXRecords {
		priorities = append(priorities, mx.Priority)
	}
	assert.Contains(t, priorities, uint16(10))
	assert.Contains(t, priorities, uint16(20))
	assert.Contains(t, priorities, uint16(50))
}

// TestTXTRecord_Operations tests TXT record operations.
func TestTXTRecord_Operations(t *testing.T) {
	skipIfNotIntegration(t)

	svc := createTestService(t)
	ctx := context.Background()

	zoneName := "txt-test.com."
	zone := createTestZone(zoneName, false)
	require.NoError(t, svc.Save(ctx, zone))

	// Add various TXT records
	txtRecords := []*entities.TXTRecord{
		{Name: "@", Value: "v=spf1 include:_spf.google.com ~all", TTL: 3600},
		{Name: "_dmarc", Value: "v=DMARC1; p=reject; rua=mailto:dmarc@" + zoneName, TTL: 3600},
		{Name: "google._domainkey", Value: "v=DKIM1; k=rsa; p=MIGfMA0...", TTL: 86400},
		{Name: "@", Value: "google-site-verification=abc123xyz", TTL: 300},
	}

	for _, r := range txtRecords {
		zone.AddTXTRecord(r)
	}
	require.NoError(t, svc.Save(ctx, zone))

	retrieved, err := svc.Zone(ctx, zoneName)
	require.NoError(t, err)

	assert.Len(t, retrieved.RecordSet.TXTRecords, 4)
}

// TestSRVRecord_Operations tests SRV record operations.
func TestSRVRecord_Operations(t *testing.T) {
	skipIfNotIntegration(t)

	svc := createTestService(t)
	ctx := context.Background()

	zoneName := "srv-test.com."
	zone := createTestZone(zoneName, false)
	require.NoError(t, svc.Save(ctx, zone))

	// Add SRV records for various services
	srvRecords := []*entities.SRVRecord{
		{Name: "_ldap._tcp", Target: "ldap." + zoneName, Port: 389, Priority: 10, Weight: 100, TTL: 3600},
		{Name: "_sip._udp", Target: "sip." + zoneName, Port: 5060, Priority: 10, Weight: 50, TTL: 3600},
		{Name: "_xmpp-server._tcp", Target: "xmpp." + zoneName, Port: 5269, Priority: 5, Weight: 0, TTL: 3600},
		{Name: "_http._tcp", Target: "www." + zoneName, Port: 80, Priority: 10, Weight: 100, TTL: 300},
	}

	for _, r := range srvRecords {
		zone.AddSRVRecord(r)
	}
	require.NoError(t, svc.Save(ctx, zone))

	retrieved, err := svc.Zone(ctx, zoneName)
	require.NoError(t, err)

	assert.Len(t, retrieved.RecordSet.SRVRecords, 4)

	// Verify SRV record fields
	for _, srv := range retrieved.RecordSet.SRVRecords {
		assert.NotEmpty(t, srv.Name)
		assert.NotEmpty(t, srv.Target)
		assert.Greater(t, srv.Port, uint16(0))
	}
}

// TestNSRecord_Operations tests NS record operations.
func TestNSRecord_Operations(t *testing.T) {
	skipIfNotIntegration(t)

	svc := createTestService(t)
	ctx := context.Background()

	zoneName := "ns-test.com."
	zone := &entities.Zone{
		ID:   util.NewID([]byte(zoneName)),
		Name: zoneName,
		TTL:  3600,
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

	// Add NS records
	nsRecords := []*entities.NSRecord{
		{Name: "@", Value: "ns1." + zoneName, TTL: 86400},
		{Name: "@", Value: "ns2." + zoneName, TTL: 86400},
		{Name: "@", Value: "ns3." + zoneName, TTL: 86400},
		{Name: "subdomain", Value: "ns.subdomain." + zoneName, TTL: 3600}, // Delegated subdomain
	}

	for _, r := range nsRecords {
		zone.AddNSRecord(r)
	}
	require.NoError(t, svc.Save(ctx, zone))

	retrieved, err := svc.Zone(ctx, zoneName)
	require.NoError(t, err)

	assert.Len(t, retrieved.RecordSet.NSRecords, 4)

	// Remove NS record
	zone.RemoveNSRecord("subdomain")
	require.NoError(t, svc.Save(ctx, zone))

	retrieved, err = svc.Zone(ctx, zoneName)
	require.NoError(t, err)
	assert.Len(t, retrieved.RecordSet.NSRecords, 3)
}

// TestRecordCreationHelpers tests the dns.New* helper functions integration.
func TestRecordCreationHelpers(t *testing.T) {
	skipIfNotIntegration(t)

	svc := createTestService(t)
	ctx := context.Background()

	zoneName := "helpers-test.com."
	zone := &entities.Zone{
		ID:   util.NewID([]byte(zoneName)),
		Name: zoneName,
		TTL:  3600,
		RecordSet: entities.RecordSet{
			SOARecord: *dns.NewSOARecord(
				zoneName,
				"ns1."+zoneName,
				"hostmaster."+zoneName,
				2024010101, 7200, 3600, 1209600, 86400, 3600,
			),
		},
	}
	require.NoError(t, svc.Save(ctx, zone))

	// Use helper functions to create records
	zone.AddARecord(dns.NewARecord("www", "192.168.1.1", 300))
	zone.AddAAAARecord(dns.NewAAAARecord("www", "2001:db8::1", 300))
	zone.AddCNAMERecord(dns.NewCNAMERecord("blog", "www."+zoneName, 300))
	zone.AddMXRecord(dns.NewMXRecord("@", "mail."+zoneName, 10, 3600))
	zone.AddNSRecord(dns.NewNSRecord("@", "ns1."+zoneName, 86400))
	zone.AddTXTRecord(dns.NewTXTRecord("@", "v=spf1 ~all", 3600))
	zone.AddSRVRecord(dns.NewSRVRecord("_ldap._tcp", "ldap."+zoneName, 389, 10, 100, 3600))
	zone.AddCAARecord(dns.NewCAARecord("@", 0, "issue", "letsencrypt.org", 3600))
	zone.AddTLSARecord(dns.NewTLSARecord("_443._tcp.www", 3, 1, 1, "abcdef123456", 3600))

	require.NoError(t, svc.Save(ctx, zone))

	retrieved, err := svc.Zone(ctx, zoneName)
	require.NoError(t, err)

	// Verify all record types were created
	assert.Len(t, retrieved.RecordSet.ARecords, 1)
	assert.Len(t, retrieved.RecordSet.AAAARecords, 1)
	assert.Len(t, retrieved.RecordSet.CNAMERecords, 1)
	assert.Len(t, retrieved.RecordSet.MXRecords, 1)
	assert.Len(t, retrieved.RecordSet.NSRecords, 1)
	assert.Len(t, retrieved.RecordSet.TXTRecords, 1)
	assert.Len(t, retrieved.RecordSet.SRVRecords, 1)
	assert.Len(t, retrieved.RecordSet.CAARecords, 1)
	assert.Len(t, retrieved.RecordSet.TLSARecords, 1)
}
