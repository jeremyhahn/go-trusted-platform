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
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/mocks"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestDatastore creates a mock QuicBaaS-backed datastore for testing
func createTestDatastore(t *testing.T) *Datastore {
	logger := logging.DefaultLogger()
	mockStorage := quicbaas.NewMockStorage()
	// Start the mock storage - required before any operations
	err := mockStorage.Start(context.Background())
	require.NoError(t, err)
	return NewDatastore(mockStorage, logger)
}

func TestService_AddTLSARecord(t *testing.T) {
	ds := createTestDatastore(t)

	svcParams := &Params{
		TenantID:  "platform",
		Config:    &Config{},
		Datastore: ds,
	}

	svc, err := NewService(svcParams)
	require.NoError(t, err)

	// Create a test zone first
	zoneName := "example.com."
	zone := &entities.Zone{
		ID:       util.NewID([]byte(zoneName)), // ID must match what Zone() lookup uses
		Name:     zoneName,
		TenantID: "platform",
		TTL:      3600,
		RecordSet: entities.RecordSet{
			SOARecord: entities.SOARecord{
				Name:   zoneName,
				MName:  "ns1.example.com.",
				RName:  "hostmaster.example.com.",
				Serial: 1,
			},
		},
	}

	ctx := context.Background()
	err = svc.Save(ctx, zone)
	require.NoError(t, err)

	// Create a TLSA record
	tlsaRecord := &entities.TLSARecord{
		Name:         "_443._tcp.www.example.com.",
		Usage:        3,
		Selector:     1,
		MatchingType: 1,
		Data:         "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		TTL:          3600,
	}

	// Add the TLSA record
	err = svc.AddTLSARecord(ctx, zoneName, tlsaRecord)
	require.NoError(t, err)

	// Retrieve the zone and verify the TLSA record was added
	retrievedZone, err := svc.Zone(ctx, zoneName)
	require.NoError(t, err)

	assert.Len(t, retrievedZone.RecordSet.TLSARecords, 1)

	record := retrievedZone.RecordSet.TLSARecords[0]
	assert.Equal(t, tlsaRecord.Name, record.Name)
	assert.Equal(t, tlsaRecord.Usage, record.Usage)
	assert.Equal(t, tlsaRecord.Selector, record.Selector)
	assert.Equal(t, tlsaRecord.MatchingType, record.MatchingType)
	assert.Equal(t, tlsaRecord.Data, record.Data)
	assert.Equal(t, tlsaRecord.TTL, record.TTL)
}

func TestService_AddTLSARecord_MultipleRecords(t *testing.T) {
	ds := createTestDatastore(t)

	svcParams := &Params{
		TenantID:  "platform",
		Config:    &Config{},
		Datastore: ds,
	}

	svc, err := NewService(svcParams)
	require.NoError(t, err)

	// Create a test zone
	zoneName := "example.com."
	zone := &entities.Zone{
		ID:       util.NewID([]byte(zoneName)), // ID must match what Zone() lookup uses
		Name:     zoneName,
		TenantID: "platform",
		TTL:      3600,
		RecordSet: entities.RecordSet{
			SOARecord: entities.SOARecord{
				Name:   zoneName,
				MName:  "ns1.example.com.",
				RName:  "hostmaster.example.com.",
				Serial: 1,
			},
		},
	}

	ctx := context.Background()
	err = svc.Save(ctx, zone)
	require.NoError(t, err)

	// Add multiple TLSA records
	tlsaRecords := []*entities.TLSARecord{
		{
			Name:         "_443._tcp.www.example.com.",
			Usage:        3,
			Selector:     1,
			MatchingType: 1,
			Data:         "aaaa1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			TTL:          3600,
		},
		{
			Name:         "_443._tcp.api.example.com.",
			Usage:        3,
			Selector:     1,
			MatchingType: 1,
			Data:         "bbbb1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			TTL:          3600,
		},
		{
			Name:         "_25._tcp.mail.example.com.",
			Usage:        2,
			Selector:     1,
			MatchingType: 1,
			Data:         "cccc1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			TTL:          7200,
		},
	}

	for _, record := range tlsaRecords {
		err := svc.AddTLSARecord(ctx, zoneName, record)
		require.NoError(t, err, "failed to add TLSA record %s", record.Name)
	}

	// Retrieve the zone and verify all TLSA records were added
	retrievedZone, err := svc.Zone(ctx, zoneName)
	require.NoError(t, err)

	assert.Len(t, retrievedZone.RecordSet.TLSARecords, 3)

	// Verify each record
	for i, expected := range tlsaRecords {
		actual := retrievedZone.RecordSet.TLSARecords[i]
		assert.Equal(t, expected.Name, actual.Name)
		assert.Equal(t, expected.Usage, actual.Usage)
		assert.Equal(t, expected.Selector, actual.Selector)
		assert.Equal(t, expected.MatchingType, actual.MatchingType)
		assert.Equal(t, expected.Data, actual.Data)
		assert.Equal(t, expected.TTL, actual.TTL)
	}
}

func TestService_AddTLSARecord_ZoneNotFound(t *testing.T) {
	ds := createTestDatastore(t)

	svcParams := &Params{
		Config:    &Config{},
		Datastore: ds,
	}

	svc, err := NewService(svcParams)
	require.NoError(t, err)

	// Try to add a TLSA record to a non-existent zone
	tlsaRecord := &entities.TLSARecord{
		Name:         "_443._tcp.www.nonexistent.com.",
		Usage:        3,
		Selector:     1,
		MatchingType: 1,
		Data:         "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		TTL:          3600,
	}

	ctx := context.Background()
	err = svc.AddTLSARecord(ctx, "nonexistent.com.", tlsaRecord)
	assert.Error(t, err, "expected error when adding TLSA record to non-existent zone")
}

func TestService_AddTLSARecord_PreservesExistingRecords(t *testing.T) {
	ds := createTestDatastore(t)

	svcParams := &Params{
		TenantID:  "platform",
		Config:    &Config{},
		Datastore: ds,
	}

	svc, err := NewService(svcParams)
	require.NoError(t, err)

	// Create a test zone with existing A and NS records
	zoneName := "example.com."
	zone := &entities.Zone{
		ID:       util.NewID([]byte(zoneName)), // ID must match what Zone() lookup uses
		Name:     zoneName,
		TenantID: "platform",
		TTL:      3600,
		RecordSet: entities.RecordSet{
			SOARecord: entities.SOARecord{
				Name:   zoneName,
				MName:  "ns1.example.com.",
				RName:  "hostmaster.example.com.",
				Serial: 1,
			},
			ARecords: []*entities.ARecord{
				{Name: "www", Value: "192.168.1.1", TTL: 3600},
			},
			NSRecords: []*entities.NSRecord{
				{Name: "ns1", Value: "ns1.example.com.", TTL: 3600},
			},
			CAARecords: []*entities.CAARecord{
				{Name: "@", Tag: "issue", Value: "letsencrypt.org", TTL: 3600},
			},
			TXTRecords: []*entities.TXTRecord{
				{Name: "@", Value: "v=spf1 include:_spf.example.com ~all", TTL: 3600},
			},
		},
	}

	ctx := context.Background()
	err = svc.Save(ctx, zone)
	require.NoError(t, err)

	// Add a TLSA record
	tlsaRecord := &entities.TLSARecord{
		Name:         "_443._tcp.www.example.com.",
		Usage:        3,
		Selector:     1,
		MatchingType: 1,
		Data:         "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		TTL:          3600,
	}

	err = svc.AddTLSARecord(ctx, zoneName, tlsaRecord)
	require.NoError(t, err)

	// Retrieve the zone and verify existing records are preserved
	retrievedZone, err := svc.Zone(ctx, zoneName)
	require.NoError(t, err)

	// TLSA record should be added
	assert.Len(t, retrievedZone.RecordSet.TLSARecords, 1)

	// Existing records should still be there
	assert.Len(t, retrievedZone.RecordSet.ARecords, 1)
	assert.Equal(t, "www", retrievedZone.RecordSet.ARecords[0].Name)
	assert.Len(t, retrievedZone.RecordSet.NSRecords, 1)
	assert.Equal(t, "ns1", retrievedZone.RecordSet.NSRecords[0].Name)
	assert.Equal(t, zone.RecordSet.CAARecords, retrievedZone.RecordSet.CAARecords)
	assert.Equal(t, zone.RecordSet.TXTRecords, retrievedZone.RecordSet.TXTRecords)
}

// TestNewARecord verifies A record creation with all fields.
func TestNewARecord(t *testing.T) {
	tests := []struct {
		name     string
		recName  string
		value    string
		ttl      uint32
		expected *entities.ARecord
	}{
		{
			name:    "standard A record",
			recName: "www",
			value:   "192.168.1.1",
			ttl:     3600,
			expected: &entities.ARecord{
				Name:  "www",
				Value: "192.168.1.1",
				TTL:   3600,
			},
		},
		{
			name:    "apex record",
			recName: "@",
			value:   "10.0.0.1",
			ttl:     7200,
			expected: &entities.ARecord{
				Name:  "@",
				Value: "10.0.0.1",
				TTL:   7200,
			},
		},
		{
			name:    "zero TTL",
			recName: "test",
			value:   "127.0.0.1",
			ttl:     0,
			expected: &entities.ARecord{
				Name:  "test",
				Value: "127.0.0.1",
				TTL:   0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := NewARecord(tt.recName, tt.value, tt.ttl)
			assert.Equal(t, tt.expected.Name, record.Name)
			assert.Equal(t, tt.expected.Value, record.Value)
			assert.Equal(t, tt.expected.TTL, record.TTL)
		})
	}
}

// TestNewAAAARecord verifies AAAA record creation with all fields.
func TestNewAAAARecord(t *testing.T) {
	tests := []struct {
		name     string
		recName  string
		value    string
		ttl      uint32
		expected *entities.AAAARecord
	}{
		{
			name:    "standard AAAA record",
			recName: "www",
			value:   "2001:db8::1",
			ttl:     3600,
			expected: &entities.AAAARecord{
				Name:  "www",
				Value: "2001:db8::1",
				TTL:   3600,
			},
		},
		{
			name:    "full IPv6 address",
			recName: "server",
			value:   "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			ttl:     1800,
			expected: &entities.AAAARecord{
				Name:  "server",
				Value: "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
				TTL:   1800,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := NewAAAARecord(tt.recName, tt.value, tt.ttl)
			assert.Equal(t, tt.expected.Name, record.Name)
			assert.Equal(t, tt.expected.Value, record.Value)
			assert.Equal(t, tt.expected.TTL, record.TTL)
		})
	}
}

// TestNewCNAMERecord verifies CNAME record creation with all fields.
func TestNewCNAMERecord(t *testing.T) {
	tests := []struct {
		name     string
		recName  string
		target   string
		ttl      uint32
		expected *entities.CNAMERecord
	}{
		{
			name:    "standard CNAME record",
			recName: "www",
			target:  "example.com.",
			ttl:     3600,
			expected: &entities.CNAMERecord{
				Name:  "www",
				Value: "example.com.",
				TTL:   3600,
			},
		},
		{
			name:    "subdomain CNAME",
			recName: "blog",
			target:  "wordpress.example.com.",
			ttl:     86400,
			expected: &entities.CNAMERecord{
				Name:  "blog",
				Value: "wordpress.example.com.",
				TTL:   86400,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := NewCNAMERecord(tt.recName, tt.target, tt.ttl)
			assert.Equal(t, tt.expected.Name, record.Name)
			assert.Equal(t, tt.expected.Value, record.Value)
			assert.Equal(t, tt.expected.TTL, record.TTL)
		})
	}
}

// TestNewDNSKEYRecord verifies DNSKEY record creation with all fields.
func TestNewDNSKEYRecord(t *testing.T) {
	tests := []struct {
		name      string
		recName   string
		key       string
		flags     uint16
		protocol  uint8
		algorithm uint8
		ttl       uint32
	}{
		{
			name:      "ZSK record",
			recName:   "example.com.",
			key:       "AwEAAd...base64key...",
			flags:     256, // ZSK
			protocol:  3,
			algorithm: 13, // ECDSAP256SHA256
			ttl:       3600,
		},
		{
			name:      "KSK record",
			recName:   "example.com.",
			key:       "AwEAAe...base64key...",
			flags:     257, // KSK
			protocol:  3,
			algorithm: 8, // RSASHA256
			ttl:       86400,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := NewDNSKEYRecord(tt.recName, tt.key, tt.flags, tt.protocol, tt.algorithm, tt.ttl)
			assert.Equal(t, tt.recName, record.Name)
			assert.Equal(t, tt.key, record.Key)
			assert.Equal(t, tt.flags, record.Flags)
			assert.Equal(t, tt.protocol, record.Protocol)
			assert.Equal(t, tt.algorithm, record.Algorithm)
			assert.Equal(t, tt.ttl, record.TTL)
		})
	}
}

// TestNewDSRecord verifies DS record creation with all fields.
func TestNewDSRecord(t *testing.T) {
	tests := []struct {
		name       string
		recName    string
		keyTag     uint16
		algorithm  uint8
		digestType uint8
		digest     string
		ttl        uint32
	}{
		{
			name:       "SHA-256 DS record",
			recName:    "example.com.",
			keyTag:     12345,
			algorithm:  13,
			digestType: 2, // SHA-256
			digest:     "abc123...",
			ttl:        86400,
		},
		{
			name:       "SHA-384 DS record",
			recName:    "secure.example.com.",
			keyTag:     54321,
			algorithm:  8,
			digestType: 4, // SHA-384
			digest:     "def456...",
			ttl:        3600,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := NewDSRecord(tt.recName, tt.keyTag, tt.algorithm, tt.digestType, tt.digest, tt.ttl)
			assert.Equal(t, tt.recName, record.Name)
			assert.Equal(t, tt.keyTag, record.KeyTag)
			assert.Equal(t, tt.algorithm, record.Algorithm)
			assert.Equal(t, tt.digestType, record.DigestType)
			assert.Equal(t, tt.digest, record.Digest)
			assert.Equal(t, tt.ttl, record.TTL)
		})
	}
}

// TestNewMXRecord verifies MX record creation with all fields.
func TestNewMXRecord(t *testing.T) {
	tests := []struct {
		name     string
		recName  string
		value    string
		priority uint16
		ttl      uint32
	}{
		{
			name:     "primary mail server",
			recName:  "@",
			value:    "mail1.example.com.",
			priority: 10,
			ttl:      3600,
		},
		{
			name:     "backup mail server",
			recName:  "@",
			value:    "mail2.example.com.",
			priority: 20,
			ttl:      3600,
		},
		{
			name:     "high priority",
			recName:  "subdomain",
			value:    "smtp.example.com.",
			priority: 1,
			ttl:      7200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := NewMXRecord(tt.recName, tt.value, tt.priority, tt.ttl)
			assert.Equal(t, tt.recName, record.Name)
			assert.Equal(t, tt.value, record.Value)
			assert.Equal(t, tt.priority, record.Priority)
			assert.Equal(t, tt.ttl, record.TTL)
		})
	}
}

// TestNewNSRecord verifies NS record creation with all fields.
func TestNewNSRecord(t *testing.T) {
	tests := []struct {
		name    string
		recName string
		value   string
		ttl     uint32
	}{
		{
			name:    "primary nameserver",
			recName: "@",
			value:   "ns1.example.com.",
			ttl:     86400,
		},
		{
			name:    "secondary nameserver",
			recName: "@",
			value:   "ns2.example.com.",
			ttl:     86400,
		},
		{
			name:    "delegated subdomain",
			recName: "sub",
			value:   "ns.sub.example.com.",
			ttl:     3600,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := NewNSRecord(tt.recName, tt.value, tt.ttl)
			assert.Equal(t, tt.recName, record.Name)
			assert.Equal(t, tt.value, record.Value)
			assert.Equal(t, tt.ttl, record.TTL)
		})
	}
}

// TestNewRRSIGRecord verifies RRSIG record creation with all fields.
func TestNewRRSIGRecord(t *testing.T) {
	tests := []struct {
		name        string
		recName     string
		typeCovered string
		algorithm   uint8
		labels      uint8
		originalTTL uint32
		expiration  string
		inception   string
		keyTag      uint16
		signerName  string
		signature   string
	}{
		{
			name:        "A record signature",
			recName:     "www.example.com.",
			typeCovered: "A",
			algorithm:   13,
			labels:      3,
			originalTTL: 3600,
			expiration:  "20251231235959",
			inception:   "20250101000000",
			keyTag:      12345,
			signerName:  "example.com.",
			signature:   "base64signature...",
		},
		{
			name:        "DNSKEY record signature",
			recName:     "example.com.",
			typeCovered: "DNSKEY",
			algorithm:   8,
			labels:      2,
			originalTTL: 86400,
			expiration:  "20260101000000",
			inception:   "20250601000000",
			keyTag:      54321,
			signerName:  "example.com.",
			signature:   "anotherbase64sig...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := NewRRSIGRecord(
				tt.recName, tt.typeCovered, tt.algorithm, tt.labels,
				tt.originalTTL, tt.expiration, tt.inception,
				tt.keyTag, tt.signerName, tt.signature,
			)
			assert.Equal(t, tt.recName, record.Name)
			assert.Equal(t, tt.signerName, record.SignerName)
			assert.Equal(t, tt.signature, record.Signature)
			assert.Equal(t, tt.typeCovered, record.TypeCovered)
			assert.Equal(t, tt.algorithm, record.Algorithm)
			assert.Equal(t, tt.labels, record.Labels)
			assert.Equal(t, tt.originalTTL, record.OriginalTTL)
			assert.Equal(t, tt.expiration, record.Expiration)
			assert.Equal(t, tt.inception, record.Inception)
			assert.Equal(t, tt.keyTag, record.KeyTag)
		})
	}
}

// TestNewSOARecord verifies SOA record creation with all fields.
func TestNewSOARecord(t *testing.T) {
	tests := []struct {
		name       string
		recName    string
		mname      string
		rname      string
		serial     uint32
		refresh    uint32
		retry      uint32
		expire     uint32
		minimumTTL uint32
		ttl        uint32
	}{
		{
			name:       "standard SOA record",
			recName:    "example.com.",
			mname:      "ns1.example.com.",
			rname:      "hostmaster.example.com.",
			serial:     2024010101,
			refresh:    86400,
			retry:      7200,
			expire:     604800,
			minimumTTL: 3600,
			ttl:        86400,
		},
		{
			name:       "internal zone SOA",
			recName:    "internal.local.",
			mname:      "ns1.internal.local.",
			rname:      "admin.internal.local.",
			serial:     1,
			refresh:    3600,
			retry:      1800,
			expire:     86400,
			minimumTTL: 300,
			ttl:        3600,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := NewSOARecord(
				tt.recName, tt.mname, tt.rname,
				tt.serial, tt.refresh, tt.retry, tt.expire, tt.minimumTTL, tt.ttl,
			)
			assert.Equal(t, tt.recName, record.Name)
			assert.Equal(t, tt.mname, record.MName)
			assert.Equal(t, tt.rname, record.RName)
			assert.Equal(t, tt.serial, record.Serial)
			assert.Equal(t, tt.refresh, record.Refresh)
			assert.Equal(t, tt.retry, record.Retry)
			assert.Equal(t, tt.expire, record.Expire)
			assert.Equal(t, tt.minimumTTL, record.MinimumTTL)
			assert.Equal(t, tt.ttl, record.TTL)
		})
	}
}

// TestNewSRVRecord verifies SRV record creation with all fields.
func TestNewSRVRecord(t *testing.T) {
	tests := []struct {
		name     string
		recName  string
		target   string
		port     uint16
		priority uint16
		weight   uint16
		ttl      uint32
	}{
		{
			name:     "LDAP service",
			recName:  "_ldap._tcp.example.com.",
			target:   "ldap.example.com.",
			port:     389,
			priority: 10,
			weight:   100,
			ttl:      3600,
		},
		{
			name:     "SIP service",
			recName:  "_sip._udp.example.com.",
			target:   "sip.example.com.",
			port:     5060,
			priority: 5,
			weight:   50,
			ttl:      1800,
		},
		{
			name:     "XMPP service",
			recName:  "_xmpp-server._tcp.example.com.",
			target:   "xmpp.example.com.",
			port:     5269,
			priority: 0,
			weight:   0,
			ttl:      7200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := NewSRVRecord(tt.recName, tt.target, tt.port, tt.priority, tt.weight, tt.ttl)
			assert.Equal(t, tt.recName, record.Name)
			assert.Equal(t, tt.target, record.Target)
			assert.Equal(t, tt.port, record.Port)
			assert.Equal(t, tt.priority, record.Priority)
			assert.Equal(t, tt.weight, record.Weight)
			assert.Equal(t, tt.ttl, record.TTL)
		})
	}
}

// TestNewTXTRecord verifies TXT record creation with all fields.
func TestNewTXTRecord(t *testing.T) {
	tests := []struct {
		name    string
		recName string
		value   string
		ttl     uint32
	}{
		{
			name:    "SPF record",
			recName: "@",
			value:   "v=spf1 include:_spf.google.com ~all",
			ttl:     3600,
		},
		{
			name:    "DKIM record",
			recName: "selector._domainkey",
			value:   "v=DKIM1; k=rsa; p=MIGfMA0...",
			ttl:     86400,
		},
		{
			name:    "DMARC record",
			recName: "_dmarc",
			value:   "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
			ttl:     3600,
		},
		{
			name:    "verification record",
			recName: "@",
			value:   "google-site-verification=abc123",
			ttl:     300,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := NewTXTRecord(tt.recName, tt.value, tt.ttl)
			assert.Equal(t, tt.recName, record.Name)
			assert.Equal(t, tt.value, record.Value)
			assert.Equal(t, tt.ttl, record.TTL)
		})
	}
}

// TestNewCAARecord verifies CAA record creation with all fields.
func TestNewCAARecord(t *testing.T) {
	tests := []struct {
		name    string
		recName string
		flags   uint8
		tag     string
		value   string
		ttl     uint32
	}{
		{
			name:    "issue CAA record",
			recName: "@",
			flags:   0,
			tag:     "issue",
			value:   "letsencrypt.org",
			ttl:     3600,
		},
		{
			name:    "issuewild CAA record",
			recName: "@",
			flags:   0,
			tag:     "issuewild",
			value:   "digicert.com",
			ttl:     86400,
		},
		{
			name:    "iodef CAA record",
			recName: "@",
			flags:   0,
			tag:     "iodef",
			value:   "mailto:security@example.com",
			ttl:     3600,
		},
		{
			name:    "critical flag CAA",
			recName: "secure",
			flags:   128, // Critical
			tag:     "issue",
			value:   "ca.example.com",
			ttl:     1800,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := NewCAARecord(tt.recName, tt.flags, tt.tag, tt.value, tt.ttl)
			assert.Equal(t, tt.recName, record.Name)
			assert.Equal(t, tt.flags, record.Flags)
			assert.Equal(t, tt.tag, record.Tag)
			assert.Equal(t, tt.value, record.Value)
			assert.Equal(t, tt.ttl, record.TTL)
		})
	}
}

// TestNewTLSARecord verifies TLSA record creation with all fields.
func TestNewTLSARecord(t *testing.T) {
	tests := []struct {
		name         string
		recName      string
		usage        uint8
		selector     uint8
		matchingType uint8
		data         string
		ttl          uint32
	}{
		{
			name:         "DANE-EE SHA-256",
			recName:      "_443._tcp.www.example.com.",
			usage:        3, // DANE-EE
			selector:     1, // SPKI
			matchingType: 1, // SHA-256
			data:         "abc123def456...",
			ttl:          3600,
		},
		{
			name:         "DANE-TA SHA-512",
			recName:      "_443._tcp.secure.example.com.",
			usage:        2, // DANE-TA
			selector:     0, // Full certificate
			matchingType: 2, // SHA-512
			data:         "fedcba654321...",
			ttl:          86400,
		},
		{
			name:         "PKIX-EE full cert",
			recName:      "_25._tcp.mail.example.com.",
			usage:        1, // PKIX-EE
			selector:     0, // Full certificate
			matchingType: 0, // Full
			data:         "fullcertdata...",
			ttl:          7200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := NewTLSARecord(tt.recName, tt.usage, tt.selector, tt.matchingType, tt.data, tt.ttl)
			assert.Equal(t, tt.recName, record.Name)
			assert.Equal(t, tt.usage, record.Usage)
			assert.Equal(t, tt.selector, record.Selector)
			assert.Equal(t, tt.matchingType, record.MatchingType)
			assert.Equal(t, tt.data, record.Data)
			assert.Equal(t, tt.ttl, record.TTL)
		})
	}
}

// TestService_Delete verifies zone deletion functionality.
func TestService_Delete(t *testing.T) {
	ds := createTestDatastore(t)

	svcParams := &Params{
		TenantID:  "platform",
		Config:    &Config{},
		Datastore: ds,
	}

	svc, err := NewService(svcParams)
	require.NoError(t, err)

	ctx := context.Background()

	// Create a test zone with TenantID
	zoneName := "delete-test.com."
	zone := &entities.Zone{
		ID:       util.NewID([]byte(zoneName)),
		Name:     zoneName,
		TenantID: "platform",
		TTL:      3600,
	}

	// Save the zone
	err = svc.Save(ctx, zone)
	require.NoError(t, err)

	// Verify zone exists
	_, err = svc.Zone(ctx, zoneName)
	require.NoError(t, err)

	// Delete the zone
	err = svc.Delete(ctx, zone)
	require.NoError(t, err)

	// Verify zone is deleted
	_, err = svc.Zone(ctx, zoneName)
	assert.Error(t, err, "expected error when retrieving deleted zone")
}

// TestService_Delete_Error verifies error handling when delete fails.
func TestService_Delete_Error(t *testing.T) {
	mockDAO := mocks.NewMockZoneDAO()
	expectedErr := errors.New("mock delete error")
	mockDAO.DeleteFunc = func(ctx context.Context, zone *entities.Zone) error {
		return expectedErr
	}

	svc := &Service{
		params: &Params{
			TenantID: "platform",
			Config:   &Config{Logger: logging.DefaultLogger()},
		},
		zoneDAO: mockDAO,
	}

	ctx := context.Background()
	zone := &entities.Zone{ID: 1, Name: "test.com.", TenantID: "platform"}

	err := svc.Delete(ctx, zone)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete zone")
}

// TestService_InternalDomain verifies internal domain retrieval.
func TestService_InternalDomain(t *testing.T) {
	svc := &Service{
		params: &Params{
			Config: &Config{
				InternalServer: &InternalServer{
					Zone: entities.Zone{
						Name: "example.internal.",
					},
				},
			},
		},
	}

	domain := svc.InternalDomain()
	assert.Equal(t, "example.internal.", domain)
}

// TestService_PublicDomain verifies public domain retrieval.
func TestService_PublicDomain(t *testing.T) {
	svc := &Service{
		params: &Params{
			Config: &Config{
				PublicServer: &PublicServer{
					Zone: entities.Zone{
						Name: "example.com.",
					},
				},
			},
		},
	}

	domain := svc.PublicDomain()
	assert.Equal(t, "example.com.", domain)
}

// A daemon may run the DNS service with neither server configured (the
// integration platformd does); its domains are then empty, and reading them
// must not dereference the absent server config (QUIC DNS GetConfig panicked).
func TestService_Domains_NoServerConfigured(t *testing.T) {
	svc := &Service{params: &Params{Config: &Config{}}}

	assert.Empty(t, svc.InternalDomain())
	assert.Empty(t, svc.PublicDomain())
}

// TestService_InternalZone verifies internal zone retrieval.
func TestService_InternalZone(t *testing.T) {
	mockDAO := mocks.NewMockZoneDAO()

	tenantID := "platform"
	zoneName := "example.internal."
	zoneID := util.NewID([]byte(zoneName))
	zone := &entities.Zone{
		ID:       zoneID,
		Name:     zoneName,
		TenantID: tenantID,
		TTL:      3600,
		Internal: true,
	}
	mockDAO.AddZone(zone)

	svc := &Service{
		params: &Params{
			TenantID: tenantID,
			Config: &Config{
				InternalServer: &InternalServer{
					Zone: entities.Zone{
						Name: zoneName,
					},
				},
			},
		},
		zoneDAO: mockDAO,
	}

	ctx := context.Background()
	retrievedZone, err := svc.InternalZone(ctx)
	require.NoError(t, err)
	assert.Equal(t, zoneName, retrievedZone.Name)
	assert.True(t, retrievedZone.Internal)
}

// TestService_PublicZone verifies public zone retrieval.
func TestService_PublicZone(t *testing.T) {
	mockDAO := mocks.NewMockZoneDAO()

	tenantID := "platform"
	zoneName := "example.com."
	zoneID := util.NewID([]byte(zoneName))
	zone := &entities.Zone{
		ID:       zoneID,
		Name:     zoneName,
		TenantID: tenantID,
		TTL:      3600,
		Internal: false,
	}
	mockDAO.AddZone(zone)

	svc := &Service{
		params: &Params{
			TenantID: tenantID,
			Config: &Config{
				PublicServer: &PublicServer{
					Zone: entities.Zone{
						Name: zoneName,
					},
				},
			},
		},
		zoneDAO: mockDAO,
	}

	ctx := context.Background()
	retrievedZone, err := svc.PublicZone(ctx)
	require.NoError(t, err)
	assert.Equal(t, zoneName, retrievedZone.Name)
	assert.False(t, retrievedZone.Internal)
}

// TestService_Zone_WithoutTrailingDot verifies zone retrieval normalizes names.
func TestService_Zone_WithoutTrailingDot(t *testing.T) {
	mockDAO := mocks.NewMockZoneDAO()

	tenantID := "platform"
	zoneName := "example.com."
	zoneID := util.NewID([]byte(zoneName))
	zone := &entities.Zone{
		ID:       zoneID,
		Name:     zoneName,
		TenantID: tenantID,
		TTL:      3600,
	}
	mockDAO.AddZone(zone)

	svc := &Service{
		params:  &Params{TenantID: tenantID, Config: &Config{}},
		zoneDAO: mockDAO,
	}

	ctx := context.Background()

	// Query without trailing dot
	retrievedZone, err := svc.Zone(ctx, "example.com")
	require.NoError(t, err)
	assert.Equal(t, zoneName, retrievedZone.Name)
}

// TestService_Save_Error verifies error handling when save fails.
func TestService_Save_Error(t *testing.T) {
	mockDAO := mocks.NewMockZoneDAO()
	expectedErr := errors.New("mock save error")
	mockDAO.SaveFunc = func(ctx context.Context, zone *entities.Zone) error {
		return expectedErr
	}

	svc := &Service{
		params: &Params{
			TenantID: "platform",
			Config:   &Config{},
		},
		zoneDAO: mockDAO,
	}

	ctx := context.Background()
	zone := &entities.Zone{ID: 1, Name: "test.com.", TenantID: "platform"}

	err := svc.Save(ctx, zone)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to save zone")
}

// TestService_Register_Disabled verifies registration disabled error.
func TestService_Register_Disabled(t *testing.T) {
	svc := &Service{
		params: &Params{
			Config: &Config{
				AllowRegistration: false,
			},
		},
	}

	ctx := context.Background()
	_, err := svc.Register(ctx, "test.example.com", "192.168.1.1")
	assert.ErrorIs(t, err, ErrRegistrationDisabled)
}

// TestService_Register_InvalidIP verifies invalid IP error.
func TestService_Register_InvalidIP(t *testing.T) {
	svc := &Service{
		params: &Params{
			Config: &Config{
				AllowRegistration: true,
			},
		},
	}

	ctx := context.Background()
	_, err := svc.Register(ctx, "test.example.com", "not-an-ip")
	assert.ErrorIs(t, err, ErrInvalidIPAddress)
}

// TestService_Register_InvalidPrivateIP verifies private IP validation for internal zones.
func TestService_Register_InvalidPrivateIP(t *testing.T) {
	// Initialize TLDs for testing
	err := LoadTLDs(nil, []byte("com\norg\nnet\n"))
	require.NoError(t, err)

	svc := &Service{
		params: &Params{
			Config: &Config{
				AllowRegistration: true,
				InternalServer: &InternalServer{
					Zone: entities.Zone{
						Name: "example.internal.",
					},
				},
			},
		},
	}

	ctx := context.Background()
	// Try to register with a public IP in the internal zone
	_, err = svc.Register(ctx, "test.example.internal", "8.8.8.8")
	assert.ErrorIs(t, err, ErrInvalidPrivateIP)
}

// TestService_Register_InvalidPublicIP verifies public IP validation for public zones.
func TestService_Register_InvalidPublicIP(t *testing.T) {
	// Initialize TLDs for testing
	err := LoadTLDs(nil, []byte("com\norg\nnet\nio\n"))
	require.NoError(t, err)

	svc := &Service{
		params: &Params{
			Config: &Config{
				AllowRegistration: true,
				PublicServer: &PublicServer{
					Zone: entities.Zone{
						Name: "example.com.",
					},
				},
			},
		},
	}

	ctx := context.Background()
	// Try to register with a private IP in the public zone
	_, err = svc.Register(ctx, "test.example.com", "192.168.1.1")
	assert.ErrorIs(t, err, ErrInvalidPublicIP)
}

// TestService_Register_ExternalRegistrationDisabled verifies external registration error.
func TestService_Register_ExternalRegistrationDisabled(t *testing.T) {
	// Initialize TLDs for testing
	err := LoadTLDs(nil, []byte("com\norg\nnet\n"))
	require.NoError(t, err)

	mockDAO := mocks.NewMockZoneDAO()

	svc := &Service{
		params: &Params{
			Config: &Config{
				AllowRegistration:         true,
				AllowExternalRegistration: false,
				AllowInternalRegistration: true,
			},
		},
		zoneDAO: mockDAO,
	}

	ctx := context.Background()
	// Try external registration with public TLD
	_, err = svc.Register(ctx, "test.example.com", "8.8.8.8")
	assert.ErrorIs(t, err, ErrExternalRegistrationDisabled)
}

// TestService_Register_InternalRegistrationDisabled verifies internal registration error.
func TestService_Register_InternalRegistrationDisabled(t *testing.T) {
	// Initialize TLDs with common public TLDs but NOT private TLDs
	err := LoadTLDs(nil, []byte("com\norg\nnet\n"))
	require.NoError(t, err)

	mockDAO := mocks.NewMockZoneDAO()

	svc := &Service{
		params: &Params{
			Config: &Config{
				AllowRegistration:         true,
				AllowExternalRegistration: true,
				AllowInternalRegistration: false,
			},
		},
		zoneDAO: mockDAO,
	}

	ctx := context.Background()
	// Try internal registration with private TLD (not in IANA list)
	_, err = svc.Register(ctx, "test.example.internal", "192.168.1.1")
	assert.ErrorIs(t, err, ErrInternalRegistrationDisabled)
}

// TestService_Register_ZoneAlreadyExists verifies zone already exists error.
func TestService_Register_ZoneAlreadyExists(t *testing.T) {
	// Initialize TLDs for testing
	err := LoadTLDs(nil, []byte("com\norg\nnet\n"))
	require.NoError(t, err)

	mockDAO := mocks.NewMockZoneDAO()

	// Add an existing zone
	existingZone := &entities.Zone{
		ID:   util.NewID([]byte("example.com.")),
		Name: "example.com.",
	}
	mockDAO.AddZone(existingZone)

	svc := &Service{
		params: &Params{
			Config: &Config{
				AllowRegistration:         true,
				AllowExternalRegistration: true,
			},
		},
		zoneDAO: mockDAO,
	}

	ctx := context.Background()
	_, err = svc.Register(ctx, "test.example.com", "8.8.8.8")
	assert.ErrorIs(t, err, ErrZoneAlreadyExists)
}

// TestService_Register_Success_NewZone verifies successful new zone registration.
func TestService_Register_Success_NewZone(t *testing.T) {
	// Initialize TLDs for testing
	err := LoadTLDs(nil, []byte("com\norg\nnet\n"))
	require.NoError(t, err)

	mockDAO := mocks.NewMockZoneDAO()

	svc := &Service{
		params: &Params{
			Config: &Config{
				AllowRegistration:         true,
				AllowExternalRegistration: true,
				Logger:                    logging.DefaultLogger(),
			},
		},
		zoneDAO: mockDAO,
	}

	ctx := context.Background()
	_, err = svc.Register(ctx, "host.newdomain.com", "8.8.8.8")
	require.NoError(t, err)

	// Verify zone was created
	assert.Equal(t, 1, mockDAO.ZoneCount())
}

// TestService_Register_AddToExistingZone verifies adding a host to an existing zone.
func TestService_Register_AddToExistingZone(t *testing.T) {
	// Initialize TLDs for testing
	err := LoadTLDs(nil, []byte("com\norg\nnet\nio\n"))
	require.NoError(t, err)

	mockDAO := mocks.NewMockZoneDAO()

	zoneName := "example.com."
	zoneID := util.NewID([]byte(zoneName))
	existingZone := &entities.Zone{
		ID:   zoneID,
		Name: zoneName,
		TTL:  3600,
		RecordSet: entities.RecordSet{
			ARecords: []*entities.ARecord{
				{Name: "www", Value: "1.2.3.4", TTL: 3600},
			},
		},
	}
	mockDAO.AddZone(existingZone)

	svc := &Service{
		params: &Params{
			Config: &Config{
				AllowRegistration:         true,
				AllowExternalRegistration: true,
				Logger:                    logging.DefaultLogger(),
				PublicServer: &PublicServer{
					Zone: entities.Zone{
						Name: zoneName,
					},
				},
			},
		},
		zoneDAO: mockDAO,
	}

	ctx := context.Background()
	_, err = svc.Register(ctx, "newhost.example.com", "5.6.7.8")
	require.NoError(t, err)

	// Verify zone still has 1 entry (updated, not duplicated)
	assert.Equal(t, 1, mockDAO.ZoneCount())
}

// TestService_Resolver verifies resolver creation.
func TestService_Resolver(t *testing.T) {
	svc := &Service{
		params: &Params{
			Config: &Config{
				InternalServer: &InternalServer{
					Port: 5353,
				},
			},
		},
	}

	resolver := svc.Resolver()
	assert.NotNil(t, resolver)
	assert.True(t, resolver.PreferGo)
}

// TestService_AddTLSARecord_SaveError verifies error handling when TLSA save fails.
func TestService_AddTLSARecord_SaveError(t *testing.T) {
	mockDAO := mocks.NewMockZoneDAO()

	tenantID := "test-tenant"
	zoneName := "example.com."
	zoneID := util.NewID([]byte(zoneName))
	zone := &entities.Zone{
		ID:       zoneID,
		Name:     zoneName,
		TTL:      3600,
		TenantID: tenantID,
	}
	mockDAO.AddZone(zone)

	// Configure save to fail
	saveCallCount := 0
	mockDAO.SaveFunc = func(ctx context.Context, zone *entities.Zone) error {
		saveCallCount++
		return errors.New("save failed")
	}

	svc := &Service{
		params:  &Params{Config: &Config{}, TenantID: tenantID},
		zoneDAO: mockDAO,
	}

	ctx := context.Background()
	tlsaRecord := &entities.TLSARecord{
		Name:         "_443._tcp.www.example.com.",
		Usage:        3,
		Selector:     1,
		MatchingType: 1,
		Data:         "abc123",
		TTL:          3600,
	}

	err := svc.AddTLSARecord(ctx, zoneName, tlsaRecord)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to save zone")
}

// TestService_Zone_Error verifies error handling when get zone fails.
func TestService_Zone_Error(t *testing.T) {
	mockDAO := mocks.NewMockZoneDAO()
	mockDAO.GetFunc = func(ctx context.Context, id uint64) (*entities.Zone, error) {
		return nil, errors.New("zone not found")
	}

	svc := &Service{
		params:  &Params{Config: &Config{}, TenantID: "test-tenant"},
		zoneDAO: mockDAO,
	}

	ctx := context.Background()
	_, err := svc.Zone(ctx, "nonexistent.com.")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get zone")
}

// TestService_Register_ParsingError verifies error handling when FQDN parsing fails.
func TestService_Register_ParsingError(t *testing.T) {
	svc := &Service{
		params: &Params{
			Config: &Config{
				AllowRegistration: true,
				Logger:            logging.DefaultLogger(),
			},
		},
	}

	ctx := context.Background()
	// Try to register with invalid FQDN (single character without a TLD)
	_, err := svc.Register(ctx, "x", "192.168.1.1")
	assert.ErrorIs(t, err, ErrParsingDomainName)
}

// TestService_Register_InvalidPrivateTLD verifies error for private TLD in internal zone.
func TestService_Register_InvalidPrivateTLD(t *testing.T) {
	// Load a public TLD
	err := LoadTLDs(nil, []byte("com\norg\nnet\nio\n"))
	require.NoError(t, err)

	mockDAO := mocks.NewMockZoneDAO()

	// Create service with internal zone using public TLD (com) - this is invalid
	svc := &Service{
		params: &Params{
			Config: &Config{
				AllowRegistration: true,
				Logger:            logging.DefaultLogger(),
				InternalServer: &InternalServer{
					Zone: entities.Zone{
						Name: "example.com.", // Public TLD used for internal zone
					},
				},
			},
		},
		zoneDAO: mockDAO,
	}

	ctx := context.Background()
	// Try to register with public TLD for internal zone - triggers TLD error
	_, err = svc.Register(ctx, "test.example.com", "192.168.1.1")
	// This triggers the public TLD check for internal zone
	assert.ErrorIs(t, err, ErrInvalidPrivateTLD)
}

// TestService_Register_InvalidPublicTLD verifies error for invalid public TLD.
func TestService_Register_InvalidPublicTLD(t *testing.T) {
	// Load some public TLDs
	err := LoadTLDs(nil, []byte("com\norg\nnet\nio\n"))
	require.NoError(t, err)

	svc := &Service{
		params: &Params{
			Config: &Config{
				AllowRegistration: true,
				Logger:            logging.DefaultLogger(),
				PublicServer: &PublicServer{
					Zone: entities.Zone{
						Name: "trusted-platform.notreal.", // Non-existent TLD
					},
				},
			},
		},
	}

	ctx := context.Background()
	// Try to register with a non-public TLD for public zone
	_, err = svc.Register(ctx, "test.trusted-platform.notreal", "8.8.8.8")
	assert.ErrorIs(t, err, ErrInvalidPublicTLD)
}

// TestService_Register_SaveError verifies error handling when save fails during registration.
func TestService_Register_SaveError(t *testing.T) {
	err := LoadTLDs(nil, []byte("com\norg\nnet\n"))
	require.NoError(t, err)

	mockDAO := mocks.NewMockZoneDAO()
	mockDAO.SaveFunc = func(ctx context.Context, zone *entities.Zone) error {
		return errors.New("save failed")
	}

	svc := &Service{
		params: &Params{
			Config: &Config{
				AllowRegistration:         true,
				AllowExternalRegistration: true,
				Logger:                    logging.DefaultLogger(),
			},
		},
		zoneDAO: mockDAO,
	}

	ctx := context.Background()
	_, err = svc.Register(ctx, "host.newzone.com", "8.8.8.8")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to save zone")
}

// TestService_Register_AddRecordToInternalZone verifies adding record to existing internal zone.
func TestService_Register_AddRecordToInternalZone(t *testing.T) {
	// Clear and load TLDs - ensure "internal" is NOT in the public list
	err := LoadTLDs(nil, []byte("com\norg\nnet\nio\n"))
	require.NoError(t, err)

	mockDAO := mocks.NewMockZoneDAO()

	zoneName := "example.internal."
	zoneID := util.NewID([]byte(zoneName))
	existingZone := &entities.Zone{
		ID:       zoneID,
		Name:     zoneName,
		TTL:      3600,
		Internal: true,
		RecordSet: entities.RecordSet{
			ARecords: []*entities.ARecord{
				{Name: "www", Value: "192.168.1.1", TTL: 3600},
			},
		},
	}
	mockDAO.AddZone(existingZone)

	svc := &Service{
		params: &Params{
			Config: &Config{
				AllowRegistration:         true,
				AllowInternalRegistration: true,
				Logger:                    logging.DefaultLogger(),
				InternalServer: &InternalServer{
					Zone: entities.Zone{
						Name: zoneName,
					},
				},
			},
		},
		zoneDAO: mockDAO,
	}

	ctx := context.Background()
	_, err = svc.Register(ctx, "newhost.example.internal", "192.168.1.100")
	require.NoError(t, err)

	// Verify zone still has 1 entry (updated, not duplicated)
	assert.Equal(t, 1, mockDAO.ZoneCount())
}

// TestService_Register_ZoneAlreadyExistsInRegister verifies duplicate zone error in register.
func TestService_Register_ZoneAlreadyExistsInRegister(t *testing.T) {
	err := LoadTLDs(nil, []byte("com\norg\nnet\n"))
	require.NoError(t, err)

	mockDAO := mocks.NewMockZoneDAO()

	// Add an existing zone with the same name
	zoneName := "existing.com."
	existingZone := &entities.Zone{
		ID:   util.NewID([]byte(zoneName)),
		Name: zoneName,
		TTL:  3600,
	}
	mockDAO.AddZone(existingZone)

	svc := &Service{
		params: &Params{
			Config: &Config{
				AllowRegistration:         true,
				AllowExternalRegistration: true,
				Logger:                    logging.DefaultLogger(),
			},
		},
		zoneDAO: mockDAO,
	}

	ctx := context.Background()
	// This should fail because the zone already exists and doesn't match internal/public server zones
	_, err = svc.Register(ctx, "host.existing.com", "8.8.8.8")
	assert.ErrorIs(t, err, ErrZoneAlreadyExists)
}

// TestService_Register_WithSubdomains verifies registration with subdomains.
func TestService_Register_WithSubdomains(t *testing.T) {
	err := LoadTLDs(nil, []byte("com\norg\nnet\n"))
	require.NoError(t, err)

	mockDAO := mocks.NewMockZoneDAO()

	svc := &Service{
		params: &Params{
			Config: &Config{
				AllowRegistration:         true,
				AllowExternalRegistration: true,
				Logger:                    logging.DefaultLogger(),
			},
		},
		zoneDAO: mockDAO,
	}

	ctx := context.Background()
	_, err = svc.Register(ctx, "host.sub.domain.com", "8.8.8.8")
	require.NoError(t, err)

	// Verify zone was created with subdomain
	assert.Equal(t, 1, mockDAO.ZoneCount())
}

// TestService_Resolver_Dial verifies the resolver dial function.
func TestService_Resolver_Dial(t *testing.T) {
	svc := &Service{
		params: &Params{
			Config: &Config{
				InternalServer: &InternalServer{
					Port: 15353, // Use non-standard port
				},
			},
		},
	}

	resolver := svc.Resolver()
	require.NotNil(t, resolver)
	assert.True(t, resolver.PreferGo)

	// The Dial function exists but we can't easily test it without a running server
	// At least verify the resolver was created correctly
}

// TestServiceErrors verifies all error variables are properly defined.
func TestServiceErrors(t *testing.T) {
	errors := []error{
		ErrZoneAlreadyExists,
		ErrParsingDomainName,
		ErrInvalidIPAddress,
		ErrZoneNotFound,
		ErrInvalidPrivateIP,
		ErrInvalidPublicIP,
		ErrInvalidPrivateTLD,
		ErrInvalidPublicTLD,
		ErrRegistrationDisabled,
		ErrExternalRegistrationDisabled,
		ErrInternalRegistrationDisabled,
		ErrMissingTenantContext,
		ErrUnauthorizedZoneAccess,
	}

	for _, err := range errors {
		assert.NotNil(t, err)
		assert.NotEmpty(t, err.Error())
	}
}

// =============================================================================
// Tenant Authorization Tests
// =============================================================================

// TestService_TenantID verifies TenantID getter returns the correct value.
func TestService_TenantID(t *testing.T) {
	svc := &Service{
		params: &Params{
			TenantID: "test-tenant",
			Config:   &Config{},
		},
	}

	assert.Equal(t, "test-tenant", svc.TenantID())
}

// TestService_TenantID_Empty verifies empty TenantID is handled correctly.
func TestService_TenantID_Empty(t *testing.T) {
	svc := &Service{
		params: &Params{
			TenantID: "",
			Config:   &Config{},
		},
	}

	assert.Empty(t, svc.TenantID())
}

// TestService_AuthorizeZoneAccess_SameTenant verifies access is allowed for matching tenants.
func TestService_AuthorizeZoneAccess_SameTenant(t *testing.T) {
	svc := &Service{
		params: &Params{
			TenantID: "tenant-123",
			Config:   &Config{Logger: logging.DefaultLogger()},
		},
	}

	zone := &entities.Zone{
		ID:       1,
		Name:     "example.com.",
		TenantID: "tenant-123",
	}

	err := svc.authorizeZoneAccess(zone, "save")
	assert.NoError(t, err)
}

// TestService_AuthorizeZoneAccess_DifferentTenant verifies access is denied for different tenants.
func TestService_AuthorizeZoneAccess_DifferentTenant(t *testing.T) {
	svc := &Service{
		params: &Params{
			TenantID: "tenant-123",
			Config:   &Config{Logger: logging.DefaultLogger()},
		},
	}

	zone := &entities.Zone{
		ID:       1,
		Name:     "example.com.",
		TenantID: "tenant-456", // Different tenant
	}

	err := svc.authorizeZoneAccess(zone, "save")
	assert.ErrorIs(t, err, ErrUnauthorizedZoneAccess)
}

// TestService_AuthorizeZoneAccess_MissingTenantContext verifies error when service has no tenant.
func TestService_AuthorizeZoneAccess_MissingTenantContext(t *testing.T) {
	svc := &Service{
		params: &Params{
			TenantID: "", // No tenant
			Config:   &Config{Logger: logging.DefaultLogger()},
		},
	}

	zone := &entities.Zone{
		ID:       1,
		Name:     "example.com.",
		TenantID: "tenant-123",
	}

	err := svc.authorizeZoneAccess(zone, "save")
	assert.ErrorIs(t, err, ErrMissingTenantContext)
}

// TestService_EnsureZoneTenantID_SetsEmptyTenantID verifies TenantID is set on zones without one.
func TestService_EnsureZoneTenantID_SetsEmptyTenantID(t *testing.T) {
	svc := &Service{
		params: &Params{
			TenantID: "service-tenant",
			Config:   &Config{},
		},
	}

	zone := &entities.Zone{
		ID:       1,
		Name:     "example.com.",
		TenantID: "", // Empty tenant
	}

	err := svc.ensureZoneTenantID(zone)
	require.NoError(t, err)
	assert.Equal(t, "service-tenant", zone.TenantID)
}

// TestService_EnsureZoneTenantID_PreservesExistingTenantID verifies existing TenantID is not overwritten.
func TestService_EnsureZoneTenantID_PreservesExistingTenantID(t *testing.T) {
	svc := &Service{
		params: &Params{
			TenantID: "service-tenant",
			Config:   &Config{},
		},
	}

	zone := &entities.Zone{
		ID:       1,
		Name:     "example.com.",
		TenantID: "original-tenant", // Already has a tenant
	}

	err := svc.ensureZoneTenantID(zone)
	require.NoError(t, err)
	assert.Equal(t, "original-tenant", zone.TenantID) // Should be unchanged
}

// TestService_EnsureZoneTenantID_MissingServiceTenantID verifies error when service has no tenant.
func TestService_EnsureZoneTenantID_MissingServiceTenantID(t *testing.T) {
	svc := &Service{
		params: &Params{
			TenantID: "", // No tenant on service
			Config:   &Config{},
		},
	}

	zone := &entities.Zone{
		ID:       1,
		Name:     "example.com.",
		TenantID: "", // Empty tenant
	}

	err := svc.ensureZoneTenantID(zone)
	assert.ErrorIs(t, err, ErrMissingTenantContext)
}

// TestService_Save_SetsTenantID verifies Save sets TenantID on zones without one.
func TestService_Save_SetsTenantID(t *testing.T) {
	mockDAO := mocks.NewMockZoneDAO()

	var savedZone *entities.Zone
	mockDAO.SaveFunc = func(ctx context.Context, zone *entities.Zone) error {
		savedZone = zone
		return nil
	}

	svc := &Service{
		params: &Params{
			TenantID: "platform",
			Config:   &Config{},
		},
		zoneDAO: mockDAO,
	}

	ctx := context.Background()
	zone := &entities.Zone{
		ID:       1,
		Name:     "example.com.",
		TenantID: "", // No tenant
	}

	err := svc.Save(ctx, zone)
	require.NoError(t, err)
	assert.Equal(t, "platform", savedZone.TenantID)
}

// TestService_Save_DeniesUnauthorizedAccess verifies Save denies access to zones owned by other tenants.
func TestService_Save_DeniesUnauthorizedAccess(t *testing.T) {
	mockDAO := mocks.NewMockZoneDAO()

	svc := &Service{
		params: &Params{
			TenantID: "tenant-A",
			Config:   &Config{Logger: logging.DefaultLogger()},
		},
		zoneDAO: mockDAO,
	}

	ctx := context.Background()
	zone := &entities.Zone{
		ID:       1,
		Name:     "example.com.",
		TenantID: "tenant-B", // Different tenant owns this zone
	}

	err := svc.Save(ctx, zone)
	assert.ErrorIs(t, err, ErrUnauthorizedZoneAccess)
}

// TestService_SaveAndSign_AuthorizesAccess verifies SaveAndSign checks authorization.
func TestService_SaveAndSign_AuthorizesAccess(t *testing.T) {
	mockDAO := mocks.NewMockZoneDAO()

	svc := &Service{
		params: &Params{
			TenantID: "tenant-A",
			Config:   &Config{Logger: logging.DefaultLogger()},
		},
		zoneDAO: mockDAO,
	}

	ctx := context.Background()

	t.Run("allows same tenant", func(t *testing.T) {
		zone := &entities.Zone{
			ID:       1,
			Name:     "example.com.",
			TenantID: "tenant-A",
		}

		err := svc.SaveAndSign(ctx, zone)
		require.NoError(t, err)
	})

	t.Run("denies different tenant", func(t *testing.T) {
		zone := &entities.Zone{
			ID:       2,
			Name:     "other.com.",
			TenantID: "tenant-B",
		}

		err := svc.SaveAndSign(ctx, zone)
		assert.ErrorIs(t, err, ErrUnauthorizedZoneAccess)
	})
}

// TestService_Delete_AuthorizesAccess verifies Delete checks authorization.
func TestService_Delete_AuthorizesAccess(t *testing.T) {
	mockDAO := mocks.NewMockZoneDAO()
	mockDAO.DeleteFunc = func(ctx context.Context, zone *entities.Zone) error {
		return nil
	}

	svc := &Service{
		params: &Params{
			TenantID: "tenant-A",
			Config:   &Config{Logger: logging.DefaultLogger()},
		},
		zoneDAO: mockDAO,
	}

	ctx := context.Background()

	t.Run("allows same tenant", func(t *testing.T) {
		zone := &entities.Zone{
			ID:       1,
			Name:     "example.com.",
			TenantID: "tenant-A",
		}

		err := svc.Delete(ctx, zone)
		require.NoError(t, err)
	})

	t.Run("denies different tenant", func(t *testing.T) {
		zone := &entities.Zone{
			ID:       2,
			Name:     "other.com.",
			TenantID: "tenant-B",
		}

		err := svc.Delete(ctx, zone)
		assert.ErrorIs(t, err, ErrUnauthorizedZoneAccess)
	})
}

// TestService_SignZone_AuthorizesAccess verifies SignZone checks authorization.
func TestService_SignZone_AuthorizesAccess(t *testing.T) {
	svc := &Service{
		params: &Params{
			TenantID: "tenant-A",
			Config:   &Config{Logger: logging.DefaultLogger()},
		},
		dnssecSvc: nil, // DNSSEC not enabled
	}

	t.Run("returns DNSSEC not enabled without auth check", func(t *testing.T) {
		zone := &entities.Zone{
			ID:       1,
			Name:     "example.com.",
			TenantID: "tenant-B",
		}

		err := svc.SignZone(zone)
		// DNSSEC check happens before authorization
		assert.ErrorIs(t, err, ErrDNSSECNotEnabled)
	})
}

// TestService_CreateZone_SetsTenantID verifies CreateZone sets TenantID from service.
func TestService_CreateZone_SetsTenantID(t *testing.T) {
	mockDAO := mocks.NewMockZoneDAO()

	var savedZone *entities.Zone
	mockDAO.SaveFunc = func(ctx context.Context, zone *entities.Zone) error {
		savedZone = zone
		return nil
	}

	svc := &Service{
		params: &Params{
			TenantID: "platform-tenant",
			Config:   &Config{},
		},
		zoneDAO: mockDAO,
	}

	ctx := context.Background()
	err := svc.CreateZone(ctx, "newzone.com.")
	require.NoError(t, err)
	assert.Equal(t, "platform-tenant", savedZone.TenantID)
}

// TestService_DeleteZone_ChecksAuthorization verifies DeleteZone checks zone ownership.
func TestService_DeleteZone_ChecksAuthorization(t *testing.T) {
	mockDAO := mocks.NewMockZoneDAO()

	zoneName := "example.com."
	zoneID := util.NewID([]byte(zoneName))
	zone := &entities.Zone{
		ID:       zoneID,
		Name:     zoneName,
		TenantID: "tenant-B", // Different tenant
	}
	mockDAO.AddZone(zone)

	svc := &Service{
		params: &Params{
			TenantID: "tenant-A",
			Config:   &Config{Logger: logging.DefaultLogger()},
		},
		zoneDAO: mockDAO,
	}

	ctx := context.Background()
	err := svc.DeleteZone(ctx, zoneName)
	assert.ErrorIs(t, err, ErrUnauthorizedZoneAccess)
}

// TestService_AddRecord_ChecksAuthorization verifies AddRecord checks zone ownership.
func TestService_AddRecord_ChecksAuthorization(t *testing.T) {
	mockDAO := mocks.NewMockZoneDAO()

	zoneName := "example.com."
	zoneID := util.NewID([]byte(zoneName))
	zone := &entities.Zone{
		ID:       zoneID,
		Name:     zoneName,
		TenantID: "tenant-B", // Different tenant
	}
	mockDAO.AddZone(zone)

	svc := &Service{
		params: &Params{
			TenantID: "tenant-A",
			Config:   &Config{Logger: logging.DefaultLogger()},
		},
		zoneDAO: mockDAO,
	}

	ctx := context.Background()
	err := svc.AddRecord(ctx, "www.example.com", "A", "192.168.1.1", 3600)
	assert.ErrorIs(t, err, ErrUnauthorizedZoneAccess)
}

// TestService_DeleteRecord_ChecksAuthorization verifies DeleteRecord checks zone ownership.
func TestService_DeleteRecord_ChecksAuthorization(t *testing.T) {
	mockDAO := mocks.NewMockZoneDAO()

	zoneName := "example.com."
	zoneID := util.NewID([]byte(zoneName))
	zone := &entities.Zone{
		ID:       zoneID,
		Name:     zoneName,
		TenantID: "tenant-B", // Different tenant
		RecordSet: entities.RecordSet{
			ARecords: []*entities.ARecord{
				{Name: "www.example.com", Value: "192.168.1.1", TTL: 3600},
			},
		},
	}
	mockDAO.AddZone(zone)

	svc := &Service{
		params: &Params{
			TenantID: "tenant-A",
			Config:   &Config{Logger: logging.DefaultLogger()},
		},
		zoneDAO: mockDAO,
	}

	ctx := context.Background()
	err := svc.DeleteRecord(ctx, "www.example.com", "A")
	assert.ErrorIs(t, err, ErrUnauthorizedZoneAccess)
}

// TestService_TenantIsolation_MultipleZones verifies tenants can only access their own zones.
func TestService_TenantIsolation_MultipleZones(t *testing.T) {
	mockDAO := mocks.NewMockZoneDAO()

	// Create zones for different tenants
	zone1 := &entities.Zone{
		ID:       util.NewID([]byte("tenant-a.com.")),
		Name:     "tenant-a.com.",
		TenantID: "tenant-A",
	}
	zone2 := &entities.Zone{
		ID:       util.NewID([]byte("tenant-b.com.")),
		Name:     "tenant-b.com.",
		TenantID: "tenant-B",
	}
	mockDAO.AddZone(zone1)
	mockDAO.AddZone(zone2)

	svc := &Service{
		params: &Params{
			TenantID: "tenant-A",
			Config:   &Config{Logger: logging.DefaultLogger()},
		},
		zoneDAO: mockDAO,
	}

	ctx := context.Background()

	// Tenant A can access their zone
	err := svc.Delete(ctx, zone1)
	assert.NoError(t, err)

	// Tenant A cannot access Tenant B's zone
	err = svc.Delete(ctx, zone2)
	assert.ErrorIs(t, err, ErrUnauthorizedZoneAccess)
}
