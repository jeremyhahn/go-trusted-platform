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
	"net"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseQueriedRecord_ARecord(t *testing.T) {
	zone := &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			ARecords: []*entities.ARecord{
				{Name: "www", Value: "192.168.1.1", TTL: 3600},
				{Name: "mail", Value: "192.168.1.2", TTL: 7200},
			},
		},
	}

	rrs, err := parseQueriedRecord(dns.TypeA, "www.example.com.", zone)
	require.NoError(t, err)
	require.Len(t, rrs, 1)

	aRecord := rrs[0].(*dns.A)
	assert.Equal(t, "www.example.com.", aRecord.Hdr.Name)
	assert.Equal(t, uint32(3600), aRecord.Hdr.Ttl)
	assert.True(t, aRecord.A.Equal(net.ParseIP("192.168.1.1")))
}

// TestParseQueriedRecord_ARecord_ApexQuery tests A record lookup at zone apex.
func TestParseQueriedRecord_ARecord_ApexQuery(t *testing.T) {
	zone := &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			ARecords: []*entities.ARecord{
				{Name: "@", Value: "192.168.1.1", TTL: 3600},
				{Name: "www", Value: "192.168.1.2", TTL: 3600},
			},
		},
	}

	rrs, err := parseQueriedRecord(dns.TypeA, "example.com.", zone)
	require.NoError(t, err)
	require.Len(t, rrs, 1)

	aRecord := rrs[0].(*dns.A)
	assert.Equal(t, "example.com.", aRecord.Hdr.Name)
	assert.True(t, aRecord.A.Equal(net.ParseIP("192.168.1.1")))
}

func TestParseQueriedRecord_AAAARecord(t *testing.T) {
	zone := &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			AAAARecords: []*entities.AAAARecord{
				{Name: "www", Value: "2001:db8::1", TTL: 3600},
			},
		},
	}

	rrs, err := parseQueriedRecord(dns.TypeAAAA, "www.example.com.", zone)
	require.NoError(t, err)
	require.Len(t, rrs, 1)

	aaaaRecord := rrs[0].(*dns.AAAA)
	assert.Equal(t, "www.example.com.", aaaaRecord.Hdr.Name)
	assert.True(t, aaaaRecord.AAAA.Equal(net.ParseIP("2001:db8::1")))
}

// TestParseQueriedRecord_AAAARecord_ApexQuery tests AAAA record lookup at zone apex.
func TestParseQueriedRecord_AAAARecord_ApexQuery(t *testing.T) {
	zone := &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			AAAARecords: []*entities.AAAARecord{
				{Name: "@", Value: "2001:db8::1", TTL: 3600},
			},
		},
	}

	rrs, err := parseQueriedRecord(dns.TypeAAAA, "example.com.", zone)
	require.NoError(t, err)
	require.Len(t, rrs, 1)

	aaaaRecord := rrs[0].(*dns.AAAA)
	assert.Equal(t, "example.com.", aaaaRecord.Hdr.Name)
	assert.True(t, aaaaRecord.AAAA.Equal(net.ParseIP("2001:db8::1")))
}

func TestParseQueriedRecord_MXRecord(t *testing.T) {
	zone := &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			MXRecords: []*entities.MXRecord{
				{Name: "example.com.", Value: "mail.example.com.", Priority: 10, TTL: 3600},
				{Name: "example.com.", Value: "mail2.example.com.", Priority: 20, TTL: 3600},
			},
		},
	}

	rrs, err := parseQueriedRecord(dns.TypeMX, "example.com.", zone)
	require.NoError(t, err)
	require.Len(t, rrs, 2)

	mxRecord := rrs[0].(*dns.MX)
	assert.Equal(t, "example.com.", mxRecord.Hdr.Name)
	assert.Equal(t, uint16(10), mxRecord.Preference)
	assert.Equal(t, "mail.example.com.", mxRecord.Mx)
}

func TestParseQueriedRecord_CNAMERecord(t *testing.T) {
	zone := &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			CNAMERecords: []*entities.CNAMERecord{
				{Name: "www", Value: "example.com.", TTL: 3600},
			},
		},
	}

	rrs, err := parseQueriedRecord(dns.TypeCNAME, "www.example.com.", zone)
	require.NoError(t, err)
	require.Len(t, rrs, 1)

	cnameRecord := rrs[0].(*dns.CNAME)
	assert.Equal(t, "www.example.com.", cnameRecord.Hdr.Name)
	assert.Equal(t, "example.com.", cnameRecord.Target)
}

func TestParseQueriedRecord_NSRecord(t *testing.T) {
	zone := &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			NSRecords: []*entities.NSRecord{
				{Name: "example.com.", Value: "ns1.example.com.", TTL: 3600},
				{Name: "example.com.", Value: "ns2.example.com.", TTL: 3600},
			},
		},
	}

	rrs, err := parseQueriedRecord(dns.TypeNS, "example.com.", zone)
	require.NoError(t, err)
	require.Len(t, rrs, 2)

	nsRecord := rrs[0].(*dns.NS)
	assert.Equal(t, "example.com.", nsRecord.Hdr.Name)
	assert.Equal(t, "ns1.example.com.", nsRecord.Ns)
}

func TestParseQueriedRecord_SOARecord(t *testing.T) {
	zone := &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			SOARecord: entities.SOARecord{
				Name:       "example.com.",
				MName:      "ns1.example.com.",
				RName:      "admin.example.com.",
				Serial:     2024010101,
				Refresh:    3600,
				Retry:      600,
				Expire:     86400,
				MinimumTTL: 300,
				TTL:        3600,
			},
		},
	}

	rrs, err := parseQueriedRecord(dns.TypeSOA, "example.com.", zone)
	require.NoError(t, err)
	require.Len(t, rrs, 1)

	soaRecord := rrs[0].(*dns.SOA)
	assert.Equal(t, "example.com.", soaRecord.Hdr.Name)
	assert.Equal(t, "ns1.example.com.", soaRecord.Ns)
	assert.Equal(t, "admin.example.com.", soaRecord.Mbox)
	assert.Equal(t, uint32(2024010101), soaRecord.Serial)
	assert.Equal(t, uint32(3600), soaRecord.Refresh)
	assert.Equal(t, uint32(600), soaRecord.Retry)
	assert.Equal(t, uint32(86400), soaRecord.Expire)
	assert.Equal(t, uint32(300), soaRecord.Minttl)
}

func TestParseQueriedRecord_TXTRecord(t *testing.T) {
	zone := &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			TXTRecords: []*entities.TXTRecord{
				{Name: "example.com.", Value: "v=spf1 include:_spf.example.com ~all", TTL: 3600},
			},
		},
	}

	rrs, err := parseQueriedRecord(dns.TypeTXT, "example.com.", zone)
	require.NoError(t, err)
	require.Len(t, rrs, 1)

	txtRecord := rrs[0].(*dns.TXT)
	assert.Equal(t, "example.com.", txtRecord.Hdr.Name)
	assert.Equal(t, []string{"v=spf1 include:_spf.example.com ~all"}, txtRecord.Txt)
}

// TestParseQueriedRecord_TXTRecord_NoMatch tests TXT record query with no matching record.
func TestParseQueriedRecord_TXTRecord_NoMatch(t *testing.T) {
	zone := &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			TXTRecords: []*entities.TXTRecord{
				{Name: "_dmarc.example.com.", Value: "v=DMARC1; p=none", TTL: 3600},
			},
		},
	}

	rrs, err := parseQueriedRecord(dns.TypeTXT, "example.com.", zone)
	require.NoError(t, err)
	assert.Len(t, rrs, 0)
}

func TestParseQueriedRecord_SRVRecord(t *testing.T) {
	zone := &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			SRVRecords: []*entities.SRVRecord{
				{
					Name:     "_http._tcp.example.com.",
					Target:   "server.example.com.",
					Port:     80,
					Priority: 10,
					Weight:   5,
					TTL:      3600,
				},
			},
		},
	}

	rrs, err := parseQueriedRecord(dns.TypeSRV, "_http._tcp.example.com.", zone)
	require.NoError(t, err)
	require.Len(t, rrs, 1)

	srvRecord := rrs[0].(*dns.SRV)
	assert.Equal(t, "_http._tcp.example.com.", srvRecord.Hdr.Name)
	assert.Equal(t, "server.example.com.", srvRecord.Target)
	assert.Equal(t, uint16(80), srvRecord.Port)
	assert.Equal(t, uint16(10), srvRecord.Priority)
	assert.Equal(t, uint16(5), srvRecord.Weight)
}

func TestParseQueriedRecord_CAARecord(t *testing.T) {
	zone := &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			CAARecords: []*entities.CAARecord{
				{Name: "example.com.", Flags: 0, Tag: "issue", Value: "letsencrypt.org", TTL: 3600},
				{Name: "example.com.", Flags: 0, Tag: "issuewild", Value: "letsencrypt.org", TTL: 3600},
				{Name: "example.com.", Flags: 128, Tag: "iodef", Value: "mailto:security@example.com", TTL: 3600},
			},
		},
	}

	rrs, err := parseQueriedRecord(dns.TypeCAA, "example.com.", zone)
	require.NoError(t, err)
	require.Len(t, rrs, 3)

	// Check first record (issue)
	caa0 := rrs[0].(*dns.CAA)
	assert.Equal(t, "example.com.", caa0.Hdr.Name)
	assert.Equal(t, dns.TypeCAA, caa0.Hdr.Rrtype)
	assert.Equal(t, uint32(3600), caa0.Hdr.Ttl)
	assert.Equal(t, uint8(0), caa0.Flag)
	assert.Equal(t, "issue", caa0.Tag)
	assert.Equal(t, "letsencrypt.org", caa0.Value)

	// Check second record (issuewild)
	caa1 := rrs[1].(*dns.CAA)
	assert.Equal(t, "issuewild", caa1.Tag)

	// Check third record (critical iodef)
	caa2 := rrs[2].(*dns.CAA)
	assert.Equal(t, uint8(128), caa2.Flag)
	assert.Equal(t, "iodef", caa2.Tag)
	assert.Equal(t, "mailto:security@example.com", caa2.Value)
}

func TestParseQueriedRecord_CAARecord_Empty(t *testing.T) {
	zone := &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			CAARecords: []*entities.CAARecord{},
		},
	}

	rrs, err := parseQueriedRecord(dns.TypeCAA, "example.com.", zone)
	require.NoError(t, err)
	require.Len(t, rrs, 0)
}

func TestParseQueriedRecord_TLSARecord(t *testing.T) {
	zone := &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			TLSARecords: []*entities.TLSARecord{
				{
					Name:         "_443._tcp.www.example.com.",
					Usage:        3,
					Selector:     1,
					MatchingType: 1,
					Data:         "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
					TTL:          3600,
				},
			},
		},
	}

	rrs, err := parseQueriedRecord(dns.TypeTLSA, "_443._tcp.www.example.com.", zone)
	require.NoError(t, err)
	require.Len(t, rrs, 1)

	tlsa := rrs[0].(*dns.TLSA)
	assert.Equal(t, "_443._tcp.www.example.com.", tlsa.Hdr.Name)
	assert.Equal(t, dns.TypeTLSA, tlsa.Hdr.Rrtype)
	assert.Equal(t, uint32(3600), tlsa.Hdr.Ttl)
	assert.Equal(t, uint8(3), tlsa.Usage)
	assert.Equal(t, uint8(1), tlsa.Selector)
	assert.Equal(t, uint8(1), tlsa.MatchingType)
	assert.Equal(t, "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2", tlsa.Certificate)
}

func TestParseQueriedRecord_TLSARecord_MultipleUsageTypes(t *testing.T) {
	zone := &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			TLSARecords: []*entities.TLSARecord{
				{Name: "_443._tcp.www.example.com.", Usage: 0, Selector: 0, MatchingType: 0, Data: "full-cert-data", TTL: 3600},
				{Name: "_443._tcp.www.example.com.", Usage: 1, Selector: 1, MatchingType: 1, Data: "sha256-hash", TTL: 3600},
				{Name: "_443._tcp.www.example.com.", Usage: 2, Selector: 0, MatchingType: 2, Data: "sha512-hash", TTL: 3600},
				{Name: "_443._tcp.www.example.com.", Usage: 3, Selector: 1, MatchingType: 1, Data: "dane-ee-hash", TTL: 3600},
			},
		},
	}

	rrs, err := parseQueriedRecord(dns.TypeTLSA, "_443._tcp.www.example.com.", zone)
	require.NoError(t, err)
	require.Len(t, rrs, 4)

	// Verify usage types
	assert.Equal(t, uint8(0), rrs[0].(*dns.TLSA).Usage) // PKIX-TA
	assert.Equal(t, uint8(1), rrs[1].(*dns.TLSA).Usage) // PKIX-EE
	assert.Equal(t, uint8(2), rrs[2].(*dns.TLSA).Usage) // DANE-TA
	assert.Equal(t, uint8(3), rrs[3].(*dns.TLSA).Usage) // DANE-EE
}

func TestParseQueriedRecord_UnsupportedType(t *testing.T) {
	zone := &entities.Zone{Name: "example.com."}

	_, err := parseQueriedRecord(dns.TypePTR, "example.com.", zone)
	assert.ErrorIs(t, err, ErrRecordTypeNotSupported)
}

func TestParseQueriedRecord_NoMatchingRecords(t *testing.T) {
	zone := &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			ARecords: []*entities.ARecord{
				{Name: "www", Value: "192.168.1.1", TTL: 3600},
			},
		},
	}

	rrs, err := parseQueriedRecord(dns.TypeA, "nonexistent.example.com.", zone)
	require.NoError(t, err)
	assert.Len(t, rrs, 0)
}

// TestParseQueriedRecord_DNSKEYRecord tests DNSKEY record parsing.
func TestParseQueriedRecord_DNSKEYRecord(t *testing.T) {
	zone := &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			DNSKEYRecords: []*entities.DNSKEYRecord{
				{
					Name:      "example.com.",
					TTL:       3600,
					Flags:     257, // KSK
					Protocol:  3,
					Algorithm: 13, // ECDSAP256SHA256
					Key:       "base64encodedkey",
				},
				{
					Name:      "example.com.",
					TTL:       3600,
					Flags:     256, // ZSK
					Protocol:  3,
					Algorithm: 13,
					Key:       "anotherbase64key",
				},
			},
		},
	}

	rrs, err := parseQueriedRecord(dns.TypeDNSKEY, "example.com.", zone)
	require.NoError(t, err)
	require.Len(t, rrs, 2)

	// Check KSK
	dnskey0 := rrs[0].(*dns.DNSKEY)
	assert.Equal(t, "example.com.", dnskey0.Hdr.Name)
	assert.Equal(t, dns.TypeDNSKEY, dnskey0.Hdr.Rrtype)
	assert.Equal(t, uint16(257), dnskey0.Flags)
	assert.Equal(t, uint8(3), dnskey0.Protocol)
	assert.Equal(t, uint8(13), dnskey0.Algorithm)
	assert.Equal(t, "base64encodedkey", dnskey0.PublicKey)

	// Check ZSK
	dnskey1 := rrs[1].(*dns.DNSKEY)
	assert.Equal(t, uint16(256), dnskey1.Flags)
}

// TestParseQueriedRecord_DNSKEYRecord_Nil tests DNSKEY record when nil.
func TestParseQueriedRecord_DNSKEYRecord_Nil(t *testing.T) {
	zone := &entities.Zone{
		Name:      "example.com.",
		RecordSet: entities.RecordSet{},
	}

	rrs, err := parseQueriedRecord(dns.TypeDNSKEY, "example.com.", zone)
	require.NoError(t, err)
	assert.Nil(t, rrs)
}

// TestParseQueriedRecord_DSRecord tests DS record parsing.
func TestParseQueriedRecord_DSRecord(t *testing.T) {
	zone := &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			DSRecords: []*entities.DSRecord{
				{
					Name:       "sub.example.com.",
					TTL:        3600,
					KeyTag:     12345,
					Algorithm:  13,
					DigestType: 2, // SHA-256
					Digest:     "abc123def456",
				},
			},
		},
	}

	rrs, err := parseQueriedRecord(dns.TypeDS, "sub.example.com.", zone)
	require.NoError(t, err)
	require.Len(t, rrs, 1)

	dsRecord := rrs[0].(*dns.DS)
	assert.Equal(t, "sub.example.com.", dsRecord.Hdr.Name)
	assert.Equal(t, dns.TypeDS, dsRecord.Hdr.Rrtype)
	assert.Equal(t, uint16(12345), dsRecord.KeyTag)
	assert.Equal(t, uint8(13), dsRecord.Algorithm)
	assert.Equal(t, uint8(2), dsRecord.DigestType)
	assert.Equal(t, "abc123def456", dsRecord.Digest)
}

// TestParseQueriedRecord_DSRecord_Nil tests DS record when nil.
func TestParseQueriedRecord_DSRecord_Nil(t *testing.T) {
	zone := &entities.Zone{
		Name:      "example.com.",
		RecordSet: entities.RecordSet{},
	}

	rrs, err := parseQueriedRecord(dns.TypeDS, "example.com.", zone)
	require.NoError(t, err)
	assert.Nil(t, rrs)
}

// TestParseQueriedRecord_RRSIGRecord tests RRSIG record parsing.
func TestParseQueriedRecord_RRSIGRecord(t *testing.T) {
	zone := &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			RRSIGRecords: []*entities.RRSIGRecord{
				{
					TypeCovered: "A",
					Algorithm:   13,
					Labels:      2,
					OriginalTTL: 3600,
					Expiration:  "20260101000000",
					Inception:   "20250101000000",
					KeyTag:      12345,
					SignerName:  "example.com.",
					Signature:   "base64signature",
				},
			},
		},
	}

	rrs, err := parseQueriedRecord(dns.TypeRRSIG, "example.com.", zone)
	require.NoError(t, err)
	require.Len(t, rrs, 1)

	rrsigRecord := rrs[0].(*dns.RRSIG)
	assert.Equal(t, "example.com.", rrsigRecord.Hdr.Name)
	assert.Equal(t, dns.TypeRRSIG, rrsigRecord.Hdr.Rrtype)
	assert.Equal(t, dns.TypeA, rrsigRecord.TypeCovered)
	assert.Equal(t, uint8(13), rrsigRecord.Algorithm)
	assert.Equal(t, uint8(2), rrsigRecord.Labels)
	assert.Equal(t, uint32(3600), rrsigRecord.OrigTtl)
	assert.Equal(t, uint16(12345), rrsigRecord.KeyTag)
	assert.Equal(t, "example.com.", rrsigRecord.SignerName)
	assert.Equal(t, "base64signature", rrsigRecord.Signature)
}

// TestParseQueriedRecord_RRSIGRecord_Nil tests RRSIG record when nil.
func TestParseQueriedRecord_RRSIGRecord_Nil(t *testing.T) {
	zone := &entities.Zone{
		Name:      "example.com.",
		RecordSet: entities.RecordSet{},
	}

	rrs, err := parseQueriedRecord(dns.TypeRRSIG, "example.com.", zone)
	require.NoError(t, err)
	assert.Nil(t, rrs)
}

// TestParseQueriedRecord_NSECRecord tests NSEC record parsing.
func TestParseQueriedRecord_NSECRecord(t *testing.T) {
	zone := &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			NSECRecords: []*entities.NSECRecord{
				{
					Name:       "example.com.",
					TTL:        3600,
					NextDomain: "www.example.com.",
					TypeBitMap: []uint16{dns.TypeA, dns.TypeNS, dns.TypeSOA, dns.TypeMX},
				},
			},
		},
	}

	rrs, err := parseQueriedRecord(dns.TypeNSEC, "example.com.", zone)
	require.NoError(t, err)
	require.Len(t, rrs, 1)

	nsecRecord := rrs[0].(*dns.NSEC)
	assert.Equal(t, "example.com.", nsecRecord.Hdr.Name)
	assert.Equal(t, dns.TypeNSEC, nsecRecord.Hdr.Rrtype)
	assert.Equal(t, "www.example.com.", nsecRecord.NextDomain)
	assert.Equal(t, []uint16{dns.TypeA, dns.TypeNS, dns.TypeSOA, dns.TypeMX}, nsecRecord.TypeBitMap)
}

// TestParseQueriedRecord_NSECRecord_Nil tests NSEC record when nil.
func TestParseQueriedRecord_NSECRecord_Nil(t *testing.T) {
	zone := &entities.Zone{
		Name:      "example.com.",
		RecordSet: entities.RecordSet{},
	}

	rrs, err := parseQueriedRecord(dns.TypeNSEC, "example.com.", zone)
	require.NoError(t, err)
	assert.Nil(t, rrs)
}

// TestParseQueriedRecord_NSEC3Record tests NSEC3 record parsing.
func TestParseQueriedRecord_NSEC3Record(t *testing.T) {
	zone := &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			NSEC3Records: []*entities.NSEC3Record{
				{
					Name:       "abc123.example.com.",
					TTL:        3600,
					Algorithm:  1,  // SHA-1
					Flags:      0,  // Not opt-out
					Iterations: 10, // Number of iterations
					Salt:       "aabbccdd",
					NextHashed: "def456ghi789",
					TypeBitMap: []uint16{dns.TypeA, dns.TypeAAAA},
				},
			},
		},
	}

	rrs, err := parseQueriedRecord(dns.TypeNSEC3, "abc123.example.com.", zone)
	require.NoError(t, err)
	require.Len(t, rrs, 1)

	nsec3Record := rrs[0].(*dns.NSEC3)
	assert.Equal(t, "abc123.example.com.", nsec3Record.Hdr.Name)
	assert.Equal(t, dns.TypeNSEC3, nsec3Record.Hdr.Rrtype)
	assert.Equal(t, uint8(1), nsec3Record.Hash)
	assert.Equal(t, uint8(0), nsec3Record.Flags)
	assert.Equal(t, uint16(10), nsec3Record.Iterations)
	assert.Equal(t, "aabbccdd", nsec3Record.Salt)
	assert.Equal(t, "def456ghi789", nsec3Record.NextDomain)
	assert.Equal(t, []uint16{dns.TypeA, dns.TypeAAAA}, nsec3Record.TypeBitMap)
}

// TestParseQueriedRecord_NSEC3Record_Nil tests NSEC3 record when nil.
func TestParseQueriedRecord_NSEC3Record_Nil(t *testing.T) {
	zone := &entities.Zone{
		Name:      "example.com.",
		RecordSet: entities.RecordSet{},
	}

	rrs, err := parseQueriedRecord(dns.TypeNSEC3, "example.com.", zone)
	require.NoError(t, err)
	assert.Nil(t, rrs)
}

// TestParseQueriedRecord_NSEC3PARAMRecord tests NSEC3PARAM record parsing.
func TestParseQueriedRecord_NSEC3PARAMRecord(t *testing.T) {
	zone := &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			NSEC3PARAMRecords: []*entities.NSEC3PARAMRecord{
				{
					Name:       "example.com.",
					TTL:        0, // NSEC3PARAM usually has TTL of 0
					Algorithm:  1,
					Flags:      0,
					Iterations: 10,
					Salt:       "aabbccdd",
				},
			},
		},
	}

	rrs, err := parseQueriedRecord(dns.TypeNSEC3PARAM, "example.com.", zone)
	require.NoError(t, err)
	require.Len(t, rrs, 1)

	nsec3paramRecord := rrs[0].(*dns.NSEC3PARAM)
	assert.Equal(t, "example.com.", nsec3paramRecord.Hdr.Name)
	assert.Equal(t, dns.TypeNSEC3PARAM, nsec3paramRecord.Hdr.Rrtype)
	assert.Equal(t, uint8(1), nsec3paramRecord.Hash)
	assert.Equal(t, uint8(0), nsec3paramRecord.Flags)
	assert.Equal(t, uint16(10), nsec3paramRecord.Iterations)
	assert.Equal(t, "aabbccdd", nsec3paramRecord.Salt)
}

// TestParseQueriedRecord_NSEC3PARAMRecord_Nil tests NSEC3PARAM record when nil.
func TestParseQueriedRecord_NSEC3PARAMRecord_Nil(t *testing.T) {
	zone := &entities.Zone{
		Name:      "example.com.",
		RecordSet: entities.RecordSet{},
	}

	rrs, err := parseQueriedRecord(dns.TypeNSEC3PARAM, "example.com.", zone)
	require.NoError(t, err)
	assert.Nil(t, rrs)
}

// TestParseRRSIGTimestamp tests the RRSIG timestamp parsing function.
func TestParseRRSIGTimestamp(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected uint32
	}{
		{
			name:     "empty string",
			input:    "",
			expected: 0,
		},
		{
			name:     "Unix timestamp",
			input:    "1704067200", // 2024-01-01 00:00:00 UTC
			expected: 1704067200,
		},
		{
			name:     "DNSSEC timestamp format",
			input:    "20240101000000",
			expected: 1704067200,
		},
		{
			name:     "DNSSEC timestamp future",
			input:    "20260701120000",
			expected: 1782907200,
		},
		{
			name:     "Invalid timestamp format",
			input:    "invalid",
			expected: 0,
		},
		{
			name:     "Partial timestamp",
			input:    "20240101",
			expected: 20240101, // 8 chars, treated as Unix timestamp
		},
		{
			name:     "Large Unix timestamp",
			input:    "2147483647", // Max int32
			expected: 2147483647,
		},
		{
			name:     "Small Unix timestamp",
			input:    "1",
			expected: 1,
		},
		{
			name:     "Zero Unix timestamp",
			input:    "0",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseRRSIGTimestamp(tt.input)
			assert.Equal(t, tt.expected, result, "parseRRSIGTimestamp(%q) = %d, want %d", tt.input, result, tt.expected)
		})
	}
}

// TestParseRRSIGTimestamp_EdgeCases tests edge cases for RRSIG timestamp parsing.
func TestParseRRSIGTimestamp_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected uint32
	}{
		{
			name:     "10 digit number as unix timestamp",
			input:    "1234567890",
			expected: 1234567890,
		},
		{
			name:     "11 digit number treated as DNSSEC format but invalid",
			input:    "12345678901",
			expected: 0, // Invalid DNSSEC format
		},
		{
			name:     "DNSSEC format at year 2000",
			input:    "20000101000000",
			expected: 946684800,
		},
		{
			name:     "DNSSEC format at year 2099",
			input:    "20991231235959",
			expected: 4102444799,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseRRSIGTimestamp(tt.input)
			assert.Equal(t, tt.expected, result, "parseRRSIGTimestamp(%q) = %d, want %d", tt.input, result, tt.expected)
		})
	}
}

// TestParseQueriedRecord_RRSIGRecord_UnixTimestamp tests RRSIG with Unix timestamps.
func TestParseQueriedRecord_RRSIGRecord_UnixTimestamp(t *testing.T) {
	zone := &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			RRSIGRecords: []*entities.RRSIGRecord{
				{
					TypeCovered: "AAAA",
					Algorithm:   8,
					Labels:      3,
					OriginalTTL: 7200,
					Expiration:  "1767225600", // Unix timestamp
					Inception:   "1704067200", // Unix timestamp
					KeyTag:      54321,
					SignerName:  "example.com.",
					Signature:   "signaturedata",
				},
			},
		},
	}

	rrs, err := parseQueriedRecord(dns.TypeRRSIG, "example.com.", zone)
	require.NoError(t, err)
	require.Len(t, rrs, 1)

	rrsigRecord := rrs[0].(*dns.RRSIG)
	assert.Equal(t, uint32(1767225600), rrsigRecord.Expiration)
	assert.Equal(t, uint32(1704067200), rrsigRecord.Inception)
}

func TestParseDomainName(t *testing.T) {
	tests := []struct {
		name           string
		fqdn           string
		wantHostname   string
		wantSubdomains string
		wantRootDomain string
		wantTLD        string
		wantErr        bool
	}{
		{
			name:           "Simple domain",
			fqdn:           "example.com",
			wantHostname:   "",
			wantSubdomains: "",
			wantRootDomain: "example.com",
			wantTLD:        "com",
			wantErr:        false,
		},
		{
			name:           "Domain with trailing dot",
			fqdn:           "example.com.",
			wantHostname:   "",
			wantSubdomains: "",
			wantRootDomain: "example.com",
			wantTLD:        "com",
			wantErr:        false,
		},
		{
			name:           "Subdomain",
			fqdn:           "www.example.com",
			wantHostname:   "www",
			wantSubdomains: "",
			wantRootDomain: "example.com",
			wantTLD:        "com",
			wantErr:        false,
		},
		{
			name:           "Multiple subdomains",
			fqdn:           "mail.server.example.com",
			wantHostname:   "mail",
			wantSubdomains: "server",
			wantRootDomain: "example.com",
			wantTLD:        "com",
			wantErr:        false,
		},
		{
			name:           "Co.uk TLD",
			fqdn:           "www.example.co.uk",
			wantHostname:   "www",
			wantSubdomains: "",
			wantRootDomain: "example.co.uk",
			wantTLD:        "co.uk",
			wantErr:        false,
		},
		{
			name:    "Invalid - single label",
			fqdn:    "localhost",
			wantErr: true,
		},
		{
			name:    "Invalid - empty",
			fqdn:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hostname, subdomains, rootDomain, tld, err := ParseDomainName(tt.fqdn)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantHostname, hostname, "hostname mismatch")
			assert.Equal(t, tt.wantSubdomains, subdomains, "subdomains mismatch")
			assert.Equal(t, tt.wantRootDomain, rootDomain, "rootDomain mismatch")
			assert.Equal(t, tt.wantTLD, tld, "tld mismatch")
		})
	}
}

func TestValidateQuery(t *testing.T) {
	tests := []struct {
		name    string
		query   string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "Valid simple domain",
			query:   "example.com",
			wantErr: false,
		},
		{
			name:    "Valid with subdomain",
			query:   "www.example.com",
			wantErr: false,
		},
		{
			name:    "Valid with trailing dot",
			query:   "example.com.",
			wantErr: false,
		},
		{
			name:    "Valid with hyphens",
			query:   "my-domain.example.com",
			wantErr: false,
		},
		{
			name:    "Valid max label length",
			query:   "a12345678901234567890123456789012345678901234567890123456789012.com",
			wantErr: false,
		},
		{
			name:    "Empty query",
			query:   "",
			wantErr: true,
			errMsg:  "empty",
		},
		{
			name:    "Too long domain",
			query:   "a." + string(make([]byte, 255)) + ".com",
			wantErr: true,
			errMsg:  "exceeds maximum domain length",
		},
		{
			name:    "Label too long",
			query:   "a1234567890123456789012345678901234567890123456789012345678901234.com",
			wantErr: true,
			errMsg:  "exceeding 63 characters",
		},
		{
			name:    "Invalid characters",
			query:   "example@invalid.com",
			wantErr: true,
			errMsg:  "invalid label",
		},
		{
			name:    "Leading hyphen",
			query:   "-invalid.com",
			wantErr: true,
			errMsg:  "invalid label",
		},
		{
			name:    "Trailing hyphen",
			query:   "invalid-.com",
			wantErr: true,
			errMsg:  "invalid label",
		},
		{
			name:    "Empty label",
			query:   "example..com",
			wantErr: true,
			errMsg:  "empty label",
		},
		{
			name:    "IPv4 address",
			query:   "192.168.1.1",
			wantErr: true,
			errMsg:  "IP address",
		},
		{
			name:    "IPv6 address",
			query:   "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			wantErr: true,
			errMsg:  "invalid label",
		},
		// RFC 8552: underscore-prefixed labels for scoped DNS records
		{
			name:    "Valid TLSA record name",
			query:   "_8443._tcp.server.example.com",
			wantErr: false,
		},
		{
			name:    "Valid TLSA record name with trailing dot",
			query:   "_8443._tcp.server.example.com.",
			wantErr: false,
		},
		{
			name:    "Valid SRV record name",
			query:   "_sip._tcp.example.com",
			wantErr: false,
		},
		{
			name:    "Valid DKIM record name",
			query:   "_dkim.example.com",
			wantErr: false,
		},
		{
			name:    "Valid underscore-only label",
			query:   "_tcp.example.com",
			wantErr: false,
		},
		{
			name:    "Valid port-based TLSA",
			query:   "_443._tcp.www.example.com",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateQuery(tt.query)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestIsIPAddress(t *testing.T) {
	tests := []struct {
		name  string
		query string
		want  bool
	}{
		{
			name:  "Valid IPv4",
			query: "192.168.1.1",
			want:  true,
		},
		{
			name:  "Valid IPv4 - edge case",
			query: "255.255.255.255",
			want:  true,
		},
		{
			name:  "Valid IPv6",
			query: "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			want:  true,
		},
		{
			name:  "Not an IP - domain",
			query: "example.com",
			want:  false,
		},
		{
			name:  "Not an IP - invalid IPv4",
			query: "256.256.256.256",
			want:  true, // Regex matches format but invalid values
		},
		{
			name:  "Not an IP - partial IPv4",
			query: "192.168.1",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isIPAddress(tt.query)
			assert.Equal(t, tt.want, result)
		})
	}
}

// TestValidateQuery_WhitespaceHandling tests whitespace handling in query validation.
func TestValidateQuery_WhitespaceHandling(t *testing.T) {
	tests := []struct {
		name    string
		query   string
		wantErr bool
	}{
		{
			name:    "Leading whitespace",
			query:   "  example.com",
			wantErr: false,
		},
		{
			name:    "Trailing whitespace",
			query:   "example.com  ",
			wantErr: false,
		},
		{
			name:    "Both whitespace",
			query:   "  example.com  ",
			wantErr: false,
		},
		{
			name:    "Only whitespace",
			query:   "   ",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateQuery(tt.query)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateQuery_SingleCharLabel tests single character labels.
func TestValidateQuery_SingleCharLabel(t *testing.T) {
	tests := []struct {
		name    string
		query   string
		wantErr bool
	}{
		{
			name:    "Single char domain label",
			query:   "a.com",
			wantErr: false,
		},
		{
			name:    "Single char subdomain",
			query:   "a.b.com",
			wantErr: false,
		},
		{
			name:    "Numeric single char",
			query:   "1.com",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateQuery(tt.query)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// zoneWithOwner builds a zone holding exactly one record of every
// owner-matched type, all owned by the same name, so the whole dispatch table
// can be exercised against one query.
func zoneWithOwner(owner string) *entities.Zone {
	return &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			ARecords:          []*entities.ARecord{{Name: owner, Value: "192.0.2.1", TTL: 3600}},
			AAAARecords:       []*entities.AAAARecord{{Name: owner, Value: "2001:db8::1", TTL: 3600}},
			CNAMERecords:      []*entities.CNAMERecord{{Name: owner, Value: "target.example.com.", TTL: 3600}},
			MXRecords:         []*entities.MXRecord{{Name: owner, Value: "mail.example.com.", Priority: 10, TTL: 3600}},
			NSRecords:         []*entities.NSRecord{{Name: owner, Value: "ns1.example.com.", TTL: 3600}},
			TXTRecords:        []*entities.TXTRecord{{Name: owner, Value: "v=spf1 -all", TTL: 3600}},
			SRVRecords:        []*entities.SRVRecord{{Name: owner, Target: "sip.example.com.", Port: 5060, TTL: 3600}},
			CAARecords:        []*entities.CAARecord{{Name: owner, Tag: "issue", Value: "ca.example.com", TTL: 3600}},
			TLSARecords:       []*entities.TLSARecord{{Name: owner, Usage: 3, Selector: 1, MatchingType: 1, Data: "abcd", TTL: 3600}},
			DNSKEYRecords:     []*entities.DNSKEYRecord{{Name: owner, Flags: 257, Protocol: 3, Algorithm: 13, Key: "key", TTL: 3600}},
			DSRecords:         []*entities.DSRecord{{Name: owner, KeyTag: 1234, Algorithm: 13, DigestType: 2, Digest: "digest", TTL: 3600}},
			NSECRecords:       []*entities.NSECRecord{{Name: owner, NextDomain: "z.example.com.", TypeBitMap: []uint16{dns.TypeA}, TTL: 3600}},
			NSEC3Records:      []*entities.NSEC3Record{{Name: owner, Algorithm: 1, NextHashed: "abcd", TypeBitMap: []uint16{dns.TypeA}, TTL: 3600}},
			NSEC3PARAMRecords: []*entities.NSEC3PARAMRecord{{Name: owner, Algorithm: 1, Salt: "aabb", TTL: 3600}},
		},
	}
}

// ownerMatchedTypes lists every query type whose records are selected by owner
// name. SOA and RRSIG are excluded: they answer at the zone apex only and are
// covered separately.
var ownerMatchedTypes = []uint16{
	dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeMX, dns.TypeNS,
	dns.TypeTXT, dns.TypeSRV, dns.TypeCAA, dns.TypeTLSA,
	dns.TypeDNSKEY, dns.TypeDS, dns.TypeNSEC, dns.TypeNSEC3, dns.TypeNSEC3PARAM,
}

// TestParseQueriedRecord_AllTypes_AnswerOwnedName asserts every parser in the
// dispatch table answers the name its record actually names.
func TestParseQueriedRecord_AllTypes_AnswerOwnedName(t *testing.T) {
	zone := zoneWithOwner("www")
	for _, qtype := range ownerMatchedTypes {
		t.Run(dns.TypeToString[qtype], func(t *testing.T) {
			rrs, err := parseQueriedRecord(qtype, "www.example.com.", zone)
			require.NoError(t, err)
			require.Len(t, rrs, 1)
			assert.Equal(t, "www.example.com.", rrs[0].Header().Name)
			assert.Equal(t, qtype, rrs[0].Header().Rrtype)
		})
	}
}

// TestParseQueriedRecord_AllTypes_RejectUndefinedName is the defect in issue
// #182: a record owned by "www" answered www.anything.example.com and every
// deeper name, because only the query's first label was compared. No parser in
// the table may answer a name the zone does not define.
func TestParseQueriedRecord_AllTypes_RejectUndefinedName(t *testing.T) {
	zone := zoneWithOwner("www")
	undefined := []string{
		"www.anything.example.com.",
		"www.a.b.c.example.com.",
		"wwww.example.com.",
		"example.com.",
	}
	for _, qtype := range ownerMatchedTypes {
		for _, qname := range undefined {
			t.Run(dns.TypeToString[qtype]+"/"+qname, func(t *testing.T) {
				rrs, err := parseQueriedRecord(qtype, qname, zone)
				require.NoError(t, err)
				assert.Empty(t, rrs, "%s query for %s must not be answered", dns.TypeToString[qtype], qname)
			})
		}
	}
}

// TestParseQueriedRecord_AllTypes_ApexOwner asserts records stored against the
// apex marker answer the zone name, and only the zone name.
func TestParseQueriedRecord_AllTypes_ApexOwner(t *testing.T) {
	zone := zoneWithOwner("@")
	for _, qtype := range ownerMatchedTypes {
		t.Run(dns.TypeToString[qtype], func(t *testing.T) {
			rrs, err := parseQueriedRecord(qtype, "example.com.", zone)
			require.NoError(t, err)
			require.Len(t, rrs, 1)

			rrs, err = parseQueriedRecord(qtype, "anything.example.com.", zone)
			require.NoError(t, err)
			assert.Empty(t, rrs)
		})
	}
}

// TestParseQueriedRecord_AllTypes_FullyQualifiedOwner asserts owners stored as
// FQDNs resolve the same way as relative ones. Shipped zone configurations use
// both forms.
func TestParseQueriedRecord_AllTypes_FullyQualifiedOwner(t *testing.T) {
	zone := zoneWithOwner("www.example.com.")
	for _, qtype := range ownerMatchedTypes {
		t.Run(dns.TypeToString[qtype], func(t *testing.T) {
			rrs, err := parseQueriedRecord(qtype, "www.example.com.", zone)
			require.NoError(t, err)
			require.Len(t, rrs, 1)

			rrs, err = parseQueriedRecord(qtype, "www.anything.example.com.", zone)
			require.NoError(t, err)
			assert.Empty(t, rrs)
		})
	}
}

// TestParseQueriedRecord_ARecord_CaseInsensitive covers RFC 4343 §3: the
// comparison is case-insensitive in both directions, including the 0x20
// case-randomisation resolvers apply to queries.
func TestParseQueriedRecord_ARecord_CaseInsensitive(t *testing.T) {
	zone := &entities.Zone{
		Name: "Example.COM.",
		RecordSet: entities.RecordSet{
			ARecords: []*entities.ARecord{{Name: "WwW", Value: "192.0.2.1", TTL: 3600}},
		},
	}

	rrs, err := parseQueriedRecord(dns.TypeA, "wWw.eXaMpLe.cOm.", zone)
	require.NoError(t, err)
	require.Len(t, rrs, 1)
	// The answer echoes the query name, which is what a 0x20-randomising
	// resolver checks the response against.
	assert.Equal(t, "wWw.eXaMpLe.cOm.", rrs[0].Header().Name)
}

// TestParseQueriedRecord_ARecord_ZoneNameWithoutTrailingDot asserts a zone
// stored without its trailing dot still matches the always-fully-qualified
// query name.
func TestParseQueriedRecord_ARecord_ZoneNameWithoutTrailingDot(t *testing.T) {
	zone := &entities.Zone{
		Name: "example.com",
		RecordSet: entities.RecordSet{
			ARecords: []*entities.ARecord{
				{Name: "www", Value: "192.0.2.1", TTL: 3600},
				{Name: "@", Value: "192.0.2.2", TTL: 3600},
			},
		},
	}

	rrs, err := parseQueriedRecord(dns.TypeA, "www.example.com.", zone)
	require.NoError(t, err)
	require.Len(t, rrs, 1)

	rrs, err = parseQueriedRecord(dns.TypeA, "example.com.", zone)
	require.NoError(t, err)
	require.Len(t, rrs, 1)

	rrs, err = parseQueriedRecord(dns.TypeA, "www.anything.example.com.", zone)
	require.NoError(t, err)
	assert.Empty(t, rrs)
}

// TestParseQueriedRecord_ARecord_OnlyMatchingOwnerAnswers asserts the parser
// picks the queried name's records out of a zone holding several owners.
func TestParseQueriedRecord_ARecord_OnlyMatchingOwnerAnswers(t *testing.T) {
	zone := &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			ARecords: []*entities.ARecord{
				{Name: "www", Value: "192.0.2.1", TTL: 3600},
				{Name: "www", Value: "192.0.2.2", TTL: 3600},
				{Name: "mail", Value: "192.0.2.3", TTL: 3600},
				{Name: "@", Value: "192.0.2.4", TTL: 3600},
			},
		},
	}

	rrs, err := parseQueriedRecord(dns.TypeA, "www.example.com.", zone)
	require.NoError(t, err)
	require.Len(t, rrs, 2)
	assert.True(t, rrs[0].(*dns.A).A.Equal(net.ParseIP("192.0.2.1")))
	assert.True(t, rrs[1].(*dns.A).A.Equal(net.ParseIP("192.0.2.2")))
}

// TestParseQueriedRecord_SOARecord_ApexOnly asserts the SOA answers the zone
// apex and nothing else: a zone has exactly one SOA (RFC 1034 §4.2), and the
// parser used to return it for every name in the zone.
func TestParseQueriedRecord_SOARecord_ApexOnly(t *testing.T) {
	zone := &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			SOARecord: entities.SOARecord{
				// Shipped configurations set this to a name that is not the
				// apex; the apex owns the SOA regardless.
				Name:       "cp.example.com.",
				MName:      "ns1.example.com.",
				RName:      "hostmaster.example.com.",
				Serial:     1,
				MinimumTTL: 300,
				TTL:        3600,
			},
		},
	}

	rrs, err := parseQueriedRecord(dns.TypeSOA, "example.com.", zone)
	require.NoError(t, err)
	require.Len(t, rrs, 1)
	assert.Equal(t, "example.com.", rrs[0].Header().Name)

	for _, qname := range []string{"www.example.com.", "cp.example.com.", "a.b.example.com."} {
		rrs, err = parseQueriedRecord(dns.TypeSOA, qname, zone)
		require.NoError(t, err)
		assert.Empty(t, rrs, "SOA must not answer %s", qname)
	}
}

// TestParseQueriedRecord_SOARecord_Unconfigured asserts a zone with no SOA
// answers nothing rather than a record naming no primary server.
func TestParseQueriedRecord_SOARecord_Unconfigured(t *testing.T) {
	zone := &entities.Zone{Name: "example.com."}

	rrs, err := parseQueriedRecord(dns.TypeSOA, "example.com.", zone)
	require.NoError(t, err)
	assert.Empty(t, rrs)
}

// TestParseQueriedRecord_RRSIGRecord_ApexOnly asserts the zone's signatures
// answer at the apex only. RRSIGRecord carries no owner name, so returning the
// set for every queried name leaked the whole signature set.
func TestParseQueriedRecord_RRSIGRecord_ApexOnly(t *testing.T) {
	zone := &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			RRSIGRecords: []*entities.RRSIGRecord{
				{
					TypeCovered: "A",
					Algorithm:   13,
					Labels:      2,
					OriginalTTL: 3600,
					SignerName:  "example.com.",
					Signature:   "sig",
				},
			},
		},
	}

	rrs, err := parseQueriedRecord(dns.TypeRRSIG, "example.com.", zone)
	require.NoError(t, err)
	require.Len(t, rrs, 1)
	assert.Equal(t, dns.TypeA, rrs[0].(*dns.RRSIG).TypeCovered)

	rrs, err = parseQueriedRecord(dns.TypeRRSIG, "www.example.com.", zone)
	require.NoError(t, err)
	assert.Empty(t, rrs)
}

// TestParseQueriedRecord_SOARecord_TTLInheritedFromZone asserts an SOA with no
// TTL of its own serves the zone default, which is what the AXFR responder has
// always done. Serving TTL 0 would make every resolver re-ask immediately.
func TestParseQueriedRecord_SOARecord_TTLInheritedFromZone(t *testing.T) {
	zone := &entities.Zone{
		Name: "example.com.",
		TTL:  1800,
		RecordSet: entities.RecordSet{
			SOARecord: entities.SOARecord{
				MName: "ns1.example.com.",
				RName: "hostmaster.example.com.",
			},
		},
	}

	rrs, err := parseQueriedRecord(dns.TypeSOA, "example.com.", zone)
	require.NoError(t, err)
	require.Len(t, rrs, 1)
	assert.Equal(t, uint32(1800), rrs[0].Header().Ttl)

	// An explicit record TTL still wins.
	zone.RecordSet.SOARecord.TTL = 60
	rrs, err = parseQueriedRecord(dns.TypeSOA, "example.com.", zone)
	require.NoError(t, err)
	require.Len(t, rrs, 1)
	assert.Equal(t, uint32(60), rrs[0].Header().Ttl)
}
