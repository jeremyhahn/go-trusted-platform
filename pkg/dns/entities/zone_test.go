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

package entities

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestZone_EntityID(t *testing.T) {
	zone := &Zone{ID: 123}
	assert.Equal(t, uint64(123), zone.EntityID())
}

func TestZone_SetEntityID(t *testing.T) {
	zone := &Zone{}
	zone.SetEntityID(456)
	assert.Equal(t, uint64(456), zone.ID)
}

func TestZone_ARecords(t *testing.T) {
	zone := &Zone{}

	// Test SetARecords
	records := []*ARecord{
		{Name: "www", Value: "192.168.1.1", TTL: 3600},
		{Name: "mail", Value: "192.168.1.2", TTL: 3600},
	}
	zone.SetARecords(records)
	assert.Len(t, zone.RecordSet.ARecords, 2)
	assert.Equal(t, "www", zone.RecordSet.ARecords[0].Name)

	// Test AddARecord
	newRecord := &ARecord{Name: "api", Value: "192.168.1.3", TTL: 3600}
	zone.AddARecord(newRecord)
	assert.Len(t, zone.RecordSet.ARecords, 3)
	assert.Equal(t, "api", zone.RecordSet.ARecords[2].Name)

	// Test RemoveARecord
	zone.RemoveARecord("www")
	assert.Len(t, zone.RecordSet.ARecords, 2)
	assert.Equal(t, "mail", zone.RecordSet.ARecords[0].Name)
}

func TestZone_AAAARecords(t *testing.T) {
	zone := &Zone{}

	records := []*AAAARecord{
		{Name: "www", Value: "2001:db8::1", TTL: 3600},
	}
	zone.SetAAAARecords(records)
	assert.Len(t, zone.RecordSet.AAAARecords, 1)

	newRecord := &AAAARecord{Name: "mail", Value: "2001:db8::2", TTL: 3600}
	zone.AddAAAARecord(newRecord)
	assert.Len(t, zone.RecordSet.AAAARecords, 2)

	zone.RemoveAAAARecord("www")
	assert.Len(t, zone.RecordSet.AAAARecords, 1)
	assert.Equal(t, "mail", zone.RecordSet.AAAARecords[0].Name)
}

func TestZone_CNAMERecords(t *testing.T) {
	zone := &Zone{}

	records := []*CNAMERecord{
		{Name: "www", Value: "example.com.", TTL: 3600},
	}
	zone.SetCNAMERecords(records)
	assert.Len(t, zone.RecordSet.CNAMERecords, 1)

	newRecord := &CNAMERecord{Name: "blog", Value: "example.com.", TTL: 3600}
	zone.AddCNAMERecord(newRecord)
	assert.Len(t, zone.RecordSet.CNAMERecords, 2)

	zone.RemoveCNAMERecord("www")
	assert.Len(t, zone.RecordSet.CNAMERecords, 1)
	assert.Equal(t, "blog", zone.RecordSet.CNAMERecords[0].Name)
}

func TestZone_DNSKEYRecords(t *testing.T) {
	zone := &Zone{}

	records := []*DNSKEYRecord{
		{Name: "example.com.", Algorithm: 8, Flags: 257, Protocol: 3, Key: "base64key", TTL: 3600},
	}
	zone.SetDNSKEYRecords(records)
	assert.Len(t, zone.RecordSet.DNSKEYRecords, 1)

	newRecord := &DNSKEYRecord{Name: "test.com.", Algorithm: 13, Flags: 256, Protocol: 3, Key: "anotherkey", TTL: 3600}
	zone.AddDNSKEYRecord(newRecord)
	assert.Len(t, zone.RecordSet.DNSKEYRecords, 2)

	zone.RemoveDNSKEYRecord("example.com.")
	assert.Len(t, zone.RecordSet.DNSKEYRecords, 1)
	assert.Equal(t, "test.com.", zone.RecordSet.DNSKEYRecords[0].Name)
}

func TestZone_DSRecords(t *testing.T) {
	zone := &Zone{}

	records := []*DSRecord{
		{Name: "example.com.", KeyTag: 12345, Algorithm: 8, DigestType: 2, Digest: "abcd", TTL: 3600},
	}
	zone.SetDSRecords(records)
	assert.Len(t, zone.RecordSet.DSRecords, 1)

	newRecord := &DSRecord{Name: "test.com.", KeyTag: 54321, Algorithm: 13, DigestType: 2, Digest: "efgh", TTL: 3600}
	zone.AddDSRecord(newRecord)
	assert.Len(t, zone.RecordSet.DSRecords, 2)

	zone.RemoveDSRecord("example.com.")
	assert.Len(t, zone.RecordSet.DSRecords, 1)
	assert.Equal(t, "test.com.", zone.RecordSet.DSRecords[0].Name)
}

func TestZone_MXRecords(t *testing.T) {
	zone := &Zone{}

	records := []*MXRecord{
		{Name: "example.com.", Value: "mail.example.com.", Priority: 10, TTL: 3600},
	}
	zone.SetMXRecords(records)
	assert.Len(t, zone.RecordSet.MXRecords, 1)

	newRecord := &MXRecord{Name: "test.com.", Value: "mail.test.com.", Priority: 20, TTL: 3600}
	zone.AddMXRecord(newRecord)
	assert.Len(t, zone.RecordSet.MXRecords, 2)

	zone.RemoveMXRecord("example.com.")
	assert.Len(t, zone.RecordSet.MXRecords, 1)
	assert.Equal(t, "test.com.", zone.RecordSet.MXRecords[0].Name)
}

func TestZone_NSRecords(t *testing.T) {
	zone := &Zone{}

	records := []*NSRecord{
		{Name: "example.com.", Value: "ns1.example.com.", TTL: 3600},
	}
	zone.SetNSRecords(records)
	assert.Len(t, zone.RecordSet.NSRecords, 1)

	newRecord := &NSRecord{Name: "test.com.", Value: "ns1.test.com.", TTL: 3600}
	zone.AddNSRecord(newRecord)
	assert.Len(t, zone.RecordSet.NSRecords, 2)

	zone.RemoveNSRecord("example.com.")
	assert.Len(t, zone.RecordSet.NSRecords, 1)
	assert.Equal(t, "test.com.", zone.RecordSet.NSRecords[0].Name)
}

func TestZone_RRSIGRecords(t *testing.T) {
	zone := &Zone{}

	records := []*RRSIGRecord{
		{SignerName: "example.com.", Algorithm: 8, KeyTag: 12345, TypeCovered: "A", OriginalTTL: 3600},
	}
	zone.SetRRSIGRecords(records)
	assert.Len(t, zone.RecordSet.RRSIGRecords, 1)

	newRecord := &RRSIGRecord{SignerName: "test.com.", Algorithm: 13, KeyTag: 54321, TypeCovered: "AAAA", OriginalTTL: 3600}
	zone.AddRRSIGRecord(newRecord)
	assert.Len(t, zone.RecordSet.RRSIGRecords, 2)

	zone.RemoveRRSIGRecord("example.com.")
	assert.Len(t, zone.RecordSet.RRSIGRecords, 1)
	assert.Equal(t, "test.com.", zone.RecordSet.RRSIGRecords[0].SignerName)
}

func TestZone_SOARecord(t *testing.T) {
	zone := &Zone{}

	record := SOARecord{
		Name:       "example.com.",
		MName:      "ns1.example.com.",
		RName:      "admin.example.com.",
		Serial:     1,
		Refresh:    3600,
		Retry:      600,
		Expire:     86400,
		MinimumTTL: 300,
		TTL:        3600,
	}
	zone.SetSOARecord(record)
	assert.Equal(t, "example.com.", zone.RecordSet.SOARecord.Name)
	assert.Equal(t, uint32(1), zone.RecordSet.SOARecord.Serial)
}

func TestZone_SRVRecords(t *testing.T) {
	zone := &Zone{}

	records := []*SRVRecord{
		{Name: "_http._tcp.example.com.", Target: "server.example.com.", Port: 80, Priority: 10, Weight: 5, TTL: 3600},
	}
	zone.SetSRVRecords(records)
	assert.Len(t, zone.RecordSet.SRVRecords, 1)

	newRecord := &SRVRecord{Name: "_https._tcp.example.com.", Target: "server.example.com.", Port: 443, Priority: 10, Weight: 5, TTL: 3600}
	zone.AddSRVRecord(newRecord)
	assert.Len(t, zone.RecordSet.SRVRecords, 2)

	zone.RemoveSRVRecord("_http._tcp.example.com.")
	assert.Len(t, zone.RecordSet.SRVRecords, 1)
	assert.Equal(t, "_https._tcp.example.com.", zone.RecordSet.SRVRecords[0].Name)
}

func TestZone_TXTRecords(t *testing.T) {
	zone := &Zone{}

	records := []*TXTRecord{
		{Name: "example.com.", Value: "v=spf1 include:_spf.example.com ~all", TTL: 3600},
	}
	zone.SetTXTRecords(records)
	assert.Len(t, zone.RecordSet.TXTRecords, 1)

	newRecord := &TXTRecord{Name: "_dmarc.example.com.", Value: "v=DMARC1; p=none", TTL: 3600}
	zone.AddTXTRecord(newRecord)
	assert.Len(t, zone.RecordSet.TXTRecords, 2)

	zone.RemoveTXTRecord("example.com.")
	assert.Len(t, zone.RecordSet.TXTRecords, 1)
	assert.Equal(t, "_dmarc.example.com.", zone.RecordSet.TXTRecords[0].Name)
}

func TestZone_RemoveNonExistentRecords(t *testing.T) {
	zone := &Zone{}

	// Add some records
	zone.AddARecord(&ARecord{Name: "www", Value: "192.168.1.1", TTL: 3600})
	zone.AddAAAARecord(&AAAARecord{Name: "www", Value: "2001:db8::1", TTL: 3600})
	zone.AddCNAMERecord(&CNAMERecord{Name: "blog", Value: "example.com.", TTL: 3600})
	zone.AddMXRecord(&MXRecord{Name: "example.com.", Value: "mail.example.com.", Priority: 10, TTL: 3600})
	zone.AddNSRecord(&NSRecord{Name: "example.com.", Value: "ns1.example.com.", TTL: 3600})
	zone.AddSRVRecord(&SRVRecord{Name: "_http._tcp", Target: "server.example.com.", Port: 80, TTL: 3600})
	zone.AddTXTRecord(&TXTRecord{Name: "example.com.", Value: "v=spf1", TTL: 3600})

	// Try to remove non-existent records - should not panic and should not affect existing records
	initialACount := len(zone.RecordSet.ARecords)
	zone.RemoveARecord("nonexistent")
	assert.Len(t, zone.RecordSet.ARecords, initialACount)

	initialAAAACount := len(zone.RecordSet.AAAARecords)
	zone.RemoveAAAARecord("nonexistent")
	assert.Len(t, zone.RecordSet.AAAARecords, initialAAAACount)

	initialCNAMECount := len(zone.RecordSet.CNAMERecords)
	zone.RemoveCNAMERecord("nonexistent")
	assert.Len(t, zone.RecordSet.CNAMERecords, initialCNAMECount)

	initialMXCount := len(zone.RecordSet.MXRecords)
	zone.RemoveMXRecord("nonexistent")
	assert.Len(t, zone.RecordSet.MXRecords, initialMXCount)

	initialNSCount := len(zone.RecordSet.NSRecords)
	zone.RemoveNSRecord("nonexistent")
	assert.Len(t, zone.RecordSet.NSRecords, initialNSCount)

	initialSRVCount := len(zone.RecordSet.SRVRecords)
	zone.RemoveSRVRecord("nonexistent")
	assert.Len(t, zone.RecordSet.SRVRecords, initialSRVCount)

	initialTXTCount := len(zone.RecordSet.TXTRecords)
	zone.RemoveTXTRecord("nonexistent")
	assert.Len(t, zone.RecordSet.TXTRecords, initialTXTCount)
}

func TestZone_SetCAARecords(t *testing.T) {
	zone := &Zone{Name: "example.com."}

	records := []*CAARecord{
		{Name: "example.com.", Flags: 0, Tag: "issue", Value: "letsencrypt.org", TTL: 3600},
		{Name: "example.com.", Flags: 0, Tag: "issuewild", Value: "letsencrypt.org", TTL: 3600},
	}

	zone.SetCAARecords(records)

	assert.Len(t, zone.RecordSet.CAARecords, 2)
	assert.Equal(t, "issue", zone.RecordSet.CAARecords[0].Tag)
	assert.Equal(t, "issuewild", zone.RecordSet.CAARecords[1].Tag)
}

func TestZone_AddCAARecord(t *testing.T) {
	zone := &Zone{Name: "example.com."}

	zone.AddCAARecord(&CAARecord{Name: "example.com.", Flags: 0, Tag: "issue", Value: "ca1.example.com", TTL: 3600})
	zone.AddCAARecord(&CAARecord{Name: "example.com.", Flags: 0, Tag: "issue", Value: "ca2.example.com", TTL: 3600})

	assert.Len(t, zone.RecordSet.CAARecords, 2)
	assert.Equal(t, "ca1.example.com", zone.RecordSet.CAARecords[0].Value)
	assert.Equal(t, "ca2.example.com", zone.RecordSet.CAARecords[1].Value)
}

func TestZone_RemoveCAARecord(t *testing.T) {
	zone := &Zone{
		Name: "example.com.",
		RecordSet: RecordSet{
			CAARecords: []*CAARecord{
				{Name: "example.com.", Flags: 0, Tag: "issue", Value: "ca1.example.com", TTL: 3600},
				{Name: "sub.example.com.", Flags: 0, Tag: "issue", Value: "ca2.example.com", TTL: 3600},
			},
		},
	}

	zone.RemoveCAARecord("example.com.")

	assert.Len(t, zone.RecordSet.CAARecords, 1)
	assert.Equal(t, "sub.example.com.", zone.RecordSet.CAARecords[0].Name)
}

func TestZone_RemoveCAARecord_NotFound(t *testing.T) {
	zone := &Zone{
		Name: "example.com.",
		RecordSet: RecordSet{
			CAARecords: []*CAARecord{
				{Name: "example.com.", Flags: 0, Tag: "issue", Value: "ca.example.com", TTL: 3600},
			},
		},
	}

	zone.RemoveCAARecord("nonexistent.example.com.")

	// Should not modify the list
	assert.Len(t, zone.RecordSet.CAARecords, 1)
}

func TestZone_SetTLSARecords(t *testing.T) {
	zone := &Zone{Name: "example.com."}

	records := []*TLSARecord{
		{Name: "_443._tcp.www.example.com.", Usage: 3, Selector: 1, MatchingType: 1, Data: "hash1", TTL: 3600},
		{Name: "_25._tcp.mail.example.com.", Usage: 3, Selector: 1, MatchingType: 1, Data: "hash2", TTL: 3600},
	}

	zone.SetTLSARecords(records)

	assert.Len(t, zone.RecordSet.TLSARecords, 2)
	assert.Equal(t, "_443._tcp.www.example.com.", zone.RecordSet.TLSARecords[0].Name)
	assert.Equal(t, "_25._tcp.mail.example.com.", zone.RecordSet.TLSARecords[1].Name)
}

func TestZone_AddTLSARecord(t *testing.T) {
	zone := &Zone{Name: "example.com."}

	zone.AddTLSARecord(&TLSARecord{Name: "_443._tcp.www.example.com.", Usage: 3, Selector: 1, MatchingType: 1, Data: "hash1", TTL: 3600})
	zone.AddTLSARecord(&TLSARecord{Name: "_853._tcp.dns.example.com.", Usage: 3, Selector: 1, MatchingType: 1, Data: "hash2", TTL: 3600})

	assert.Len(t, zone.RecordSet.TLSARecords, 2)
}

func TestZone_RemoveTLSARecord(t *testing.T) {
	zone := &Zone{
		Name: "example.com.",
		RecordSet: RecordSet{
			TLSARecords: []*TLSARecord{
				{Name: "_443._tcp.www.example.com.", Usage: 3, Selector: 1, MatchingType: 1, Data: "hash1", TTL: 3600},
				{Name: "_25._tcp.mail.example.com.", Usage: 3, Selector: 1, MatchingType: 1, Data: "hash2", TTL: 3600},
			},
		},
	}

	zone.RemoveTLSARecord("_443._tcp.www.example.com.")

	assert.Len(t, zone.RecordSet.TLSARecords, 1)
	assert.Equal(t, "_25._tcp.mail.example.com.", zone.RecordSet.TLSARecords[0].Name)
}

func TestZone_RemoveTLSARecord_NotFound(t *testing.T) {
	zone := &Zone{
		Name: "example.com.",
		RecordSet: RecordSet{
			TLSARecords: []*TLSARecord{
				{Name: "_443._tcp.www.example.com.", Usage: 3, Selector: 1, MatchingType: 1, Data: "hash", TTL: 3600},
			},
		},
	}

	zone.RemoveTLSARecord("_25._tcp.mail.example.com.")

	// Should not modify the list
	assert.Len(t, zone.RecordSet.TLSARecords, 1)
}

// TestZone_NSECRecords tests NSEC record management.
func TestZone_NSECRecords(t *testing.T) {
	zone := &Zone{Name: "example.com."}

	// Test SetNSECRecords
	records := []*NSECRecord{
		{Name: "example.com.", TTL: 3600, NextDomain: "www.example.com.", TypeBitMap: []uint16{dns.TypeA, dns.TypeNS, dns.TypeSOA}},
		{Name: "www.example.com.", TTL: 3600, NextDomain: "example.com.", TypeBitMap: []uint16{dns.TypeA, dns.TypeAAAA}},
	}
	zone.SetNSECRecords(records)
	assert.Len(t, zone.RecordSet.NSECRecords, 2)
	assert.Equal(t, "example.com.", zone.RecordSet.NSECRecords[0].Name)
	assert.Equal(t, "www.example.com.", zone.RecordSet.NSECRecords[0].NextDomain)

	// Test AddNSECRecord
	newRecord := &NSECRecord{Name: "mail.example.com.", TTL: 3600, NextDomain: "www.example.com.", TypeBitMap: []uint16{dns.TypeA, dns.TypeMX}}
	zone.AddNSECRecord(newRecord)
	assert.Len(t, zone.RecordSet.NSECRecords, 3)
	assert.Equal(t, "mail.example.com.", zone.RecordSet.NSECRecords[2].Name)

	// Test RemoveNSECRecord
	zone.RemoveNSECRecord("example.com.")
	assert.Len(t, zone.RecordSet.NSECRecords, 2)
	assert.Equal(t, "www.example.com.", zone.RecordSet.NSECRecords[0].Name)
}

// TestZone_NSECRecords_RemoveNonExistent tests removing non-existent NSEC record.
func TestZone_NSECRecords_RemoveNonExistent(t *testing.T) {
	zone := &Zone{
		Name: "example.com.",
		RecordSet: RecordSet{
			NSECRecords: []*NSECRecord{
				{Name: "example.com.", TTL: 3600, NextDomain: "www.example.com.", TypeBitMap: []uint16{dns.TypeA}},
			},
		},
	}

	zone.RemoveNSECRecord("nonexistent.example.com.")
	assert.Len(t, zone.RecordSet.NSECRecords, 1)
}

// TestZone_NSEC3Records tests NSEC3 record management.
func TestZone_NSEC3Records(t *testing.T) {
	zone := &Zone{Name: "example.com."}

	// Test SetNSEC3Records
	records := []*NSEC3Record{
		{
			Name:       "abc123.example.com.",
			TTL:        3600,
			Algorithm:  1,
			Flags:      0,
			Iterations: 10,
			Salt:       "aabbccdd",
			NextHashed: "def456",
			TypeBitMap: []uint16{dns.TypeA, dns.TypeNS},
		},
		{
			Name:       "def456.example.com.",
			TTL:        3600,
			Algorithm:  1,
			Flags:      0,
			Iterations: 10,
			Salt:       "aabbccdd",
			NextHashed: "abc123",
			TypeBitMap: []uint16{dns.TypeA},
		},
	}
	zone.SetNSEC3Records(records)
	assert.Len(t, zone.RecordSet.NSEC3Records, 2)
	assert.Equal(t, "abc123.example.com.", zone.RecordSet.NSEC3Records[0].Name)
	assert.Equal(t, uint16(10), zone.RecordSet.NSEC3Records[0].Iterations)

	// Test AddNSEC3Record
	newRecord := &NSEC3Record{
		Name:       "ghi789.example.com.",
		TTL:        3600,
		Algorithm:  1,
		Flags:      0,
		Iterations: 10,
		Salt:       "aabbccdd",
		NextHashed: "abc123",
		TypeBitMap: []uint16{dns.TypeMX},
	}
	zone.AddNSEC3Record(newRecord)
	assert.Len(t, zone.RecordSet.NSEC3Records, 3)
	assert.Equal(t, "ghi789.example.com.", zone.RecordSet.NSEC3Records[2].Name)

	// Test RemoveNSEC3Record
	zone.RemoveNSEC3Record("abc123.example.com.")
	assert.Len(t, zone.RecordSet.NSEC3Records, 2)
	assert.Equal(t, "def456.example.com.", zone.RecordSet.NSEC3Records[0].Name)
}

// TestZone_NSEC3Records_RemoveNonExistent tests removing non-existent NSEC3 record.
func TestZone_NSEC3Records_RemoveNonExistent(t *testing.T) {
	zone := &Zone{
		Name: "example.com.",
		RecordSet: RecordSet{
			NSEC3Records: []*NSEC3Record{
				{Name: "abc123.example.com.", TTL: 3600, Algorithm: 1, NextHashed: "def456"},
			},
		},
	}

	zone.RemoveNSEC3Record("nonexistent.example.com.")
	assert.Len(t, zone.RecordSet.NSEC3Records, 1)
}

// TestZone_NSEC3PARAMRecords tests NSEC3PARAM record management.
func TestZone_NSEC3PARAMRecords(t *testing.T) {
	zone := &Zone{Name: "example.com."}

	// Test SetNSEC3PARAMRecords
	records := []*NSEC3PARAMRecord{
		{
			Name:       "example.com.",
			TTL:        3600,
			Algorithm:  1,
			Flags:      0,
			Iterations: 10,
			Salt:       "aabbccdd",
		},
	}
	zone.SetNSEC3PARAMRecords(records)
	assert.Len(t, zone.RecordSet.NSEC3PARAMRecords, 1)
	assert.Equal(t, "example.com.", zone.RecordSet.NSEC3PARAMRecords[0].Name)
	assert.Equal(t, uint8(1), zone.RecordSet.NSEC3PARAMRecords[0].Algorithm)

	// Test AddNSEC3PARAMRecord
	newRecord := &NSEC3PARAMRecord{
		Name:       "example.com.",
		TTL:        3600,
		Algorithm:  1,
		Flags:      1,
		Iterations: 5,
		Salt:       "11223344",
	}
	zone.AddNSEC3PARAMRecord(newRecord)
	assert.Len(t, zone.RecordSet.NSEC3PARAMRecords, 2)

	// Test RemoveNSEC3PARAMRecord
	zone.RemoveNSEC3PARAMRecord("example.com.")
	assert.Len(t, zone.RecordSet.NSEC3PARAMRecords, 1)
	assert.Equal(t, uint8(1), zone.RecordSet.NSEC3PARAMRecords[0].Flags)
}

// TestZone_NSEC3PARAMRecords_RemoveNonExistent tests removing non-existent NSEC3PARAM record.
func TestZone_NSEC3PARAMRecords_RemoveNonExistent(t *testing.T) {
	zone := &Zone{
		Name: "example.com.",
		RecordSet: RecordSet{
			NSEC3PARAMRecords: []*NSEC3PARAMRecord{
				{Name: "example.com.", TTL: 3600, Algorithm: 1, Iterations: 10},
			},
		},
	}

	zone.RemoveNSEC3PARAMRecord("nonexistent.example.com.")
	assert.Len(t, zone.RecordSet.NSEC3PARAMRecords, 1)
}

// TestZone_NSECRecords_EmptyZone tests NSEC operations on empty zone.
func TestZone_NSECRecords_EmptyZone(t *testing.T) {
	zone := &Zone{Name: "example.com."}

	// Operations on empty zone should not panic
	zone.RemoveNSECRecord("example.com.")
	assert.Nil(t, zone.RecordSet.NSECRecords)

	// Adding to empty zone should work
	zone.AddNSECRecord(&NSECRecord{Name: "example.com.", TTL: 3600})
	assert.Len(t, zone.RecordSet.NSECRecords, 1)
}

// TestZone_NSEC3Records_EmptyZone tests NSEC3 operations on empty zone.
func TestZone_NSEC3Records_EmptyZone(t *testing.T) {
	zone := &Zone{Name: "example.com."}

	// Operations on empty zone should not panic
	zone.RemoveNSEC3Record("abc123.example.com.")
	assert.Nil(t, zone.RecordSet.NSEC3Records)

	// Adding to empty zone should work
	zone.AddNSEC3Record(&NSEC3Record{Name: "abc123.example.com.", TTL: 3600})
	assert.Len(t, zone.RecordSet.NSEC3Records, 1)
}

// TestZone_NSEC3PARAMRecords_EmptyZone tests NSEC3PARAM operations on empty zone.
func TestZone_NSEC3PARAMRecords_EmptyZone(t *testing.T) {
	zone := &Zone{Name: "example.com."}

	// Operations on empty zone should not panic
	zone.RemoveNSEC3PARAMRecord("example.com.")
	assert.Nil(t, zone.RecordSet.NSEC3PARAMRecords)

	// Adding to empty zone should work
	zone.AddNSEC3PARAMRecord(&NSEC3PARAMRecord{Name: "example.com.", TTL: 3600})
	assert.Len(t, zone.RecordSet.NSEC3PARAMRecords, 1)
}

// TestZone_RemoveDNSKEYRecord_NotFound tests removing non-existent DNSKEY record.
func TestZone_RemoveDNSKEYRecord_NotFound(t *testing.T) {
	zone := &Zone{
		Name: "example.com.",
		RecordSet: RecordSet{
			DNSKEYRecords: []*DNSKEYRecord{
				{Name: "example.com.", Algorithm: 13, Flags: 257, Protocol: 3},
			},
		},
	}

	zone.RemoveDNSKEYRecord("nonexistent.com.")
	assert.Len(t, zone.RecordSet.DNSKEYRecords, 1)
}

// TestZone_RemoveDSRecord_NotFound tests removing non-existent DS record.
func TestZone_RemoveDSRecord_NotFound(t *testing.T) {
	zone := &Zone{
		Name: "example.com.",
		RecordSet: RecordSet{
			DSRecords: []*DSRecord{
				{Name: "example.com.", KeyTag: 12345, Algorithm: 13},
			},
		},
	}

	zone.RemoveDSRecord("nonexistent.com.")
	assert.Len(t, zone.RecordSet.DSRecords, 1)
}

// TestZone_RemoveRRSIGRecord_NotFound tests removing non-existent RRSIG record.
func TestZone_RemoveRRSIGRecord_NotFound(t *testing.T) {
	zone := &Zone{
		Name: "example.com.",
		RecordSet: RecordSet{
			RRSIGRecords: []*RRSIGRecord{
				{SignerName: "example.com.", Algorithm: 13, KeyTag: 12345},
			},
		},
	}

	zone.RemoveRRSIGRecord("nonexistent.com.")
	assert.Len(t, zone.RecordSet.RRSIGRecords, 1)
}

// TestZone_IsOwnedBy tests the IsOwnedBy method
func TestZone_IsOwnedBy(t *testing.T) {
	tests := []struct {
		name           string
		zoneTenantID   string
		checkTenantID  string
		expectedResult bool
	}{
		{
			name:           "matching_tenant",
			zoneTenantID:   "tenant-a",
			checkTenantID:  "tenant-a",
			expectedResult: true,
		},
		{
			name:           "different_tenant",
			zoneTenantID:   "tenant-a",
			checkTenantID:  "tenant-b",
			expectedResult: false,
		},
		{
			name:           "empty_zone_tenant",
			zoneTenantID:   "",
			checkTenantID:  "tenant-a",
			expectedResult: false,
		},
		{
			name:           "empty_check_tenant",
			zoneTenantID:   "tenant-a",
			checkTenantID:  "",
			expectedResult: false,
		},
		{
			name:           "both_empty",
			zoneTenantID:   "",
			checkTenantID:  "",
			expectedResult: true,
		},
		{
			name:           "case_sensitive",
			zoneTenantID:   "Tenant-A",
			checkTenantID:  "tenant-a",
			expectedResult: false,
		},
		{
			name:           "uuid_matching",
			zoneTenantID:   "550e8400-e29b-41d4-a716-446655440000",
			checkTenantID:  "550e8400-e29b-41d4-a716-446655440000",
			expectedResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			zone := &Zone{
				Name:     "example.com.",
				TenantID: tt.zoneTenantID,
			}
			result := zone.IsOwnedBy(tt.checkTenantID)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}

// TestZone_IsOwnedBy_WithRecords tests IsOwnedBy with a fully populated zone
func TestZone_IsOwnedBy_WithRecords(t *testing.T) {
	zone := &Zone{
		ID:       1,
		Name:     "example.com.",
		TenantID: "test-tenant",
		TTL:      3600,
		RecordSet: RecordSet{
			SOARecord: SOARecord{
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
			NSRecords: []*NSRecord{
				{Name: "example.com.", Value: "ns1.example.com.", TTL: 3600},
			},
			ARecords: []*ARecord{
				{Name: "@", Value: "192.0.2.1", TTL: 3600},
			},
		},
	}

	// Test ownership
	assert.True(t, zone.IsOwnedBy("test-tenant"))
	assert.False(t, zone.IsOwnedBy("other-tenant"))
	assert.False(t, zone.IsOwnedBy(""))
}
