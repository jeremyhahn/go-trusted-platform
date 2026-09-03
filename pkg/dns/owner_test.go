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
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecordOwnerFQDN(t *testing.T) {
	cases := []struct {
		name, zone, want string
	}{
		{"", "example.com.", "example.com."},
		{"@", "example.com.", "example.com."},
		{"www", "example.com.", "www.example.com."},
		{"www.example.com.", "example.com.", "www.example.com."},
		{"host", "example.com", "host.example.com."},
		{"_8443._tcp.host", "example.com.", "_8443._tcp.host.example.com."},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, recordOwnerFQDN(c.name, c.zone),
			"recordOwnerFQDN(%q, %q)", c.name, c.zone)
	}
}

// TestOwnerMatchesQuery_Matches covers the owner forms a zone may store: a
// relative label, the "@" apex marker, an empty name, and a fully qualified
// name. Case and the trailing dot must not matter (RFC 4343 §3).
func TestOwnerMatchesQuery_Matches(t *testing.T) {
	cases := []struct {
		owner, qname, zone string
	}{
		{"www", "www.example.com.", "example.com."},
		{"www", "WWW.Example.COM.", "example.com."},
		{"WWW", "www.example.com.", "example.com."},
		{"@", "example.com.", "example.com."},
		{"", "example.com.", "example.com."},
		{"www.example.com.", "www.example.com.", "example.com."},
		{"www", "www.example.com.", "example.com"},
		{"_8443._tcp.host", "_8443._tcp.host.example.com.", "example.com."},
		{"a.b", "a.b.example.com.", "example.com."},
	}
	for _, c := range cases {
		assert.True(t, ownerMatchesQuery(c.owner, c.qname, c.zone),
			"ownerMatchesQuery(%q, %q, %q)", c.owner, c.qname, c.zone)
	}
}

// TestOwnerMatchesQuery_Rejects is the regression this issue is about: a
// record named "www" must not answer for names the zone never defined, at any
// depth, and must not match a sibling that merely shares its first label.
func TestOwnerMatchesQuery_Rejects(t *testing.T) {
	cases := []struct {
		owner, qname, zone string
	}{
		{"www", "www.anything.example.com.", "example.com."},
		{"www", "www.a.b.c.example.com.", "example.com."},
		{"www", "www.example.com.evil.com.", "example.com."},
		{"www", "wwww.example.com.", "example.com."},
		{"www", "example.com.", "example.com."},
		{"@", "www.example.com.", "example.com."},
		{"www.example.com.", "www.anything.example.com.", "example.com."},
		{"a.b", "b.example.com.", "example.com."},
	}
	for _, c := range cases {
		assert.False(t, ownerMatchesQuery(c.owner, c.qname, c.zone),
			"ownerMatchesQuery(%q, %q, %q)", c.owner, c.qname, c.zone)
	}
}

func TestIsZoneApex(t *testing.T) {
	assert.True(t, isZoneApex("example.com.", "example.com."))
	assert.True(t, isZoneApex("EXAMPLE.com.", "example.com"))
	assert.False(t, isZoneApex("www.example.com.", "example.com."))
	assert.False(t, isZoneApex("example.com.", "other.com."))
}

// ownerNameZone holds a record of every owner-bearing type, in both the
// relative and the fully qualified stored form.
func ownerNameZone() *entities.Zone {
	return &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			ARecords: []*entities.ARecord{
				{Name: "@", Value: "192.0.2.1"},
				{Name: "www", Value: "192.0.2.2"},
			},
			AAAARecords:   []*entities.AAAARecord{{Name: "www", Value: "2001:db8::1"}},
			CNAMERecords:  []*entities.CNAMERecord{{Name: "alias", Value: "www.example.com."}},
			MXRecords:     []*entities.MXRecord{{Name: "example.com.", Value: "mail.example.com."}},
			NSRecords:     []*entities.NSRecord{{Name: "@", Value: "ns1.example.com."}},
			TXTRecords:    []*entities.TXTRecord{{Name: "_acme-challenge", Value: "token"}},
			SRVRecords:    []*entities.SRVRecord{{Name: "_sip._tcp", Target: "sip.example.com."}},
			CAARecords:    []*entities.CAARecord{{Name: "@", Tag: "issue", Value: "ca.example.com"}},
			TLSARecords:   []*entities.TLSARecord{{Name: "_8443._tcp.www", Data: "ab"}},
			DNSKEYRecords: []*entities.DNSKEYRecord{{Name: "example.com.", Key: "k"}},
			DSRecords:     []*entities.DSRecord{{Name: "delegated", Digest: "d"}},
			NSEC3Records:  []*entities.NSEC3Record{{Name: "hash.example.com."}},
		},
	}
}

func TestZoneDataOwnerNames(t *testing.T) {
	owners := zoneDataOwnerNames(ownerNameZone())

	// DNSSEC meta-records are generated from this set by the signer, so they
	// must not feed back into it.
	assert.Equal(t, []string{
		"_8443._tcp.www.example.com.",
		"_acme-challenge.example.com.",
		"_sip._tcp.example.com.",
		"alias.example.com.",
		"example.com.",
		"www.example.com.",
	}, owners)
}

// TestZoneOwnerNames covers the other half of the split: the existence set
// used for negative answers includes DNSSEC owners, because a name owning only
// an NSEC3 or a DS record is still a name the zone defines.
func TestZoneOwnerNames(t *testing.T) {
	owners := zoneOwnerNames(ownerNameZone())

	assert.Equal(t, []string{
		"_8443._tcp.www.example.com.",
		"_acme-challenge.example.com.",
		"_sip._tcp.example.com.",
		"alias.example.com.",
		"delegated.example.com.",
		"example.com.",
		"hash.example.com.",
		"www.example.com.",
	}, owners)
}

// TestZoneOwnerNames_EmptyZone verifies the degenerate input: a zone with no
// records still owns its own apex, which is where its SOA lives.
func TestZoneOwnerNames_EmptyZone(t *testing.T) {
	empty := &entities.Zone{Name: "example.com."}
	assert.Equal(t, []string{"example.com."}, zoneOwnerNames(empty))
	assert.Equal(t, []string{"example.com."}, zoneDataOwnerNames(empty))
}

func TestZoneHasName(t *testing.T) {
	zone := &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			ARecords: []*entities.ARecord{
				{Name: "www", Value: "192.0.2.1"},
				{Name: "deep.nested.host", Value: "192.0.2.2"},
			},
		},
	}

	// Names that exist: the apex, a record owner, and the empty non-terminals
	// between the apex and a deeper owner (RFC 1034 §4.3.2).
	require.True(t, zoneHasName(zone, "example.com."))
	require.True(t, zoneHasName(zone, "www.example.com."))
	require.True(t, zoneHasName(zone, "WWW.EXAMPLE.COM."))
	require.True(t, zoneHasName(zone, "nested.host.example.com."))
	require.True(t, zoneHasName(zone, "host.example.com."))
}

// TestZoneHasName_DNSSECOwner asserts a name that owns only a DNSSEC record
// exists. A signed zone answers DS or NSEC3 at such a name, so replying
// NXDOMAIN for a different qtype at the same name would contradict itself.
func TestZoneHasName_DNSSECOwner(t *testing.T) {
	zone := &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			DSRecords:    []*entities.DSRecord{{Name: "delegated", Digest: "d"}},
			NSEC3Records: []*entities.NSEC3Record{{Name: "hash.example.com."}},
		},
	}

	assert.True(t, zoneHasName(zone, "delegated.example.com."))
	assert.True(t, zoneHasName(zone, "hash.example.com."))
	assert.False(t, zoneHasName(zone, "missing.example.com."))
}

// TestZoneHasName_Missing covers the names that must produce NXDOMAIN rather
// than an empty NOERROR: anything the zone never defined.
func TestZoneHasName_Missing(t *testing.T) {
	zone := &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			ARecords: []*entities.ARecord{{Name: "www", Value: "192.0.2.1"}},
		},
	}

	assert.False(t, zoneHasName(zone, "www.anything.example.com."))
	assert.False(t, zoneHasName(zone, "missing.example.com."))
	assert.False(t, zoneHasName(zone, "wwww.example.com."))
	assert.False(t, zoneHasName(zone, "ww.example.com."))
}

// TestCollectOwnerNames_ExcludesSignerOutput pins which of the two owner sets
// the DNSSEC signer takes. Chaining over the signer's own output would have
// the NSEC/NSEC3 chain prove the existence of the hashed names it just
// generated, and each re-signing would grow the chain again.
func TestCollectOwnerNames_ExcludesSignerOutput(t *testing.T) {
	svc := &DNSSECService{}
	zone := ownerNameZone()

	owners := svc.collectOwnerNames(zone)

	assert.NotContains(t, owners, "hash.example.com.",
		"the NSEC3 hashed name is signer output, not a zone name to chain over")
	assert.Contains(t, owners, "www.example.com.")
	assert.Contains(t, owners, "example.com.")
}

// TestGetTypeBitMapForName_SOAApexOnly asserts the NSEC/NSEC3 type bitmap
// claims an SOA at the zone apex only. SOARecord.Name is not an owner name —
// shipped templates set it to a non-apex name — and a bitmap bit for an RRset
// the resolver never serves makes the signed zone contradict itself.
func TestGetTypeBitMapForName_SOAApexOnly(t *testing.T) {
	svc := &DNSSECService{}
	zone := &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			ARecords: []*entities.ARecord{{Name: "cp", Value: "192.0.2.1"}},
			SOARecord: entities.SOARecord{
				Name:  "cp.example.com.",
				MName: "ns1.example.com.",
				RName: "hostmaster.example.com.",
			},
		},
	}

	assert.Contains(t, svc.getTypeBitMapForName(zone, "example.com."), dns.TypeSOA)
	assert.NotContains(t, svc.getTypeBitMapForName(zone, "cp.example.com."), dns.TypeSOA,
		"the SOA record's name field must not put an SOA bit on a non-apex name")
	assert.Contains(t, svc.getTypeBitMapForName(zone, "cp.example.com."), dns.TypeA)
}

// TestGetTypeBitMapForName_NoSOAConfigured asserts a zone with no SOA claims
// none, matching what the resolver and the AXFR responder serve for it.
func TestGetTypeBitMapForName_NoSOAConfigured(t *testing.T) {
	svc := &DNSSECService{}
	zone := &entities.Zone{Name: "example.com."}

	assert.NotContains(t, svc.getTypeBitMapForName(zone, "example.com."), dns.TypeSOA)
}

// TestCollectRRsets_NoSOAConfigured asserts signing a zone with no SOA is a
// zone with one fewer RRset, not a nil dereference: soaToRR returns nil there.
func TestCollectRRsets_NoSOAConfigured(t *testing.T) {
	svc := &DNSSECService{}
	zone := &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			ARecords: []*entities.ARecord{{Name: "www", Value: "192.0.2.1"}},
		},
	}

	rrsets := svc.collectRRsets(zone)

	require.NotEmpty(t, rrsets)
	for key, rrs := range rrsets {
		for _, rr := range rrs {
			assert.NotEqual(t, dns.TypeSOA, rr.Header().Rrtype, "rrset %s", key)
		}
	}
}

// TestCollectRRsets_SOAAtApex asserts the signed SOA is owned by the apex,
// whatever the record's name field says.
func TestCollectRRsets_SOAAtApex(t *testing.T) {
	svc := &DNSSECService{}
	zone := &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			SOARecord: entities.SOARecord{
				Name:  "cp.example.com.",
				MName: "ns1.example.com.",
				RName: "hostmaster.example.com.",
			},
		},
	}

	rrsets := svc.collectRRsets(zone)

	require.Contains(t, rrsets, fmt.Sprintf("example.com._%d", dns.TypeSOA))
	require.NotContains(t, rrsets, fmt.Sprintf("cp.example.com._%d", dns.TypeSOA))
}

// TestCollectRRsets_SOATTLInheritedFromZone asserts the signer covers the same
// SOA TTL the resolver and the AXFR responder serve. Signing at 0 while
// serving the inherited zone TTL leaves the RRSIG's original TTL disagreeing
// with the RRset, which strict validators reject.
func TestCollectRRsets_SOATTLInheritedFromZone(t *testing.T) {
	svc := &DNSSECService{}
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

	rrsets := svc.collectRRsets(zone)

	signed := rrsets[fmt.Sprintf("example.com._%d", dns.TypeSOA)]
	require.Len(t, signed, 1)
	assert.Equal(t, uint32(1800), signed[0].Header().Ttl)

	served, err := parseQueriedRecord(dns.TypeSOA, "example.com.", zone)
	require.NoError(t, err)
	require.Len(t, served, 1)
	assert.Equal(t, served[0].Header().Ttl, signed[0].Header().Ttl,
		"the signed SOA and the served SOA must carry the same TTL")
}
