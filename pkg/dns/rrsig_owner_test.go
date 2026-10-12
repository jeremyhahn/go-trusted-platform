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
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// signedTestZone signs createTestZone, which holds the non-apex A RRsets
// www and mail beside the apex RRsets.
func signedTestZone(t *testing.T) *entities.Zone {
	t.Helper()
	service, _ := createTestDNSSECServiceWithMock(t)
	zone := createTestZone()
	require.NoError(t, service.SignZone(zone))
	return zone
}

// findRRSIG returns the signature covering rrtype among rrs.
func findRRSIG(t *testing.T, rrs []dns.RR, rrtype uint16) *dns.RRSIG {
	t.Helper()
	for _, rr := range rrs {
		if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == rrtype {
			return sig
		}
	}
	require.Failf(t, "no RRSIG", "no RRSIG covers %s", dns.TypeToString[rrtype])
	return nil
}

// verifyRRSIG checks sig over rrset with the DNSKEY whose tag it names.
func verifyRRSIG(t *testing.T, sig *dns.RRSIG, rrset []dns.RR, keys []dns.RR) {
	t.Helper()
	for _, rr := range keys {
		key, ok := rr.(*dns.DNSKEY)
		if ok && key.KeyTag() == sig.KeyTag {
			require.NoError(t, sig.Verify(key, rrset))
			return
		}
	}
	require.Failf(t, "no DNSKEY", "no DNSKEY has tag %d", sig.KeyTag)
}

func TestSignZone_PersistsRRSIGOwner(t *testing.T) {
	zone := signedTestZone(t)

	var wwwA *entities.RRSIGRecord
	for _, r := range zone.RecordSet.RRSIGRecords {
		require.NotEmpty(t, r.Name, "every signature persists its owner")
		assert.Equal(t, uint8(dns.CountLabel(r.Name)), r.Labels,
			"owner %s disagrees with the labels it was signed with", r.Name)
		if r.TypeCovered == "A" && equalNames(r.Name, "www.example.com.") {
			wwwA = r
		}
	}
	require.NotNil(t, wwwA, "the www A RRset signature is persisted under www")
}

func TestResolveRRSIG_AnswersAtSignedOwner(t *testing.T) {
	zone := signedTestZone(t)

	sigs, err := parseQueriedRecord(dns.TypeRRSIG, "www.example.com.", zone)
	require.NoError(t, err)
	require.NotEmpty(t, sigs)
	for _, rr := range sigs {
		assert.Equal(t, uint8(3), rr.(*dns.RRSIG).Labels, "only www signatures answer at www")
	}

	rrset, err := parseQueriedRecord(dns.TypeA, "www.example.com.", zone)
	require.NoError(t, err)
	keys, err := parseQueriedRecord(dns.TypeDNSKEY, "example.com.", zone)
	require.NoError(t, err)
	verifyRRSIG(t, findRRSIG(t, sigs, dns.TypeA), rrset, keys)
}

func TestResolveRRSIG_ApexDoesNotAnswerNonApexSignatures(t *testing.T) {
	zone := signedTestZone(t)

	sigs, err := parseQueriedRecord(dns.TypeRRSIG, "example.com.", zone)
	require.NoError(t, err)
	require.NotEmpty(t, sigs)
	for _, rr := range sigs {
		assert.Equal(t, uint8(2), rr.(*dns.RRSIG).Labels, "only apex signatures answer at the apex")
	}

	sigs, err = parseQueriedRecord(dns.TypeRRSIG, "absent.example.com.", zone)
	require.NoError(t, err)
	assert.Empty(t, sigs)
}

// TestResolveRRSIG_ServedSignatureVerifies guards the stored signature form:
// it is kept as the base64 miekg/dns produced, not encoded a second time.
func TestResolveRRSIG_ServedSignatureVerifies(t *testing.T) {
	zone := signedTestZone(t)

	sigs, err := parseQueriedRecord(dns.TypeRRSIG, "example.com.", zone)
	require.NoError(t, err)
	keys, err := parseQueriedRecord(dns.TypeDNSKEY, "example.com.", zone)
	require.NoError(t, err)
	verifyRRSIG(t, findRRSIG(t, sigs, dns.TypeDNSKEY), keys, keys)
}

func TestBuildZoneTransfer_RRSIGUnderSignedOwner(t *testing.T) {
	zone := signedTestZone(t)
	rrs := BuildZoneTransfer(zone)

	// owned[name][type] is every RRset the transfer carries.
	owned := make(map[string]map[uint16][]dns.RR)
	for _, rr := range rrs {
		name := dns.CanonicalName(rr.Header().Name)
		if owned[name] == nil {
			owned[name] = make(map[uint16][]dns.RR)
		}
		owned[name][rr.Header().Rrtype] = append(owned[name][rr.Header().Rrtype], rr)
	}

	sigs := owned["www.example.com."][dns.TypeRRSIG]
	require.NotEmpty(t, sigs, "www signatures transfer under www")
	for _, rr := range rrs {
		sig, ok := rr.(*dns.RRSIG)
		if !ok {
			continue
		}
		covered := owned[dns.CanonicalName(sig.Hdr.Name)][sig.TypeCovered]
		assert.NotEmpty(t, covered, "RRSIG %s/%s has no RRset at its owner",
			sig.Hdr.Name, dns.TypeToString[sig.TypeCovered])
	}

	verifyRRSIG(t, findRRSIG(t, sigs, dns.TypeA),
		owned["www.example.com."][dns.TypeA], owned["example.com."][dns.TypeDNSKEY])
}

func TestBuildZoneTransfer_RRSIGWithoutOwnerIsApex(t *testing.T) {
	zone := testTransferZone()
	zone.RecordSet.RRSIGRecords = []*entities.RRSIGRecord{
		{TypeCovered: "SOA", Algorithm: 13, Labels: 2, OriginalTTL: 3600, SignerName: "example.com."},
	}

	for _, rr := range BuildZoneTransfer(zone) {
		if sig, ok := rr.(*dns.RRSIG); ok {
			assert.Equal(t, "example.com.", sig.Hdr.Name)
			return
		}
	}
	t.Fatal("transfer carries no RRSIG")
}

func TestZoneOwnerNames_IncludesRRSIGOwner(t *testing.T) {
	zone := &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			RRSIGRecords: []*entities.RRSIGRecord{{Name: "signed.example.com.", TypeCovered: "A"}},
		},
	}

	assert.Contains(t, zoneOwnerNames(zone), "signed.example.com.")
	assert.NotContains(t, zoneDataOwnerNames(zone), "signed.example.com.",
		"a signature is not data the NSEC chain is built from")
}
