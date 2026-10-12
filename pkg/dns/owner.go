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
	"sort"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/miekg/dns"
)

// recordOwnerFQDN resolves a stored record owner name to a fully qualified
// name within the zone. An empty name or "@" maps to the zone apex; a name
// that is already fully qualified is returned unchanged; a relative label is
// joined to the zone apex.
func recordOwnerFQDN(name, zoneName string) string {
	zoneFQDN := dns.Fqdn(zoneName)
	if name == "" || name == "@" {
		return zoneFQDN
	}
	if dns.IsFqdn(name) {
		return name
	}
	return dns.Fqdn(name + "." + strings.TrimSuffix(zoneFQDN, "."))
}

// ownerMatchesQuery reports whether a stored record owner name denotes the
// queried name within the zone. Owners are stored either relative to the zone
// ("www", or "@" for the apex) or fully qualified ("www.example.com."); both
// forms resolve to the same FQDN before comparison. Comparison is
// case-insensitive and trailing-dot insensitive per RFC 4343 §3.
//
// A record owner matches the query only when the WHOLE name matches. Matching
// the query's first label alone made every record a de-facto wildcard across
// every subdomain depth, so a zone holding "www" answered for
// www.anything.example.com as readily as for www.example.com.
func ownerMatchesQuery(ownerName, qname, zoneName string) bool {
	return dns.CanonicalName(recordOwnerFQDN(ownerName, zoneName)) == dns.CanonicalName(qname)
}

// equalNames compares two domain names case- and trailing-dot insensitively
// (RFC 4343 §3).
func equalNames(a, b string) bool {
	return dns.CanonicalName(a) == dns.CanonicalName(b)
}

// isZoneApex reports whether the queried name is the top of the zone. The
// SOA is owned by the apex and by nothing else.
func isZoneApex(qname, zoneName string) bool {
	return equalNames(qname, zoneName)
}

// zoneDataOwnerNames returns the owner names the zone's DATA records define,
// resolved to FQDNs, deduplicated and canonically sorted. The zone apex is
// always present: it owns the SOA.
//
// DNSSEC meta-records (DNSKEY, DS, NSEC, NSEC3, NSEC3PARAM, RRSIG) are
// deliberately excluded. The signer generates them FROM this set, so including
// them would feed the NSEC/NSEC3 chain its own output. Use zoneOwnerNames for
// the question "does this name exist", which they do answer.
func zoneDataOwnerNames(zone *entities.Zone) []string {
	return sortedOwnerNames(dataOwnerNameSet(zone))
}

// zoneOwnerNames returns EVERY owner name in the zone, DNSSEC meta-records
// included, resolved to FQDNs, deduplicated and canonically sorted. A name
// that owns only an NSEC3 or a DS record is still a name the zone defines.
func zoneOwnerNames(zone *entities.Zone) []string {
	zoneFQDN := dns.Fqdn(zone.Name)
	names := dataOwnerNameSet(zone)

	add := func(name string) {
		names[recordOwnerFQDN(name, zoneFQDN)] = struct{}{}
	}
	for _, r := range zone.RecordSet.DNSKEYRecords {
		add(r.Name)
	}
	for _, r := range zone.RecordSet.DSRecords {
		add(r.Name)
	}
	for _, r := range zone.RecordSet.NSECRecords {
		add(r.Name)
	}
	for _, r := range zone.RecordSet.NSEC3Records {
		add(r.Name)
	}
	for _, r := range zone.RecordSet.NSEC3PARAMRecords {
		add(r.Name)
	}
	for _, r := range zone.RecordSet.RRSIGRecords {
		add(r.Name)
	}
	return sortedOwnerNames(names)
}

// dataOwnerNameSet collects the owner names of the zone's data records, plus
// the apex, resolved to FQDNs.
func dataOwnerNameSet(zone *entities.Zone) map[string]struct{} {
	zoneFQDN := dns.Fqdn(zone.Name)
	names := map[string]struct{}{zoneFQDN: {}}

	add := func(name string) {
		names[recordOwnerFQDN(name, zoneFQDN)] = struct{}{}
	}
	for _, r := range zone.RecordSet.ARecords {
		add(r.Name)
	}
	for _, r := range zone.RecordSet.AAAARecords {
		add(r.Name)
	}
	for _, r := range zone.RecordSet.CNAMERecords {
		add(r.Name)
	}
	for _, r := range zone.RecordSet.MXRecords {
		add(r.Name)
	}
	for _, r := range zone.RecordSet.NSRecords {
		add(r.Name)
	}
	for _, r := range zone.RecordSet.TXTRecords {
		add(r.Name)
	}
	for _, r := range zone.RecordSet.SRVRecords {
		add(r.Name)
	}
	for _, r := range zone.RecordSet.CAARecords {
		add(r.Name)
	}
	for _, r := range zone.RecordSet.TLSARecords {
		add(r.Name)
	}
	return names
}

// sortedOwnerNames flattens an owner-name set into canonical DNS order, so
// callers that build an ordered chain from it get a deterministic result.
func sortedOwnerNames(names map[string]struct{}) []string {
	owners := make([]string, 0, len(names))
	for name := range names {
		owners = append(owners, name)
	}
	sort.Slice(owners, func(i, j int) bool {
		return dns.CanonicalName(owners[i]) < dns.CanonicalName(owners[j])
	})
	return owners
}

// ownsNonDelegationData reports whether a name owns data in this zone beyond
// what a delegation may carry. A zone cut holds the child's NS records and, at
// most, a DS and the DNSSEC records proving it; authoritative data and a cut
// cannot share an owner in the same zone (RFC 2181 §6.1).
//
// The distinction matters because an NS record stored under a hostname rather
// than the apex used to resolve anyway — the resolver matched no owner names
// at all — and zones seeded from older templates still carry that shape
// alongside the hostname's own address records.
func ownsNonDelegationData(zone *entities.Zone, owner string) bool {
	rs := &zone.RecordSet
	for _, r := range rs.ARecords {
		if ownerMatchesQuery(r.Name, owner, zone.Name) {
			return true
		}
	}
	for _, r := range rs.AAAARecords {
		if ownerMatchesQuery(r.Name, owner, zone.Name) {
			return true
		}
	}
	for _, r := range rs.CNAMERecords {
		if ownerMatchesQuery(r.Name, owner, zone.Name) {
			return true
		}
	}
	for _, r := range rs.MXRecords {
		if ownerMatchesQuery(r.Name, owner, zone.Name) {
			return true
		}
	}
	for _, r := range rs.TXTRecords {
		if ownerMatchesQuery(r.Name, owner, zone.Name) {
			return true
		}
	}
	for _, r := range rs.SRVRecords {
		if ownerMatchesQuery(r.Name, owner, zone.Name) {
			return true
		}
	}
	for _, r := range rs.CAARecords {
		if ownerMatchesQuery(r.Name, owner, zone.Name) {
			return true
		}
	}
	for _, r := range rs.TLSARecords {
		if ownerMatchesQuery(r.Name, owner, zone.Name) {
			return true
		}
	}
	return false
}

// zoneHasName reports whether the queried name exists in the zone, which is
// what separates the two kinds of negative answer (RFC 2308 §2): a name that
// exists but holds no record of the queried type is NODATA, and a name that
// exists nowhere in the zone is NXDOMAIN.
//
// A name exists when it owns a record, when it is the zone apex, or when it is
// an empty non-terminal — an interior node with no records of its own but with
// records beneath it, such as example.com. given a.b.example.com. RFC 1034
// §4.3.2 makes the empty non-terminal an existing name, so it is NODATA and
// never NXDOMAIN.
func zoneHasName(zone *entities.Zone, qname string) bool {
	q := dns.CanonicalName(qname)
	for _, owner := range zoneOwnerNames(zone) {
		o := dns.CanonicalName(owner)
		if o == q || strings.HasSuffix(o, "."+q) {
			return true
		}
	}
	return false
}
