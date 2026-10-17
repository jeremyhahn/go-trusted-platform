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
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/miekg/dns"
)

// ZoneReader looks a managed zone up by name. Every DNSService is one.
type ZoneReader interface {
	Zone(ctx context.Context, zoneName string) (*entities.Zone, error)
}

// Resolution is the answer the managed zones give for one name
// (docs/dns/resolution.md, "API resolve").
type Resolution struct {
	// Zone is the managed zone holding the name; empty when none does.
	Zone string

	// Authoritative is true when a managed zone holds the name. Records may
	// then be empty: the zone has no such records.
	Authoritative bool

	// Records holds only the records the queried name owns, of the
	// requested type.
	Records entities.RecordSet
}

// recordSelector copies the src records of one type that owns accepts into
// dst.
type recordSelector func(dst, src *entities.RecordSet, owns func(owner string) bool)

// recordSelectors are the record types resolution answers, by mnemonic.
var recordSelectors = map[string]recordSelector{
	"A": func(dst, src *entities.RecordSet, owns func(string) bool) {
		dst.ARecords = selectOwned(src.ARecords, owns, func(r *entities.ARecord) string { return r.Name })
	},
	"AAAA": func(dst, src *entities.RecordSet, owns func(string) bool) {
		dst.AAAARecords = selectOwned(src.AAAARecords, owns, func(r *entities.AAAARecord) string { return r.Name })
	},
	"CNAME": func(dst, src *entities.RecordSet, owns func(string) bool) {
		dst.CNAMERecords = selectOwned(src.CNAMERecords, owns, func(r *entities.CNAMERecord) string { return r.Name })
	},
	"MX": func(dst, src *entities.RecordSet, owns func(string) bool) {
		dst.MXRecords = selectOwned(src.MXRecords, owns, func(r *entities.MXRecord) string { return r.Name })
	},
	"NS": func(dst, src *entities.RecordSet, owns func(string) bool) {
		dst.NSRecords = selectOwned(src.NSRecords, owns, func(r *entities.NSRecord) string { return r.Name })
	},
	"TXT": func(dst, src *entities.RecordSet, owns func(string) bool) {
		dst.TXTRecords = selectOwned(src.TXTRecords, owns, func(r *entities.TXTRecord) string { return r.Name })
	},
	"SRV": func(dst, src *entities.RecordSet, owns func(string) bool) {
		dst.SRVRecords = selectOwned(src.SRVRecords, owns, func(r *entities.SRVRecord) string { return r.Name })
	},
	"CAA": func(dst, src *entities.RecordSet, owns func(string) bool) {
		dst.CAARecords = selectOwned(src.CAARecords, owns, func(r *entities.CAARecord) string { return r.Name })
	},
	"TLSA": func(dst, src *entities.RecordSet, owns func(string) bool) {
		dst.TLSARecords = selectOwned(src.TLSARecords, owns, func(r *entities.TLSARecord) string { return r.Name })
	},
}

// resolvedValues renders the values Service.Resolve returns, by the record
// types it serves.
var resolvedValues = map[string]func(rs *entities.RecordSet) []string{
	"A": func(rs *entities.RecordSet) []string {
		return recordValues(rs.ARecords, func(r *entities.ARecord) string { return r.Value })
	},
	"AAAA": func(rs *entities.RecordSet) []string {
		return recordValues(rs.AAAARecords, func(r *entities.AAAARecord) string { return r.Value })
	},
	"CNAME": func(rs *entities.RecordSet) []string {
		return recordValues(rs.CNAMERecords, func(r *entities.CNAMERecord) string { return r.Value })
	},
	"MX": func(rs *entities.RecordSet) []string {
		return recordValues(rs.MXRecords, func(r *entities.MXRecord) string { return r.Value })
	},
	"NS": func(rs *entities.RecordSet) []string {
		return recordValues(rs.NSRecords, func(r *entities.NSRecord) string { return r.Value })
	},
	"TXT": func(rs *entities.RecordSet) []string {
		return recordValues(rs.TXTRecords, func(r *entities.TXTRecord) string { return r.Value })
	},
}

// ResolveName answers name from the managed zones. It is the one resolution
// every transport serves.
//
// The zone is the managed zone with the longest suffix of name. Only records
// whose owner IS name answer, filtered by recordType (a mnemonic, any case;
// empty means every type). Names compare case-insensitively and the trailing
// dot is optional. A name under no managed zone is a non-authoritative empty
// answer; a name inside one with no matching records is an authoritative
// empty answer. A record type resolution does not serve is
// ErrRecordTypeNotSupported.
func ResolveName(ctx context.Context, zones ZoneReader, name, recordType string) (*Resolution, error) {
	selectors := recordSelectors
	if recordType != "" {
		selector, ok := recordSelectors[strings.ToUpper(recordType)]
		if !ok {
			return nil, &DetailError{Err: ErrRecordTypeNotSupported, Detail: ": " + recordType}
		}
		selectors = map[string]recordSelector{recordType: selector}
	}

	zone := enclosingZone(ctx, zones, name)
	if zone == nil {
		return &Resolution{}, nil
	}

	owns := func(owner string) bool { return resolvedOwnerIs(owner, name, zone.Name) }
	resolution := &Resolution{Zone: dns.Fqdn(zone.Name), Authoritative: true}
	for _, selector := range selectors {
		selector(&resolution.Records, &zone.RecordSet, owns)
	}
	return resolution, nil
}

// enclosingZone returns the managed zone with the longest suffix of name, or
// nil when no zone holds it or the caller may not read the zone that does.
func enclosingZone(ctx context.Context, zones ZoneReader, name string) *entities.Zone {
	zone, err := lookupEnclosingZone(ctx, zones, name)
	if err != nil {
		return nil
	}
	return zone
}

// lookupEnclosingZone returns the managed zone with the longest suffix of
// name. Each suffix is tried lower-cased, then as written. A zone the caller
// may not read ends the walk with ErrUnauthorizedZoneAccess: the name belongs
// to that zone, not to a shorter one the caller happens to own. With no zone
// holding the name the error is ErrZoneNotFound.
func lookupEnclosingZone(ctx context.Context, zones ZoneReader, name string) (*entities.Zone, error) {
	labels := dns.SplitDomainName(name)
	for i := range labels {
		suffix := dns.Fqdn(strings.Join(labels[i:], "."))
		candidates := []string{dns.CanonicalName(suffix)}
		if suffix != candidates[0] {
			candidates = append(candidates, suffix)
		}
		for _, candidate := range candidates {
			zone, err := zones.Zone(ctx, candidate)
			if err == nil {
				return zone, nil
			}
			if errors.Is(err, ErrUnauthorizedZoneAccess) {
				return nil, err
			}
		}
	}
	return nil, ErrZoneNotFound
}

// resolvedOwnerIs reports whether a stored owner names qname. Besides the
// three stored forms the wire plugin reads (ownerMatchesQuery), an owner
// written absolute without its trailing dot — the shape AddRecord stores —
// names itself.
func resolvedOwnerIs(owner, qname, zoneName string) bool {
	if ownerMatchesQuery(owner, qname, zoneName) {
		return true
	}
	return owner != "" && owner != "@" && equalNames(owner, qname)
}

// recordValues returns each record's value, in order.
func recordValues[R any](records []*R, valueOf func(*R) string) []string {
	values := make([]string, 0, len(records))
	for _, record := range records {
		values = append(values, valueOf(record))
	}
	return values
}

// selectOwned returns the records whose owner owns accepts.
func selectOwned[R any](records []*R, owns func(owner string) bool, ownerOf func(*R) string) []*R {
	var owned []*R
	for _, record := range records {
		if owns(ownerOf(record)) {
			owned = append(owned, record)
		}
	}
	return owned
}
