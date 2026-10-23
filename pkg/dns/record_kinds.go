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
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/miekg/dns"
)

// recordKind is one record type the record API (AddRecord, DeleteRecord,
// GetRecord, ListRecords) manages. The set is the one ResolveName serves. SOA
// belongs to the zone, and the DNSSEC types are written by signing, so neither
// is managed here.
type recordKind struct {
	// add stores a record of the type, parsed from its value.
	add func(zone *entities.Zone, name, value string, ttl uint32) error
	// remove deletes the first record of the type that name owns.
	remove func(zone *entities.Zone, name string)
	// records lists the stored records of the type with their owner names.
	records func(rs *entities.RecordSet) []ownedRecord
}

// ownedRecord is a stored record and its owner name.
type ownedRecord struct {
	name   string
	record interface{}
}

// recordKindOrder is the order ListRecords returns the types in.
var recordKindOrder = []string{"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SRV", "CAA", "TLSA"}

// recordKinds maps a record type mnemonic to the record API's handling of it.
// A, AAAA, CNAME, MX, NS and TXT store the value as it is given (an MX value
// is the exchange). SRV, CAA and TLSA parse the value as the RDATA in its
// zone-file presentation form (RFC 1035 §5.1): "priority weight port target"
// (RFC 2782), "flags tag value" (RFC 8659 §4.1) and
// "usage selector matching-type data" (RFC 6698 §2.2).
var recordKinds = map[string]recordKind{
	"A": {
		add: func(zone *entities.Zone, name, value string, ttl uint32) error {
			zone.AddARecord(&entities.ARecord{Name: name, Value: value, TTL: ttl})
			return nil
		},
		remove: (*entities.Zone).RemoveARecord,
		records: func(rs *entities.RecordSet) []ownedRecord {
			return owned(rs.ARecords, func(r *entities.ARecord) string { return r.Name })
		},
	},
	"AAAA": {
		add: func(zone *entities.Zone, name, value string, ttl uint32) error {
			zone.AddAAAARecord(&entities.AAAARecord{Name: name, Value: value, TTL: ttl})
			return nil
		},
		remove: (*entities.Zone).RemoveAAAARecord,
		records: func(rs *entities.RecordSet) []ownedRecord {
			return owned(rs.AAAARecords, func(r *entities.AAAARecord) string { return r.Name })
		},
	},
	"CNAME": {
		add: func(zone *entities.Zone, name, value string, ttl uint32) error {
			zone.AddCNAMERecord(&entities.CNAMERecord{Name: name, Value: value, TTL: ttl})
			return nil
		},
		remove: (*entities.Zone).RemoveCNAMERecord,
		records: func(rs *entities.RecordSet) []ownedRecord {
			return owned(rs.CNAMERecords, func(r *entities.CNAMERecord) string { return r.Name })
		},
	},
	"MX": {
		add: func(zone *entities.Zone, name, value string, ttl uint32) error {
			zone.AddMXRecord(&entities.MXRecord{Name: name, Value: value, TTL: ttl})
			return nil
		},
		remove: (*entities.Zone).RemoveMXRecord,
		records: func(rs *entities.RecordSet) []ownedRecord {
			return owned(rs.MXRecords, func(r *entities.MXRecord) string { return r.Name })
		},
	},
	"NS": {
		add: func(zone *entities.Zone, name, value string, ttl uint32) error {
			zone.AddNSRecord(&entities.NSRecord{Name: name, Value: value, TTL: ttl})
			return nil
		},
		remove: (*entities.Zone).RemoveNSRecord,
		records: func(rs *entities.RecordSet) []ownedRecord {
			return owned(rs.NSRecords, func(r *entities.NSRecord) string { return r.Name })
		},
	},
	"TXT": {
		add: func(zone *entities.Zone, name, value string, ttl uint32) error {
			zone.AddTXTRecord(&entities.TXTRecord{Name: name, Value: value, TTL: ttl})
			return nil
		},
		remove: (*entities.Zone).RemoveTXTRecord,
		records: func(rs *entities.RecordSet) []ownedRecord {
			return owned(rs.TXTRecords, func(r *entities.TXTRecord) string { return r.Name })
		},
	},
	"SRV": {
		add: func(zone *entities.Zone, name, value string, ttl uint32) error {
			srv, err := parseRData[*dns.SRV]("SRV", value)
			if err != nil {
				return err
			}
			zone.AddSRVRecord(&entities.SRVRecord{
				Name:     name,
				Priority: srv.Priority,
				Weight:   srv.Weight,
				Port:     srv.Port,
				Target:   srv.Target,
				TTL:      ttl,
			})
			return nil
		},
		remove: (*entities.Zone).RemoveSRVRecord,
		records: func(rs *entities.RecordSet) []ownedRecord {
			return owned(rs.SRVRecords, func(r *entities.SRVRecord) string { return r.Name })
		},
	},
	"CAA": {
		add: func(zone *entities.Zone, name, value string, ttl uint32) error {
			caa, err := parseRData[*dns.CAA]("CAA", value)
			if err != nil {
				return err
			}
			zone.AddCAARecord(&entities.CAARecord{Name: name, Flags: caa.Flag, Tag: caa.Tag, Value: caa.Value, TTL: ttl})
			return nil
		},
		remove: (*entities.Zone).RemoveCAARecord,
		records: func(rs *entities.RecordSet) []ownedRecord {
			return owned(rs.CAARecords, func(r *entities.CAARecord) string { return r.Name })
		},
	},
	"TLSA": {
		add: func(zone *entities.Zone, name, value string, ttl uint32) error {
			tlsa, err := parseRData[*dns.TLSA]("TLSA", value)
			if err != nil {
				return err
			}
			zone.AddTLSARecord(&entities.TLSARecord{
				Name:         name,
				Usage:        tlsa.Usage,
				Selector:     tlsa.Selector,
				MatchingType: tlsa.MatchingType,
				Data:         tlsa.Certificate,
				TTL:          ttl,
			})
			return nil
		},
		remove: (*entities.Zone).RemoveTLSARecord,
		records: func(rs *entities.RecordSet) []ownedRecord {
			return owned(rs.TLSARecords, func(r *entities.TLSARecord) string { return r.Name })
		},
	},
}

// lookupRecordKind returns the handling of recordType (a mnemonic, any case),
// or ErrRecordTypeNotSupported.
func lookupRecordKind(recordType string) (recordKind, error) {
	kind, ok := recordKinds[strings.ToUpper(recordType)]
	if !ok {
		return recordKind{}, &DetailError{Err: ErrRecordTypeNotSupported, Detail: ": " + recordType}
	}
	return kind, nil
}

// owned pairs each record with its owner name.
func owned[T any](records []*T, owner func(*T) string) []ownedRecord {
	pairs := make([]ownedRecord, 0, len(records))
	for _, record := range records {
		pairs = append(pairs, ownedRecord{name: owner(record), record: record})
	}
	return pairs
}

// parseRData parses value as the presentation-form RDATA of recordType. A
// value that is empty, malformed or not of the type is ErrInvalidRecordValue.
func parseRData[T dns.RR](recordType, value string) (T, error) {
	var zero T
	if strings.TrimSpace(value) == "" {
		return zero, &DetailError{Err: ErrInvalidRecordValue, Detail: ": empty " + recordType + " value"}
	}
	rr, err := dns.NewRR(". IN " + recordType + " " + value)
	if err != nil {
		return zero, &SentinelCauseError{Sentinel: ErrInvalidRecordValue, Cause: err}
	}
	parsed, ok := rr.(T)
	if !ok {
		return zero, &DetailError{Err: ErrInvalidRecordValue, Detail: ": " + recordType + " " + value}
	}
	return parsed, nil
}
