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
	"errors"
	"net/netip"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
)

// The record checks every API transport applies before it changes a zone.
var (
	ErrRecordNameRequired = errors.New("dns: record name is required")
	ErrInvalidIPv4Address = errors.New("dns: A record value must be an IPv4 address (RFC 1035 §3.4.1)")
	ErrInvalidIPv6Address = errors.New("dns: AAAA record value must be an IPv6 address (RFC 3596 §2.2)")
	ErrInvalidTLSAUsage   = errors.New("dns: TLSA certificate usage must be 0 to 3 (RFC 6698 §2.1.1, RFC 7218 §2.1)")
)

// maxTLSAUsage is DANE-EE(3), the highest certificate usage RFC 7218 §2.1
// assigns.
const maxTLSAUsage = 3

// ValidateRecordName rejects a record without an owner name.
func ValidateRecordName(name string) error {
	if name == "" {
		return ErrRecordNameRequired
	}
	return nil
}

// ValidateARecordValue accepts only a dotted-quad IPv4 address.
func ValidateARecordValue(value string) error {
	addr, err := netip.ParseAddr(value)
	if err != nil || !addr.Is4() {
		return &DetailError{Err: ErrInvalidIPv4Address, Detail: ": " + value}
	}
	return nil
}

// ValidateAAAARecordValue accepts only an IPv6 address; an IPv4 address,
// written plainly or IPv4-mapped, belongs in an A record.
func ValidateAAAARecordValue(value string) error {
	addr, err := netip.ParseAddr(value)
	if err != nil || !addr.Is6() || addr.Is4In6() {
		return &DetailError{Err: ErrInvalidIPv6Address, Detail: ": " + value}
	}
	return nil
}

// recordValueValidators holds the value check of each record type whose value
// has a fixed syntax; a type without one accepts any value.
var recordValueValidators = map[string]func(string) error{
	"A":    ValidateARecordValue,
	"AAAA": ValidateAAAARecordValue,
}

// ValidateRecordValue applies the value check of recordType, so a record
// update can refuse a bad new value before it removes the old record.
func ValidateRecordValue(recordType, value string) error {
	validate, ok := recordValueValidators[strings.ToUpper(recordType)]
	if !ok {
		return nil
	}
	return validate(value)
}

// ValidateTLSAUsage accepts the certificate usages PKIX-TA(0) to DANE-EE(3).
func ValidateTLSAUsage(usage uint32) error {
	if usage > maxTLSAUsage {
		return ErrInvalidTLSAUsage
	}
	return nil
}

// FindRecord returns the record of recordType that name owns in rs. A name
// that owns no such record is a RecordError wrapping ErrRecordNotFound.
func FindRecord(rs *entities.RecordSet, recordType, name string) (interface{}, error) {
	kind, err := lookupRecordKind(recordType)
	if err != nil {
		return nil, err
	}

	for _, rec := range kind.records(rs) {
		if rec.name == name {
			return rec.record, nil
		}
	}

	return nil, &RecordError{Op: "find", Type: recordType, Name: name, Err: ErrRecordNotFound}
}
