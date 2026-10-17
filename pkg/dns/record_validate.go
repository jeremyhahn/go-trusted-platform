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
	"net/netip"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrRecordNameRequired is returned when a record added through the API has
// no owner name. An API caller names the zone apex with "@".
type ErrRecordNameRequired struct {
	Type string
}

func (e ErrRecordNameRequired) Error() string {
	return fmt.Sprintf("dns: %s record name is required (use @ for the zone apex)", e.Type)
}

// GRPCStatus classes the refusal as InvalidArgument on every transport.
func (e ErrRecordNameRequired) GRPCStatus() *status.Status {
	return status.New(codes.InvalidArgument, e.Error())
}

// ErrInvalidRecordAddress is returned when an A record's value is not an IPv4
// address (RFC 1035 §3.4.1) or an AAAA record's value is not an IPv6 address
// (RFC 3596 §2.2).
type ErrInvalidRecordAddress struct {
	Type  string
	Value string
}

func (e ErrInvalidRecordAddress) Error() string {
	family := "IPv4"
	if e.Type == "AAAA" {
		family = "IPv6"
	}
	return fmt.Sprintf("dns: %s record value %q is not an %s address", e.Type, e.Value, family)
}

// GRPCStatus classes the refusal as InvalidArgument on every transport.
func (e ErrInvalidRecordAddress) GRPCStatus() *status.Status {
	return status.New(codes.InvalidArgument, e.Error())
}

// addressFamilies holds the check of each record type whose value is an
// address: an A record carries a 32-bit IPv4 address (RFC 1035 §3.4.1), an
// AAAA record a 128-bit IPv6 address (RFC 3596 §2.2). A zoned address
// (fe80::1%eth0) has no place in a zone file, so it is refused too.
var addressFamilies = map[string]func(netip.Addr) bool{
	"A":    netip.Addr.Is4,
	"AAAA": netip.Addr.Is6,
}

// ValidateRecord refuses a record the API must not store: one with no owner
// name, or an A or AAAA record whose value is not an address of its family.
// recordType is matched case-insensitively; value is checked only for A and
// AAAA. Every transport's AddRecord calls it before the record is stored.
func ValidateRecord(recordType, name, value string) error {
	recordType = strings.ToUpper(recordType)
	if name == "" {
		return ErrRecordNameRequired{Type: recordType}
	}
	isFamily, ok := addressFamilies[recordType]
	if !ok {
		return nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil || addr.Zone() != "" || !isFamily(addr) {
		return ErrInvalidRecordAddress{Type: recordType, Value: value}
	}
	return nil
}
