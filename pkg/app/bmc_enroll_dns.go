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

package app

import (
	"context"
	"net"
	"strings"

	dnsentities "github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
)

// bmcRecordTTL is the TTL of the A record the dns-register step writes.
const bmcRecordTTL = 3600

// bmcZoneStore is the part of the DNS service the dns-register step writes
// through. *dns.Service satisfies it.
type bmcZoneStore interface {
	Zone(ctx context.Context, zoneName string) (*dnsentities.Zone, error)
	Save(ctx context.Context, zone *dnsentities.Zone) error
}

// registerBMCRecord points the A record <hostname>-bmc.<zoneName> at address
// in the platform's internal zone and returns the record's FQDN.
//
// The record is the platform's own, so it is written straight into the zone,
// as RegisterWebservice writes the web service's record; dns.allow-registration
// gates caller-driven dynamic registration and does not apply here.
// Re-enrolling a BMC updates its record rather than adding a second one.
func registerBMCRecord(ctx context.Context, zones bmcZoneStore, hostname, address, zoneName string) (string, error) {
	ip := net.ParseIP(address)
	if ip == nil || ip.To4() == nil {
		return "", ErrBMCDNSInvalidAddress{Address: address}
	}
	if !strings.HasSuffix(zoneName, ".") {
		zoneName += "."
	}

	zone, err := zones.Zone(ctx, zoneName)
	if err != nil {
		return "", err
	}

	name := hostname + "-bmc"
	if record := findARecord(zone, name); record != nil {
		record.Value = address
	} else {
		zone.AddARecord(&dnsentities.ARecord{Name: name, Value: address, TTL: bmcRecordTTL})
	}
	if err := zones.Save(ctx, zone); err != nil {
		return "", err
	}
	return name + "." + zoneName, nil
}

// findARecord returns the zone's A record called name, or nil.
func findARecord(zone *dnsentities.Zone, name string) *dnsentities.ARecord {
	for _, record := range zone.RecordSet.ARecords {
		if record.Name == name {
			return record
		}
	}
	return nil
}
