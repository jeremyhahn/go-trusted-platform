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

package main

import (
	"log/slog"
	"strings"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/platform"
)

// DNSBinding exposes DNS service methods to the Wails frontend.
type DNSBinding struct {
	logger *slog.Logger
	conn   *ConnectionBinding
}

// NewDNSBinding creates a new DNSBinding.
func NewDNSBinding(logger *slog.Logger, conn *ConnectionBinding) *DNSBinding {
	return &DNSBinding{logger: logger, conn: conn}
}

// getClient returns the current platform client or an error.
func (b *DNSBinding) getClient() (platform.Client, error) {
	cl, err := b.conn.loadClient()
	if err != nil {
		return nil, err
	}
	return *cl, nil
}

// CreateZone creates a new DNS zone.
func (b *DNSBinding) CreateZone(name string, ttl uint32, description string, internal bool) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.DNS().CreateZone(b.conn.ctx, &platformv1.CreateZoneRequest{
		Name:        name,
		Ttl:         ttl,
		Description: description,
		Internal:    internal,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// GetZone returns a DNS zone by name.
func (b *DNSBinding) GetZone(name string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.DNS().GetZone(b.conn.ctx, &platformv1.GetZoneRequest{
		Name: name,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// DeleteZone deletes a DNS zone by name.
func (b *DNSBinding) DeleteZone(name string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.DNS().DeleteZone(b.conn.ctx, &platformv1.DeleteZoneRequest{
		Name: name,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// ListZones returns all DNS zones with optional filters.
func (b *DNSBinding) ListZones(internalOnly, publicOnly bool) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.DNS().ListZones(b.conn.ctx, &platformv1.ListZonesRequest{
		InternalOnly: internalOnly,
		PublicOnly:   publicOnly,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// AddRecord adds a DNS record to a zone. The recordType should be A, AAAA,
// CNAME, MX, NS, or TXT.
func (b *DNSBinding) AddRecord(zoneName, recordName, recordType, value string, ttl uint32) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	rType, err := parseRecordType(recordType)
	if err != nil {
		return nil, err
	}
	record, err := buildRecord(rType, recordName, value, ttl)
	if err != nil {
		return nil, err
	}
	resp, err := cl.DNS().AddRecord(b.conn.ctx, &platformv1.AddRecordRequest{
		ZoneName: zoneName,
		Record:   record,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// DeleteRecord removes a DNS record from a zone.
func (b *DNSBinding) DeleteRecord(zoneName, recordType, recordName string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	rType, err := parseRecordType(recordType)
	if err != nil {
		return nil, err
	}
	resp, err := cl.DNS().DeleteRecord(b.conn.ctx, &platformv1.DeleteRecordRequest{
		ZoneName: zoneName,
		Type:     rType,
		Name:     recordName,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// ListRecords returns all records in a zone, optionally filtered by type.
// Pass an empty string for recordType to list all records.
func (b *DNSBinding) ListRecords(zoneName, recordType string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	var rType platformv1.RecordType
	if recordType != "" {
		parsed, parseErr := parseRecordType(recordType)
		if parseErr != nil {
			return nil, parseErr
		}
		rType = parsed
	}
	resp, err := cl.DNS().ListRecords(b.conn.ctx, &platformv1.ListRecordsRequest{
		ZoneName: zoneName,
		Type:     rType,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// Resolve resolves a fully qualified domain name.
func (b *DNSBinding) Resolve(fqdn, recordType string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	rType, err := parseRecordType(recordType)
	if err != nil {
		return nil, err
	}
	resp, err := cl.DNS().Resolve(b.conn.ctx, &platformv1.ResolveRequest{
		Fqdn: fqdn,
		Type: rType,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// GetDNSSECStatus returns the DNSSEC status for a zone.
func (b *DNSBinding) GetDNSSECStatus(zoneName string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.DNS().GetDNSSECStatus(b.conn.ctx, &platformv1.GetDNSSECStatusRequest{
		ZoneName: zoneName,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// SignZone signs a DNS zone with DNSSEC.
func (b *DNSBinding) SignZone(zoneName string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.DNS().SignZone(b.conn.ctx, &platformv1.SignZoneRequest{
		ZoneName: zoneName,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// Register registers an FQDN with an IP address.
func (b *DNSBinding) Register(fqdn, ip string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.DNS().Register(b.conn.ctx, &platformv1.RegisterRequest{
		Fqdn: fqdn,
		Ip:   ip,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// InvalidRecordTypeError indicates an unrecognized DNS record type string.
type InvalidRecordTypeError struct {
	Input string
}

// Error returns the error message.
func (e *InvalidRecordTypeError) Error() string {
	return "invalid DNS record type: " + e.Input
}

// UnsupportedRecordTypeError indicates a record type that cannot be
// constructed from simple name/value parameters.
type UnsupportedRecordTypeError struct {
	Type string
}

// Error returns the error message.
func (e *UnsupportedRecordTypeError) Error() string {
	return "unsupported record type for simple add: " + e.Type
}

// parseRecordType converts a record type string to the protobuf enum.
func parseRecordType(input string) (platformv1.RecordType, error) {
	upper := strings.ToUpper(input)

	// Try full enum name first.
	if val, ok := platformv1.RecordType_value[upper]; ok {
		return platformv1.RecordType(val), nil
	}

	// Try with RECORD_TYPE_ prefix.
	prefixed := "RECORD_TYPE_" + upper
	if val, ok := platformv1.RecordType_value[prefixed]; ok {
		return platformv1.RecordType(val), nil
	}

	return platformv1.RecordType(0), &InvalidRecordTypeError{Input: input}
}

// buildRecord constructs a Record protobuf message with the correct oneof
// variant based on the record type.
func buildRecord(rType platformv1.RecordType, name, value string, ttl uint32) (*platformv1.Record, error) {
	record := &platformv1.Record{Type: rType}

	switch rType {
	case platformv1.RecordType_RECORD_TYPE_A:
		record.Record = &platformv1.Record_A{
			A: &platformv1.ARecord{Name: name, Value: value, Ttl: ttl},
		}
	case platformv1.RecordType_RECORD_TYPE_AAAA:
		record.Record = &platformv1.Record_Aaaa{
			Aaaa: &platformv1.AAAARecord{Name: name, Value: value, Ttl: ttl},
		}
	case platformv1.RecordType_RECORD_TYPE_CNAME:
		record.Record = &platformv1.Record_Cname{
			Cname: &platformv1.CNAMERecord{Name: name, Value: value, Ttl: ttl},
		}
	case platformv1.RecordType_RECORD_TYPE_MX:
		record.Record = &platformv1.Record_Mx{
			Mx: &platformv1.MXRecord{Name: name, Value: value, Ttl: ttl},
		}
	case platformv1.RecordType_RECORD_TYPE_NS:
		record.Record = &platformv1.Record_Ns{
			Ns: &platformv1.NSRecord{Name: name, Value: value, Ttl: ttl},
		}
	case platformv1.RecordType_RECORD_TYPE_TXT:
		record.Record = &platformv1.Record_Txt{
			Txt: &platformv1.TXTRecord{Name: name, Value: value, Ttl: ttl},
		}
	default:
		return nil, &UnsupportedRecordTypeError{Type: rType.String()}
	}

	return record, nil
}
