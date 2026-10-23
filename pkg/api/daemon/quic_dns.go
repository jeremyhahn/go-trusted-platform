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

package daemon

import (
	"context"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// DNS QUIC transport.
//
// The DNS surface splits into two wire contracts:
//
//   - SDK-mapped operations (AddRecord 0x20, DeleteRecord 0x21,
//     ListRecords 0x24, AddZone/CreateZone 0x25, DeleteZone 0x26,
//     ListZones 0x28, Resolve 0x29) speak the platform.v1 protobuf wire
//     contract and delegate to the shared *DNSServiceServer. Their handlers,
//     mirror wire types, and error mapping live in quic_dns_delegate.go.
//
//   - Daemon-native operations (UpdateRecord 0x22, GetRecord 0x23,
//     GetZone 0x27, GetConfig 0x2A, GetMetrics 0x2C) have NO SDK QUIC
//     client. They are exercised only by the local CLI and integration
//     harness and keep their flat wire structs defined below.
//
// 0x2B and 0x2D (UpdateConfig, FlushCache) were retired unimplemented
// (#317): the DNS service has no runtime config update and no cache.
//
// The SDK QUIC adapter sends the generated platform.v1 request struct straight
// to the wire, so the SDK-mapped handlers MUST decode the same message the SDK
// sent; the previous flat DNSAddRecordRequest{Zone,Name,RecordType,Value} decode
// silently dropped every field because the Go field names did not match the pb.

// DNSUpdateRecordRequest represents a request to update a DNS record
type DNSUpdateRecordRequest struct {
	Zone       string `codec:"zone"`
	Name       string `codec:"name"`
	RecordType string `codec:"record_type"`
	Value      string `codec:"value"`
	TTL        int    `codec:"ttl"`
	Priority   uint16 `codec:"priority"`
}

// DNSUpdateRecordResponse represents the response after updating a DNS record
type DNSUpdateRecordResponse struct {
	Success   bool   `codec:"success"`
	Zone      string `codec:"zone"`
	Name      string `codec:"name"`
	Timestamp int64  `codec:"timestamp"`
}

// DNSGetRecordRequest represents a request to get a DNS record
type DNSGetRecordRequest struct {
	Zone       string `codec:"zone"`
	Name       string `codec:"name"`
	RecordType string `codec:"record_type"`
}

// DNSRecord represents a DNS record in QUIC responses
type DNSRecord struct {
	Name       string `codec:"name"`
	RecordType string `codec:"record_type"`
	Value      string `codec:"value"`
	TTL        uint32 `codec:"ttl"`
	Priority   uint16 `codec:"priority"`
}

// DNSGetRecordResponse represents the response containing a DNS record
type DNSGetRecordResponse struct {
	Record    *DNSRecord `codec:"record"`
	Zone      string     `codec:"zone"`
	Timestamp int64      `codec:"timestamp"`
}

// DNSGetZoneRequest represents a request to get a DNS zone
type DNSGetZoneRequest struct {
	Zone string `codec:"zone"`
}

// DNSZone represents a DNS zone in QUIC responses
type DNSZone struct {
	ID          uint64 `codec:"id"`
	Name        string `codec:"name"`
	TTL         uint32 `codec:"ttl"`
	Description string `codec:"description"`
	Internal    bool   `codec:"internal"`
	RecordCount int    `codec:"record_count"`
}

// DNSGetZoneResponse represents the response containing a DNS zone
type DNSGetZoneResponse struct {
	Zone      *DNSZone `codec:"zone"`
	Timestamp int64    `codec:"timestamp"`
}

// DNSGetConfigRequest represents a request to get DNS configuration
type DNSGetConfigRequest struct{}

// DNSConfig represents DNS service configuration
type DNSConfig struct {
	InternalDomain    string `codec:"internal_domain"`
	PublicDomain      string `codec:"public_domain"`
	DNSSECEnabled     bool   `codec:"dnssec_enabled"`
	AllowRegistration bool   `codec:"allow_registration"`
}

// DNSGetConfigResponse represents the response containing DNS configuration
type DNSGetConfigResponse struct {
	Config    *DNSConfig `codec:"config"`
	Timestamp int64      `codec:"timestamp"`
}

// DNSGetMetricsRequest represents a request to get DNS metrics
type DNSGetMetricsRequest struct{}

// DNSMetrics represents DNS service metrics
type DNSMetrics struct {
	ZoneCount        int   `codec:"zone_count"`
	TotalRecords     int   `codec:"total_records"`
	QueriesTotal     int64 `codec:"queries_total"`
	CacheHits        int64 `codec:"cache_hits"`
	CacheMisses      int64 `codec:"cache_misses"`
	DNSSECValidated  int64 `codec:"dnssec_validated"`
	ForwardedQueries int64 `codec:"forwarded_queries"`
}

// DNSGetMetricsResponse represents the response containing DNS metrics
type DNSGetMetricsResponse struct {
	Metrics   *DNSMetrics `codec:"metrics"`
	Timestamp int64       `codec:"timestamp"`
}

// handleDNSOperation routes DNS operations to their handlers. SDK-mapped
// operations delegate to the shared *DNSServiceServer (handlers in
// quic_dns_delegate.go); daemon-native operations use the flat wire structs
// in this file.
func (h *QUICServiceHandler) handleDNSOperation(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.dnsService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrDNSServiceNotAvailable{})
	}

	switch req.Opcode {
	// SDK-mapped operations (pb / mirror wire, delegated to *DNSServiceServer)
	case quicwire.OpDNSAddRecord:
		return h.handleDNSAddRecord(ctx, req)
	case quicwire.OpDNSDeleteRecord:
		return h.handleDNSDeleteRecord(ctx, req)
	case quicwire.OpDNSListRecords:
		return h.handleDNSListRecords(ctx, req)
	case quicwire.OpDNSAddZone:
		return h.handleDNSAddZone(ctx, req)
	case quicwire.OpDNSDeleteZone:
		return h.handleDNSDeleteZone(ctx, req)
	case quicwire.OpDNSListZones:
		return h.handleDNSListZones(ctx, req)
	case quicwire.OpDNSResolve:
		return h.handleDNSResolve(ctx, req)

	// Daemon-native operations (flat wire, no SDK QUIC client)
	case quicwire.OpDNSUpdateRecord:
		return h.handleDNSUpdateRecord(ctx, req)
	case quicwire.OpDNSGetRecord:
		return h.handleDNSGetRecord(ctx, req)
	case quicwire.OpDNSGetZone:
		return h.handleDNSGetZone(ctx, req)
	case quicwire.OpDNSGetConfig:
		return h.handleDNSGetConfig(ctx, req)
	case quicwire.OpDNSGetMetrics:
		return h.handleDNSGetMetrics(ctx, req)

	default:
		return h.errorResponse(quicwire.StatusNotImplemented, ErrQUICUnknownOpcode{Opcode: req.Opcode})
	}
}

// handleDNSUpdateRecord handles updating a DNS record (daemon-native).
func (h *QUICServiceHandler) handleDNSUpdateRecord(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var updateReq DNSUpdateRecordRequest
	if err := quicwire.DecodePayload(req.Payload, &updateReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if updateReq.Zone == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "zone"})
	}
	if updateReq.Name == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "name"})
	}
	if updateReq.RecordType == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "record_type"})
	}
	if updateReq.Value == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "value"})
	}

	// Update is delete + add
	if err := h.dnsService.DeleteRecord(ctx, updateReq.Name, updateReq.RecordType); err != nil {
		h.logger.Debug("delete during update failed (may not exist)", "error", err)
	}

	ttl := updateReq.TTL
	if ttl <= 0 {
		ttl = 3600
	}

	err := h.dnsService.AddRecord(ctx, updateReq.Name, updateReq.RecordType, updateReq.Value, ttl)
	if err != nil {
		h.logger.Error(err, "failed to update DNS record",
			"zone", updateReq.Zone,
			"name", updateReq.Name,
			"type", updateReq.RecordType)
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICOperationFailed{Op: "DNSUpdateRecord", Cause: err})
	}

	resp := &DNSUpdateRecordResponse{
		Success:   true,
		Zone:      updateReq.Zone,
		Name:      updateReq.Name,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleDNSGetRecord handles getting a DNS record (daemon-native).
func (h *QUICServiceHandler) handleDNSGetRecord(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var getReq DNSGetRecordRequest
	if err := quicwire.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if getReq.Zone == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "zone"})
	}
	if getReq.Name == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "name"})
	}
	if getReq.RecordType == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "record_type"})
	}

	record, err := h.dnsService.GetRecord(ctx, getReq.Name, getReq.RecordType)
	if err != nil {
		h.logger.Error(err, "failed to get DNS record",
			"zone", getReq.Zone,
			"name", getReq.Name,
			"type", getReq.RecordType)
		return h.errorResponse(quicwire.StatusNotFound, ErrQUICOperationFailed{Op: "DNSGetRecord", Cause: err})
	}

	dnsRecord := convertToQUICRecord(record, getReq.RecordType)

	resp := &DNSGetRecordResponse{
		Record:    dnsRecord,
		Zone:      getReq.Zone,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleDNSGetZone handles getting a DNS zone (daemon-native).
func (h *QUICServiceHandler) handleDNSGetZone(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var getReq DNSGetZoneRequest
	if err := quicwire.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if getReq.Zone == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "zone"})
	}

	zone, err := h.dnsService.Zone(ctx, getReq.Zone)
	if err != nil {
		h.logger.Error(err, "failed to get DNS zone", "zone", getReq.Zone)
		return h.errorResponse(quicwire.StatusNotFound, ErrQUICOperationFailed{Op: "DNSGetZone", Cause: err})
	}

	recordCount := countZoneRecords(zone)

	resp := &DNSGetZoneResponse{
		Zone: &DNSZone{
			ID:          zone.ID,
			Name:        zone.Name,
			TTL:         zone.TTL,
			Description: zone.Description,
			Internal:    zone.Internal,
			RecordCount: recordCount,
		},
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleDNSGetConfig handles getting DNS configuration (daemon-native).
func (h *QUICServiceHandler) handleDNSGetConfig(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	config := &DNSConfig{
		InternalDomain: h.dnsService.InternalDomain(),
		PublicDomain:   h.dnsService.PublicDomain(),
		DNSSECEnabled:  h.dnsService.IsDNSSECEnabled(),
	}

	resp := &DNSGetConfigResponse{
		Config:    config,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleDNSGetMetrics handles getting DNS metrics (daemon-native).
func (h *QUICServiceHandler) handleDNSGetMetrics(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	zones, err := h.dnsService.ListZones(ctx)
	if err != nil {
		h.logger.Error(err, "failed to get DNS zones for metrics")
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICOperationFailed{Op: "DNSGetMetrics", Cause: err})
	}

	totalRecords := 0
	for _, zone := range zones {
		totalRecords += countZoneRecords(zone)
	}

	metrics := &DNSMetrics{
		ZoneCount:    len(zones),
		TotalRecords: totalRecords,
	}

	resp := &DNSGetMetricsResponse{
		Metrics:   metrics,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// Helper functions

// convertToQUICRecord converts a DNS record interface to a QUIC DNSRecord
func convertToQUICRecord(record interface{}, recordType string) *DNSRecord {
	if record == nil {
		return nil
	}

	dnsRec := &DNSRecord{RecordType: recordType}

	switch r := record.(type) {
	case *entities.ARecord:
		dnsRec.Name = r.Name
		dnsRec.Value = r.Value
		dnsRec.TTL = r.TTL
	case *entities.AAAARecord:
		dnsRec.Name = r.Name
		dnsRec.Value = r.Value
		dnsRec.TTL = r.TTL
	case *entities.CNAMERecord:
		dnsRec.Name = r.Name
		dnsRec.Value = r.Value
		dnsRec.TTL = r.TTL
	case *entities.TXTRecord:
		dnsRec.Name = r.Name
		dnsRec.Value = r.Value
		dnsRec.TTL = r.TTL
	case *entities.MXRecord:
		dnsRec.Name = r.Name
		dnsRec.Value = r.Value
		dnsRec.TTL = r.TTL
		dnsRec.Priority = r.Priority
	case *entities.NSRecord:
		dnsRec.Name = r.Name
		dnsRec.Value = r.Value
		dnsRec.TTL = r.TTL
	default:
		return nil
	}

	return dnsRec
}

// convertInterfaceToQUICRecord converts a generic interface to a QUIC DNSRecord
func convertInterfaceToQUICRecord(record interface{}) *DNSRecord {
	if record == nil {
		return nil
	}

	switch r := record.(type) {
	case *entities.ARecord:
		return &DNSRecord{
			Name:       r.Name,
			RecordType: "A",
			Value:      r.Value,
			TTL:        r.TTL,
		}
	case *entities.AAAARecord:
		return &DNSRecord{
			Name:       r.Name,
			RecordType: "AAAA",
			Value:      r.Value,
			TTL:        r.TTL,
		}
	case *entities.CNAMERecord:
		return &DNSRecord{
			Name:       r.Name,
			RecordType: "CNAME",
			Value:      r.Value,
			TTL:        r.TTL,
		}
	case *entities.TXTRecord:
		return &DNSRecord{
			Name:       r.Name,
			RecordType: "TXT",
			Value:      r.Value,
			TTL:        r.TTL,
		}
	case *entities.MXRecord:
		return &DNSRecord{
			Name:       r.Name,
			RecordType: "MX",
			Value:      r.Value,
			TTL:        r.TTL,
			Priority:   r.Priority,
		}
	case *entities.NSRecord:
		return &DNSRecord{
			Name:       r.Name,
			RecordType: "NS",
			Value:      r.Value,
			TTL:        r.TTL,
		}
	default:
		return nil
	}
}

// countZoneRecords counts the total number of records in a zone
func countZoneRecords(zone *entities.Zone) int {
	if zone == nil {
		return 0
	}
	count := 0
	count += len(zone.RecordSet.ARecords)
	count += len(zone.RecordSet.AAAARecords)
	count += len(zone.RecordSet.CNAMERecords)
	count += len(zone.RecordSet.TXTRecords)
	count += len(zone.RecordSet.MXRecords)
	count += len(zone.RecordSet.NSRecords)
	count += len(zone.RecordSet.SRVRecords)
	count += len(zone.RecordSet.CAARecords)
	count += len(zone.RecordSet.TLSARecords)
	count += len(zone.RecordSet.DNSKEYRecords)
	count += len(zone.RecordSet.DSRecords)
	count += len(zone.RecordSet.RRSIGRecords)
	count += len(zone.RecordSet.NSECRecords)
	count += len(zone.RecordSet.NSEC3Records)
	count += len(zone.RecordSet.NSEC3PARAMRecords)
	// SOA record is always present
	if zone.RecordSet.SOARecord.Name != "" {
		count++
	}
	return count
}
