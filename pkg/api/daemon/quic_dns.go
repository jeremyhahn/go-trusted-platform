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

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
)

// DNS request/response types for QUIC protocol

// DNSAddRecordRequest represents a request to add a DNS record
type DNSAddRecordRequest struct {
	Zone       string `codec:"zone"`
	Name       string `codec:"name"`
	RecordType string `codec:"record_type"`
	Value      string `codec:"value"`
	TTL        int    `codec:"ttl"`
	Priority   uint16 `codec:"priority"`
}

// DNSAddRecordResponse represents the response after adding a DNS record
type DNSAddRecordResponse struct {
	Success   bool   `codec:"success"`
	Zone      string `codec:"zone"`
	Name      string `codec:"name"`
	Timestamp int64  `codec:"timestamp"`
}

// DNSDeleteRecordRequest represents a request to delete a DNS record
type DNSDeleteRecordRequest struct {
	Zone       string `codec:"zone"`
	Name       string `codec:"name"`
	RecordType string `codec:"record_type"`
}

// DNSDeleteRecordResponse represents the response after deleting a DNS record
type DNSDeleteRecordResponse struct {
	Success   bool   `codec:"success"`
	Zone      string `codec:"zone"`
	Name      string `codec:"name"`
	Timestamp int64  `codec:"timestamp"`
}

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

// DNSListRecordsRequest represents a request to list DNS records
type DNSListRecordsRequest struct {
	Zone       string `codec:"zone"`
	RecordType string `codec:"record_type"`
}

// DNSListRecordsResponse represents the response containing DNS records
type DNSListRecordsResponse struct {
	Records   []*DNSRecord `codec:"records"`
	Zone      string       `codec:"zone"`
	Total     int          `codec:"total"`
	Timestamp int64        `codec:"timestamp"`
}

// DNSAddZoneRequest represents a request to create a DNS zone
type DNSAddZoneRequest struct {
	Name        string `codec:"name"`
	Description string `codec:"description"`
	TTL         uint32 `codec:"ttl"`
	Internal    bool   `codec:"internal"`
}

// DNSAddZoneResponse represents the response after creating a DNS zone
type DNSAddZoneResponse struct {
	Success   bool   `codec:"success"`
	Zone      string `codec:"zone"`
	ID        uint64 `codec:"id"`
	Timestamp int64  `codec:"timestamp"`
}

// DNSDeleteZoneRequest represents a request to delete a DNS zone
type DNSDeleteZoneRequest struct {
	Zone string `codec:"zone"`
}

// DNSDeleteZoneResponse represents the response after deleting a DNS zone
type DNSDeleteZoneResponse struct {
	Success   bool   `codec:"success"`
	Zone      string `codec:"zone"`
	Timestamp int64  `codec:"timestamp"`
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

// DNSListZonesRequest represents a request to list DNS zones
type DNSListZonesRequest struct {
	Internal *bool `codec:"internal"`
}

// DNSListZonesResponse represents the response containing DNS zones
type DNSListZonesResponse struct {
	Zones     []*DNSZone `codec:"zones"`
	Total     int        `codec:"total"`
	Timestamp int64      `codec:"timestamp"`
}

// DNSResolveRequest represents a DNS resolution request
type DNSResolveRequest struct {
	Name       string `codec:"name"`
	RecordType string `codec:"record_type"`
}

// DNSResolveResponse represents a DNS resolution response
type DNSResolveResponse struct {
	Name      string   `codec:"name"`
	Type      string   `codec:"type"`
	Values    []string `codec:"values"`
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

// DNSUpdateConfigRequest represents a request to update DNS configuration
type DNSUpdateConfigRequest struct {
	AllowRegistration         *bool `codec:"allow_registration"`
	AllowExternalRegistration *bool `codec:"allow_external_registration"`
	AllowInternalRegistration *bool `codec:"allow_internal_registration"`
}

// DNSUpdateConfigResponse represents the response after updating DNS configuration
type DNSUpdateConfigResponse struct {
	Success   bool  `codec:"success"`
	Timestamp int64 `codec:"timestamp"`
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

// DNSFlushCacheRequest represents a request to flush DNS cache
type DNSFlushCacheRequest struct {
	Zone string `codec:"zone"`
}

// DNSFlushCacheResponse represents the response after flushing DNS cache
type DNSFlushCacheResponse struct {
	Success       bool  `codec:"success"`
	EntriesPurged int   `codec:"entries_purged"`
	Timestamp     int64 `codec:"timestamp"`
}

// handleDNSOperation routes DNS operations to their handlers
func (h *QUICServiceHandler) handleDNSOperation(ctx context.Context, req *quic.Request) *quic.Response {
	if h.dnsService == nil {
		return h.errorResponse(quic.StatusUnavailable, ErrDNSServiceNotAvailable{})
	}

	switch req.Opcode {
	case quic.OpDNSAddRecord:
		return h.handleDNSAddRecord(ctx, req)
	case quic.OpDNSDeleteRecord:
		return h.handleDNSDeleteRecord(ctx, req)
	case quic.OpDNSUpdateRecord:
		return h.handleDNSUpdateRecord(ctx, req)
	case quic.OpDNSGetRecord:
		return h.handleDNSGetRecord(ctx, req)
	case quic.OpDNSListRecords:
		return h.handleDNSListRecords(ctx, req)
	case quic.OpDNSAddZone:
		return h.handleDNSAddZone(ctx, req)
	case quic.OpDNSDeleteZone:
		return h.handleDNSDeleteZone(ctx, req)
	case quic.OpDNSGetZone:
		return h.handleDNSGetZone(ctx, req)
	case quic.OpDNSListZones:
		return h.handleDNSListZones(ctx, req)
	case quic.OpDNSResolve:
		return h.handleDNSResolve(ctx, req)
	case quic.OpDNSGetConfig:
		return h.handleDNSGetConfig(ctx, req)
	case quic.OpDNSUpdateConfig:
		return h.handleDNSUpdateConfig(ctx, req)
	case quic.OpDNSGetMetrics:
		return h.handleDNSGetMetrics(ctx, req)
	case quic.OpDNSFlushCache:
		return h.handleDNSFlushCache(ctx, req)
	default:
		return h.errorResponse(quic.StatusNotImplemented, ErrQUICUnknownOpcode{Opcode: req.Opcode})
	}
}

// handleDNSAddRecord handles adding a DNS record
func (h *QUICServiceHandler) handleDNSAddRecord(ctx context.Context, req *quic.Request) *quic.Response {
	var addReq DNSAddRecordRequest
	if err := quic.DecodePayload(req.Payload, &addReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if addReq.Zone == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "zone"})
	}
	if addReq.Name == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "name"})
	}
	if addReq.RecordType == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "record_type"})
	}
	if addReq.Value == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "value"})
	}

	ttl := addReq.TTL
	if ttl <= 0 {
		ttl = 3600
	}

	err := h.dnsService.AddRecord(ctx, addReq.Name, addReq.RecordType, addReq.Value, ttl)
	if err != nil {
		h.logger.Error(err, "failed to add DNS record",
			"zone", addReq.Zone,
			"name", addReq.Name,
			"type", addReq.RecordType)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "DNSAddRecord", Cause: err})
	}

	resp := &DNSAddRecordResponse{
		Success:   true,
		Zone:      addReq.Zone,
		Name:      addReq.Name,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleDNSDeleteRecord handles deleting a DNS record
func (h *QUICServiceHandler) handleDNSDeleteRecord(ctx context.Context, req *quic.Request) *quic.Response {
	var deleteReq DNSDeleteRecordRequest
	if err := quic.DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if deleteReq.Zone == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "zone"})
	}
	if deleteReq.Name == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "name"})
	}
	if deleteReq.RecordType == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "record_type"})
	}

	err := h.dnsService.DeleteRecord(ctx, deleteReq.Name, deleteReq.RecordType)
	if err != nil {
		h.logger.Error(err, "failed to delete DNS record",
			"zone", deleteReq.Zone,
			"name", deleteReq.Name,
			"type", deleteReq.RecordType)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "DNSDeleteRecord", Cause: err})
	}

	resp := &DNSDeleteRecordResponse{
		Success:   true,
		Zone:      deleteReq.Zone,
		Name:      deleteReq.Name,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleDNSUpdateRecord handles updating a DNS record
func (h *QUICServiceHandler) handleDNSUpdateRecord(ctx context.Context, req *quic.Request) *quic.Response {
	var updateReq DNSUpdateRecordRequest
	if err := quic.DecodePayload(req.Payload, &updateReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if updateReq.Zone == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "zone"})
	}
	if updateReq.Name == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "name"})
	}
	if updateReq.RecordType == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "record_type"})
	}
	if updateReq.Value == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "value"})
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
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "DNSUpdateRecord", Cause: err})
	}

	resp := &DNSUpdateRecordResponse{
		Success:   true,
		Zone:      updateReq.Zone,
		Name:      updateReq.Name,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleDNSGetRecord handles getting a DNS record
func (h *QUICServiceHandler) handleDNSGetRecord(ctx context.Context, req *quic.Request) *quic.Response {
	var getReq DNSGetRecordRequest
	if err := quic.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if getReq.Zone == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "zone"})
	}
	if getReq.Name == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "name"})
	}
	if getReq.RecordType == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "record_type"})
	}

	record, err := h.dnsService.GetRecord(ctx, getReq.Name, getReq.RecordType)
	if err != nil {
		h.logger.Error(err, "failed to get DNS record",
			"zone", getReq.Zone,
			"name", getReq.Name,
			"type", getReq.RecordType)
		return h.errorResponse(quic.StatusNotFound, ErrQUICOperationFailed{Op: "DNSGetRecord", Cause: err})
	}

	dnsRecord := convertToQUICRecord(record, getReq.RecordType)

	resp := &DNSGetRecordResponse{
		Record:    dnsRecord,
		Zone:      getReq.Zone,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleDNSListRecords handles listing DNS records
func (h *QUICServiceHandler) handleDNSListRecords(ctx context.Context, req *quic.Request) *quic.Response {
	var listReq DNSListRecordsRequest
	if len(req.Payload) > 0 {
		if err := quic.DecodePayload(req.Payload, &listReq); err != nil {
			return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
		}
	}

	if listReq.Zone == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "zone"})
	}

	records, err := h.dnsService.ListRecords(ctx, listReq.Zone)
	if err != nil {
		h.logger.Error(err, "failed to list DNS records", "zone", listReq.Zone)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "DNSListRecords", Cause: err})
	}

	dnsRecords := make([]*DNSRecord, 0, len(records))
	for _, rec := range records {
		dnsRec := convertInterfaceToQUICRecord(rec)
		if dnsRec != nil {
			if listReq.RecordType == "" || dnsRec.RecordType == listReq.RecordType {
				dnsRecords = append(dnsRecords, dnsRec)
			}
		}
	}

	resp := &DNSListRecordsResponse{
		Records:   dnsRecords,
		Zone:      listReq.Zone,
		Total:     len(dnsRecords),
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleDNSAddZone handles creating a DNS zone
func (h *QUICServiceHandler) handleDNSAddZone(ctx context.Context, req *quic.Request) *quic.Response {
	var addReq DNSAddZoneRequest
	if err := quic.DecodePayload(req.Payload, &addReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if addReq.Name == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "name"})
	}

	err := h.dnsService.CreateZone(ctx, addReq.Name)
	if err != nil {
		h.logger.Error(err, "failed to create DNS zone", "zone", addReq.Name)
		if err == dns.ErrZoneAlreadyExists {
			return h.errorResponse(quic.StatusAlreadyExists, ErrQUICOperationFailed{Op: "DNSAddZone", Cause: err})
		}
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "DNSAddZone", Cause: err})
	}

	resp := &DNSAddZoneResponse{
		Success:   true,
		Zone:      addReq.Name,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleDNSDeleteZone handles deleting a DNS zone
func (h *QUICServiceHandler) handleDNSDeleteZone(ctx context.Context, req *quic.Request) *quic.Response {
	var deleteReq DNSDeleteZoneRequest
	if err := quic.DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if deleteReq.Zone == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "zone"})
	}

	err := h.dnsService.DeleteZone(ctx, deleteReq.Zone)
	if err != nil {
		h.logger.Error(err, "failed to delete DNS zone", "zone", deleteReq.Zone)
		if err == dns.ErrZoneNotFound {
			return h.errorResponse(quic.StatusNotFound, ErrQUICOperationFailed{Op: "DNSDeleteZone", Cause: err})
		}
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "DNSDeleteZone", Cause: err})
	}

	resp := &DNSDeleteZoneResponse{
		Success:   true,
		Zone:      deleteReq.Zone,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleDNSGetZone handles getting a DNS zone
func (h *QUICServiceHandler) handleDNSGetZone(ctx context.Context, req *quic.Request) *quic.Response {
	var getReq DNSGetZoneRequest
	if err := quic.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if getReq.Zone == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "zone"})
	}

	zone, err := h.dnsService.Zone(ctx, getReq.Zone)
	if err != nil {
		h.logger.Error(err, "failed to get DNS zone", "zone", getReq.Zone)
		return h.errorResponse(quic.StatusNotFound, ErrQUICOperationFailed{Op: "DNSGetZone", Cause: err})
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

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleDNSListZones handles listing DNS zones
func (h *QUICServiceHandler) handleDNSListZones(ctx context.Context, req *quic.Request) *quic.Response {
	var listReq DNSListZonesRequest
	if len(req.Payload) > 0 {
		if err := quic.DecodePayload(req.Payload, &listReq); err != nil {
			return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
		}
	}

	zones, err := h.dnsService.ListZones(ctx)
	if err != nil {
		h.logger.Error(err, "failed to list DNS zones")
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "DNSListZones", Cause: err})
	}

	dnsZones := make([]*DNSZone, 0, len(zones))
	for _, zone := range zones {
		if listReq.Internal != nil && *listReq.Internal != zone.Internal {
			continue
		}
		dnsZones = append(dnsZones, &DNSZone{
			ID:          zone.ID,
			Name:        zone.Name,
			TTL:         zone.TTL,
			Description: zone.Description,
			Internal:    zone.Internal,
			RecordCount: countZoneRecords(zone),
		})
	}

	resp := &DNSListZonesResponse{
		Zones:     dnsZones,
		Total:     len(dnsZones),
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleDNSResolve handles DNS resolution
func (h *QUICServiceHandler) handleDNSResolve(ctx context.Context, req *quic.Request) *quic.Response {
	var resolveReq DNSResolveRequest
	if err := quic.DecodePayload(req.Payload, &resolveReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if resolveReq.Name == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "name"})
	}

	recordType := resolveReq.RecordType
	if recordType == "" {
		recordType = "A"
	}

	values, err := h.dnsService.Resolve(ctx, resolveReq.Name, recordType)
	if err != nil {
		h.logger.Error(err, "failed to resolve DNS",
			"name", resolveReq.Name,
			"type", recordType)
		return h.errorResponse(quic.StatusNotFound, ErrQUICOperationFailed{Op: "DNSResolve", Cause: err})
	}

	resp := &DNSResolveResponse{
		Name:      resolveReq.Name,
		Type:      recordType,
		Values:    values,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleDNSGetConfig handles getting DNS configuration
func (h *QUICServiceHandler) handleDNSGetConfig(ctx context.Context, req *quic.Request) *quic.Response {
	config := &DNSConfig{
		InternalDomain: h.dnsService.InternalDomain(),
		PublicDomain:   h.dnsService.PublicDomain(),
		DNSSECEnabled:  h.dnsService.IsDNSSECEnabled(),
	}

	resp := &DNSGetConfigResponse{
		Config:    config,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleDNSUpdateConfig handles updating DNS configuration
func (h *QUICServiceHandler) handleDNSUpdateConfig(ctx context.Context, req *quic.Request) *quic.Response {
	// DNS configuration updates are not directly supported by the service interface
	// This would require extending the DNS service to support runtime configuration changes
	return h.errorResponse(quic.StatusNotImplemented, ErrQUICOperationFailed{Op: "DNSUpdateConfig", Cause: ErrDNSConfigUpdateNotSupported{}})
}

// handleDNSGetMetrics handles getting DNS metrics
func (h *QUICServiceHandler) handleDNSGetMetrics(ctx context.Context, req *quic.Request) *quic.Response {
	// Get zone count
	zones, err := h.dnsService.ListZones(ctx)
	if err != nil {
		h.logger.Error(err, "failed to get DNS zones for metrics")
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "DNSGetMetrics", Cause: err})
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

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleDNSFlushCache handles flushing DNS cache
func (h *QUICServiceHandler) handleDNSFlushCache(ctx context.Context, req *quic.Request) *quic.Response {
	// DNS cache flushing is not directly supported by the service interface
	// This would require CoreDNS integration to clear caches
	return h.errorResponse(quic.StatusNotImplemented, ErrQUICOperationFailed{Op: "DNSFlushCache", Cause: ErrDNSCacheFlushNotSupported{}})
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
