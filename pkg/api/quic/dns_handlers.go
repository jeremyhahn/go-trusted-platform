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

package quic

import (
	"context"
	"errors"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// DNS pagination defaults
const (
	dnsDefaultLimit int32 = 100
	dnsMaxLimit     int32 = 1000
)

// DNS-specific sentinel errors
var (
	// ErrDNSServiceNotAvailable is returned when the DNS service is not
	// configured or unavailable.
	ErrDNSServiceNotAvailable = errors.New("dns service not available")

	// ErrDNSMissingZoneName is returned when a zone name is required but not provided.
	ErrDNSMissingZoneName = errors.New("zone name is required")

	// ErrDNSMissingRecordName is returned when a record name is required but not provided.
	ErrDNSMissingRecordName = errors.New("record name is required")

	// ErrDNSMissingRecordType is returned when a record type is required but not provided.
	ErrDNSMissingRecordType = errors.New("record type is required")

	// ErrDNSMissingFQDN is returned when an FQDN is required but not provided.
	ErrDNSMissingFQDN = errors.New("fqdn is required")

	// ErrDNSMissingIP is returned when an IP address is required but not provided.
	ErrDNSMissingIP = errors.New("ip address is required")

	// ErrDNSInvalidRecordType is returned when an unsupported record type is specified.
	ErrDNSInvalidRecordType = errors.New("invalid record type")
)

// DNSHandler handles DNS operations over QUIC
type DNSHandler struct {
	dnsService dns.DNSService
	logger     *logging.Logger
}

// NewDNSHandler creates a new DNS handler
func NewDNSHandler(logger *logging.Logger, dnsService dns.DNSService) *DNSHandler {
	return &DNSHandler{
		dnsService: dnsService,
		logger:     logger,
	}
}

// HandleRequest processes a DNS request and returns a response
func (h *DNSHandler) HandleRequest(ctx context.Context, req *Request) *Response {
	if req == nil {
		return &Response{
			Status:  StatusInvalidRequest,
			Payload: []byte(ErrNilRequest.Error()),
		}
	}

	switch req.Opcode {
	case OpDNSAddZone:
		return h.handleAddZone(ctx, req)
	case OpDNSGetZone:
		return h.handleGetZone(ctx, req)
	case OpDNSDeleteZone:
		return h.handleDeleteZone(ctx, req)
	case OpDNSListZones:
		return h.handleListZones(ctx, req)
	case OpDNSAddRecord:
		return h.handleAddRecord(ctx, req)
	case OpDNSGetRecord:
		return h.handleGetRecord(ctx, req)
	case OpDNSUpdateRecord:
		return h.handleUpdateRecord(ctx, req)
	case OpDNSDeleteRecord:
		return h.handleDeleteRecord(ctx, req)
	case OpDNSListRecords:
		return h.handleListRecords(ctx, req)
	case OpDNSResolve:
		return h.handleResolve(ctx, req)
	default:
		return &Response{
			Status:  StatusInvalidRequest,
			Payload: []byte("unknown dns operation"),
		}
	}
}

// =============================================================================
// Request/Response Types
// =============================================================================

// DNSAddZoneRequest represents a zone creation request
type DNSAddZoneRequest struct {
	Name        string               `codec:"name"`
	TTL         uint32               `codec:"ttl"`
	Description string               `codec:"description"`
	Internal    bool                 `codec:"internal"`
	SOA         *DNSSOARecordRequest `codec:"soa"`
	NSRecords   []DNSNSRecordRequest `codec:"ns_records"`
}

// DNSSOARecordRequest represents a SOA record in API requests
type DNSSOARecordRequest struct {
	MName      string `codec:"mname"`
	RName      string `codec:"rname"`
	Serial     uint32 `codec:"serial"`
	Refresh    uint32 `codec:"refresh"`
	Retry      uint32 `codec:"retry"`
	Expire     uint32 `codec:"expire"`
	MinimumTTL uint32 `codec:"minimum_ttl"`
	TTL        uint32 `codec:"ttl"`
}

// DNSNSRecordRequest represents an NS record in API requests
type DNSNSRecordRequest struct {
	Name  string `codec:"name"`
	Value string `codec:"value"`
	TTL   uint32 `codec:"ttl"`
}

// DNSAddZoneResponse represents a zone creation response
type DNSAddZoneResponse struct {
	Zone      *DNSZoneInfo `codec:"zone"`
	Timestamp int64        `codec:"timestamp"`
}

// DNSZoneInfo contains zone information
type DNSZoneInfo struct {
	ID          uint64        `codec:"id"`
	Name        string        `codec:"name"`
	TTL         uint32        `codec:"ttl"`
	Description string        `codec:"description"`
	Internal    bool          `codec:"internal"`
	Records     *DNSRecordSet `codec:"records"`
}

// DNSRecordSet contains all DNS records for a zone
type DNSRecordSet struct {
	SOA    *DNSSOARecord     `codec:"soa"`
	A      []DNSARecord      `codec:"a"`
	AAAA   []DNSAAAARecord   `codec:"aaaa"`
	CNAME  []DNSCNAMERecord  `codec:"cname"`
	MX     []DNSMXRecord     `codec:"mx"`
	NS     []DNSNSRecord     `codec:"ns"`
	TXT    []DNSTXTRecord    `codec:"txt"`
	SRV    []DNSSRVRecord    `codec:"srv"`
	CAA    []DNSCAARecord    `codec:"caa"`
	TLSA   []DNSTLSARecord   `codec:"tlsa"`
	DNSKEY []DNSDNSKEYRecord `codec:"dnskey"`
	DS     []DNSDSRecord     `codec:"ds"`
}

// DNSSOARecord represents a SOA record
type DNSSOARecord struct {
	Name       string `codec:"name"`
	MName      string `codec:"mname"`
	RName      string `codec:"rname"`
	Serial     uint32 `codec:"serial"`
	Refresh    uint32 `codec:"refresh"`
	Retry      uint32 `codec:"retry"`
	Expire     uint32 `codec:"expire"`
	MinimumTTL uint32 `codec:"minimum_ttl"`
	TTL        uint32 `codec:"ttl"`
}

// DNSARecord represents an A record
type DNSARecord struct {
	Name  string `codec:"name"`
	Value string `codec:"value"`
	TTL   uint32 `codec:"ttl"`
}

// DNSAAAARecord represents an AAAA record
type DNSAAAARecord struct {
	Name  string `codec:"name"`
	Value string `codec:"value"`
	TTL   uint32 `codec:"ttl"`
}

// DNSCNAMERecord represents a CNAME record
type DNSCNAMERecord struct {
	Name  string `codec:"name"`
	Value string `codec:"value"`
	TTL   uint32 `codec:"ttl"`
}

// DNSMXRecord represents an MX record
type DNSMXRecord struct {
	Name     string `codec:"name"`
	Value    string `codec:"value"`
	Priority uint16 `codec:"priority"`
	TTL      uint32 `codec:"ttl"`
}

// DNSNSRecord represents an NS record
type DNSNSRecord struct {
	Name  string `codec:"name"`
	Value string `codec:"value"`
	TTL   uint32 `codec:"ttl"`
}

// DNSTXTRecord represents a TXT record
type DNSTXTRecord struct {
	Name  string `codec:"name"`
	Value string `codec:"value"`
	TTL   uint32 `codec:"ttl"`
}

// DNSSRVRecord represents an SRV record
type DNSSRVRecord struct {
	Name     string `codec:"name"`
	Target   string `codec:"target"`
	Port     uint16 `codec:"port"`
	Priority uint16 `codec:"priority"`
	Weight   uint16 `codec:"weight"`
	TTL      uint32 `codec:"ttl"`
}

// DNSCAARecord represents a CAA record
type DNSCAARecord struct {
	Name  string `codec:"name"`
	Flags uint8  `codec:"flags"`
	Tag   string `codec:"tag"`
	Value string `codec:"value"`
	TTL   uint32 `codec:"ttl"`
}

// DNSTLSARecord represents a TLSA record
type DNSTLSARecord struct {
	Name         string `codec:"name"`
	Usage        uint8  `codec:"usage"`
	Selector     uint8  `codec:"selector"`
	MatchingType uint8  `codec:"matching_type"`
	Data         string `codec:"data"`
	TTL          uint32 `codec:"ttl"`
}

// DNSDNSKEYRecord represents a DNSKEY record
type DNSDNSKEYRecord struct {
	Name      string `codec:"name"`
	Flags     uint16 `codec:"flags"`
	Protocol  uint8  `codec:"protocol"`
	Algorithm uint8  `codec:"algorithm"`
	Key       string `codec:"key"`
	TTL       uint32 `codec:"ttl"`
}

// DNSDSRecord represents a DS record
type DNSDSRecord struct {
	Name       string `codec:"name"`
	KeyTag     uint16 `codec:"key_tag"`
	Algorithm  uint8  `codec:"algorithm"`
	DigestType uint8  `codec:"digest_type"`
	Digest     string `codec:"digest"`
	TTL        uint32 `codec:"ttl"`
}

// DNSGetZoneRequest represents a zone get request
type DNSGetZoneRequest struct {
	Name string `codec:"name"`
}

// DNSGetZoneResponse represents a zone get response
type DNSGetZoneResponse struct {
	Zone      *DNSZoneInfo `codec:"zone"`
	Timestamp int64        `codec:"timestamp"`
}

// DNSDeleteZoneRequest represents a zone deletion request
type DNSDeleteZoneRequest struct {
	Name string `codec:"name"`
}

// DNSDeleteZoneResponse represents a zone deletion response
type DNSDeleteZoneResponse struct {
	Name      string `codec:"name"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// DNSListZonesRequest represents a zone list request
type DNSListZonesRequest struct {
	Limit  int32 `codec:"limit"`
	Offset int32 `codec:"offset"`
}

// DNSListZonesResponse represents a zone list response
type DNSListZonesResponse struct {
	Zones     []*DNSZoneInfo `codec:"zones"`
	Count     int32          `codec:"count"`
	Timestamp int64          `codec:"timestamp"`
}

// DNSAddRecordRequest represents a record addition request
type DNSAddRecordRequest struct {
	ZoneName     string `codec:"zone_name"`
	Type         string `codec:"type"`
	Name         string `codec:"name"`
	Value        string `codec:"value"`
	TTL          uint32 `codec:"ttl"`
	Priority     uint16 `codec:"priority"`
	Weight       uint16 `codec:"weight"`
	Port         uint16 `codec:"port"`
	Target       string `codec:"target"`
	Flags        uint8  `codec:"flags"`
	Tag          string `codec:"tag"`
	Usage        uint8  `codec:"usage"`
	Selector     uint8  `codec:"selector"`
	MatchingType uint8  `codec:"matching_type"`
	Data         string `codec:"data"`
}

// DNSAddRecordResponse represents a record addition response
type DNSAddRecordResponse struct {
	Zone      *DNSZoneInfo `codec:"zone"`
	Timestamp int64        `codec:"timestamp"`
}

// DNSGetRecordRequest represents a record get request
type DNSGetRecordRequest struct {
	ZoneName   string `codec:"zone_name"`
	RecordName string `codec:"record_name"`
	RecordType string `codec:"record_type"`
}

// DNSGetRecordResponse represents a record get response
type DNSGetRecordResponse struct {
	Record    interface{} `codec:"record"`
	Timestamp int64       `codec:"timestamp"`
}

// DNSUpdateRecordRequest represents a record update request
type DNSUpdateRecordRequest struct {
	ZoneName     string `codec:"zone_name"`
	Type         string `codec:"type"`
	Name         string `codec:"name"`
	Value        string `codec:"value"`
	TTL          uint32 `codec:"ttl"`
	Priority     uint16 `codec:"priority"`
	Weight       uint16 `codec:"weight"`
	Port         uint16 `codec:"port"`
	Target       string `codec:"target"`
	Flags        uint8  `codec:"flags"`
	Tag          string `codec:"tag"`
	Usage        uint8  `codec:"usage"`
	Selector     uint8  `codec:"selector"`
	MatchingType uint8  `codec:"matching_type"`
	Data         string `codec:"data"`
}

// DNSUpdateRecordResponse represents a record update response
type DNSUpdateRecordResponse struct {
	Zone      *DNSZoneInfo `codec:"zone"`
	Timestamp int64        `codec:"timestamp"`
}

// DNSDeleteRecordRequest represents a record deletion request
type DNSDeleteRecordRequest struct {
	ZoneName   string `codec:"zone_name"`
	RecordName string `codec:"record_name"`
	RecordType string `codec:"record_type"`
}

// DNSDeleteRecordResponse represents a record deletion response
type DNSDeleteRecordResponse struct {
	ZoneName   string `codec:"zone_name"`
	RecordName string `codec:"record_name"`
	RecordType string `codec:"record_type"`
	Success    bool   `codec:"success"`
	Timestamp  int64  `codec:"timestamp"`
}

// DNSListRecordsRequest represents a records list request
type DNSListRecordsRequest struct {
	ZoneName   string `codec:"zone_name"`
	TypeFilter string `codec:"type_filter"`
}

// DNSListRecordsResponse represents a records list response
type DNSListRecordsResponse struct {
	Records   []DNSRecordInfo `codec:"records"`
	Count     int32           `codec:"count"`
	Timestamp int64           `codec:"timestamp"`
}

// DNSRecordInfo represents generic record information
type DNSRecordInfo struct {
	ID   string      `codec:"id"`
	Type string      `codec:"type"`
	Data interface{} `codec:"data"`
}

// DNSResolveRequest represents a DNS resolution request
type DNSResolveRequest struct {
	FQDN string `codec:"fqdn"`
	Type string `codec:"type"`
}

// DNSResolveResponse represents a DNS resolution response
type DNSResolveResponse struct {
	FQDN          string   `codec:"fqdn"`
	Type          string   `codec:"type"`
	Values        []string `codec:"values"`
	Authoritative bool     `codec:"authoritative"`
	Timestamp     int64    `codec:"timestamp"`
}

// =============================================================================
// Handler Methods
// =============================================================================

// handleAddZone creates a new DNS zone
func (h *DNSHandler) handleAddZone(ctx context.Context, req *Request) *Response {
	if h.dnsService == nil {
		return h.errorResponse(StatusUnavailable, ErrDNSServiceNotAvailable)
	}

	var addReq DNSAddZoneRequest
	if err := DecodePayload(req.Payload, &addReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrDNSDecodingFailed{Cause: err})
	}

	if addReq.Name == "" {
		return h.errorResponse(StatusInvalidArgument, ErrDNSMissingZoneName)
	}

	zone := h.buildZoneFromRequest(&addReq)

	if err := h.dnsService.Save(ctx, zone); err != nil {
		h.logger.Error(err, "failed to create zone")
		return h.dnsErrorResponse(err)
	}

	resp := &DNSAddZoneResponse{
		Zone:      h.zoneToInfo(zone),
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrDNSEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleGetZone retrieves a DNS zone by name
func (h *DNSHandler) handleGetZone(ctx context.Context, req *Request) *Response {
	if h.dnsService == nil {
		return h.errorResponse(StatusUnavailable, ErrDNSServiceNotAvailable)
	}

	var getReq DNSGetZoneRequest
	if err := DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrDNSDecodingFailed{Cause: err})
	}

	if getReq.Name == "" {
		return h.errorResponse(StatusInvalidArgument, ErrDNSMissingZoneName)
	}

	zone, err := h.dnsService.Zone(ctx, getReq.Name)
	if err != nil {
		h.logger.Error(err, "failed to get zone")
		return h.dnsErrorResponse(err)
	}

	resp := &DNSGetZoneResponse{
		Zone:      h.zoneToInfo(zone),
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrDNSEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleDeleteZone deletes a DNS zone
func (h *DNSHandler) handleDeleteZone(ctx context.Context, req *Request) *Response {
	if h.dnsService == nil {
		return h.errorResponse(StatusUnavailable, ErrDNSServiceNotAvailable)
	}

	var deleteReq DNSDeleteZoneRequest
	if err := DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrDNSDecodingFailed{Cause: err})
	}

	if deleteReq.Name == "" {
		return h.errorResponse(StatusInvalidArgument, ErrDNSMissingZoneName)
	}

	if err := h.dnsService.DeleteZone(ctx, deleteReq.Name); err != nil {
		h.logger.Error(err, "failed to delete zone")
		return h.dnsErrorResponse(err)
	}

	resp := &DNSDeleteZoneResponse{
		Name:      deleteReq.Name,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrDNSEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleListZones lists all DNS zones
func (h *DNSHandler) handleListZones(ctx context.Context, req *Request) *Response {
	if h.dnsService == nil {
		return h.errorResponse(StatusUnavailable, ErrDNSServiceNotAvailable)
	}

	var listReq DNSListZonesRequest
	if err := DecodePayload(req.Payload, &listReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrDNSDecodingFailed{Cause: err})
	}

	zones, err := h.dnsService.ListZones(ctx)
	if err != nil {
		h.logger.Error(err, "failed to list zones")
		return h.dnsErrorResponse(err)
	}

	// Apply pagination
	limit := listReq.Limit
	if limit <= 0 {
		limit = dnsDefaultLimit
	}
	if limit > dnsMaxLimit {
		limit = dnsMaxLimit
	}

	offset := listReq.Offset
	if offset < 0 {
		offset = 0
	}

	// Calculate slice boundaries
	start := int(offset)
	end := start + int(limit)

	if start > len(zones) {
		start = len(zones)
	}
	if end > len(zones) {
		end = len(zones)
	}

	paginatedZones := zones[start:end]

	zoneInfos := make([]*DNSZoneInfo, 0, len(paginatedZones))
	for _, z := range paginatedZones {
		zoneInfos = append(zoneInfos, h.zoneToInfo(z))
	}

	resp := &DNSListZonesResponse{
		Zones:     zoneInfos,
		Count:     int32(len(zoneInfos)),
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrDNSEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleAddRecord adds a DNS record to a zone
func (h *DNSHandler) handleAddRecord(ctx context.Context, req *Request) *Response {
	if h.dnsService == nil {
		return h.errorResponse(StatusUnavailable, ErrDNSServiceNotAvailable)
	}

	var addReq DNSAddRecordRequest
	if err := DecodePayload(req.Payload, &addReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrDNSDecodingFailed{Cause: err})
	}

	if addReq.ZoneName == "" {
		return h.errorResponse(StatusInvalidArgument, ErrDNSMissingZoneName)
	}
	if addReq.Type == "" {
		return h.errorResponse(StatusInvalidArgument, ErrDNSMissingRecordType)
	}
	if addReq.Name == "" {
		return h.errorResponse(StatusInvalidArgument, ErrDNSMissingRecordName)
	}

	zone, err := h.dnsService.Zone(ctx, addReq.ZoneName)
	if err != nil {
		h.logger.Error(err, "failed to get zone for adding record")
		return h.dnsErrorResponse(err)
	}

	if err := h.addRecordToZone(zone, &addReq); err != nil {
		return h.errorResponse(StatusInvalidArgument, err)
	}

	if err := h.dnsService.Save(ctx, zone); err != nil {
		h.logger.Error(err, "failed to save zone with new record")
		return h.dnsErrorResponse(err)
	}

	resp := &DNSAddRecordResponse{
		Zone:      h.zoneToInfo(zone),
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrDNSEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleGetRecord retrieves a DNS record
func (h *DNSHandler) handleGetRecord(ctx context.Context, req *Request) *Response {
	if h.dnsService == nil {
		return h.errorResponse(StatusUnavailable, ErrDNSServiceNotAvailable)
	}

	var getReq DNSGetRecordRequest
	if err := DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrDNSDecodingFailed{Cause: err})
	}

	if getReq.ZoneName == "" {
		return h.errorResponse(StatusInvalidArgument, ErrDNSMissingZoneName)
	}
	if getReq.RecordName == "" {
		return h.errorResponse(StatusInvalidArgument, ErrDNSMissingRecordName)
	}
	if getReq.RecordType == "" {
		return h.errorResponse(StatusInvalidArgument, ErrDNSMissingRecordType)
	}

	record, err := h.dnsService.GetRecord(ctx, getReq.RecordName, getReq.RecordType)
	if err != nil {
		h.logger.Error(err, "failed to get record")
		return h.dnsErrorResponse(err)
	}

	resp := &DNSGetRecordResponse{
		Record:    record,
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrDNSEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleUpdateRecord updates a DNS record
func (h *DNSHandler) handleUpdateRecord(ctx context.Context, req *Request) *Response {
	if h.dnsService == nil {
		return h.errorResponse(StatusUnavailable, ErrDNSServiceNotAvailable)
	}

	var updateReq DNSUpdateRecordRequest
	if err := DecodePayload(req.Payload, &updateReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrDNSDecodingFailed{Cause: err})
	}

	if updateReq.ZoneName == "" {
		return h.errorResponse(StatusInvalidArgument, ErrDNSMissingZoneName)
	}
	if updateReq.Type == "" {
		return h.errorResponse(StatusInvalidArgument, ErrDNSMissingRecordType)
	}
	if updateReq.Name == "" {
		return h.errorResponse(StatusInvalidArgument, ErrDNSMissingRecordName)
	}

	zone, err := h.dnsService.Zone(ctx, updateReq.ZoneName)
	if err != nil {
		h.logger.Error(err, "failed to get zone for updating record")
		return h.dnsErrorResponse(err)
	}

	if err := h.updateRecordInZone(zone, &updateReq); err != nil {
		return h.errorResponse(StatusNotFound, err)
	}

	if err := h.dnsService.Save(ctx, zone); err != nil {
		h.logger.Error(err, "failed to save zone with updated record")
		return h.dnsErrorResponse(err)
	}

	resp := &DNSUpdateRecordResponse{
		Zone:      h.zoneToInfo(zone),
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrDNSEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleDeleteRecord deletes a DNS record
func (h *DNSHandler) handleDeleteRecord(ctx context.Context, req *Request) *Response {
	if h.dnsService == nil {
		return h.errorResponse(StatusUnavailable, ErrDNSServiceNotAvailable)
	}

	var deleteReq DNSDeleteRecordRequest
	if err := DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrDNSDecodingFailed{Cause: err})
	}

	if deleteReq.ZoneName == "" {
		return h.errorResponse(StatusInvalidArgument, ErrDNSMissingZoneName)
	}
	if deleteReq.RecordName == "" {
		return h.errorResponse(StatusInvalidArgument, ErrDNSMissingRecordName)
	}
	if deleteReq.RecordType == "" {
		return h.errorResponse(StatusInvalidArgument, ErrDNSMissingRecordType)
	}

	zone, err := h.dnsService.Zone(ctx, deleteReq.ZoneName)
	if err != nil {
		h.logger.Error(err, "failed to get zone for deleting record")
		return h.dnsErrorResponse(err)
	}

	if err := h.deleteRecordFromZone(zone, deleteReq.RecordName, deleteReq.RecordType); err != nil {
		return h.errorResponse(StatusNotFound, err)
	}

	if err := h.dnsService.Save(ctx, zone); err != nil {
		h.logger.Error(err, "failed to save zone after deleting record")
		return h.dnsErrorResponse(err)
	}

	resp := &DNSDeleteRecordResponse{
		ZoneName:   deleteReq.ZoneName,
		RecordName: deleteReq.RecordName,
		RecordType: deleteReq.RecordType,
		Success:    true,
		Timestamp:  time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrDNSEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleListRecords lists all records in a zone
func (h *DNSHandler) handleListRecords(ctx context.Context, req *Request) *Response {
	if h.dnsService == nil {
		return h.errorResponse(StatusUnavailable, ErrDNSServiceNotAvailable)
	}

	var listReq DNSListRecordsRequest
	if err := DecodePayload(req.Payload, &listReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrDNSDecodingFailed{Cause: err})
	}

	if listReq.ZoneName == "" {
		return h.errorResponse(StatusInvalidArgument, ErrDNSMissingZoneName)
	}

	zone, err := h.dnsService.Zone(ctx, listReq.ZoneName)
	if err != nil {
		h.logger.Error(err, "failed to get zone for listing records")
		return h.dnsErrorResponse(err)
	}

	records := h.collectRecords(zone, listReq.TypeFilter)

	resp := &DNSListRecordsResponse{
		Records:   records,
		Count:     int32(len(records)),
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrDNSEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleResolve resolves a DNS name
func (h *DNSHandler) handleResolve(ctx context.Context, req *Request) *Response {
	if h.dnsService == nil {
		return h.errorResponse(StatusUnavailable, ErrDNSServiceNotAvailable)
	}

	var resolveReq DNSResolveRequest
	if err := DecodePayload(req.Payload, &resolveReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrDNSDecodingFailed{Cause: err})
	}

	if resolveReq.FQDN == "" {
		return h.errorResponse(StatusInvalidArgument, ErrDNSMissingFQDN)
	}

	recordType := resolveReq.Type
	if recordType == "" {
		recordType = "A"
	}

	values, err := h.dnsService.Resolve(ctx, resolveReq.FQDN, recordType)
	if err != nil {
		h.logger.Error(err, "failed to resolve DNS query")
		return h.dnsErrorResponse(err)
	}

	resp := &DNSResolveResponse{
		FQDN:          resolveReq.FQDN,
		Type:          recordType,
		Values:        values,
		Authoritative: true,
		Timestamp:     time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrDNSEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Helper Methods
// =============================================================================

// buildZoneFromRequest creates a Zone entity from a DNSAddZoneRequest
func (h *DNSHandler) buildZoneFromRequest(req *DNSAddZoneRequest) *entities.Zone {
	zone := &entities.Zone{
		Name:        req.Name,
		TTL:         req.TTL,
		Description: req.Description,
		Internal:    req.Internal,
	}

	if zone.TTL == 0 {
		zone.TTL = 3600
	}

	if req.SOA != nil {
		zone.RecordSet.SOARecord = entities.SOARecord{
			Name:       req.Name,
			MName:      req.SOA.MName,
			RName:      req.SOA.RName,
			Serial:     req.SOA.Serial,
			Refresh:    req.SOA.Refresh,
			Retry:      req.SOA.Retry,
			Expire:     req.SOA.Expire,
			MinimumTTL: req.SOA.MinimumTTL,
			TTL:        req.SOA.TTL,
		}

		if zone.RecordSet.SOARecord.Refresh == 0 {
			zone.RecordSet.SOARecord.Refresh = 86400
		}
		if zone.RecordSet.SOARecord.Retry == 0 {
			zone.RecordSet.SOARecord.Retry = 7200
		}
		if zone.RecordSet.SOARecord.Expire == 0 {
			zone.RecordSet.SOARecord.Expire = 86400
		}
		if zone.RecordSet.SOARecord.MinimumTTL == 0 {
			zone.RecordSet.SOARecord.MinimumTTL = 3600
		}
		if zone.RecordSet.SOARecord.TTL == 0 {
			zone.RecordSet.SOARecord.TTL = zone.TTL
		}
	}

	for _, ns := range req.NSRecords {
		zone.AddNSRecord(&entities.NSRecord{
			Name:  ns.Name,
			Value: ns.Value,
			TTL:   ns.TTL,
		})
	}

	return zone
}

// addRecordToZone adds a record to the zone based on request type
func (h *DNSHandler) addRecordToZone(zone *entities.Zone, req *DNSAddRecordRequest) error {
	ttl := req.TTL
	if ttl == 0 {
		ttl = zone.TTL
	}

	switch req.Type {
	case "A":
		zone.AddARecord(&entities.ARecord{
			Name:  req.Name,
			Value: req.Value,
			TTL:   ttl,
		})
	case "AAAA":
		zone.AddAAAARecord(&entities.AAAARecord{
			Name:  req.Name,
			Value: req.Value,
			TTL:   ttl,
		})
	case "CNAME":
		zone.AddCNAMERecord(&entities.CNAMERecord{
			Name:  req.Name,
			Value: req.Value,
			TTL:   ttl,
		})
	case "MX":
		zone.AddMXRecord(&entities.MXRecord{
			Name:     req.Name,
			Value:    req.Value,
			Priority: req.Priority,
			TTL:      ttl,
		})
	case "NS":
		zone.AddNSRecord(&entities.NSRecord{
			Name:  req.Name,
			Value: req.Value,
			TTL:   ttl,
		})
	case "TXT":
		zone.AddTXTRecord(&entities.TXTRecord{
			Name:  req.Name,
			Value: req.Value,
			TTL:   ttl,
		})
	case "SRV":
		zone.AddSRVRecord(&entities.SRVRecord{
			Name:     req.Name,
			Target:   req.Target,
			Port:     req.Port,
			Priority: req.Priority,
			Weight:   req.Weight,
			TTL:      ttl,
		})
	case "CAA":
		zone.AddCAARecord(&entities.CAARecord{
			Name:  req.Name,
			Flags: req.Flags,
			Tag:   req.Tag,
			Value: req.Value,
			TTL:   ttl,
		})
	case "TLSA":
		zone.AddTLSARecord(&entities.TLSARecord{
			Name:         req.Name,
			Usage:        req.Usage,
			Selector:     req.Selector,
			MatchingType: req.MatchingType,
			Data:         req.Data,
			TTL:          ttl,
		})
	default:
		return ErrDNSInvalidRecordType
	}
	return nil
}

// updateRecordInZone updates a record in the zone
func (h *DNSHandler) updateRecordInZone(zone *entities.Zone, req *DNSUpdateRecordRequest) error {
	ttl := req.TTL
	if ttl == 0 {
		ttl = zone.TTL
	}

	switch req.Type {
	case "A":
		for _, rec := range zone.RecordSet.ARecords {
			if rec.Name == req.Name {
				if req.Value != "" {
					rec.Value = req.Value
				}
				if req.TTL > 0 {
					rec.TTL = ttl
				}
				return nil
			}
		}
	case "AAAA":
		for _, rec := range zone.RecordSet.AAAARecords {
			if rec.Name == req.Name {
				if req.Value != "" {
					rec.Value = req.Value
				}
				if req.TTL > 0 {
					rec.TTL = ttl
				}
				return nil
			}
		}
	case "CNAME":
		for _, rec := range zone.RecordSet.CNAMERecords {
			if rec.Name == req.Name {
				if req.Value != "" {
					rec.Value = req.Value
				}
				if req.TTL > 0 {
					rec.TTL = ttl
				}
				return nil
			}
		}
	case "MX":
		for _, rec := range zone.RecordSet.MXRecords {
			if rec.Name == req.Name {
				if req.Value != "" {
					rec.Value = req.Value
				}
				if req.Priority > 0 {
					rec.Priority = req.Priority
				}
				if req.TTL > 0 {
					rec.TTL = ttl
				}
				return nil
			}
		}
	case "NS":
		for _, rec := range zone.RecordSet.NSRecords {
			if rec.Name == req.Name {
				if req.Value != "" {
					rec.Value = req.Value
				}
				if req.TTL > 0 {
					rec.TTL = ttl
				}
				return nil
			}
		}
	case "TXT":
		for _, rec := range zone.RecordSet.TXTRecords {
			if rec.Name == req.Name {
				if req.Value != "" {
					rec.Value = req.Value
				}
				if req.TTL > 0 {
					rec.TTL = ttl
				}
				return nil
			}
		}
	case "SRV":
		for _, rec := range zone.RecordSet.SRVRecords {
			if rec.Name == req.Name {
				if req.Target != "" {
					rec.Target = req.Target
				}
				if req.Port > 0 {
					rec.Port = req.Port
				}
				if req.Priority > 0 {
					rec.Priority = req.Priority
				}
				if req.Weight > 0 {
					rec.Weight = req.Weight
				}
				if req.TTL > 0 {
					rec.TTL = ttl
				}
				return nil
			}
		}
	case "CAA":
		for _, rec := range zone.RecordSet.CAARecords {
			if rec.Name == req.Name {
				if req.Value != "" {
					rec.Value = req.Value
				}
				if req.Tag != "" {
					rec.Tag = req.Tag
				}
				rec.Flags = req.Flags
				if req.TTL > 0 {
					rec.TTL = ttl
				}
				return nil
			}
		}
	case "TLSA":
		for _, rec := range zone.RecordSet.TLSARecords {
			if rec.Name == req.Name {
				if req.Data != "" {
					rec.Data = req.Data
				}
				rec.Usage = req.Usage
				rec.Selector = req.Selector
				rec.MatchingType = req.MatchingType
				if req.TTL > 0 {
					rec.TTL = ttl
				}
				return nil
			}
		}
	default:
		return ErrDNSInvalidRecordType
	}
	return ErrDNSRecordNotFound{Name: req.Name, Type: req.Type}
}

// deleteRecordFromZone deletes a record from the zone
func (h *DNSHandler) deleteRecordFromZone(zone *entities.Zone, recordName, recordType string) error {
	switch recordType {
	case "A":
		for i, rec := range zone.RecordSet.ARecords {
			if rec.Name == recordName {
				zone.RecordSet.ARecords = append(zone.RecordSet.ARecords[:i], zone.RecordSet.ARecords[i+1:]...)
				return nil
			}
		}
	case "AAAA":
		for i, rec := range zone.RecordSet.AAAARecords {
			if rec.Name == recordName {
				zone.RecordSet.AAAARecords = append(zone.RecordSet.AAAARecords[:i], zone.RecordSet.AAAARecords[i+1:]...)
				return nil
			}
		}
	case "CNAME":
		for i, rec := range zone.RecordSet.CNAMERecords {
			if rec.Name == recordName {
				zone.RecordSet.CNAMERecords = append(zone.RecordSet.CNAMERecords[:i], zone.RecordSet.CNAMERecords[i+1:]...)
				return nil
			}
		}
	case "MX":
		for i, rec := range zone.RecordSet.MXRecords {
			if rec.Name == recordName {
				zone.RecordSet.MXRecords = append(zone.RecordSet.MXRecords[:i], zone.RecordSet.MXRecords[i+1:]...)
				return nil
			}
		}
	case "NS":
		for i, rec := range zone.RecordSet.NSRecords {
			if rec.Name == recordName {
				zone.RecordSet.NSRecords = append(zone.RecordSet.NSRecords[:i], zone.RecordSet.NSRecords[i+1:]...)
				return nil
			}
		}
	case "TXT":
		for i, rec := range zone.RecordSet.TXTRecords {
			if rec.Name == recordName {
				zone.RecordSet.TXTRecords = append(zone.RecordSet.TXTRecords[:i], zone.RecordSet.TXTRecords[i+1:]...)
				return nil
			}
		}
	case "SRV":
		for i, rec := range zone.RecordSet.SRVRecords {
			if rec.Name == recordName {
				zone.RecordSet.SRVRecords = append(zone.RecordSet.SRVRecords[:i], zone.RecordSet.SRVRecords[i+1:]...)
				return nil
			}
		}
	case "CAA":
		for i, rec := range zone.RecordSet.CAARecords {
			if rec.Name == recordName {
				zone.RecordSet.CAARecords = append(zone.RecordSet.CAARecords[:i], zone.RecordSet.CAARecords[i+1:]...)
				return nil
			}
		}
	case "TLSA":
		for i, rec := range zone.RecordSet.TLSARecords {
			if rec.Name == recordName {
				zone.RecordSet.TLSARecords = append(zone.RecordSet.TLSARecords[:i], zone.RecordSet.TLSARecords[i+1:]...)
				return nil
			}
		}
	default:
		return ErrDNSInvalidRecordType
	}
	return ErrDNSRecordNotFound{Name: recordName, Type: recordType}
}

// collectRecords gathers all records from a zone into a flat list
func (h *DNSHandler) collectRecords(zone *entities.Zone, typeFilter string) []DNSRecordInfo {
	var records []DNSRecordInfo

	if typeFilter == "" || typeFilter == "A" {
		for _, rec := range zone.RecordSet.ARecords {
			records = append(records, DNSRecordInfo{
				ID:   rec.Name,
				Type: "A",
				Data: DNSARecord{
					Name:  rec.Name,
					Value: rec.Value,
					TTL:   rec.TTL,
				},
			})
		}
	}

	if typeFilter == "" || typeFilter == "AAAA" {
		for _, rec := range zone.RecordSet.AAAARecords {
			records = append(records, DNSRecordInfo{
				ID:   rec.Name,
				Type: "AAAA",
				Data: DNSAAAARecord{
					Name:  rec.Name,
					Value: rec.Value,
					TTL:   rec.TTL,
				},
			})
		}
	}

	if typeFilter == "" || typeFilter == "CNAME" {
		for _, rec := range zone.RecordSet.CNAMERecords {
			records = append(records, DNSRecordInfo{
				ID:   rec.Name,
				Type: "CNAME",
				Data: DNSCNAMERecord{
					Name:  rec.Name,
					Value: rec.Value,
					TTL:   rec.TTL,
				},
			})
		}
	}

	if typeFilter == "" || typeFilter == "MX" {
		for _, rec := range zone.RecordSet.MXRecords {
			records = append(records, DNSRecordInfo{
				ID:   rec.Name,
				Type: "MX",
				Data: DNSMXRecord{
					Name:     rec.Name,
					Value:    rec.Value,
					Priority: rec.Priority,
					TTL:      rec.TTL,
				},
			})
		}
	}

	if typeFilter == "" || typeFilter == "NS" {
		for _, rec := range zone.RecordSet.NSRecords {
			records = append(records, DNSRecordInfo{
				ID:   rec.Name,
				Type: "NS",
				Data: DNSNSRecord{
					Name:  rec.Name,
					Value: rec.Value,
					TTL:   rec.TTL,
				},
			})
		}
	}

	if typeFilter == "" || typeFilter == "TXT" {
		for _, rec := range zone.RecordSet.TXTRecords {
			records = append(records, DNSRecordInfo{
				ID:   rec.Name,
				Type: "TXT",
				Data: DNSTXTRecord{
					Name:  rec.Name,
					Value: rec.Value,
					TTL:   rec.TTL,
				},
			})
		}
	}

	if typeFilter == "" || typeFilter == "SRV" {
		for _, rec := range zone.RecordSet.SRVRecords {
			records = append(records, DNSRecordInfo{
				ID:   rec.Name,
				Type: "SRV",
				Data: DNSSRVRecord{
					Name:     rec.Name,
					Target:   rec.Target,
					Port:     rec.Port,
					Priority: rec.Priority,
					Weight:   rec.Weight,
					TTL:      rec.TTL,
				},
			})
		}
	}

	if typeFilter == "" || typeFilter == "CAA" {
		for _, rec := range zone.RecordSet.CAARecords {
			records = append(records, DNSRecordInfo{
				ID:   rec.Name,
				Type: "CAA",
				Data: DNSCAARecord{
					Name:  rec.Name,
					Flags: rec.Flags,
					Tag:   rec.Tag,
					Value: rec.Value,
					TTL:   rec.TTL,
				},
			})
		}
	}

	if typeFilter == "" || typeFilter == "TLSA" {
		for _, rec := range zone.RecordSet.TLSARecords {
			records = append(records, DNSRecordInfo{
				ID:   rec.Name,
				Type: "TLSA",
				Data: DNSTLSARecord{
					Name:         rec.Name,
					Usage:        rec.Usage,
					Selector:     rec.Selector,
					MatchingType: rec.MatchingType,
					Data:         rec.Data,
					TTL:          rec.TTL,
				},
			})
		}
	}

	if typeFilter == "" || typeFilter == "DNSKEY" {
		for _, rec := range zone.RecordSet.DNSKEYRecords {
			records = append(records, DNSRecordInfo{
				ID:   rec.Name,
				Type: "DNSKEY",
				Data: DNSDNSKEYRecord{
					Name:      rec.Name,
					Flags:     rec.Flags,
					Protocol:  rec.Protocol,
					Algorithm: rec.Algorithm,
					Key:       rec.Key,
					TTL:       rec.TTL,
				},
			})
		}
	}

	if typeFilter == "" || typeFilter == "DS" {
		for _, rec := range zone.RecordSet.DSRecords {
			records = append(records, DNSRecordInfo{
				ID:   rec.Name,
				Type: "DS",
				Data: DNSDSRecord{
					Name:       rec.Name,
					KeyTag:     rec.KeyTag,
					Algorithm:  rec.Algorithm,
					DigestType: rec.DigestType,
					Digest:     rec.Digest,
					TTL:        rec.TTL,
				},
			})
		}
	}

	return records
}

// zoneToInfo converts a Zone entity to DNSZoneInfo
func (h *DNSHandler) zoneToInfo(zone *entities.Zone) *DNSZoneInfo {
	if zone == nil {
		return nil
	}

	info := &DNSZoneInfo{
		ID:          zone.ID,
		Name:        zone.Name,
		TTL:         zone.TTL,
		Description: zone.Description,
		Internal:    zone.Internal,
		Records:     h.recordSetToInfo(&zone.RecordSet),
	}

	return info
}

// recordSetToInfo converts a RecordSet to DNSRecordSet
func (h *DNSHandler) recordSetToInfo(rs *entities.RecordSet) *DNSRecordSet {
	info := &DNSRecordSet{}

	if rs.SOARecord.Name != "" {
		info.SOA = &DNSSOARecord{
			Name:       rs.SOARecord.Name,
			MName:      rs.SOARecord.MName,
			RName:      rs.SOARecord.RName,
			Serial:     rs.SOARecord.Serial,
			Refresh:    rs.SOARecord.Refresh,
			Retry:      rs.SOARecord.Retry,
			Expire:     rs.SOARecord.Expire,
			MinimumTTL: rs.SOARecord.MinimumTTL,
			TTL:        rs.SOARecord.TTL,
		}
	}

	for _, rec := range rs.ARecords {
		info.A = append(info.A, DNSARecord{
			Name:  rec.Name,
			Value: rec.Value,
			TTL:   rec.TTL,
		})
	}

	for _, rec := range rs.AAAARecords {
		info.AAAA = append(info.AAAA, DNSAAAARecord{
			Name:  rec.Name,
			Value: rec.Value,
			TTL:   rec.TTL,
		})
	}

	for _, rec := range rs.CNAMERecords {
		info.CNAME = append(info.CNAME, DNSCNAMERecord{
			Name:  rec.Name,
			Value: rec.Value,
			TTL:   rec.TTL,
		})
	}

	for _, rec := range rs.MXRecords {
		info.MX = append(info.MX, DNSMXRecord{
			Name:     rec.Name,
			Value:    rec.Value,
			Priority: rec.Priority,
			TTL:      rec.TTL,
		})
	}

	for _, rec := range rs.NSRecords {
		info.NS = append(info.NS, DNSNSRecord{
			Name:  rec.Name,
			Value: rec.Value,
			TTL:   rec.TTL,
		})
	}

	for _, rec := range rs.TXTRecords {
		info.TXT = append(info.TXT, DNSTXTRecord{
			Name:  rec.Name,
			Value: rec.Value,
			TTL:   rec.TTL,
		})
	}

	for _, rec := range rs.SRVRecords {
		info.SRV = append(info.SRV, DNSSRVRecord{
			Name:     rec.Name,
			Target:   rec.Target,
			Port:     rec.Port,
			Priority: rec.Priority,
			Weight:   rec.Weight,
			TTL:      rec.TTL,
		})
	}

	for _, rec := range rs.CAARecords {
		info.CAA = append(info.CAA, DNSCAARecord{
			Name:  rec.Name,
			Flags: rec.Flags,
			Tag:   rec.Tag,
			Value: rec.Value,
			TTL:   rec.TTL,
		})
	}

	for _, rec := range rs.TLSARecords {
		info.TLSA = append(info.TLSA, DNSTLSARecord{
			Name:         rec.Name,
			Usage:        rec.Usage,
			Selector:     rec.Selector,
			MatchingType: rec.MatchingType,
			Data:         rec.Data,
			TTL:          rec.TTL,
		})
	}

	for _, rec := range rs.DNSKEYRecords {
		info.DNSKEY = append(info.DNSKEY, DNSDNSKEYRecord{
			Name:      rec.Name,
			Flags:     rec.Flags,
			Protocol:  rec.Protocol,
			Algorithm: rec.Algorithm,
			Key:       rec.Key,
			TTL:       rec.TTL,
		})
	}

	for _, rec := range rs.DSRecords {
		info.DS = append(info.DS, DNSDSRecord{
			Name:       rec.Name,
			KeyTag:     rec.KeyTag,
			Algorithm:  rec.Algorithm,
			DigestType: rec.DigestType,
			Digest:     rec.Digest,
			TTL:        rec.TTL,
		})
	}

	return info
}

// errorResponse creates an error response with the given status and error
func (h *DNSHandler) errorResponse(status byte, err error) *Response {
	return &Response{
		Status:  status,
		Payload: []byte(err.Error()),
	}
}

// dnsErrorResponse maps DNS errors to appropriate status codes
func (h *DNSHandler) dnsErrorResponse(err error) *Response {
	var status byte

	switch {
	case errors.Is(err, dns.ErrZoneNotFound):
		status = StatusNotFound
	case errors.Is(err, dns.ErrZoneAlreadyExists):
		status = StatusAlreadyExists
	case errors.Is(err, dns.ErrDNSSECNotEnabled):
		status = StatusInvalidRequest
	case errors.Is(err, dns.ErrRegistrationDisabled):
		status = StatusPermissionDenied
	case errors.Is(err, dns.ErrExternalRegistrationDisabled):
		status = StatusPermissionDenied
	case errors.Is(err, dns.ErrInternalRegistrationDisabled):
		status = StatusPermissionDenied
	case errors.Is(err, dns.ErrInvalidIPAddress):
		status = StatusInvalidArgument
	case errors.Is(err, dns.ErrInvalidPrivateIP):
		status = StatusInvalidArgument
	case errors.Is(err, dns.ErrInvalidPublicIP):
		status = StatusInvalidArgument
	case errors.Is(err, dns.ErrInvalidPrivateTLD):
		status = StatusInvalidArgument
	case errors.Is(err, dns.ErrInvalidPublicTLD):
		status = StatusInvalidArgument
	case errors.Is(err, dns.ErrParsingDomainName):
		status = StatusInvalidArgument
	case errors.Is(err, context.Canceled):
		status = StatusTimeout
	case errors.Is(err, context.DeadlineExceeded):
		status = StatusTimeout
	default:
		status = StatusInternalError
	}

	return h.errorResponse(status, err)
}

// =============================================================================
// DNS Error Types
// =============================================================================

// ErrDNSEncodingFailed represents an encoding failure error
type ErrDNSEncodingFailed struct {
	Cause error
}

func (e ErrDNSEncodingFailed) Error() string {
	return "failed to encode dns payload: " + e.Cause.Error()
}

func (e ErrDNSEncodingFailed) Unwrap() error {
	return e.Cause
}

// ErrDNSDecodingFailed represents a decoding failure error
type ErrDNSDecodingFailed struct {
	Cause error
}

func (e ErrDNSDecodingFailed) Error() string {
	return "failed to decode dns payload: " + e.Cause.Error()
}

func (e ErrDNSDecodingFailed) Unwrap() error {
	return e.Cause
}

// ErrDNSRecordNotFound represents a record not found error
type ErrDNSRecordNotFound struct {
	Name string
	Type string
}

func (e ErrDNSRecordNotFound) Error() string {
	return "record not found: " + e.Name + " " + e.Type
}

// ErrDNSOperationFailed represents a DNS operation failure
type ErrDNSOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrDNSOperationFailed) Error() string {
	return "dns operation " + e.Operation + " failed: " + e.Cause.Error()
}

func (e ErrDNSOperationFailed) Unwrap() error {
	return e.Cause
}
