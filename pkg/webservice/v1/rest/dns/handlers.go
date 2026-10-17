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
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

const (
	defaultLimit  int32 = dns.DefaultPageLimit
	maxLimit      int32 = dns.MaxPageLimit
	defaultOffset int32 = 0

	requestTimeout = 30 * time.Second
)

// DNSHandlers provides REST handlers for DNS operations.
// All handlers delegate to the dns.DNSService interface (service layer).
type DNSHandlers struct {
	logger     *logging.Logger
	service    dns.DNSService
	respWriter response.HttpWriter
}

// NewDNSHandlers creates a new DNSHandlers instance.
func NewDNSHandlers(
	logger *logging.Logger,
	service dns.DNSService,
	respWriter response.HttpWriter,
) *DNSHandlers {
	return &DNSHandlers{
		logger:     logger,
		service:    service,
		respWriter: respWriter,
	}
}

// Helper methods

func (h *DNSHandlers) getZoneName(r *http.Request) string {
	return mux.Vars(r)["zone"]
}

func (h *DNSHandlers) getRecordType(r *http.Request) string {
	return mux.Vars(r)["type"]
}

func (h *DNSHandlers) getRecordName(r *http.Request) string {
	return mux.Vars(r)["name"]
}

func (h *DNSHandlers) getPaginationParams(r *http.Request) (int32, int32) {
	limit := defaultLimit
	offset := defaultOffset

	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.ParseInt(l, 10, 32); err == nil {
			limit = int32(parsed)
			if limit > maxLimit {
				limit = maxLimit
			}
			if limit < 1 {
				limit = defaultLimit
			}
		}
	}

	if o := r.URL.Query().Get("offset"); o != "" {
		if parsed, err := strconv.ParseInt(o, 10, 32); err == nil {
			offset = int32(parsed)
			if offset < 0 {
				offset = defaultOffset
			}
		}
	}

	return limit, offset
}

// pageBounds returns the [start, end) bounds of the page of n items a list
// route answers. A request that sends neither limit nor offset gets every
// item, so a caller that does not page never loses the tail of a list.
func (h *DNSHandlers) pageBounds(r *http.Request, n int) (int, int) {
	query := r.URL.Query()
	if !query.Has("limit") && !query.Has("offset") {
		return 0, n
	}
	limit, offset := h.getPaginationParams(r)
	start := min(int(offset), n)
	end := min(start+int(limit), n)
	return start, end
}

func (h *DNSHandlers) createContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), requestTimeout)
}

func (h *DNSHandlers) decodeJSON(r *http.Request, v interface{}) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(v)
}

// Zone Handlers

// CreateZone handles POST /api/v1/dns/zones
func (h *DNSHandlers) CreateZone(w http.ResponseWriter, r *http.Request) {
	var req CreateZoneRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Name == "" {
		h.respWriter.Error400(w, r, ErrMissingZoneName{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	// Build SOA record
	var soaRecord entities.SOARecord
	if req.SOA != nil {
		soaRecord = entities.SOARecord{
			Name:       req.SOA.Name,
			MName:      req.SOA.MName,
			RName:      req.SOA.RName,
			Serial:     req.SOA.Serial,
			Refresh:    req.SOA.Refresh,
			Retry:      req.SOA.Retry,
			Expire:     req.SOA.Expire,
			MinimumTTL: req.SOA.MinimumTTL,
			TTL:        req.SOA.TTL,
		}
	}

	// Build NS records
	var nsRecords []*entities.NSRecord
	for _, ns := range req.NSRecords {
		nsRecords = append(nsRecords, &entities.NSRecord{
			Name:  ns.Name,
			Value: ns.Value,
			TTL:   ns.TTL,
		})
	}

	zone := &entities.Zone{
		Name:        req.Name,
		TTL:         req.TTL,
		Description: req.Description,
		Internal:    req.Internal,
		RecordSet: entities.RecordSet{
			SOARecord: soaRecord,
			NSRecords: nsRecords,
		},
	}

	if err := h.service.Save(ctx, zone); err != nil {
		h.respWriter.Error500(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, h.zoneToResponse(zone))
}

// GetZone handles GET /api/v1/dns/zones/{zone}
func (h *DNSHandlers) GetZone(w http.ResponseWriter, r *http.Request) {
	zoneName := h.getZoneName(r)
	if zoneName == "" {
		h.respWriter.Error400(w, r, ErrMissingZoneName{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	zone, err := h.service.Zone(ctx, zoneName)
	if err != nil {
		h.respWriter.Error404(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, h.zoneToResponse(zone))
}

// UpdateZone handles PUT /api/v1/dns/zones/{zone}
func (h *DNSHandlers) UpdateZone(w http.ResponseWriter, r *http.Request) {
	zoneName := h.getZoneName(r)
	if zoneName == "" {
		h.respWriter.Error400(w, r, ErrMissingZoneName{})
		return
	}

	var req UpdateZoneRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	zone, err := h.service.Zone(ctx, zoneName)
	if err != nil {
		h.respWriter.Error404(w, r, err)
		return
	}

	if req.TTL > 0 {
		zone.TTL = req.TTL
	}
	if req.Description != "" {
		zone.Description = req.Description
	}

	if err := h.service.Save(ctx, zone); err != nil {
		h.respWriter.Error500(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, h.zoneToResponse(zone))
}

// DeleteZone handles DELETE /api/v1/dns/zones/{zone}
func (h *DNSHandlers) DeleteZone(w http.ResponseWriter, r *http.Request) {
	zoneName := h.getZoneName(r)
	if zoneName == "" {
		h.respWriter.Error400(w, r, ErrMissingZoneName{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	zone, err := h.service.Zone(ctx, zoneName)
	if err != nil {
		h.respWriter.Error404(w, r, err)
		return
	}

	if err := h.service.Delete(ctx, zone); err != nil {
		h.respWriter.Error500(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, SuccessResponse{
		Success: true,
		Message: "zone deleted successfully",
	})
}

// ListZones handles GET /api/v1/dns/zones
func (h *DNSHandlers) ListZones(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := h.createContext()
	defer cancel()

	zones, err := h.service.ListZones(ctx)
	if err != nil {
		h.respWriter.Error500(w, r, err)
		return
	}

	// Apply filters
	internalOnly := r.URL.Query().Get("internal") == "true"
	publicOnly := r.URL.Query().Get("public") == "true"

	var responseZones []ZoneResponse
	for _, zone := range zones {
		if internalOnly && !zone.Internal {
			continue
		}
		if publicOnly && zone.Internal {
			continue
		}
		responseZones = append(responseZones, h.zoneToResponse(zone))
	}

	limit, offset := h.getPaginationParams(r)
	start, end := h.pageBounds(r, len(responseZones))

	h.respWriter.Success200(w, r, ListZonesResponse{
		PaginatedResponse: PaginatedResponse{
			Total:  int64(len(responseZones)),
			Limit:  limit,
			Offset: offset,
		},
		Zones: responseZones[start:end],
	})
}

// Record Handlers

// AddRecord handles POST /api/v1/dns/zones/{zone}/records
func (h *DNSHandlers) AddRecord(w http.ResponseWriter, r *http.Request) {
	zoneName := h.getZoneName(r)
	if zoneName == "" {
		h.respWriter.Error400(w, r, ErrMissingZoneName{})
		return
	}

	var req AddRecordRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Type == "" {
		h.respWriter.Error400(w, r, ErrMissingRecordType{})
		return
	}

	recordType := strings.ToUpper(req.Type)
	fields, ok := addRecordFields[recordType]
	if !ok {
		h.respWriter.Error400(w, r, ErrInvalidRecordType{Type: req.Type})
		return
	}
	name, value := fields(&req)
	if err := dns.ValidateRecord(recordType, name, value); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	zone, err := h.service.Zone(ctx, zoneName)
	if err != nil {
		h.respWriter.Error404(w, r, err)
		return
	}

	// Add record based on type
	switch recordType {
	case "A":
		if req.A != nil {
			zone.AddARecord(&entities.ARecord{
				Name:  req.A.Name,
				Value: req.A.Value,
				TTL:   req.A.TTL,
			})
		}
	case "AAAA":
		if req.AAAA != nil {
			zone.AddAAAARecord(&entities.AAAARecord{
				Name:  req.AAAA.Name,
				Value: req.AAAA.Value,
				TTL:   req.AAAA.TTL,
			})
		}
	case "CNAME":
		if req.CNAME != nil {
			zone.AddCNAMERecord(&entities.CNAMERecord{
				Name:  req.CNAME.Name,
				Value: req.CNAME.Value,
				TTL:   req.CNAME.TTL,
			})
		}
	case "MX":
		if req.MX != nil {
			zone.AddMXRecord(&entities.MXRecord{
				Name:     req.MX.Name,
				Value:    req.MX.Value,
				Priority: req.MX.Priority,
				TTL:      req.MX.TTL,
			})
		}
	case "NS":
		if req.NS != nil {
			zone.AddNSRecord(&entities.NSRecord{
				Name:  req.NS.Name,
				Value: req.NS.Value,
				TTL:   req.NS.TTL,
			})
		}
	case "TXT":
		if req.TXT != nil {
			zone.AddTXTRecord(&entities.TXTRecord{
				Name:  req.TXT.Name,
				Value: req.TXT.Value,
				TTL:   req.TXT.TTL,
			})
		}
	case "SRV":
		if req.SRV != nil {
			zone.AddSRVRecord(&entities.SRVRecord{
				Name:     req.SRV.Name,
				Target:   req.SRV.Target,
				Port:     req.SRV.Port,
				Priority: req.SRV.Priority,
				Weight:   req.SRV.Weight,
				TTL:      req.SRV.TTL,
			})
		}
	case "CAA":
		if req.CAA != nil {
			zone.AddCAARecord(&entities.CAARecord{
				Name:  req.CAA.Name,
				Flags: req.CAA.Flags,
				Tag:   req.CAA.Tag,
				Value: req.CAA.Value,
				TTL:   req.CAA.TTL,
			})
		}
	case "TLSA":
		if req.TLSA != nil {
			if err := dns.ValidateTLSAUsage(uint32(req.TLSA.Usage)); err != nil {
				h.respWriter.Error400(w, r, err)
				return
			}
			zone.AddTLSARecord(&entities.TLSARecord{
				Name:         req.TLSA.Name,
				Usage:        req.TLSA.Usage,
				Selector:     req.TLSA.Selector,
				MatchingType: req.TLSA.MatchingType,
				Data:         req.TLSA.Data,
				TTL:          req.TLSA.TTL,
			})
		}
	default:
		h.respWriter.Error400(w, r, ErrInvalidRecordType{Type: req.Type})
		return
	}

	if err := h.service.Save(ctx, zone); err != nil {
		h.respWriter.Error500(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, h.zoneToResponse(zone))
}

// addRecordFields returns the owner name and value of the record an
// AddRecordRequest carries for each record type, both empty when the request
// has no body of that type. Only the A and AAAA values are checked.
var addRecordFields = map[string]func(*AddRecordRequest) (string, string){
	"A": func(req *AddRecordRequest) (string, string) {
		if req.A == nil {
			return "", ""
		}
		return req.A.Name, req.A.Value
	},
	"AAAA": func(req *AddRecordRequest) (string, string) {
		if req.AAAA == nil {
			return "", ""
		}
		return req.AAAA.Name, req.AAAA.Value
	},
	"CNAME": func(req *AddRecordRequest) (string, string) {
		if req.CNAME == nil {
			return "", ""
		}
		return req.CNAME.Name, req.CNAME.Value
	},
	"MX": func(req *AddRecordRequest) (string, string) {
		if req.MX == nil {
			return "", ""
		}
		return req.MX.Name, req.MX.Value
	},
	"NS": func(req *AddRecordRequest) (string, string) {
		if req.NS == nil {
			return "", ""
		}
		return req.NS.Name, req.NS.Value
	},
	"TXT": func(req *AddRecordRequest) (string, string) {
		if req.TXT == nil {
			return "", ""
		}
		return req.TXT.Name, req.TXT.Value
	},
	"SRV": func(req *AddRecordRequest) (string, string) {
		if req.SRV == nil {
			return "", ""
		}
		return req.SRV.Name, req.SRV.Target
	},
	"CAA": func(req *AddRecordRequest) (string, string) {
		if req.CAA == nil {
			return "", ""
		}
		return req.CAA.Name, req.CAA.Value
	},
	"TLSA": func(req *AddRecordRequest) (string, string) {
		if req.TLSA == nil {
			return "", ""
		}
		return req.TLSA.Name, ""
	},
}

// DeleteRecord handles DELETE /api/v1/dns/zones/{zone}/records/{type}/{name}
func (h *DNSHandlers) DeleteRecord(w http.ResponseWriter, r *http.Request) {
	zoneName := h.getZoneName(r)
	if zoneName == "" {
		h.respWriter.Error400(w, r, ErrMissingZoneName{})
		return
	}

	recordType := h.getRecordType(r)
	if recordType == "" {
		h.respWriter.Error400(w, r, ErrMissingRecordType{})
		return
	}

	recordName := h.getRecordName(r)
	if recordName == "" {
		h.respWriter.Error400(w, r, ErrMissingRecordName{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	zone, err := h.service.Zone(ctx, zoneName)
	if err != nil {
		h.respWriter.Error404(w, r, err)
		return
	}

	// Delete record based on type
	switch strings.ToUpper(recordType) {
	case "A":
		zone.RemoveARecord(recordName)
	case "AAAA":
		zone.RemoveAAAARecord(recordName)
	case "CNAME":
		zone.RemoveCNAMERecord(recordName)
	case "MX":
		zone.RemoveMXRecord(recordName)
	case "NS":
		zone.RemoveNSRecord(recordName)
	case "TXT":
		zone.RemoveTXTRecord(recordName)
	case "SRV":
		zone.RemoveSRVRecord(recordName)
	case "CAA":
		zone.RemoveCAARecord(recordName)
	case "TLSA":
		zone.RemoveTLSARecord(recordName)
	default:
		h.respWriter.Error400(w, r, ErrInvalidRecordType{Type: recordType})
		return
	}

	if err := h.service.Save(ctx, zone); err != nil {
		h.respWriter.Error500(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, h.zoneToResponse(zone))
}

// ListRecords handles GET /api/v1/dns/zones/{zone}/records
func (h *DNSHandlers) ListRecords(w http.ResponseWriter, r *http.Request) {
	zoneName := h.getZoneName(r)
	if zoneName == "" {
		h.respWriter.Error400(w, r, ErrMissingZoneName{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	zone, err := h.service.Zone(ctx, zoneName)
	if err != nil {
		h.respWriter.Error404(w, r, err)
		return
	}

	// Filter by type if provided
	typeFilter := strings.ToUpper(r.URL.Query().Get("type"))

	records := h.extractRecords(&zone.RecordSet, typeFilter)
	limit, offset := h.getPaginationParams(r)
	start, end := h.pageBounds(r, len(records))

	h.respWriter.Success200(w, r, ListRecordsResponse{
		PaginatedResponse: PaginatedResponse{
			Total:  int64(len(records)),
			Limit:  limit,
			Offset: offset,
		},
		Records: records[start:end],
	})
}

// recordTypes are the record types a zone's record set carries.
var recordTypes = map[string]bool{
	"A": true, "AAAA": true, "CNAME": true, "MX": true, "NS": true,
	"TXT": true, "SRV": true, "CAA": true, "TLSA": true,
}

// GetRecord returns the record of one type and name in a zone.
func (h *DNSHandlers) GetRecord(w http.ResponseWriter, r *http.Request) {
	zoneName := h.getZoneName(r)
	if zoneName == "" {
		h.respWriter.Error400(w, r, ErrMissingZoneName{})
		return
	}

	recordType := strings.ToUpper(h.getRecordType(r))
	if recordType == "" {
		h.respWriter.Error400(w, r, ErrMissingRecordType{})
		return
	}
	if !recordTypes[recordType] {
		h.respWriter.Error400(w, r, ErrInvalidRecordType{Type: recordType})
		return
	}

	recordName := h.getRecordName(r)
	if recordName == "" {
		h.respWriter.Error400(w, r, ErrMissingRecordName{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	zone, err := h.service.Zone(ctx, zoneName)
	if err != nil {
		h.respWriter.Error404(w, r, err)
		return
	}

	for _, record := range h.extractRecords(&zone.RecordSet, recordType) {
		if record.Name() == recordName {
			h.respWriter.Success200(w, r, record)
			return
		}
	}
	h.respWriter.Error404(w, r, ErrRecordNotFound{Type: recordType, Name: recordName})
}

// Resolve answers a name from the zones this platform serves, through
// dns.ResolveName as every transport does. A name with no managed zone is not
// an error: the answer is empty and not authoritative. A type resolution does
// not serve is a 400.
func (h *DNSHandlers) Resolve(w http.ResponseWriter, r *http.Request) {
	fqdn := r.URL.Query().Get("fqdn")
	if fqdn == "" {
		h.respWriter.Error400(w, r, ErrMissingFQDN{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	recordType := r.URL.Query().Get("type")
	resolution, err := dns.ResolveName(ctx, h.service, fqdn, recordType)
	if err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRecordType{Type: recordType})
		return
	}

	// An empty answer is an empty list, never null.
	records := append([]RecordResponse{}, h.extractRecords(&resolution.Records, "")...)
	h.respWriter.Success200(w, r, ResolveResponse{
		Records:       records,
		Authoritative: resolution.Authoritative,
	})
}

// DNSSEC Handlers

// SignZone handles POST /api/v1/dns/zones/{zone}/sign
func (h *DNSHandlers) SignZone(w http.ResponseWriter, r *http.Request) {
	zoneName := h.getZoneName(r)
	if zoneName == "" {
		h.respWriter.Error400(w, r, ErrMissingZoneName{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	zone, err := h.service.Zone(ctx, zoneName)
	if err != nil {
		h.respWriter.Error404(w, r, err)
		return
	}

	if err := h.service.SignZone(zone); err != nil {
		h.respWriter.Error500(w, r, err)
		return
	}

	if err := h.service.Save(ctx, zone); err != nil {
		h.respWriter.Error500(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, h.zoneToResponse(zone))
}

// GetDNSSECStatus handles GET /api/v1/dns/zones/{zone}/dnssec
func (h *DNSHandlers) GetDNSSECStatus(w http.ResponseWriter, r *http.Request) {
	zoneName := h.getZoneName(r)
	if zoneName == "" {
		h.respWriter.Error400(w, r, ErrMissingZoneName{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	zone, err := h.service.Zone(ctx, zoneName)
	if err != nil {
		h.respWriter.Error404(w, r, err)
		return
	}

	status := DNSSECStatusResponse{
		Enabled:    h.service.IsDNSSECEnabled(),
		ZoneSigned: len(zone.RecordSet.DNSKEYRecords) > 0,
	}

	for _, key := range zone.RecordSet.DNSKEYRecords {
		status.Keys = append(status.Keys, &DNSKEYResponse{
			Name:      key.Name,
			Flags:     key.Flags,
			Protocol:  key.Protocol,
			Algorithm: key.Algorithm,
			Key:       key.Key,
			TTL:       key.TTL,
		})
	}

	for _, ds := range zone.RecordSet.DSRecords {
		status.DSRecords = append(status.DSRecords, &DSResponse{
			Name:       ds.Name,
			KeyTag:     ds.KeyTag,
			Algorithm:  ds.Algorithm,
			DigestType: ds.DigestType,
			Digest:     ds.Digest,
			TTL:        ds.TTL,
		})
	}

	h.respWriter.Success200(w, r, status)
}

// Registration Handler

// Register handles POST /api/v1/dns/register
func (h *DNSHandlers) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.FQDN == "" {
		h.respWriter.Error400(w, r, ErrMissingFQDN{})
		return
	}
	if req.IP == "" {
		h.respWriter.Error400(w, r, ErrMissingIP{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	zone, err := h.service.Register(ctx, req.FQDN, req.IP)
	if err != nil {
		h.respWriter.Error500(w, r, err)
		return
	}

	var zoneResp *ZoneResponse
	if zone != nil {
		resp := h.zoneToResponse(zone)
		zoneResp = &resp
	}

	h.respWriter.Success200(w, r, struct {
		Success bool          `json:"success"`
		Message string        `json:"message"`
		Zone    *ZoneResponse `json:"zone,omitempty"`
	}{
		Success: true,
		Message: "registration successful",
		Zone:    zoneResp,
	})
}

// Helper conversion methods

func (h *DNSHandlers) zoneToResponse(zone *entities.Zone) ZoneResponse {
	if zone == nil {
		return ZoneResponse{}
	}

	resp := ZoneResponse{
		ID:          zone.ID,
		Name:        zone.Name,
		TTL:         zone.TTL,
		Description: zone.Description,
		Internal:    zone.Internal,
		Records:     h.recordSetToResponse(&zone.RecordSet),
	}
	// Only emit real lifecycle timestamps; a zero-value time would render
	// as "0001-01-01T00:00:00Z" which is worse than absent. The frontend
	// shows "—" when the field is missing instead of falling back to
	// `new Date()` and lying about when the zone was created.
	if !zone.CreatedAt.IsZero() {
		resp.CreatedAt = zone.CreatedAt.UTC().Format(time.RFC3339)
	}
	if !zone.UpdatedAt.IsZero() {
		resp.UpdatedAt = zone.UpdatedAt.UTC().Format(time.RFC3339)
	}
	return resp
}

func (h *DNSHandlers) recordSetToResponse(rs *entities.RecordSet) *RecordSetResponse {
	if rs == nil {
		return nil
	}

	resp := &RecordSetResponse{
		SOA: &SOAResponse{
			Name:       rs.SOARecord.Name,
			MName:      rs.SOARecord.MName,
			RName:      rs.SOARecord.RName,
			Serial:     rs.SOARecord.Serial,
			Refresh:    rs.SOARecord.Refresh,
			Retry:      rs.SOARecord.Retry,
			Expire:     rs.SOARecord.Expire,
			MinimumTTL: rs.SOARecord.MinimumTTL,
			TTL:        rs.SOARecord.TTL,
		},
	}

	for _, r := range rs.ARecords {
		resp.A = append(resp.A, &AResponse{
			Name:  r.Name,
			Value: r.Value,
			TTL:   r.TTL,
		})
	}

	for _, r := range rs.AAAARecords {
		resp.AAAA = append(resp.AAAA, &AAAAResponse{
			Name:  r.Name,
			Value: r.Value,
			TTL:   r.TTL,
		})
	}

	for _, r := range rs.CNAMERecords {
		resp.CNAME = append(resp.CNAME, &CNAMEResponse{
			Name:  r.Name,
			Value: r.Value,
			TTL:   r.TTL,
		})
	}

	for _, r := range rs.MXRecords {
		resp.MX = append(resp.MX, &MXResponse{
			Name:     r.Name,
			Value:    r.Value,
			Priority: r.Priority,
			TTL:      r.TTL,
		})
	}

	for _, r := range rs.NSRecords {
		resp.NS = append(resp.NS, &NSResponse{
			Name:  r.Name,
			Value: r.Value,
			TTL:   r.TTL,
		})
	}

	for _, r := range rs.TXTRecords {
		resp.TXT = append(resp.TXT, &TXTResponse{
			Name:  r.Name,
			Value: r.Value,
			TTL:   r.TTL,
		})
	}

	for _, r := range rs.SRVRecords {
		resp.SRV = append(resp.SRV, &SRVResponse{
			Name:     r.Name,
			Target:   r.Target,
			Port:     r.Port,
			Priority: r.Priority,
			Weight:   r.Weight,
			TTL:      r.TTL,
		})
	}

	for _, r := range rs.CAARecords {
		resp.CAA = append(resp.CAA, &CAAResponse{
			Name:  r.Name,
			Flags: r.Flags,
			Tag:   r.Tag,
			Value: r.Value,
			TTL:   r.TTL,
		})
	}

	for _, r := range rs.TLSARecords {
		resp.TLSA = append(resp.TLSA, &TLSAResponse{
			Name:         r.Name,
			Usage:        r.Usage,
			Selector:     r.Selector,
			MatchingType: r.MatchingType,
			Data:         r.Data,
			TTL:          r.TTL,
		})
	}

	for _, r := range rs.DNSKEYRecords {
		resp.DNSKEY = append(resp.DNSKEY, &DNSKEYResponse{
			Name:      r.Name,
			Flags:     r.Flags,
			Protocol:  r.Protocol,
			Algorithm: r.Algorithm,
			Key:       r.Key,
			TTL:       r.TTL,
		})
	}

	for _, r := range rs.DSRecords {
		resp.DS = append(resp.DS, &DSResponse{
			Name:       r.Name,
			KeyTag:     r.KeyTag,
			Algorithm:  r.Algorithm,
			DigestType: r.DigestType,
			Digest:     r.Digest,
			TTL:        r.TTL,
		})
	}

	return resp
}

func (h *DNSHandlers) extractRecords(rs *entities.RecordSet, typeFilter string) []RecordResponse {
	var records []RecordResponse

	if typeFilter == "" || typeFilter == "A" {
		for _, r := range rs.ARecords {
			records = append(records, RecordResponse{
				Type: "A",
				A:    &AResponse{Name: r.Name, Value: r.Value, TTL: r.TTL},
			})
		}
	}

	if typeFilter == "" || typeFilter == "AAAA" {
		for _, r := range rs.AAAARecords {
			records = append(records, RecordResponse{
				Type: "AAAA",
				AAAA: &AAAAResponse{Name: r.Name, Value: r.Value, TTL: r.TTL},
			})
		}
	}

	if typeFilter == "" || typeFilter == "CNAME" {
		for _, r := range rs.CNAMERecords {
			records = append(records, RecordResponse{
				Type:  "CNAME",
				CNAME: &CNAMEResponse{Name: r.Name, Value: r.Value, TTL: r.TTL},
			})
		}
	}

	if typeFilter == "" || typeFilter == "MX" {
		for _, r := range rs.MXRecords {
			records = append(records, RecordResponse{
				Type: "MX",
				MX:   &MXResponse{Name: r.Name, Value: r.Value, Priority: r.Priority, TTL: r.TTL},
			})
		}
	}

	if typeFilter == "" || typeFilter == "NS" {
		for _, r := range rs.NSRecords {
			records = append(records, RecordResponse{
				Type: "NS",
				NS:   &NSResponse{Name: r.Name, Value: r.Value, TTL: r.TTL},
			})
		}
	}

	if typeFilter == "" || typeFilter == "TXT" {
		for _, r := range rs.TXTRecords {
			records = append(records, RecordResponse{
				Type: "TXT",
				TXT:  &TXTResponse{Name: r.Name, Value: r.Value, TTL: r.TTL},
			})
		}
	}

	if typeFilter == "" || typeFilter == "SRV" {
		for _, r := range rs.SRVRecords {
			records = append(records, RecordResponse{
				Type: "SRV",
				SRV:  &SRVResponse{Name: r.Name, Target: r.Target, Port: r.Port, Priority: r.Priority, Weight: r.Weight, TTL: r.TTL},
			})
		}
	}

	if typeFilter == "" || typeFilter == "CAA" {
		for _, r := range rs.CAARecords {
			records = append(records, RecordResponse{
				Type: "CAA",
				CAA:  &CAAResponse{Name: r.Name, Flags: r.Flags, Tag: r.Tag, Value: r.Value, TTL: r.TTL},
			})
		}
	}

	if typeFilter == "" || typeFilter == "TLSA" {
		for _, r := range rs.TLSARecords {
			records = append(records, RecordResponse{
				Type: "TLSA",
				TLSA: &TLSAResponse{Name: r.Name, Usage: r.Usage, Selector: r.Selector, MatchingType: r.MatchingType, Data: r.Data, TTL: r.TTL},
			})
		}
	}

	return records
}
