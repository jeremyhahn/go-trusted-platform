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

// Package rest provides REST API handlers for the trusted platform services.
package rest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
)

// =============================================================================
// DNS REST Handler Errors
// =============================================================================

// ErrDNSServiceNotAvailable is returned when the DNS service is not configured
// or unavailable.
type ErrDNSServiceNotAvailable struct{}

func (e ErrDNSServiceNotAvailable) Error() string {
	return "dns service not available"
}

// ErrInvalidZoneName is returned when a zone name is invalid or empty.
type ErrInvalidZoneName struct {
	Name string
}

func (e ErrInvalidZoneName) Error() string {
	if e.Name == "" {
		return "zone name is required"
	}
	return fmt.Sprintf("invalid zone name: %s", e.Name)
}

// ErrInvalidRecordID is returned when a record ID is invalid or empty.
type ErrInvalidRecordID struct {
	ID string
}

func (e ErrInvalidRecordID) Error() string {
	if e.ID == "" {
		return "record ID is required"
	}
	return fmt.Sprintf("invalid record ID: %s", e.ID)
}

// ErrDNSOperationFailed is returned when a DNS operation fails.
type ErrDNSOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrDNSOperationFailed) Error() string {
	return fmt.Sprintf("dns operation %s failed: %v", e.Operation, e.Cause)
}

func (e ErrDNSOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrInvalidRecordType is returned when an unsupported record type is specified.
type ErrInvalidRecordType struct {
	Type string
}

func (e ErrInvalidRecordType) Error() string {
	return fmt.Sprintf("invalid record type: %s", e.Type)
}

// ErrRecordNotFound is returned when a DNS record is not found.
type ErrRecordNotFound struct {
	Name string
	Type string
}

func (e ErrRecordNotFound) Error() string {
	return fmt.Sprintf("record not found: %s %s", e.Name, e.Type)
}

// =============================================================================
// Request/Response Types
// =============================================================================

// CreateZoneRequest represents a zone creation request.
type CreateZoneRequest struct {
	Name        string            `json:"name"`
	TTL         uint32            `json:"ttl,omitempty"`
	Description string            `json:"description,omitempty"`
	Internal    bool              `json:"internal,omitempty"`
	SOA         *SOARecordRequest `json:"soa,omitempty"`
	NSRecords   []NSRecordRequest `json:"ns_records,omitempty"`
}

// SOARecordRequest represents a SOA record in API requests.
type SOARecordRequest struct {
	MName      string `json:"mname"`
	RName      string `json:"rname"`
	Serial     uint32 `json:"serial,omitempty"`
	Refresh    uint32 `json:"refresh,omitempty"`
	Retry      uint32 `json:"retry,omitempty"`
	Expire     uint32 `json:"expire,omitempty"`
	MinimumTTL uint32 `json:"minimum_ttl,omitempty"`
	TTL        uint32 `json:"ttl,omitempty"`
}

// NSRecordRequest represents a NS record in API requests.
type NSRecordRequest struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl,omitempty"`
}

// ZoneResponse represents a zone in API responses.
type ZoneResponse struct {
	ID          uint64             `json:"id"`
	Name        string             `json:"name"`
	TTL         uint32             `json:"ttl"`
	Description string             `json:"description,omitempty"`
	Internal    bool               `json:"internal"`
	Records     *RecordSetResponse `json:"records,omitempty"`
}

// RecordSetResponse represents the record set in API responses.
type RecordSetResponse struct {
	SOA    *SOARecordResponse     `json:"soa,omitempty"`
	A      []ARecordResponse      `json:"a,omitempty"`
	AAAA   []AAAARecordResponse   `json:"aaaa,omitempty"`
	CNAME  []CNAMERecordResponse  `json:"cname,omitempty"`
	MX     []MXRecordResponse     `json:"mx,omitempty"`
	NS     []NSRecordResponse     `json:"ns,omitempty"`
	TXT    []TXTRecordResponse    `json:"txt,omitempty"`
	SRV    []SRVRecordResponse    `json:"srv,omitempty"`
	CAA    []CAARecordResponse    `json:"caa,omitempty"`
	TLSA   []TLSARecordResponse   `json:"tlsa,omitempty"`
	DNSKEY []DNSKEYRecordResponse `json:"dnskey,omitempty"`
	DS     []DSRecordResponse     `json:"ds,omitempty"`
}

// SOARecordResponse represents a SOA record in API responses.
type SOARecordResponse struct {
	Name       string `json:"name"`
	MName      string `json:"mname"`
	RName      string `json:"rname"`
	Serial     uint32 `json:"serial"`
	Refresh    uint32 `json:"refresh"`
	Retry      uint32 `json:"retry"`
	Expire     uint32 `json:"expire"`
	MinimumTTL uint32 `json:"minimum_ttl"`
	TTL        uint32 `json:"ttl"`
}

// ARecordResponse represents an A record in API responses.
type ARecordResponse struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl"`
}

// AAAARecordResponse represents an AAAA record in API responses.
type AAAARecordResponse struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl"`
}

// CNAMERecordResponse represents a CNAME record in API responses.
type CNAMERecordResponse struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl"`
}

// MXRecordResponse represents an MX record in API responses.
type MXRecordResponse struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Priority uint16 `json:"priority"`
	TTL      uint32 `json:"ttl"`
}

// NSRecordResponse represents an NS record in API responses.
type NSRecordResponse struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl"`
}

// TXTRecordResponse represents a TXT record in API responses.
type TXTRecordResponse struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl"`
}

// SRVRecordResponse represents an SRV record in API responses.
type SRVRecordResponse struct {
	Name     string `json:"name"`
	Target   string `json:"target"`
	Port     uint16 `json:"port"`
	Priority uint16 `json:"priority"`
	Weight   uint16 `json:"weight"`
	TTL      uint32 `json:"ttl"`
}

// CAARecordResponse represents a CAA record in API responses.
type CAARecordResponse struct {
	Name  string `json:"name"`
	Flags uint8  `json:"flags"`
	Tag   string `json:"tag"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl"`
}

// TLSARecordResponse represents a TLSA record in API responses.
type TLSARecordResponse struct {
	Name         string `json:"name"`
	Usage        uint8  `json:"usage"`
	Selector     uint8  `json:"selector"`
	MatchingType uint8  `json:"matching_type"`
	Data         string `json:"data"`
	TTL          uint32 `json:"ttl"`
}

// DNSKEYRecordResponse represents a DNSKEY record in API responses.
type DNSKEYRecordResponse struct {
	Name      string `json:"name"`
	Flags     uint16 `json:"flags"`
	Protocol  uint8  `json:"protocol"`
	Algorithm uint8  `json:"algorithm"`
	Key       string `json:"key"`
	TTL       uint32 `json:"ttl"`
}

// DSRecordResponse represents a DS record in API responses.
type DSRecordResponse struct {
	Name       string `json:"name"`
	KeyTag     uint16 `json:"key_tag"`
	Algorithm  uint8  `json:"algorithm"`
	DigestType uint8  `json:"digest_type"`
	Digest     string `json:"digest"`
	TTL        uint32 `json:"ttl"`
}

// ZoneListResponse represents a list of zones.
type ZoneListResponse struct {
	Zones     []ZoneResponse `json:"zones"`
	Count     int            `json:"count"`
	Timestamp time.Time      `json:"timestamp"`
}

// AddRecordRequest represents a request to add a DNS record.
type AddRecordRequest struct {
	Type         string `json:"type"`
	Name         string `json:"name"`
	Value        string `json:"value,omitempty"`
	TTL          uint32 `json:"ttl,omitempty"`
	Priority     uint16 `json:"priority,omitempty"`
	Weight       uint16 `json:"weight,omitempty"`
	Port         uint16 `json:"port,omitempty"`
	Target       string `json:"target,omitempty"`
	Flags        uint8  `json:"flags,omitempty"`
	Tag          string `json:"tag,omitempty"`
	Usage        uint8  `json:"usage,omitempty"`
	Selector     uint8  `json:"selector,omitempty"`
	MatchingType uint8  `json:"matching_type,omitempty"`
	Data         string `json:"data,omitempty"`
}

// UpdateRecordRequest represents a request to update a DNS record.
type UpdateRecordRequest struct {
	Type         string `json:"type"`
	Name         string `json:"name"`
	Value        string `json:"value,omitempty"`
	TTL          uint32 `json:"ttl,omitempty"`
	Priority     uint16 `json:"priority,omitempty"`
	Weight       uint16 `json:"weight,omitempty"`
	Port         uint16 `json:"port,omitempty"`
	Target       string `json:"target,omitempty"`
	Flags        uint8  `json:"flags,omitempty"`
	Tag          string `json:"tag,omitempty"`
	Usage        uint8  `json:"usage,omitempty"`
	Selector     uint8  `json:"selector,omitempty"`
	MatchingType uint8  `json:"matching_type,omitempty"`
	Data         string `json:"data,omitempty"`
}

// RecordResponse represents a generic DNS record response.
type RecordResponse struct {
	ID   string      `json:"id"`
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

// RecordListResponse represents a list of DNS records.
type RecordListResponse struct {
	Records   []RecordResponse `json:"records"`
	Count     int              `json:"count"`
	Timestamp time.Time        `json:"timestamp"`
}

// SignZoneResponse represents a zone signing response.
type SignZoneResponse struct {
	ZoneName  string    `json:"zone_name"`
	Signed    bool      `json:"signed"`
	Message   string    `json:"message,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// ResolveRequest represents a DNS resolution request.
type ResolveRequest struct {
	FQDN string `json:"fqdn"`
	Type string `json:"type"`
}

// ResolveResponse represents a DNS resolution response.
type ResolveResponse struct {
	FQDN          string    `json:"fqdn"`
	Type          string    `json:"type"`
	Values        []string  `json:"values"`
	Authoritative bool      `json:"authoritative"`
	Timestamp     time.Time `json:"timestamp"`
}

// RegisterRequest represents a DNS registration request.
type RegisterRequest struct {
	FQDN string `json:"fqdn"`
	IP   string `json:"ip"`
}

// RegisterResponse represents a DNS registration response.
type RegisterResponse struct {
	Success   bool          `json:"success"`
	Zone      *ZoneResponse `json:"zone,omitempty"`
	Message   string        `json:"message,omitempty"`
	Timestamp time.Time     `json:"timestamp"`
}

// TransferRequest represents a zone transfer request.
type TransferRequest struct {
	ZoneName string `json:"zone_name"`
	Server   string `json:"server"`
	Port     uint16 `json:"port,omitempty"`
}

// TransferResponse represents a zone transfer response.
type TransferResponse struct {
	Success   bool          `json:"success"`
	Zone      *ZoneResponse `json:"zone,omitempty"`
	Message   string        `json:"message,omitempty"`
	Timestamp time.Time     `json:"timestamp"`
}

// ZoneTransferResponse is the management/export view of an authoritative
// zone transfer. The platform is a PRIMARY nameserver: live AXFR is served
// over DNS TCP to TSIG-authenticated secondaries by the DNS server itself.
// This REST surface returns the exact records a secondary would receive
// (RFC 5936 order) plus the configured secondary key names, without
// performing a wire transfer or exposing any TSIG secret.
type ZoneTransferResponse struct {
	ZoneName    string    `json:"zone_name"`
	Model       string    `json:"model"`
	Records     []string  `json:"records"`
	RecordCount int       `json:"record_count"`
	Secondaries []string  `json:"secondaries,omitempty"`
	Message     string    `json:"message,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

// DNSActionResponse represents a generic DNS action result.
type DNSActionResponse struct {
	Action    string    `json:"action"`
	Success   bool      `json:"success"`
	Message   string    `json:"message,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// =============================================================================
// DNS Handlers
// =============================================================================

// DNSHandlers provides REST API handlers for DNS operations.
type DNSHandlers struct {
	dnsService dns.DNSService
	logger     *slog.Logger
}

// NewDNSHandlers creates a new DNSHandlers instance.
func NewDNSHandlers(dnsService dns.DNSService, logger *slog.Logger) *DNSHandlers {
	if logger == nil {
		logger = slog.Default()
	}
	return &DNSHandlers{
		dnsService: dnsService,
		logger:     logger,
	}
}

// RegisterRoutes registers all DNS routes on the provided router.
func (h *DNSHandlers) RegisterRoutes(router *mux.Router) {
	// Zone operations
	router.HandleFunc("/api/v1/dns/zones", h.handleCreateZone).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/dns/zones", h.handleListZones).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/dns/zones/{name}", h.handleGetZone).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/dns/zones/{name}", h.handleDeleteZone).Methods(http.MethodDelete)
	router.HandleFunc("/api/v1/dns/zones/{name}/sign", h.handleSignZone).Methods(http.MethodPost)

	// Record operations
	router.HandleFunc("/api/v1/dns/zones/{name}/records", h.handleAddRecord).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/dns/zones/{name}/records", h.handleListRecords).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/dns/zones/{name}/records/{id}", h.handleUpdateRecord).Methods(http.MethodPut)
	router.HandleFunc("/api/v1/dns/zones/{name}/records/{id}", h.handleDeleteRecord).Methods(http.MethodDelete)

	// DNS resolution and registration
	router.HandleFunc("/api/v1/dns/resolve", h.handleResolve).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/dns/register", h.handleRegister).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/dns/transfer", h.handleTransfer).Methods(http.MethodPost)

	h.logger.Info("DNS REST routes registered")
}

// handleCreateZone handles POST /api/v1/dns/zones
func (h *DNSHandlers) handleCreateZone(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.dnsService == nil {
		h.writeDNSError(w, http.StatusServiceUnavailable, ErrDNSServiceNotAvailable{})
		return
	}

	var req CreateZoneRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeDNSError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Name == "" {
		h.writeDNSError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "name"})
		return
	}

	zone := h.buildZoneFromRequest(&req)

	if err := h.dnsService.Save(ctx, zone); err != nil {
		h.logger.Error("Failed to create zone", "error", err, "name", req.Name)
		h.handleDNSError(w, "create_zone", err)
		return
	}

	resp := h.zoneToResponse(zone)
	h.logger.Info("Zone created", "name", zone.Name)
	h.writeJSON(w, http.StatusCreated, resp)
}

// handleListZones handles GET /api/v1/dns/zones
func (h *DNSHandlers) handleListZones(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.dnsService == nil {
		h.writeDNSError(w, http.StatusServiceUnavailable, ErrDNSServiceNotAvailable{})
		return
	}

	zones, err := h.dnsService.ListZones(ctx)
	if err != nil {
		h.logger.Error("Failed to list zones", "error", err)
		h.handleDNSError(w, "list_zones", err)
		return
	}

	zoneResponses := make([]ZoneResponse, 0, len(zones))
	for _, z := range zones {
		zoneResponses = append(zoneResponses, h.zoneToResponse(z))
	}

	resp := ZoneListResponse{
		Zones:     zoneResponses,
		Count:     len(zoneResponses),
		Timestamp: time.Now().UTC(),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// handleGetZone handles GET /api/v1/dns/zones/{name}
func (h *DNSHandlers) handleGetZone(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.dnsService == nil {
		h.writeDNSError(w, http.StatusServiceUnavailable, ErrDNSServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	zoneName := vars["name"]
	if zoneName == "" {
		h.writeDNSError(w, http.StatusBadRequest, ErrInvalidZoneName{})
		return
	}

	zone, err := h.dnsService.Zone(ctx, zoneName)
	if err != nil {
		h.logger.Error("Failed to get zone", "error", err, "name", zoneName)
		h.handleDNSError(w, "get_zone", err)
		return
	}

	resp := h.zoneToResponse(zone)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleDeleteZone handles DELETE /api/v1/dns/zones/{name}
func (h *DNSHandlers) handleDeleteZone(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.dnsService == nil {
		h.writeDNSError(w, http.StatusServiceUnavailable, ErrDNSServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	zoneName := vars["name"]
	if zoneName == "" {
		h.writeDNSError(w, http.StatusBadRequest, ErrInvalidZoneName{})
		return
	}

	if err := h.dnsService.DeleteZone(ctx, zoneName); err != nil {
		h.logger.Error("Failed to delete zone", "error", err, "name", zoneName)
		h.handleDNSError(w, "delete_zone", err)
		return
	}

	resp := DNSActionResponse{
		Action:    "delete_zone",
		Success:   true,
		Message:   fmt.Sprintf("zone %s deleted successfully", zoneName),
		Timestamp: time.Now().UTC(),
	}

	h.logger.Info("Zone deleted", "name", zoneName)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleSignZone handles POST /api/v1/dns/zones/{name}/sign
func (h *DNSHandlers) handleSignZone(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.dnsService == nil {
		h.writeDNSError(w, http.StatusServiceUnavailable, ErrDNSServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	zoneName := vars["name"]
	if zoneName == "" {
		h.writeDNSError(w, http.StatusBadRequest, ErrInvalidZoneName{})
		return
	}

	zone, err := h.dnsService.Zone(ctx, zoneName)
	if err != nil {
		h.logger.Error("Failed to get zone for signing", "error", err, "name", zoneName)
		h.handleDNSError(w, "sign_zone", err)
		return
	}

	if err := h.dnsService.SignZone(zone); err != nil {
		h.logger.Error("Failed to sign zone", "error", err, "name", zoneName)
		h.handleDNSError(w, "sign_zone", err)
		return
	}

	if err := h.dnsService.Save(ctx, zone); err != nil {
		h.logger.Error("Failed to save signed zone", "error", err, "name", zoneName)
		h.handleDNSError(w, "sign_zone", err)
		return
	}

	resp := SignZoneResponse{
		ZoneName:  zoneName,
		Signed:    true,
		Message:   "zone signed successfully with DNSSEC",
		Timestamp: time.Now().UTC(),
	}

	h.logger.Info("Zone signed", "name", zoneName)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleAddRecord handles POST /api/v1/dns/zones/{name}/records
func (h *DNSHandlers) handleAddRecord(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.dnsService == nil {
		h.writeDNSError(w, http.StatusServiceUnavailable, ErrDNSServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	zoneName := vars["name"]
	if zoneName == "" {
		h.writeDNSError(w, http.StatusBadRequest, ErrInvalidZoneName{})
		return
	}

	var req AddRecordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeDNSError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Type == "" {
		h.writeDNSError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "type"})
		return
	}
	if req.Name == "" {
		h.writeDNSError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "name"})
		return
	}

	zone, err := h.dnsService.Zone(ctx, zoneName)
	if err != nil {
		h.logger.Error("Failed to get zone for adding record", "error", err, "zone", zoneName)
		h.handleDNSError(w, "add_record", err)
		return
	}

	if err := h.addRecordToZone(zone, &req); err != nil {
		h.writeDNSError(w, http.StatusBadRequest, err)
		return
	}

	if err := h.dnsService.Save(ctx, zone); err != nil {
		h.logger.Error("Failed to save zone with new record", "error", err, "zone", zoneName)
		h.handleDNSError(w, "add_record", err)
		return
	}

	resp := h.zoneToResponse(zone)
	h.logger.Info("Record added", "zone", zoneName, "type", req.Type, "name", req.Name)
	h.writeJSON(w, http.StatusCreated, resp)
}

// handleListRecords handles GET /api/v1/dns/zones/{name}/records
func (h *DNSHandlers) handleListRecords(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.dnsService == nil {
		h.writeDNSError(w, http.StatusServiceUnavailable, ErrDNSServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	zoneName := vars["name"]
	if zoneName == "" {
		h.writeDNSError(w, http.StatusBadRequest, ErrInvalidZoneName{})
		return
	}

	typeFilter := r.URL.Query().Get("type")

	zone, err := h.dnsService.Zone(ctx, zoneName)
	if err != nil {
		h.logger.Error("Failed to get zone for listing records", "error", err, "zone", zoneName)
		h.handleDNSError(w, "list_records", err)
		return
	}

	records := h.collectRecords(zone, typeFilter)

	resp := RecordListResponse{
		Records:   records,
		Count:     len(records),
		Timestamp: time.Now().UTC(),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// handleUpdateRecord handles PUT /api/v1/dns/zones/{name}/records/{id}
func (h *DNSHandlers) handleUpdateRecord(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.dnsService == nil {
		h.writeDNSError(w, http.StatusServiceUnavailable, ErrDNSServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	zoneName := vars["name"]
	recordID := vars["id"]
	if zoneName == "" {
		h.writeDNSError(w, http.StatusBadRequest, ErrInvalidZoneName{})
		return
	}
	if recordID == "" {
		h.writeDNSError(w, http.StatusBadRequest, ErrInvalidRecordID{})
		return
	}

	var req UpdateRecordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeDNSError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Type == "" {
		h.writeDNSError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "type"})
		return
	}

	zone, err := h.dnsService.Zone(ctx, zoneName)
	if err != nil {
		h.logger.Error("Failed to get zone for updating record", "error", err, "zone", zoneName)
		h.handleDNSError(w, "update_record", err)
		return
	}

	if err := h.updateRecordInZone(zone, recordID, &req); err != nil {
		h.writeDNSError(w, http.StatusNotFound, err)
		return
	}

	if err := h.dnsService.Save(ctx, zone); err != nil {
		h.logger.Error("Failed to save zone with updated record", "error", err, "zone", zoneName)
		h.handleDNSError(w, "update_record", err)
		return
	}

	resp := h.zoneToResponse(zone)
	h.logger.Info("Record updated", "zone", zoneName, "id", recordID)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleDeleteRecord handles DELETE /api/v1/dns/zones/{name}/records/{id}
func (h *DNSHandlers) handleDeleteRecord(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.dnsService == nil {
		h.writeDNSError(w, http.StatusServiceUnavailable, ErrDNSServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	zoneName := vars["name"]
	recordID := vars["id"]
	if zoneName == "" {
		h.writeDNSError(w, http.StatusBadRequest, ErrInvalidZoneName{})
		return
	}
	if recordID == "" {
		h.writeDNSError(w, http.StatusBadRequest, ErrInvalidRecordID{})
		return
	}

	recordType := r.URL.Query().Get("type")
	if recordType == "" {
		h.writeDNSError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "type"})
		return
	}

	zone, err := h.dnsService.Zone(ctx, zoneName)
	if err != nil {
		h.logger.Error("Failed to get zone for deleting record", "error", err, "zone", zoneName)
		h.handleDNSError(w, "delete_record", err)
		return
	}

	if err := h.deleteRecordFromZone(zone, recordID, recordType); err != nil {
		h.writeDNSError(w, http.StatusNotFound, err)
		return
	}

	if err := h.dnsService.Save(ctx, zone); err != nil {
		h.logger.Error("Failed to save zone after deleting record", "error", err, "zone", zoneName)
		h.handleDNSError(w, "delete_record", err)
		return
	}

	resp := DNSActionResponse{
		Action:    "delete_record",
		Success:   true,
		Message:   fmt.Sprintf("record %s deleted from zone %s", recordID, zoneName),
		Timestamp: time.Now().UTC(),
	}

	h.logger.Info("Record deleted", "zone", zoneName, "id", recordID)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleResolve handles POST /api/v1/dns/resolve
func (h *DNSHandlers) handleResolve(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.dnsService == nil {
		h.writeDNSError(w, http.StatusServiceUnavailable, ErrDNSServiceNotAvailable{})
		return
	}

	var req ResolveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeDNSError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.FQDN == "" {
		h.writeDNSError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "fqdn"})
		return
	}
	if req.Type == "" {
		req.Type = "A"
	}

	values, err := h.dnsService.Resolve(ctx, req.FQDN, req.Type)
	if err != nil {
		h.logger.Error("Failed to resolve DNS query", "error", err, "fqdn", req.FQDN)
		h.handleDNSError(w, "resolve", err)
		return
	}

	resp := ResolveResponse{
		FQDN:          req.FQDN,
		Type:          req.Type,
		Values:        values,
		Authoritative: true,
		Timestamp:     time.Now().UTC(),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// handleRegister handles POST /api/v1/dns/register
func (h *DNSHandlers) handleRegister(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.dnsService == nil {
		h.writeDNSError(w, http.StatusServiceUnavailable, ErrDNSServiceNotAvailable{})
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeDNSError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.FQDN == "" {
		h.writeDNSError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "fqdn"})
		return
	}
	if req.IP == "" {
		h.writeDNSError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "ip"})
		return
	}

	zone, err := h.dnsService.Register(ctx, req.FQDN, req.IP)
	if err != nil {
		h.logger.Error("Failed to register DNS name", "error", err, "fqdn", req.FQDN)
		h.handleDNSError(w, "register", err)
		return
	}

	var zoneResp *ZoneResponse
	if zone != nil {
		zr := h.zoneToResponse(zone)
		zoneResp = &zr
	}

	resp := RegisterResponse{
		Success:   true,
		Zone:      zoneResp,
		Message:   fmt.Sprintf("DNS name %s registered to %s", req.FQDN, req.IP),
		Timestamp: time.Now().UTC(),
	}

	h.logger.Info("DNS name registered", "fqdn", req.FQDN, "ip", req.IP)
	h.writeJSON(w, http.StatusCreated, resp)
}

// handleTransfer handles POST /api/v1/dns/transfer
//
// Zone transfer is a DNS-protocol operation: authoritative AXFR is served by
// the platform's DNS server over TCP to TSIG-authenticated secondaries (the
// platform is a PRIMARY nameserver). This REST endpoint is the management /
// export projection of that model — it returns exactly the records a
// secondary would receive, in RFC 5936 order, along with the configured
// secondary key names. It never performs a wire transfer or discloses a TSIG
// secret.
func (h *DNSHandlers) handleTransfer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.dnsService == nil {
		h.writeDNSError(w, http.StatusServiceUnavailable, ErrDNSServiceNotAvailable{})
		return
	}

	var req TransferRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeDNSError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.ZoneName == "" {
		h.writeDNSError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "zone_name"})
		return
	}

	transferrer, ok := h.dnsService.(dns.ZoneTransferrer)
	if !ok {
		h.writeDNSError(w, http.StatusNotImplemented, ErrDNSOperationFailed{
			Operation: "transfer",
			Cause:     errors.New("zone transfer export not supported by this DNS service"),
		})
		return
	}

	records, err := transferrer.ZoneTransfer(ctx, req.ZoneName)
	if err != nil {
		h.logger.Error("Failed to export zone for transfer", "error", err, "zone", req.ZoneName)
		h.handleDNSError(w, "transfer", err)
		return
	}

	rrStrings := make([]string, 0, len(records))
	for _, rr := range records {
		if rr == nil {
			continue
		}
		rrStrings = append(rrStrings, rr.String())
	}

	resp := ZoneTransferResponse{
		ZoneName:    req.ZoneName,
		Model:       "primary",
		Records:     rrStrings,
		RecordCount: len(rrStrings),
		Secondaries: transferrer.TransferSecondaries(),
		Message:     "authoritative AXFR is served over DNS TCP to TSIG-authenticated secondaries; this is the zone-export preview",
		Timestamp:   time.Now().UTC(),
	}

	h.logger.Info("Zone transfer export served", "zone", req.ZoneName, "records", len(rrStrings))
	h.writeJSON(w, http.StatusOK, resp)
}

// =============================================================================
// Helper Methods
// =============================================================================

// buildZoneFromRequest creates a Zone entity from a CreateZoneRequest.
func (h *DNSHandlers) buildZoneFromRequest(req *CreateZoneRequest) *entities.Zone {
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

// addRecordToZone adds a record to the zone based on request type.
func (h *DNSHandlers) addRecordToZone(zone *entities.Zone, req *AddRecordRequest) error {
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
		return ErrInvalidRecordType{Type: req.Type}
	}
	return nil
}

// updateRecordInZone updates a record in the zone.
func (h *DNSHandlers) updateRecordInZone(zone *entities.Zone, recordID string, req *UpdateRecordRequest) error {
	ttl := req.TTL
	if ttl == 0 {
		ttl = zone.TTL
	}

	switch req.Type {
	case "A":
		for _, rec := range zone.RecordSet.ARecords {
			if rec.Name == recordID {
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
			if rec.Name == recordID {
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
			if rec.Name == recordID {
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
			if rec.Name == recordID {
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
			if rec.Name == recordID {
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
			if rec.Name == recordID {
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
			if rec.Name == recordID {
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
			if rec.Name == recordID {
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
			if rec.Name == recordID {
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
		return ErrInvalidRecordType{Type: req.Type}
	}
	return ErrRecordNotFound{Name: recordID, Type: req.Type}
}

// deleteRecordFromZone deletes a record from the zone.
func (h *DNSHandlers) deleteRecordFromZone(zone *entities.Zone, recordID string, recordType string) error {
	switch recordType {
	case "A":
		for i, rec := range zone.RecordSet.ARecords {
			if rec.Name == recordID {
				zone.RecordSet.ARecords = append(zone.RecordSet.ARecords[:i], zone.RecordSet.ARecords[i+1:]...)
				return nil
			}
		}
	case "AAAA":
		for i, rec := range zone.RecordSet.AAAARecords {
			if rec.Name == recordID {
				zone.RecordSet.AAAARecords = append(zone.RecordSet.AAAARecords[:i], zone.RecordSet.AAAARecords[i+1:]...)
				return nil
			}
		}
	case "CNAME":
		for i, rec := range zone.RecordSet.CNAMERecords {
			if rec.Name == recordID {
				zone.RecordSet.CNAMERecords = append(zone.RecordSet.CNAMERecords[:i], zone.RecordSet.CNAMERecords[i+1:]...)
				return nil
			}
		}
	case "MX":
		for i, rec := range zone.RecordSet.MXRecords {
			if rec.Name == recordID {
				zone.RecordSet.MXRecords = append(zone.RecordSet.MXRecords[:i], zone.RecordSet.MXRecords[i+1:]...)
				return nil
			}
		}
	case "NS":
		for i, rec := range zone.RecordSet.NSRecords {
			if rec.Name == recordID {
				zone.RecordSet.NSRecords = append(zone.RecordSet.NSRecords[:i], zone.RecordSet.NSRecords[i+1:]...)
				return nil
			}
		}
	case "TXT":
		for i, rec := range zone.RecordSet.TXTRecords {
			if rec.Name == recordID {
				zone.RecordSet.TXTRecords = append(zone.RecordSet.TXTRecords[:i], zone.RecordSet.TXTRecords[i+1:]...)
				return nil
			}
		}
	case "SRV":
		for i, rec := range zone.RecordSet.SRVRecords {
			if rec.Name == recordID {
				zone.RecordSet.SRVRecords = append(zone.RecordSet.SRVRecords[:i], zone.RecordSet.SRVRecords[i+1:]...)
				return nil
			}
		}
	case "CAA":
		for i, rec := range zone.RecordSet.CAARecords {
			if rec.Name == recordID {
				zone.RecordSet.CAARecords = append(zone.RecordSet.CAARecords[:i], zone.RecordSet.CAARecords[i+1:]...)
				return nil
			}
		}
	case "TLSA":
		for i, rec := range zone.RecordSet.TLSARecords {
			if rec.Name == recordID {
				zone.RecordSet.TLSARecords = append(zone.RecordSet.TLSARecords[:i], zone.RecordSet.TLSARecords[i+1:]...)
				return nil
			}
		}
	default:
		return ErrInvalidRecordType{Type: recordType}
	}
	return ErrRecordNotFound{Name: recordID, Type: recordType}
}

// collectRecords gathers all records from a zone into a flat list.
func (h *DNSHandlers) collectRecords(zone *entities.Zone, typeFilter string) []RecordResponse {
	var records []RecordResponse

	if typeFilter == "" || typeFilter == "A" {
		for _, rec := range zone.RecordSet.ARecords {
			records = append(records, RecordResponse{
				ID:   rec.Name,
				Type: "A",
				Data: ARecordResponse{
					Name:  rec.Name,
					Value: rec.Value,
					TTL:   rec.TTL,
				},
			})
		}
	}

	if typeFilter == "" || typeFilter == "AAAA" {
		for _, rec := range zone.RecordSet.AAAARecords {
			records = append(records, RecordResponse{
				ID:   rec.Name,
				Type: "AAAA",
				Data: AAAARecordResponse{
					Name:  rec.Name,
					Value: rec.Value,
					TTL:   rec.TTL,
				},
			})
		}
	}

	if typeFilter == "" || typeFilter == "CNAME" {
		for _, rec := range zone.RecordSet.CNAMERecords {
			records = append(records, RecordResponse{
				ID:   rec.Name,
				Type: "CNAME",
				Data: CNAMERecordResponse{
					Name:  rec.Name,
					Value: rec.Value,
					TTL:   rec.TTL,
				},
			})
		}
	}

	if typeFilter == "" || typeFilter == "MX" {
		for _, rec := range zone.RecordSet.MXRecords {
			records = append(records, RecordResponse{
				ID:   rec.Name,
				Type: "MX",
				Data: MXRecordResponse{
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
			records = append(records, RecordResponse{
				ID:   rec.Name,
				Type: "NS",
				Data: NSRecordResponse{
					Name:  rec.Name,
					Value: rec.Value,
					TTL:   rec.TTL,
				},
			})
		}
	}

	if typeFilter == "" || typeFilter == "TXT" {
		for _, rec := range zone.RecordSet.TXTRecords {
			records = append(records, RecordResponse{
				ID:   rec.Name,
				Type: "TXT",
				Data: TXTRecordResponse{
					Name:  rec.Name,
					Value: rec.Value,
					TTL:   rec.TTL,
				},
			})
		}
	}

	if typeFilter == "" || typeFilter == "SRV" {
		for _, rec := range zone.RecordSet.SRVRecords {
			records = append(records, RecordResponse{
				ID:   rec.Name,
				Type: "SRV",
				Data: SRVRecordResponse{
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
			records = append(records, RecordResponse{
				ID:   rec.Name,
				Type: "CAA",
				Data: CAARecordResponse{
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
			records = append(records, RecordResponse{
				ID:   rec.Name,
				Type: "TLSA",
				Data: TLSARecordResponse{
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
			records = append(records, RecordResponse{
				ID:   rec.Name,
				Type: "DNSKEY",
				Data: DNSKEYRecordResponse{
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
			records = append(records, RecordResponse{
				ID:   rec.Name,
				Type: "DS",
				Data: DSRecordResponse{
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

// zoneToResponse converts a Zone entity to a ZoneResponse.
func (h *DNSHandlers) zoneToResponse(zone *entities.Zone) ZoneResponse {
	resp := ZoneResponse{
		ID:          zone.ID,
		Name:        zone.Name,
		TTL:         zone.TTL,
		Description: zone.Description,
		Internal:    zone.Internal,
		Records:     h.recordSetToResponse(&zone.RecordSet),
	}
	return resp
}

// recordSetToResponse converts a RecordSet to a RecordSetResponse.
func (h *DNSHandlers) recordSetToResponse(rs *entities.RecordSet) *RecordSetResponse {
	resp := &RecordSetResponse{}

	if rs.SOARecord.Name != "" {
		resp.SOA = &SOARecordResponse{
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
		resp.A = append(resp.A, ARecordResponse{
			Name:  rec.Name,
			Value: rec.Value,
			TTL:   rec.TTL,
		})
	}

	for _, rec := range rs.AAAARecords {
		resp.AAAA = append(resp.AAAA, AAAARecordResponse{
			Name:  rec.Name,
			Value: rec.Value,
			TTL:   rec.TTL,
		})
	}

	for _, rec := range rs.CNAMERecords {
		resp.CNAME = append(resp.CNAME, CNAMERecordResponse{
			Name:  rec.Name,
			Value: rec.Value,
			TTL:   rec.TTL,
		})
	}

	for _, rec := range rs.MXRecords {
		resp.MX = append(resp.MX, MXRecordResponse{
			Name:     rec.Name,
			Value:    rec.Value,
			Priority: rec.Priority,
			TTL:      rec.TTL,
		})
	}

	for _, rec := range rs.NSRecords {
		resp.NS = append(resp.NS, NSRecordResponse{
			Name:  rec.Name,
			Value: rec.Value,
			TTL:   rec.TTL,
		})
	}

	for _, rec := range rs.TXTRecords {
		resp.TXT = append(resp.TXT, TXTRecordResponse{
			Name:  rec.Name,
			Value: rec.Value,
			TTL:   rec.TTL,
		})
	}

	for _, rec := range rs.SRVRecords {
		resp.SRV = append(resp.SRV, SRVRecordResponse{
			Name:     rec.Name,
			Target:   rec.Target,
			Port:     rec.Port,
			Priority: rec.Priority,
			Weight:   rec.Weight,
			TTL:      rec.TTL,
		})
	}

	for _, rec := range rs.CAARecords {
		resp.CAA = append(resp.CAA, CAARecordResponse{
			Name:  rec.Name,
			Flags: rec.Flags,
			Tag:   rec.Tag,
			Value: rec.Value,
			TTL:   rec.TTL,
		})
	}

	for _, rec := range rs.TLSARecords {
		resp.TLSA = append(resp.TLSA, TLSARecordResponse{
			Name:         rec.Name,
			Usage:        rec.Usage,
			Selector:     rec.Selector,
			MatchingType: rec.MatchingType,
			Data:         rec.Data,
			TTL:          rec.TTL,
		})
	}

	for _, rec := range rs.DNSKEYRecords {
		resp.DNSKEY = append(resp.DNSKEY, DNSKEYRecordResponse{
			Name:      rec.Name,
			Flags:     rec.Flags,
			Protocol:  rec.Protocol,
			Algorithm: rec.Algorithm,
			Key:       rec.Key,
			TTL:       rec.TTL,
		})
	}

	for _, rec := range rs.DSRecords {
		resp.DS = append(resp.DS, DSRecordResponse{
			Name:       rec.Name,
			KeyTag:     rec.KeyTag,
			Algorithm:  rec.Algorithm,
			DigestType: rec.DigestType,
			Digest:     rec.Digest,
			TTL:        rec.TTL,
		})
	}

	return resp
}

// writeJSON writes a JSON response.
func (h *DNSHandlers) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", "error", err)
	}
}

// writeDNSError writes an error response.
func (h *DNSHandlers) writeDNSError(w http.ResponseWriter, status int, err error) {
	h.writeJSON(w, status, ErrorResponse{
		Error:     err.Error(),
		Code:      status,
		Timestamp: time.Now().UTC(),
	})
}

// handleDNSError maps DNS errors to appropriate HTTP status codes.
func (h *DNSHandlers) handleDNSError(w http.ResponseWriter, operation string, err error) {
	var status int

	switch {
	case errors.Is(err, dns.ErrZoneNotFound):
		status = http.StatusNotFound
	case errors.Is(err, dns.ErrZoneAlreadyExists):
		status = http.StatusConflict
	case errors.Is(err, dns.ErrDNSSECNotEnabled):
		status = http.StatusBadRequest
	case errors.Is(err, dns.ErrRegistrationDisabled):
		status = http.StatusForbidden
	case errors.Is(err, dns.ErrExternalRegistrationDisabled):
		status = http.StatusForbidden
	case errors.Is(err, dns.ErrInternalRegistrationDisabled):
		status = http.StatusForbidden
	case errors.Is(err, dns.ErrInvalidIPAddress):
		status = http.StatusBadRequest
	case errors.Is(err, dns.ErrInvalidPrivateIP):
		status = http.StatusBadRequest
	case errors.Is(err, dns.ErrInvalidPublicIP):
		status = http.StatusBadRequest
	case errors.Is(err, dns.ErrInvalidPrivateTLD):
		status = http.StatusBadRequest
	case errors.Is(err, dns.ErrInvalidPublicTLD):
		status = http.StatusBadRequest
	case errors.Is(err, dns.ErrParsingDomainName):
		status = http.StatusBadRequest
	case errors.Is(err, context.Canceled):
		status = http.StatusRequestTimeout
	case errors.Is(err, context.DeadlineExceeded):
		status = http.StatusGatewayTimeout
	default:
		status = http.StatusInternalServerError
	}

	h.writeDNSError(w, status, ErrDNSOperationFailed{
		Operation: operation,
		Cause:     err,
	})
}
