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
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/mux"
)

// =============================================================================
// Gateway REST Handler Errors
// =============================================================================

// ErrGatewayServiceNotAvailable is returned when the gateway service is not
// configured or unavailable.
type ErrGatewayServiceNotAvailable struct{}

func (e ErrGatewayServiceNotAvailable) Error() string {
	return "gateway service not available"
}

// ErrInvalidGatewayMode is returned when a gateway mode is invalid.
type ErrInvalidGatewayMode struct {
	Mode uint32
}

func (e ErrInvalidGatewayMode) Error() string {
	return fmt.Sprintf("invalid gateway mode: %d", e.Mode)
}

// ErrInvalidPrefix is returned when a prefix is invalid or empty.
type ErrInvalidPrefix struct {
	Prefix string
}

func (e ErrInvalidPrefix) Error() string {
	if e.Prefix == "" {
		return "prefix is required"
	}
	return fmt.Sprintf("invalid prefix: %s", e.Prefix)
}

// ErrInvalidIPAddress is returned when an IP address is invalid or empty.
type ErrInvalidIPAddress struct {
	IP string
}

func (e ErrInvalidIPAddress) Error() string {
	if e.IP == "" {
		return "IP address is required"
	}
	return fmt.Sprintf("invalid IP address: %s", e.IP)
}

// ErrInvalidPoolID is returned when a pool ID is invalid or empty.
type ErrInvalidPoolID struct {
	ID string
}

func (e ErrInvalidPoolID) Error() string {
	if e.ID == "" {
		return "pool ID is required"
	}
	return fmt.Sprintf("invalid pool ID: %s", e.ID)
}

// ErrBGPNotEnabled is returned when BGP is not enabled.
type ErrBGPNotEnabled struct{}

func (e ErrBGPNotEnabled) Error() string {
	return "BGP is not enabled"
}

// ErrBGPPeerNotFound is returned when a BGP peer is not found.
type ErrBGPPeerNotFound struct {
	Address string
}

func (e ErrBGPPeerNotFound) Error() string {
	return fmt.Sprintf("BGP peer not found: %s", e.Address)
}

// ErrPrefixNotFound is returned when a prefix is not found.
type ErrPrefixNotFound struct {
	Prefix string
}

func (e ErrPrefixNotFound) Error() string {
	return fmt.Sprintf("prefix not found: %s", e.Prefix)
}

// ErrPrefixAlreadyAnnounced is returned when a prefix is already announced.
type ErrPrefixAlreadyAnnounced struct {
	Prefix string
}

func (e ErrPrefixAlreadyAnnounced) Error() string {
	return fmt.Sprintf("prefix already announced: %s", e.Prefix)
}

// ErrIPAMPoolNotFound is returned when an IPAM pool is not found.
type ErrIPAMPoolNotFound struct {
	ID string
}

func (e ErrIPAMPoolNotFound) Error() string {
	return fmt.Sprintf("IPAM pool not found: %s", e.ID)
}

// ErrIPAMPoolAlreadyExists is returned when attempting to create a pool that
// already exists.
type ErrIPAMPoolAlreadyExists struct {
	ID string
}

func (e ErrIPAMPoolAlreadyExists) Error() string {
	return fmt.Sprintf("IPAM pool already exists: %s", e.ID)
}

// ErrIPAMPoolHasAllocations is returned when attempting to delete a pool that
// still has active allocations.
type ErrIPAMPoolHasAllocations struct {
	ID string
}

func (e ErrIPAMPoolHasAllocations) Error() string {
	return fmt.Sprintf("IPAM pool has active allocations: %s", e.ID)
}

// ErrIPAMCIDRImmutable is returned when attempting to change the CIDR of a pool.
type ErrIPAMCIDRImmutable struct{}

func (e ErrIPAMCIDRImmutable) Error() string {
	return "CIDR cannot be changed after pool creation"
}

// ErrIPAllocationNotFound is returned when an IP allocation is not found.
type ErrIPAllocationNotFound struct {
	IP string
}

func (e ErrIPAllocationNotFound) Error() string {
	return fmt.Sprintf("IP allocation not found: %s", e.IP)
}

// ErrIPAlreadyAllocated is returned when an IP is already allocated.
type ErrIPAlreadyAllocated struct {
	IP string
}

func (e ErrIPAlreadyAllocated) Error() string {
	return fmt.Sprintf("IP already allocated: %s", e.IP)
}

// ErrIPAMPoolExhausted is returned when an IPAM pool has no available IPs.
type ErrIPAMPoolExhausted struct {
	ID string
}

func (e ErrIPAMPoolExhausted) Error() string {
	return fmt.Sprintf("IPAM pool exhausted: %s", e.ID)
}

// ErrGatewayOperationFailed is returned when a gateway operation fails.
type ErrGatewayOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrGatewayOperationFailed) Error() string {
	return fmt.Sprintf("gateway operation %s failed: %v", e.Operation, e.Cause)
}

func (e ErrGatewayOperationFailed) Unwrap() error {
	return e.Cause
}

// =============================================================================
// Gateway Mode Constants
// =============================================================================

// GatewayMode represents the gateway operation mode.
type GatewayMode uint32

const (
	// GatewayModeUnspecified represents an unspecified gateway mode.
	GatewayModeUnspecified GatewayMode = 0
	// GatewayModeOverlay represents overlay mode.
	GatewayModeOverlay GatewayMode = 1
	// GatewayModeEdge represents edge mode.
	GatewayModeEdge GatewayMode = 2
	// GatewayModeTransit represents transit mode.
	GatewayModeTransit GatewayMode = 4
)

// =============================================================================
// Request/Response Types
// =============================================================================

// GatewayStatusResponse represents the gateway status.
type GatewayStatusResponse struct {
	ID            string    `json:"id"`
	NodeID        string    `json:"node_id"`
	Modes         uint32    `json:"modes"`
	Tier          string    `json:"tier"`
	Reputation    float64   `json:"reputation"`
	UptimeSeconds uint64    `json:"uptime_seconds"`
	Healthy       bool      `json:"healthy"`
	StartedAt     time.Time `json:"started_at"`
	Timestamp     time.Time `json:"timestamp"`
}

// SetGatewayModeRequest represents a request to set gateway mode.
type SetGatewayModeRequest struct {
	Modes uint32 `json:"modes"`
}

// SetGatewayModeResponse represents the response to setting gateway mode.
type SetGatewayModeResponse struct {
	Success       bool                   `json:"success"`
	Message       string                 `json:"message,omitempty"`
	GatewayStatus *GatewayStatusResponse `json:"gateway_status,omitempty"`
}

// BGPStatusResponse represents the BGP status.
type BGPStatusResponse struct {
	LocalASN          uint32    `json:"local_asn"`
	RouterID          string    `json:"router_id"`
	PeerCount         uint32    `json:"peer_count"`
	EstablishedPeers  uint32    `json:"established_peers"`
	PrefixesAnnounced uint32    `json:"prefixes_announced"`
	Running           bool      `json:"running"`
	Timestamp         time.Time `json:"timestamp"`
}

// BGPPeerResponse represents a BGP peer.
type BGPPeerResponse struct {
	Address          string    `json:"address"`
	ASN              uint32    `json:"asn"`
	State            string    `json:"state"`
	Description      string    `json:"description,omitempty"`
	PrefixesReceived uint32    `json:"prefixes_received"`
	PrefixesSent     uint32    `json:"prefixes_sent"`
	Uptime           time.Time `json:"uptime"`
}

// BGPPeerListResponse represents a list of BGP peers.
type BGPPeerListResponse struct {
	Peers     []BGPPeerResponse `json:"peers"`
	Count     int               `json:"count"`
	Timestamp time.Time         `json:"timestamp"`
}

// AnnouncePrefixRequest represents a request to announce a prefix.
type AnnouncePrefixRequest struct {
	Prefix  string `json:"prefix"`
	NextHop string `json:"next_hop,omitempty"`
}

// AnnouncedPrefixResponse represents an announced prefix.
type AnnouncedPrefixResponse struct {
	Prefix      string    `json:"prefix"`
	NextHop     string    `json:"next_hop"`
	AnnouncedAt time.Time `json:"announced_at"`
}

// AnnouncedPrefixListResponse represents a list of announced prefixes.
type AnnouncedPrefixListResponse struct {
	Prefixes  []AnnouncedPrefixResponse `json:"prefixes"`
	Count     int                       `json:"count"`
	Timestamp time.Time                 `json:"timestamp"`
}

// IPAMPoolResponse represents an IPAM pool.
type IPAMPoolResponse struct {
	ID                     string    `json:"id"`
	Name                   string    `json:"name"`
	CIDR                   string    `json:"cidr"`
	Gateway                string    `json:"gateway,omitempty"`
	Zone                   string    `json:"zone,omitempty"`
	Description            string    `json:"description,omitempty"`
	Total                  uint64    `json:"total"`
	Allocated              uint64    `json:"allocated"`
	Available              uint64    `json:"available"`
	DefaultLeaseDurationNs int64     `json:"default_lease_duration_nanos,omitempty"`
	InactivityTimeoutNs    int64     `json:"inactivity_timeout_nanos,omitempty"`
	CreatedAt              time.Time `json:"created_at,omitempty"`
	UpdatedAt              time.Time `json:"updated_at,omitempty"`
}

// IPAMPoolListResponse represents a list of IPAM pools.
type IPAMPoolListResponse struct {
	Pools     []IPAMPoolResponse `json:"pools"`
	Count     int                `json:"count"`
	Timestamp time.Time          `json:"timestamp"`
}

// CreateIPAMPoolRequest is the REST body for creating an IPAM pool.
type CreateIPAMPoolRequest struct {
	ID                     string `json:"id,omitempty"`
	Name                   string `json:"name"`
	CIDR                   string `json:"cidr"`
	Gateway                string `json:"gateway,omitempty"`
	Zone                   string `json:"zone,omitempty"`
	Description            string `json:"description,omitempty"`
	DefaultLeaseDurationNs int64  `json:"default_lease_duration_nanos,omitempty"`
	InactivityTimeoutNs    int64  `json:"inactivity_timeout_nanos,omitempty"`
}

// UpdateIPAMPoolRequest is the REST body for updating an IPAM pool.
// CIDR is immutable and must not be included.
type UpdateIPAMPoolRequest struct {
	Name                   string `json:"name,omitempty"`
	Gateway                string `json:"gateway,omitempty"`
	Zone                   string `json:"zone,omitempty"`
	Description            string `json:"description,omitempty"`
	DefaultLeaseDurationNs int64  `json:"default_lease_duration_nanos,omitempty"`
	InactivityTimeoutNs    int64  `json:"inactivity_timeout_nanos,omitempty"`
}

// AllocateIPRequest represents a request to allocate an IP.
type AllocateIPRequest struct {
	PoolID   string `json:"pool_id"`
	DeviceID string `json:"device_id"`
	Hostname string `json:"hostname,omitempty"`
}

// IPAllocationResponse represents an IP allocation.
type IPAllocationResponse struct {
	IP          string    `json:"ip"`
	PoolID      string    `json:"pool_id"`
	DeviceID    string    `json:"device_id"`
	Hostname    string    `json:"hostname,omitempty"`
	AllocatedAt time.Time `json:"allocated_at"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
}

// IPAllocationListResponse represents a list of IP allocations.
type IPAllocationListResponse struct {
	Allocations []IPAllocationResponse `json:"allocations"`
	Count       int                    `json:"count"`
	Timestamp   time.Time              `json:"timestamp"`
}

// GatewayActionResponse represents a gateway action result.
type GatewayActionResponse struct {
	ResourceID   string `json:"resource_id"`
	ResourceType string `json:"resource_type"`
	Action       string `json:"action"`
	Success      bool   `json:"success"`
	Message      string `json:"message,omitempty"`
}

// GatewayErrorResponse represents a gateway error response.
type GatewayErrorResponse struct {
	Error     string    `json:"error"`
	Code      int       `json:"code"`
	Timestamp time.Time `json:"timestamp"`
}

// =============================================================================
// Gateway Service Interface
// =============================================================================

// GatewayServiceInterface defines the interface for gateway operations.
type GatewayServiceInterface interface {
	// Gateway status operations
	GetGatewayStatus(ctx context.Context) (*GatewayStatusResponse, error)
	SetGatewayMode(ctx context.Context, modes uint32) (*SetGatewayModeResponse, error)

	// BGP operations
	GetBGPStatus(ctx context.Context) (*BGPStatusResponse, error)
	ListBGPPeers(ctx context.Context) ([]BGPPeerResponse, error)
	AnnouncePrefix(ctx context.Context, prefix, nextHop string) error
	WithdrawPrefix(ctx context.Context, prefix string) error
	ListAnnouncedPrefixes(ctx context.Context) ([]AnnouncedPrefixResponse, error)

	// IPAM pool CRUD
	CreateIPAMPool(ctx context.Context, req *CreateIPAMPoolRequest) (*IPAMPoolResponse, error)
	GetIPAMPool(ctx context.Context, poolID string) (*IPAMPoolResponse, error)
	UpdateIPAMPool(ctx context.Context, poolID string, req *UpdateIPAMPoolRequest) (*IPAMPoolResponse, error)
	DeleteIPAMPool(ctx context.Context, poolID string) error
	ListIPAMPools(ctx context.Context, zone string) ([]IPAMPoolResponse, error)

	// IPAM allocation operations
	AllocateIP(ctx context.Context, poolID, deviceID, hostname string) (*IPAllocationResponse, error)
	ReleaseIP(ctx context.Context, ip string) error
	ListAllocations(ctx context.Context, poolID string) ([]IPAllocationResponse, error)
}

// =============================================================================
// Gateway Handlers
// =============================================================================

// GatewayHandlers provides REST API handlers for gateway operations.
type GatewayHandlers struct {
	gatewayService GatewayServiceInterface
	logger         *slog.Logger
}

// NewGatewayHandlers creates a new GatewayHandlers instance.
func NewGatewayHandlers(gatewayService GatewayServiceInterface, logger *slog.Logger) *GatewayHandlers {
	if logger == nil {
		logger = slog.Default()
	}
	return &GatewayHandlers{
		gatewayService: gatewayService,
		logger:         logger,
	}
}

// SetGatewayService sets the gateway service for the handlers.
func (h *GatewayHandlers) SetGatewayService(gatewayService GatewayServiceInterface) {
	h.gatewayService = gatewayService
}

// RegisterRoutes registers all gateway routes on the provided router.
func (h *GatewayHandlers) RegisterRoutes(router *mux.Router) {
	// Gateway status operations
	router.HandleFunc("/api/v1/sdn/gateway/status", h.handleGetGatewayStatus).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/sdn/gateway/mode", h.handleSetGatewayMode).Methods(http.MethodPut)

	// BGP operations
	router.HandleFunc("/api/v1/sdn/gateway/bgp/status", h.handleGetBGPStatus).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/sdn/gateway/bgp/peers", h.handleListBGPPeers).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/sdn/gateway/bgp/prefixes", h.handleAnnouncePrefix).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/sdn/gateway/bgp/prefixes/{prefix}", h.handleWithdrawPrefix).Methods(http.MethodDelete)
	router.HandleFunc("/api/v1/sdn/gateway/bgp/prefixes", h.handleListAnnouncedPrefixes).Methods(http.MethodGet)

	// IPAM pool CRUD — pools collection
	router.HandleFunc("/api/v1/sdn/gateway/ipam/pools", h.handleCreateIPAMPool).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/sdn/gateway/ipam/pools", h.handleListIPAMPools).Methods(http.MethodGet)
	// IPAM pool CRUD — single pool
	router.HandleFunc("/api/v1/sdn/gateway/ipam/pools/{id}", h.handleGetIPAMPool).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/sdn/gateway/ipam/pools/{id}", h.handleUpdateIPAMPool).Methods(http.MethodPut)
	router.HandleFunc("/api/v1/sdn/gateway/ipam/pools/{id}", h.handleDeleteIPAMPool).Methods(http.MethodDelete)

	// IPAM allocation operations
	router.HandleFunc("/api/v1/sdn/gateway/ipam/allocations", h.handleAllocateIP).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/sdn/gateway/ipam/allocations/{ip}", h.handleReleaseIP).Methods(http.MethodDelete)
	router.HandleFunc("/api/v1/sdn/gateway/ipam/allocations", h.handleListAllocations).Methods(http.MethodGet)

	h.logger.Info("Gateway REST routes registered")
}

// =============================================================================
// Gateway Status Handlers
// =============================================================================

// handleGetGatewayStatus handles GET /api/v1/sdn/gateway/status
func (h *GatewayHandlers) handleGetGatewayStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.gatewayService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrGatewayServiceNotAvailable{})
		return
	}

	gwStatus, err := h.gatewayService.GetGatewayStatus(ctx)
	if err != nil {
		h.logger.Error("Failed to get gateway status", "error", err)
		h.writeGatewayError(w, "get_gateway_status", err)
		return
	}

	gwStatus.Timestamp = time.Now().UTC()
	h.writeJSON(w, http.StatusOK, gwStatus)
}

// handleSetGatewayMode handles PUT /api/v1/sdn/gateway/mode
func (h *GatewayHandlers) handleSetGatewayMode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.gatewayService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrGatewayServiceNotAvailable{})
		return
	}

	var req SetGatewayModeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	// Validate mode bitmask
	validModes := uint32(GatewayModeOverlay | GatewayModeEdge | GatewayModeTransit)
	if req.Modes > validModes {
		h.writeError(w, http.StatusBadRequest, ErrInvalidGatewayMode{Mode: req.Modes})
		return
	}

	resp, err := h.gatewayService.SetGatewayMode(ctx, req.Modes)
	if err != nil {
		h.logger.Error("Failed to set gateway mode", "error", err, "modes", req.Modes)
		h.writeGatewayError(w, "set_gateway_mode", err)
		return
	}

	h.logger.Info("Gateway mode set", "modes", req.Modes)
	h.writeJSON(w, http.StatusOK, resp)
}

// =============================================================================
// BGP Handlers
// =============================================================================

// handleGetBGPStatus handles GET /api/v1/sdn/gateway/bgp/status
func (h *GatewayHandlers) handleGetBGPStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.gatewayService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrGatewayServiceNotAvailable{})
		return
	}

	bgpStatus, err := h.gatewayService.GetBGPStatus(ctx)
	if err != nil {
		h.logger.Error("Failed to get BGP status", "error", err)
		h.writeGatewayError(w, "get_bgp_status", err)
		return
	}

	bgpStatus.Timestamp = time.Now().UTC()
	h.writeJSON(w, http.StatusOK, bgpStatus)
}

// handleListBGPPeers handles GET /api/v1/sdn/gateway/bgp/peers
func (h *GatewayHandlers) handleListBGPPeers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.gatewayService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrGatewayServiceNotAvailable{})
		return
	}

	peers, err := h.gatewayService.ListBGPPeers(ctx)
	if err != nil {
		h.logger.Error("Failed to list BGP peers", "error", err)
		h.writeGatewayError(w, "list_bgp_peers", err)
		return
	}

	resp := BGPPeerListResponse{
		Peers:     peers,
		Count:     len(peers),
		Timestamp: time.Now().UTC(),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// handleAnnouncePrefix handles POST /api/v1/sdn/gateway/bgp/prefixes
func (h *GatewayHandlers) handleAnnouncePrefix(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.gatewayService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrGatewayServiceNotAvailable{})
		return
	}

	var req AnnouncePrefixRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Prefix == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "prefix"})
		return
	}

	if err := h.gatewayService.AnnouncePrefix(ctx, req.Prefix, req.NextHop); err != nil {
		h.logger.Error("Failed to announce prefix", "error", err, "prefix", req.Prefix)
		h.writeGatewayError(w, "announce_prefix", err)
		return
	}

	resp := GatewayActionResponse{
		ResourceID:   req.Prefix,
		ResourceType: "prefix",
		Action:       "announce",
		Success:      true,
		Message:      "prefix announced successfully",
	}

	h.logger.Info("Prefix announced", "prefix", req.Prefix, "next_hop", req.NextHop)
	h.writeJSON(w, http.StatusCreated, resp)
}

// handleWithdrawPrefix handles DELETE /api/v1/sdn/gateway/bgp/prefixes/{prefix}
func (h *GatewayHandlers) handleWithdrawPrefix(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.gatewayService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrGatewayServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	prefix := vars["prefix"]
	if prefix == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidPrefix{})
		return
	}

	// URL decode the prefix (in case it contains special characters like /)
	decodedPrefix, err := url.PathUnescape(prefix)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidPrefix{Prefix: prefix})
		return
	}

	if err := h.gatewayService.WithdrawPrefix(ctx, decodedPrefix); err != nil {
		h.logger.Error("Failed to withdraw prefix", "error", err, "prefix", decodedPrefix)
		h.writeGatewayError(w, "withdraw_prefix", err)
		return
	}

	resp := GatewayActionResponse{
		ResourceID:   decodedPrefix,
		ResourceType: "prefix",
		Action:       "withdraw",
		Success:      true,
		Message:      "prefix withdrawn successfully",
	}

	h.logger.Info("Prefix withdrawn", "prefix", decodedPrefix)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleListAnnouncedPrefixes handles GET /api/v1/sdn/gateway/bgp/prefixes
func (h *GatewayHandlers) handleListAnnouncedPrefixes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.gatewayService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrGatewayServiceNotAvailable{})
		return
	}

	prefixes, err := h.gatewayService.ListAnnouncedPrefixes(ctx)
	if err != nil {
		h.logger.Error("Failed to list announced prefixes", "error", err)
		h.writeGatewayError(w, "list_announced_prefixes", err)
		return
	}

	resp := AnnouncedPrefixListResponse{
		Prefixes:  prefixes,
		Count:     len(prefixes),
		Timestamp: time.Now().UTC(),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// =============================================================================
// IPAM Pool CRUD Handlers
// =============================================================================

// handleCreateIPAMPool handles POST /api/v1/sdn/gateway/ipam/pools
func (h *GatewayHandlers) handleCreateIPAMPool(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.gatewayService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrGatewayServiceNotAvailable{})
		return
	}

	var req CreateIPAMPoolRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Name == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "name"})
		return
	}

	if req.CIDR == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "cidr"})
		return
	}

	pool, err := h.gatewayService.CreateIPAMPool(ctx, &req)
	if err != nil {
		h.logger.Error("Failed to create IPAM pool", "error", err, "name", req.Name, "cidr", req.CIDR)
		h.writeGatewayError(w, "create_ipam_pool", err)
		return
	}

	h.logger.Info("IPAM pool created", "id", pool.ID, "name", pool.Name, "cidr", pool.CIDR)
	h.writeJSON(w, http.StatusCreated, pool)
}

// handleGetIPAMPool handles GET /api/v1/sdn/gateway/ipam/pools/{id}
func (h *GatewayHandlers) handleGetIPAMPool(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.gatewayService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrGatewayServiceNotAvailable{})
		return
	}

	id := mux.Vars(r)["id"]
	if id == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidPoolID{})
		return
	}

	pool, err := h.gatewayService.GetIPAMPool(ctx, id)
	if err != nil {
		h.logger.Error("Failed to get IPAM pool", "error", err, "id", id)
		h.writeGatewayError(w, "get_ipam_pool", err)
		return
	}

	h.writeJSON(w, http.StatusOK, pool)
}

// handleUpdateIPAMPool handles PUT /api/v1/sdn/gateway/ipam/pools/{id}
func (h *GatewayHandlers) handleUpdateIPAMPool(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.gatewayService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrGatewayServiceNotAvailable{})
		return
	}

	id := mux.Vars(r)["id"]
	if id == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidPoolID{})
		return
	}

	var req UpdateIPAMPoolRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	pool, err := h.gatewayService.UpdateIPAMPool(ctx, id, &req)
	if err != nil {
		h.logger.Error("Failed to update IPAM pool", "error", err, "id", id)
		h.writeGatewayError(w, "update_ipam_pool", err)
		return
	}

	h.logger.Info("IPAM pool updated", "id", id)
	h.writeJSON(w, http.StatusOK, pool)
}

// handleDeleteIPAMPool handles DELETE /api/v1/sdn/gateway/ipam/pools/{id}
func (h *GatewayHandlers) handleDeleteIPAMPool(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.gatewayService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrGatewayServiceNotAvailable{})
		return
	}

	id := mux.Vars(r)["id"]
	if id == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidPoolID{})
		return
	}

	if err := h.gatewayService.DeleteIPAMPool(ctx, id); err != nil {
		h.logger.Error("Failed to delete IPAM pool", "error", err, "id", id)
		h.writeGatewayError(w, "delete_ipam_pool", err)
		return
	}

	resp := GatewayActionResponse{
		ResourceID:   id,
		ResourceType: "ipam_pool",
		Action:       "delete",
		Success:      true,
		Message:      "pool deleted successfully",
	}

	h.logger.Info("IPAM pool deleted", "id", id)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleListIPAMPools handles GET /api/v1/sdn/gateway/ipam/pools
func (h *GatewayHandlers) handleListIPAMPools(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.gatewayService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrGatewayServiceNotAvailable{})
		return
	}

	// Optional zone filter via query parameter.
	zone := r.URL.Query().Get("zone")

	pools, err := h.gatewayService.ListIPAMPools(ctx, zone)
	if err != nil {
		h.logger.Error("Failed to list IPAM pools", "error", err)
		h.writeGatewayError(w, "list_ipam_pools", err)
		return
	}

	resp := IPAMPoolListResponse{
		Pools:     pools,
		Count:     len(pools),
		Timestamp: time.Now().UTC(),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// =============================================================================
// IPAM Allocation Handlers
// =============================================================================

// handleAllocateIP handles POST /api/v1/sdn/gateway/ipam/allocations
func (h *GatewayHandlers) handleAllocateIP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.gatewayService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrGatewayServiceNotAvailable{})
		return
	}

	var req AllocateIPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.PoolID == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "pool_id"})
		return
	}

	if req.DeviceID == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "device_id"})
		return
	}

	allocation, err := h.gatewayService.AllocateIP(ctx, req.PoolID, req.DeviceID, req.Hostname)
	if err != nil {
		h.logger.Error("Failed to allocate IP", "error", err, "pool_id", req.PoolID, "device_id", req.DeviceID)
		h.writeGatewayError(w, "allocate_ip", err)
		return
	}

	h.logger.Info("IP allocated", "ip", allocation.IP, "pool_id", req.PoolID, "device_id", req.DeviceID)
	h.writeJSON(w, http.StatusCreated, allocation)
}

// handleReleaseIP handles DELETE /api/v1/sdn/gateway/ipam/allocations/{ip}
func (h *GatewayHandlers) handleReleaseIP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.gatewayService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrGatewayServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	ip := vars["ip"]
	if ip == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidIPAddress{})
		return
	}

	// URL decode the IP (in case it contains special characters)
	decodedIP, err := url.PathUnescape(ip)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidIPAddress{IP: ip})
		return
	}

	if err := h.gatewayService.ReleaseIP(ctx, decodedIP); err != nil {
		h.logger.Error("Failed to release IP", "error", err, "ip", decodedIP)
		h.writeGatewayError(w, "release_ip", err)
		return
	}

	resp := GatewayActionResponse{
		ResourceID:   decodedIP,
		ResourceType: "ip_allocation",
		Action:       "release",
		Success:      true,
		Message:      "IP released successfully",
	}

	h.logger.Info("IP released", "ip", decodedIP)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleListAllocations handles GET /api/v1/sdn/gateway/ipam/allocations
func (h *GatewayHandlers) handleListAllocations(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.gatewayService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrGatewayServiceNotAvailable{})
		return
	}

	// Parse optional pool_id filter
	poolID := r.URL.Query().Get("pool_id")

	allocations, err := h.gatewayService.ListAllocations(ctx, poolID)
	if err != nil {
		h.logger.Error("Failed to list allocations", "error", err)
		h.writeGatewayError(w, "list_allocations", err)
		return
	}

	resp := IPAllocationListResponse{
		Allocations: allocations,
		Count:       len(allocations),
		Timestamp:   time.Now().UTC(),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// =============================================================================
// Helper Methods
// =============================================================================

// writeJSON writes a JSON response.
func (h *GatewayHandlers) writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", "error", err)
	}
}

// writeError writes an error response.
func (h *GatewayHandlers) writeError(w http.ResponseWriter, statusCode int, err error) {
	h.writeJSON(w, statusCode, GatewayErrorResponse{
		Error:     err.Error(),
		Code:      statusCode,
		Timestamp: time.Now().UTC(),
	})
}

// writeGatewayError maps gateway errors to appropriate HTTP status codes.
func (h *GatewayHandlers) writeGatewayError(w http.ResponseWriter, operation string, err error) {
	var statusCode int

	switch err.(type) {
	case ErrBGPNotEnabled:
		statusCode = http.StatusServiceUnavailable
	case ErrBGPPeerNotFound:
		statusCode = http.StatusNotFound
	case ErrPrefixNotFound:
		statusCode = http.StatusNotFound
	case ErrPrefixAlreadyAnnounced:
		statusCode = http.StatusConflict
	case ErrIPAMPoolNotFound:
		statusCode = http.StatusNotFound
	case ErrIPAMPoolAlreadyExists:
		statusCode = http.StatusConflict
	case ErrIPAMPoolHasAllocations:
		statusCode = http.StatusConflict
	case ErrIPAMCIDRImmutable:
		statusCode = http.StatusBadRequest
	case ErrIPAllocationNotFound:
		statusCode = http.StatusNotFound
	case ErrIPAlreadyAllocated:
		statusCode = http.StatusConflict
	case ErrIPAMPoolExhausted:
		statusCode = http.StatusServiceUnavailable
	case ErrInvalidGatewayMode:
		statusCode = http.StatusBadRequest
	case ErrInvalidPrefix:
		statusCode = http.StatusBadRequest
	case ErrInvalidIPAddress:
		statusCode = http.StatusBadRequest
	case ErrInvalidPoolID:
		statusCode = http.StatusBadRequest
	case ErrGatewayServiceNotAvailable:
		statusCode = http.StatusServiceUnavailable
	default:
		statusCode = http.StatusInternalServerError
	}

	h.writeError(w, statusCode, ErrGatewayOperationFailed{
		Operation: operation,
		Cause:     err,
	})
}
