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
	"strconv"
	"time"

	"github.com/gorilla/mux"
)

// =============================================================================
// Overlay REST Handler Errors
// =============================================================================

// ErrOverlayServiceNotAvailable is returned when the overlay service is not
// configured or unavailable.
type ErrOverlayServiceNotAvailable struct{}

func (e ErrOverlayServiceNotAvailable) Error() string {
	return "overlay service not available"
}

// ErrInvalidNodeID is returned when a node ID is invalid or empty.
type ErrInvalidNodeID struct {
	ID string
}

func (e ErrInvalidNodeID) Error() string {
	if e.ID == "" {
		return "node ID is required"
	}
	return fmt.Sprintf("invalid node ID: %s", e.ID)
}

// ErrInvalidVNI is returned when a VNI is invalid.
type ErrInvalidVNI struct {
	VNI uint32
}

func (e ErrInvalidVNI) Error() string {
	return fmt.Sprintf("invalid VNI: %d", e.VNI)
}

// ErrInvalidMAC is returned when a MAC address is invalid or empty.
type ErrInvalidMAC struct {
	MAC string
}

func (e ErrInvalidMAC) Error() string {
	if e.MAC == "" {
		return "MAC address is required"
	}
	return fmt.Sprintf("invalid MAC address: %s", e.MAC)
}

// ErrVTEPNotFound is returned when a VTEP is not found.
type ErrVTEPNotFound struct {
	NodeID string
}

func (e ErrVTEPNotFound) Error() string {
	return fmt.Sprintf("VTEP not found for node: %s", e.NodeID)
}

// ErrVNINotFound is returned when a VNI is not found.
type ErrVNINotFound struct {
	VNI uint32
}

func (e ErrVNINotFound) Error() string {
	return fmt.Sprintf("VNI not found: %d", e.VNI)
}

// ErrVNIAlreadyExists is returned when attempting to create a VNI that already
// exists.
type ErrVNIAlreadyExists struct {
	VNI uint32
}

func (e ErrVNIAlreadyExists) Error() string {
	return fmt.Sprintf("VNI already exists: %d", e.VNI)
}

// ErrMACNotFound is returned when a MAC address is not found.
type ErrMACNotFound struct {
	MAC string
}

func (e ErrMACNotFound) Error() string {
	return fmt.Sprintf("MAC not found: %s", e.MAC)
}

// ErrOverlayOperationFailed is returned when an overlay operation fails.
type ErrOverlayOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrOverlayOperationFailed) Error() string {
	return fmt.Sprintf("overlay operation %s failed: %v", e.Operation, e.Cause)
}

func (e ErrOverlayOperationFailed) Unwrap() error {
	return e.Cause
}

// =============================================================================
// Request/Response Types
// =============================================================================

// VTEPInfoResponse represents VTEP information in API responses.
type VTEPInfoResponse struct {
	NodeID   string    `json:"node_id"`
	IP       string    `json:"ip"`
	VNIs     []uint32  `json:"vnis"`
	Healthy  bool      `json:"healthy"`
	LastSeen time.Time `json:"last_seen"`
}

// VTEPListResponse represents a list of VTEPs.
type VTEPListResponse struct {
	VTEPs     []VTEPInfoResponse `json:"vteps"`
	Count     int                `json:"count"`
	Timestamp time.Time          `json:"timestamp"`
}

// VNIConfigRequest represents a VNI creation request.
type VNIConfigRequest struct {
	VNI    uint32            `json:"vni"`
	VLAN   uint32            `json:"vlan,omitempty"`
	Name   string            `json:"name,omitempty"`
	Labels map[string]string `json:"labels,omitempty"`
}

// VNIResponse represents a VNI in API responses.
type VNIResponse struct {
	ID        string           `json:"id"`
	Config    VNIConfigRequest `json:"config"`
	CreatedAt time.Time        `json:"created_at"`
	MACCount  uint32           `json:"mac_count"`
}

// VNIListResponse represents a list of VNIs.
type VNIListResponse struct {
	VNIs      []VNIResponse `json:"vnis"`
	Count     int           `json:"count"`
	Timestamp time.Time     `json:"timestamp"`
}

// TunnelInfoResponse represents tunnel information in API responses.
type TunnelInfoResponse struct {
	LocalVTEP  string `json:"local_vtep"`
	RemoteVTEP string `json:"remote_vtep"`
	VNI        uint32 `json:"vni"`
	State      string `json:"state"`
	BytesTx    uint64 `json:"bytes_tx"`
	BytesRx    uint64 `json:"bytes_rx"`
}

// TunnelListResponse represents a list of tunnels.
type TunnelListResponse struct {
	Tunnels   []TunnelInfoResponse `json:"tunnels"`
	Count     int                  `json:"count"`
	Timestamp time.Time            `json:"timestamp"`
}

// RemoteMACResponse represents a remote MAC entry in API responses.
type RemoteMACResponse struct {
	MAC        string    `json:"mac"`
	VNI        uint32    `json:"vni"`
	RemoteVTEP string    `json:"remote_vtep"`
	LearnedAt  time.Time `json:"learned_at"`
}

// RemoteMACListResponse represents a list of remote MACs.
type RemoteMACListResponse struct {
	MACs      []RemoteMACResponse `json:"macs"`
	Count     int                 `json:"count"`
	Timestamp time.Time           `json:"timestamp"`
}

// OverlayStatusResponse represents the overlay network status.
type OverlayStatusResponse struct {
	NodeID         string    `json:"node_id"`
	VTEPIP         string    `json:"vtep_ip"`
	VXLANPort      uint16    `json:"vxlan_port"`
	VTEPCount      uint32    `json:"vtep_count"`
	VNICount       uint32    `json:"vni_count"`
	TunnelCount    uint32    `json:"tunnel_count"`
	RemoteMACCount uint32    `json:"remote_mac_count"`
	Healthy        bool      `json:"healthy"`
	Timestamp      time.Time `json:"timestamp"`
}

// OverlayActionResponse represents an overlay action result.
type OverlayActionResponse struct {
	ResourceID   string `json:"resource_id"`
	ResourceType string `json:"resource_type"`
	Action       string `json:"action"`
	Success      bool   `json:"success"`
	Message      string `json:"message,omitempty"`
}

// OverlayErrorResponse represents an overlay error response.
type OverlayErrorResponse struct {
	Error     string    `json:"error"`
	Code      int       `json:"code"`
	Timestamp time.Time `json:"timestamp"`
}

// =============================================================================
// Overlay Service Interface
// =============================================================================

// OverlayServiceInterface defines the interface for overlay network operations.
type OverlayServiceInterface interface {
	// Status operations
	GetOverlayStatus(ctx context.Context) (*OverlayStatusResponse, error)

	// VTEP operations
	ListVTEPs(ctx context.Context) ([]VTEPInfoResponse, error)
	GetVTEP(ctx context.Context, nodeID string) (*VTEPInfoResponse, error)

	// VNI operations
	CreateVNI(ctx context.Context, config *VNIConfigRequest) (*VNIResponse, error)
	DeleteVNI(ctx context.Context, vni uint32) error
	ListVNIs(ctx context.Context) ([]VNIResponse, error)

	// Tunnel operations
	ListTunnels(ctx context.Context, vni uint32) ([]TunnelInfoResponse, error)

	// MAC operations
	ListRemoteMACs(ctx context.Context, vni uint32) ([]RemoteMACResponse, error)
	ForgetMAC(ctx context.Context, mac string, vni uint32) error
}

// =============================================================================
// Overlay Handlers
// =============================================================================

// OverlayHandlers provides REST API handlers for overlay network operations.
type OverlayHandlers struct {
	overlayService OverlayServiceInterface
	logger         *slog.Logger
}

// NewOverlayHandlers creates a new OverlayHandlers instance.
func NewOverlayHandlers(overlayService OverlayServiceInterface, logger *slog.Logger) *OverlayHandlers {
	if logger == nil {
		logger = slog.Default()
	}
	return &OverlayHandlers{
		overlayService: overlayService,
		logger:         logger,
	}
}

// SetOverlayService sets the overlay service for the handlers.
func (h *OverlayHandlers) SetOverlayService(overlayService OverlayServiceInterface) {
	h.overlayService = overlayService
}

// RegisterRoutes registers all overlay routes on the provided router.
func (h *OverlayHandlers) RegisterRoutes(router *mux.Router) {
	// Overlay status
	router.HandleFunc("/api/v1/sdn/overlay/status", h.handleGetOverlayStatus).Methods(http.MethodGet)

	// VTEP operations
	router.HandleFunc("/api/v1/sdn/overlay/vteps", h.handleListVTEPs).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/sdn/overlay/vteps/{node_id}", h.handleGetVTEP).Methods(http.MethodGet)

	// VNI operations
	router.HandleFunc("/api/v1/sdn/overlay/vnis", h.handleListVNIs).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/sdn/overlay/vnis", h.handleCreateVNI).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/sdn/overlay/vnis/{vni}", h.handleDeleteVNI).Methods(http.MethodDelete)

	// Tunnel operations
	router.HandleFunc("/api/v1/sdn/overlay/tunnels", h.handleListTunnels).Methods(http.MethodGet)

	// MAC operations
	router.HandleFunc("/api/v1/sdn/overlay/macs", h.handleListRemoteMACs).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/sdn/overlay/macs/{mac}", h.handleForgetMAC).Methods(http.MethodDelete)

	h.logger.Info("Overlay REST routes registered")
}

// =============================================================================
// Status Handler
// =============================================================================

// handleGetOverlayStatus handles GET /api/v1/sdn/overlay/status
func (h *OverlayHandlers) handleGetOverlayStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.overlayService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrOverlayServiceNotAvailable{})
		return
	}

	status, err := h.overlayService.GetOverlayStatus(ctx)
	if err != nil {
		h.logger.Error("Failed to get overlay status", "error", err)
		h.writeOverlayError(w, "get_overlay_status", err)
		return
	}

	status.Timestamp = time.Now().UTC()
	h.writeJSON(w, http.StatusOK, status)
}

// =============================================================================
// VTEP Handlers
// =============================================================================

// handleListVTEPs handles GET /api/v1/sdn/overlay/vteps
func (h *OverlayHandlers) handleListVTEPs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.overlayService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrOverlayServiceNotAvailable{})
		return
	}

	vteps, err := h.overlayService.ListVTEPs(ctx)
	if err != nil {
		h.logger.Error("Failed to list VTEPs", "error", err)
		h.writeOverlayError(w, "list_vteps", err)
		return
	}

	resp := VTEPListResponse{
		VTEPs:     vteps,
		Count:     len(vteps),
		Timestamp: time.Now().UTC(),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// handleGetVTEP handles GET /api/v1/sdn/overlay/vteps/{node_id}
func (h *OverlayHandlers) handleGetVTEP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.overlayService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrOverlayServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	nodeID := vars["node_id"]
	if nodeID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidNodeID{})
		return
	}

	vtep, err := h.overlayService.GetVTEP(ctx, nodeID)
	if err != nil {
		h.logger.Error("Failed to get VTEP", "error", err, "node_id", nodeID)
		h.writeOverlayError(w, "get_vtep", err)
		return
	}

	h.writeJSON(w, http.StatusOK, vtep)
}

// =============================================================================
// VNI Handlers
// =============================================================================

// handleListVNIs handles GET /api/v1/sdn/overlay/vnis
func (h *OverlayHandlers) handleListVNIs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.overlayService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrOverlayServiceNotAvailable{})
		return
	}

	vnis, err := h.overlayService.ListVNIs(ctx)
	if err != nil {
		h.logger.Error("Failed to list VNIs", "error", err)
		h.writeOverlayError(w, "list_vnis", err)
		return
	}

	resp := VNIListResponse{
		VNIs:      vnis,
		Count:     len(vnis),
		Timestamp: time.Now().UTC(),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// handleCreateVNI handles POST /api/v1/sdn/overlay/vnis
func (h *OverlayHandlers) handleCreateVNI(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.overlayService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrOverlayServiceNotAvailable{})
		return
	}

	var req VNIConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.VNI == 0 {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "vni"})
		return
	}

	// VNI range validation (1-16777215 for VXLAN)
	if req.VNI > 16777215 {
		h.writeError(w, http.StatusBadRequest, ErrInvalidVNI{VNI: req.VNI})
		return
	}

	vni, err := h.overlayService.CreateVNI(ctx, &req)
	if err != nil {
		h.logger.Error("Failed to create VNI", "error", err, "vni", req.VNI)
		h.writeOverlayError(w, "create_vni", err)
		return
	}

	h.logger.Info("VNI created", "vni", req.VNI, "name", req.Name)
	h.writeJSON(w, http.StatusCreated, vni)
}

// handleDeleteVNI handles DELETE /api/v1/sdn/overlay/vnis/{vni}
func (h *OverlayHandlers) handleDeleteVNI(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.overlayService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrOverlayServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	vniStr := vars["vni"]
	if vniStr == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidVNI{VNI: 0})
		return
	}

	vni, err := strconv.ParseUint(vniStr, 10, 32)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidVNI{VNI: 0})
		return
	}

	if err := h.overlayService.DeleteVNI(ctx, uint32(vni)); err != nil {
		h.logger.Error("Failed to delete VNI", "error", err, "vni", vni)
		h.writeOverlayError(w, "delete_vni", err)
		return
	}

	resp := OverlayActionResponse{
		ResourceID:   vniStr,
		ResourceType: "vni",
		Action:       "delete",
		Success:      true,
		Message:      "VNI deleted successfully",
	}

	h.logger.Info("VNI deleted", "vni", vni)
	h.writeJSON(w, http.StatusOK, resp)
}

// =============================================================================
// Tunnel Handlers
// =============================================================================

// handleListTunnels handles GET /api/v1/sdn/overlay/tunnels
func (h *OverlayHandlers) handleListTunnels(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.overlayService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrOverlayServiceNotAvailable{})
		return
	}

	// Parse optional VNI filter
	var vni uint32
	vniStr := r.URL.Query().Get("vni")
	if vniStr != "" {
		vniVal, err := strconv.ParseUint(vniStr, 10, 32)
		if err != nil {
			h.writeError(w, http.StatusBadRequest, ErrInvalidVNI{VNI: 0})
			return
		}
		vni = uint32(vniVal)
	}

	tunnels, err := h.overlayService.ListTunnels(ctx, vni)
	if err != nil {
		h.logger.Error("Failed to list tunnels", "error", err)
		h.writeOverlayError(w, "list_tunnels", err)
		return
	}

	resp := TunnelListResponse{
		Tunnels:   tunnels,
		Count:     len(tunnels),
		Timestamp: time.Now().UTC(),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// =============================================================================
// MAC Handlers
// =============================================================================

// handleListRemoteMACs handles GET /api/v1/sdn/overlay/macs
func (h *OverlayHandlers) handleListRemoteMACs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.overlayService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrOverlayServiceNotAvailable{})
		return
	}

	// Parse optional VNI filter
	var vni uint32
	vniStr := r.URL.Query().Get("vni")
	if vniStr != "" {
		vniVal, err := strconv.ParseUint(vniStr, 10, 32)
		if err != nil {
			h.writeError(w, http.StatusBadRequest, ErrInvalidVNI{VNI: 0})
			return
		}
		vni = uint32(vniVal)
	}

	macs, err := h.overlayService.ListRemoteMACs(ctx, vni)
	if err != nil {
		h.logger.Error("Failed to list remote MACs", "error", err)
		h.writeOverlayError(w, "list_remote_macs", err)
		return
	}

	resp := RemoteMACListResponse{
		MACs:      macs,
		Count:     len(macs),
		Timestamp: time.Now().UTC(),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// handleForgetMAC handles DELETE /api/v1/sdn/overlay/macs/{mac}
func (h *OverlayHandlers) handleForgetMAC(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.overlayService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrOverlayServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	mac := vars["mac"]
	if mac == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidMAC{})
		return
	}

	// URL decode the MAC address (in case it contains special characters)
	decodedMAC, err := url.PathUnescape(mac)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidMAC{MAC: mac})
		return
	}

	// Parse optional VNI from query
	var vni uint32
	vniStr := r.URL.Query().Get("vni")
	if vniStr != "" {
		vniVal, err := strconv.ParseUint(vniStr, 10, 32)
		if err != nil {
			h.writeError(w, http.StatusBadRequest, ErrInvalidVNI{VNI: 0})
			return
		}
		vni = uint32(vniVal)
	}

	if err := h.overlayService.ForgetMAC(ctx, decodedMAC, vni); err != nil {
		h.logger.Error("Failed to forget MAC", "error", err, "mac", decodedMAC)
		h.writeOverlayError(w, "forget_mac", err)
		return
	}

	resp := OverlayActionResponse{
		ResourceID:   decodedMAC,
		ResourceType: "mac",
		Action:       "forget",
		Success:      true,
		Message:      "MAC address forgotten successfully",
	}

	h.logger.Info("MAC forgotten", "mac", decodedMAC, "vni", vni)
	h.writeJSON(w, http.StatusOK, resp)
}

// =============================================================================
// Helper Methods
// =============================================================================

// writeJSON writes a JSON response.
func (h *OverlayHandlers) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", "error", err)
	}
}

// writeError writes an error response.
func (h *OverlayHandlers) writeError(w http.ResponseWriter, status int, err error) {
	h.writeJSON(w, status, OverlayErrorResponse{
		Error:     err.Error(),
		Code:      status,
		Timestamp: time.Now().UTC(),
	})
}

// writeOverlayError maps overlay errors to appropriate HTTP status codes.
func (h *OverlayHandlers) writeOverlayError(w http.ResponseWriter, operation string, err error) {
	var status int

	switch err.(type) {
	case ErrVTEPNotFound:
		status = http.StatusNotFound
	case ErrVNINotFound:
		status = http.StatusNotFound
	case ErrVNIAlreadyExists:
		status = http.StatusConflict
	case ErrMACNotFound:
		status = http.StatusNotFound
	case ErrInvalidVNI:
		status = http.StatusBadRequest
	case ErrInvalidNodeID:
		status = http.StatusBadRequest
	case ErrInvalidMAC:
		status = http.StatusBadRequest
	case ErrOverlayServiceNotAvailable:
		status = http.StatusServiceUnavailable
	default:
		status = http.StatusInternalServerError
	}

	h.writeError(w, status, ErrOverlayOperationFailed{
		Operation: operation,
		Cause:     err,
	})
}
