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

package rest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant/quota"
)

// =============================================================================
// Tenant REST Handler Errors
// =============================================================================

// ErrTenantManagerNotAvailable is returned when the tenant manager is not configured
// or unavailable.
type ErrTenantManagerNotAvailable struct{}

func (e ErrTenantManagerNotAvailable) Error() string {
	return "tenant manager not available"
}

// ErrInvalidTenantID is returned when a tenant ID is invalid or empty.
type ErrInvalidTenantID struct {
	ID string
}

func (e ErrInvalidTenantID) Error() string {
	if e.ID == "" {
		return "tenant ID is required"
	}
	return fmt.Sprintf("invalid tenant ID: %s", e.ID)
}

// ErrInvalidTenantName is returned when a tenant name is invalid or empty.
type ErrInvalidTenantName struct {
	Name string
}

func (e ErrInvalidTenantName) Error() string {
	if e.Name == "" {
		return "tenant name is required"
	}
	return fmt.Sprintf("invalid tenant name: %s", e.Name)
}

// ErrTenantOperationFailed is returned when a tenant operation fails.
type ErrTenantOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrTenantOperationFailed) Error() string {
	return fmt.Sprintf("tenant operation %s failed: %v", e.Operation, e.Cause)
}

func (e ErrTenantOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrInvalidResourceType is returned when a resource type is invalid.
type ErrInvalidResourceType struct {
	Resource string
}

func (e ErrInvalidResourceType) Error() string {
	return fmt.Sprintf("invalid resource type: %s", e.Resource)
}

// =============================================================================
// Request Types
// =============================================================================

// CreateTenantRequest represents a request to create a new tenant.
type CreateTenantRequest struct {
	Name        string            `json:"name"`
	DisplayName string            `json:"display_name,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// UpdateTenantRequest represents a request to update a tenant.
type UpdateTenantRequest struct {
	DisplayName *string           `json:"display_name,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// UpdateQuotasRequest represents a request to update tenant quotas.
type UpdateQuotasRequest struct {
	Compute *ComputeQuotaRequest `json:"compute,omitempty"`
	Network *NetworkQuotaRequest `json:"network,omitempty"`
	Storage *StorageQuotaRequest `json:"storage,omitempty"`
}

// ComputeQuotaRequest represents compute quota settings in API requests.
type ComputeQuotaRequest struct {
	MaxVMs        int64 `json:"max_vms,omitempty"`
	MaxContainers int64 `json:"max_containers,omitempty"`
	MaxVCPUs      int64 `json:"max_vcpus,omitempty"`
	MaxMemoryMB   int64 `json:"max_memory_mb,omitempty"`
	MaxDiskGB     int64 `json:"max_disk_gb,omitempty"`
}

// NetworkQuotaRequest represents network quota settings in API requests.
type NetworkQuotaRequest struct {
	MaxBridges       int64 `json:"max_bridges,omitempty"`
	MaxPorts         int64 `json:"max_ports,omitempty"`
	MaxBandwidthMbps int64 `json:"max_bandwidth_mbps,omitempty"`
}

// StorageQuotaRequest represents storage quota settings in API requests.
type StorageQuotaRequest struct {
	MaxVolumesGB int64 `json:"max_volumes_gb,omitempty"`
	MaxSnapshots int64 `json:"max_snapshots,omitempty"`
}

// CheckQuotaRequest represents a request to check quota availability.
type CheckQuotaRequest struct {
	Resource string `json:"resource"`
	Amount   int64  `json:"amount"`
}

// RotateDEKRequest represents a request to rotate a tenant's DEK.
type RotateDEKRequest struct {
	Background bool `json:"background"`
}

// InitTenantBarrierRequest represents a request to initialize a per-tenant
// barrier with optional Shamir threshold/shares parameters.
type InitTenantBarrierRequest struct {
	Threshold int `json:"threshold,omitempty"`
	Shares    int `json:"shares,omitempty"`
}

// UnsealTenantBarrierRequest represents a request to unseal a per-tenant
// barrier with the supplied key material. The key is base64-encoded by the
// JSON layer because it is bytes; an empty key falls back to the deterministic
// init credential.
type UnsealTenantBarrierRequest struct {
	Key []byte `json:"key,omitempty"`
}

// =============================================================================
// Response Types
// =============================================================================

// TenantResponse represents a tenant in API responses.
type TenantResponse struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	DisplayName  string            `json:"display_name"`
	State        string            `json:"state"`
	ComputeQuota *ComputeQuotaResp `json:"compute_quota,omitempty"`
	NetworkQuota *NetworkQuotaResp `json:"network_quota,omitempty"`
	StorageQuota *StorageQuotaResp `json:"storage_quota,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
	Annotations  map[string]string `json:"annotations,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
}

// ComputeQuotaResp represents compute quota in API responses.
type ComputeQuotaResp struct {
	MaxVMs        int64 `json:"max_vms"`
	MaxContainers int64 `json:"max_containers"`
	MaxVCPUs      int64 `json:"max_vcpus"`
	MaxMemoryMB   int64 `json:"max_memory_mb"`
	MaxDiskGB     int64 `json:"max_disk_gb"`
}

// NetworkQuotaResp represents network quota in API responses.
type NetworkQuotaResp struct {
	MaxBridges       int64 `json:"max_bridges"`
	MaxPorts         int64 `json:"max_ports"`
	MaxBandwidthMbps int64 `json:"max_bandwidth_mbps"`
}

// StorageQuotaResp represents storage quota in API responses.
type StorageQuotaResp struct {
	MaxVolumesGB int64 `json:"max_volumes_gb"`
	MaxSnapshots int64 `json:"max_snapshots"`
}

// TenantListResponse represents a list of tenants.
type TenantListResponse struct {
	Tenants   []TenantResponse `json:"tenants"`
	Total     int              `json:"total"`
	Limit     int              `json:"limit"`
	Offset    int              `json:"offset"`
	Timestamp time.Time        `json:"timestamp"`
}

// TenantQuotasResponse represents tenant quotas in API responses.
type TenantQuotasResponse struct {
	TenantID  string            `json:"tenant_id"`
	Compute   *ComputeQuotaResp `json:"compute"`
	Network   *NetworkQuotaResp `json:"network"`
	Storage   *StorageQuotaResp `json:"storage"`
	Timestamp time.Time         `json:"timestamp"`
}

// TenantUsageResponse represents tenant resource usage in API responses.
type TenantUsageResponse struct {
	TenantID      string    `json:"tenant_id"`
	VMs           int64     `json:"vms"`
	Containers    int64     `json:"containers"`
	VCPUs         int64     `json:"vcpus"`
	MemoryMB      int64     `json:"memory_mb"`
	DiskGB        int64     `json:"disk_gb"`
	Bridges       int64     `json:"bridges"`
	Ports         int64     `json:"ports"`
	BandwidthMbps int64     `json:"bandwidth_mbps"`
	Volumes       int64     `json:"volumes"`
	Snapshots     int64     `json:"snapshots"`
	Timestamp     time.Time `json:"timestamp"`
}

// TenantActionResponse represents a tenant action result.
type TenantActionResponse struct {
	TenantID string `json:"tenant_id,omitempty"`
	Action   string `json:"action"`
	Success  bool   `json:"success"`
	Message  string `json:"message,omitempty"`
}

// CheckQuotaResponse represents a quota check result.
type CheckQuotaResponse struct {
	TenantID  string    `json:"tenant_id"`
	Resource  string    `json:"resource"`
	Amount    int64     `json:"amount"`
	Allowed   bool      `json:"allowed"`
	Message   string    `json:"message,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// TenantErrorResponse represents a tenant error response.
type TenantErrorResponse struct {
	Error     string    `json:"error"`
	Code      int       `json:"code"`
	Timestamp time.Time `json:"timestamp"`
}

// RotateDEKResponse represents the response for a DEK rotation operation.
type RotateDEKResponse struct {
	TenantID   string    `json:"tenant_id"`
	OldVersion uint64    `json:"old_version"`
	NewVersion uint64    `json:"new_version"`
	Timestamp  time.Time `json:"timestamp"`
}

// ReencryptionProgressResponse represents the progress of a DEK re-encryption operation.
type ReencryptionProgressResponse struct {
	InProgress          bool      `json:"in_progress"`
	TotalKeys           int32     `json:"total_keys"`
	ProcessedKeys       int32     `json:"processed_keys"`
	FailedKeys          int32     `json:"failed_keys"`
	StartedAt           time.Time `json:"started_at,omitempty"`
	EstimatedCompletion time.Time `json:"estimated_completion,omitempty"`
}

// DEKStatusResponse represents the status of a tenant's DEK.
type DEKStatusResponse struct {
	TenantID             string                        `json:"tenant_id"`
	Path                 string                        `json:"path"`
	Algorithm            string                        `json:"algorithm"`
	Version              uint64                        `json:"version"`
	Status               string                        `json:"status"`
	IsDefault            bool                          `json:"is_default"`
	CreatedAt            time.Time                     `json:"created_at"`
	RotatedAt            time.Time                     `json:"rotated_at,omitempty"`
	UsageCount           uint64                        `json:"usage_count"`
	BytesUsed            uint64                        `json:"bytes_used"`
	MaxUsageCount        uint64                        `json:"max_usage_count,omitempty"`
	MaxBytesUsed         uint64                        `json:"max_bytes_used,omitempty"`
	WarningPercent       int32                         `json:"warning_percent,omitempty"`
	UsagePercent         float64                       `json:"usage_percent"`
	NeedsRotation        bool                          `json:"needs_rotation"`
	ReencryptionProgress *ReencryptionProgressResponse `json:"reencryption_progress,omitempty"`
	Timestamp            time.Time                     `json:"timestamp"`
}

// TenantBarrierActionResponse represents the result of a barrier lifecycle
// operation (init, unseal, seal). It mirrors TenantActionResponse but is named
// distinctly so callers can switch on the response type if they wish.
type TenantBarrierActionResponse struct {
	TenantID  string    `json:"tenant_id,omitempty"`
	Success   bool      `json:"success"`
	Message   string    `json:"message,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// TenantBarrierStatusResponse represents the current sealed/initialized state
// and active strategy metadata of a per-tenant barrier.
type TenantBarrierStatusResponse struct {
	TenantID       string    `json:"tenant_id"`
	Sealed         bool      `json:"sealed"`
	Initialized    bool      `json:"initialized"`
	Strategy       string    `json:"strategy"`
	HardwareBacked bool      `json:"hardware_backed"`
	Timestamp      time.Time `json:"timestamp"`
}

// =============================================================================
// Tenant Manager Interface
// =============================================================================

// TenantManagerInterface defines the interface for tenant management operations.
// This interface allows for mocking in unit tests.
type TenantManagerInterface interface {
	// CreateTenant creates a new tenant.
	CreateTenant(ctx context.Context, req *tenant.CreateTenantRequest) (*tenant.TenantEntity, error)
	// GetTenant retrieves a tenant by ID.
	GetTenant(ctx context.Context, id string) (*tenant.TenantEntity, error)
	// GetTenantByName retrieves a tenant by name.
	GetTenantByName(ctx context.Context, name string) (*tenant.TenantEntity, error)
	// ListTenants lists all tenants with pagination.
	ListTenants(ctx context.Context, limit, offset int) ([]*tenant.TenantEntity, int, error)
	// UpdateTenant updates tenant metadata.
	UpdateTenant(ctx context.Context, id string, req *tenant.UpdateTenantRequest) (*tenant.TenantEntity, error)
	// DeleteTenant deletes a tenant.
	DeleteTenant(ctx context.Context, id string) error
	// SuspendTenant suspends a tenant.
	SuspendTenant(ctx context.Context, id string) error
	// ResumeTenant resumes a suspended tenant.
	ResumeTenant(ctx context.Context, id string) error
	// GetQuotas returns tenant quotas.
	GetQuotas(ctx context.Context, tenantID string) (*tenant.TenantQuotas, error)
	// UpdateQuotas updates tenant quotas.
	UpdateQuotas(ctx context.Context, tenantID string, quotas *tenant.TenantQuotas) error
	// GetUsage returns tenant resource usage.
	GetUsage(ctx context.Context, tenantID string) (*quota.TenantUsage, error)
	// CheckQuota checks if a resource request can be fulfilled.
	CheckQuota(ctx context.Context, tenantID string, resource quota.ResourceType, amount int64) error
	// Sync synchronizes manager state with external systems.
	Sync(ctx context.Context) error
	// RotateTenantDEKWithOptions rotates the DEK for a tenant. The
	// background flag controls whether the re-encryption proceeds inline
	// (false) or as a background job (true).
	RotateTenantDEKWithOptions(ctx context.Context, tenantID string, background bool) (*tenant.DEKRotationResult, error)
	// GetTenantDEKStatus returns the status of a tenant's DEK.
	GetTenantDEKStatus(ctx context.Context, tenantID string) (*tenant.DEKStatus, error)
	// InitTenantBarrier explicitly initializes a per-tenant barrier.
	InitTenantBarrier(ctx context.Context, tenantID string) error
	// UnsealTenantBarrier unseals a per-tenant barrier with the supplied key.
	UnsealTenantBarrier(ctx context.Context, tenantID string, key []byte) error
	// SealTenantBarrier seals a per-tenant barrier.
	SealTenantBarrier(ctx context.Context, tenantID string) error
	// TenantBarrierStatus reports the current barrier state for a tenant.
	TenantBarrierStatus(ctx context.Context, tenantID string) (*tenant.TenantBarrierState, error)
}

// =============================================================================
// Tenant Handlers
// =============================================================================

// TenantHandlers provides REST API handlers for tenant operations.
type TenantHandlers struct {
	manager TenantManagerInterface
	logger  *slog.Logger
}

// TenantHandlersOption is a functional option for configuring TenantHandlers.
type TenantHandlersOption func(*TenantHandlers)

// WithTenantManager sets the tenant manager for the handlers.
func WithTenantManager(manager TenantManagerInterface) TenantHandlersOption {
	return func(h *TenantHandlers) {
		h.manager = manager
	}
}

// WithTenantLogger sets the logger for the handlers.
func WithTenantLogger(logger *slog.Logger) TenantHandlersOption {
	return func(h *TenantHandlers) {
		h.logger = logger
	}
}

// NewTenantHandlers creates a new TenantHandlers instance with the provided options.
func NewTenantHandlers(opts ...TenantHandlersOption) *TenantHandlers {
	h := &TenantHandlers{
		logger: slog.Default(),
	}

	for _, opt := range opts {
		opt(h)
	}

	return h
}

// RegisterRoutes registers all tenant routes on the provided router.
func (h *TenantHandlers) RegisterRoutes(router *mux.Router) {
	// List and Create
	router.HandleFunc("/api/v1/tenants", h.handleListTenants).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/tenants", h.handleCreateTenant).Methods(http.MethodPost)

	// Sync operation
	router.HandleFunc("/api/v1/tenants/sync", h.handleSync).Methods(http.MethodPost)

	// Get by name (before {id} to prevent conflict)
	router.HandleFunc("/api/v1/tenants/name/{name}", h.handleGetTenantByName).Methods(http.MethodGet)

	// Individual tenant operations
	router.HandleFunc("/api/v1/tenants/{id}", h.handleGetTenant).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/tenants/{id}", h.handleUpdateTenant).Methods(http.MethodPut)
	router.HandleFunc("/api/v1/tenants/{id}", h.handleDeleteTenant).Methods(http.MethodDelete)

	// Tenant state management
	router.HandleFunc("/api/v1/tenants/{id}/suspend", h.handleSuspendTenant).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/tenants/{id}/resume", h.handleResumeTenant).Methods(http.MethodPost)

	// Quota operations
	router.HandleFunc("/api/v1/tenants/{id}/quotas", h.handleGetQuotas).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/tenants/{id}/quotas", h.handleUpdateQuotas).Methods(http.MethodPut)
	router.HandleFunc("/api/v1/tenants/{id}/usage", h.handleGetUsage).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/tenants/{id}/check-quota", h.handleCheckQuota).Methods(http.MethodPost)

	// DEK operations
	router.HandleFunc("/api/v1/tenants/{id}/dek/rotate", h.handleRotateTenantDEK).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/tenants/{id}/dek/status", h.handleGetTenantDEKStatus).Methods(http.MethodGet)

	// Per-tenant barrier operations
	router.HandleFunc("/api/v1/tenants/{id}/barrier/init", h.handleInitTenantBarrier).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/tenants/{id}/barrier/unseal", h.handleUnsealTenantBarrier).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/tenants/{id}/barrier/seal", h.handleSealTenantBarrier).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/tenants/{id}/barrier/status", h.handleTenantBarrierStatus).Methods(http.MethodGet)

	h.logger.Info("Tenant REST routes registered")
}

// =============================================================================
// List and Create Handlers
// =============================================================================

// handleListTenants handles GET /api/v1/tenants
func (h *TenantHandlers) handleListTenants(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.manager == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTenantManagerNotAvailable{})
		return
	}

	limit := ParseIntParam(r, "limit", 100)
	offset := ParseIntParam(r, "offset", 0)

	tenants, total, err := h.manager.ListTenants(ctx, limit, offset)
	if err != nil {
		h.logger.Error("Failed to list tenants", "error", err)
		h.writeTenantError(w, "list_tenants", err)
		return
	}

	responses := make([]TenantResponse, 0, len(tenants))
	for _, t := range tenants {
		responses = append(responses, h.tenantToResponse(t))
	}

	resp := TenantListResponse{
		Tenants:   responses,
		Total:     total,
		Limit:     limit,
		Offset:    offset,
		Timestamp: time.Now().UTC(),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// handleCreateTenant handles POST /api/v1/tenants
func (h *TenantHandlers) handleCreateTenant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.manager == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTenantManagerNotAvailable{})
		return
	}

	var req CreateTenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Name == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "name"})
		return
	}

	createReq := &tenant.CreateTenantRequest{
		Name:        req.Name,
		DisplayName: req.DisplayName,
		Labels:      req.Labels,
		Annotations: req.Annotations,
	}

	entity, err := h.manager.CreateTenant(ctx, createReq)
	if err != nil {
		h.logger.Error("Failed to create tenant", "error", err, "name", req.Name)
		h.writeTenantError(w, "create_tenant", err)
		return
	}

	resp := h.tenantToResponse(entity)
	h.logger.Info("Tenant created", "tenant_id", entity.ID, "name", req.Name)
	h.writeJSON(w, http.StatusCreated, resp)
}

// =============================================================================
// Get Handlers
// =============================================================================

// handleGetTenant handles GET /api/v1/tenants/{id}
func (h *TenantHandlers) handleGetTenant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.manager == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTenantManagerNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	tenantID := vars["id"]
	if tenantID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidTenantID{})
		return
	}

	entity, err := h.manager.GetTenant(ctx, tenantID)
	if err != nil {
		h.logger.Error("Failed to get tenant", "error", err, "tenant_id", tenantID)
		h.writeTenantError(w, "get_tenant", err)
		return
	}

	resp := h.tenantToResponse(entity)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleGetTenantByName handles GET /api/v1/tenants/name/{name}
func (h *TenantHandlers) handleGetTenantByName(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.manager == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTenantManagerNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	name := vars["name"]
	if name == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidTenantName{})
		return
	}

	entity, err := h.manager.GetTenantByName(ctx, name)
	if err != nil {
		h.logger.Error("Failed to get tenant by name", "error", err, "name", name)
		h.writeTenantError(w, "get_tenant_by_name", err)
		return
	}

	resp := h.tenantToResponse(entity)
	h.writeJSON(w, http.StatusOK, resp)
}

// =============================================================================
// Update and Delete Handlers
// =============================================================================

// handleUpdateTenant handles PUT /api/v1/tenants/{id}
func (h *TenantHandlers) handleUpdateTenant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.manager == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTenantManagerNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	tenantID := vars["id"]
	if tenantID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidTenantID{})
		return
	}

	var req UpdateTenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	updateReq := &tenant.UpdateTenantRequest{
		DisplayName: req.DisplayName,
		Labels:      req.Labels,
		Annotations: req.Annotations,
	}

	entity, err := h.manager.UpdateTenant(ctx, tenantID, updateReq)
	if err != nil {
		h.logger.Error("Failed to update tenant", "error", err, "tenant_id", tenantID)
		h.writeTenantError(w, "update_tenant", err)
		return
	}

	resp := h.tenantToResponse(entity)
	h.logger.Info("Tenant updated", "tenant_id", tenantID)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleDeleteTenant handles DELETE /api/v1/tenants/{id}
func (h *TenantHandlers) handleDeleteTenant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.manager == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTenantManagerNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	tenantID := vars["id"]
	if tenantID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidTenantID{})
		return
	}

	if err := h.manager.DeleteTenant(ctx, tenantID); err != nil {
		h.logger.Error("Failed to delete tenant", "error", err, "tenant_id", tenantID)
		h.writeTenantError(w, "delete_tenant", err)
		return
	}

	resp := TenantActionResponse{
		TenantID: tenantID,
		Action:   "delete",
		Success:  true,
		Message:  "tenant deleted successfully",
	}

	h.logger.Info("Tenant deleted", "tenant_id", tenantID)
	h.writeJSON(w, http.StatusOK, resp)
}

// =============================================================================
// State Management Handlers
// =============================================================================

// handleSuspendTenant handles POST /api/v1/tenants/{id}/suspend
func (h *TenantHandlers) handleSuspendTenant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.manager == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTenantManagerNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	tenantID := vars["id"]
	if tenantID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidTenantID{})
		return
	}

	if err := h.manager.SuspendTenant(ctx, tenantID); err != nil {
		h.logger.Error("Failed to suspend tenant", "error", err, "tenant_id", tenantID)
		h.writeTenantError(w, "suspend_tenant", err)
		return
	}

	resp := TenantActionResponse{
		TenantID: tenantID,
		Action:   "suspend",
		Success:  true,
		Message:  "tenant suspended successfully",
	}

	h.logger.Info("Tenant suspended", "tenant_id", tenantID)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleResumeTenant handles POST /api/v1/tenants/{id}/resume
func (h *TenantHandlers) handleResumeTenant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.manager == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTenantManagerNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	tenantID := vars["id"]
	if tenantID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidTenantID{})
		return
	}

	if err := h.manager.ResumeTenant(ctx, tenantID); err != nil {
		h.logger.Error("Failed to resume tenant", "error", err, "tenant_id", tenantID)
		h.writeTenantError(w, "resume_tenant", err)
		return
	}

	resp := TenantActionResponse{
		TenantID: tenantID,
		Action:   "resume",
		Success:  true,
		Message:  "tenant resumed successfully",
	}

	h.logger.Info("Tenant resumed", "tenant_id", tenantID)
	h.writeJSON(w, http.StatusOK, resp)
}

// =============================================================================
// Quota Handlers
// =============================================================================

// handleGetQuotas handles GET /api/v1/tenants/{id}/quotas
func (h *TenantHandlers) handleGetQuotas(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.manager == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTenantManagerNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	tenantID := vars["id"]
	if tenantID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidTenantID{})
		return
	}

	quotas, err := h.manager.GetQuotas(ctx, tenantID)
	if err != nil {
		h.logger.Error("Failed to get tenant quotas", "error", err, "tenant_id", tenantID)
		h.writeTenantError(w, "get_quotas", err)
		return
	}

	resp := TenantQuotasResponse{
		TenantID: tenantID,
		Compute: &ComputeQuotaResp{
			MaxVMs:        quotas.Compute.MaxVMs,
			MaxContainers: quotas.Compute.MaxContainers,
			MaxVCPUs:      quotas.Compute.MaxVCPUs,
			MaxMemoryMB:   quotas.Compute.MaxMemoryMB,
			MaxDiskGB:     quotas.Compute.MaxDiskGB,
		},
		Network: &NetworkQuotaResp{
			MaxBridges:       quotas.Network.MaxBridges,
			MaxPorts:         quotas.Network.MaxPorts,
			MaxBandwidthMbps: quotas.Network.MaxBandwidthMbps,
		},
		Storage: &StorageQuotaResp{
			MaxVolumesGB: quotas.Storage.MaxVolumesGB,
			MaxSnapshots: quotas.Storage.MaxSnapshots,
		},
		Timestamp: time.Now().UTC(),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// handleUpdateQuotas handles PUT /api/v1/tenants/{id}/quotas
func (h *TenantHandlers) handleUpdateQuotas(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.manager == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTenantManagerNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	tenantID := vars["id"]
	if tenantID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidTenantID{})
		return
	}

	var req UpdateQuotasRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	// Get existing quotas to merge with updates
	existingQuotas, err := h.manager.GetQuotas(ctx, tenantID)
	if err != nil {
		h.logger.Error("Failed to get existing quotas", "error", err, "tenant_id", tenantID)
		h.writeTenantError(w, "update_quotas", err)
		return
	}

	// Apply updates
	if req.Compute != nil {
		if req.Compute.MaxVMs > 0 {
			existingQuotas.Compute.MaxVMs = req.Compute.MaxVMs
		}
		if req.Compute.MaxContainers > 0 {
			existingQuotas.Compute.MaxContainers = req.Compute.MaxContainers
		}
		if req.Compute.MaxVCPUs > 0 {
			existingQuotas.Compute.MaxVCPUs = req.Compute.MaxVCPUs
		}
		if req.Compute.MaxMemoryMB > 0 {
			existingQuotas.Compute.MaxMemoryMB = req.Compute.MaxMemoryMB
		}
		if req.Compute.MaxDiskGB > 0 {
			existingQuotas.Compute.MaxDiskGB = req.Compute.MaxDiskGB
		}
	}

	if req.Network != nil {
		if req.Network.MaxBridges > 0 {
			existingQuotas.Network.MaxBridges = req.Network.MaxBridges
		}
		if req.Network.MaxPorts > 0 {
			existingQuotas.Network.MaxPorts = req.Network.MaxPorts
		}
		if req.Network.MaxBandwidthMbps > 0 {
			existingQuotas.Network.MaxBandwidthMbps = req.Network.MaxBandwidthMbps
		}
	}

	if req.Storage != nil {
		if req.Storage.MaxVolumesGB > 0 {
			existingQuotas.Storage.MaxVolumesGB = req.Storage.MaxVolumesGB
		}
		if req.Storage.MaxSnapshots > 0 {
			existingQuotas.Storage.MaxSnapshots = req.Storage.MaxSnapshots
		}
	}

	if err := h.manager.UpdateQuotas(ctx, tenantID, existingQuotas); err != nil {
		h.logger.Error("Failed to update tenant quotas", "error", err, "tenant_id", tenantID)
		h.writeTenantError(w, "update_quotas", err)
		return
	}

	resp := TenantQuotasResponse{
		TenantID: tenantID,
		Compute: &ComputeQuotaResp{
			MaxVMs:        existingQuotas.Compute.MaxVMs,
			MaxContainers: existingQuotas.Compute.MaxContainers,
			MaxVCPUs:      existingQuotas.Compute.MaxVCPUs,
			MaxMemoryMB:   existingQuotas.Compute.MaxMemoryMB,
			MaxDiskGB:     existingQuotas.Compute.MaxDiskGB,
		},
		Network: &NetworkQuotaResp{
			MaxBridges:       existingQuotas.Network.MaxBridges,
			MaxPorts:         existingQuotas.Network.MaxPorts,
			MaxBandwidthMbps: existingQuotas.Network.MaxBandwidthMbps,
		},
		Storage: &StorageQuotaResp{
			MaxVolumesGB: existingQuotas.Storage.MaxVolumesGB,
			MaxSnapshots: existingQuotas.Storage.MaxSnapshots,
		},
		Timestamp: time.Now().UTC(),
	}

	h.logger.Info("Tenant quotas updated", "tenant_id", tenantID)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleGetUsage handles GET /api/v1/tenants/{id}/usage
func (h *TenantHandlers) handleGetUsage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.manager == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTenantManagerNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	tenantID := vars["id"]
	if tenantID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidTenantID{})
		return
	}

	usage, err := h.manager.GetUsage(ctx, tenantID)
	if err != nil {
		h.logger.Error("Failed to get tenant usage", "error", err, "tenant_id", tenantID)
		h.writeTenantError(w, "get_usage", err)
		return
	}

	resp := TenantUsageResponse{
		TenantID:      tenantID,
		VMs:           usage.VMs,
		Containers:    usage.Containers,
		VCPUs:         usage.VCPUs,
		MemoryMB:      usage.MemoryMB,
		DiskGB:        usage.DiskGB,
		Bridges:       usage.Bridges,
		Ports:         usage.Ports,
		BandwidthMbps: usage.BandwidthMbps,
		Volumes:       usage.Volumes,
		Snapshots:     usage.Snapshots,
		Timestamp:     time.Now().UTC(),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// handleCheckQuota handles POST /api/v1/tenants/{id}/check-quota
func (h *TenantHandlers) handleCheckQuota(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.manager == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTenantManagerNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	tenantID := vars["id"]
	if tenantID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidTenantID{})
		return
	}

	var req CheckQuotaRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Resource == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "resource"})
		return
	}

	resourceType := quota.ResourceType(req.Resource)
	if !resourceType.IsValid() {
		h.writeError(w, http.StatusBadRequest, ErrInvalidResourceType{Resource: req.Resource})
		return
	}

	err := h.manager.CheckQuota(ctx, tenantID, resourceType, req.Amount)

	resp := CheckQuotaResponse{
		TenantID:  tenantID,
		Resource:  req.Resource,
		Amount:    req.Amount,
		Allowed:   err == nil,
		Timestamp: time.Now().UTC(),
	}

	if err != nil {
		resp.Message = err.Error()
	} else {
		resp.Message = "quota available"
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// =============================================================================
// DEK Handlers
// =============================================================================

// handleRotateTenantDEK handles POST /api/v1/tenants/{id}/dek/rotate
func (h *TenantHandlers) handleRotateTenantDEK(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.manager == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTenantManagerNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	tenantID := vars["id"]
	if tenantID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidTenantID{})
		return
	}

	var req RotateDEKRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	result, err := h.manager.RotateTenantDEKWithOptions(ctx, tenantID, req.Background)
	if err != nil {
		h.logger.Error("Failed to rotate tenant DEK", "error", err, "tenant_id", tenantID)
		h.writeTenantError(w, "rotate_dek", err)
		return
	}

	resp := RotateDEKResponse{
		TenantID:   tenantID,
		OldVersion: uint64(result.OldVersion),
		NewVersion: uint64(result.NewVersion),
		Timestamp:  time.Now().UTC(),
	}

	h.logger.Info("Tenant DEK rotated", "tenant_id", tenantID, "old_version", result.OldVersion, "new_version", result.NewVersion)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleGetTenantDEKStatus handles GET /api/v1/tenants/{id}/dek/status
func (h *TenantHandlers) handleGetTenantDEKStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.manager == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTenantManagerNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	tenantID := vars["id"]
	if tenantID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidTenantID{})
		return
	}

	status, err := h.manager.GetTenantDEKStatus(ctx, tenantID)
	if err != nil {
		h.logger.Error("Failed to get tenant DEK status", "error", err, "tenant_id", tenantID)
		h.writeTenantError(w, "get_dek_status", err)
		return
	}

	resp := DEKStatusResponse{
		TenantID:       tenantID,
		Path:           status.Path,
		Algorithm:      status.Algorithm,
		Version:        status.Version,
		Status:         status.Status,
		IsDefault:      status.IsDefault,
		CreatedAt:      status.CreatedAt,
		RotatedAt:      status.RotatedAt,
		UsageCount:     status.UsageCount,
		BytesUsed:      status.BytesUsed,
		MaxUsageCount:  status.MaxUsageCount,
		MaxBytesUsed:   status.MaxBytesUsed,
		WarningPercent: status.WarningPercent,
		UsagePercent:   status.UsagePercent,
		NeedsRotation:  status.NeedsRotation,
		Timestamp:      time.Now().UTC(),
	}

	if status.ReencryptProgress != nil {
		resp.ReencryptionProgress = &ReencryptionProgressResponse{
			InProgress:          status.ReencryptProgress.InProgress,
			TotalKeys:           status.ReencryptProgress.TotalKeys,
			ProcessedKeys:       status.ReencryptProgress.ProcessedKeys,
			FailedKeys:          status.ReencryptProgress.FailedKeys,
			StartedAt:           status.ReencryptProgress.StartedAt,
			EstimatedCompletion: status.ReencryptProgress.EstimatedCompletion,
		}
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// =============================================================================
// Per-Tenant Barrier Handlers
// =============================================================================

// handleInitTenantBarrier handles POST /api/v1/tenants/{id}/barrier/init.
// The body may contain optional Shamir threshold/shares parameters; if absent
// or empty, deterministic non-Shamir initialization is performed. The tenant
// must exist.
func (h *TenantHandlers) handleInitTenantBarrier(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.manager == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTenantManagerNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	tenantID := vars["id"]
	if tenantID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidTenantID{})
		return
	}

	// Body is optional — accept and ignore decode errors when the body is empty.
	if r.Body != nil && r.ContentLength != 0 {
		var req InitTenantBarrierRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
			return
		}
		// Threshold/shares are accepted for forward compatibility with the
		// SDK's TenantBarrierInitRequest; the platform Manager currently
		// performs deterministic init regardless of the values supplied. The
		// gRPC server exhibits the same behaviour.
		_ = req
	}

	if err := h.manager.InitTenantBarrier(ctx, tenantID); err != nil {
		h.logger.Error("Failed to init tenant barrier", "error", err, "tenant_id", tenantID)
		h.writeTenantError(w, "init_tenant_barrier", err)
		return
	}

	resp := TenantBarrierActionResponse{
		TenantID:  tenantID,
		Success:   true,
		Message:   "tenant barrier initialized",
		Timestamp: time.Now().UTC(),
	}

	h.logger.Info("Tenant barrier initialized", "tenant_id", tenantID)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleUnsealTenantBarrier handles POST /api/v1/tenants/{id}/barrier/unseal.
// The body must contain a "key" field (base64-encoded bytes) carrying the
// unseal key material.
func (h *TenantHandlers) handleUnsealTenantBarrier(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.manager == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTenantManagerNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	tenantID := vars["id"]
	if tenantID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidTenantID{})
		return
	}

	var req UnsealTenantBarrierRequest
	if r.Body != nil && r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
			return
		}
	}

	if err := h.manager.UnsealTenantBarrier(ctx, tenantID, req.Key); err != nil {
		h.logger.Error("Failed to unseal tenant barrier", "error", err, "tenant_id", tenantID)
		h.writeTenantError(w, "unseal_tenant_barrier", err)
		return
	}

	resp := TenantBarrierActionResponse{
		TenantID:  tenantID,
		Success:   true,
		Message:   "tenant barrier unsealed",
		Timestamp: time.Now().UTC(),
	}

	h.logger.Info("Tenant barrier unsealed", "tenant_id", tenantID)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleSealTenantBarrier handles POST /api/v1/tenants/{id}/barrier/seal.
// No request body is required; the tenant ID is taken from the URL path.
func (h *TenantHandlers) handleSealTenantBarrier(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.manager == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTenantManagerNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	tenantID := vars["id"]
	if tenantID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidTenantID{})
		return
	}

	if err := h.manager.SealTenantBarrier(ctx, tenantID); err != nil {
		h.logger.Error("Failed to seal tenant barrier", "error", err, "tenant_id", tenantID)
		h.writeTenantError(w, "seal_tenant_barrier", err)
		return
	}

	resp := TenantBarrierActionResponse{
		TenantID:  tenantID,
		Success:   true,
		Message:   "tenant barrier sealed",
		Timestamp: time.Now().UTC(),
	}

	h.logger.Info("Tenant barrier sealed", "tenant_id", tenantID)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleTenantBarrierStatus handles GET /api/v1/tenants/{id}/barrier/status.
// Uninitialized barriers return Sealed=true, Initialized=false rather than
// erroring.
func (h *TenantHandlers) handleTenantBarrierStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.manager == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTenantManagerNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	tenantID := vars["id"]
	if tenantID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidTenantID{})
		return
	}

	st, err := h.manager.TenantBarrierStatus(ctx, tenantID)
	if err != nil {
		h.logger.Error("Failed to get tenant barrier status", "error", err, "tenant_id", tenantID)
		h.writeTenantError(w, "tenant_barrier_status", err)
		return
	}

	resp := TenantBarrierStatusResponse{
		TenantID:       st.TenantID,
		Sealed:         st.Sealed,
		Initialized:    st.Initialized,
		Strategy:       st.Strategy,
		HardwareBacked: st.HardwareBacked,
		Timestamp:      time.Now().UTC(),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// =============================================================================
// Sync Handler
// =============================================================================

// handleSync handles POST /api/v1/tenants/sync
func (h *TenantHandlers) handleSync(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.manager == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTenantManagerNotAvailable{})
		return
	}

	if err := h.manager.Sync(ctx); err != nil {
		h.logger.Error("Failed to sync tenant manager", "error", err)
		h.writeTenantError(w, "sync", err)
		return
	}

	resp := TenantActionResponse{
		Action:  "sync",
		Success: true,
		Message: "tenant manager synchronized successfully",
	}

	h.logger.Info("Tenant manager synchronized")
	h.writeJSON(w, http.StatusOK, resp)
}

// =============================================================================
// Helper Methods
// =============================================================================

// tenantToResponse converts a TenantEntity to TenantResponse.
func (h *TenantHandlers) tenantToResponse(entity *tenant.TenantEntity) TenantResponse {
	resp := TenantResponse{
		ID:          entity.ID,
		Name:        entity.Name,
		DisplayName: entity.DisplayName,
		State:       string(entity.State),
		Labels:      entity.Labels,
		Annotations: entity.Annotations,
		CreatedAt:   entity.CreatedAt,
		UpdatedAt:   entity.UpdatedAt,
	}

	resp.ComputeQuota = &ComputeQuotaResp{
		MaxVMs:        entity.ComputeQuota.MaxVMs,
		MaxContainers: entity.ComputeQuota.MaxContainers,
		MaxVCPUs:      entity.ComputeQuota.MaxVCPUs,
		MaxMemoryMB:   entity.ComputeQuota.MaxMemoryMB,
		MaxDiskGB:     entity.ComputeQuota.MaxDiskGB,
	}

	resp.NetworkQuota = &NetworkQuotaResp{
		MaxBridges:       entity.NetworkQuota.MaxBridges,
		MaxPorts:         entity.NetworkQuota.MaxPorts,
		MaxBandwidthMbps: entity.NetworkQuota.MaxBandwidthMbps,
	}

	resp.StorageQuota = &StorageQuotaResp{
		MaxVolumesGB: entity.StorageQuota.MaxVolumesGB,
		MaxSnapshots: entity.StorageQuota.MaxSnapshots,
	}

	return resp
}

// writeJSON writes a JSON response.
func (h *TenantHandlers) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", "error", err)
	}
}

// writeError writes an error response.
func (h *TenantHandlers) writeError(w http.ResponseWriter, status int, err error) {
	h.writeJSON(w, status, TenantErrorResponse{
		Error:     err.Error(),
		Code:      status,
		Timestamp: time.Now().UTC(),
	})
}

// writeTenantError maps tenant errors to appropriate HTTP status codes.
func (h *TenantHandlers) writeTenantError(w http.ResponseWriter, operation string, err error) {
	var status int

	switch err.(type) {
	case tenant.ErrTenantNotFound:
		status = http.StatusNotFound
	case tenant.ErrTenantExists:
		status = http.StatusConflict
	case tenant.ErrInvalidRequest:
		status = http.StatusBadRequest
	case tenant.ErrInvalidState:
		status = http.StatusBadRequest
	case tenant.ErrInvalidTransition:
		status = http.StatusConflict
	case tenant.ErrQuotaExceeded:
		status = http.StatusForbidden
	case tenant.ErrResourceLimitReached:
		status = http.StatusForbidden
	case tenant.ErrDEKOperationFailed:
		status = http.StatusInternalServerError
	case tenant.ErrStorageFailed:
		status = http.StatusInternalServerError
	case tenant.ErrBarrierOperationFailed:
		status = http.StatusInternalServerError
	case tenant.ErrBarrierNotSupported:
		status = http.StatusNotImplemented
	default:
		status = http.StatusInternalServerError
	}

	h.writeError(w, status, ErrTenantOperationFailed{
		Operation: operation,
		Cause:     err,
	})
}
