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

// This file implements multi-tenant operations for the QUIC protocol transport layer.
// QUIC provides low-latency, multiplexed streams with built-in TLS 1.3, making it
// ideal for mobile and high-performance clients.
//
// The QUIC Tenant handlers delegate to the TenantManagerInterface, which abstracts
// the underlying tenant management implementation. All requests and responses use
// MessagePack encoding via codec tags for efficient binary serialization.
//
// # Supported Operations
//
// Tenant Management:
//   - OpTenantList: List all tenants with pagination
//   - OpTenantGet: Get tenant by ID
//   - OpTenantGetByName: Get tenant by name
//   - OpTenantCreate: Create a new tenant
//   - OpTenantUpdate: Update tenant metadata
//   - OpTenantDelete: Delete a tenant
//   - OpTenantSuspend: Suspend tenant (blocks traffic)
//   - OpTenantResume: Resume suspended tenant
//
// Quota Management:
//   - OpTenantGetQuotas: Get tenant quotas
//   - OpTenantUpdateQuotas: Update tenant quotas
//   - OpTenantGetUsage: Get tenant resource usage
//   - OpTenantCheckQuota: Check quota availability
//
// Network/VLAN Operations:
//   - OpTenantValidateVLAN: Validate VLAN for tenant
//   - OpTenantGetBridge: Get OVS bridge name for tenant
//
// Synchronization:
//   - OpTenantSync: Synchronize tenant state with external systems
//
// DEK Operations:
//   - OpTenantRotateDEK: Rotate tenant DEK
//   - OpTenantGetDEKStatus: Get tenant DEK status

package daemon

import (
	"context"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant/quota"
)

// Tenant QUIC opcodes - aliased from quic.protocol for convenience
const (
	OpTenantList         = quic.OpTenantList         // 0xDB
	OpTenantGet          = quic.OpTenantGet          // 0xDC
	OpTenantGetByName    = quic.OpTenantGetByName    // 0xDD
	OpTenantCreate       = quic.OpTenantCreate       // 0xDE
	OpTenantUpdate       = quic.OpTenantUpdate       // 0xDF
	OpTenantDelete       = quic.OpTenantDelete       // 0xE0
	OpTenantSuspend      = quic.OpTenantSuspend      // 0xE1
	OpTenantResume       = quic.OpTenantResume       // 0xE2
	OpTenantGetQuotas    = quic.OpTenantGetQuotas    // 0xE3
	OpTenantUpdateQuotas = quic.OpTenantUpdateQuotas // 0xE4
	OpTenantGetUsage     = quic.OpTenantGetUsage     // 0xE5
	OpTenantCheckQuota   = quic.OpTenantCheckQuota   // 0xE6
	OpTenantValidateVLAN = quic.OpTenantValidateVLAN // 0xE7
	OpTenantGetBridge    = quic.OpTenantGetBridge    // 0xE8
	OpTenantSync         = quic.OpTenantSync         // 0xE9
	OpTenantRotateDEK    = quic.OpTenantRotateDEK    // 0xEA
	OpTenantGetDEKStatus = quic.OpTenantGetDEKStatus // 0xEB
)

// =============================================================================
// Service Interface
// =============================================================================

// TenantManagerInterface defines the interface for tenant management operations.
// This interface abstracts the underlying tenant manager implementation,
// enabling the QUIC handler to remain decoupled from specific backends.
type TenantManagerInterface interface {
	// Tenant CRUD operations
	CreateTenant(ctx context.Context, req *tenant.CreateTenantRequest) (*tenant.TenantEntity, error)
	GetTenant(ctx context.Context, id string) (*tenant.TenantEntity, error)
	GetTenantByName(ctx context.Context, name string) (*tenant.TenantEntity, error)
	ListTenants(ctx context.Context, limit, offset int) ([]*tenant.TenantEntity, int, error)
	UpdateTenant(ctx context.Context, id string, req *tenant.UpdateTenantRequest) (*tenant.TenantEntity, error)
	DeleteTenant(ctx context.Context, id string) error

	// Lifecycle operations
	SuspendTenant(ctx context.Context, id string) error
	ResumeTenant(ctx context.Context, id string) error

	// Quota operations
	GetQuotas(ctx context.Context, tenantID string) (*tenant.TenantQuotas, error)
	UpdateQuotas(ctx context.Context, tenantID string, quotas *tenant.TenantQuotas) error
	GetUsage(ctx context.Context, tenantID string) (*quota.TenantUsage, error)
	CheckQuota(ctx context.Context, tenantID string, resource quota.ResourceType, amount int64) error

	// Network operations
	ValidateVLAN(ctx context.Context, tenantID string, vlanID uint16) error
	GetBridgeName(ctx context.Context, tenantID string) (string, error)

	// Synchronization
	Sync(ctx context.Context) error

	// DEK operations
	RotateDEK(ctx context.Context, tenantID string, background bool) (*tenant.DEKRotationResult, error)
	GetDEKStatus(ctx context.Context, tenantID string) (*tenant.DEKStatus, error)
}

// =============================================================================
// Request/Response Types
// =============================================================================

// TenantListRequest represents a request to list tenants
type TenantListRequest struct {
	Limit  int `codec:"limit,omitempty"`
	Offset int `codec:"offset,omitempty"`
}

// QUICTenantResponse represents a tenant entity in QUIC API responses
type QUICTenantResponse struct {
	ID           string            `codec:"id"`
	Name         string            `codec:"name"`
	DisplayName  string            `codec:"display_name"`
	State        string            `codec:"state"`
	OVSBridge    string            `codec:"ovs_bridge,omitempty"`
	VLANStart    uint16            `codec:"vlan_start,omitempty"`
	VLANEnd      uint16            `codec:"vlan_end,omitempty"`
	DEKPath      string            `codec:"dek_path,omitempty"`
	DEKHandle    uint32            `codec:"dek_handle,omitempty"` // Deprecated: use DEKPath
	ComputeQuota *ComputeQuotaDTO  `codec:"compute_quota,omitempty"`
	NetworkQuota *NetworkQuotaDTO  `codec:"network_quota,omitempty"`
	StorageQuota *StorageQuotaDTO  `codec:"storage_quota,omitempty"`
	Labels       map[string]string `codec:"labels,omitempty"`
	Annotations  map[string]string `codec:"annotations,omitempty"`
	CreatedAt    int64             `codec:"created_at"`
	UpdatedAt    int64             `codec:"updated_at"`
	Timestamp    int64             `codec:"timestamp"`
}

// ComputeQuotaDTO represents compute quota for QUIC responses
type ComputeQuotaDTO struct {
	MaxVMs         int64 `codec:"max_vms"`
	MaxContainers  int64 `codec:"max_containers"`
	MaxVCPUs       int64 `codec:"max_vcpus"`
	MaxMemoryMB    int64 `codec:"max_memory_mb"`
	MaxDiskGB      int64 `codec:"max_disk_gb"`
	UsedVMs        int64 `codec:"used_vms"`
	UsedContainers int64 `codec:"used_containers"`
	UsedVCPUs      int64 `codec:"used_vcpus"`
	UsedMemoryMB   int64 `codec:"used_memory_mb"`
	UsedDiskGB     int64 `codec:"used_disk_gb"`
}

// NetworkQuotaDTO represents network quota for QUIC responses
type NetworkQuotaDTO struct {
	MaxBridges       int64 `codec:"max_bridges"`
	MaxPorts         int64 `codec:"max_ports"`
	MaxBandwidthMbps int64 `codec:"max_bandwidth_mbps"`
	UsedBridges      int64 `codec:"used_bridges"`
	UsedPorts        int64 `codec:"used_ports"`
}

// StorageQuotaDTO represents storage quota for QUIC responses
type StorageQuotaDTO struct {
	MaxVolumesGB  int64 `codec:"max_volumes_gb"`
	MaxSnapshots  int64 `codec:"max_snapshots"`
	UsedVolumesGB int64 `codec:"used_volumes_gb"`
	UsedSnapshots int64 `codec:"used_snapshots"`
}

// TenantListResponse represents a response containing tenants
type TenantListResponse struct {
	Tenants   []*QUICTenantResponse `codec:"tenants"`
	Total     int                   `codec:"total"`
	Limit     int                   `codec:"limit"`
	Offset    int                   `codec:"offset"`
	Timestamp int64                 `codec:"timestamp"`
}

// TenantGetRequest represents a request to get a tenant by ID
type TenantGetRequest struct {
	TenantID string `codec:"tenant_id"`
}

// TenantGetByNameRequest represents a request to get a tenant by name
type TenantGetByNameRequest struct {
	Name string `codec:"name"`
}

// TenantGetResponse represents a response containing a single tenant
type TenantGetResponse struct {
	Tenant    *QUICTenantResponse `codec:"tenant"`
	Timestamp int64               `codec:"timestamp"`
}

// TenantCreateRequest represents a request to create a new tenant
type TenantCreateRequest struct {
	Name         string            `codec:"name"`
	DisplayName  string            `codec:"display_name,omitempty"`
	VLANStart    uint16            `codec:"vlan_start,omitempty"`
	VLANEnd      uint16            `codec:"vlan_end,omitempty"`
	Labels       map[string]string `codec:"labels,omitempty"`
	Annotations  map[string]string `codec:"annotations,omitempty"`
	ComputeQuota *ComputeQuotaDTO  `codec:"compute_quota,omitempty"`
	NetworkQuota *NetworkQuotaDTO  `codec:"network_quota,omitempty"`
	StorageQuota *StorageQuotaDTO  `codec:"storage_quota,omitempty"`
}

// TenantCreateResponse represents a response after creating a tenant
type TenantCreateResponse struct {
	Tenant    *QUICTenantResponse `codec:"tenant"`
	Timestamp int64               `codec:"timestamp"`
}

// TenantUpdateRequest represents a request to update a tenant
type TenantUpdateRequest struct {
	TenantID    string            `codec:"tenant_id"`
	DisplayName string            `codec:"display_name,omitempty"`
	Labels      map[string]string `codec:"labels,omitempty"`
	Annotations map[string]string `codec:"annotations,omitempty"`
}

// TenantUpdateResponse represents a response after updating a tenant
type TenantUpdateResponse struct {
	Tenant    *QUICTenantResponse `codec:"tenant"`
	Timestamp int64               `codec:"timestamp"`
}

// TenantDeleteRequest represents a request to delete a tenant
type TenantDeleteRequest struct {
	TenantID string `codec:"tenant_id"`
}

// TenantDeleteResponse represents a response after deleting a tenant
type TenantDeleteResponse struct {
	TenantID  string `codec:"tenant_id"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// TenantSuspendRequest represents a request to suspend a tenant
type TenantSuspendRequest struct {
	TenantID string `codec:"tenant_id"`
}

// TenantSuspendResponse represents a response after suspending a tenant
type TenantSuspendResponse struct {
	TenantID  string `codec:"tenant_id"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// TenantResumeRequest represents a request to resume a tenant
type TenantResumeRequest struct {
	TenantID string `codec:"tenant_id"`
}

// TenantResumeResponse represents a response after resuming a tenant
type TenantResumeResponse struct {
	TenantID  string `codec:"tenant_id"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// TenantQuotasRequest represents a request to get tenant quotas
type TenantQuotasRequest struct {
	TenantID string `codec:"tenant_id"`
}

// TenantQuotasResponse represents a response containing tenant quotas
type TenantQuotasResponse struct {
	TenantID     string           `codec:"tenant_id"`
	ComputeQuota *ComputeQuotaDTO `codec:"compute_quota"`
	NetworkQuota *NetworkQuotaDTO `codec:"network_quota"`
	StorageQuota *StorageQuotaDTO `codec:"storage_quota"`
	Timestamp    int64            `codec:"timestamp"`
}

// TenantUpdateQuotasRequest represents a request to update tenant quotas
type TenantUpdateQuotasRequest struct {
	TenantID     string           `codec:"tenant_id"`
	ComputeQuota *ComputeQuotaDTO `codec:"compute_quota,omitempty"`
	NetworkQuota *NetworkQuotaDTO `codec:"network_quota,omitempty"`
	StorageQuota *StorageQuotaDTO `codec:"storage_quota,omitempty"`
}

// TenantUpdateQuotasResponse represents a response after updating quotas
type TenantUpdateQuotasResponse struct {
	TenantID  string `codec:"tenant_id"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// TenantUsageRequest represents a request to get tenant usage
type TenantUsageRequest struct {
	TenantID string `codec:"tenant_id"`
}

// TenantUsageResponse represents a response containing tenant usage
type TenantUsageResponse struct {
	TenantID      string `codec:"tenant_id"`
	VMs           int64  `codec:"vms"`
	Containers    int64  `codec:"containers"`
	VCPUs         int64  `codec:"vcpus"`
	MemoryMB      int64  `codec:"memory_mb"`
	DiskGB        int64  `codec:"disk_gb"`
	Bridges       int64  `codec:"bridges"`
	Ports         int64  `codec:"ports"`
	BandwidthMbps int64  `codec:"bandwidth_mbps"`
	Volumes       int64  `codec:"volumes"`
	Snapshots     int64  `codec:"snapshots"`
	Timestamp     int64  `codec:"timestamp"`
}

// TenantCheckQuotaRequest represents a request to check quota availability
type TenantCheckQuotaRequest struct {
	TenantID string `codec:"tenant_id"`
	Resource string `codec:"resource"`
	Amount   int64  `codec:"amount"`
}

// TenantCheckQuotaResponse represents a response for quota availability check
type TenantCheckQuotaResponse struct {
	TenantID  string `codec:"tenant_id"`
	Resource  string `codec:"resource"`
	Amount    int64  `codec:"amount"`
	Available bool   `codec:"available"`
	Message   string `codec:"message,omitempty"`
	Timestamp int64  `codec:"timestamp"`
}

// TenantValidateVLANRequest represents a request to validate VLAN for tenant
type TenantValidateVLANRequest struct {
	TenantID string `codec:"tenant_id"`
	VLANID   uint16 `codec:"vlan_id"`
}

// TenantValidateVLANResponse represents a response for VLAN validation
type TenantValidateVLANResponse struct {
	TenantID  string `codec:"tenant_id"`
	VLANID    uint16 `codec:"vlan_id"`
	Valid     bool   `codec:"valid"`
	Message   string `codec:"message,omitempty"`
	Timestamp int64  `codec:"timestamp"`
}

// TenantGetBridgeRequest represents a request to get bridge name
type TenantGetBridgeRequest struct {
	TenantID string `codec:"tenant_id"`
}

// TenantGetBridgeResponse represents a response containing bridge name
type TenantGetBridgeResponse struct {
	TenantID   string `codec:"tenant_id"`
	BridgeName string `codec:"bridge_name"`
	Timestamp  int64  `codec:"timestamp"`
}

// TenantSyncRequest represents a request to sync tenant state
type TenantSyncRequest struct{}

// TenantSyncResponse represents a response after syncing tenant state
type TenantSyncResponse struct {
	Success   bool   `codec:"success"`
	Message   string `codec:"message,omitempty"`
	Timestamp int64  `codec:"timestamp"`
}

// TenantRotateDEKRequest represents a request to rotate tenant DEK
type TenantRotateDEKRequest struct {
	TenantID   string `codec:"tenant_id"`
	Background bool   `codec:"background,omitempty"`
}

// TenantRotateDEKResponse represents a response after rotating tenant DEK
type TenantRotateDEKResponse struct {
	TenantID   string `codec:"tenant_id"`
	OldVersion uint32 `codec:"old_version"`
	NewVersion uint32 `codec:"new_version"`
	Timestamp  int64  `codec:"timestamp"`
}

// TenantGetDEKStatusRequest represents a request to get tenant DEK status
type TenantGetDEKStatusRequest struct {
	TenantID string `codec:"tenant_id"`
}

// QUICTenantDEKStatusResponse represents a response containing tenant DEK status
type QUICTenantDEKStatusResponse struct {
	TenantID       string  `codec:"tenant_id"`
	Path           string  `codec:"path"`
	Algorithm      string  `codec:"algorithm"`
	Version        uint64  `codec:"version"`
	Status         string  `codec:"status"`
	IsDefault      bool    `codec:"is_default"`
	CreatedAt      int64   `codec:"created_at"`
	RotatedAt      int64   `codec:"rotated_at,omitempty"`
	UsageCount     uint64  `codec:"usage_count"`
	BytesUsed      uint64  `codec:"bytes_used"`
	MaxUsageCount  uint64  `codec:"max_usage_count"`
	MaxBytesUsed   uint64  `codec:"max_bytes_used"`
	WarningPercent int32   `codec:"warning_percent"`
	UsagePercent   float64 `codec:"usage_percent"`
	NeedsRotation  bool    `codec:"needs_rotation"`
	Timestamp      int64   `codec:"timestamp"`
}

// =============================================================================
// Service Handler Extension
// =============================================================================

// WithQUICTenantManager sets the tenant manager for the QUIC handler
func WithQUICTenantManager(mgr TenantManagerInterface) QUICServiceHandlerOption {
	return func(h *QUICServiceHandler) {
		h.tenantManager = mgr
	}
}

// SetTenantManager sets the tenant manager after construction
func (h *QUICServiceHandler) SetTenantManager(mgr TenantManagerInterface) {
	h.tenantManager = mgr
}

// =============================================================================
// Handler Implementation
// =============================================================================

// handleTenantOperation routes tenant operations to their handlers
func (h *QUICServiceHandler) handleTenantOperation(ctx context.Context, req *quic.Request) *quic.Response {
	if h.tenantManager == nil {
		return h.errorResponse(quic.StatusUnavailable, ErrQUICServiceUnavailable{Service: "tenant"})
	}

	switch req.Opcode {
	case OpTenantList:
		return h.handleTenantList(ctx, req)
	case OpTenantGet:
		return h.handleTenantGet(ctx, req)
	case OpTenantGetByName:
		return h.handleTenantGetByName(ctx, req)
	case OpTenantCreate:
		return h.handleTenantCreate(ctx, req)
	case OpTenantUpdate:
		return h.handleTenantUpdate(ctx, req)
	case OpTenantDelete:
		return h.handleTenantDelete(ctx, req)
	case OpTenantSuspend:
		return h.handleTenantSuspend(ctx, req)
	case OpTenantResume:
		return h.handleTenantResume(ctx, req)
	case OpTenantGetQuotas:
		return h.handleTenantGetQuotas(ctx, req)
	case OpTenantUpdateQuotas:
		return h.handleTenantUpdateQuotas(ctx, req)
	case OpTenantGetUsage:
		return h.handleTenantGetUsage(ctx, req)
	case OpTenantCheckQuota:
		return h.handleTenantCheckQuota(ctx, req)
	case OpTenantValidateVLAN:
		return h.handleTenantValidateVLAN(ctx, req)
	case OpTenantGetBridge:
		return h.handleTenantGetBridge(ctx, req)
	case OpTenantSync:
		return h.handleTenantSync(ctx, req)
	case OpTenantRotateDEK:
		return h.handleTenantRotateDEK(ctx, req)
	case OpTenantGetDEKStatus:
		return h.handleTenantGetDEKStatus(ctx, req)
	default:
		return h.errorResponse(quic.StatusNotImplemented, ErrQUICUnknownOpcode{Opcode: req.Opcode})
	}
}

// handleTenantList handles the list tenants operation
func (h *QUICServiceHandler) handleTenantList(ctx context.Context, req *quic.Request) *quic.Response {
	var listReq TenantListRequest
	if len(req.Payload) > 0 {
		if err := quic.DecodePayload(req.Payload, &listReq); err != nil {
			return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
		}
	}

	// Apply defaults
	limit := listReq.Limit
	if limit <= 0 {
		limit = 100
	}
	offset := listReq.Offset
	if offset < 0 {
		offset = 0
	}

	tenants, total, err := h.tenantManager.ListTenants(ctx, limit, offset)
	if err != nil {
		h.logger.Error(err, "failed to list tenants")
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "TenantList", Cause: err})
	}

	tenantResponses := make([]*QUICTenantResponse, 0, len(tenants))
	for _, t := range tenants {
		tenantResponses = append(tenantResponses, convertTenantEntityToResponse(t))
	}

	resp := &TenantListResponse{
		Tenants:   tenantResponses,
		Total:     total,
		Limit:     limit,
		Offset:    offset,
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

// handleTenantGet handles the get tenant by ID operation
func (h *QUICServiceHandler) handleTenantGet(ctx context.Context, req *quic.Request) *quic.Response {
	var getReq TenantGetRequest
	if err := quic.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if getReq.TenantID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "tenant_id"})
	}

	tenantEntity, err := h.tenantManager.GetTenant(ctx, getReq.TenantID)
	if err != nil {
		h.logger.Error(err, "failed to get tenant", "tenant_id", getReq.TenantID)
		return h.errorResponse(quic.StatusNotFound, ErrTenantNotFound(getReq))
	}

	resp := &TenantGetResponse{
		Tenant:    convertTenantEntityToResponse(tenantEntity),
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

// handleTenantGetByName handles the get tenant by name operation
func (h *QUICServiceHandler) handleTenantGetByName(ctx context.Context, req *quic.Request) *quic.Response {
	var getReq TenantGetByNameRequest
	if err := quic.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if getReq.Name == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "name"})
	}

	tenantEntity, err := h.tenantManager.GetTenantByName(ctx, getReq.Name)
	if err != nil {
		h.logger.Error(err, "failed to get tenant by name", "name", getReq.Name)
		return h.errorResponse(quic.StatusNotFound, ErrTenantNotFoundByName(getReq))
	}

	resp := &TenantGetResponse{
		Tenant:    convertTenantEntityToResponse(tenantEntity),
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

// handleTenantCreate handles the create tenant operation
func (h *QUICServiceHandler) handleTenantCreate(ctx context.Context, req *quic.Request) *quic.Response {
	var createReq TenantCreateRequest
	if err := quic.DecodePayload(req.Payload, &createReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if createReq.Name == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "name"})
	}

	// Convert request to internal format
	internalReq := &tenant.CreateTenantRequest{
		Name:        createReq.Name,
		DisplayName: createReq.DisplayName,
		Labels:      createReq.Labels,
		Annotations: createReq.Annotations,
	}

	// Set VLAN range if provided
	if createReq.VLANStart > 0 && createReq.VLANEnd > 0 {
		internalReq.VLANRange = &tenant.VLANRange{
			Start: createReq.VLANStart,
			End:   createReq.VLANEnd,
		}
	}

	// Set quotas if provided
	if createReq.ComputeQuota != nil {
		internalReq.ComputeQuota = &tenant.ComputeQuota{
			MaxVMs:        createReq.ComputeQuota.MaxVMs,
			MaxContainers: createReq.ComputeQuota.MaxContainers,
			MaxVCPUs:      createReq.ComputeQuota.MaxVCPUs,
			MaxMemoryMB:   createReq.ComputeQuota.MaxMemoryMB,
			MaxDiskGB:     createReq.ComputeQuota.MaxDiskGB,
		}
	}
	if createReq.NetworkQuota != nil {
		internalReq.NetworkQuota = &tenant.NetworkQuota{
			MaxBridges:       createReq.NetworkQuota.MaxBridges,
			MaxPorts:         createReq.NetworkQuota.MaxPorts,
			MaxBandwidthMbps: createReq.NetworkQuota.MaxBandwidthMbps,
		}
	}
	if createReq.StorageQuota != nil {
		internalReq.StorageQuota = &tenant.StorageQuota{
			MaxVolumesGB: createReq.StorageQuota.MaxVolumesGB,
			MaxSnapshots: createReq.StorageQuota.MaxSnapshots,
		}
	}

	tenantEntity, err := h.tenantManager.CreateTenant(ctx, internalReq)
	if err != nil {
		h.logger.Error(err, "failed to create tenant", "name", createReq.Name)
		return h.errorResponse(quic.StatusInternalError, ErrTenantCreateFailed{Name: createReq.Name, Cause: err})
	}

	resp := &TenantCreateResponse{
		Tenant:    convertTenantEntityToResponse(tenantEntity),
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("created tenant",
		"tenant_id", tenantEntity.ID,
		"name", createReq.Name)

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleTenantUpdate handles the update tenant operation
func (h *QUICServiceHandler) handleTenantUpdate(ctx context.Context, req *quic.Request) *quic.Response {
	var updateReq TenantUpdateRequest
	if err := quic.DecodePayload(req.Payload, &updateReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if updateReq.TenantID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "tenant_id"})
	}

	// Convert request to internal format
	internalReq := &tenant.UpdateTenantRequest{
		Labels:      updateReq.Labels,
		Annotations: updateReq.Annotations,
	}
	if updateReq.DisplayName != "" {
		internalReq.DisplayName = &updateReq.DisplayName
	}

	tenantEntity, err := h.tenantManager.UpdateTenant(ctx, updateReq.TenantID, internalReq)
	if err != nil {
		h.logger.Error(err, "failed to update tenant", "tenant_id", updateReq.TenantID)
		return h.errorResponse(quic.StatusInternalError, ErrTenantUpdateFailed{TenantID: updateReq.TenantID, Cause: err})
	}

	resp := &TenantUpdateResponse{
		Tenant:    convertTenantEntityToResponse(tenantEntity),
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("updated tenant", "tenant_id", updateReq.TenantID)

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleTenantDelete handles the delete tenant operation
func (h *QUICServiceHandler) handleTenantDelete(ctx context.Context, req *quic.Request) *quic.Response {
	var deleteReq TenantDeleteRequest
	if err := quic.DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if deleteReq.TenantID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "tenant_id"})
	}

	if err := h.tenantManager.DeleteTenant(ctx, deleteReq.TenantID); err != nil {
		h.logger.Error(err, "failed to delete tenant", "tenant_id", deleteReq.TenantID)
		return h.errorResponse(quic.StatusInternalError, ErrTenantDeleteFailed{TenantID: deleteReq.TenantID, Cause: err})
	}

	resp := &TenantDeleteResponse{
		TenantID:  deleteReq.TenantID,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("deleted tenant", "tenant_id", deleteReq.TenantID)

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleTenantSuspend handles the suspend tenant operation
func (h *QUICServiceHandler) handleTenantSuspend(ctx context.Context, req *quic.Request) *quic.Response {
	var suspendReq TenantSuspendRequest
	if err := quic.DecodePayload(req.Payload, &suspendReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if suspendReq.TenantID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "tenant_id"})
	}

	if err := h.tenantManager.SuspendTenant(ctx, suspendReq.TenantID); err != nil {
		h.logger.Error(err, "failed to suspend tenant", "tenant_id", suspendReq.TenantID)
		return h.errorResponse(quic.StatusInternalError, ErrTenantSuspendFailed{TenantID: suspendReq.TenantID, Cause: err})
	}

	resp := &TenantSuspendResponse{
		TenantID:  suspendReq.TenantID,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Warn("suspended tenant", "tenant_id", suspendReq.TenantID)

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleTenantResume handles the resume tenant operation
func (h *QUICServiceHandler) handleTenantResume(ctx context.Context, req *quic.Request) *quic.Response {
	var resumeReq TenantResumeRequest
	if err := quic.DecodePayload(req.Payload, &resumeReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if resumeReq.TenantID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "tenant_id"})
	}

	if err := h.tenantManager.ResumeTenant(ctx, resumeReq.TenantID); err != nil {
		h.logger.Error(err, "failed to resume tenant", "tenant_id", resumeReq.TenantID)
		return h.errorResponse(quic.StatusInternalError, ErrTenantResumeFailed{TenantID: resumeReq.TenantID, Cause: err})
	}

	resp := &TenantResumeResponse{
		TenantID:  resumeReq.TenantID,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("resumed tenant", "tenant_id", resumeReq.TenantID)

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleTenantGetQuotas handles the get quotas operation
func (h *QUICServiceHandler) handleTenantGetQuotas(ctx context.Context, req *quic.Request) *quic.Response {
	var quotasReq TenantQuotasRequest
	if err := quic.DecodePayload(req.Payload, &quotasReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if quotasReq.TenantID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "tenant_id"})
	}

	quotas, err := h.tenantManager.GetQuotas(ctx, quotasReq.TenantID)
	if err != nil {
		h.logger.Error(err, "failed to get tenant quotas", "tenant_id", quotasReq.TenantID)
		return h.errorResponse(quic.StatusNotFound, ErrTenantNotFound(quotasReq))
	}

	resp := &TenantQuotasResponse{
		TenantID: quotasReq.TenantID,
		ComputeQuota: &ComputeQuotaDTO{
			MaxVMs:         quotas.Compute.MaxVMs,
			MaxContainers:  quotas.Compute.MaxContainers,
			MaxVCPUs:       quotas.Compute.MaxVCPUs,
			MaxMemoryMB:    quotas.Compute.MaxMemoryMB,
			MaxDiskGB:      quotas.Compute.MaxDiskGB,
			UsedVMs:        quotas.Compute.UsedVMs,
			UsedContainers: quotas.Compute.UsedContainers,
			UsedVCPUs:      quotas.Compute.UsedVCPUs,
			UsedMemoryMB:   quotas.Compute.UsedMemoryMB,
			UsedDiskGB:     quotas.Compute.UsedDiskGB,
		},
		NetworkQuota: &NetworkQuotaDTO{
			MaxBridges:       quotas.Network.MaxBridges,
			MaxPorts:         quotas.Network.MaxPorts,
			MaxBandwidthMbps: quotas.Network.MaxBandwidthMbps,
			UsedBridges:      quotas.Network.UsedBridges,
			UsedPorts:        quotas.Network.UsedPorts,
		},
		StorageQuota: &StorageQuotaDTO{
			MaxVolumesGB:  quotas.Storage.MaxVolumesGB,
			MaxSnapshots:  quotas.Storage.MaxSnapshots,
			UsedVolumesGB: quotas.Storage.UsedVolumesGB,
			UsedSnapshots: quotas.Storage.UsedSnapshots,
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

// handleTenantUpdateQuotas handles the update quotas operation
func (h *QUICServiceHandler) handleTenantUpdateQuotas(ctx context.Context, req *quic.Request) *quic.Response {
	var updateReq TenantUpdateQuotasRequest
	if err := quic.DecodePayload(req.Payload, &updateReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if updateReq.TenantID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "tenant_id"})
	}

	// Build internal quotas
	quotas := &tenant.TenantQuotas{}

	if updateReq.ComputeQuota != nil {
		quotas.Compute = tenant.ComputeQuota{
			MaxVMs:        updateReq.ComputeQuota.MaxVMs,
			MaxContainers: updateReq.ComputeQuota.MaxContainers,
			MaxVCPUs:      updateReq.ComputeQuota.MaxVCPUs,
			MaxMemoryMB:   updateReq.ComputeQuota.MaxMemoryMB,
			MaxDiskGB:     updateReq.ComputeQuota.MaxDiskGB,
		}
	}
	if updateReq.NetworkQuota != nil {
		quotas.Network = tenant.NetworkQuota{
			MaxBridges:       updateReq.NetworkQuota.MaxBridges,
			MaxPorts:         updateReq.NetworkQuota.MaxPorts,
			MaxBandwidthMbps: updateReq.NetworkQuota.MaxBandwidthMbps,
		}
	}
	if updateReq.StorageQuota != nil {
		quotas.Storage = tenant.StorageQuota{
			MaxVolumesGB: updateReq.StorageQuota.MaxVolumesGB,
			MaxSnapshots: updateReq.StorageQuota.MaxSnapshots,
		}
	}

	if err := h.tenantManager.UpdateQuotas(ctx, updateReq.TenantID, quotas); err != nil {
		h.logger.Error(err, "failed to update tenant quotas", "tenant_id", updateReq.TenantID)
		return h.errorResponse(quic.StatusInternalError, ErrTenantQuotaUpdateFailed{TenantID: updateReq.TenantID, Cause: err})
	}

	resp := &TenantUpdateQuotasResponse{
		TenantID:  updateReq.TenantID,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("updated tenant quotas", "tenant_id", updateReq.TenantID)

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleTenantGetUsage handles the get usage operation
func (h *QUICServiceHandler) handleTenantGetUsage(ctx context.Context, req *quic.Request) *quic.Response {
	var usageReq TenantUsageRequest
	if err := quic.DecodePayload(req.Payload, &usageReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if usageReq.TenantID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "tenant_id"})
	}

	usage, err := h.tenantManager.GetUsage(ctx, usageReq.TenantID)
	if err != nil {
		h.logger.Error(err, "failed to get tenant usage", "tenant_id", usageReq.TenantID)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "TenantGetUsage", Cause: err})
	}

	resp := &TenantUsageResponse{
		TenantID:      usageReq.TenantID,
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
		Timestamp:     time.Now().Unix(),
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

// handleTenantCheckQuota handles the check quota operation
func (h *QUICServiceHandler) handleTenantCheckQuota(ctx context.Context, req *quic.Request) *quic.Response {
	var checkReq TenantCheckQuotaRequest
	if err := quic.DecodePayload(req.Payload, &checkReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if checkReq.TenantID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "tenant_id"})
	}
	if checkReq.Resource == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "resource"})
	}
	if checkReq.Amount <= 0 {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "amount"})
	}

	resourceType := quota.ResourceType(checkReq.Resource)
	err := h.tenantManager.CheckQuota(ctx, checkReq.TenantID, resourceType, checkReq.Amount)

	resp := &TenantCheckQuotaResponse{
		TenantID:  checkReq.TenantID,
		Resource:  checkReq.Resource,
		Amount:    checkReq.Amount,
		Available: err == nil,
		Timestamp: time.Now().Unix(),
	}

	if err != nil {
		resp.Message = err.Error()
	}

	payload, encodeErr := quic.EncodePayload(resp)
	if encodeErr != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: encodeErr})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleTenantValidateVLAN handles the validate VLAN operation
func (h *QUICServiceHandler) handleTenantValidateVLAN(ctx context.Context, req *quic.Request) *quic.Response {
	var vlanReq TenantValidateVLANRequest
	if err := quic.DecodePayload(req.Payload, &vlanReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if vlanReq.TenantID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "tenant_id"})
	}
	if vlanReq.VLANID == 0 {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "vlan_id"})
	}

	err := h.tenantManager.ValidateVLAN(ctx, vlanReq.TenantID, vlanReq.VLANID)

	resp := &TenantValidateVLANResponse{
		TenantID:  vlanReq.TenantID,
		VLANID:    vlanReq.VLANID,
		Valid:     err == nil,
		Timestamp: time.Now().Unix(),
	}

	if err != nil {
		resp.Message = err.Error()
	}

	payload, encodeErr := quic.EncodePayload(resp)
	if encodeErr != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: encodeErr})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleTenantGetBridge handles the get bridge name operation
func (h *QUICServiceHandler) handleTenantGetBridge(ctx context.Context, req *quic.Request) *quic.Response {
	var bridgeReq TenantGetBridgeRequest
	if err := quic.DecodePayload(req.Payload, &bridgeReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if bridgeReq.TenantID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "tenant_id"})
	}

	bridgeName, err := h.tenantManager.GetBridgeName(ctx, bridgeReq.TenantID)
	if err != nil {
		h.logger.Error(err, "failed to get tenant bridge name", "tenant_id", bridgeReq.TenantID)
		return h.errorResponse(quic.StatusNotFound, ErrTenantBridgeNotFound(bridgeReq))
	}

	resp := &TenantGetBridgeResponse{
		TenantID:   bridgeReq.TenantID,
		BridgeName: bridgeName,
		Timestamp:  time.Now().Unix(),
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

// handleTenantSync handles the sync operation
func (h *QUICServiceHandler) handleTenantSync(ctx context.Context, req *quic.Request) *quic.Response {
	if err := h.tenantManager.Sync(ctx); err != nil {
		h.logger.Error(err, "failed to sync tenant manager")
		return h.errorResponse(quic.StatusInternalError, ErrTenantSyncFailed{Cause: err})
	}

	resp := &TenantSyncResponse{
		Success:   true,
		Message:   "tenant state synchronized successfully",
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("tenant manager state synchronized")

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleTenantRotateDEK handles the rotate DEK operation
func (h *QUICServiceHandler) handleTenantRotateDEK(ctx context.Context, req *quic.Request) *quic.Response {
	var rotateReq TenantRotateDEKRequest
	if err := quic.DecodePayload(req.Payload, &rotateReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if rotateReq.TenantID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "tenant_id"})
	}

	result, err := h.tenantManager.RotateDEK(ctx, rotateReq.TenantID, rotateReq.Background)
	if err != nil {
		h.logger.Error(err, "failed to rotate tenant DEK", "tenant_id", rotateReq.TenantID)
		return h.errorResponse(quic.StatusInternalError, ErrTenantDEKRotationFailed{TenantID: rotateReq.TenantID, Cause: err})
	}

	resp := &TenantRotateDEKResponse{
		TenantID:   rotateReq.TenantID,
		OldVersion: result.OldVersion,
		NewVersion: result.NewVersion,
		Timestamp:  time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("rotated tenant DEK",
		"tenant_id", rotateReq.TenantID,
		"old_version", result.OldVersion,
		"new_version", result.NewVersion)

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleTenantGetDEKStatus handles the get DEK status operation
func (h *QUICServiceHandler) handleTenantGetDEKStatus(ctx context.Context, req *quic.Request) *quic.Response {
	var statusReq TenantGetDEKStatusRequest
	if err := quic.DecodePayload(req.Payload, &statusReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if statusReq.TenantID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "tenant_id"})
	}

	status, err := h.tenantManager.GetDEKStatus(ctx, statusReq.TenantID)
	if err != nil {
		h.logger.Error(err, "failed to get tenant DEK status", "tenant_id", statusReq.TenantID)
		return h.errorResponse(quic.StatusNotFound, ErrTenantDEKNotFound(statusReq))
	}

	resp := &QUICTenantDEKStatusResponse{
		TenantID:       statusReq.TenantID,
		Path:           status.Path,
		Algorithm:      status.Algorithm,
		Version:        status.Version,
		Status:         status.Status,
		IsDefault:      status.IsDefault,
		CreatedAt:      status.CreatedAt.Unix(),
		UsageCount:     status.UsageCount,
		BytesUsed:      status.BytesUsed,
		MaxUsageCount:  status.MaxUsageCount,
		MaxBytesUsed:   status.MaxBytesUsed,
		WarningPercent: status.WarningPercent,
		UsagePercent:   status.UsagePercent,
		NeedsRotation:  status.NeedsRotation,
		Timestamp:      time.Now().Unix(),
	}

	if !status.RotatedAt.IsZero() {
		resp.RotatedAt = status.RotatedAt.Unix()
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

// =============================================================================
// Conversion Helpers
// =============================================================================

// convertTenantEntityToResponse converts a tenant.TenantEntity to a QUICTenantResponse
func convertTenantEntityToResponse(entity *tenant.TenantEntity) *QUICTenantResponse {
	if entity == nil {
		return nil
	}

	resp := &QUICTenantResponse{
		ID:          entity.ID,
		Name:        entity.Name,
		DisplayName: entity.DisplayName,
		State:       string(entity.State),
		OVSBridge:   entity.OVSBridge,
		VLANStart:   entity.VLANRange.Start,
		VLANEnd:     entity.VLANRange.End,
		DEKPath:     entity.DEKPath,
		DEKHandle:   entity.DEKHandle(), // Deprecated: for backward compatibility
		Labels:      entity.Labels,
		Annotations: entity.Annotations,
		CreatedAt:   entity.CreatedAt.Unix(),
		UpdatedAt:   entity.UpdatedAt.Unix(),
		Timestamp:   time.Now().Unix(),
	}

	// Convert quotas
	resp.ComputeQuota = &ComputeQuotaDTO{
		MaxVMs:         entity.ComputeQuota.MaxVMs,
		MaxContainers:  entity.ComputeQuota.MaxContainers,
		MaxVCPUs:       entity.ComputeQuota.MaxVCPUs,
		MaxMemoryMB:    entity.ComputeQuota.MaxMemoryMB,
		MaxDiskGB:      entity.ComputeQuota.MaxDiskGB,
		UsedVMs:        entity.ComputeQuota.UsedVMs,
		UsedContainers: entity.ComputeQuota.UsedContainers,
		UsedVCPUs:      entity.ComputeQuota.UsedVCPUs,
		UsedMemoryMB:   entity.ComputeQuota.UsedMemoryMB,
		UsedDiskGB:     entity.ComputeQuota.UsedDiskGB,
	}

	resp.NetworkQuota = &NetworkQuotaDTO{
		MaxBridges:       entity.NetworkQuota.MaxBridges,
		MaxPorts:         entity.NetworkQuota.MaxPorts,
		MaxBandwidthMbps: entity.NetworkQuota.MaxBandwidthMbps,
		UsedBridges:      entity.NetworkQuota.UsedBridges,
		UsedPorts:        entity.NetworkQuota.UsedPorts,
	}

	resp.StorageQuota = &StorageQuotaDTO{
		MaxVolumesGB:  entity.StorageQuota.MaxVolumesGB,
		MaxSnapshots:  entity.StorageQuota.MaxSnapshots,
		UsedVolumesGB: entity.StorageQuota.UsedVolumesGB,
		UsedSnapshots: entity.StorageQuota.UsedSnapshots,
	}

	return resp
}

// =============================================================================
// Tenant-specific Error Types
// =============================================================================

// ErrTenantNotFound is returned when a tenant is not found
type ErrTenantNotFound struct {
	TenantID string
}

func (e ErrTenantNotFound) Error() string {
	return "tenant not found: " + e.TenantID
}

// ErrTenantNotFoundByName is returned when a tenant is not found by name
type ErrTenantNotFoundByName struct {
	Name string
}

func (e ErrTenantNotFoundByName) Error() string {
	return "tenant not found with name: " + e.Name
}

// ErrTenantCreateFailed is returned when tenant creation fails
type ErrTenantCreateFailed struct {
	Name  string
	Cause error
}

func (e ErrTenantCreateFailed) Error() string {
	return "tenant creation failed for " + e.Name + ": " + e.Cause.Error()
}

func (e ErrTenantCreateFailed) Unwrap() error {
	return e.Cause
}

// ErrTenantUpdateFailed is returned when tenant update fails
type ErrTenantUpdateFailed struct {
	TenantID string
	Cause    error
}

func (e ErrTenantUpdateFailed) Error() string {
	return "tenant update failed for " + e.TenantID + ": " + e.Cause.Error()
}

func (e ErrTenantUpdateFailed) Unwrap() error {
	return e.Cause
}

// ErrTenantDeleteFailed is returned when tenant deletion fails
type ErrTenantDeleteFailed struct {
	TenantID string
	Cause    error
}

func (e ErrTenantDeleteFailed) Error() string {
	return "tenant deletion failed for " + e.TenantID + ": " + e.Cause.Error()
}

func (e ErrTenantDeleteFailed) Unwrap() error {
	return e.Cause
}

// ErrTenantSuspendFailed is returned when tenant suspension fails
type ErrTenantSuspendFailed struct {
	TenantID string
	Cause    error
}

func (e ErrTenantSuspendFailed) Error() string {
	return "tenant suspension failed for " + e.TenantID + ": " + e.Cause.Error()
}

func (e ErrTenantSuspendFailed) Unwrap() error {
	return e.Cause
}

// ErrTenantResumeFailed is returned when tenant resume fails
type ErrTenantResumeFailed struct {
	TenantID string
	Cause    error
}

func (e ErrTenantResumeFailed) Error() string {
	return "tenant resume failed for " + e.TenantID + ": " + e.Cause.Error()
}

func (e ErrTenantResumeFailed) Unwrap() error {
	return e.Cause
}

// ErrTenantQuotaUpdateFailed is returned when quota update fails
type ErrTenantQuotaUpdateFailed struct {
	TenantID string
	Cause    error
}

func (e ErrTenantQuotaUpdateFailed) Error() string {
	return "tenant quota update failed for " + e.TenantID + ": " + e.Cause.Error()
}

func (e ErrTenantQuotaUpdateFailed) Unwrap() error {
	return e.Cause
}

// ErrTenantBridgeNotFound is returned when tenant bridge is not found
type ErrTenantBridgeNotFound struct {
	TenantID string
}

func (e ErrTenantBridgeNotFound) Error() string {
	return "tenant bridge not found for: " + e.TenantID
}

// ErrTenantSyncFailed is returned when tenant sync fails
type ErrTenantSyncFailed struct {
	Cause error
}

func (e ErrTenantSyncFailed) Error() string {
	return "tenant sync failed: " + e.Cause.Error()
}

func (e ErrTenantSyncFailed) Unwrap() error {
	return e.Cause
}

// ErrTenantDEKRotationFailed is returned when DEK rotation fails
type ErrTenantDEKRotationFailed struct {
	TenantID string
	Cause    error
}

func (e ErrTenantDEKRotationFailed) Error() string {
	return "tenant DEK rotation failed for " + e.TenantID + ": " + e.Cause.Error()
}

func (e ErrTenantDEKRotationFailed) Unwrap() error {
	return e.Cause
}

// ErrTenantDEKNotFound is returned when tenant DEK is not found
type ErrTenantDEKNotFound struct {
	TenantID string
}

func (e ErrTenantDEKNotFound) Error() string {
	return "tenant DEK not found for: " + e.TenantID
}
