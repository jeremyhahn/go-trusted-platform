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
	"errors"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant/quota"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TenantGRPCService implements gRPC service for multi-tenant platform operations.
// It exposes 15 operations for complete tenant lifecycle management including
// VLAN isolation, OVS bridge management, quota enforcement, and state synchronization.
type TenantGRPCService struct {
	logger  *logging.Logger
	manager *tenant.Manager
}

// TenantGRPCServiceOption is a functional option for configuring TenantGRPCService.
type TenantGRPCServiceOption func(*TenantGRPCService)

// WithTenantManagerGRPC sets the tenant manager for the gRPC service.
func WithTenantManagerGRPC(manager *tenant.Manager) TenantGRPCServiceOption {
	return func(s *TenantGRPCService) {
		s.manager = manager
	}
}

// WithTenantLoggerGRPC sets the logger for the gRPC service.
func WithTenantLoggerGRPC(logger *logging.Logger) TenantGRPCServiceOption {
	return func(s *TenantGRPCService) {
		s.logger = logger
	}
}

// NewTenantGRPCService creates a new TenantGRPCService with the provided options.
func NewTenantGRPCService(opts ...TenantGRPCServiceOption) *TenantGRPCService {
	svc := &TenantGRPCService{}
	for _, opt := range opts {
		opt(svc)
	}
	if svc.logger == nil {
		svc.logger = logging.DefaultLogger()
	}
	return svc
}

// SetManager sets the tenant manager (useful for late initialization).
func (s *TenantGRPCService) SetManager(manager *tenant.Manager) {
	s.manager = manager
}

// =============================================================================
// Request/Response Types
// =============================================================================

// ListTenantsRequest contains parameters for listing tenants.
type ListTenantsRequest struct {
	Limit  int32 `json:"limit"`
	Offset int32 `json:"offset"`
}

// ListTenantsResponse contains the list of tenants.
type ListTenantsResponse struct {
	Tenants []*TenantInfo `json:"tenants"`
	Total   int32         `json:"total"`
}

// GetTenantRequest contains the tenant ID to retrieve.
type GetTenantRequest struct {
	TenantID string `json:"tenant_id"`
}

// GetTenantByNameRequest contains the tenant name to retrieve.
type GetTenantByNameRequest struct {
	Name string `json:"name"`
}

// TenantResponse contains a single tenant.
type TenantResponse struct {
	Tenant *TenantInfo `json:"tenant"`
}

// CreateTenantRequest contains parameters for creating a tenant.
type CreateTenantRequest struct {
	Name           string            `json:"name"`
	DisplayName    string            `json:"display_name"`
	VLANRangeStart uint16            `json:"vlan_range_start,omitempty"`
	VLANRangeEnd   uint16            `json:"vlan_range_end,omitempty"`
	Labels         map[string]string `json:"labels,omitempty"`
	Annotations    map[string]string `json:"annotations,omitempty"`
	ComputeQuota   *ComputeQuotaInfo `json:"compute_quota,omitempty"`
	NetworkQuota   *NetworkQuotaInfo `json:"network_quota,omitempty"`
	StorageQuota   *StorageQuotaInfo `json:"storage_quota,omitempty"`
}

// UpdateTenantRequest contains parameters for updating a tenant.
type UpdateTenantRequest struct {
	TenantID    string            `json:"tenant_id"`
	DisplayName string            `json:"display_name,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// DeleteTenantRequest contains the tenant ID to delete.
type DeleteTenantRequest struct {
	TenantID string `json:"tenant_id"`
}

// SuspendTenantRequest contains the tenant ID to suspend.
type SuspendTenantRequest struct {
	TenantID string `json:"tenant_id"`
}

// ResumeTenantRequest contains the tenant ID to resume.
type ResumeTenantRequest struct {
	TenantID string `json:"tenant_id"`
}

// GetQuotasRequest contains the tenant ID to get quotas for.
type GetQuotasRequest struct {
	TenantID string `json:"tenant_id"`
}

// QuotasResponse contains the tenant quotas.
type QuotasResponse struct {
	TenantID string            `json:"tenant_id"`
	Compute  *ComputeQuotaInfo `json:"compute"`
	Network  *NetworkQuotaInfo `json:"network"`
	Storage  *StorageQuotaInfo `json:"storage"`
}

// UpdateQuotasRequest contains parameters for updating quotas.
type UpdateQuotasRequest struct {
	TenantID string            `json:"tenant_id"`
	Compute  *ComputeQuotaInfo `json:"compute"`
	Network  *NetworkQuotaInfo `json:"network"`
	Storage  *StorageQuotaInfo `json:"storage"`
}

// GetUsageRequest contains the tenant ID to get usage for.
type GetUsageRequest struct {
	TenantID string `json:"tenant_id"`
}

// UsageResponse contains the tenant resource usage.
type UsageResponse struct {
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

// CheckQuotaRequest contains parameters for checking quota availability.
type CheckQuotaRequest struct {
	TenantID string `json:"tenant_id"`
	Resource string `json:"resource"`
	Amount   int64  `json:"amount"`
}

// CheckQuotaResponse contains the quota check result.
type CheckQuotaResponse struct {
	TenantID  string `json:"tenant_id"`
	Resource  string `json:"resource"`
	Amount    int64  `json:"amount"`
	Available bool   `json:"available"`
	Message   string `json:"message,omitempty"`
}

// ValidateVLANRequest contains parameters for VLAN validation.
type ValidateVLANRequest struct {
	TenantID string `json:"tenant_id"`
	VLANID   uint16 `json:"vlan_id"`
}

// ValidateVLANResponse contains the VLAN validation result.
type ValidateVLANResponse struct {
	TenantID string `json:"tenant_id"`
	VLANID   uint16 `json:"vlan_id"`
	Valid    bool   `json:"valid"`
	Message  string `json:"message,omitempty"`
}

// GetBridgeNameRequest contains the tenant ID to get bridge name for.
type GetBridgeNameRequest struct {
	TenantID string `json:"tenant_id"`
}

// GetBridgeNameResponse contains the OVS bridge name.
type GetBridgeNameResponse struct {
	TenantID   string `json:"tenant_id"`
	BridgeName string `json:"bridge_name"`
}

// SyncRequest contains parameters for state synchronization.
type SyncRequest struct{}

// SyncResponse contains the synchronization result.
type SyncResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// OperationStatusResponse is a generic status response for operations.
type OperationStatusResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// RotateTenantDEKRequest contains parameters for rotating a tenant's DEK.
type RotateTenantDEKRequest struct {
	TenantID   string `json:"tenant_id"`
	Background bool   `json:"background"`
}

// RotateTenantDEKResponse contains the DEK rotation result.
type RotateTenantDEKResponse struct {
	TenantID   string    `json:"tenant_id"`
	OldVersion uint32    `json:"old_version"`
	NewVersion uint32    `json:"new_version"`
	Timestamp  time.Time `json:"timestamp"`
}

// GetTenantDEKStatusRequest contains the tenant ID to get DEK status for.
type GetTenantDEKStatusRequest struct {
	TenantID string `json:"tenant_id"`
}

// TenantDEKStatusResponse contains the DEK status for a tenant.
type TenantDEKStatusResponse struct {
	TenantID          string                         `json:"tenant_id"`
	Path              string                         `json:"path"`
	Version           uint64                         `json:"version"`
	Algorithm         string                         `json:"algorithm"`
	Status            string                         `json:"status"`
	IsDefault         bool                           `json:"is_default"`
	CreatedAt         time.Time                      `json:"created_at"`
	RotatedAt         time.Time                      `json:"rotated_at"`
	UsageCount        uint64                         `json:"usage_count"`
	BytesUsed         uint64                         `json:"bytes_used"`
	MaxUsageCount     uint64                         `json:"max_usage_count"`
	MaxBytesUsed      uint64                         `json:"max_bytes_used"`
	WarningPercent    int32                          `json:"warning_percent"`
	UsagePercent      float64                        `json:"usage_percent"`
	NeedsRotation     bool                           `json:"needs_rotation"`
	ReencryptProgress *TenantDEKReencryptionProgress `json:"reencrypt_progress,omitempty"`
}

// TenantDEKReencryptionProgress contains re-encryption progress information.
type TenantDEKReencryptionProgress struct {
	InProgress          bool      `json:"in_progress"`
	TotalKeys           int32     `json:"total_keys"`
	ProcessedKeys       int32     `json:"processed_keys"`
	FailedKeys          int32     `json:"failed_keys"`
	StartedAt           time.Time `json:"started_at"`
	EstimatedCompletion time.Time `json:"estimated_completion"`
}

// TenantInfo represents tenant information returned by the service.
type TenantInfo struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	DisplayName  string            `json:"display_name"`
	State        string            `json:"state"`
	OVSBridge    string            `json:"ovs_bridge,omitempty"`
	VLANStart    uint16            `json:"vlan_start,omitempty"`
	VLANEnd      uint16            `json:"vlan_end,omitempty"`
	DEKPath      string            `json:"dek_path,omitempty"`
	DEKHandle    uint32            `json:"dek_handle,omitempty"` // Deprecated: use DEKPath
	ComputeQuota *ComputeQuotaInfo `json:"compute_quota,omitempty"`
	NetworkQuota *NetworkQuotaInfo `json:"network_quota,omitempty"`
	StorageQuota *StorageQuotaInfo `json:"storage_quota,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
	Annotations  map[string]string `json:"annotations,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
}

// ComputeQuotaInfo represents compute resource quotas.
type ComputeQuotaInfo struct {
	MaxVMs        int64 `json:"max_vms"`
	MaxContainers int64 `json:"max_containers"`
	MaxVCPUs      int64 `json:"max_vcpus"`
	MaxMemoryMB   int64 `json:"max_memory_mb"`
}

// NetworkQuotaInfo represents network resource quotas.
type NetworkQuotaInfo struct {
	MaxBridges       int64 `json:"max_bridges"`
	MaxPorts         int64 `json:"max_ports"`
	MaxBandwidthMbps int64 `json:"max_bandwidth_mbps"`
}

// StorageQuotaInfo represents storage resource quotas.
type StorageQuotaInfo struct {
	MaxVolumesGB int64 `json:"max_volumes_gb"`
	MaxSnapshots int64 `json:"max_snapshots"`
}

// =============================================================================
// gRPC Service Methods
// =============================================================================

// ListTenants lists all tenants with pagination.
func (s *TenantGRPCService) ListTenants(ctx context.Context, req *ListTenantsRequest) (*ListTenantsResponse, error) {
	if s.manager == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant manager not initialized")
	}

	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}

	limit := int(req.Limit)
	if limit <= 0 {
		limit = 100
	}

	offset := int(req.Offset)
	if offset < 0 {
		offset = 0
	}

	entities, total, err := s.manager.ListTenants(ctx, limit, offset)
	if err != nil {
		s.logger.Error(err, "failed to list tenants")
		return nil, s.toGRPCError(err)
	}

	tenants := make([]*TenantInfo, 0, len(entities))
	for _, entity := range entities {
		tenants = append(tenants, s.entityToTenantInfo(entity))
	}

	return &ListTenantsResponse{
		Tenants: tenants,
		Total:   int32(total),
	}, nil
}

// GetTenant retrieves a tenant by ID.
func (s *TenantGRPCService) GetTenant(ctx context.Context, req *GetTenantRequest) (*TenantResponse, error) {
	if s.manager == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant manager not initialized")
	}

	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}

	if req.TenantID == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}

	entity, err := s.manager.GetTenant(ctx, req.TenantID)
	if err != nil {
		s.logger.Error(err, "failed to get tenant", "tenant_id", req.TenantID)
		return nil, s.toGRPCError(err)
	}

	return &TenantResponse{
		Tenant: s.entityToTenantInfo(entity),
	}, nil
}

// GetTenantByName retrieves a tenant by name.
func (s *TenantGRPCService) GetTenantByName(ctx context.Context, req *GetTenantByNameRequest) (*TenantResponse, error) {
	if s.manager == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant manager not initialized")
	}

	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}

	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}

	entity, err := s.manager.GetTenantByName(ctx, req.Name)
	if err != nil {
		s.logger.Error(err, "failed to get tenant by name", "name", req.Name)
		return nil, s.toGRPCError(err)
	}

	return &TenantResponse{
		Tenant: s.entityToTenantInfo(entity),
	}, nil
}

// CreateTenant creates a new tenant.
func (s *TenantGRPCService) CreateTenant(ctx context.Context, req *CreateTenantRequest) (*TenantResponse, error) {
	if s.manager == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant manager not initialized")
	}

	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}

	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}

	createReq := &tenant.CreateTenantRequest{
		Name:        req.Name,
		DisplayName: req.DisplayName,
		Labels:      req.Labels,
		Annotations: req.Annotations,
	}

	// Set VLAN range if provided
	if req.VLANRangeStart > 0 && req.VLANRangeEnd > 0 {
		createReq.VLANRange = &tenant.VLANRange{
			Start: req.VLANRangeStart,
			End:   req.VLANRangeEnd,
		}
	}

	// Set quotas if provided
	if req.ComputeQuota != nil {
		createReq.ComputeQuota = &tenant.ComputeQuota{
			MaxVMs:        req.ComputeQuota.MaxVMs,
			MaxContainers: req.ComputeQuota.MaxContainers,
			MaxVCPUs:      req.ComputeQuota.MaxVCPUs,
			MaxMemoryMB:   req.ComputeQuota.MaxMemoryMB,
		}
	}

	if req.NetworkQuota != nil {
		createReq.NetworkQuota = &tenant.NetworkQuota{
			MaxBridges:       req.NetworkQuota.MaxBridges,
			MaxPorts:         req.NetworkQuota.MaxPorts,
			MaxBandwidthMbps: req.NetworkQuota.MaxBandwidthMbps,
		}
	}

	if req.StorageQuota != nil {
		createReq.StorageQuota = &tenant.StorageQuota{
			MaxVolumesGB: req.StorageQuota.MaxVolumesGB,
			MaxSnapshots: req.StorageQuota.MaxSnapshots,
		}
	}

	entity, err := s.manager.CreateTenant(ctx, createReq)
	if err != nil {
		s.logger.Error(err, "failed to create tenant", "name", req.Name)
		return nil, s.toGRPCError(err)
	}

	return &TenantResponse{
		Tenant: s.entityToTenantInfo(entity),
	}, nil
}

// UpdateTenant updates tenant metadata.
func (s *TenantGRPCService) UpdateTenant(ctx context.Context, req *UpdateTenantRequest) (*TenantResponse, error) {
	if s.manager == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant manager not initialized")
	}

	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}

	if req.TenantID == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}

	updateReq := &tenant.UpdateTenantRequest{
		Labels:      req.Labels,
		Annotations: req.Annotations,
	}

	if req.DisplayName != "" {
		updateReq.DisplayName = &req.DisplayName
	}

	entity, err := s.manager.UpdateTenant(ctx, req.TenantID, updateReq)
	if err != nil {
		s.logger.Error(err, "failed to update tenant", "tenant_id", req.TenantID)
		return nil, s.toGRPCError(err)
	}

	return &TenantResponse{
		Tenant: s.entityToTenantInfo(entity),
	}, nil
}

// DeleteTenant deletes a tenant and all its resources.
func (s *TenantGRPCService) DeleteTenant(ctx context.Context, req *DeleteTenantRequest) (*OperationStatusResponse, error) {
	if s.manager == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant manager not initialized")
	}

	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}

	if req.TenantID == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}

	err := s.manager.DeleteTenant(ctx, req.TenantID)
	if err != nil {
		s.logger.Error(err, "failed to delete tenant", "tenant_id", req.TenantID)
		return nil, s.toGRPCError(err)
	}

	return &OperationStatusResponse{
		Success: true,
		Message: "tenant deleted successfully",
	}, nil
}

// SuspendTenant suspends a tenant (blocks traffic).
func (s *TenantGRPCService) SuspendTenant(ctx context.Context, req *SuspendTenantRequest) (*OperationStatusResponse, error) {
	if s.manager == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant manager not initialized")
	}

	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}

	if req.TenantID == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}

	err := s.manager.SuspendTenant(ctx, req.TenantID)
	if err != nil {
		s.logger.Error(err, "failed to suspend tenant", "tenant_id", req.TenantID)
		return nil, s.toGRPCError(err)
	}

	return &OperationStatusResponse{
		Success: true,
		Message: "tenant suspended successfully",
	}, nil
}

// ResumeTenant resumes a suspended tenant.
func (s *TenantGRPCService) ResumeTenant(ctx context.Context, req *ResumeTenantRequest) (*OperationStatusResponse, error) {
	if s.manager == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant manager not initialized")
	}

	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}

	if req.TenantID == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}

	err := s.manager.ResumeTenant(ctx, req.TenantID)
	if err != nil {
		s.logger.Error(err, "failed to resume tenant", "tenant_id", req.TenantID)
		return nil, s.toGRPCError(err)
	}

	return &OperationStatusResponse{
		Success: true,
		Message: "tenant resumed successfully",
	}, nil
}

// GetQuotas returns tenant quotas.
func (s *TenantGRPCService) GetQuotas(ctx context.Context, req *GetQuotasRequest) (*QuotasResponse, error) {
	if s.manager == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant manager not initialized")
	}

	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}

	if req.TenantID == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}

	quotas, err := s.manager.GetQuotas(ctx, req.TenantID)
	if err != nil {
		s.logger.Error(err, "failed to get quotas", "tenant_id", req.TenantID)
		return nil, s.toGRPCError(err)
	}

	return &QuotasResponse{
		TenantID: req.TenantID,
		Compute: &ComputeQuotaInfo{
			MaxVMs:        quotas.Compute.MaxVMs,
			MaxContainers: quotas.Compute.MaxContainers,
			MaxVCPUs:      quotas.Compute.MaxVCPUs,
			MaxMemoryMB:   quotas.Compute.MaxMemoryMB,
		},
		Network: &NetworkQuotaInfo{
			MaxBridges:       quotas.Network.MaxBridges,
			MaxPorts:         quotas.Network.MaxPorts,
			MaxBandwidthMbps: quotas.Network.MaxBandwidthMbps,
		},
		Storage: &StorageQuotaInfo{
			MaxVolumesGB: quotas.Storage.MaxVolumesGB,
			MaxSnapshots: quotas.Storage.MaxSnapshots,
		},
	}, nil
}

// UpdateQuotas updates tenant quotas.
func (s *TenantGRPCService) UpdateQuotas(ctx context.Context, req *UpdateQuotasRequest) (*OperationStatusResponse, error) {
	if s.manager == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant manager not initialized")
	}

	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}

	if req.TenantID == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}

	quotas := &tenant.TenantQuotas{}

	if req.Compute != nil {
		quotas.Compute = tenant.ComputeQuota{
			MaxVMs:        req.Compute.MaxVMs,
			MaxContainers: req.Compute.MaxContainers,
			MaxVCPUs:      req.Compute.MaxVCPUs,
			MaxMemoryMB:   req.Compute.MaxMemoryMB,
		}
	}

	if req.Network != nil {
		quotas.Network = tenant.NetworkQuota{
			MaxBridges:       req.Network.MaxBridges,
			MaxPorts:         req.Network.MaxPorts,
			MaxBandwidthMbps: req.Network.MaxBandwidthMbps,
		}
	}

	if req.Storage != nil {
		quotas.Storage = tenant.StorageQuota{
			MaxVolumesGB: req.Storage.MaxVolumesGB,
			MaxSnapshots: req.Storage.MaxSnapshots,
		}
	}

	err := s.manager.UpdateQuotas(ctx, req.TenantID, quotas)
	if err != nil {
		s.logger.Error(err, "failed to update quotas", "tenant_id", req.TenantID)
		return nil, s.toGRPCError(err)
	}

	return &OperationStatusResponse{
		Success: true,
		Message: "quotas updated successfully",
	}, nil
}

// GetUsage returns tenant resource usage.
func (s *TenantGRPCService) GetUsage(ctx context.Context, req *GetUsageRequest) (*UsageResponse, error) {
	if s.manager == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant manager not initialized")
	}

	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}

	if req.TenantID == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}

	usage, err := s.manager.GetUsage(ctx, req.TenantID)
	if err != nil {
		s.logger.Error(err, "failed to get usage", "tenant_id", req.TenantID)
		return nil, s.toGRPCError(err)
	}

	return &UsageResponse{
		TenantID:      req.TenantID,
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
		Timestamp:     usage.Timestamp,
	}, nil
}

// CheckQuota checks if a resource request can be fulfilled.
func (s *TenantGRPCService) CheckQuota(ctx context.Context, req *CheckQuotaRequest) (*CheckQuotaResponse, error) {
	if s.manager == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant manager not initialized")
	}

	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}

	if req.TenantID == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}

	if req.Resource == "" {
		return nil, status.Error(codes.InvalidArgument, "resource is required")
	}

	if req.Amount <= 0 {
		return nil, status.Error(codes.InvalidArgument, "amount must be positive")
	}

	resourceType := quota.ResourceType(req.Resource)
	if !resourceType.IsValid() {
		return nil, status.Error(codes.InvalidArgument, "invalid resource type: "+req.Resource)
	}

	err := s.manager.CheckQuota(ctx, req.TenantID, resourceType, req.Amount)

	response := &CheckQuotaResponse{
		TenantID: req.TenantID,
		Resource: req.Resource,
		Amount:   req.Amount,
	}

	if err != nil {
		response.Available = false
		response.Message = err.Error()
	} else {
		response.Available = true
		response.Message = "quota available"
	}

	return response, nil
}

// ValidateVLAN checks if a tenant can use a specific VLAN.
func (s *TenantGRPCService) ValidateVLAN(ctx context.Context, req *ValidateVLANRequest) (*ValidateVLANResponse, error) {
	if s.manager == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant manager not initialized")
	}

	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}

	if req.TenantID == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}

	if req.VLANID == 0 {
		return nil, status.Error(codes.InvalidArgument, "vlan_id is required")
	}

	if req.VLANID > 4094 {
		return nil, status.Error(codes.InvalidArgument, "vlan_id must be between 1 and 4094")
	}

	err := s.manager.ValidateVLAN(ctx, req.TenantID, req.VLANID)

	response := &ValidateVLANResponse{
		TenantID: req.TenantID,
		VLANID:   req.VLANID,
	}

	if err != nil {
		response.Valid = false
		response.Message = err.Error()
	} else {
		response.Valid = true
		response.Message = "VLAN is valid for tenant"
	}

	return response, nil
}

// GetBridgeName returns the OVS bridge name for a tenant.
func (s *TenantGRPCService) GetBridgeName(ctx context.Context, req *GetBridgeNameRequest) (*GetBridgeNameResponse, error) {
	if s.manager == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant manager not initialized")
	}

	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}

	if req.TenantID == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}

	bridgeName, err := s.manager.GetBridgeName(ctx, req.TenantID)
	if err != nil {
		s.logger.Error(err, "failed to get bridge name", "tenant_id", req.TenantID)
		return nil, s.toGRPCError(err)
	}

	return &GetBridgeNameResponse{
		TenantID:   req.TenantID,
		BridgeName: bridgeName,
	}, nil
}

// Sync synchronizes tenant manager state with external systems.
func (s *TenantGRPCService) Sync(ctx context.Context, req *SyncRequest) (*SyncResponse, error) {
	if s.manager == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant manager not initialized")
	}

	err := s.manager.Sync(ctx)
	if err != nil {
		s.logger.Error(err, "failed to sync tenant manager")
		return &SyncResponse{
			Success: false,
			Message: "sync completed with errors: " + err.Error(),
		}, nil
	}

	return &SyncResponse{
		Success: true,
		Message: "sync completed successfully",
	}, nil
}

// RotateTenantDEK rotates the DEK for a tenant.
func (s *TenantGRPCService) RotateTenantDEK(ctx context.Context, req *RotateTenantDEKRequest) (*RotateTenantDEKResponse, error) {
	if s.manager == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant manager not initialized")
	}

	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}

	if req.TenantID == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}

	result, err := s.manager.RotateTenantDEKWithOptions(ctx, req.TenantID, req.Background)
	if err != nil {
		s.logger.Error(err, "failed to rotate tenant DEK", "tenant_id", req.TenantID)
		return nil, s.toGRPCError(err)
	}

	return &RotateTenantDEKResponse{
		TenantID:   result.TenantID,
		OldVersion: result.OldVersion,
		NewVersion: result.NewVersion,
		Timestamp:  result.Timestamp,
	}, nil
}

// GetTenantDEKStatus gets the DEK status for a tenant.
func (s *TenantGRPCService) GetTenantDEKStatus(ctx context.Context, req *GetTenantDEKStatusRequest) (*TenantDEKStatusResponse, error) {
	if s.manager == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant manager not initialized")
	}

	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}

	if req.TenantID == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}

	dekStatus, err := s.manager.GetTenantDEKStatus(ctx, req.TenantID)
	if err != nil {
		s.logger.Error(err, "failed to get tenant DEK status", "tenant_id", req.TenantID)
		return nil, s.toGRPCError(err)
	}

	response := &TenantDEKStatusResponse{
		TenantID:       req.TenantID,
		Path:           dekStatus.Path,
		Version:        dekStatus.Version,
		Algorithm:      dekStatus.Algorithm,
		Status:         dekStatus.Status,
		IsDefault:      dekStatus.IsDefault,
		CreatedAt:      dekStatus.CreatedAt,
		RotatedAt:      dekStatus.RotatedAt,
		UsageCount:     dekStatus.UsageCount,
		BytesUsed:      dekStatus.BytesUsed,
		MaxUsageCount:  dekStatus.MaxUsageCount,
		MaxBytesUsed:   dekStatus.MaxBytesUsed,
		WarningPercent: dekStatus.WarningPercent,
		UsagePercent:   dekStatus.UsagePercent,
		NeedsRotation:  dekStatus.NeedsRotation,
	}

	if dekStatus.ReencryptProgress != nil {
		response.ReencryptProgress = &TenantDEKReencryptionProgress{
			InProgress:          dekStatus.ReencryptProgress.InProgress,
			TotalKeys:           dekStatus.ReencryptProgress.TotalKeys,
			ProcessedKeys:       dekStatus.ReencryptProgress.ProcessedKeys,
			FailedKeys:          dekStatus.ReencryptProgress.FailedKeys,
			StartedAt:           dekStatus.ReencryptProgress.StartedAt,
			EstimatedCompletion: dekStatus.ReencryptProgress.EstimatedCompletion,
		}
	}

	return response, nil
}

// =============================================================================
// Helper Methods
// =============================================================================

// entityToTenantInfo converts a TenantEntity to TenantInfo for the response.
func (s *TenantGRPCService) entityToTenantInfo(entity *tenant.TenantEntity) *TenantInfo {
	if entity == nil {
		return nil
	}

	info := &TenantInfo{
		ID:          entity.ID,
		Name:        entity.Name,
		DisplayName: entity.DisplayName,
		State:       entity.State.String(),
		OVSBridge:   entity.OVSBridge,
		VLANStart:   entity.VLANRange.Start,
		VLANEnd:     entity.VLANRange.End,
		DEKPath:     entity.DEKPath,
		DEKHandle:   entity.DEKHandle(), // Deprecated: for backward compatibility
		Labels:      entity.Labels,
		Annotations: entity.Annotations,
		CreatedAt:   entity.CreatedAt,
		UpdatedAt:   entity.UpdatedAt,
		ComputeQuota: &ComputeQuotaInfo{
			MaxVMs:        entity.ComputeQuota.MaxVMs,
			MaxContainers: entity.ComputeQuota.MaxContainers,
			MaxVCPUs:      entity.ComputeQuota.MaxVCPUs,
			MaxMemoryMB:   entity.ComputeQuota.MaxMemoryMB,
		},
		NetworkQuota: &NetworkQuotaInfo{
			MaxBridges:       entity.NetworkQuota.MaxBridges,
			MaxPorts:         entity.NetworkQuota.MaxPorts,
			MaxBandwidthMbps: entity.NetworkQuota.MaxBandwidthMbps,
		},
		StorageQuota: &StorageQuotaInfo{
			MaxVolumesGB: entity.StorageQuota.MaxVolumesGB,
			MaxSnapshots: entity.StorageQuota.MaxSnapshots,
		},
	}

	return info
}

// toGRPCError converts tenant package errors to gRPC status errors.
func (s *TenantGRPCService) toGRPCError(err error) error {
	if err == nil {
		return nil
	}

	// Check for specific error types and map to appropriate gRPC codes
	var tenantNotFound tenant.ErrTenantNotFound
	if errors.As(err, &tenantNotFound) {
		return status.Error(codes.NotFound, err.Error())
	}

	var tenantExists tenant.ErrTenantExists
	if errors.As(err, &tenantExists) {
		return status.Error(codes.AlreadyExists, err.Error())
	}

	var invalidRequest tenant.ErrInvalidRequest
	if errors.As(err, &invalidRequest) {
		return status.Error(codes.InvalidArgument, err.Error())
	}

	var invalidState tenant.ErrInvalidState
	if errors.As(err, &invalidState) {
		return status.Error(codes.FailedPrecondition, err.Error())
	}

	var invalidTransition tenant.ErrInvalidTransition
	if errors.As(err, &invalidTransition) {
		return status.Error(codes.FailedPrecondition, err.Error())
	}

	var storageFailed tenant.ErrStorageFailed
	if errors.As(err, &storageFailed) {
		return status.Error(codes.Internal, err.Error())
	}

	var bridgeFailed tenant.ErrBridgeOperationFailed
	if errors.As(err, &bridgeFailed) {
		return status.Error(codes.Internal, err.Error())
	}

	var vlanFailed tenant.ErrVLANAllocationFailed
	if errors.As(err, &vlanFailed) {
		return status.Error(codes.ResourceExhausted, err.Error())
	}

	var quotaExceeded tenant.ErrQuotaExceeded
	if errors.As(err, &quotaExceeded) {
		return status.Error(codes.ResourceExhausted, err.Error())
	}

	var invalidVLAN tenant.ErrInvalidVLANRange
	if errors.As(err, &invalidVLAN) {
		return status.Error(codes.InvalidArgument, err.Error())
	}

	var dekFailed tenant.ErrDEKOperationFailed
	if errors.As(err, &dekFailed) {
		return status.Error(codes.Internal, err.Error())
	}

	var configValidation tenant.ErrConfigValidation
	if errors.As(err, &configValidation) {
		return status.Error(codes.InvalidArgument, err.Error())
	}

	// Default to internal error for unknown error types
	return status.Error(codes.Internal, err.Error())
}
