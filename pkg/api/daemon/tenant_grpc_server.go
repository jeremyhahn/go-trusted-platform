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
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant/quota"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TenantGRPCServer implements the gRPC TenantService.
// It delegates all operations to the tenant.Manager for business logic.
type TenantGRPCServer struct {
	platformv1.UnimplementedTenantServiceServer

	manager *tenant.Manager
	logger  *slog.Logger
}

// TenantGRPCServerOption is a functional option for configuring TenantGRPCServer.
type TenantGRPCServerOption func(*TenantGRPCServer)

// WithTenantManager sets the tenant manager for the gRPC server.
func WithTenantManager(manager *tenant.Manager) TenantGRPCServerOption {
	return func(s *TenantGRPCServer) {
		s.manager = manager
	}
}

// WithTenantLogger sets the logger for the gRPC server.
func WithTenantLogger(logger *slog.Logger) TenantGRPCServerOption {
	return func(s *TenantGRPCServer) {
		s.logger = logger
	}
}

// NewTenantGRPCServer creates a new TenantGRPCServer with the provided options.
func NewTenantGRPCServer(opts ...TenantGRPCServerOption) *TenantGRPCServer {
	svc := &TenantGRPCServer{}
	for _, opt := range opts {
		opt(svc)
	}
	if svc.logger == nil {
		svc.logger = slog.Default()
	}
	return svc
}

// SetManager sets the tenant manager (useful for late initialization).
func (s *TenantGRPCServer) SetManager(manager *tenant.Manager) {
	s.manager = manager
}

// =============================================================================
// Tenant CRUD Operations
// =============================================================================

// ListTenants lists all tenants with pagination.
func (s *TenantGRPCServer) ListTenants(
	ctx context.Context,
	req *platformv1.ListTenantsRequest,
) (*platformv1.ListTenantsResponse, error) {
	if s.manager == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant manager not initialized")
	}

	limit := int(req.GetLimit())
	if limit <= 0 {
		limit = 100
	}

	offset := int(req.GetOffset())
	if offset < 0 {
		offset = 0
	}

	entities, total, err := s.manager.ListTenants(ctx, limit, offset)
	if err != nil {
		s.logger.Error("failed to list tenants", "error", err)
		return nil, s.toGRPCError(err)
	}

	tenants := make([]*platformv1.Tenant, 0, len(entities))
	for _, entity := range entities {
		tenants = append(tenants, s.entityToTenantPb(entity))
	}

	return &platformv1.ListTenantsResponse{
		Tenants: tenants,
		Total:   int32(total),
	}, nil
}

// GetTenant retrieves a tenant by ID.
func (s *TenantGRPCServer) GetTenant(
	ctx context.Context,
	req *platformv1.GetTenantRequest,
) (*platformv1.GetTenantResponse, error) {
	if s.manager == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant manager not initialized")
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}

	entity, err := s.manager.GetTenant(ctx, req.GetTenantId())
	if err != nil {
		s.logger.Error("failed to get tenant", "tenant_id", req.GetTenantId(), "error", err)
		return nil, s.toGRPCError(err)
	}

	return &platformv1.GetTenantResponse{
		Tenant: s.entityToTenantPb(entity),
	}, nil
}

// GetTenantByName retrieves a tenant by name.
func (s *TenantGRPCServer) GetTenantByName(
	ctx context.Context,
	req *platformv1.GetTenantByNameRequest,
) (*platformv1.GetTenantByNameResponse, error) {
	if s.manager == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant manager not initialized")
	}

	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}

	entity, err := s.manager.GetTenantByName(ctx, req.GetName())
	if err != nil {
		s.logger.Error("failed to get tenant by name", "name", req.GetName(), "error", err)
		return nil, s.toGRPCError(err)
	}

	return &platformv1.GetTenantByNameResponse{
		Tenant: s.entityToTenantPb(entity),
	}, nil
}

// CreateTenant creates a new tenant.
func (s *TenantGRPCServer) CreateTenant(
	ctx context.Context,
	req *platformv1.CreateTenantRequest,
) (*platformv1.CreateTenantResponse, error) {
	if s.manager == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant manager not initialized")
	}

	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}

	createReq := &tenant.CreateTenantRequest{
		Name:        req.GetName(),
		DisplayName: req.GetDisplayName(),
		Labels:      req.GetLabels(),
		Annotations: req.GetAnnotations(),
	}

	// Set VLAN range if provided
	if req.GetVlanRangeStart() > 0 && req.GetVlanRangeEnd() > 0 {
		createReq.VLANRange = &tenant.VLANRange{
			Start: uint16(req.GetVlanRangeStart()),
			End:   uint16(req.GetVlanRangeEnd()),
		}
	}

	// Set quotas if provided
	if req.GetComputeQuota() != nil {
		createReq.ComputeQuota = &tenant.ComputeQuota{
			MaxVMs:        req.GetComputeQuota().GetMaxVms(),
			MaxContainers: req.GetComputeQuota().GetMaxContainers(),
			MaxVCPUs:      req.GetComputeQuota().GetMaxVcpus(),
			MaxMemoryMB:   req.GetComputeQuota().GetMaxMemoryMb(),
		}
	}

	if req.GetNetworkQuota() != nil {
		createReq.NetworkQuota = &tenant.NetworkQuota{
			MaxBridges:       req.GetNetworkQuota().GetMaxBridges(),
			MaxPorts:         req.GetNetworkQuota().GetMaxPorts(),
			MaxBandwidthMbps: req.GetNetworkQuota().GetMaxBandwidthMbps(),
		}
	}

	if req.GetStorageQuota() != nil {
		createReq.StorageQuota = &tenant.StorageQuota{
			MaxVolumesGB: req.GetStorageQuota().GetMaxVolumesGb(),
			MaxSnapshots: req.GetStorageQuota().GetMaxSnapshots(),
		}
	}

	entity, err := s.manager.CreateTenant(ctx, createReq)
	if err != nil {
		s.logger.Error("failed to create tenant", "name", req.GetName(), "error", err)
		return nil, s.toGRPCError(err)
	}

	s.logger.Info("tenant created", "id", entity.ID, "name", entity.Name)

	return &platformv1.CreateTenantResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "tenant created successfully",
		},
		Tenant: s.entityToTenantPb(entity),
	}, nil
}

// UpdateTenant updates tenant metadata.
func (s *TenantGRPCServer) UpdateTenant(
	ctx context.Context,
	req *platformv1.UpdateTenantRequest,
) (*platformv1.UpdateTenantResponse, error) {
	if s.manager == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant manager not initialized")
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}

	updateReq := &tenant.UpdateTenantRequest{
		Labels:      req.GetLabels(),
		Annotations: req.GetAnnotations(),
	}

	if req.GetDisplayName() != "" {
		displayName := req.GetDisplayName()
		updateReq.DisplayName = &displayName
	}

	entity, err := s.manager.UpdateTenant(ctx, req.GetTenantId(), updateReq)
	if err != nil {
		s.logger.Error("failed to update tenant", "tenant_id", req.GetTenantId(), "error", err)
		return nil, s.toGRPCError(err)
	}

	s.logger.Info("tenant updated", "id", entity.ID)

	return &platformv1.UpdateTenantResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "tenant updated successfully",
		},
		Tenant: s.entityToTenantPb(entity),
	}, nil
}

// DeleteTenant deletes a tenant and all its resources.
func (s *TenantGRPCServer) DeleteTenant(
	ctx context.Context,
	req *platformv1.DeleteTenantRequest,
) (*platformv1.DeleteTenantResponse, error) {
	if s.manager == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant manager not initialized")
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}

	err := s.manager.DeleteTenant(ctx, req.GetTenantId())
	if err != nil {
		s.logger.Error("failed to delete tenant", "tenant_id", req.GetTenantId(), "error", err)
		return nil, s.toGRPCError(err)
	}

	s.logger.Info("tenant deleted", "id", req.GetTenantId())

	return &platformv1.DeleteTenantResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "tenant deleted successfully",
		},
	}, nil
}

// =============================================================================
// Tenant Lifecycle Operations
// =============================================================================

// SuspendTenant suspends a tenant (blocks traffic).
func (s *TenantGRPCServer) SuspendTenant(
	ctx context.Context,
	req *platformv1.SuspendTenantRequest,
) (*platformv1.SuspendTenantResponse, error) {
	if s.manager == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant manager not initialized")
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}

	err := s.manager.SuspendTenant(ctx, req.GetTenantId())
	if err != nil {
		s.logger.Error("failed to suspend tenant", "tenant_id", req.GetTenantId(), "error", err)
		return nil, s.toGRPCError(err)
	}

	s.logger.Info("tenant suspended", "id", req.GetTenantId())

	return &platformv1.SuspendTenantResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "tenant suspended successfully",
		},
	}, nil
}

// ResumeTenant resumes a suspended tenant.
func (s *TenantGRPCServer) ResumeTenant(
	ctx context.Context,
	req *platformv1.ResumeTenantRequest,
) (*platformv1.ResumeTenantResponse, error) {
	if s.manager == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant manager not initialized")
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}

	err := s.manager.ResumeTenant(ctx, req.GetTenantId())
	if err != nil {
		s.logger.Error("failed to resume tenant", "tenant_id", req.GetTenantId(), "error", err)
		return nil, s.toGRPCError(err)
	}

	s.logger.Info("tenant resumed", "id", req.GetTenantId())

	return &platformv1.ResumeTenantResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "tenant resumed successfully",
		},
	}, nil
}

// =============================================================================
// Quota Management
// =============================================================================

// GetQuotas returns tenant quotas.
func (s *TenantGRPCServer) GetQuotas(
	ctx context.Context,
	req *platformv1.GetQuotasRequest,
) (*platformv1.GetQuotasResponse, error) {
	if s.manager == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant manager not initialized")
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}

	quotas, err := s.manager.GetQuotas(ctx, req.GetTenantId())
	if err != nil {
		s.logger.Error("failed to get quotas", "tenant_id", req.GetTenantId(), "error", err)
		return nil, s.toGRPCError(err)
	}

	return &platformv1.GetQuotasResponse{
		TenantId: req.GetTenantId(),
		Compute: &platformv1.ComputeQuota{
			MaxVms:        quotas.Compute.MaxVMs,
			MaxContainers: quotas.Compute.MaxContainers,
			MaxVcpus:      quotas.Compute.MaxVCPUs,
			MaxMemoryMb:   quotas.Compute.MaxMemoryMB,
		},
		Network: &platformv1.NetworkQuota{
			MaxBridges:       quotas.Network.MaxBridges,
			MaxPorts:         quotas.Network.MaxPorts,
			MaxBandwidthMbps: quotas.Network.MaxBandwidthMbps,
		},
		Storage: &platformv1.StorageQuota{
			MaxVolumesGb: quotas.Storage.MaxVolumesGB,
			MaxSnapshots: quotas.Storage.MaxSnapshots,
		},
	}, nil
}

// UpdateQuotas updates tenant quotas.
func (s *TenantGRPCServer) UpdateQuotas(
	ctx context.Context,
	req *platformv1.UpdateQuotasRequest,
) (*platformv1.UpdateQuotasResponse, error) {
	if s.manager == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant manager not initialized")
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}

	quotas := &tenant.TenantQuotas{}

	if req.GetCompute() != nil {
		quotas.Compute = tenant.ComputeQuota{
			MaxVMs:        req.GetCompute().GetMaxVms(),
			MaxContainers: req.GetCompute().GetMaxContainers(),
			MaxVCPUs:      req.GetCompute().GetMaxVcpus(),
			MaxMemoryMB:   req.GetCompute().GetMaxMemoryMb(),
		}
	}

	if req.GetNetwork() != nil {
		quotas.Network = tenant.NetworkQuota{
			MaxBridges:       req.GetNetwork().GetMaxBridges(),
			MaxPorts:         req.GetNetwork().GetMaxPorts(),
			MaxBandwidthMbps: req.GetNetwork().GetMaxBandwidthMbps(),
		}
	}

	if req.GetStorage() != nil {
		quotas.Storage = tenant.StorageQuota{
			MaxVolumesGB: req.GetStorage().GetMaxVolumesGb(),
			MaxSnapshots: req.GetStorage().GetMaxSnapshots(),
		}
	}

	err := s.manager.UpdateQuotas(ctx, req.GetTenantId(), quotas)
	if err != nil {
		s.logger.Error("failed to update quotas", "tenant_id", req.GetTenantId(), "error", err)
		return nil, s.toGRPCError(err)
	}

	s.logger.Info("quotas updated", "tenant_id", req.GetTenantId())

	return &platformv1.UpdateQuotasResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "quotas updated successfully",
		},
	}, nil
}

// GetUsage returns tenant resource usage.
func (s *TenantGRPCServer) GetUsage(
	ctx context.Context,
	req *platformv1.GetUsageRequest,
) (*platformv1.GetUsageResponse, error) {
	if s.manager == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant manager not initialized")
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}

	usage, err := s.manager.GetUsage(ctx, req.GetTenantId())
	if err != nil {
		s.logger.Error("failed to get usage", "tenant_id", req.GetTenantId(), "error", err)
		return nil, s.toGRPCError(err)
	}

	return &platformv1.GetUsageResponse{
		Usage: &platformv1.TenantUsage{
			TenantId:      req.GetTenantId(),
			Vms:           usage.VMs,
			Containers:    usage.Containers,
			Vcpus:         usage.VCPUs,
			MemoryMb:      usage.MemoryMB,
			DiskGb:        usage.DiskGB,
			Bridges:       usage.Bridges,
			Ports:         usage.Ports,
			BandwidthMbps: usage.BandwidthMbps,
			Volumes:       usage.Volumes,
			Snapshots:     usage.Snapshots,
			Timestamp:     timestamppb.New(usage.Timestamp),
		},
	}, nil
}

// CheckQuota checks if a resource request can be fulfilled.
func (s *TenantGRPCServer) CheckQuota(
	ctx context.Context,
	req *platformv1.CheckQuotaRequest,
) (*platformv1.CheckQuotaResponse, error) {
	if s.manager == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant manager not initialized")
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}

	if req.GetResource() == "" {
		return nil, status.Error(codes.InvalidArgument, "resource is required")
	}

	if req.GetAmount() <= 0 {
		return nil, status.Error(codes.InvalidArgument, "amount must be positive")
	}

	resourceType := quota.ResourceType(req.GetResource())
	if !resourceType.IsValid() {
		return nil, status.Error(codes.InvalidArgument, "invalid resource type: "+req.GetResource())
	}

	err := s.manager.CheckQuota(ctx, req.GetTenantId(), resourceType, req.GetAmount())

	response := &platformv1.CheckQuotaResponse{
		TenantId: req.GetTenantId(),
		Resource: req.GetResource(),
		Amount:   req.GetAmount(),
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

// =============================================================================
// Network Isolation
// =============================================================================

// ValidateVLAN checks if a tenant can use a specific VLAN.
func (s *TenantGRPCServer) ValidateVLAN(
	ctx context.Context,
	req *platformv1.ValidateVLANRequest,
) (*platformv1.ValidateVLANResponse, error) {
	if s.manager == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant manager not initialized")
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}

	if req.GetVlanId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "vlan_id is required")
	}

	if req.GetVlanId() > 4094 {
		return nil, status.Error(codes.InvalidArgument, "vlan_id must be between 1 and 4094")
	}

	err := s.manager.ValidateVLAN(ctx, req.GetTenantId(), uint16(req.GetVlanId()))

	response := &platformv1.ValidateVLANResponse{
		TenantId: req.GetTenantId(),
		VlanId:   req.GetVlanId(),
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
func (s *TenantGRPCServer) GetBridgeName(
	ctx context.Context,
	req *platformv1.GetBridgeNameRequest,
) (*platformv1.GetBridgeNameResponse, error) {
	if s.manager == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant manager not initialized")
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}

	bridgeName, err := s.manager.GetBridgeName(ctx, req.GetTenantId())
	if err != nil {
		s.logger.Error("failed to get bridge name", "tenant_id", req.GetTenantId(), "error", err)
		return nil, s.toGRPCError(err)
	}

	return &platformv1.GetBridgeNameResponse{
		TenantId:   req.GetTenantId(),
		BridgeName: bridgeName,
	}, nil
}

// =============================================================================
// State Synchronization
// =============================================================================

// Sync synchronizes tenant manager state with external systems.
func (s *TenantGRPCServer) Sync(
	ctx context.Context,
	req *platformv1.SyncTenantsRequest,
) (*platformv1.SyncTenantsResponse, error) {
	if s.manager == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant manager not initialized")
	}

	err := s.manager.Sync(ctx)
	if err != nil {
		s.logger.Error("failed to sync tenant manager", "error", err)
		return &platformv1.SyncTenantsResponse{
			Status: &platformv1.Status{
				Success: false,
				Message: "sync completed with errors: " + err.Error(),
			},
		}, nil
	}

	return &platformv1.SyncTenantsResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "sync completed successfully",
		},
	}, nil
}

// =============================================================================
// DEK Management
// =============================================================================

// RotateTenantDEK rotates the DEK for a tenant.
func (s *TenantGRPCServer) RotateTenantDEK(
	ctx context.Context,
	req *platformv1.RotateTenantDEKRequest,
) (*platformv1.RotateTenantDEKResponse, error) {
	if s.manager == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant manager not initialized")
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}

	result, err := s.manager.RotateTenantDEKWithOptions(ctx, req.GetTenantId(), req.GetBackground())
	if err != nil {
		s.logger.Error("failed to rotate tenant DEK", "tenant_id", req.GetTenantId(), "error", err)
		return nil, s.toGRPCError(err)
	}

	s.logger.Info("tenant DEK rotated", "tenant_id", req.GetTenantId(), "new_version", result.NewVersion)

	return &platformv1.RotateTenantDEKResponse{
		TenantId:   result.TenantID,
		OldVersion: result.OldVersion,
		NewVersion: result.NewVersion,
		Timestamp:  timestamppb.New(result.Timestamp),
	}, nil
}

// GetTenantDEKStatus gets the DEK status for a tenant.
func (s *TenantGRPCServer) GetTenantDEKStatus(
	ctx context.Context,
	req *platformv1.GetTenantDEKStatusRequest,
) (*platformv1.GetTenantDEKStatusResponse, error) {
	if s.manager == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant manager not initialized")
	}

	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}

	dekStatus, err := s.manager.GetTenantDEKStatus(ctx, req.GetTenantId())
	if err != nil {
		s.logger.Error("failed to get tenant DEK status", "tenant_id", req.GetTenantId(), "error", err)
		return nil, s.toGRPCError(err)
	}

	response := &platformv1.GetTenantDEKStatusResponse{
		DekStatus: &platformv1.TenantDEKStatus{
			TenantId:       req.GetTenantId(),
			Path:           dekStatus.Path,
			Version:        dekStatus.Version,
			Algorithm:      dekStatus.Algorithm,
			Status:         dekStatus.Status,
			IsDefault:      dekStatus.IsDefault,
			CreatedAt:      timestamppb.New(dekStatus.CreatedAt),
			RotatedAt:      timestamppb.New(dekStatus.RotatedAt),
			UsageCount:     dekStatus.UsageCount,
			BytesUsed:      dekStatus.BytesUsed,
			MaxUsageCount:  dekStatus.MaxUsageCount,
			MaxBytesUsed:   dekStatus.MaxBytesUsed,
			WarningPercent: dekStatus.WarningPercent,
			UsagePercent:   dekStatus.UsagePercent,
			NeedsRotation:  dekStatus.NeedsRotation,
		},
	}

	if dekStatus.ReencryptProgress != nil {
		response.DekStatus.ReencryptProgress = &platformv1.DEKReencryptionProgress{
			InProgress:          dekStatus.ReencryptProgress.InProgress,
			TotalKeys:           dekStatus.ReencryptProgress.TotalKeys,
			ProcessedKeys:       dekStatus.ReencryptProgress.ProcessedKeys,
			FailedKeys:          dekStatus.ReencryptProgress.FailedKeys,
			StartedAt:           timestamppb.New(dekStatus.ReencryptProgress.StartedAt),
			EstimatedCompletion: timestamppb.New(dekStatus.ReencryptProgress.EstimatedCompletion),
		}
	}

	return response, nil
}

// =============================================================================
// Per-Tenant Barrier Operations (added 2026-04-28)
// =============================================================================

// InitTenantBarrier explicitly initializes a per-tenant barrier. The optional
// threshold/shares parameters configure Shamir secret sharing; both zero
// means deterministic non-Shamir init. The tenant must already exist.
func (s *TenantGRPCServer) InitTenantBarrier(
	ctx context.Context,
	req *platformv1.InitTenantBarrierRequest,
) (*platformv1.InitTenantBarrierResponse, error) {
	if s.manager == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant manager not initialized")
	}
	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}

	if err := s.manager.InitTenantBarrier(ctx, req.GetTenantId()); err != nil {
		s.logger.Error("failed to init tenant barrier", "tenant_id", req.GetTenantId(), "error", err)
		return nil, s.toGRPCError(err)
	}

	s.logger.Info("tenant barrier initialized", "tenant_id", req.GetTenantId())

	return &platformv1.InitTenantBarrierResponse{
		Status: &platformv1.Status{Success: true, Message: "tenant barrier initialized"},
	}, nil
}

// UnsealTenantBarrier unseals a per-tenant barrier with the provided key
// material. An empty key falls back to the deterministic init credential.
func (s *TenantGRPCServer) UnsealTenantBarrier(
	ctx context.Context,
	req *platformv1.UnsealTenantBarrierRequest,
) (*platformv1.UnsealTenantBarrierResponse, error) {
	if s.manager == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant manager not initialized")
	}
	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}

	if err := s.manager.UnsealTenantBarrier(ctx, req.GetTenantId(), req.GetKey()); err != nil {
		s.logger.Error("failed to unseal tenant barrier", "tenant_id", req.GetTenantId(), "error", err)
		return nil, s.toGRPCError(err)
	}

	s.logger.Info("tenant barrier unsealed", "tenant_id", req.GetTenantId())

	return &platformv1.UnsealTenantBarrierResponse{
		Status: &platformv1.Status{Success: true, Message: "tenant barrier unsealed"},
	}, nil
}

// SealTenantBarrier seals a per-tenant barrier. Subsequent reads/writes
// against the tenant namespace fail until unsealed again.
func (s *TenantGRPCServer) SealTenantBarrier(
	ctx context.Context,
	req *platformv1.SealTenantBarrierRequest,
) (*platformv1.SealTenantBarrierResponse, error) {
	if s.manager == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant manager not initialized")
	}
	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}

	if err := s.manager.SealTenantBarrier(ctx, req.GetTenantId()); err != nil {
		s.logger.Error("failed to seal tenant barrier", "tenant_id", req.GetTenantId(), "error", err)
		return nil, s.toGRPCError(err)
	}

	s.logger.Info("tenant barrier sealed", "tenant_id", req.GetTenantId())

	return &platformv1.SealTenantBarrierResponse{
		Status: &platformv1.Status{Success: true, Message: "tenant barrier sealed"},
	}, nil
}

// GetTenantBarrierStatus reports the current sealed/initialized state and
// active strategy metadata of a per-tenant barrier. Uninitialized barriers
// return Sealed=true, Initialized=false rather than erroring.
func (s *TenantGRPCServer) GetTenantBarrierStatus(
	ctx context.Context,
	req *platformv1.GetTenantBarrierStatusRequest,
) (*platformv1.GetTenantBarrierStatusResponse, error) {
	if s.manager == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant manager not initialized")
	}
	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}

	st, err := s.manager.TenantBarrierStatus(ctx, req.GetTenantId())
	if err != nil {
		s.logger.Error("failed to get tenant barrier status", "tenant_id", req.GetTenantId(), "error", err)
		return nil, s.toGRPCError(err)
	}

	return &platformv1.GetTenantBarrierStatusResponse{
		BarrierStatus: &platformv1.TenantBarrierStatus{
			TenantId:       st.TenantID,
			Sealed:         st.Sealed,
			Initialized:    st.Initialized,
			Strategy:       st.Strategy,
			HardwareBacked: st.HardwareBacked,
		},
	}, nil
}

// =============================================================================
// Helper Methods
// =============================================================================

// entityToTenantPb converts a TenantEntity to protobuf Tenant.
func (s *TenantGRPCServer) entityToTenantPb(entity *tenant.TenantEntity) *platformv1.Tenant {
	if entity == nil {
		return nil
	}

	return &platformv1.Tenant{
		Id:          entity.ID,
		Name:        entity.Name,
		DisplayName: entity.DisplayName,
		State:       s.tenantStateToPb(entity.State),
		OvsBridge:   entity.OVSBridge,
		VlanStart:   uint32(entity.VLANRange.Start),
		VlanEnd:     uint32(entity.VLANRange.End),
		DekPath:     entity.DEKPath,
		DekHandle:   entity.DEKHandle(),
		ComputeQuota: &platformv1.ComputeQuota{
			MaxVms:        entity.ComputeQuota.MaxVMs,
			MaxContainers: entity.ComputeQuota.MaxContainers,
			MaxVcpus:      entity.ComputeQuota.MaxVCPUs,
			MaxMemoryMb:   entity.ComputeQuota.MaxMemoryMB,
		},
		NetworkQuota: &platformv1.NetworkQuota{
			MaxBridges:       entity.NetworkQuota.MaxBridges,
			MaxPorts:         entity.NetworkQuota.MaxPorts,
			MaxBandwidthMbps: entity.NetworkQuota.MaxBandwidthMbps,
		},
		StorageQuota: &platformv1.StorageQuota{
			MaxVolumesGb: entity.StorageQuota.MaxVolumesGB,
			MaxSnapshots: entity.StorageQuota.MaxSnapshots,
		},
		Labels:      entity.Labels,
		Annotations: entity.Annotations,
		CreatedAt:   timestamppb.New(entity.CreatedAt),
		UpdatedAt:   timestamppb.New(entity.UpdatedAt),
	}
}

// tenantStateToPb converts tenant.State to protobuf TenantState.
func (s *TenantGRPCServer) tenantStateToPb(state tenant.State) platformv1.TenantState {
	switch state {
	case tenant.StateCreated:
		return platformv1.TenantState_TENANT_STATE_PENDING
	case tenant.StateActive:
		return platformv1.TenantState_TENANT_STATE_ACTIVE
	case tenant.StateSuspended:
		return platformv1.TenantState_TENANT_STATE_SUSPENDED
	case tenant.StateDeleting:
		return platformv1.TenantState_TENANT_STATE_DELETING
	case tenant.StateDeleted:
		return platformv1.TenantState_TENANT_STATE_DELETED
	default:
		return platformv1.TenantState_TENANT_STATE_UNSPECIFIED
	}
}

// toGRPCError converts tenant package errors to gRPC status errors.
func (s *TenantGRPCServer) toGRPCError(err error) error {
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
