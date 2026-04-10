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

package tenant

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	pb "github.com/jeremyhahn/go-quicbaas/api/proto"
	iampb "github.com/jeremyhahn/go-quicbaas/api/proto/iam"
	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/pkg/barrier"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant/bridge"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant/quota"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant/vlan"
	"google.golang.org/grpc"
)

// DEKClient defines the minimal interface for DEK operations.
// This interface is satisfied by the QuicBaaS KMS DEKManagementClient.
type DEKClient interface {
	CreateDEK(ctx context.Context, req *pb.CreateDEKRequest, opts ...grpc.CallOption) (*pb.CreateDEKResponse, error)
	GetDEK(ctx context.Context, req *pb.GetDEKRequest, opts ...grpc.CallOption) (*pb.GetDEKResponse, error)
	RotateDEK(ctx context.Context, req *pb.RotateDEKRequest, opts ...grpc.CallOption) (*pb.RotateDEKResponse, error)
	DeleteDEK(ctx context.Context, req *pb.DeleteDEKRequest, opts ...grpc.CallOption) (*pb.DeleteDEKResponse, error)
	GetDEKStatus(ctx context.Context, req *pb.GetDEKStatusRequest, opts ...grpc.CallOption) (*pb.GetDEKStatusResponse, error)
}

// TenantBarrierClient defines the minimal interface for per-tenant barrier
// operations. This interface is satisfied by the QRDB TenantClient
// (quicbaassdk.QRDBTenantClient) from the go-quicbaas SDK.
type TenantBarrierClient interface {
	// TenantBarrierInit initializes a per-tenant barrier.
	TenantBarrierInit(ctx context.Context, req *quicbaassdk.QRDBTenantBarrierInitRequest) error

	// TenantBarrierUnseal unseals a per-tenant barrier.
	TenantBarrierUnseal(ctx context.Context, req *quicbaassdk.QRDBTenantBarrierUnsealRequest) error
}

// DEKStatus represents the status of a tenant's DEK.
type DEKStatus struct {
	Path              string
	Algorithm         string
	Version           uint64
	Status            string
	IsDefault         bool
	CreatedAt         time.Time
	RotatedAt         time.Time
	UsageCount        uint64
	BytesUsed         uint64
	MaxUsageCount     uint64
	MaxBytesUsed      uint64
	WarningPercent    int32
	UsagePercent      float64
	NeedsRotation     bool
	ReencryptProgress *ReencryptionProgress
}

// ReencryptionProgress tracks DEK rotation re-encryption progress.
type ReencryptionProgress struct {
	InProgress          bool
	TotalKeys           int32
	ProcessedKeys       int32
	FailedKeys          int32
	StartedAt           time.Time
	EstimatedCompletion time.Time
}

// DEKRotationResult represents the result of a DEK rotation operation.
type DEKRotationResult struct {
	TenantID   string
	OldVersion uint32
	NewVersion uint32
	Timestamp  time.Time
}

// Manager coordinates all tenant lifecycle operations.
// It wraps QuicBaaS IAM operations and adds platform-specific orchestration
// for VLAN allocation, OVS bridge management, quota enforcement, DEK isolation,
// and per-tenant barrier management.
type Manager struct {
	// QuicBaaS IAM client for tenant CRUD
	iamClient iampb.IAMServiceClient

	// DEK client for key isolation
	dekClient DEKClient

	// Per-tenant barrier client for barrier init/unseal
	tenantBarrierClient TenantBarrierClient

	// Platform barrier manager for global barrier awareness
	barrierManager *barrier.Manager

	// Component managers
	bridgeManager  *bridge.Manager
	vlanAllocator  *vlan.Allocator
	vlanValidator  *vlan.Validator
	quotaEnforcer  *quota.Enforcer
	usageTracker   *quota.Tracker
	lifecycleHooks *bridge.LifecycleHooks

	// Configuration
	config *Config
	logger *slog.Logger

	// Runtime state - using sync.Map for lock-free concurrent access
	cache sync.Map // map[string]*TenantEntity
}

// ManagerConfig holds manager dependencies.
type ManagerConfig struct {
	IAMClient           iampb.IAMServiceClient
	DEKClient           DEKClient
	TenantBarrierClient TenantBarrierClient
	BarrierManager      *barrier.Manager
	BridgeManager       *bridge.Manager
	VLANAllocator       *vlan.Allocator
	VLANValidator       *vlan.Validator
	QuotaEnforcer       *quota.Enforcer
	UsageTracker        *quota.Tracker
	LifecycleHooks      *bridge.LifecycleHooks
	Config              *Config
	Logger              *slog.Logger
}

// CreateTenantRequest contains parameters for creating a new tenant.
type CreateTenantRequest struct {
	Name        string
	DisplayName string
	VLANRange   *VLANRange // Optional, auto-allocate if nil
	Labels      map[string]string
	Annotations map[string]string

	// Optional custom quotas (use defaults if nil)
	ComputeQuota *ComputeQuota
	NetworkQuota *NetworkQuota
	StorageQuota *StorageQuota
}

// UpdateTenantRequest contains parameters for updating a tenant.
type UpdateTenantRequest struct {
	DisplayName *string
	Labels      map[string]string
	Annotations map[string]string
}

// TenantQuotas holds all quota types for a tenant.
type TenantQuotas struct {
	Compute ComputeQuota
	Network NetworkQuota
	Storage StorageQuota
}

// NewManager creates a new tenant manager with the provided configuration.
func NewManager(cfg *ManagerConfig) (*Manager, error) {
	if cfg == nil {
		return nil, ErrInvalidRequest{Reason: "manager config is required"}
	}

	if cfg.IAMClient == nil {
		return nil, ErrInvalidRequest{Reason: "IAM client is required"}
	}

	if cfg.Config == nil {
		cfg.Config = DefaultConfig()
	}

	if err := cfg.Config.Validate(); err != nil {
		return nil, err
	}

	// Validate DEK client is provided when DEK isolation is enabled
	if cfg.Config.EnableDEKIsolation && cfg.DEKClient == nil {
		return nil, ErrInvalidRequest{Reason: "DEK client is required when EnableDEKIsolation is true"}
	}

	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	m := &Manager{
		iamClient:           cfg.IAMClient,
		dekClient:           cfg.DEKClient,
		tenantBarrierClient: cfg.TenantBarrierClient,
		barrierManager:      cfg.BarrierManager,
		bridgeManager:       cfg.BridgeManager,
		vlanAllocator:       cfg.VLANAllocator,
		vlanValidator:       cfg.VLANValidator,
		quotaEnforcer:       cfg.QuotaEnforcer,
		usageTracker:        cfg.UsageTracker,
		lifecycleHooks:      cfg.LifecycleHooks,
		config:              cfg.Config,
		logger:              cfg.Logger,
	}

	return m, nil
}

// CreateTenant creates a new tenant with full resource provisioning.
// Steps:
// 1. Create in QuicBaaS IAM
// 2. Allocate VLAN range
// 3. Create OVS bridge
// 4. Initialize quotas
// 5. Create DEK (if enabled)
// 6. Initialize per-tenant barrier (if barrier client configured)
func (m *Manager) CreateTenant(ctx context.Context, req *CreateTenantRequest) (*TenantEntity, error) {
	if req == nil {
		return nil, ErrInvalidRequest{Reason: "create request is required"}
	}

	if req.Name == "" {
		return nil, ErrInvalidRequest{Reason: "tenant name is required"}
	}

	m.logger.Info("creating tenant",
		slog.String("name", req.Name),
		slog.String("display_name", req.DisplayName),
	)

	// Check if tenant already exists by name
	existingTenant, err := m.GetTenantByName(ctx, req.Name)
	if err == nil && existingTenant != nil {
		return nil, ErrTenantExists{Name: req.Name}
	}

	// Generate tenant ID
	tenantID := uuid.New().String()

	// Track resources for rollback
	var rollbackActions []func()
	defer func() {
		// Execute rollback actions in reverse order if any remain
		for i := len(rollbackActions) - 1; i >= 0; i-- {
			rollbackActions[i]()
		}
	}()

	// Step 1: Create tenant in QuicBaaS IAM
	iamTenant, err := m.createInIAM(ctx, tenantID, req.Name)
	if err != nil {
		m.logger.Error("failed to create tenant in IAM",
			slog.String("name", req.Name),
			slog.Any("error", err),
		)
		return nil, ErrStorageFailed{Operation: "CreateTenant", Err: err}
	}

	rollbackActions = append(rollbackActions, func() {
		m.logger.Warn("rolling back IAM tenant creation",
			slog.String("tenant_id", tenantID),
		)
		if delErr := m.deleteFromIAM(ctx, tenantID); delErr != nil {
			m.logger.Error("failed to rollback IAM tenant",
				slog.String("tenant_id", tenantID),
				slog.Any("error", delErr),
			)
		}
	})

	// Create entity from IAM response
	entity := FromProto(iamTenant)
	entity.ID = tenantID
	entity.DisplayName = req.DisplayName
	if entity.DisplayName == "" {
		entity.DisplayName = req.Name
	}
	entity.State = StateCreated
	entity.Labels = req.Labels
	entity.Annotations = req.Annotations

	// Step 2: Allocate VLAN range
	if m.vlanAllocator != nil {
		var allocatedRange vlan.Range
		if req.VLANRange != nil {
			// Use requested range
			requestedRange := vlan.Range{
				Start: req.VLANRange.Start,
				End:   req.VLANRange.End,
			}
			allocation, err := m.vlanAllocator.AllocateSpecific(ctx, tenantID, requestedRange)
			if err != nil {
				m.logger.Error("failed to allocate specific VLAN range",
					slog.String("tenant_id", tenantID),
					slog.Any("error", err),
				)
				return nil, ErrVLANAllocationFailed{TenantID: tenantID, Err: err}
			}
			allocatedRange = allocation.Range
		} else {
			// Auto-allocate
			allocation, err := m.vlanAllocator.Allocate(ctx, tenantID, m.config.DefaultVLANRangeSize)
			if err != nil {
				m.logger.Error("failed to allocate VLAN range",
					slog.String("tenant_id", tenantID),
					slog.Any("error", err),
				)
				return nil, ErrVLANAllocationFailed{TenantID: tenantID, Err: err}
			}
			allocatedRange = allocation.Range
		}

		entity.VLANRange = VLANRange{
			Start: allocatedRange.Start,
			End:   allocatedRange.End,
		}

		rollbackActions = append(rollbackActions, func() {
			m.logger.Warn("rolling back VLAN allocation",
				slog.String("tenant_id", tenantID),
			)
			if relErr := m.vlanAllocator.Release(ctx, tenantID); relErr != nil {
				m.logger.Error("failed to rollback VLAN allocation",
					slog.String("tenant_id", tenantID),
					slog.Any("error", relErr),
				)
			}
		})
	}

	// Step 3: Create OVS bridge
	if m.lifecycleHooks != nil {
		bridgeVLANRange := bridge.VLANRange{
			Start: entity.VLANRange.Start,
			End:   entity.VLANRange.End,
		}

		if err := m.lifecycleHooks.OnTenantCreate(ctx, tenantID, req.Name, bridgeVLANRange); err != nil {
			m.logger.Error("failed to create OVS bridge",
				slog.String("tenant_id", tenantID),
				slog.Any("error", err),
			)
			return nil, ErrBridgeOperationFailed{
				Bridge:    m.config.BridgePrefix + req.Name,
				Operation: "create",
				Err:       err,
			}
		}

		entity.OVSBridge = m.config.BridgePrefix + req.Name

		rollbackActions = append(rollbackActions, func() {
			m.logger.Warn("rolling back OVS bridge creation",
				slog.String("tenant_id", tenantID),
			)
			if delErr := m.lifecycleHooks.OnTenantDelete(ctx, tenantID); delErr != nil {
				m.logger.Error("failed to rollback OVS bridge",
					slog.String("tenant_id", tenantID),
					slog.Any("error", delErr),
				)
			}
		})
	}

	// Step 4: Initialize quotas
	entity.ComputeQuota = m.config.DefaultComputeQuota
	entity.NetworkQuota = m.config.DefaultNetworkQuota
	entity.StorageQuota = m.config.DefaultStorageQuota

	if req.ComputeQuota != nil {
		entity.ComputeQuota = *req.ComputeQuota
	}
	if req.NetworkQuota != nil {
		entity.NetworkQuota = *req.NetworkQuota
	}
	if req.StorageQuota != nil {
		entity.StorageQuota = *req.StorageQuota
	}

	// Step 5: Create DEK (if enabled)
	if m.config.EnableDEKIsolation {
		dekPath, err := m.createDEK(ctx, tenantID)
		if err != nil {
			m.logger.Error("failed to create DEK",
				slog.String("tenant_id", tenantID),
				slog.Any("error", err),
			)
			return nil, ErrDEKOperationFailed{
				TenantID:  tenantID,
				Operation: "create",
				Err:       err,
			}
		}
		entity.DEKPath = dekPath

		m.logger.Info("DEK created for tenant",
			slog.String("tenant_id", tenantID),
			slog.String("dek_path", dekPath),
		)

		rollbackActions = append(rollbackActions, func() {
			m.logger.Warn("rolling back DEK creation",
				slog.String("tenant_id", tenantID),
			)
			if delErr := m.deleteDEK(ctx, tenantID, dekPath); delErr != nil {
				m.logger.Error("failed to rollback DEK",
					slog.String("tenant_id", tenantID),
					slog.Any("error", delErr),
				)
			}
		})
	}

	// Step 6: Initialize per-tenant barrier (non-fatal on failure)
	if m.tenantBarrierClient != nil {
		if barrierErr := m.initTenantBarrierInternal(ctx, tenantID); barrierErr != nil {
			m.logger.Warn("failed to initialize per-tenant barrier during creation; barrier can be initialized later",
				slog.String("tenant_id", tenantID),
				slog.Any("error", barrierErr),
			)
		} else {
			m.logger.Info("per-tenant barrier initialized",
				slog.String("tenant_id", tenantID),
			)
		}
	}

	// Transition to active state
	if err := entity.SetState(StateActive); err != nil {
		return nil, err
	}

	// Activate the bridge
	if m.lifecycleHooks != nil {
		if err := m.lifecycleHooks.OnTenantActivate(ctx, tenantID); err != nil {
			m.logger.Warn("failed to activate tenant bridge",
				slog.String("tenant_id", tenantID),
				slog.Any("error", err),
			)
			// Non-fatal, continue
		}
	}

	// Store in cache
	m.cache.Store(tenantID, entity)

	// Clear rollback actions since we succeeded
	rollbackActions = nil

	m.logger.Info("tenant created successfully",
		slog.String("tenant_id", tenantID),
		slog.String("name", req.Name),
		slog.String("bridge", entity.OVSBridge),
		slog.String("vlan_range", fmt.Sprintf("%d-%d", entity.VLANRange.Start, entity.VLANRange.End)),
		slog.String("dek_path", entity.DEKPath),
	)

	return entity.Clone(), nil
}

// GetTenant retrieves a tenant by ID.
func (m *Manager) GetTenant(ctx context.Context, id string) (*TenantEntity, error) {
	if id == "" {
		return nil, ErrInvalidRequest{Reason: "tenant ID is required"}
	}

	// Check cache first
	if cached, ok := m.cache.Load(id); ok {
		entity := cached.(*TenantEntity)
		return entity.Clone(), nil
	}

	// Fetch from IAM
	iamTenant, err := m.getFromIAM(ctx, id)
	if err != nil {
		return nil, ErrTenantNotFound{ID: id}
	}

	entity := FromProto(iamTenant)

	// Enrich with VLAN allocation
	if m.vlanAllocator != nil {
		allocation, err := m.vlanAllocator.Get(ctx, id)
		if err == nil && allocation != nil {
			entity.VLANRange = VLANRange{
				Start: allocation.Range.Start,
				End:   allocation.Range.End,
			}
		}
	}

	// Enrich with bridge info
	if m.bridgeManager != nil {
		bridgeInfo, err := m.bridgeManager.GetBridge(ctx, id)
		if err == nil && bridgeInfo != nil {
			entity.OVSBridge = bridgeInfo.Name
		}
	}

	// Enrich with DEK path
	if m.config.EnableDEKIsolation {
		entity.DEKPath = BuildDEKPath(id)
	}

	// Cache and return
	m.cache.Store(id, entity)

	return entity.Clone(), nil
}

// GetTenantByName retrieves a tenant by name.
func (m *Manager) GetTenantByName(ctx context.Context, name string) (*TenantEntity, error) {
	if name == "" {
		return nil, ErrInvalidRequest{Reason: "tenant name is required"}
	}

	// Search cache first
	var found *TenantEntity
	m.cache.Range(func(key, value any) bool {
		entity := value.(*TenantEntity)
		if entity.Name == name {
			found = entity
			return false
		}
		return true
	})

	if found != nil {
		return found.Clone(), nil
	}

	// Fetch from IAM
	iamTenant, err := m.getFromIAMByName(ctx, name)
	if err != nil {
		return nil, ErrTenantNotFound{Name: name}
	}

	entity := FromProto(iamTenant)

	// Enrich with platform-specific data
	if m.vlanAllocator != nil {
		allocation, err := m.vlanAllocator.Get(ctx, entity.ID)
		if err == nil && allocation != nil {
			entity.VLANRange = VLANRange{
				Start: allocation.Range.Start,
				End:   allocation.Range.End,
			}
		}
	}

	if m.bridgeManager != nil {
		bridgeInfo, err := m.bridgeManager.GetBridge(ctx, entity.ID)
		if err == nil && bridgeInfo != nil {
			entity.OVSBridge = bridgeInfo.Name
		}
	}

	// Enrich with DEK path
	if m.config.EnableDEKIsolation {
		entity.DEKPath = BuildDEKPath(entity.ID)
	}

	// Cache and return
	m.cache.Store(entity.ID, entity)

	return entity.Clone(), nil
}

// ListTenants lists all tenants with pagination.
func (m *Manager) ListTenants(ctx context.Context, limit, offset int) ([]*TenantEntity, int, error) {
	if limit <= 0 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	// List from IAM
	tenants, total, err := m.listFromIAM(ctx, limit, offset)
	if err != nil {
		return nil, 0, ErrStorageFailed{Operation: "ListTenants", Err: err}
	}

	entities := make([]*TenantEntity, 0, len(tenants))
	for _, t := range tenants {
		entity := FromProto(t)

		// Enrich with platform-specific data
		if m.vlanAllocator != nil {
			allocation, err := m.vlanAllocator.Get(ctx, entity.ID)
			if err == nil && allocation != nil {
				entity.VLANRange = VLANRange{
					Start: allocation.Range.Start,
					End:   allocation.Range.End,
				}
			}
		}

		if m.bridgeManager != nil {
			bridgeInfo, err := m.bridgeManager.GetBridge(ctx, entity.ID)
			if err == nil && bridgeInfo != nil {
				entity.OVSBridge = bridgeInfo.Name
			}
		}

		// Enrich with DEK path
		if m.config.EnableDEKIsolation {
			entity.DEKPath = BuildDEKPath(entity.ID)
		}

		// Update cache
		m.cache.Store(entity.ID, entity)
		entities = append(entities, entity.Clone())
	}

	return entities, total, nil
}

// UpdateTenant updates tenant metadata.
func (m *Manager) UpdateTenant(ctx context.Context, id string, req *UpdateTenantRequest) (*TenantEntity, error) {
	if id == "" {
		return nil, ErrInvalidRequest{Reason: "tenant ID is required"}
	}
	if req == nil {
		return nil, ErrInvalidRequest{Reason: "update request is required"}
	}

	entity, err := m.GetTenant(ctx, id)
	if err != nil {
		return nil, err
	}

	m.logger.Info("updating tenant",
		slog.String("tenant_id", id),
	)

	// Apply updates
	if req.DisplayName != nil {
		entity.DisplayName = *req.DisplayName
	}

	if req.Labels != nil {
		entity.Labels = req.Labels
	}

	if req.Annotations != nil {
		entity.Annotations = req.Annotations
	}

	entity.UpdatedAt = time.Now()

	// Update in IAM
	if err := m.updateInIAM(ctx, entity); err != nil {
		return nil, ErrStorageFailed{Operation: "UpdateTenant", Err: err}
	}

	// Update cache
	m.cache.Store(id, entity)

	m.logger.Info("tenant updated successfully",
		slog.String("tenant_id", id),
	)

	return entity.Clone(), nil
}

// DeleteTenant deletes a tenant and all its resources.
// Steps:
// 1. Set state to deleting
// 2. Delete OVS bridge
// 3. Release VLAN allocation
// 4. Delete DEK
// 5. Log barrier cleanup warning (seal/cleanup not yet supported by SDK)
// 6. Delete from QuicBaaS IAM
func (m *Manager) DeleteTenant(ctx context.Context, id string) error {
	if id == "" {
		return ErrInvalidRequest{Reason: "tenant ID is required"}
	}

	entity, err := m.GetTenant(ctx, id)
	if err != nil {
		return err
	}

	m.logger.Info("deleting tenant",
		slog.String("tenant_id", id),
		slog.String("name", entity.Name),
	)

	// Step 1: Set state to deleting
	if err := entity.SetState(StateDeleting); err != nil {
		return err
	}
	m.cache.Store(id, entity)

	// Step 2: Delete OVS bridge
	if m.lifecycleHooks != nil {
		if err := m.lifecycleHooks.OnTenantDelete(ctx, id); err != nil {
			m.logger.Error("failed to delete OVS bridge",
				slog.String("tenant_id", id),
				slog.Any("error", err),
			)
			// Continue with deletion, log the error
		}
	}

	// Step 3: Release VLAN allocation
	if m.vlanAllocator != nil {
		if err := m.vlanAllocator.Release(ctx, id); err != nil {
			m.logger.Error("failed to release VLAN allocation",
				slog.String("tenant_id", id),
				slog.Any("error", err),
			)
			// Continue with deletion, log the error
		}
	}

	// Step 4: Delete DEK
	if m.config.EnableDEKIsolation && entity.DEKPath != "" {
		if err := m.deleteDEK(ctx, id, entity.DEKPath); err != nil {
			m.logger.Error("failed to delete DEK",
				slog.String("tenant_id", id),
				slog.String("dek_path", entity.DEKPath),
				slog.Any("error", err),
			)
			// Continue with deletion, log the error
		} else {
			m.logger.Info("DEK deleted for tenant",
				slog.String("tenant_id", id),
				slog.String("dek_path", entity.DEKPath),
			)
		}
	}

	// Step 5: Log barrier cleanup
	// The SDK does not currently provide TenantBarrierSeal, so we log a
	// warning. The per-tenant barrier will be cleaned up when the QRDB
	// tenant record is removed by the IAM delete below.
	if m.tenantBarrierClient != nil {
		m.logger.Warn("per-tenant barrier cleanup deferred to IAM tenant deletion; explicit seal not yet supported by SDK",
			slog.String("tenant_id", id),
		)
	}

	// Step 6: Delete from QuicBaaS IAM
	if err := m.deleteFromIAM(ctx, id); err != nil {
		m.logger.Error("failed to delete tenant from IAM",
			slog.String("tenant_id", id),
			slog.Any("error", err),
		)
		return ErrStorageFailed{Operation: "DeleteTenant", Err: err}
	}

	// Remove from cache
	m.cache.Delete(id)

	// Invalidate usage tracker cache
	if m.usageTracker != nil {
		m.usageTracker.Invalidate(id)
	}

	m.logger.Info("tenant deleted successfully",
		slog.String("tenant_id", id),
		slog.String("name", entity.Name),
	)

	return nil
}

// SuspendTenant suspends a tenant (blocks traffic).
func (m *Manager) SuspendTenant(ctx context.Context, id string) error {
	if id == "" {
		return ErrInvalidRequest{Reason: "tenant ID is required"}
	}

	entity, err := m.GetTenant(ctx, id)
	if err != nil {
		return err
	}

	m.logger.Info("suspending tenant",
		slog.String("tenant_id", id),
		slog.String("name", entity.Name),
	)

	// Transition state
	if err := entity.SetState(StateSuspended); err != nil {
		return err
	}

	// Suspend bridge traffic
	if m.lifecycleHooks != nil {
		if err := m.lifecycleHooks.OnTenantSuspend(ctx, id); err != nil {
			m.logger.Error("failed to suspend tenant bridge",
				slog.String("tenant_id", id),
				slog.Any("error", err),
			)
			return ErrBridgeOperationFailed{
				Bridge:    entity.OVSBridge,
				Operation: "suspend",
				Err:       err,
			}
		}
	}

	// Update cache
	entity.UpdatedAt = time.Now()
	m.cache.Store(id, entity)

	m.logger.Info("tenant suspended successfully",
		slog.String("tenant_id", id),
	)

	return nil
}

// ResumeTenant resumes a suspended tenant.
func (m *Manager) ResumeTenant(ctx context.Context, id string) error {
	if id == "" {
		return ErrInvalidRequest{Reason: "tenant ID is required"}
	}

	entity, err := m.GetTenant(ctx, id)
	if err != nil {
		return err
	}

	if entity.State != StateSuspended {
		return ErrInvalidTransition{
			From: entity.State,
			To:   StateActive,
		}
	}

	m.logger.Info("resuming tenant",
		slog.String("tenant_id", id),
		slog.String("name", entity.Name),
	)

	// Resume bridge traffic
	if m.lifecycleHooks != nil {
		if err := m.lifecycleHooks.OnTenantResume(ctx, id); err != nil {
			m.logger.Error("failed to resume tenant bridge",
				slog.String("tenant_id", id),
				slog.Any("error", err),
			)
			return ErrBridgeOperationFailed{
				Bridge:    entity.OVSBridge,
				Operation: "resume",
				Err:       err,
			}
		}
	}

	// Transition state
	if err := entity.SetState(StateActive); err != nil {
		return err
	}

	// Update cache
	entity.UpdatedAt = time.Now()
	m.cache.Store(id, entity)

	m.logger.Info("tenant resumed successfully",
		slog.String("tenant_id", id),
	)

	return nil
}

// GetQuotas returns tenant quotas.
func (m *Manager) GetQuotas(ctx context.Context, tenantID string) (*TenantQuotas, error) {
	entity, err := m.GetTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	return &TenantQuotas{
		Compute: entity.ComputeQuota,
		Network: entity.NetworkQuota,
		Storage: entity.StorageQuota,
	}, nil
}

// UpdateQuotas updates tenant quotas.
func (m *Manager) UpdateQuotas(ctx context.Context, tenantID string, quotas *TenantQuotas) error {
	if quotas == nil {
		return ErrInvalidRequest{Reason: "quotas are required"}
	}

	entity, err := m.GetTenant(ctx, tenantID)
	if err != nil {
		return err
	}

	m.logger.Info("updating tenant quotas",
		slog.String("tenant_id", tenantID),
	)

	entity.ComputeQuota = quotas.Compute
	entity.NetworkQuota = quotas.Network
	entity.StorageQuota = quotas.Storage
	entity.UpdatedAt = time.Now()

	// Update cache
	m.cache.Store(tenantID, entity)

	m.logger.Info("tenant quotas updated successfully",
		slog.String("tenant_id", tenantID),
	)

	return nil
}

// GetUsage returns tenant resource usage.
func (m *Manager) GetUsage(ctx context.Context, tenantID string) (*quota.TenantUsage, error) {
	if m.usageTracker == nil {
		return nil, ErrInvalidRequest{Reason: "usage tracker not configured"}
	}

	return m.usageTracker.GetAllUsage(ctx, tenantID)
}

// CheckQuota checks if a resource request can be fulfilled.
func (m *Manager) CheckQuota(ctx context.Context, tenantID string, resource quota.ResourceType, amount int64) error {
	if m.quotaEnforcer == nil {
		return ErrInvalidRequest{Reason: "quota enforcer not configured"}
	}

	return m.quotaEnforcer.CheckQuota(ctx, tenantID, resource, amount)
}

// ReserveQuota reserves quota for a pending resource creation.
func (m *Manager) ReserveQuota(ctx context.Context, tenantID string, resource quota.ResourceType, amount int64) (*quota.Reservation, error) {
	if m.quotaEnforcer == nil {
		return nil, ErrInvalidRequest{Reason: "quota enforcer not configured"}
	}

	return m.quotaEnforcer.Reserve(ctx, tenantID, resource, amount)
}

// CommitQuota commits a quota reservation.
func (m *Manager) CommitQuota(ctx context.Context, reservationID string) error {
	if m.quotaEnforcer == nil {
		return ErrInvalidRequest{Reason: "quota enforcer not configured"}
	}

	return m.quotaEnforcer.Commit(ctx, reservationID)
}

// ReleaseQuota releases a quota reservation or used quota.
func (m *Manager) ReleaseQuota(ctx context.Context, reservationID string) error {
	if m.quotaEnforcer == nil {
		return ErrInvalidRequest{Reason: "quota enforcer not configured"}
	}

	return m.quotaEnforcer.Release(ctx, reservationID)
}

// ValidateVLAN checks if a tenant can use a specific VLAN.
func (m *Manager) ValidateVLAN(ctx context.Context, tenantID string, vlanID uint16) error {
	if m.vlanValidator == nil {
		return ErrInvalidRequest{Reason: "VLAN validator not configured"}
	}

	return m.vlanValidator.ValidateTenantVLAN(ctx, tenantID, vlanID)
}

// GetBridgeName returns the OVS bridge name for a tenant.
func (m *Manager) GetBridgeName(ctx context.Context, tenantID string) (string, error) {
	entity, err := m.GetTenant(ctx, tenantID)
	if err != nil {
		return "", err
	}

	if entity.OVSBridge == "" {
		return "", ErrInvalidRequest{Reason: "tenant has no associated bridge"}
	}

	return entity.OVSBridge, nil
}

// RotateTenantDEK rotates the DEK for a tenant.
// Deprecated: Use RotateTenantDEKWithOptions for full rotation result.
func (m *Manager) RotateTenantDEK(ctx context.Context, tenantID string) error {
	_, err := m.RotateTenantDEKWithOptions(ctx, tenantID, false)
	return err
}

// RotateTenantDEKWithOptions rotates the DEK for a tenant with additional options.
// If background is true, the rotation will be performed asynchronously.
// Returns a DEKRotationResult containing the old and new version numbers.
func (m *Manager) RotateTenantDEKWithOptions(ctx context.Context, tenantID string, background bool) (*DEKRotationResult, error) {
	if tenantID == "" {
		return nil, ErrInvalidRequest{Reason: "tenant ID is required"}
	}

	if !m.config.EnableDEKIsolation {
		return nil, ErrInvalidRequest{Reason: "DEK isolation is not enabled"}
	}

	if m.dekClient == nil {
		return nil, ErrInvalidRequest{Reason: "DEK client is not configured"}
	}

	entity, err := m.GetTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	if entity.DEKPath == "" {
		return nil, ErrInvalidRequest{Reason: "tenant has no DEK configured"}
	}

	m.logger.Info("rotating tenant DEK",
		slog.String("tenant_id", tenantID),
		slog.String("dek_path", entity.DEKPath),
		slog.Bool("background", background),
	)

	req := &pb.RotateDEKRequest{
		Path:       entity.DEKPath,
		Background: background,
	}

	resp, err := m.dekClient.RotateDEK(ctx, req)
	if err != nil {
		m.logger.Error("failed to rotate DEK",
			slog.String("tenant_id", tenantID),
			slog.String("dek_path", entity.DEKPath),
			slog.Any("error", err),
		)
		return nil, ErrDEKOperationFailed{
			TenantID:  tenantID,
			Operation: "rotate",
			Err:       err,
		}
	}

	m.logger.Info("DEK rotated successfully",
		slog.String("tenant_id", tenantID),
		slog.String("dek_path", entity.DEKPath),
		slog.Uint64("old_version", resp.OldVersion),
		slog.Uint64("new_version", resp.NewVersion),
	)

	return &DEKRotationResult{
		TenantID:   tenantID,
		OldVersion: uint32(resp.OldVersion),
		NewVersion: uint32(resp.NewVersion),
		Timestamp:  time.Now(),
	}, nil
}

// GetTenantDEKStatus returns the status of a tenant's DEK.
func (m *Manager) GetTenantDEKStatus(ctx context.Context, tenantID string) (*DEKStatus, error) {
	if tenantID == "" {
		return nil, ErrInvalidRequest{Reason: "tenant ID is required"}
	}

	if !m.config.EnableDEKIsolation {
		return nil, ErrInvalidRequest{Reason: "DEK isolation is not enabled"}
	}

	if m.dekClient == nil {
		return nil, ErrInvalidRequest{Reason: "DEK client is not configured"}
	}

	entity, err := m.GetTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	if entity.DEKPath == "" {
		return nil, ErrInvalidRequest{Reason: "tenant has no DEK configured"}
	}

	req := &pb.GetDEKStatusRequest{
		Path: entity.DEKPath,
	}

	resp, err := m.dekClient.GetDEKStatus(ctx, req)
	if err != nil {
		m.logger.Error("failed to get DEK status",
			slog.String("tenant_id", tenantID),
			slog.String("dek_path", entity.DEKPath),
			slog.Any("error", err),
		)
		return nil, ErrDEKOperationFailed{
			TenantID:  tenantID,
			Operation: "status",
			Err:       err,
		}
	}

	status := &DEKStatus{
		Path:           resp.Dek.Path,
		Algorithm:      protoKeyAlgorithmToString(resp.Dek.Algorithm),
		Version:        resp.Dek.Version,
		Status:         resp.Dek.Status,
		IsDefault:      resp.Dek.IsDefault,
		CreatedAt:      time.Unix(resp.Dek.CreatedAt, 0),
		RotatedAt:      time.Unix(resp.Dek.RotatedAt, 0),
		UsageCount:     resp.Dek.UsageCount,
		BytesUsed:      resp.Dek.BytesUsed,
		MaxUsageCount:  resp.Dek.MaxUsageCount,
		MaxBytesUsed:   resp.Dek.MaxBytesUsed,
		WarningPercent: resp.Dek.WarningPercent,
	}

	// Calculate usage percent
	if status.MaxUsageCount > 0 {
		status.UsagePercent = float64(status.UsageCount) / float64(status.MaxUsageCount) * 100
	}

	// Determine if rotation is needed
	if status.MaxUsageCount > 0 && status.UsageCount >= status.MaxUsageCount {
		status.NeedsRotation = true
	}
	if status.MaxBytesUsed > 0 && status.BytesUsed >= status.MaxBytesUsed {
		status.NeedsRotation = true
	}

	// Include re-encryption progress if available
	if resp.ReencryptionProgress != nil {
		status.ReencryptProgress = &ReencryptionProgress{
			InProgress:          resp.ReencryptionProgress.InProgress,
			TotalKeys:           resp.ReencryptionProgress.TotalKeys,
			ProcessedKeys:       resp.ReencryptionProgress.ProcessedKeys,
			FailedKeys:          resp.ReencryptionProgress.FailedKeys,
			StartedAt:           time.Unix(resp.ReencryptionProgress.StartedAt, 0),
			EstimatedCompletion: time.Unix(resp.ReencryptionProgress.EstimatedCompletion, 0),
		}
	}

	return status, nil
}

// ---------------------------------------------------------------------------
// Per-tenant barrier operations
// ---------------------------------------------------------------------------

// InitTenantBarrier explicitly initializes the per-tenant barrier for the
// given tenant. This is useful when the automatic initialization during
// CreateTenant was skipped or failed.
func (m *Manager) InitTenantBarrier(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return ErrInvalidRequest{Reason: "tenant ID is required"}
	}

	if m.tenantBarrierClient == nil {
		return ErrInvalidRequest{Reason: "tenant barrier client is not configured"}
	}

	// Verify tenant exists
	if _, err := m.GetTenant(ctx, tenantID); err != nil {
		return err
	}

	return m.initTenantBarrierInternal(ctx, tenantID)
}

// UnsealTenantBarrier explicitly unseals a per-tenant barrier using the
// provided key material.
func (m *Manager) UnsealTenantBarrier(ctx context.Context, tenantID string, key []byte) error {
	if tenantID == "" {
		return ErrInvalidRequest{Reason: "tenant ID is required"}
	}

	if len(key) == 0 {
		return ErrInvalidRequest{Reason: "unseal key is required"}
	}

	if m.tenantBarrierClient == nil {
		return ErrInvalidRequest{Reason: "tenant barrier client is not configured"}
	}

	// Verify tenant exists
	if _, err := m.GetTenant(ctx, tenantID); err != nil {
		return err
	}

	req := &quicbaassdk.QRDBTenantBarrierUnsealRequest{
		TenantID: tenantID,
		Key:      key,
	}

	if err := m.tenantBarrierClient.TenantBarrierUnseal(ctx, req); err != nil {
		return ErrBarrierOperationFailed{
			TenantID:  tenantID,
			Operation: "unseal",
			Err:       err,
		}
	}

	m.logger.Info("per-tenant barrier unsealed",
		slog.String("tenant_id", tenantID),
	)

	return nil
}

// SealTenantBarrier seals a per-tenant barrier. This operation is not yet
// supported by the QRDB SDK and returns ErrBarrierNotSupported.
func (m *Manager) SealTenantBarrier(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return ErrInvalidRequest{Reason: "tenant ID is required"}
	}

	return ErrBarrierNotSupported{Operation: "SealTenantBarrier"}
}

// TenantBarrierStatus returns the sealed state of a per-tenant barrier.
// This operation is not yet supported by the QRDB SDK and returns
// ErrBarrierNotSupported.
func (m *Manager) TenantBarrierStatus(ctx context.Context, tenantID string) (bool, error) {
	if tenantID == "" {
		return false, ErrInvalidRequest{Reason: "tenant ID is required"}
	}

	return false, ErrBarrierNotSupported{Operation: "TenantBarrierStatus"}
}

// BarrierManager returns the platform barrier manager, or nil if not configured.
func (m *Manager) BarrierManager() *barrier.Manager {
	return m.barrierManager
}

// ---------------------------------------------------------------------------
// Sync and cache operations
// ---------------------------------------------------------------------------

// Sync synchronizes manager state with external systems.
func (m *Manager) Sync(ctx context.Context) error {
	m.logger.Info("synchronizing manager state")

	// Sync VLAN allocator
	if m.vlanAllocator != nil {
		if err := m.vlanAllocator.Reload(ctx); err != nil {
			m.logger.Error("failed to sync VLAN allocator",
				slog.Any("error", err),
			)
		}
	}

	// Sync bridge manager
	if m.bridgeManager != nil {
		if err := m.bridgeManager.Sync(ctx); err != nil {
			m.logger.Error("failed to sync bridge manager",
				slog.Any("error", err),
			)
		}
	}

	// Sync usage tracker
	if m.usageTracker != nil {
		if err := m.usageTracker.SyncAll(ctx); err != nil {
			m.logger.Error("failed to sync usage tracker",
				slog.Any("error", err),
			)
		}
	}

	// Clean up expired quota reservations
	if m.quotaEnforcer != nil {
		cleaned := m.quotaEnforcer.CleanupExpiredReservations()
		if cleaned > 0 {
			m.logger.Info("cleaned up expired reservations",
				slog.Int("count", cleaned),
			)
		}
	}

	m.logger.Info("manager state synchronized")

	return nil
}

// InvalidateCache clears the tenant cache for a specific tenant or all tenants.
func (m *Manager) InvalidateCache(tenantID string) {
	if tenantID == "" {
		// Clear all cache entries
		m.cache.Range(func(key, _ any) bool {
			m.cache.Delete(key)
			return true
		})
		m.logger.Debug("cleared all tenant cache entries")
	} else {
		m.cache.Delete(tenantID)
		m.logger.Debug("cleared tenant cache entry",
			slog.String("tenant_id", tenantID),
		)
	}
}

// GetCacheSize returns the number of cached tenant entities.
func (m *Manager) GetCacheSize() int {
	count := 0
	m.cache.Range(func(_, _ any) bool {
		count++
		return true
	})
	return count
}

// ---------------------------------------------------------------------------
// IAM integration methods
// ---------------------------------------------------------------------------

func (m *Manager) createInIAM(ctx context.Context, id, name string) (*iampb.Tenant, error) {
	req := &iampb.CreateTenantRequest{
		Id:   id,
		Name: name,
	}

	// IAM service returns *iampb.Tenant directly
	tenant, err := m.iamClient.CreateTenant(ctx, req)
	if err != nil {
		return nil, err
	}

	return tenant, nil
}

func (m *Manager) getFromIAM(ctx context.Context, id string) (*iampb.Tenant, error) {
	req := &iampb.GetTenantRequest{
		Id: id,
	}

	// IAM service returns *iampb.Tenant directly
	tenant, err := m.iamClient.GetTenant(ctx, req)
	if err != nil {
		return nil, err
	}

	return tenant, nil
}

func (m *Manager) getFromIAMByName(ctx context.Context, name string) (*iampb.Tenant, error) {
	// Use ListTenants with a filter to find by name
	req := &iampb.ListTenantsRequest{
		Limit:  100,
		Offset: 0,
	}

	resp, err := m.iamClient.ListTenants(ctx, req)
	if err != nil {
		return nil, err
	}

	for _, t := range resp.Tenants {
		if t.Name == name {
			return t, nil
		}
	}

	return nil, ErrTenantNotFound{Name: name}
}

func (m *Manager) listFromIAM(ctx context.Context, limit, offset int) ([]*iampb.Tenant, int, error) {
	req := &iampb.ListTenantsRequest{
		Limit:  int32(limit),
		Offset: int32(offset),
	}

	resp, err := m.iamClient.ListTenants(ctx, req)
	if err != nil {
		return nil, 0, err
	}

	return resp.Tenants, int(resp.Total), nil
}

func (m *Manager) updateInIAM(ctx context.Context, entity *TenantEntity) error {
	req := &iampb.UpdateTenantRequest{
		Id:   entity.ID,
		Name: entity.Name,
	}

	_, err := m.iamClient.UpdateTenant(ctx, req)
	return err
}

func (m *Manager) deleteFromIAM(ctx context.Context, id string) error {
	req := &iampb.DeleteTenantRequest{
		Id: id,
	}

	_, err := m.iamClient.DeleteTenant(ctx, req)
	return err
}

// ---------------------------------------------------------------------------
// DEK integration methods
// ---------------------------------------------------------------------------

func (m *Manager) createDEK(ctx context.Context, tenantID string) (string, error) {
	if m.dekClient == nil {
		return "", ErrInvalidRequest{Reason: "DEK client is not configured"}
	}

	dekPath := BuildDEKPath(tenantID)
	algorithm := m.algorithmStringToProto(m.config.DEKAlgorithm)

	req := &pb.CreateDEKRequest{
		Path:           dekPath,
		Algorithm:      algorithm,
		Description:    fmt.Sprintf("Tenant DEK for %s", tenantID),
		MaxOperations:  m.config.DEKMaxOperations,
		MaxBytes:       m.config.DEKMaxBytes,
		WarningPercent: m.config.DEKWarningPercent,
	}

	resp, err := m.dekClient.CreateDEK(ctx, req)
	if err != nil {
		return "", err
	}

	return resp.Dek.Path, nil
}

func (m *Manager) deleteDEK(ctx context.Context, tenantID, dekPath string) error {
	if m.dekClient == nil {
		return ErrInvalidRequest{Reason: "DEK client is not configured"}
	}

	req := &pb.DeleteDEKRequest{
		Path:  dekPath,
		Force: true, // Force delete for tenant cleanup
	}

	_, err := m.dekClient.DeleteDEK(ctx, req)
	return err
}

// algorithmStringToProto converts a string algorithm to proto enum.
func (m *Manager) algorithmStringToProto(algorithm string) pb.KeyAlgorithm {
	algorithmMap := map[string]pb.KeyAlgorithm{
		DEKAlgorithmAES128GCM:         pb.KeyAlgorithm_KEY_ALG_AES_128_GCM,
		DEKAlgorithmAES192GCM:         pb.KeyAlgorithm_KEY_ALG_AES_192_GCM,
		DEKAlgorithmAES256GCM:         pb.KeyAlgorithm_KEY_ALG_AES_256_GCM,
		DEKAlgorithmChaCha20Poly1305:  pb.KeyAlgorithm_KEY_ALG_CHACHA20_POLY1305,
		DEKAlgorithmXChaCha20Poly1305: pb.KeyAlgorithm_KEY_ALG_XCHACHA20_POLY1305,
	}

	if alg, ok := algorithmMap[algorithm]; ok {
		return alg
	}
	return pb.KeyAlgorithm_KEY_ALG_AES_256_GCM // Default
}

// protoKeyAlgorithmToString converts a proto enum to string.
func protoKeyAlgorithmToString(algorithm pb.KeyAlgorithm) string {
	algorithmMap := map[pb.KeyAlgorithm]string{
		pb.KeyAlgorithm_KEY_ALG_AES_128_GCM:        DEKAlgorithmAES128GCM,
		pb.KeyAlgorithm_KEY_ALG_AES_192_GCM:        DEKAlgorithmAES192GCM,
		pb.KeyAlgorithm_KEY_ALG_AES_256_GCM:        DEKAlgorithmAES256GCM,
		pb.KeyAlgorithm_KEY_ALG_CHACHA20_POLY1305:  DEKAlgorithmChaCha20Poly1305,
		pb.KeyAlgorithm_KEY_ALG_XCHACHA20_POLY1305: DEKAlgorithmXChaCha20Poly1305,
	}

	if str, ok := algorithmMap[algorithm]; ok {
		return str
	}
	return "unknown"
}

// ---------------------------------------------------------------------------
// Per-tenant barrier internal methods
// ---------------------------------------------------------------------------

// initTenantBarrierInternal calls the SDK to initialize the per-tenant barrier.
func (m *Manager) initTenantBarrierInternal(ctx context.Context, tenantID string) error {
	req := &quicbaassdk.QRDBTenantBarrierInitRequest{
		TenantID: tenantID,
	}

	if err := m.tenantBarrierClient.TenantBarrierInit(ctx, req); err != nil {
		return ErrBarrierOperationFailed{
			TenantID:  tenantID,
			Operation: "init",
			Err:       err,
		}
	}

	return nil
}
