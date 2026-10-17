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
	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/barrier"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant/quota"
)

// TenantBarrierClient defines the interface for per-tenant barrier operations.
// This interface is satisfied by the QRDB TenantClient
// (quicbaassdk.QRDBTenantClient) from the go-quicbaas SDK and gives the
// platform tenant manager full lifecycle control over per-tenant barriers
// (init, unseal, seal, status) across every QRDB transport (REST, gRPC, QUIC,
// MCP, Unix).
type TenantBarrierClient interface {
	// TenantBarrierInit initializes a per-tenant barrier.
	TenantBarrierInit(ctx context.Context, req *quicbaassdk.QRDBTenantBarrierInitRequest) error

	// TenantBarrierUnseal unseals a per-tenant barrier.
	TenantBarrierUnseal(ctx context.Context, req *quicbaassdk.QRDBTenantBarrierUnsealRequest) error

	// TenantBarrierSeal seals a per-tenant barrier, refusing further reads
	// and writes against the tenant namespace until unsealed again.
	TenantBarrierSeal(ctx context.Context, req *quicbaassdk.QRDBTenantBarrierSealRequest) error

	// TenantBarrierStatus reports the current sealed/initialized state and
	// active strategy metadata of a per-tenant barrier.
	TenantBarrierStatus(ctx context.Context, req *quicbaassdk.QRDBTenantBarrierStatusRequest) (*quicbaassdk.QRDBTenantBarrierStatusResponse, error)
}

// TenantBarrierState describes the current state of a per-tenant barrier as
// returned by Manager.TenantBarrierStatus. It mirrors the SDK's
// QRDBTenantBarrierStatusResponse without exposing the wire-level type to
// platform callers.
type TenantBarrierState struct {
	// TenantID is the tenant whose barrier is being reported on.
	TenantID string

	// Sealed is true when the tenant barrier is in sealed state.
	Sealed bool

	// Initialized is true when the tenant barrier has been registered and
	// initialized at least once via TenantBarrierInit.
	Initialized bool

	// Strategy identifies the active sealing strategy (e.g. "software",
	// "shamir", "pkcs11").
	Strategy string

	// HardwareBacked is true when the active strategy uses dedicated
	// cryptographic hardware (HSM, TPM, etc.).
	HardwareBacked bool
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

// RoleReconciler provisions an IAM tenant's built-in roles. It is satisfied by
// the quicbaas SDK's iam.RoleClient: Reconcile seeds every absent built-in
// role, re-permissions drifted ones, never touches custom roles, and writes
// nothing on a tenant that already matches.
type RoleReconciler interface {
	Reconcile(ctx context.Context, tenantID string) (*iam.ReconcileRolesResponse, error)
}

// Manager coordinates all tenant lifecycle operations.
// It wraps QuicBaaS IAM operations and adds platform-specific orchestration
// for quota enforcement, DEK isolation, and per-tenant barrier management.
//
// A tenant has no network identity of its own yet: the per-tenant VLAN range
// and OVS bridge were retired with the reference network (#708), and a
// tenant's routing domain becomes a VRF (plan §5.3).
type Manager struct {
	// QuicBaaS IAM SDK tenant client for tenant CRUD
	iamTenantClient iam.TenantClient

	// QuicBaaS IAM SDK role client that provisions each tenant's default roles
	iamRoleClient RoleReconciler

	// Tenant DEK client for per-tenant DEK isolation
	dekClient TenantDEKClient

	// Per-tenant barrier client for barrier init/unseal
	tenantBarrierClient TenantBarrierClient

	// Platform barrier manager for global barrier awareness
	barrierManager *barrier.Manager

	// Component managers
	quotaEnforcer *quota.Enforcer
	usageTracker  *quota.Tracker

	// Configuration
	config *Config
	logger *slog.Logger

	// Runtime state - using sync.Map for lock-free concurrent access
	cache sync.Map // map[string]*TenantEntity
}

// ManagerConfig holds manager dependencies.
type ManagerConfig struct {
	IAMTenantClient     iam.TenantClient
	IAMRoleClient       RoleReconciler
	DEKClient           TenantDEKClient
	TenantBarrierClient TenantBarrierClient
	BarrierManager      *barrier.Manager
	QuotaEnforcer       *quota.Enforcer
	UsageTracker        *quota.Tracker
	Config              *Config
	Logger              *slog.Logger
}

// CreateTenantRequest contains parameters for creating a new tenant.
type CreateTenantRequest struct {
	Name        string
	DisplayName string
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

	if cfg.IAMTenantClient == nil {
		return nil, ErrInvalidRequest{Reason: "IAM tenant client is required"}
	}

	if cfg.IAMRoleClient == nil {
		return nil, ErrInvalidRequest{Reason: "IAM role client is required"}
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
		iamTenantClient:     cfg.IAMTenantClient,
		iamRoleClient:       cfg.IAMRoleClient,
		dekClient:           cfg.DEKClient,
		tenantBarrierClient: cfg.TenantBarrierClient,
		barrierManager:      cfg.BarrierManager,
		quotaEnforcer:       cfg.QuotaEnforcer,
		usageTracker:        cfg.UsageTracker,
		config:              cfg.Config,
		logger:              cfg.Logger,
	}

	return m, nil
}

// CreateTenant creates a new tenant with full resource provisioning.
// Steps:
// 1. Create in QuicBaaS IAM
// 2. Initialize quotas
// 3. Create DEK (if enabled)
// 4. Initialize per-tenant barrier (if barrier client configured)
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

	// Step 1b: Provision the tenant's default roles. Users are mirrored
	// into IAM by role name, so a tenant without them cannot hold a user.
	if err := m.EnsureDefaultRoles(ctx, tenantID); err != nil {
		return nil, err
	}

	// Create entity from IAM response
	entity := FromIAM(iamTenant)
	entity.ID = tenantID
	entity.DisplayName = req.DisplayName
	if entity.DisplayName == "" {
		entity.DisplayName = req.Name
	}
	entity.State = StateCreated
	entity.Labels = req.Labels
	entity.Annotations = req.Annotations

	// Step 2: Initialize quotas
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

	// Step 3: Create DEK (if enabled)
	if m.config.EnableDEKIsolation {
		dekPath, err := m.ensureTenantDEK(ctx, tenantID)
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
			if delErr := m.deleteTenantDEK(ctx, tenantID); delErr != nil {
				m.logger.Error("failed to rollback DEK",
					slog.String("tenant_id", tenantID),
					slog.Any("error", delErr),
				)
			}
		})
	}

	// Step 4: Initialize per-tenant barrier (non-fatal on failure)
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

	// Persist the display name and platform record; a failure rolls the
	// IAM tenant and DEK back like any other step.
	if err := m.store(ctx, "CreateTenant", entity); err != nil {
		return nil, err
	}

	// Clear rollback actions since we succeeded
	rollbackActions = nil

	m.logger.Info("tenant created successfully",
		slog.String("tenant_id", tenantID),
		slog.String("name", req.Name),
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

	entity, err := m.entityFromIAM("GetTenant", iamTenant)
	if err != nil {
		return nil, err
	}

	// Cache and return; an entity cached meanwhile (a concurrent create or
	// state change) wins over the IAM copy.
	cached, _ := m.cache.LoadOrStore(id, entity)

	return cached.(*TenantEntity).Clone(), nil
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

	entity, err := m.entityFromIAM("GetTenantByName", iamTenant)
	if err != nil {
		return nil, err
	}

	// Cache and return; an entity cached meanwhile (a concurrent create or
	// state change) wins over the IAM copy.
	cached, _ := m.cache.LoadOrStore(entity.ID, entity)

	return cached.(*TenantEntity).Clone(), nil
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
		entity, err := m.entityFromIAM("ListTenants", &t)
		if err != nil {
			return nil, 0, err
		}

		// A cached entity is the one this daemon last stored, and it wins
		// over the IAM copy a concurrent write may not have reached yet.
		cached, _ := m.cache.LoadOrStore(entity.ID, entity)
		entities = append(entities, cached.(*TenantEntity).Clone())
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

	if err := m.store(ctx, "UpdateTenant", entity); err != nil {
		return nil, err
	}

	m.logger.Info("tenant updated successfully",
		slog.String("tenant_id", id),
	)

	return entity.Clone(), nil
}

// DeleteTenant deletes a tenant and all its resources.
// Steps:
// 1. Set state to deleting
// 2. Delete DEK
// 3. Seal the per-tenant barrier
// 4. Delete from QuicBaaS IAM
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
	if err := m.store(ctx, "DeleteTenant", entity); err != nil {
		return err
	}

	// Step 2: Delete DEK
	if m.config.EnableDEKIsolation && entity.DEKPath != "" {
		if err := m.deleteTenantDEK(ctx, id); err != nil {
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

	// Step 3: Seal the per-tenant barrier before IAM tenant deletion so any
	// in-flight reads/writes are refused while the metadata cleanup runs.
	// A failed seal is logged but does not block deletion — the IAM delete
	// below removes the underlying QRDB tenant record which implicitly
	// tears down the barrier registry entry.
	if m.tenantBarrierClient != nil {
		sealReq := &quicbaassdk.QRDBTenantBarrierSealRequest{TenantID: id}
		if err := m.tenantBarrierClient.TenantBarrierSeal(ctx, sealReq); err != nil {
			m.logger.Warn("failed to seal per-tenant barrier before delete",
				slog.String("tenant_id", id),
				slog.Any("error", err),
			)
		} else {
			m.logger.Info("per-tenant barrier sealed before IAM delete",
				slog.String("tenant_id", id),
			)
		}
	}

	// Step 4: Delete from QuicBaaS IAM
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

// SuspendTenant moves a tenant to the suspended state. Blocking the
// tenant's traffic belongs to its VRF (plan §5.3); until tenancy has a
// routing domain, suspension is a state change only.
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

	entity.UpdatedAt = time.Now()
	if err := m.store(ctx, "SuspendTenant", entity); err != nil {
		return err
	}

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

	// Transition state
	if err := entity.SetState(StateActive); err != nil {
		return err
	}

	entity.UpdatedAt = time.Now()
	if err := m.store(ctx, "ResumeTenant", entity); err != nil {
		return err
	}

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

	// Only limits come from the request; the usage counters are the
	// tenant's own and survive every update.
	entity.ComputeQuota.SetLimits(quotas.Compute)
	entity.NetworkQuota.SetLimits(quotas.Network)
	entity.StorageQuota.SetLimits(quotas.Storage)
	entity.UpdatedAt = time.Now()

	if err := m.store(ctx, "UpdateQuotas", entity); err != nil {
		return err
	}

	m.logger.Info("tenant quotas updated successfully",
		slog.String("tenant_id", tenantID),
	)

	return nil
}

// GetUsage returns tenant resource usage. When the usage tracker is not
// configured (a daemon wired with IAM-only tenant management), the usage is
// the counters the tenant entity carries; an unknown tenant is
// ErrTenantNotFound.
func (m *Manager) GetUsage(ctx context.Context, tenantID string) (*quota.TenantUsage, error) {
	if m.usageTracker != nil {
		return m.usageTracker.GetAllUsage(ctx, tenantID)
	}

	entity, err := m.GetTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	return entityUsage(entity), nil
}

// CheckQuota checks if a resource request can be fulfilled. Without a quota
// enforcer it checks the request against the tenant entity's own limits and
// usage: an unknown tenant is ErrTenantNotFound and a request beyond the
// remaining capacity is ErrQuotaExceeded.
func (m *Manager) CheckQuota(ctx context.Context, tenantID string, resource quota.ResourceType, amount int64) error {
	if m.quotaEnforcer != nil {
		return m.quotaEnforcer.CheckQuota(ctx, tenantID, resource, amount)
	}

	if !resource.IsValid() {
		return ErrInvalidRequest{Reason: "invalid quota resource: " + string(resource)}
	}
	if amount < 0 {
		return ErrInvalidRequest{Reason: "quota amount must not be negative"}
	}

	entity, err := m.GetTenant(ctx, tenantID)
	if err != nil {
		return err
	}

	available := entityLimits(entity).GetLimit(resource) - entityUsage(entity).GetUsage(resource)
	if amount > available {
		return ErrQuotaExceeded{
			TenantID:  tenantID,
			Resource:  string(resource),
			Requested: amount,
			Available: available,
		}
	}

	return nil
}

// entityUsage reports the usage counters the tenant entity carries beside
// its limits (docs/tenant/engineering.md §3). The entity measures its volume
// dimension in gigabytes and keeps no bandwidth counter.
func entityUsage(entity *TenantEntity) *quota.TenantUsage {
	return &quota.TenantUsage{
		TenantID:   entity.ID,
		VMs:        entity.ComputeQuota.UsedVMs,
		Containers: entity.ComputeQuota.UsedContainers,
		VCPUs:      entity.ComputeQuota.UsedVCPUs,
		MemoryMB:   entity.ComputeQuota.UsedMemoryMB,
		DiskGB:     entity.ComputeQuota.UsedDiskGB,
		Bridges:    entity.NetworkQuota.UsedBridges,
		Ports:      entity.NetworkQuota.UsedPorts,
		Volumes:    entity.StorageQuota.UsedVolumesGB,
		Snapshots:  entity.StorageQuota.UsedSnapshots,
		Timestamp:  time.Now(),
	}
}

// entityLimits reports the tenant entity's limits in the quota package's
// shape, so a resource name resolves to its limit in one place.
func entityLimits(entity *TenantEntity) *quota.TenantQuotas {
	return &quota.TenantQuotas{
		TenantID: entity.ID,
		Compute: quota.ComputeQuota{
			MaxVMs:        entity.ComputeQuota.MaxVMs,
			MaxContainers: entity.ComputeQuota.MaxContainers,
			MaxVCPUs:      entity.ComputeQuota.MaxVCPUs,
			MaxMemoryMB:   entity.ComputeQuota.MaxMemoryMB,
		},
		Network: quota.NetworkQuota{
			MaxBridges:       entity.NetworkQuota.MaxBridges,
			MaxPorts:         entity.NetworkQuota.MaxPorts,
			MaxBandwidthMbps: entity.NetworkQuota.MaxBandwidthMbps,
		},
		Storage: quota.StorageQuota{
			MaxDiskGB:    entity.ComputeQuota.MaxDiskGB,
			MaxVolumes:   entity.StorageQuota.MaxVolumesGB,
			MaxSnapshots: entity.StorageQuota.MaxSnapshots,
		},
		UpdatedAt: entity.UpdatedAt,
	}
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

// RotateTenantDEK rotates the DEK for a tenant.
//
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

	req := &RotateTenantDEKRequest{
		TenantID:              tenantID,
		Reason:                fmt.Sprintf("tenant DEK rotation for %s", tenantID),
		AutoStartReencryption: background,
	}

	resp, err := m.dekClient.RotateTenantDEK(ctx, req)
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
		Timestamp:  resp.RotatedAt,
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

	resp, err := m.dekClient.TenantDEKStatus(ctx, &TenantDEKStatusRequest{TenantID: tenantID})
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
		Path:      entity.DEKPath,
		Algorithm: resp.Algorithm,
		Version:   resp.CurrentVersion,
		CreatedAt: resp.CreatedAt,
	}

	if resp.RotatedAt != nil {
		status.RotatedAt = *resp.RotatedAt
	}

	// Include re-encryption progress if available
	if resp.ReencryptionInProgress {
		status.ReencryptProgress = &ReencryptionProgress{
			InProgress: true,
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

// SealTenantBarrier seals a per-tenant barrier, returning it to the sealed
// state. Subsequent reads and writes against the tenant's namespace fail
// until the barrier is unsealed again via UnsealTenantBarrier. The tenant
// must exist and its barrier must have been previously initialized.
func (m *Manager) SealTenantBarrier(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return ErrInvalidRequest{Reason: "tenant ID is required"}
	}
	if m.tenantBarrierClient == nil {
		return ErrBarrierNotSupported{Operation: "SealTenantBarrier"}
	}

	req := &quicbaassdk.QRDBTenantBarrierSealRequest{TenantID: tenantID}
	if err := m.tenantBarrierClient.TenantBarrierSeal(ctx, req); err != nil {
		return ErrStorageFailed{Operation: "SealTenantBarrier", Err: err}
	}

	m.logger.Info("per-tenant barrier sealed", slog.String("tenant_id", tenantID))

	return nil
}

// TenantBarrierStatus returns the current sealed/initialized state and active
// strategy metadata of a per-tenant barrier. When the barrier has never been
// registered the response carries Sealed=true, Initialized=false, and an
// empty Strategy — callers can use the Initialized flag to decide whether to
// call InitTenantBarrier first.
func (m *Manager) TenantBarrierStatus(ctx context.Context, tenantID string) (*TenantBarrierState, error) {
	if tenantID == "" {
		return nil, ErrInvalidRequest{Reason: "tenant ID is required"}
	}
	if m.tenantBarrierClient == nil {
		return nil, ErrBarrierNotSupported{Operation: "TenantBarrierStatus"}
	}

	req := &quicbaassdk.QRDBTenantBarrierStatusRequest{TenantID: tenantID}
	resp, err := m.tenantBarrierClient.TenantBarrierStatus(ctx, req)
	if err != nil {
		return nil, ErrStorageFailed{Operation: "TenantBarrierStatus", Err: err}
	}
	if resp == nil {
		return nil, ErrStorageFailed{Operation: "TenantBarrierStatus", Err: ErrNilBarrierStatus}
	}

	return &TenantBarrierState{
		TenantID:       resp.TenantID,
		Sealed:         resp.Sealed,
		Initialized:    resp.Initialized,
		Strategy:       resp.Strategy,
		HardwareBacked: resp.HardwareBacked,
	}, nil
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
// IAM integration methods (using go-quicbaas SDK)
// ---------------------------------------------------------------------------

func (m *Manager) createInIAM(ctx context.Context, id, name string) (*iam.Tenant, error) {
	req := &iam.CreateTenantRequest{
		ID:   id,
		Name: name,
	}

	tenant, err := m.iamTenantClient.Create(ctx, req)
	if err != nil {
		return nil, err
	}

	return tenant, nil
}

// EnsureDefaultRoles provisions the IAM tenant's built-in roles through the
// SDK. It is idempotent: on a tenant that already carries them it writes
// nothing, and it never alters a custom role. CreateTenant calls it for every
// new tenant; the startup user reconcile calls it for tenants created before
// the roles were provisioned.
func (m *Manager) EnsureDefaultRoles(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return ErrInvalidRequest{Reason: "tenant ID is required"}
	}

	resp, err := m.iamRoleClient.Reconcile(ctx, tenantID)
	if err != nil {
		m.logger.Error("failed to provision default IAM roles",
			slog.String("tenant_id", tenantID),
			slog.Any("error", err),
		)
		return ErrDefaultRolesFailed{TenantID: tenantID, Err: err}
	}

	if resp != nil && resp.Changed {
		created := make([]string, 0, len(resp.Roles))
		for _, role := range resp.Roles {
			if role.Created {
				created = append(created, role.Name)
			}
		}
		m.logger.Info("provisioned default IAM roles",
			slog.String("tenant_id", tenantID),
			slog.Any("created", created),
		)
	}

	return nil
}

func (m *Manager) getFromIAM(ctx context.Context, id string) (*iam.Tenant, error) {
	tenant, err := m.iamTenantClient.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	return tenant, nil
}

func (m *Manager) getFromIAMByName(ctx context.Context, name string) (*iam.Tenant, error) {
	// Use List with a large page size to find by name
	req := &iam.ListTenantsRequest{
		PageSize: 100,
	}

	resp, err := m.iamTenantClient.List(ctx, req)
	if err != nil {
		return nil, err
	}

	for i := range resp.Tenants {
		if resp.Tenants[i].Name == name {
			return &resp.Tenants[i], nil
		}
	}

	return nil, ErrTenantNotFound{Name: name}
}

func (m *Manager) listFromIAM(ctx context.Context, limit, offset int) ([]iam.Tenant, int, error) {
	req := &iam.ListTenantsRequest{
		PageSize: limit,
	}

	resp, err := m.iamTenantClient.List(ctx, req)
	if err != nil {
		return nil, 0, err
	}

	// Apply offset client-side since SDK uses token-based pagination
	tenants := resp.Tenants
	if offset > 0 && offset < len(tenants) {
		tenants = tenants[offset:]
	} else if offset >= len(tenants) {
		tenants = nil
	}

	return tenants, resp.Pagination.TotalCount, nil
}

func (m *Manager) updateInIAM(ctx context.Context, entity *TenantEntity) error {
	metadata, err := entity.platformMetadata()
	if err != nil {
		return err
	}

	// The display name travels in the platform record, never as IAM's
	// DisplayName: the pinned go-quicbaas embedded handleIAMTenantUpdate
	// (sdk/go/transport/embedded/handlers_iam.go:204-208) writes that field
	// into the tenant's canonical name, so sending it renames the tenant.
	req := &iam.UpdateTenantRequest{
		Metadata: metadata,
		Status:   entity.iamStatus(),
	}

	_, err = m.iamTenantClient.Update(ctx, entity.ID, req)
	return err
}

// store persists the entity's platform record in IAM, then caches it, so the
// cache never holds a tenant state IAM has not accepted and a restarted
// daemon reads back what it last served (docs/tenant/engineering.md §6).
func (m *Manager) store(ctx context.Context, operation string, entity *TenantEntity) error {
	if err := m.updateInIAM(ctx, entity); err != nil {
		return ErrStorageFailed{Operation: operation, Err: err}
	}
	m.cache.Store(entity.ID, entity)
	return nil
}

// entityFromIAM builds the entity an IAM tenant persists: the identity fields
// FromIAM maps, the platform record the tenant manager stored in its metadata,
// and the DEK path.
func (m *Manager) entityFromIAM(operation string, t *iam.Tenant) (*TenantEntity, error) {
	entity := FromIAM(t)
	if err := entity.restorePlatformRecord(t); err != nil {
		return nil, ErrStorageFailed{Operation: operation, Err: err}
	}
	if m.config.EnableDEKIsolation {
		entity.DEKPath = BuildDEKPath(entity.ID)
	}
	return entity, nil
}

func (m *Manager) deleteFromIAM(ctx context.Context, id string) error {
	return m.iamTenantClient.Delete(ctx, id)
}

// ---------------------------------------------------------------------------
// DEK integration methods (using the go-quicbaas DEK SDK via TenantDEKClient)
// ---------------------------------------------------------------------------

func (m *Manager) ensureTenantDEK(ctx context.Context, tenantID string) (string, error) {
	if m.dekClient == nil {
		return "", ErrInvalidRequest{Reason: "DEK client is not configured"}
	}

	req := &EnsureTenantDEKRequest{
		TenantID:  tenantID,
		Algorithm: m.config.DEKAlgorithm,
	}

	resp, err := m.dekClient.EnsureTenantDEK(ctx, req)
	if err != nil {
		return "", err
	}

	return resp.DEKID, nil
}

func (m *Manager) deleteTenantDEK(ctx context.Context, tenantID string) error {
	if m.dekClient == nil {
		return ErrInvalidRequest{Reason: "DEK client is not configured"}
	}

	req := &DeleteTenantDEKRequest{
		TenantID: tenantID,
	}

	if _, err := m.dekClient.DeleteTenantDEK(ctx, req); err != nil {
		return err
	}
	return nil
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
