# Tenant Isolation Mechanisms

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [architecture.md](architecture.md). `platformd serve` builds the tenant manager with `EnableDEKIsolation` off (`pkg/daemon/commands/serve_tenant.go:67`), so no per-tenant DEK is created on that path.

This document describes the tenant isolation mechanisms of the Trusted Platform across storage, cryptographic and policy boundaries.

> **Network isolation is not provided by this feature.** The per-tenant OVS
> bridge and VLAN range described in earlier revisions were retired by #708.
> Under the [reference network](../architecture/reference-network.md) tenant
> networks are EVPN/VXLAN overlays and a tenant's routing domain is a VRF,
> delivered by the tenancy work that follows the overlay transport (#709).
> [architecture.md](architecture.md) is normative where this file disagrees.

## Isolation Overview

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║                         TENANT ISOLATION LAYERS                               ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  Layer 5: Policy Isolation                                                    ║
║  ┌─────────────────────────────────────────────────────────────────────────┐  ║
║  │  Access Control │ RBAC Policies │ Audit Logging │ Compliance Rules     │  ║
║  └─────────────────────────────────────────────────────────────────────────┘  ║
║                                                                               ║
║  Layer 4: Key Isolation                                                       ║
║  ┌─────────────────────────────────────────────────────────────────────────┐  ║
║  │  Per-Tenant DEK │ TPM Sealing │ Key Hierarchy │ Rotation Policies      │  ║
║  └─────────────────────────────────────────────────────────────────────────┘  ║
║                                                                               ║
║  Layer 3: Storage Isolation                                                   ║
║  ┌─────────────────────────────────────────────────────────────────────────┐  ║
║  │  Namespace Separation │ Path Isolation │ Quota Enforcement             │  ║
║  └─────────────────────────────────────────────────────────────────────────┘  ║
║                                                                               ║
║  Layer 2: Compute Isolation                                                   ║
║  ┌─────────────────────────────────────────────────────────────────────────┐  ║
║  │  VM/Container Boundaries │ Resource Limits │ cgroups/namespaces        │  ║
║  └─────────────────────────────────────────────────────────────────────────┘  ║
║                                                                               ║
║  Layer 1: Network Isolation                                                   ║
║  ┌─────────────────────────────────────────────────────────────────────────┐  ║
║  │  Tenant VRF on the EVPN overlay (not yet implemented, see above)       │  ║
║  └─────────────────────────────────────────────────────────────────────────┘  ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
```

## Network Isolation

None in this feature yet; see the note at the top. The former sections on
per-tenant OVS bridges, VLAN namespaces, VLAN allocation and per-bridge
OpenFlow rules described code that was deleted by #708.

## Storage Isolation

### Namespace Separation

Each tenant has a dedicated storage namespace:

```
/var/lib/platformd/
├── tenants/
│   ├── engineering/
│   │   ├── vms/
│   │   │   ├── vm-001/
│   │   │   │   ├── disk.qcow2
│   │   │   │   ├── config.yaml
│   │   │   │   └── tpm/
│   │   │   └── vm-002/
│   │   ├── volumes/
│   │   ├── snapshots/
│   │   └── config/
│   │
│   ├── production/
│   │   ├── vms/
│   │   ├── volumes/
│   │   ├── snapshots/
│   │   └── config/
│   │
│   └── staging/
│       ├── vms/
│       ├── volumes/
│       ├── snapshots/
│       └── config/
└── shared/
    ├── images/      # Read-only base images
    └── templates/   # Shared templates
```

### Path Isolation

```go
// PathIsolator ensures tenant can only access their paths
type PathIsolator struct {
    basePath string
}

// ResolvePath validates and resolves tenant-scoped path
func (pi *PathIsolator) ResolvePath(tenantID, relativePath string) (string, error) {
    // Sanitize input
    cleaned := filepath.Clean(relativePath)
    if strings.Contains(cleaned, "..") {
        return "", ErrPathTraversal{Path: relativePath}
    }

    // Build tenant-scoped path
    tenantPath := filepath.Join(pi.basePath, "tenants", tenantID, cleaned)

    // Verify path is within tenant directory
    if !strings.HasPrefix(tenantPath, filepath.Join(pi.basePath, "tenants", tenantID)) {
        return "", ErrPathEscape{
            TenantID: tenantID,
            Path:     relativePath,
        }
    }

    return tenantPath, nil
}

// EnsureNamespace creates tenant storage namespace
func (pi *PathIsolator) EnsureNamespace(tenantID string) error {
    dirs := []string{
        filepath.Join(pi.basePath, "tenants", tenantID, "vms"),
        filepath.Join(pi.basePath, "tenants", tenantID, "volumes"),
        filepath.Join(pi.basePath, "tenants", tenantID, "snapshots"),
        filepath.Join(pi.basePath, "tenants", tenantID, "config"),
    }

    for _, dir := range dirs {
        if err := os.MkdirAll(dir, 0750); err != nil {
            return ErrNamespaceCreationFailed{
                TenantID: tenantID,
                Path:     dir,
                Cause:    err,
            }
        }
    }

    return nil
}
```

## Key Isolation

### Per-Tenant DEK Architecture

```
                     TPM 2.0
┌────────────────────────────────────────────────────────────────┐
│                                                                │
│  ┌────────────────────┐                                        │
│  │ Platform Master Key│  (Stored in TPM, never exported)       │
│  │ Handle: 0x81000002 │                                        │
│  └──────────┬─────────┘                                        │
│             │                                                  │
│             │ (Derives KEK per tenant)                         │
│             │                                                  │
│  ┌──────────▼───────────────────────────────────────────────┐  │
│  │                    KEY HIERARCHY                         │  │
│  │                                                          │  │
│  │  ┌───────────────┐  ┌───────────────┐                    │  │
│  │  │ KEK-eng       │  │ KEK-prod      │  ...               │  │
│  │  │ (Engineering) │  │ (Production)  │                    │  │
│  │  └───────┬───────┘  └───────┬───────┘                    │  │
│  │          │                  │                            │  │
│  │  ┌───────▼───────┐  ┌───────▼───────┐                    │  │
│  │  │ DEK-eng       │  │ DEK-prod      │  ...               │  │
│  │  │ (TPM Sealed)  │  │ (TPM Sealed)  │                    │  │
│  │  └───────────────┘  └───────────────┘                    │  │
│  │                                                          │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

### DEK Creation

```go
// DEKManager manages per-tenant data encryption keys
type DEKManager struct {
    tpm    *tpm.Service
    kms    *kms.Service
    logger *logging.Logger
}

// CreateTenantDEK generates and seals a DEK for a tenant
func (dm *DEKManager) CreateTenantDEK(ctx context.Context, tenantID string) (*DEKInfo, error) {
    // Generate random DEK (256-bit AES key)
    dek := make([]byte, 32)
    if _, err := rand.Read(dek); err != nil {
        return nil, ErrDEKGenerationFailed{TenantID: tenantID, Cause: err}
    }

    // Create unique CN for this tenant's DEK
    cn := fmt.Sprintf("tenant-%s-dek", tenantID)

    // Seal DEK to TPM with PCR policy
    sealReq := &tpm.SealRequest{
        Data:         dek,
        CN:           cn,
        ParentHandle: 0x81000002, // Platform SRK
        PCRIndices:   []int{0, 1, 2, 3, 7},
        PCRBank:      tpm.PCRBankSHA256,
    }

    sealResp, err := dm.tpm.Seal(ctx, sealReq)
    if err != nil {
        return nil, ErrDEKSealingFailed{TenantID: tenantID, Cause: err}
    }

    // Clear DEK from memory immediately
    for i := range dek {
        dek[i] = 0
    }

    return &DEKInfo{
        TenantID:   tenantID,
        CN:         cn,
        Handle:     sealResp.Handle,
        CreatedAt:  time.Now(),
    }, nil
}

// GetTenantDEK unseals and returns the tenant's DEK
func (dm *DEKManager) GetTenantDEK(ctx context.Context, tenantID string, handle uint32) ([]byte, error) {
    // Verify caller has access to this tenant
    callerTenant := TenantFromContext(ctx)
    if callerTenant.ID != tenantID {
        return nil, ErrDEKAccessDenied{
            CallerTenant:  callerTenant.ID,
            RequestedTenant: tenantID,
        }
    }

    // Unseal from TPM
    unsealReq := &tpm.UnsealRequest{
        Handle: handle,
    }

    unsealResp, err := dm.tpm.Unseal(ctx, unsealReq)
    if err != nil {
        return nil, ErrDEKUnsealFailed{TenantID: tenantID, Cause: err}
    }

    return unsealResp.Data, nil
}
```

### Key Rotation

```go
// RotateTenantDEK creates a new DEK and re-encrypts data
func (dm *DEKManager) RotateTenantDEK(ctx context.Context, tenantID string) error {
    dm.logger.Info("Starting DEK rotation", "tenant_id", tenantID)

    // Get current DEK
    tenant, err := dm.tenantMgr.Get(ctx, tenantID)
    if err != nil {
        return err
    }

    oldDEK, err := dm.GetTenantDEK(ctx, tenantID, tenant.DEKHandle)
    if err != nil {
        return err
    }
    defer clearBytes(oldDEK)

    // Create new DEK
    newDEKInfo, err := dm.CreateTenantDEK(ctx, tenantID)
    if err != nil {
        return err
    }

    newDEK, err := dm.GetTenantDEK(ctx, tenantID, newDEKInfo.Handle)
    if err != nil {
        return err
    }
    defer clearBytes(newDEK)

    // Re-encrypt all tenant data
    if err := dm.reencryptTenantData(ctx, tenantID, oldDEK, newDEK); err != nil {
        return ErrDEKRotationFailed{TenantID: tenantID, Cause: err}
    }

    // Update tenant with new DEK handle
    tenant.DEKHandle = newDEKInfo.Handle
    if err := dm.tenantMgr.Update(ctx, tenant); err != nil {
        return err
    }

    // Delete old DEK
    if err := dm.tpm.DeleteKey(ctx, tenant.DEKHandle); err != nil {
        dm.logger.Warn("Failed to delete old DEK", "handle", tenant.DEKHandle, "error", err)
    }

    dm.logger.Info("DEK rotation completed", "tenant_id", tenantID)
    return nil
}
```

## Policy Isolation

### Tenant-Scoped RBAC

```go
// PolicyEnforcer implements tenant-scoped access control
type PolicyEnforcer struct {
    policies map[string]*TenantPolicy
    mu       sync.RWMutex
}

// TenantPolicy defines access rules for a tenant
type TenantPolicy struct {
    TenantID string
    Rules    []PolicyRule
}

// PolicyRule defines a single access rule
type PolicyRule struct {
    Subject    string   // User or role
    Resource   string   // Resource type (vm, container, volume, etc.)
    Actions    []string // Allowed actions (create, read, update, delete)
    Conditions []Condition
}

// Evaluate checks if an action is allowed
func (pe *PolicyEnforcer) Evaluate(ctx context.Context, req *PolicyRequest) (*PolicyDecision, error) {
    pe.mu.RLock()
    defer pe.mu.RUnlock()

    // Get caller's tenant
    callerTenant := TenantFromContext(ctx)

    // Get target resource's tenant
    resourceTenant := req.ResourceTenantID

    // Check tenant boundary
    if callerTenant.ID != resourceTenant {
        // Cross-tenant access - check if allowed
        if !pe.isCrossTenantAllowed(callerTenant.ID, resourceTenant, req.Resource, req.Action) {
            return &PolicyDecision{
                Allowed: false,
                Reason:  "Cross-tenant access denied",
            }, nil
        }
    }

    // Evaluate tenant-specific policies
    policy, ok := pe.policies[callerTenant.ID]
    if !ok {
        return &PolicyDecision{
            Allowed: false,
            Reason:  "No policy defined for tenant",
        }, nil
    }

    for _, rule := range policy.Rules {
        if pe.matchesRule(req, &rule) {
            return &PolicyDecision{
                Allowed: true,
                Rule:    &rule,
            }, nil
        }
    }

    return &PolicyDecision{
        Allowed: false,
        Reason:  "No matching policy rule",
    }, nil
}
```

### Audit Logging

```go
// AuditLogger records tenant-scoped audit events
type AuditLogger struct {
    db     *quicbaas.Client
    logger *logging.Logger
}

// AuditEvent represents an auditable action
type AuditEvent struct {
    ID          uint64    `quicbaas:"pk"`
    TenantID    string    `quicbaas:"index"`
    Timestamp   time.Time `quicbaas:"index"`
    Actor       string    // User or service
    Action      string    // create, read, update, delete
    Resource    string    // Resource type
    ResourceID  string    // Resource identifier
    Result      string    // success, denied, error
    Details     map[string]string
    SourceIP    string
    RequestID   string
}

// Log records an audit event
func (al *AuditLogger) Log(ctx context.Context, event *AuditEvent) error {
    event.ID = generateID()
    event.Timestamp = time.Now()
    event.TenantID = TenantFromContext(ctx).ID

    data, err := json.Marshal(event)
    if err != nil {
        return err
    }

    return al.db.Put(ctx, "audit_event", event.ID, data)
}

// QueryByTenant retrieves audit events for a tenant
func (al *AuditLogger) QueryByTenant(ctx context.Context, tenantID string, filter *AuditFilter) ([]*AuditEvent, error) {
    // Verify caller has access to this tenant's audit logs
    callerTenant := TenantFromContext(ctx)
    if callerTenant.ID != tenantID && !callerTenant.IsPlatformAdmin {
        return nil, ErrAuditAccessDenied{
            CallerTenant: callerTenant.ID,
            TargetTenant: tenantID,
        }
    }

    entities, err := al.db.Query(ctx, "audit_event", "tenant_id", []byte(tenantID))
    if err != nil {
        return nil, err
    }

    var events []*AuditEvent
    for _, entity := range entities {
        var event AuditEvent
        if err := json.Unmarshal(entity.Data, &event); err != nil {
            continue
        }
        if filter.Matches(&event) {
            events = append(events, &event)
        }
    }

    return events, nil
}
```

## Quota Enforcement

### Resource Quota Checking

```go
// QuotaEnforcer validates resource requests against tenant quotas
type QuotaEnforcer struct {
    tenantMgr *TenantManager
    db        *quicbaas.Client
}

// CheckQuota validates if a resource request is within quota
func (qe *QuotaEnforcer) CheckQuota(ctx context.Context, req *QuotaCheckRequest) error {
    tenant, err := qe.tenantMgr.Get(ctx, req.TenantID)
    if err != nil {
        return err
    }

    switch req.ResourceType {
    case "vm":
        return qe.checkComputeQuota(tenant, req)
    case "port":
        return qe.checkNetworkQuota(tenant, req)
    case "volume":
        return qe.checkStorageQuota(tenant, req)
    default:
        return ErrUnknownResourceType{Type: req.ResourceType}
    }
}

func (qe *QuotaEnforcer) checkComputeQuota(tenant *Tenant, req *QuotaCheckRequest) error {
    quota := tenant.ComputeQuota

    // Check VM count
    if req.ResourceType == "vm" {
        if quota.UsedVMs >= quota.MaxVMs {
            return ErrQuotaExceeded{
                TenantID: tenant.ID,
                Resource: "vms",
                Used:     quota.UsedVMs,
                Max:      quota.MaxVMs,
            }
        }
    }

    // Check vCPU
    if quota.UsedVCPUs+req.VCPUs > quota.MaxVCPUs {
        return ErrQuotaExceeded{
            TenantID: tenant.ID,
            Resource: "vcpus",
            Used:     quota.UsedVCPUs,
            Requested: req.VCPUs,
            Max:      quota.MaxVCPUs,
        }
    }

    // Check memory
    if quota.UsedMemoryMB+req.MemoryMB > quota.MaxMemoryMB {
        return ErrQuotaExceeded{
            TenantID: tenant.ID,
            Resource: "memory_mb",
            Used:     quota.UsedMemoryMB,
            Requested: req.MemoryMB,
            Max:      quota.MaxMemoryMB,
        }
    }

    return nil
}

// ReserveQuota atomically reserves quota for a resource
func (qe *QuotaEnforcer) ReserveQuota(ctx context.Context, req *QuotaReserveRequest) (*QuotaReservation, error) {
    // Use optimistic locking with QuicBaaS
    for attempts := 0; attempts < 3; attempts++ {
        tenant, err := qe.tenantMgr.Get(ctx, req.TenantID)
        if err != nil {
            return nil, err
        }

        // Check quota
        if err := qe.CheckQuota(ctx, req.ToCheckRequest()); err != nil {
            return nil, err
        }

        // Update usage
        switch req.ResourceType {
        case "vm":
            tenant.ComputeQuota.UsedVMs++
            tenant.ComputeQuota.UsedVCPUs += req.VCPUs
            tenant.ComputeQuota.UsedMemoryMB += req.MemoryMB
        }

        // Attempt to save
        if err := qe.tenantMgr.Update(ctx, tenant); err != nil {
            if isOptimisticLockError(err) {
                continue // Retry
            }
            return nil, err
        }

        return &QuotaReservation{
            ID:        generateID(),
            TenantID:  req.TenantID,
            Resources: req,
            CreatedAt: time.Now(),
        }, nil
    }

    return nil, ErrQuotaReservationFailed{TenantID: req.TenantID}
}
```

## Isolation Verification

The isolation that exists today is verified by the tenant integration suite
(`test/integration/tenant/isolation_test.go`), on all six transports:
tenant records, quotas and usage are independent, and updating or suspending
one tenant leaves another untouched. A
network isolation check arrives with the tenant VRF.

## Related Documentation

- [Architecture](architecture.md) - Multi-tenancy architecture
- [Configuration](configuration.md) - Isolation configuration options
- [SDN](../sdn/architecture.md) - Overlays and, with tenant VRFs, network isolation
- [Key Management](../kms/overview.md) - Cryptographic key isolation
