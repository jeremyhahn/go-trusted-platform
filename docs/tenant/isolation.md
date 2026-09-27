# Tenant Isolation Mechanisms

This document describes the isolation mechanisms implemented in the Trusted Platform to ensure complete separation between tenants across network, storage, cryptographic, and policy boundaries.

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
║  │  Per-Tenant OVS Bridge │ VLAN Segmentation │ OpenFlow Rules            │  ║
║  └─────────────────────────────────────────────────────────────────────────┘  ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
```

## Network Isolation

### Per-Tenant OVS Bridges

Each tenant receives a dedicated Open vSwitch bridge for network isolation:

```
                     PLATFORM HOST
┌────────────────────────────────────────────────────────────────┐
│                                                                │
│  ┌──────────────────┐    ┌──────────────────┐                  │
│  │ br-tenant-eng    │    │ br-tenant-prod   │                  │
│  │ (Engineering)    │    │ (Production)     │                  │
│  └────────┬─────────┘    └────────┬─────────┘                  │
│           │                       │                            │
│    ┌──────┴──────┐         ┌──────┴──────┐                     │
│    │      │      │         │      │      │                     │
│  ┌─▼─┐  ┌─▼─┐  ┌─▼─┐     ┌─▼─┐  ┌─▼─┐  ┌─▼─┐                  │
│  │100│  │101│  │102│     │200│  │201│  │202│                  │
│  └───┘  └───┘  └───┘     └───┘  └───┘  └───┘                  │
│  VLAN   VLAN   VLAN      VLAN   VLAN   VLAN                   │
│                                                                │
│            ISOLATED - NO CROSS-BRIDGE TRAFFIC                  │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

### Bridge Configuration

```go
// BridgeConfig for per-tenant OVS bridge
type BridgeConfig struct {
    Name         string   // br-tenant-{tenant_name}
    TenantID     string   // Owning tenant ID
    DatapathType string   // system | netdev
    FailMode     string   // standalone | secure
    STPEnabled   bool     // Spanning Tree Protocol
    MTU          int      // Maximum transmission unit
    Controllers  []string // OpenFlow controllers
}

// CreateTenantBridge creates isolated bridge for tenant
func (sdn *SDNService) CreateTenantBridge(ctx context.Context, tenant *Tenant) error {
    config := &BridgeConfig{
        Name:         fmt.Sprintf("br-tenant-%s", tenant.Name),
        TenantID:     tenant.ID,
        DatapathType: "system",
        FailMode:     "secure",  // Drop traffic if controller disconnects
        STPEnabled:   false,
        MTU:          9000,
    }

    bridge, err := sdn.ovsClient.CreateBridge(ctx, config)
    if err != nil {
        return ErrBridgeCreationFailed{TenantID: tenant.ID, Cause: err}
    }

    // Install default isolation flows
    return sdn.installIsolationFlows(ctx, bridge)
}
```

### VLAN Namespaces

VLAN ranges are allocated per-tenant to prevent VLAN hopping:

```
Tenant VLAN Allocation
┌────────────────────────────────────────────────────────────────────┐
│                                                                    │
│  Tenant: engineering    Tenant: production    Tenant: staging      │
│  ┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐│
│  │ VLANs: 100-199   │   │ VLANs: 200-299   │   │ VLANs: 300-399   ││
│  │                  │   │                  │   │                  ││
│  │ 100: web-tier    │   │ 200: web-tier    │   │ 300: web-tier    ││
│  │ 101: app-tier    │   │ 201: app-tier    │   │ 301: app-tier    ││
│  │ 102: db-tier     │   │ 202: db-tier     │   │ 302: db-tier     ││
│  │ 103-199: unused  │   │ 203-299: unused  │   │ 303-399: unused  ││
│  └──────────────────┘   └──────────────────┘   └──────────────────┘│
│                                                                    │
│                   NO VLAN ID OVERLAP ALLOWED                       │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

### VLAN Allocation

> **Code today vs. the reference design.** Tenants are isolated today by
> per-tenant VLAN ranges (`pkg/tenant/vlan`). The
> [reference network](../architecture/reference-network.md) (owner design
> decision, 2026-09-26) has no tenant VLAN range: tenant networks are
> EVPN/VXLAN overlays addressed from the environment's IPAM pool. The code change is tracked in #708.

```go
// VLANAllocator manages per-tenant VLAN ranges
type VLANAllocator struct {
    mu         sync.RWMutex
    allocations map[string]*VLANRange  // tenantID -> range
    vlansPerTenant int
}

// AllocateRange assigns a VLAN range to a tenant
func (va *VLANAllocator) AllocateRange(tenantID string) (*VLANRange, error) {
    va.mu.Lock()
    defer va.mu.Unlock()

    if existing, ok := va.allocations[tenantID]; ok {
        return existing, nil
    }

    // Find next available range
    nextStart := va.findNextAvailable()
    if nextStart+va.vlansPerTenant > 4094 {
        return nil, ErrVLANRangeExhausted{}
    }

    vlanRange := &VLANRange{
        Start:    nextStart,
        End:      nextStart + va.vlansPerTenant - 1,
        TenantID: tenantID,
    }

    va.allocations[tenantID] = vlanRange
    return vlanRange, nil
}

// ValidateVLAN ensures VLAN belongs to tenant
func (va *VLANAllocator) ValidateVLAN(tenantID string, vlanID uint16) error {
    va.mu.RLock()
    defer va.mu.RUnlock()

    vlanRange, ok := va.allocations[tenantID]
    if !ok {
        return ErrTenantNotFound{ID: tenantID}
    }

    if vlanID < vlanRange.Start || vlanID > vlanRange.End {
        return ErrVLANOutOfRange{
            TenantID: tenantID,
            VLAN:     vlanID,
            Range:    vlanRange,
        }
    }

    return nil
}
```

### OpenFlow Isolation Rules

Default isolation flows prevent cross-tenant traffic:

```go
// InstallIsolationFlows adds OpenFlow rules for tenant isolation
func (sdn *SDNService) InstallIsolationFlows(ctx context.Context, bridge string, vlanRange *VLANRange) error {
    flows := []Flow{
        // Table 0: Classification
        // Allow traffic within tenant VLAN range
        {
            Table:    0,
            Priority: 100,
            Match: Match{
                VLANRange: vlanRange,
            },
            Actions: []Action{
                {Type: ActionGotoTable, Table: 1},
            },
        },
        // Drop traffic with VLANs outside tenant range
        {
            Table:    0,
            Priority: 1,
            Match:    Match{}, // Match all
            Actions: []Action{
                {Type: ActionDrop},
            },
        },

        // Table 1: Forwarding
        // Normal L2 forwarding within tenant
        {
            Table:    1,
            Priority: 100,
            Match:    Match{}, // Match all (already filtered by Table 0)
            Actions: []Action{
                {Type: ActionNormal},
            },
        },
    }

    for _, flow := range flows {
        if err := sdn.ofClient.AddFlow(ctx, bridge, &flow); err != nil {
            return ErrFlowInstallFailed{Flow: flow, Cause: err}
        }
    }

    return nil
}
```

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

### Runtime Checks

```go
// IsolationVerifier performs runtime isolation verification
type IsolationVerifier struct {
    ovsClient *ovs.Client
    vlanAlloc *VLANAllocator
    logger    *logging.Logger
}

// VerifyNetworkIsolation checks network isolation for a tenant
func (iv *IsolationVerifier) VerifyNetworkIsolation(ctx context.Context, tenantID string) (*IsolationReport, error) {
    report := &IsolationReport{
        TenantID:  tenantID,
        Timestamp: time.Now(),
        Checks:    []IsolationCheck{},
    }

    // Check bridge isolation
    bridgeName := fmt.Sprintf("br-tenant-%s", tenantID)
    bridge, err := iv.ovsClient.GetBridge(ctx, bridgeName)
    if err != nil {
        report.Checks = append(report.Checks, IsolationCheck{
            Name:   "bridge_exists",
            Passed: false,
            Error:  err.Error(),
        })
        return report, nil
    }

    report.Checks = append(report.Checks, IsolationCheck{
        Name:   "bridge_exists",
        Passed: true,
    })

    // Check VLAN range
    vlanRange, err := iv.vlanAlloc.GetRange(tenantID)
    if err != nil {
        report.Checks = append(report.Checks, IsolationCheck{
            Name:   "vlan_range_allocated",
            Passed: false,
            Error:  err.Error(),
        })
        return report, nil
    }

    report.Checks = append(report.Checks, IsolationCheck{
        Name:   "vlan_range_allocated",
        Passed: true,
        Details: map[string]string{
            "start": fmt.Sprint(vlanRange.Start),
            "end":   fmt.Sprint(vlanRange.End),
        },
    })

    // Check OpenFlow isolation rules
    flows, err := iv.ovsClient.DumpFlows(ctx, bridgeName)
    if err != nil {
        report.Checks = append(report.Checks, IsolationCheck{
            Name:   "isolation_flows",
            Passed: false,
            Error:  err.Error(),
        })
        return report, nil
    }

    hasDropRule := false
    for _, flow := range flows {
        if flow.Table == 0 && flow.Priority == 1 && flow.Actions == "drop" {
            hasDropRule = true
            break
        }
    }

    report.Checks = append(report.Checks, IsolationCheck{
        Name:   "isolation_flows",
        Passed: hasDropRule,
    })

    // Verify no cross-bridge connections
    for _, port := range bridge.Ports {
        portInfo, err := iv.ovsClient.GetPort(ctx, port.Name)
        if err != nil {
            continue
        }

        // Check port doesn't connect to another tenant's bridge
        if portInfo.PeerBridge != "" && !strings.Contains(portInfo.PeerBridge, tenantID) {
            report.Checks = append(report.Checks, IsolationCheck{
                Name:   "no_cross_tenant_ports",
                Passed: false,
                Error:  fmt.Sprintf("port %s connects to %s", port.Name, portInfo.PeerBridge),
            })
        }
    }

    report.Passed = true
    for _, check := range report.Checks {
        if !check.Passed {
            report.Passed = false
            break
        }
    }

    return report, nil
}
```

## Related Documentation

- [Architecture](architecture.md) - Multi-tenancy architecture
- [Configuration](configuration.md) - Isolation configuration options
- [SDN Architecture](../sdn/ARCHITECTURE.md) - Network isolation details
- [Key Management](../kms/overview.md) - Cryptographic key isolation
