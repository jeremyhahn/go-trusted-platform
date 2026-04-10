# Tenant Architecture

This document provides a comprehensive view of the multi-tenancy architecture in the Trusted Platform, including per-tenant resource isolation, QuicBaaS integration, and data flow patterns.

## System Architecture

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║                          TRUSTED PLATFORM MULTI-TENANCY                       ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  ┌─────────────────────────────────────────────────────────────────────────┐  ║
║  │                         API / CLI Layer                                 │  ║
║  │                                                                         │  ║
║  │  ┌─────────────┐  ┌───────────────┐  ┌────────────────┐  ┌────────────┐ │  ║
║  │  │ platformctl │  │ REST Gateway  │  │ gRPC Services  │  │ Web Console│ │  ║
║  │  └──────┬──────┘  └───────┬───────┘  └────────┬───────┘  └─────┬──────┘ │  ║
║  │         │                 │                   │                │        │  ║
║  └─────────┼─────────────────┼───────────────────┼────────────────┼────────┘  ║
║            │                 │                   │                │           ║
║  ┌─────────┴─────────────────┴───────────────────┴────────────────┴────────┐  ║
║  │                      TENANT SERVICE LAYER                               │  ║
║  │                                                                         │  ║
║  │  ┌───────────────────┐  ┌────────────────────┐  ┌────────────────────┐  │  ║
║  │  │  TenantManager    │  │   QuotaEnforcer    │  │  ResourceAllocator │  │  ║
║  │  │                   │  │                    │  │                    │  │  ║
║  │  │  • CRUD ops       │  │  • Pre-allocation  │  │  • OVS bridges     │  │  ║
║  │  │  • State machine  │  │  • Usage tracking  │  │  • VLAN ranges     │  │  ║
║  │  │  • Validation     │  │  • Quota policies  │  │  • DEK generation  │  │  ║
║  │  └───────────────────┘  └────────────────────┘  └────────────────────┘  │  ║
║  │                                                                         │  ║
║  └─────────┬────────────────────┬────────────────────┬─────────────────────┘  ║
║            │                    │                    │                        ║
║  ┌─────────▼─────────┐ ┌────────▼────────┐ ┌────────▼─────────┐               ║
║  │   QuicBaaS        │ │   SDN Service   │ │   Key Service    │               ║
║  │   (Raft)          │ │   (OVS/OF)      │ │   (TPM/KMS)      │               ║
║  │                   │ │                 │ │                  │               ║
║  │  • TenantEntity   │ │  • Bridge mgmt  │ │  • DEK creation  │               ║
║  │  • QuotaEntity    │ │  • VLAN config  │ │  • Key sealing   │               ║
║  │  • AuditEntity    │ │  • Flow rules   │ │  • Key rotation  │               ║
║  └───────────────────┘ └─────────────────┘ └──────────────────┘               ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
```

## Tenant Isolation Model

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║                         TENANT ISOLATION ARCHITECTURE                         ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║   TENANT A (engineering)              TENANT B (production)                   ║
║   ╔══════════════════════╗            ╔══════════════════════╗                ║
║   ║                      ║            ║                      ║                ║
║   ║  ┌────────────────┐  ║            ║  ┌────────────────┐  ║                ║
║   ║  │ OVS Bridge     │  ║            ║  │ OVS Bridge     │  ║                ║
║   ║  │ br-tenant-eng  │  ║            ║  │ br-tenant-prod │  ║                ║
║   ║  └───────┬────────┘  ║            ║  └───────┬────────┘  ║                ║
║   ║          │           ║            ║          │           ║                ║
║   ║  ┌───────▼────────┐  ║            ║  ┌───────▼────────┐  ║                ║
║   ║  │ VLAN Namespace │  ║            ║  │ VLAN Namespace │  ║                ║
║   ║  │ VLANs 100-199  │  ║            ║  │ VLANs 200-299  │  ║                ║
║   ║  └────────────────┘  ║            ║  └────────────────┘  ║                ║
║   ║          │           ║            ║          │           ║                ║
║   ║  ┌───────▼────────┐  ║            ║  ┌───────▼────────┐  ║                ║
║   ║  │ VMs/Containers │  ║  ISOLATED  ║  │ VMs/Containers │  ║                ║
║   ║  │ vm-eng-001     │◀─╬────────────╬─▶│ vm-prod-001    │  ║                ║
║   ║  │ vm-eng-002     │  ║            ║  │ vm-prod-002    │  ║                ║
║   ║  └────────────────┘  ║            ║  └────────────────┘  ║                ║
║   ║          │           ║            ║          │           ║                ║
║   ║  ┌───────▼────────┐  ║            ║  ┌───────▼────────┐  ║                ║
║   ║  │ Per-Tenant DEK │  ║            ║  │ Per-Tenant DEK │  ║                ║
║   ║  │ DEK-eng        │  ║            ║  │ DEK-prod       │  ║                ║
║   ║  │ (TPM-sealed)   │  ║            ║  │ (TPM-sealed)   │  ║                ║
║   ║  └────────────────┘  ║            ║  └────────────────┘  ║                ║
║   ║                      ║            ║                      ║                ║
║   ╚══════════════════════╝            ╚══════════════════════╝                ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
```

## Per-Tenant Resources

### Network Resources

Each tenant receives dedicated network infrastructure:

| Resource | Naming Convention | Purpose |
|----------|-------------------|---------|
| OVS Bridge | `br-tenant-{name}` | Primary network bridge for tenant |
| VLAN Range | Configurable (e.g., 100-199) | L2 isolation for tenant workloads |
| Flow Tables | `tenant:{id}:flows` | OpenFlow rules for tenant traffic |
| ACL Rules | `tenant:{id}:acls` | Access control policies |

```
                     ┌───────────────────────────┐
                     │   br-tenant-engineering   │
                     └─────────────┬─────────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              │                    │                    │
        ┌─────▼─────┐        ┌─────▼─────┐        ┌─────▼─────┐
        │  VLAN 100 │        │  VLAN 101 │        │  VLAN 102 │
        │ (web tier)│        │ (app tier)│        │ (db tier) │
        └─────┬─────┘        └─────┬─────┘        └─────┬─────┘
              │                    │                    │
        ┌─────▼─────┐        ┌─────▼─────┐        ┌─────▼─────┐
        │ vm-web-01 │        │ vm-app-01 │        │ vm-db-01  │
        │ vm-web-02 │        │ vm-app-02 │        │ vm-db-02  │
        └───────────┘        └───────────┘        └───────────┘
```

### Compute Resources

Tenant compute quotas are tracked and enforced:

```go
type ComputeQuota struct {
    // Instance limits
    MaxVMs         int64  // Maximum VM instances
    MaxContainers  int64  // Maximum containers

    // Resource limits
    MaxVCPUs       int64  // Total vCPU allocation
    MaxMemoryMB    int64  // Total memory in MB
    MaxDiskGB      int64  // Total disk storage in GB

    // Usage tracking (updated in real-time)
    UsedVMs        int64
    UsedContainers int64
    UsedVCPUs      int64
    UsedMemoryMB   int64
    UsedDiskGB     int64
}
```

### Key Isolation

Per-tenant cryptographic key hierarchy:

```
┌───────────────────────────┐
│   Platform Master Key     │
│   (TPM-sealed)            │
└─────────────┬─────────────┘
              │
    ┌─────────┴─────────┐
    │                   │
┌───▼───┐           ┌───▼───┐
│ KEK-A │           │ KEK-B │   Key Encryption Keys
│ (eng) │           │ (prod)│   (per-tenant)
└───┬───┘           └───┬───┘
    │                   │
┌───▼───┐           ┌───▼───┐
│ DEK-A │           │ DEK-B │   Data Encryption Keys
│ (eng) │           │ (prod)│   (per-tenant, TPM-sealed)
└───┬───┘           └───┬───┘
    │                   │
    ▼                   ▼
┌─────────┐         ┌─────────┐
│ Tenant  │         │ Tenant  │
│ Data A  │         │ Data B  │
└─────────┘         └─────────┘
```

## QuicBaaS TenantManager Integration

### Entity Schema

```go
// TenantEntity stored in QuicBaaS
type TenantEntity struct {
    // Primary key
    ID          uint64    `quicbaas:"pk"`

    // Unique identifiers
    TenantID    string    `quicbaas:"index"`  // UUID
    Name        string    `quicbaas:"unique"` // Human-readable

    // Configuration
    DisplayName string
    State       TenantState
    VLANRange   VLANRange

    // Resource allocation
    OVSBridge   string
    DEKHandle   uint32    // TPM handle for DEK

    // Quotas (embedded)
    ComputeQuota  ComputeQuota
    NetworkQuota  NetworkQuota
    StorageQuota  StorageQuota

    // Metadata
    Labels      map[string]string
    Annotations map[string]string

    // Timestamps
    CreatedAt   time.Time
    UpdatedAt   time.Time
    DeletedAt   *time.Time  // Soft delete
}
```

### QuicBaaS Operations

```go
// TenantManager uses QuicBaaS for persistent storage
type TenantManager struct {
    db     *quicbaas.Client
    logger *logging.Logger
}

// Create stores a new tenant with Raft consensus
func (tm *TenantManager) Create(ctx context.Context, tenant *TenantEntity) error {
    data, err := json.Marshal(tenant)
    if err != nil {
        return ErrSerializationFailed{Cause: err}
    }

    return tm.db.Put(ctx, "tenant", tenant.ID, data)
}

// Get retrieves a tenant with linearizable read
func (tm *TenantManager) Get(ctx context.Context, id uint64) (*TenantEntity, error) {
    data, found, err := tm.db.Get(ctx, "tenant", id)
    if err != nil {
        return nil, err
    }
    if !found {
        return nil, ErrTenantNotFound{ID: id}
    }

    var tenant TenantEntity
    if err := json.Unmarshal(data, &tenant); err != nil {
        return nil, ErrDeserializationFailed{Cause: err}
    }
    return &tenant, nil
}

// Query finds tenants by name using secondary index
func (tm *TenantManager) FindByName(ctx context.Context, name string) (*TenantEntity, error) {
    entities, err := tm.db.Query(ctx, "tenant", "name", []byte(name))
    if err != nil {
        return nil, err
    }
    if len(entities) == 0 {
        return nil, ErrTenantNotFound{Name: name}
    }

    var tenant TenantEntity
    if err := json.Unmarshal(entities[0].Data, &tenant); err != nil {
        return nil, ErrDeserializationFailed{Cause: err}
    }
    return &tenant, nil
}
```

## Data Flow Diagrams

### Tenant Creation Flow

```
┌──────────┐    ┌───────────────┐    ┌───────────────┐    ┌──────────┐    ┌──────────┐
│  Client  │    │ TenantManager │    │ QuicBaaS/Raft │    │ OVS/SDN  │    │ KMS/TPM  │
└────┬─────┘    └───────┬───────┘    └───────┬───────┘    └────┬─────┘    └────┬─────┘
     │                  │                    │                 │               │
     │ CreateTenant     │                    │                 │               │
     │─────────────────▶│                    │                 │               │
     │                  │                    │                 │               │
     │                  │ Validate request   │                 │               │
     │                  │────┐               │                 │               │
     │                  │    │               │                 │               │
     │                  │◀───┘               │                 │               │
     │                  │                    │                 │               │
     │                  │ Put(TenantEntity)  │                 │               │
     │                  │───────────────────▶│                 │               │
     │                  │                    │                 │               │
     │                  │                    │ Raft Propose    │               │
     │                  │                    │────┐            │               │
     │                  │                    │    │ (replicate)│               │
     │                  │                    │◀───┘            │               │
     │                  │                    │                 │               │
     │                  │ Success            │                 │               │
     │                  │◀───────────────────│                 │               │
     │                  │                    │                 │               │
     │                  │ CreateBridge       │                 │               │
     │                  │─────────────────────────────────────▶│               │
     │                  │                    │                 │               │
     │                  │                    │       OVSDB     │               │
     │                  │                    │       Insert    │               │
     │                  │                    │       ┌────┐    │               │
     │                  │                    │       │    │    │               │
     │                  │                    │       └◀───┘    │               │
     │                  │                    │                 │               │
     │                  │ Bridge created     │                 │               │
     │                  │◀─────────────────────────────────────│               │
     │                  │                    │                 │               │
     │                  │ GenerateDEK        │                 │               │
     │                  │─────────────────────────────────────────────────────▶│
     │                  │                    │                 │               │
     │                  │                    │                 │   TPM Create  │
     │                  │                    │                 │   ┌────┐      │
     │                  │                    │                 │   │    │      │
     │                  │                    │                 │   └◀───┘      │
     │                  │                    │                 │               │
     │                  │ DEK handle         │                 │               │
     │                  │◀─────────────────────────────────────────────────────│
     │                  │                    │                 │               │
     │                  │ Update tenant      │                 │               │
     │                  │───────────────────▶│                 │               │
     │                  │                    │                 │               │
     │ Tenant created   │                    │                 │               │
     │◀─────────────────│                    │                 │               │
     │                  │                    │                 │               │
```

### Resource Allocation Flow

```
┌──────────┐    ┌───────────────┐    ┌───────────────┐    ┌──────────────┐
│  Client  │    │ QuotaEnforcer │    │ TenantManager │    │   QuicBaaS   │
└────┬─────┘    └───────┬───────┘    └───────┬───────┘    └──────┬───────┘
     │                  │                    │                   │
     │ CreateVM         │                    │                   │
     │─────────────────▶│                    │                   │
     │                  │                    │                   │
     │                  │ GetTenant          │                   │
     │                  │───────────────────▶│                   │
     │                  │                    │                   │
     │                  │                    │ Get(tenant_id)    │
     │                  │                    │──────────────────▶│
     │                  │                    │                   │
     │                  │                    │ TenantEntity      │
     │                  │                    │◀──────────────────│
     │                  │                    │                   │
     │                  │ TenantEntity       │                   │
     │                  │◀───────────────────│                   │
     │                  │                    │                   │
     │                  │ CheckQuota         │                   │
     │                  │────┐               │                   │
     │                  │    │ (local check) │                   │
     │                  │◀───┘               │                   │
     │                  │                    │                   │
     │  [If within quota]                    │                   │
     │                  │                    │                   │
     │                  │ IncrementUsage     │                   │
     │                  │───────────────────▶│                   │
     │                  │                    │                   │
     │                  │                    │ Put(updated)      │
     │                  │                    │──────────────────▶│
     │                  │                    │                   │
     │                  │                    │ Raft consensus    │
     │                  │                    │          ┌────┐   │
     │                  │                    │          │    │   │
     │                  │                    │          └◀───┘   │
     │                  │                    │                   │
     │                  │                    │ Success           │
     │                  │                    │◀──────────────────│
     │                  │                    │                   │
     │                  │ Quota updated      │                   │
     │                  │◀───────────────────│                   │
     │                  │                    │                   │
     │ VM Created       │                    │                   │
     │◀─────────────────│                    │                   │
     │                  │                    │                   │
```

## State Machine

### Tenant States

```
                           ┌───────────────────┐
                           │      CREATED      │
                           │  (initial state)  │
                           └─────────┬─────────┘
                                     │
                           provision_resources()
                                     │
                           ┌─────────▼─────────┐
           ┌──────────────▶│      ACTIVE       │◀──────────────┐
           │               │   (operational)   │               │
           │               └─────────┬─────────┘               │
           │                         │                         │
       resume()              suspend() │ delete()          resume()
           │                    │      │                       │
           │          ┌─────────▼──────┴───────┐               │
           │          │                        │               │
           │   ┌──────▼──────┐          ┌──────▼──────┐        │
           └───│  SUSPENDED  │          │   DELETING  │        │
               │   (paused)  │          │  (cleanup)  │        │
               └──────┬──────┘          └──────┬──────┘        │
                      │                        │               │
                delete()               cleanup_complete()      │
                      │                        │               │
                      │                 ┌──────▼──────┐        │
                      └────────────────▶│   DELETED   │────────┘
                                        │  (terminal) │
                                        └─────────────┘
```

### State Transition Rules

```go
// Valid state transitions
var validTransitions = map[TenantState][]TenantState{
    StateCreated:   {StateActive, StateDeleting},
    StateActive:    {StateSuspended, StateDeleting},
    StateSuspended: {StateActive, StateDeleting},
    StateDeleting:  {StateDeleted},
    StateDeleted:   {}, // Terminal state
}

// TransitionTo validates and performs state transition
func (t *TenantEntity) TransitionTo(newState TenantState) error {
    validStates, ok := validTransitions[t.State]
    if !ok {
        return ErrInvalidState{Current: t.State}
    }

    for _, valid := range validStates {
        if valid == newState {
            t.State = newState
            t.UpdatedAt = time.Now()
            return nil
        }
    }

    return ErrInvalidTransition{From: t.State, To: newState}
}
```

## Quota Enforcement Architecture

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║                          QUOTA ENFORCEMENT PIPELINE                           ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  ┌─────────────────────────────────────────────────────────────────────────┐  ║
║  │                         REQUEST PHASE                                   │  ║
║  │                                                                         │  ║
║  │  ┌───────────┐    ┌──────────────┐    ┌────────────────┐                │  ║
║  │  │ Incoming  │───▶│ Pre-check    │───▶│ Reserve Quota  │                │  ║
║  │  │ Request   │    │ (read quota) │    │ (optimistic)   │                │  ║
║  │  └───────────┘    └──────────────┘    └────────────────┘                │  ║
║  │                                                                         │  ║
║  └──────────────────────────────────┬──────────────────────────────────────┘  ║
║                                     │                                         ║
║                                     ▼                                         ║
║  ┌──────────────────────────────────┴──────────────────────────────────────┐  ║
║  │                       EXECUTION PHASE                                   │  ║
║  │                                                                         │  ║
║  │  ┌────────────────┐    ┌──────────────────┐    ┌──────────────────┐     │  ║
║  │  │ Create         │───▶│ Update Usage     │───▶│ Commit to        │     │  ║
║  │  │ Resource       │    │ (atomic)         │    │ QuicBaaS/Raft    │     │  ║
║  │  └────────────────┘    └──────────────────┘    └──────────────────┘     │  ║
║  │                                                                         │  ║
║  └──────────────────────────────────┬──────────────────────────────────────┘  ║
║                                     │                                         ║
║                            success  │  failure                                ║
║                      ┌──────────────┴───────────────┐                         ║
║                      │                              │                         ║
║                      ▼                              ▼                         ║
║  ┌───────────────────┴────────────┐  ┌──────────────┴───────────────────────┐ ║
║  │      COMMIT PHASE              │  │         ROLLBACK PHASE               │ ║
║  │                                │  │                                      │ ║
║  │  ┌─────────────┐               │  │  ┌────────────────┐                  │ ║
║  │  │ Finalize    │               │  │  │ Release Quota  │                  │ ║
║  │  │ Usage       │               │  │  │ Reservation    │                  │ ║
║  │  └─────────────┘               │  │  └────────────────┘                  │ ║
║  │                                │  │                                      │ ║
║  └────────────────────────────────┘  └──────────────────────────────────────┘ ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
```

## Security Model

### Access Control

```
┌────────────────────────────────────────────────────────────────────┐
│                       TENANT ACCESS CONTROL                        │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  ┌───────────────────┐    ┌───────────────────┐                    │
│  │ Platform Admins   │    │ Tenant Admins     │                    │
│  │                   │    │                   │                    │
│  │ • All tenants     │    │ • Own tenant only │                    │
│  │ • Quota mgmt      │    │ • Resource mgmt   │                    │
│  │ • CRUD tenants    │    │ • User mgmt       │                    │
│  └───────────────────┘    └───────────────────┘                    │
│           │                        │                               │
│           ▼                        ▼                               │
│  ┌───────────────────────────────────────────────────┐             │
│  │              POLICY ENFORCEMENT POINT             │             │
│  │                                                   │             │
│  │  ┌─────────────┐  ┌─────────────┐  ┌────────────┐ │             │
│  │  │ Tenant      │  │ Resource    │  │ Action     │ │             │
│  │  │ Boundary    │  │ Type        │  │ Permission │ │             │
│  │  │ Check       │  │ Check       │  │ Check      │ │             │
│  │  └─────────────┘  └─────────────┘  └────────────┘ │             │
│  │                                                   │             │
│  └───────────────────────────────────────────────────┘             │
│                              │                                     │
│                              ▼                                     │
│  ┌───────────────────────────────────────────────────┐             │
│  │                   TENANT RESOURCES                │             │
│  │                                                   │             │
│  │  ┌───────────┐  ┌───────────┐  ┌───────────┐     │             │
│  │  │ Compute   │  │ Network   │  │ Storage   │     │             │
│  │  │ Resources │  │ Resources │  │ Resources │     │             │
│  │  └───────────┘  └───────────┘  └───────────┘     │             │
│  │                                                   │             │
│  └───────────────────────────────────────────────────┘             │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

### Key Isolation Enforcement

```go
// KeyIsolation ensures tenants can only access their own keys
type KeyIsolation struct {
    kms      *kms.Service
    tenantMgr *TenantManager
}

// GetDEK retrieves the tenant-specific DEK
func (ki *KeyIsolation) GetDEK(ctx context.Context, tenantID string) ([]byte, error) {
    // Get tenant to verify DEK handle
    tenant, err := ki.tenantMgr.GetByID(ctx, tenantID)
    if err != nil {
        return nil, err
    }

    // Verify caller has access to this tenant
    callerTenantID := ctx.Value("tenant_id").(string)
    if callerTenantID != tenantID {
        return nil, ErrAccessDenied{
            Caller: callerTenantID,
            Target: tenantID,
        }
    }

    // Unseal DEK from TPM
    return ki.kms.Unseal(ctx, tenant.DEKHandle)
}
```

## User-Tenant Relationship

Users are associated with tenants through the `TenantID` field on the User entity.

### User Entity with TenantID

```go
type User struct {
    ID               uint64    `json:"id"`
    TenantID         string    `json:"tenant_id"`       // Links user to tenant
    IsTenantOwner    bool      `json:"is_tenant_owner"` // Ownership flag
    Email            string    `json:"email"`
    DisplayName      string    `json:"display"`
    Roles            []*Role   `json:"roles"`
    Credentials      []webauthn.Credential `json:"credentials"`
    CreatedAt        time.Time `json:"created_at"`
    UpdatedAt        time.Time `json:"updated_at"`
}
```

### Entity Relationship Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           USER-TENANT RELATIONSHIP                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                            TenantEntity                               │  │
│  │                                                                       │  │
│  │  ID: tenant-550e8400-e29b-41d4                                        │  │
│  │  Name: engineering                                                    │  │
│  │  DisplayName: Engineering Department                                  │  │
│  │  State: active                                                        │  │
│  │  VLANRange: 100-199                                                   │  │
│  │  OVSBridge: br-tenant-engineering                                     │  │
│  │  DEKHandle: 0x81000001                                                │  │
│  │                                                                       │  │
│  └─────────────────────────────────────┬─────────────────────────────────┘  │
│                                        │                                    │
│                         ┌──────────────┴──────────────┐                     │
│                         │                             │                     │
│                         ▼                             ▼                     │
│  ┌────────────────────────────────┐   ┌────────────────────────────────┐   │
│  │           User (Owner)         │   │          User (Member)         │   │
│  │                                │   │                                │   │
│  │  ID: 12345678901234567890      │   │  ID: 98765432109876543210      │   │
│  │  TenantID: tenant-550e8400...  │   │  TenantID: tenant-550e8400...  │   │
│  │  IsTenantOwner: true           │   │  IsTenantOwner: false          │   │
│  │  Email: alice@example.com      │   │  Email: bob@example.com        │   │
│  │  Roles: [owner, admin]         │   │  Roles: [developer]            │   │
│  │                                │   │                                │   │
│  └────────────────────────────────┘   └────────────────────────────────┘   │
│                                                                             │
│  ┌────────────────────────────────┐                                        │
│  │       Invitation (Pending)     │                                        │
│  │                                │                                        │
│  │  TenantID: tenant-550e8400...  │                                        │
│  │  Email: carol@example.com      │                                        │
│  │  Role: developer               │                                        │
│  │  Status: pending               │                                        │
│  │  ExpiresAt: 2025-01-22T00:00Z  │                                        │
│  │                                │                                        │
│  └────────────────────────────────┘                                        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Tenant Association Flow

```mermaid
flowchart TD
    A[User Registration] --> B{Has Invitation Token?}
    B -->|No| C[Create New Tenant]
    C --> D[Associate User with New Tenant]
    D --> E[Set IsTenantOwner = true]
    B -->|Yes| F[Validate Invitation]
    F --> G[Get TenantID from Invitation]
    G --> H[Associate User with Existing Tenant]
    H --> I[Set IsTenantOwner = false]
    I --> J[Assign Role from Invitation]
    E --> K[Generate JWT with tenant_id claim]
    J --> K
```

### Access Control by Tenant

All resource access is scoped by the user's TenantID:

```go
// Example: Get resources for current user's tenant
func (s *Service) GetResources(ctx context.Context, userID uint64) ([]*Resource, error) {
    user, err := s.userDAO.Get(ctx, userID)
    if err != nil {
        return nil, err
    }

    // Query scoped to user's tenant
    return s.resourceDAO.GetByTenant(ctx, user.TenantID)
}
```

### JWT Token with Tenant Context

Authenticated users receive a JWT containing their tenant association:

```json
{
  "uid": 12345678901234567890,
  "tenant_id": "tenant-550e8400-e29b-41d4",
  "is_tenant_owner": true,
  "roles": ["owner", "admin"],
  "iss": "trusted-platform",
  "exp": 1705323600
}
```

## Related Documentation

- [User-Tenant Relationship](user-relationship.md) - Detailed user-tenant model
- [User Registration](../iam/user-registration.md) - Registration and tenant creation
- [Invitation Flow](../auth/invitation-flow.md) - User invitation lifecycle
- [Invitation API Reference](../iam/api-reference-invitations.md) - Invitation REST API endpoints
- [Configuration Reference](configuration.md) - Tenant configuration options
- [Isolation Mechanisms](isolation.md) - Detailed isolation implementation
- [API Reference](api-reference.md) - Programmatic tenant management
- [Cluster Architecture](../cluster/architecture.md) - Multi-node tenancy
