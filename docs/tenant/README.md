# Multi-Tenancy Overview

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [architecture.md](architecture.md) and [user.md](user.md). The entity is `TenantEntity` (`pkg/tenant/entity.go:27`); the flag is `--max-bandwidth-mbps`, not `--max-bandwidth-gbps`; `platformd serve` turns per-tenant DEKs off; `../sdn/ARCHITECTURE.md` and `../compute-orchestrator-architecture.md` do not exist.

The Trusted Platform provides comprehensive multi-tenancy support through per-tenant resource isolation, enabling secure and efficient sharing of platform resources across multiple organizational units.

## Key Features

| Feature | Description |
|---------|-------------|
| **Resource Isolation** | Separate keyspaces, per-tenant DEKs and barriers, and compute/network/storage quotas |
| **QuicBaaS TenantManager** | Raft-replicated tenant configuration with strong consistency |
| **Key Isolation** | Per-tenant Data Encryption Keys (DEKs) sealed to TPM |
| **Quota Management** | Configurable compute, network, and storage quotas |
| **Policy Isolation** | Tenant-scoped access control and network policies |

## Architecture Overview

```
┌────────────────────────────────────────────────────────────────────┐
│                       Trusted Platform Daemon                      │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  ┌────────────────────────┐  ┌─────────────────────────────┐       │
│  │    Tenant Manager      │  │    QuicBaaS (Raft)          │       │
│  │                        │  │                             │       │
│  │  • Create/Delete       │  │  • TenantEntity storage     │       │
│  │  • Quota enforcement   │  │  • Quota tracking           │       │
│  │  • Resource allocation │  │  • Audit log                │       │
│  └────────────────────────┘  └─────────────────────────────┘       │
│                                                                    │
│  ┌────────────────────────┐  ┌─────────────────────────────┐       │
│  │  Per-Tenant Resources  │  │    Key Management           │       │
│  │                        │  │                             │       │
│  │  • Keyspace            │  │  • Per-tenant DEK           │       │
│  │  • Per-tenant barrier  │  │  • TPM-sealed keys          │       │
│  │  • Compute Quotas      │  │  • Key hierarchy            │       │
│  │  • Storage Quotas      │  │                             │       │
│  └────────────────────────┘  └─────────────────────────────┘       │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
                                 │
        ┌────────────────────────┼────────────────────────┐
        │                        │                        │
┌───────▼───────┐      ┌─────────▼─────────┐      ┌───────▼───────┐
│   Tenant A    │      │     Tenant B      │      │   Tenant C    │
│               │      │                   │      │               │
│ • keyspace A  │      │ • keyspace B      │      │ • keyspace C  │
│ • 50 VMs      │      │ • 100 VMs         │      │ • 25 VMs      │
│ • DEK-A       │      │ • DEK-B           │      │ • DEK-C       │
└───────────────┘      └───────────────────┘      └───────────────┘
```

> **No per-tenant VLAN range or OVS bridge.** Both were removed by #708: under
> the [reference network](../architecture/reference-network.md) tenant
> networks are EVPN/VXLAN overlays addressed from the environment's IPAM pool,
> and a tenant's routing domain becomes a VRF in a later release. Until then a
> tenant has no network identity, and this feature does not separate tenant
> traffic.

## Quick Start

### 1. Create a Tenant

```bash
# Create a new tenant with default quotas
platformctl tenant create \
  --name "engineering" \
  --display-name "Engineering Department"
```

### 2. Configure Quotas

```bash
# Set compute quotas
platformctl tenant quotas set engineering \
  --max-vms 50 \
  --max-vcpus 200 \
  --max-memory-gb 512

# Set network quotas
platformctl tenant quotas set engineering \
  --max-bridges 5 \
  --max-ports 500 \
  --max-bandwidth-gbps 10
```

### 3. Verify Tenant

```bash
# List all tenants
platformctl tenant list

# Output:
# NAME          ID                              STATE    VMS    BRIDGES
# engineering   tenant-550e8400-e29b-41d4       active   0/50   1/5
# production    tenant-661f9511-f30c-52e5       active   35/100 3/10

# Show tenant details
platformctl tenant show engineering
```

## Documentation Index

| Document | Description |
|----------|-------------|
| [Architecture](architecture.md) | Complete multi-tenancy architecture with diagrams |
| [User-Tenant Relationship](user-relationship.md) | User association model, ownership, and roles |
| [Configuration](configuration.md) | Tenant configuration reference and YAML examples |
| [Isolation](isolation.md) | Network, storage, and key isolation mechanisms |
| [API Reference](api-reference.md) | Full Tenant CRUD and Quota Management API |
| [CLI Usage](cli-usage.md) | Complete platformctl tenant command reference |
| [Roadmap](../../ROADMAP.md) | Development roadmap and progress tracker |

## Tenant Lifecycle

```
                ┌─────────────┐
                │   Created   │
                └──────┬──────┘
                       │
            (provision resources)
                       │
                ┌──────▼──────┐
                │   Active    │◀───────┐
                └──────┬──────┘        │
                       │               │
         ┌─────────────┴─────────────┐ │
         │                           │ │
    (suspend)                   (resume)
         │                           │
         ▼                           │
   ┌────────────┐                    │
   │  Suspended │────────────────────┘
   └─────┬──────┘
         │
     (delete)
         │
         ▼
   ┌────────────┐
   │  Deleting  │
   └─────┬──────┘
         │
   (cleanup complete)
         │
         ▼
   ┌────────────┐
   │   Deleted  │
   └────────────┘
```

## Key Concepts

### Tenant Identifier

Each tenant has a unique identifier (UUID) and a human-readable name:

```go
type Tenant struct {
    ID          string    // UUID: tenant-550e8400-e29b-41d4
    Name        string    // Unique name: engineering
    DisplayName string    // Human-readable: Engineering Department
    State       State     // created, active, suspended, deleting
    CreatedAt   time.Time
    UpdatedAt   time.Time
}
```

### Resource Boundaries

Tenants operate within strict resource boundaries:

| Resource Type | Isolation Mechanism |
|---------------|---------------------|
| Network | None yet — tenant VRFs on the overlay are a later release; network quotas are accounting only |
| Compute | VM instance quotas, vCPU limits |
| Storage | Disk quotas, per-tenant namespaces |
| Keys | Per-tenant DEK, TPM-sealed |
| Policies | Tenant-scoped ACLs, flow rules |

### QuicBaaS Integration

Tenant data is stored in QuicBaaS with Raft consensus:

```yaml
# Tenant entity in QuicBaaS
entity_type: tenant
consistency: linearizable
indexes:
  - name   # Unique tenant name
  - state  # For listing by state
```

## Related Documentation

- [User Registration](../iam/user-registration.md) - WebAuthn registration and tenant creation
- [Invitation Flow](../auth/invitation-flow.md) - User invitation lifecycle
- [Invitation API](../iam/api-reference-invitations.md) - Invitation management API
- [Cluster Architecture](../cluster/architecture.md) - Multi-node deployment with tenancy
- [SDN Architecture](../sdn/ARCHITECTURE.md) - Network isolation implementation
- [Key Management](../kms/overview.md) - Per-tenant key hierarchy
- [Compute Orchestration](../compute-orchestrator-architecture.md) - VM/Container management

## Next Steps

1. Review the [Architecture](architecture.md) documentation for detailed design
2. Configure tenants using the [Configuration](configuration.md) reference
3. Understand isolation mechanisms in the [Isolation](isolation.md) guide
4. Integrate with the [API Reference](api-reference.md) for programmatic access
