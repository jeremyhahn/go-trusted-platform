# Multi-Tenancy Overview

The Trusted Platform provides comprehensive multi-tenancy support through per-tenant resource isolation, enabling secure and efficient sharing of platform resources across multiple organizational units.

## Key Features

| Feature | Description |
|---------|-------------|
| **Resource Isolation** | Complete separation of compute, network, storage, and cryptographic resources |
| **Per-Tenant OVS Bridges** | Dedicated Open vSwitch bridges with VLAN isolation per tenant |
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
│  │  • OVS Bridge (br-X)   │  │  • Per-tenant DEK           │       │
│  │  • VLAN Namespace      │  │  • TPM-sealed keys          │       │
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
│ • br-tenant-a │      │ • br-tenant-b     │      │ • br-tenant-c │
│ • VLAN 100-199│      │ • VLAN 200-299    │      │ • VLAN 300-399│
│ • 50 VMs      │      │ • 100 VMs         │      │ • 25 VMs      │
│ • DEK-A       │      │ • DEK-B           │      │ • DEK-C       │
└───────────────┘      └───────────────────┘      └───────────────┘
```

> **Code today vs. the reference design.** Tenants are isolated today by
> per-tenant VLAN ranges (`pkg/tenant/vlan`). The
> [reference network](../architecture/reference-network.md) (owner design
> decision, 2026-09-26) has no tenant VLAN range: tenant networks are
> EVPN/VXLAN overlays addressed from the environment's IPAM pool. The code change is tracked in #708.

## Quick Start

### 1. Create a Tenant

```bash
# Create a new tenant with default quotas
platformctl tenant create \
  --name "engineering" \
  --display-name "Engineering Department" \
  --vlan-range "100-199"

# Output:
# Tenant created successfully
# Tenant ID: tenant-550e8400-e29b-41d4
# OVS Bridge: br-tenant-engineering
# VLAN Range: 100-199
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
| [Roadmap](ROADMAP.md) | Development roadmap and progress tracker |

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
| Network | Per-tenant OVS bridge, VLAN ranges |
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
