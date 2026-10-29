# IAM Configuration

> **Status: REFERENCE** · Last verified: 2026-10-13
> The `quicbaas:` storage keys IAM data lives in, the mTLS adapter options and the IAM gRPC request shapes.

## Overview

IAM (Identity and Access Management) in Trusted Platform is powered by go-quicbaas's IAM subsystem. The platform wraps QuicBaaS's IAMServiceClient to provide tenant management, user/group/role management, ABAC policy enforcement, and OIDC federation.

## Configuration File Location

IAM configuration is distributed across several platform configuration sections:

| Section | Location | Purpose |
|---------|----------|---------|
| QuicBaaS | `quicbaas` | Backend storage for IAM data |
| mTLS | `pkg/auth` (code) | Certificate-based authentication |
| ABAC Policies | QuicBaaS runtime | Policy engine rules |
| Multi-tenant | QuicBaaS runtime | Tenant isolation |

## QuicBaaS Connection Settings

IAM data is stored in QuicBaaS. Configure the QuicBaaS backend in your platform config:

```yaml
quicbaas:
  # Storage backend type (required)
  # - "memory": In-memory storage, no persistence (testing/ephemeral)
  # - "file": Simple file-based storage (development/debugging)
  # - "pebble": PebbleDB for high-performance local storage (default)
  # Any other value fails validation. Clustering is not a backend: a pebble
  # node joins peers through raft-address and join-addresses.
  storage-backend: pebble

  # Data directory for QuicBaaS files
  data-dir: trusted-data/quicbaas

  # Write-ahead log directory (defaults to data-dir/wal)
  wal-dir: trusted-data/quicbaas/wal

  # Node identifier, unique within a cluster
  node-id: 1

  # In-memory cache size in bytes (default: 128MB)
  cache-size: 134217728

  # Logging verbosity: debug, info, warn, error
  log-level: warn

  # Read consistency: linearizable (default), strong, eventual.
  # An unrecognized value silently falls back to linearizable.
  consistency-level: linearizable

  # Raft address advertised to peers (cluster members only)
  raft-address: "192.0.2.10:63000"

  # Every cluster member as "id=host:port", this node included. When set,
  # raft-address must be routable, and deployment-id and the three Raft TLS
  # files are required (see docs/cluster/user.md).
  deployment-id: 100
  join-addresses:
    - "1=192.0.2.10:63000"
    - "2=192.0.2.11:63000"
    - "3=192.0.2.12:63000"
  raft-tls-cert-file: /etc/trusted-platform/raft/tls.crt
  raft-tls-key-file: /etc/trusted-platform/raft/tls.key
  raft-tls-ca-file: /etc/trusted-platform/raft/ca.crt
```

## IAM Service Configuration

The IAM service needs the `iam` build tag. It is always in the Makefile's
`BUILD_TAGS` (see [Build Tags](../configuration/build-tags.md)), so a plain
build includes it:

```bash
make build
# Outside make, never type the tag list by hand:
go build -tags "$(make -s print-build-tags)" ./cmd/platformd
```

### Build Requirements

| Component | Build Tag | Description |
|-----------|-----------|-------------|
| IAM Service | `iam` | Enables IAM gRPC services |
| QuicBaaS IAM | `iam` | Enables IAM components in QuicBaaS |

## mTLS Authentication Configuration

mTLS authentication extracts identity from client certificates. Configure via code:

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/auth"

// Create mTLS adapter with options
adapter, err := auth.NewMTLSAdapter(
    logger,
    certificateAuthority,
    auth.WithTrustedRoots(rootCertPool),
    auth.WithIdentityField(auth.IdentityFieldEmail),
    auth.WithTenantField(auth.IdentityFieldOrganization),
    auth.WithDefaultTenant("default"),
    auth.WithRequireRevocation("https://crl.example.com"),
    auth.WithIDevIDValidation(true),
    auth.WithRequireClientAuth(true),
)
```

`NewMTLSAdapter` (`pkg/auth/mtls.go`) refuses a nil logger with `ErrNilLogger`
and a nil CA with `ErrNilCA`. With no options, identity comes from the email
SAN (`IdentityFieldEmail`), the tenant from the Organization field
(`IdentityFieldOrganization`) and a client certificate is required
(`DefaultMTLSConfig`, `pkg/auth/interface.go`).

**`TrustedRoots` is optional.** When it is nil, the adapter uses the CA's
bundle (`CABundleCertPool`); if that read fails it logs a warning and runs with
no trusted roots. Nothing refuses a missing pool.

### Identity Field Options

| Field | Value | Certificate Source |
|-------|-------|-------------------|
| `IdentityFieldEmail` | `email` | Email SAN |
| `IdentityFieldCN` | `cn` | Common Name |
| `IdentityFieldSerialNumber` | `serial_number` | Subject Serial Number |
| `IdentityFieldSubjectDN` | `subject_dn` | Full Subject DN |
| `IdentityFieldOrganization` | `organization` | Organization field |

### MTLSConfig Options

| Option | Type | Description |
|--------|------|-------------|
| `TrustedRoots` | `*x509.CertPool` | Trusted root CA certificates |
| `RequireRevocation` | `bool` | Enable CRL-based revocation checking |
| `RevocationEndpoint` | `string` | URL for revocation checking |
| `IdentityField` | `IdentityField` | Certificate field for identity extraction |
| `TenantField` | `IdentityField` | Certificate field for tenant extraction |
| `DefaultTenant` | `string` | Fallback tenant when extraction fails |
| `ValidateIDevID` | `bool` | Enable IDevID certificate validation |
| `RequireClientAuth` | `bool` | Require client certificate authentication |

## ABAC Policy Engine

Policies are defined in YAML and managed via the IAM gRPC API:

```yaml
# Example ABAC policy
name: admin-access
description: Allow admins full access
priority: 100
spec:
  rules:
    - effect: allow
      subjects:
        - role: admin
      actions:
        - "*"
      resources:
        - "*"
    - effect: allow
      subjects:
        - role: operator
      actions:
        - read
        - list
      resources:
        - "devices/*"
        - "tenants/*"
```

### Policy Operations via gRPC

```go
// Create policy
resp, err := iamClient.CreatePolicy(ctx, &platformv1.CreateIAMPolicyRequest{
    TenantId:    "tenant-1",
    Name:        "admin-access",
    Description: "Admin access policy",
    Priority:    100,
    SpecYaml:    policyYAML,
    Labels:      map[string]string{"env": "production"},
})

// Check permission
checkResp, err := iamClient.CheckPermission(ctx, &platformv1.CheckIAMPermissionRequest{
    TenantId:   "tenant-1",
    SubjectId:  "user-123",
    Action:     "read",
    Resource:   "devices/device-456",
    Roles:      []string{"operator"},
    Groups:     []string{"ops-team"},
    Context:    map[string]string{"source_ip": "10.0.0.5"},
    Attributes: map[string]string{"department": "engineering"},
})
```

## Multi-Tenant Configuration

Tenants are isolated IAM namespaces created at runtime:

```go
// Create tenant
tenant, err := iamClient.CreateTenant(ctx, &platformv1.CreateIAMTenantRequest{
    Id:   "acme-corp",
    Name: "ACME Corporation",
    Settings: &platformv1.IAMTenantSettings{
        MaxUsers:    1000,
        MfaRequired: true,
    },
})
```

### Tenant Isolation

| Resource | Isolation |
|----------|-----------|
| Users | Per-tenant |
| Groups | Per-tenant |
| Roles | Per-tenant |
| Policies | Per-tenant |
| Applications | Per-tenant |

## Daemon IAM Configuration

The platformd daemon includes IAM service configuration (`Config` and
`ServiceConfig`, `pkg/api/daemon/config.go`):

```go
config := &daemon.Config{
    // ... other config ...

    // Skip IAM validation (testing only)
    SkipIAMValidation: false,

    // Services map includes IAM
    Services: map[string]daemon.ServiceConfig{
        "iam": {
            Enabled:    true,
            AutoStart:  true,
            Timeout:    10 * time.Second,
            MaxRetries: 3,
        },
    },
}
```

## Complete Configuration Example

```yaml
# Platform configuration with IAM-related settings

debug: false
platform-dir: /var/lib/trusted-platform
config-dir: /etc/trusted-platform
log-dir: /var/log/trusted-platform

# QuicBaaS storage (platform-wide)
quicbaas:
  storage-backend: pebble
  data-dir: /var/lib/trusted-platform/quicbaas
  wal-dir: /var/lib/trusted-platform/quicbaas/wal
  node-id: 1
  cache-size: 134217728  # 128MB
  log-level: warn
  consistency-level: linearizable

# Web services with authentication
webservices:
  - name: api
    port: 8080
    tls-port: 8443

    jwt:
      expiration: 60        # 1 hour
      issuer: trusted-platform

    webauthn:
      display-name: Trusted Platform
      id: example.com
      origins:
        - https://example.com
        - https://api.example.com

    cors:
      allowed-origins:
        - https://example.com
        - https://api.example.com
      allowed-methods:
        - GET
        - POST
        - PUT
        - DELETE
        - OPTIONS
      allowed-headers:
        - Authorization
        - Content-Type
        - X-Request-ID
      allow-credentials: true

# Password hashing (when password auth is enabled)
argon2:
  memory: 64
  iterations: 3
  parallelism: 4
  saltLen: 16
  keyLen: 32
```

## Security Considerations

### Certificate Authentication

- Use strong CA hierarchies with proper chain validation
- Enable CRL or OCSP revocation checking in production
- Rotate certificates before expiration
- Use IDevID validation for device authentication

### QuicBaaS Security

- Run a multi-node cluster (`join-addresses`) for HA in production
- Configure strong consistency (`linearizable`) for IAM operations
- Encrypt data-at-rest using QuicBaaS KMS integration
- Restrict network access to Raft ports

### Policy Best Practices

- Use least-privilege policies
- Assign roles via groups, not directly to users
- Audit policy changes via the audit service
- Test policies before production deployment

### Multi-Tenant Security

- Enforce tenant isolation at the API layer
- Use separate encryption keys per tenant
- Validate tenant context in all operations
- Monitor cross-tenant access attempts

## Validation

The embedded `quicbaas:` configuration is validated at startup:

| Field | Validation |
|-------|------------|
| `quicbaas.storage-backend` | Must be `memory`, `file` or `pebble`; empty means `pebble` |
| `quicbaas.data-dir` | Required for `file` and `pebble` |
| `quicbaas.wal-dir` | Required for `pebble`; defaults to `data-dir/wal` |
| `quicbaas.cache-size` | Must not be negative; zero means 128MB |
| `quicbaas.raft-address` | Must be routable when `join-addresses` is set |
| `quicbaas.deployment-id`, `quicbaas.raft-tls-*-file` | Required when `join-addresses` is set |
| `quicbaas.spiffe-trust-domain` | Required: first-boot IAM seeding needs it |
| `mTLS.TrustedRoots` | Not validated; nil falls back to the CA bundle (above). Set it explicitly in production |

`node-id` and `consistency-level` are not validated.

## Troubleshooting

### IAM service not available

```
Check: The build includes the iam tag (make -s print-build-tags)
Check: QuicBaaS backend configured
Check: QuicBaaS client started
Check: IAM components initialized
```

### mTLS authentication failing

```
Check: Client certificate chain is valid
Check: TrustedRoots includes CA certificates
Check: Certificate not expired or revoked
Check: Identity field present in certificate
```

### Policy evaluation failing

```
Check: Policy syntax is valid YAML
Check: Subject has required roles/groups
Check: Resource path matches policy rules
Check: Tenant context is correct
```

### QuicBaaS connection issues

```
Check: data-dir and wal-dir are writable
Check: raft-address is accessible
Check: node-id is unique in cluster
Check: join-addresses are reachable
```
