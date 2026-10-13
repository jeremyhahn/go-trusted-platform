# IAM Authorization

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [architecture.md](architecture.md) and [engineering.md](engineering.md). ABAC is not the primary model: RBAC is decided upstream, and the platform only validates broker tokens.

## Overview

Trusted Platform IAM uses Attribute-Based Access Control (ABAC) for fine-grained authorization. ABAC evaluates access requests based on attributes of subjects, resources, actions, and environmental conditions.

## ABAC vs RBAC

| Aspect | RBAC | ABAC |
|--------|------|------|
| Granularity | Role-based (coarse) | Attribute-based (fine) |
| Flexibility | Limited to roles | Any attribute combination |
| Complexity | Simple | More complex, more powerful |
| Maintenance | Role explosion risk | Policy-based management |
| Context | Static assignments | Dynamic evaluation |

Trusted Platform supports both, but ABAC is the primary model.

## Core Concepts

### Subject

The entity requesting access (user, service, device).

**Attributes:**
- `id` - Unique identifier
- `tenant_id` - Tenant membership
- `roles` - Assigned roles
- `groups` - Group memberships
- `email` - Email address
- Custom attributes from identity store

### Resource

The target of the access request.

**Pattern Syntax:**
- `keys/tenant/acme/**` - Multi-level wildcard
- `keys/users/*/profile` - Single-level wildcard
- `keys/${subject.tenant}/**` - Variable substitution

### Action

The operation being performed.

**Standard Actions:**
- `read` - Read/get operations
- `write` - Create/update operations
- `delete` - Delete operations
- `list` - List/enumerate operations
- `admin` - Administrative operations
- `*` - All actions (wildcard)

### Effect

The authorization decision.

- `allow` - Grant access
- `deny` - Deny access (takes precedence)

## Policy Structure

```yaml
apiVersion: abac.trustedplatform.io/v1
kind: Policy
metadata:
  name: policy-name
  tenant: tenant-id
  description: "Policy description"
  labels:
    team: engineering
  priority: 100

spec:
  subjects:
    # WHO this policy applies to
    users: [alice, bob]
    groups: [engineering]
    roles: [admin]
    authenticated: true

  variables:
    # Reusable expressions
    tenant_prefix: "keys/tenant/${subject.tenant}/"
    is_owner: resource.owner == subject.id

  rules:
    - name: rule-name
      effect: allow
      actions: [read, write]
      resources:
        - keys/${tenant_prefix}**
      when:
        - condition
      unless:
        - negative-condition
```

## Authorization Flow

```
Request                    Policy Engine                Decision
   |                           |                           |
   | Subject: user_123         |                           |
   | Action: read              |                           |
   | Resource: keys/data/x     |                           |
   |-------------------------->|                           |
   |                           |                           |
   |                           | 1. Load applicable        |
   |                           |    policies               |
   |                           |                           |
   |                           | 2. Evaluate DENY rules    |
   |                           |    (priority order)       |
   |                           |                           |
   |                           |    If ANY deny matches:   |
   |                           |    -> DENY                |
   |                           |                           |
   |                           | 3. Evaluate ALLOW rules   |
   |                           |    (priority order)       |
   |                           |                           |
   |                           |    If ANY allow matches:  |
   |                           |    -> ALLOW               |
   |                           |                           |
   |                           | 4. Default: DENY          |
   |                           |                           |
   |                           |        ALLOW/DENY         |
   |<--------------------------|-------------------------->|
```

## Resource Types

### KMS Keys

```yaml
resources:
  - keys/**                           # All keys
  - keys/tenant/${subject.tenant}/**  # Tenant keys
  - keys/users/${subject.id}/**       # User's keys
  - keys/shared/public-*              # Shared keys by pattern
```

### Policies

```yaml
resources:
  - policies/**                       # All policies
  - policies/tenant/${subject.tenant}/* # Tenant policies
```

### Users

```yaml
resources:
  - users/**                          # All users
  - users/${subject.id}               # Own user record
  - users/tenant/${subject.tenant}/*  # Tenant users
```

### Generic Resources

```yaml
resources:
  - data/**                           # Application data
  - config/**                         # Configuration
  - secrets/**                        # Secrets
```

## Actions by Resource Type

### KMS Actions

| Action | Description |
|--------|-------------|
| `keys:generate` | Generate new key |
| `keys:import` | Import key material |
| `keys:read` | Get key metadata |
| `keys:write` | Update key metadata |
| `keys:delete` | Delete key |
| `keys:rotate` | Rotate key |
| `keys:enable` | Enable key |
| `keys:disable` | Disable key |
| `keys:revoke` | Revoke key |
| `crypto:encrypt` | Encrypt with key |
| `crypto:decrypt` | Decrypt with key |
| `crypto:sign` | Sign with key |
| `crypto:verify` | Verify signature |

### IAM Actions

| Action | Description |
|--------|-------------|
| `users:create` | Create user |
| `users:read` | Read user |
| `users:update` | Update user |
| `users:delete` | Delete user |
| `groups:create` | Create group |
| `groups:update` | Update group |
| `groups:delete` | Delete group |
| `roles:assign` | Assign role |
| `roles:revoke` | Revoke role |
| `policies:create` | Create policy |
| `policies:update` | Update policy |
| `policies:delete` | Delete policy |

## Evaluation Order

1. **Collect Applicable Policies** - Match subject attributes
2. **Sort by Priority** - Higher priority evaluated first
3. **Evaluate Deny Rules** - If ANY deny matches, DENY
4. **Evaluate Allow Rules** - If ANY allow matches, ALLOW
5. **Default Decision** - DENY (implicit deny)

## Built-in Variables

### Subject Variables

```yaml
${subject.id}             # User/service ID
${subject.name}           # Username
${subject.email}          # Email address
${subject.tenant}         # Tenant ID
${subject.roles}          # List of roles
${subject.groups}         # List of groups
${subject.attrs.custom}   # Custom attribute
```

### Resource Variables

```yaml
${resource.key}           # Full resource key
${resource.type}          # Resource type
${resource.owner}         # Resource owner
${resource.tenant}        # Resource tenant
${resource.tags.env}      # Resource tag
${resource.meta.created}  # Resource metadata
```

### Request Variables

```yaml
${request.ip}             # Client IP address
${request.method}         # HTTP method / gRPC method
${request.protocol}       # rest, grpc, internal
${request.id}             # Request ID
${request.headers.key}    # Request header
```

### Environment Variables

```yaml
${env.cluster}            # Cluster ID
${env.node}               # Node ID
${env.region}             # Geographic region
${env.environment}        # dev, staging, production
```

### Time Variables

```yaml
${time.hour}              # Hour (0-23)
${time.minute}            # Minute (0-59)
${time.weekday}           # Day of week
${time.date}              # Current date
```

## Example Policies

### Admin Full Access

```yaml
apiVersion: abac.trustedplatform.io/v1
kind: Policy
metadata:
  name: admin-full-access
  tenant: acme-corp
  priority: 1000

spec:
  subjects:
    roles: [admin]

  rules:
    - name: admin-all
      effect: allow
      actions: ["*"]
      resources:
        - keys/tenant/${subject.tenant}/**
        - users/tenant/${subject.tenant}/**
        - policies/tenant/${subject.tenant}/**
      when:
        - subject.mfa_verified exists
```

### User Read Own Keys

```yaml
apiVersion: abac.trustedplatform.io/v1
kind: Policy
metadata:
  name: user-own-keys
  tenant: acme-corp

spec:
  subjects:
    authenticated: true

  rules:
    - name: read-own-keys
      effect: allow
      actions: [read, list]
      resources:
        - keys/users/${subject.id}/**
```

### Service Account Access

```yaml
apiVersion: abac.trustedplatform.io/v1
kind: Policy
metadata:
  name: api-service-access
  tenant: acme-corp

spec:
  subjects:
    services: [api-gateway]

  rules:
    - name: encrypt-decrypt
      effect: allow
      actions: [crypto:encrypt, crypto:decrypt]
      resources:
        - keys/shared/api-encryption-key
```

### Time-Based Access

```yaml
apiVersion: abac.trustedplatform.io/v1
kind: Policy
metadata:
  name: business-hours-only
  tenant: acme-corp

spec:
  subjects:
    groups: [contractors]

  variables:
    is_business_hours: time.hour between 9..17 and time.weekday in [mon, tue, wed, thu, fri]

  rules:
    - name: business-hours
      effect: allow
      actions: [read, write]
      resources:
        - data/projects/**
      when:
        - ${is_business_hours}
```

### IP-Based Restrictions

```yaml
apiVersion: abac.trustedplatform.io/v1
kind: Policy
metadata:
  name: corporate-network-only
  tenant: acme-corp
  priority: 500

spec:
  subjects:
    authenticated: true

  rules:
    - name: deny-external
      effect: deny
      actions: ["*"]
      resources:
        - secrets/**
      unless:
        - request.ip in 10.0.0.0/8
        - request.ip in 192.168.0.0/16
```

### Deny Deleted Resources

```yaml
apiVersion: abac.trustedplatform.io/v1
kind: Policy
metadata:
  name: deny-deleted
  tenant: acme-corp
  priority: 9999

spec:
  subjects:
    any: true

  rules:
    - name: deny-deleted
      effect: deny
      actions: ["*"]
      resources:
        - "**"
      when:
        - resource.status == deleted
      unless:
        - subject.roles contains admin
```

## Route-level RBAC on the IAM REST surface

> Code: `pkg/webservice/v1/rest/iam/router.go`,
> `pkg/webservice/v1/middleware/iam/guard.go` · Architecture:
> [`docs/auth/architecture.md` §6c](../auth/architecture.md).

The ABAC model above is the fine-grained decision layer. In front of it, the
IAM REST surface carries a coarse **route-level** gate, because a request that
should never have reached a handler should not depend on that handler
remembering to ask.

**`/api/v1/iam/**` — the whole subtree — requires an authenticated caller
holding the `admin` role.** Listing a tenant's users, roles, policies or
OAuth applications is administrative disclosure, so the gate covers reads as
well as writes.

**A route that names its tenant in the URL may only name your own.** The IAM
handlers give the path's `{tenant}` precedence over the session's, so the
`admin` role alone would let an administrator of one tenant reach any other
tenant's users, groups, roles, policies or applications by naming it in the
path. Every `/api/v1/iam/tenants/{tenant}/<collection>` route therefore
requires the named tenant to equal the caller's own — **including for the
system tenant**, since go-quicbaas#357 denies system-tenant impersonation of
tenant users and a carve-out here would be built on behaviour being removed.
A request that names no tenant (the flat `/iam/users` shape) is admitted and
resolves its tenant from the verified session instead.

**Tenant records carry a different guard.** `POST /api/v1/iam/tenants`,
`GET /api/v1/iam/tenants`, and `GET|PUT|DELETE /api/v1/iam/tenants/{tenant}`
additionally require the caller's tenant to be the **system tenant**. A
tenant-scoped admin legitimately holds the same `admin` role inside their own
tenant; the control plane owns tenant records
(`software/docs/08-bootstrap-auth-contract.md` §"Control plane vs data
plane"), so that role must not let them enumerate, create or delete tenants. A
tenant admin reads their own tenant through `/api/v1/tenants`.

**Who this admits.** A tenant owner is persisted with the `admin` role
(`service.DefaultTenantOwnerRole`), so the console keeps working for them on
the tenant-scoped and flat IAM collections, while `/iam/tenants*` stays
system-tenant-only. An ordinary invited user carries no `admin` role and now
receives `403` where they previously received data.

**Credential carriers.** The platform JWT is accepted from
`Authorization: Bearer` (platformctl, scripts, service callers) or from the
`jwt` / `token` cookie (the console's SDK client sends `credentials:
"include"` and no Authorization header). The header wins. The cookie is set
`Secure` + `SameSite=Strict`, and is now verified cryptographically — the
IAM handlers previously read it with an unverified base64 decode to resolve
the tenant.

| Guard | Applies to | Denies with |
|---|---|---|
| Authenticate | every `/api/v1/iam/**` route | `401` |
| `RequireRoles("admin")` | every `/api/v1/iam/**` route | `403` |
| `RequireOwnTenant` | `/api/v1/iam/tenants/{tenant}/<collection>` — the named tenant must be the caller's | `403` |
| `RequireTenant(<system tenant>)` | the tenant records: `/api/v1/iam/tenants` and `/api/v1/iam/tenants/{tenant}` | `403` |

Properties worth relying on:

- **The guards fail closed.** With no session in the request context every one
  answers `401`, so a guard mounted without an authenticator ahead of it denies
  the route rather than opening it.
- **`RequireTenant("")` denies everyone.** An unconfigured tenant guard cannot
  tell the system tenant from any other.
- **Role matching is exact and case-sensitive** — `administrator` does not
  satisfy `admin`.
- **The router refuses to build** without all four guards, and the caller then
  leaves the IAM routes unregistered. An unreachable admin surface is a fault;
  an ungated one is a breach.
- **Verification happens once.** The auth seam publishes the verified session;
  the guards never re-parse a token.

This is designed to **tighten, never break**, under the in-flight upstream
narrowing of system-tenant authority (go-quicbaas#356, #357). Nothing here
depends on a system admin being able to reach tenant data — the tenant guard
asserts the opposite direction explicitly.

## Policy Enforcement Points

### REST API

Policies are enforced at the API handler level:

```go
func (h *Handler) GetKey(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    subject := auth.SubjectFromContext(ctx)
    keyID := chi.URLParam(r, "id")

    // Check authorization
    allowed, err := h.iam.Check(ctx, CheckRequest{
        Subject:  subject,
        Action:   "keys:read",
        Resource: "keys/" + keyID,
    })
    if err != nil || !allowed {
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }

    // Proceed with operation
}
```

### gRPC Interceptor

```go
func AuthzInterceptor(iam IAMService) grpc.UnaryServerInterceptor {
    return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
        subject := auth.SubjectFromContext(ctx)
        action, resource := extractActionResource(info.FullMethod, req)

        allowed, err := iam.Check(ctx, CheckRequest{
            Subject:  subject,
            Action:   action,
            Resource: resource,
        })
        if err != nil || !allowed {
            return nil, status.Error(codes.PermissionDenied, "forbidden")
        }

        return handler(ctx, req)
    }
}
```

## Performance

Policy evaluation is optimized for low latency:

| Operation | Time |
|-----------|------|
| Policy cache lookup | ~100ns |
| Resource pattern match (trie) | ~50ns |
| Condition evaluation (compiled) | ~1us |
| Total evaluation | ~2-5us |

### Optimizations

1. **Compiled Conditions** - Conditions compiled to bytecode
2. **Resource Trie** - O(k) resource pattern matching
3. **Bloom Filter** - Quick deny check for common denies
4. **LRU Cache** - Hot policies cached in memory
5. **Zero-Allocation Eval** - Evaluation path is allocation-free

## Debugging

### Dry Run

Test policy evaluation without applying:

```bash
platformctl iam policy test \
  --subject-id user_123 \
  --action read \
  --resource keys/data/my-key
```

### Explain Mode

Get detailed evaluation trace:

```bash
platformctl iam policy test \
  --subject-id user_123 \
  --action write \
  --resource keys/data/my-key \
  --explain

# Output:
Subject: user_123 (tenant: acme-corp)
Action: write
Resource: keys/data/my-key

Evaluation:
  Policy: admin-full-access (priority: 1000)
    Rule: admin-all
    Subject Match: NO (user not in role: admin)

  Policy: user-own-keys
    Rule: read-own-keys
    Subject Match: YES
    Action Match: NO (write not in [read, list])

  Policy: default-deny
    Rule: deny-all
    Match: YES

Decision: DENY (matched: default-deny/deny-all)
```

### Audit Log

All authorization decisions are logged:

```json
{
  "timestamp": "2025-01-15T10:30:00Z",
  "event": "policy.evaluate",
  "subject_id": "user_123",
  "tenant_id": "acme-corp",
  "action": "write",
  "resource": "keys/data/my-key",
  "decision": "deny",
  "matched_policy": "default-deny",
  "matched_rule": "deny-all",
  "evaluation_time_us": 3
}
```
