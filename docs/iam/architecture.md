# IAM Architecture

> **Status: NORMATIVE** · Scope: the platform's IAM surface · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: architecture (this file) · [engineering.md](engineering.md) ·
> [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> **Verification scope.** Package presence, RPC count, REST route registration,
> MCP tools, CLI verbs and the transport matrix were checked against code on
> 2026-08-18. The narrative below predates the migration and was carried over.

## The problem

The platform has to answer "who is this" for humans, service accounts, agents,
devices and workloads — and it has to answer it the same way everywhere, because
an authorization model with two sources of truth has no source of truth.

## The shape chosen

**Re-export the stack's IAM; implement none of it.** go-qrdb owns the identity
model and the **single** RBAC decision point; go-quicbaas composes IAM/OIDC on
top; this repository exposes the result as the platform product's IAM surface
(docs/00 L5).

The evidence is the package tree: **there is no `pkg/iam`** (verified
2026-08-18). `pkg/webservice/v1/rest/iam/doc.go` describes itself as *"a
protocol adapter that translates REST requests to gRPC calls against the
underlying QuicBaaS IAM service."*

`pkg/auth/` is **not** IAM. It is transport-level authentication — mTLS and token
validation. The platform is a broker-token **validator**, not a token
authorization decision point.

### Alternatives rejected

| Alternative | Why it was rejected |
|---|---|
| **A platform-local identity store alongside the stack's** | Two identity stores means two answers to "who is this", and no way to tell which is right. The one place two stores unavoidably meet — WebAuthn registration — is handled by an explicit mirror whose doc comment warns about keeping both on the same client. |
| **A second RBAC decision point in the platform** | There is exactly one RBAC PDP in the portfolio, in go-qrdb. A local one would drift from it and the drift would be invisible until an authorization decision differed. |
| **Reading application secrets** | A secret that can be read is a secret that gets copied into a script. `RotateAppSecret` is the only way to obtain one, and it invalidates the previous value. |
| **Merging on user update** | `update --roles` replacing rather than merging is surprising, but the alternative — no way to *remove* a role except by a separate verb — is worse. `assign-role` / `revoke-role` exist for incremental change; `update` is declarative. |
| **Applying policies without a test path** | An authorization policy that locks out its administrator is recoverable only out of band. `ValidatePolicy` and `TestPolicy` are separate operations for that reason. |

## Component boundaries

| Piece | Location | Owner |
|---|---|---|
| **Identity model, RBAC decision point** | go-qrdb via go-quicbaas | **not this repo** |
| **IAM / OIDC composition** | go-quicbaas | **not this repo** |
| REST adapter | `pkg/webservice/v1/rest/iam/` | this repo |
| **WebAuthn user mirror** | `pkg/webservice/v1/rest/iam/mirror.go` | this repo |
| Service, adapter, stub, health | `pkg/api/daemon/iam_*.go` | this repo |
| gRPC `PlatformIAMService` (41 RPCs) | `pkg/api/grpc/iam_service.go` | this repo |
| QUIC handlers | `pkg/api/quic/iam_handlers.go`, `pkg/api/daemon/quic_iam.go` | this repo |
| MCP tools | `pkg/api/mcp/iam_tools.go` | this repo |
| CLI | `pkg/cli/commands/iam/` | this repo |
| **Transport authentication (mTLS, token validation)** | `pkg/auth/` — *not IAM* | this repo |
| Login / refresh routes | `pkg/webservice/v1/router/authentication.go` | this repo |
| WebAuthn routes | `pkg/webservice/v1/router/webauthn.go` | this repo |
| **Platform tenancy** | `pkg/tenant/` — [`docs/tenant/`](../tenant/) | this repo, **different feature** |

The §R row is part of *"Re-export frontage of the composed stack (CA, KMS, IAM,
FIDO2/PIV, barrier, ceremony, LUKS, auth, data services)"*, Tier 1, reached
through `services/iam`.

## Two things called "tenant"

- **`POST /api/v1/tenants`** — a *platform* tenant: a VLAN, a bridge, a
  keyspace, a DEK and a quota. [`docs/tenant/`](../tenant/).
- **`POST /api/v1/iam/tenants`** — an *IAM scope* for users, groups, roles,
  policies and applications.

One word, two operations, and creating one does not create the other. **Which
should be authoritative — or whether the IAM tree should defer to the platform
one — is an open question for the owner**, recorded in the migration report.

## The mirror is the one place two stores meet

`QuicBaaSUserMirror` copies a WebAuthn-registered platform user into the stack's
IAM tenant so `/api/v1/iam/users` surfaces them. Its own doc comment states the
constraint: pass **the same `IAMClient` the REST IAM router uses**, so both
surfaces speak to the same tenant store.

Given different clients they diverge, and nothing detects it. That makes the
mirror the first place to look when a user exists on one surface and not the
other.

### What keeps the mirror working (#641)

The mirror names a role for every user it writes (the owner is mirrored as
`admin`), and the IAM store refuses a user whose role does not exist. An IAM
tenant created without its roles therefore cannot hold anyone, and every
registration's mirror failed with `iam.role: not_found`.

- **Every IAM tenant carries its default roles.** `tenant.Manager.CreateTenant`
  provisions them straight after creating the IAM tenant, through the SDK's
  role reconcile (`SDK().Identity().IAM().Role().Reconcile`). It seeds the built-in
  roles (`so`, `admin`, `operator`, `user`, `auditor`, `custodian`) that are
  absent, never touches a custom role, and writes nothing on a tenant that
  already has them. A failure is `tenant.ErrDefaultRolesFailed` and rolls the
  IAM tenant back: a tenant that cannot hold users is not created.
  The IAM `CreateTenant` operation does the same on every transport, REST
  included, through one helper (`restiam.CreateTenantWithDefaultRoles`): it
  reconciles after creating the tenant and deletes the tenant again when that
  fails. Creating a tenant that already exists also reconciles it, then
  answers `AlreadyExists`, so a tenant made by a path that never provisioned
  its roles gets them from a repeated create; a failed reconcile never deletes
  an existing tenant.
- **The owner's mirror is part of registration.** When `RegisterNewUser`
  cannot mirror the new tenant owner, it deletes the platform user and the
  tenant it just created and returns `service.ErrIAMMirrorFailed`. The
  registration fails as a whole rather than leaving an owner the IAM surface
  cannot see. Invited registrations do not mirror at registration time.
- **Users registered before the fix are repaired at startup.** When the
  WebAuthn surface wires the mirror, the daemon starts a background reconcile
  that reads every platform user, lists each tenant's IAM users once, and
  mirrors only the users missing from it, provisioning the default roles
  first for any tenant that lacks them. Users already present are left alone, so
  the run is idempotent and safe on every start. A failure is logged with the
  user ID and counted, never fatal: one unreachable tenant does not stop the
  others, and startup is never blocked.

## Trust boundaries

1. **Caller → IAM.** On gRPC, all 41 methods are scoped. A platform token is
   checked against its `scp` claim. A token without scope claims is checked
   by the IAM PEP ([`docs/daemon/api.md`](../daemon/api.md) §5). **On MCP** each
   `iam_*` tool needs the scope of its gRPC twin; `iam_authenticate` is open,
   as on QUIC, and it, `iam_create_token` and `iam_revoke_token` refuse every
   caller ([api.md](api.md) §8).
2. **Platform → stack IAM.** The platform adapts and forwards; it does not
   decide.
3. **The mirror.** Two stores, one synchronisation point.
4. **Application secrets.** Write-only by design: rotate to obtain, never read.

## What this feature deliberately does not do

- **It does not store identities or decide authorization.**
- **It does not run a second RBAC decision point.**
- **It does not let an application secret be read.**
- **It does not manage platform tenancy** despite having routes with "tenant"
  in them.
- **It does not offer group membership changes from the CLI** — those two verbs
  are unimplemented stubs ([cli.md](cli.md) §3), not a scope decision.

## System Overview

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                            Trusted Platform                                  │
│                     (Single Binary, Modular Features)                        │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │                       IAM Module (pkg/iam/)                            │  │
│  │                      [Enabled via config]                              │  │
│  │                                                                        │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────────┐     │  │
│  │  │   Tenant    │  │  Identity   │  │  WebAuthn   │  │  OAuth2/   │     │  │
│  │  │  Manager    │  │   Store     │  │   FIDO2     │  │   OIDC     │     │  │
│  │  │             │  │             │  │             │  │            │     │  │
│  │  │ • Isolation │  │ • Users     │  │ • Register  │  │ • Provider │     │  │
│  │  │ • Quotas    │  │ • Groups    │  │ • Authn     │  │ • Consumer │     │  │
│  │  │ • Settings  │  │ • Roles     │  │ • Creds     │  │ • Tokens   │     │  │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └────────────┘     │  │
│  │                                                                        │  │
│  │  ┌──────────────────────────────────────────────────────────────────┐  │  │
│  │  │                    ABAC Policy Engine                            │  │  │
│  │  │                                                                  │  │  │
│  │  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐      │  │  │
│  │  │  │  Parser  │─▶│ Compiler │─▶│  Cache   │─▶│  Evaluator   │      │  │  │
│  │  │  │  (YAML)  │  │  (AST)   │  │  (LRU)   │  │ (zero-alloc) │      │  │  │
│  │  │  └──────────┘  └──────────┘  └──────────┘  └──────────────┘      │  │  │
│  │  └──────────────────────────────────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                     │                                        │
│                                     │ uses                                   │
│                                     ▼                                        │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │                   mTLS Authentication Layer                            │  │
│  │                      (pkg/auth/)                                       │  │
│  │                                                                        │  │
│  │  • Certificate validation        • TPM attestation                     │  │
│  │  • Client authentication         • Platform binding                    │  │
│  │  • IDevID/IAK verification       • Credential management               │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                     │                                        │
│                                     │ enforces                               │
│                                     ▼                                        │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │                     Storage Module (existing)                          │  │
│  │                                                                        │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────────┐     │  │
│  │  │  QuicBaaS   │  │    TPM      │  │    gRPC     │  │    REST    │     │  │
│  │  │  (storage)  │  │ (hardware)  │  │    API      │  │    API     │     │  │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └────────────┘     │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

## Components

### Tenant Manager

Manages multi-tenant isolation:

- Tenant CRUD operations
- Tenant settings and quotas
- Key prefix isolation (`__iam:tenant:{tenant_id}:...`)
- Cross-tenant access prevention

### Identity Store

User, group, and role management:

- User registration and profile management
- Group membership and hierarchy
- Role assignments and permissions
- Custom attributes for ABAC

### WebAuthn/FIDO2

Passwordless authentication:

- Passkey registration and authentication
- Hardware security key support (YubiKey, etc.)
- Credential management
- Platform authenticator support

### OAuth2/OIDC

Standards-compliant identity protocols:

- **Provider**: Issue tokens to registered applications
- **Consumer**: Federate identity from external providers
- PKCE, Device Authorization, Client Credentials flows
- ID Token, Access Token, Refresh Token management

### mTLS Authentication

Certificate-based authentication integrated with platform CA:

- IDevID certificate verification
- IAK attestation validation
- TPM-backed client certificates
- Certificate revocation checking

### ABAC Policy Engine

Attribute-Based Access Control:

- YAML policy parsing
- Condition compilation to AST
- Zero-allocation evaluation (~2-5us)
- LRU caching for compiled policies

## Data Model

All IAM data uses reserved prefixes:

```
Tenants:
__iam:tenant:{tenant_id}                     -> Tenant config
__iam:tenant:{tenant_id}:settings            -> Tenant settings

Identity:
__iam:tenant:{tenant_id}:user:{user_id}      -> User record
__iam:tenant:{tenant_id}:group:{group_id}    -> Group record
__iam:tenant:{tenant_id}:role:{role_id}      -> Role record

Credentials:
__iam:tenant:{tenant_id}:cred:{cred_id}      -> WebAuthn credential
__iam:tenant:{tenant_id}:cert:{fingerprint}  -> mTLS certificate binding
__iam:tenant:{tenant_id}:challenge:{id}      -> WebAuthn challenge (TTL)

OAuth2/OIDC:
__iam:tenant:{tenant_id}:client:{client_id}  -> OAuth client
__iam:tenant:{tenant_id}:token:{jti}         -> Token metadata
__iam:tenant:{tenant_id}:code:{code}         -> Auth code (TTL)
__iam:tenant:{tenant_id}:idp:{provider_id}   -> External IdP config

Policies:
__iam:tenant:{tenant_id}:policy:{policy_id}  -> Policy document
__iam:tenant:{tenant_id}:policy:compiled:{id}-> Compiled policy (binary)

Indexes:
__iam:idx:email:{email}                      -> tenant_id:user_id
__iam:idx:username:{tenant}:{name}           -> user_id
__iam:idx:cert:{fingerprint}                 -> tenant_id:user_id
```

## Authentication Flows

### WebAuthn Registration Flow

```
Browser                    Platform                    Storage
   │                          │                           │
   │ 1. Begin registration    │                           │
   │─────────────────────────▶│                           │
   │                          │                           │
   │ 2. Challenge + options   │                           │
   │◀─────────────────────────│                           │
   │                          │                           │
   │ 3. Create credential     │                           │
   │ (authenticator)          │                           │
   │                          │                           │
   │ 4. Attestation response  │                           │
   │─────────────────────────▶│                           │
   │                          │                           │
   │                          │ 5. Verify attestation     │
   │                          │                           │
   │                          │ 6. Store credential       │
   │                          │──────────────────────────▶│
   │                          │                           │
   │ 7. Success               │                           │
   │◀─────────────────────────│                           │
```

### WebAuthn Authentication Flow

```
Browser                    Platform                    Storage
   │                          │                           │
   │ 1. Begin authentication  │                           │
   │─────────────────────────▶│                           │
   │                          │                           │
   │                          │ 2. Get user credentials   │
   │                          │──────────────────────────▶│
   │                          │                           │
   │                          │ 3. Credentials list       │
   │                          │◀──────────────────────────│
   │                          │                           │
   │ 4. Challenge + allowList │                           │
   │◀─────────────────────────│                           │
   │                          │                           │
   │ 5. Get assertion         │                           │
   │ (authenticator)          │                           │
   │                          │                           │
   │ 6. Assertion response    │                           │
   │─────────────────────────▶│                           │
   │                          │                           │
   │                          │ 7. Verify signature       │
   │                          │                           │
   │                          │ 8. Update sign count      │
   │                          │──────────────────────────▶│
   │                          │                           │
   │ 9. JWT tokens            │                           │
   │◀─────────────────────────│                           │
```

### mTLS Authentication Flow

```
Client                     Platform                    TPM/CA
   │                          │                           │
   │ 1. TLS handshake         │                           │
   │ (client cert)            │                           │
   │─────────────────────────▶│                           │
   │                          │                           │
   │                          │ 2. Validate cert chain    │
   │                          │──────────────────────────▶│
   │                          │                           │
   │                          │ 3. Check revocation       │
   │                          │──────────────────────────▶│
   │                          │                           │
   │                          │ 4. Verify TPM attestation │
   │                          │ (if IDevID/IAK)           │
   │                          │──────────────────────────▶│
   │                          │                           │
   │                          │ 5. Extract identity       │
   │                          │                           │
   │                          │ 6. Apply ABAC policies    │
   │                          │                           │
   │ 7. Authorized response   │                           │
   │◀─────────────────────────│                           │
```

### OAuth2 Authorization Code Flow

```
User-Agent    Client App    Platform IAM    Resource
    │             │               │              │
    │ 1. Access   │               │              │
    │────────────▶│               │              │
    │             │               │              │
    │             │ 2. Redirect   │              │
    │◀────────────│               │              │
    │             │               │              │
    │ 3. Authorization request    │              │
    │────────────────────────────▶│              │
    │             │               │              │
    │ 4. Login (WebAuthn/mTLS)    │              │
    │◀───────────────────────────▶│              │
    │             │               │              │
    │ 5. Consent  │               │              │
    │◀───────────────────────────▶│              │
    │             │               │              │
    │ 6. Redirect with code       │              │
    │◀────────────────────────────│              │
    │             │               │              │
    │ 7. Code     │               │              │
    │────────────▶│               │              │
    │             │               │              │
    │             │ 8. Token exchange            │
    │             │──────────────▶│              │
    │             │               │              │
    │             │ 9. Tokens     │              │
    │             │◀──────────────│              │
    │             │               │              │
    │             │ 10. API request              │
    │             │──────────────────────────────▶│
    │             │               │              │
    │             │               │ 11. Validate │
    │             │               │◀─────────────│
    │             │               │              │
    │             │ 12. Response  │              │
    │◀────────────│◀──────────────────────────────│
```

## Authorization Flow

### ABAC Policy Evaluation

```
Request                   Policy Engine                 Decision
   │                           │                           │
   │ Subject, Action, Resource │                           │
   │──────────────────────────▶│                           │
   │                           │                           │
   │                           │ 1. Get applicable policies│
   │                           │ (by subject, resource)    │
   │                           │                           │
   │                           │ 2. Quick deny check       │
   │                           │ (bloom filter)            │
   │                           │                           │
   │                           │ 3. Evaluate deny rules    │
   │                           │ (highest priority first)  │
   │                           │                           │
   │                           │ 4. If deny matches ─▶ DENY│
   │                           │                           │
   │                           │ 5. Evaluate allow rules   │
   │                           │ (highest priority first)  │
   │                           │                           │
   │                           │ 6. If allow matches ─▶    │
   │                           │    ALLOW                  │
   │                           │                           │
   │                           │ 7. Default ─▶ DENY        │
   │                           │                           │
   │                           │        Decision           │
   │◀──────────────────────────│──────────────────────────▶│
```

### Policy Processing Pipeline

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Policy Processing                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   Phase 1: Parsing                                                          │
│   ┌───────────────────────────────────────────────────────────────────────┐ │
│   │  YAML Policy ─▶ Parser ─▶ Policy AST (structs)                        │ │
│   └───────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│   Phase 2: Compilation                                                      │
│   ┌───────────────────────────────────────────────────────────────────────┐ │
│   │  Condition: "subject.role == admin"                                   │ │
│   │     ─▶ Lexer: [subject][.][role][==][admin]                           │ │
│   │     ─▶ AST: BinaryExpr{Left: Path, Op: Eq, Right: Str}                │ │
│   │     ─▶ Bytecode: LOAD_PATH 0; LOAD_CONST 1; CMP_EQ                    │ │
│   └───────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│   Phase 3: Optimization                                                     │
│   ┌───────────────────────────────────────────────────────────────────────┐ │
│   │  • Resource Pattern Trie: O(k) lookup                                 │ │
│   │  • Deny Rule Bloom Filter: Quick check for potential denies           │ │
│   │  • Subject Selector Index: Fast policy lookup by role/group           │ │
│   └───────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│   Phase 4: Caching                                                          │
│   ┌───────────────────────────────────────────────────────────────────────┐ │
│   │  • Storage: __iam:tenant:acme:policy:compiled:p123                    │ │
│   │  • In-Memory: LRU cache with TTL (5 minutes default)                  │ │
│   └───────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Runtime Evaluation

Per-request authorization (~2-5us typical):

| Step | Operation | Time |
|------|-----------|------|
| 1 | Quick Deny Check (Bloom Filter) | ~10ns |
| 2 | Get Applicable Policies (Cache) | ~100ns |
| 3 | Resource Pattern Match (Trie) | ~50ns |
| 4 | Evaluate Deny Rules | ~1us |
| 5 | Evaluate Allow Rules | ~1us |
| 6 | Default Deny (if no match) | ~0ns |

## Multi-Tenant Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Multi-Tenant Isolation                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   Tenant A (acme-corp)                                                      │
│   ┌───────────────────────────────────────────────────────────────────────┐ │
│   │  __iam:tenant:acme-corp:user:*                                        │ │
│   │  __iam:tenant:acme-corp:group:*                                       │ │
│   │  __iam:tenant:acme-corp:policy:*                                      │ │
│   │  keys/tenant/acme-corp/**  (KMS keys)                                 │ │
│   └───────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│   Tenant B (globex-inc)                                                     │
│   ┌───────────────────────────────────────────────────────────────────────┐ │
│   │  __iam:tenant:globex-inc:user:*                                       │ │
│   │  __iam:tenant:globex-inc:group:*                                      │ │
│   │  __iam:tenant:globex-inc:policy:*                                     │ │
│   │  keys/tenant/globex-inc/**  (KMS keys)                                │ │
│   └───────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│   Cross-Tenant Prevention:                                                  │
│   • All operations scoped to tenant from JWT/mTLS                           │
│   • Key prefix isolation enforced by storage layer                          │
│   • Policies cannot reference other tenants' resources                      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Security Considerations

### Authentication Security

| Layer | Protection |
|-------|------------|
| WebAuthn | Phishing-resistant, hardware-backed |
| mTLS | Certificate-based, TPM attestation |
| OAuth2 | PKCE required, short-lived tokens |
| Sessions | Secure cookies, rotation on auth events |

### Authorization Security

| Layer | Protection |
|-------|------------|
| Policies | Default deny, explicit allow |
| Evaluation | Deny rules take precedence |
| Caching | TTL-based expiration, invalidation |
| Audit | All decisions logged |

### Data Security

| Layer | Protection |
|-------|------------|
| Storage | Encrypted at rest (KMS) |
| Transport | TLS 1.3, mTLS for internal |
| Credentials | Never stored in plaintext |
| Tokens | Signed (RS256/ES256), validated |

## Platform Modes

go-trusted-platform supports two mutually exclusive operational modes:

| Mode | Description | IAM Architecture |
|------|-------------|------------------|
| **Local** | Isolated/enterprise deployments | Server/Client (this document) |
| **P2P** | Distributed/global deployments | Distributed IAM (see `docs/dht/`) |

This document covers **Local mode** IAM architecture. For P2P mode IAM, see the DHT documentation.

## Local Control Plane IAM (Local Mode)

In Local mode, a local control plane (single node or Raft cluster) provides centralized IAM services for its data plane nodes. The control plane runs IAM in **Server Mode**, while data plane nodes run in **Client Mode**.

### Server Mode

In **Server Mode**, a node operates as the IAM authority for the trusted network:

```
+------------------------------------------+
|           Platform Server Node            |
|                                           |
|  +----------------+  +----------------+   |
|  |   QuicBaaS     |  |    IAM Core    |   |
|  |   (Storage)    |<-|   (Service)    |   |
|  +----------------+  +----------------+   |
|                            |              |
|  +----------------+  +-----v--------+     |
|  |   OIDC/OAuth   |  |   Policy     |     |
|  |   Provider     |  |   Engine     |     |
|  +----------------+  +--------------+     |
+------------------------------------------+
           |                    |
           | mTLS               | gRPC/QUIC
           |                    |
    +------v------+      +------v------+
    | Client Node |      | Client Node |
    +-------------+      +-------------+
```

Server Mode responsibilities:
- User/service account management
- Authentication (mTLS certificate validation, OIDC flows)
- Authorization policy management
- Token issuance (JWTs for session management)
- Audit logging
- GDPR/compliance operations

#### Client Mode

In **Client Mode**, a node delegates all IAM operations to a remote Server Mode node:

```
+------------------------------------------+
|           Platform Client Node            |
|                                           |
|  +----------------+  +----------------+   |
|  |   IAM Client   |->|   Remote IAM   |   |
|  |   (Proxy)      |  |   Server       |   |
|  +----------------+  +----------------+   |
|                            |              |
|  +----------------+  +-----v--------+     |
|  |   Local Cache  |  |   Token      |     |
|  |   (Optional)   |  |   Validator  |     |
|  +----------------+  +--------------+     |
+------------------------------------------+
```

Client Mode responsibilities:
- Forward authentication requests to IAM server
- Cache authorization decisions (with TTL)
- Validate JWTs locally (using public keys from server)
- Report authentication/authorization events to server

### Node Enrollment Flow

1. Node generates IDevID/IAK using local TPM 2.0
2. Node connects to IAM server via mTLS (using manufacturer-issued IDevID or bootstrap certificate)
3. IAM server validates node identity through attestation
4. Upon successful validation, IAM server issues platform-specific certificates
5. Node receives tenant assignment and initial policy configuration

```
Node                                     IAM Server
  |                                           |
  |---- mTLS connection (IDevID cert) ------->|
  |                                           |
  |<--- Challenge for attestation ------------|
  |                                           |
  |---- TPM Quote (signed by IAK) ----------->|
  |                                           |
  |<--- Platform certificates + tenant ID ----|
```

### Configuration

#### Server Mode

```yaml
iam:
  mode: server
  quicbaas:
    address: "unix:///var/run/quicbaas.sock"
  oidc:
    issuer: "https://iam.trusted-platform.local"
  jwt:
    signing_key_ref: "kms://platform-iam-signing-key"
    ttl: "1h"
```

#### Client Mode

```yaml
iam:
  mode: client
  server:
    address: "grpcs://iam.trusted-platform.local:9443"
    mtls:
      cert: "/etc/platform/node.crt"
      key: "/etc/platform/node.key"
      ca: "/etc/platform/ca-bundle.pem"
  cache:
    enabled: true
    ttl: "5m"
```

### Implementation Status (Local Mode)

| Component | Status |
|-----------|--------|
| IAM Service (Server Mode) | In Progress |
| IAM Client (Client Mode) | Planned |
| Node Enrollment | Planned |
| Authorization Caching | Planned |

## P2P Network IAM (P2P Mode)

P2P mode uses a fully distributed IAM architecture with no centralized server. Key differences:

- **CA**: FROST threshold signatures (33% threshold) instead of local CA
- **Identity**: IDevID issued by distributed FROST CA pools
- **Authorization**: Distributed policy via DHT + reputation system
- **OIDC**: Distributed OIDC provider

For complete P2P mode IAM architecture, see:
- `docs/dht/05-certificate-authority.md` - FROST CA design
- `docs/dht/03-security-trust.md` - Trust model
- `docs/dht/09-defense-reputation.md` - Reputation system
