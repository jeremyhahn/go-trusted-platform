# Integrated Security Architecture - Engineering Design

> **Last Updated**: 2026-01-18
> **Specification Version**: 1.0
> **TCG Compliance**: TPM 2.0 Keys for Device Identity and Attestation v1.10r9

This document provides the complete engineering design for go-trusted-platform's integrated security architecture, including implementation code, detailed flows, and TCG specification compliance.

---

## Table of Contents

1. [Current Architecture Analysis](#part-1-current-architecture-analysis)
2. [Gaps for Top Secret Compliance](#part-2-gaps-for-top-secret-compliance)
3. [Device Enrollment Strategies](#part-3-device-enrollment-strategies)
4. [Multi-Tenant DNS Architecture](#part-4-multi-tenant-dns-architecture)
5. [Implementation Code](#part-5-implementation-code)
6. [User Journeys](#part-6-user-journeys)
7. [TCG TPM 2.0 Identity Provisioning](#part-7-tcg-tpm-20-identity-provisioning)
8. [Testing Specifications](#part-8-testing-specifications)
9. [Verification Commands](#part-9-verification-commands)

---

## Part 1: Current Architecture Analysis

### Component Status

| Component | Library | Status |
|-----------|---------|--------|
| WebAuthn/FIDO2 | go-trusted-platform | Complete |
| JWT Token Service | go-trusted-platform | Complete |
| mTLS Auth | go-trusted-platform | Complete |
| TPM Attestation | go-xkms | Complete |
| ABAC Policy Engine | go-quicbaas | Complete |
| Auth Middleware | go-trusted-platform | Complete (AuthMiddleware, AuthzMiddleware) |
| KMS | go-quicbaas | Complete |
| Multi-tenancy | go-quicbaas | Complete |
| CA/ACME | go-trusted-ca | Complete |
| OIDC Provider | go-quicbaas | Complete |
| EAB Verification | - | Storage only |
| Device Enrollment Auth | - | Gap identified |

### Authentication Flow Diagrams

#### User Authentication (WebAuthn to JWT)

```
+-----------------------------------------------------------------------+
|  Browser                                                              |
|    |                                                                  |
|    v                                                                  |
|  WebAuthn Registration/Login (/api/v1/webauthn/*)                     |
|    |                                                                  |
|    v                                                                  |
|  go-webauthn library validates credential                             |
|    |                                                                  |
|    v                                                                  |
|  JWTService issues token (asymmetric signing via go-xkms)         |
|    |                                                                  |
|    v                                                                  |
|  JWT in Authorization header for subsequent requests                  |
+-----------------------------------------------------------------------+
```

#### Device Authentication (mTLS + TPM)

```
+----------------------------------------------------------------------+
|  Device with IDevID certificate                                       |
|    |                                                                  |
|    v                                                                  |
|  mTLS handshake (certificate validated)                               |
|    |                                                                  |
|    v                                                                  |
|  AuthMiddleware extracts tenant from cert (CN, OU, O, SAN)           |
|    |                                                                  |
|    v                                                                  |
|  Optional: TPM attestation verification                               |
|    |                                                                  |
|    v                                                                  |
|  IAMSession created with tenant context                               |
+----------------------------------------------------------------------+
```

#### Authorization (QuicBaaS PEP)

```
+----------------------------------------------------------------------+
|  Request with IAMSession in context                                  |
|    |                                                                 |
|    v                                                                 |
|  AuthzMiddleware calls PEP.CheckPermission()                         |
|    |                                                                 |
|    v                                                                 |
|  QuicBaaS PolicyEngine evaluates ABAC policy                         |
|    |                                                                 |
|    v                                                                 |
|  Allow/Deny decision (cached with TTL)                               |
+----------------------------------------------------------------------+
```

---

## Part 2: Gaps for Top Secret Compliance

### Gap 1: Device Enrollment Without IDevID

**Problem**: New devices need to enroll but have no IDevID certificate yet.

**Current State**:
- enroll-01 challenge validates TPM via MakeCredential/ActivateCredential
- EAB storage exists but verification logic is in go-trusted-ca
- No tenant-controlled device approval

**Solution**: EAB-Based Tenant Enrollment

```
NEW DEVICE ENROLLMENT:
+----------------------------------------------------------------------+
|  1. Tenant Admin creates EAB credential in QuicBaaS IAM              |
|     +-> EAB = { kid, hmac_key, tenant_id, allowed_serials }          |
|                                                                       |
|  2. Device receives EAB credential (out-of-band provisioning)        |
|     +-> Via fleet management, USB provisioning, or manual entry      |
|                                                                       |
|  3. Device initiates ACME enrollment with EAB                        |
|     +-> POST /acme/new-account with externalAccountBinding           |
|     +-> EAB HMAC proves pre-authorization                            |
|                                                                       |
|  4. Platform validates EAB via QuicBaaS IAM                          |
|     +-> Verify HMAC signature                                        |
|     +-> Check tenant_id and allowed_serials                          |
|     +-> Rate limit per EAB credential                                |
|                                                                       |
|  5. enroll-01 challenge validates TPM                                |
|     +-> TCG-CSR-IDEVID with MakeCredential/ActivateCredential        |
|                                                                       |
|  6. IDevID certificate issued with tenant in extension               |
|     +-> Certificate contains tenant_id in custom OID                 |
|     +-> Device now has mTLS credential for future auth               |
+----------------------------------------------------------------------+
```

### Gap 2: User Registration & Tenant Provisioning

**Problem**: No self-service user registration with automatic tenant creation.

**Solution**: Web interface with WebAuthn registration

```
USER REGISTRATION FLOW:
+----------------------------------------------------------------------+
|  1. User visits go-trusted-platform web interface                    |
|  2. WebAuthn registration (passwordless from start)                  |
|  3. System generates random tenant UUID (e.g., 550e8400-...)         |
|  4. User becomes tenant owner with full admin rights                 |
|  5. QuicBaaS IAM creates tenant namespace + OIDC identity            |
|  6. User can now:                                                    |
|     +-- Add other users to their tenant (WebAuthn invite)            |
|     +-- Create device profiles                                       |
|     +-- Generate vTPM images                                         |
|     +-- Create EAB credentials                                       |
+----------------------------------------------------------------------+
```

### Gap 3: Device Profile Management

**Problem**: No way to pre-define devices before enrollment.

**Solution**: Device profiles in QuicBaaS IAM with multiple enrollment strategies

```go
type EnrollmentStrategy string

const (
    EnrollmentFullPreProvision  EnrollmentStrategy = "full_preprovision"
    EnrollmentEKOnly            EnrollmentStrategy = "ek_only"
    EnrollmentEAB               EnrollmentStrategy = "eab"
    EnrollmentAttestation       EnrollmentStrategy = "attestation"
)

type DeviceProfile struct {
    ID          string             `json:"id"`
    TenantID    string             `json:"tenant_id"`
    Name        string             `json:"name"`
    Description string             `json:"description,omitempty"`
    Strategy    EnrollmentStrategy `json:"strategy"`

    // Strategy-specific configuration
    VTPMConfig  *VTPMConfig        `json:"vtpm_config,omitempty"`
    EAB         *EABCredential     `json:"eab,omitempty"`
    Attestation *AttestationConfig `json:"attestation,omitempty"`

    // Device configuration (becomes app.App after enrollment)
    AppConfig   *app.App           `json:"app_config"`

    // Enrollment state
    Enrolled    bool               `json:"enrolled"`
    EnrolledAt  *time.Time         `json:"enrolled_at,omitempty"`

    CreatedAt   time.Time          `json:"created_at"`
    UpdatedAt   time.Time          `json:"updated_at"`
}

type VTPMConfig struct {
    Algorithm      string `json:"algorithm"`        // RSA2048, ECC256
    PreIssueCerts  bool   `json:"pre_issue_certs"`  // true = Level 1, false = Level 2
    RetainImage    bool   `json:"retain_image"`     // Keep copy after download
}

type EABCredential struct {
    KeyID    string     `json:"kid"`
    HMACKey  []byte     `json:"-"`           // Never serialized in responses
    Used     bool       `json:"used"`
    UsedAt   *time.Time `json:"used_at,omitempty"`
}

type AttestationConfig struct {
    ExpectedEKHash string   `json:"expected_ek_hash"` // SHA-256 of EK cert
    Manufacturer   string   `json:"manufacturer,omitempty"`
    AllowedPCRs    []int    `json:"allowed_pcrs,omitempty"`
}
```

### Gap 4: Authorization Architecture

**Decision**: Hybrid approach - coarse auth in middleware, fine-grained in service.

**Rationale**: Middleware doesn't know which specific resource until handler/service loads it.

```
HYBRID AUTHORIZATION:
+----------------------------------------------------------------------+
|  Request -> AuthMiddleware -> AuthzMiddleware -> Router -> Handler   |
|              ^ Auth              ^ Coarse Authz                       |
|                                                                       |
|  Middleware: "Can user access DNS resources at all?"                 |
|  Service:    "Does user's tenant own THIS specific zone?"            |
|                                                                       |
|  Example flow:                                                       |
|  1. AuthMiddleware: Extract JWT/mTLS -> IAMSession                   |
|  2. AuthzMiddleware: Check "dns:zone:*:read" permission              |
|  3. Handler: Load zone, set resource context                         |
|  4. Service: Verify zone.TenantID == session.TenantID               |
+----------------------------------------------------------------------+
```

This is more secure than pure middleware auth because:
- Middleware can't pre-load every resource to check ownership
- Service layer has full context for fine-grained decisions
- Ownership checks happen at point of data access

---

## Part 3: Device Enrollment Strategies

### Profile-First Principle

**The device profile is created BEFORE the device exists/boots.** This is the most secure approach because:
- Device identity is defined before it can be impersonated
- Enrollment is authenticated against pre-defined profile
- Tenant controls exactly which devices can join

### Strategy Spectrum

From most pre-provisioned to most dynamic:

| Level | Strategy | Pre-provision | Enrollment | Use Case |
|-------|----------|---------------|------------|----------|
| 1 | **Full Pre-Provision** | EK cert + IDevID | None (already enrolled) | Air-gapped, highest security |
| 2 | **EK-Only vTPM** | EK only | endorse-01 -> enroll-01 | Cloud VMs, flexible |
| 3 | **EAB + Challenges** | EAB credential | EAB auth -> endorse-01 -> enroll-01 | Physical devices, IoT |
| 4 | **Attestation** | EK cert fingerprint | TPM attestation -> enroll-01 | Enterprise hardware |

### ACME Challenge Types

| Challenge | Purpose | Output |
|-----------|---------|--------|
| **endorse-01** | Validate TPM Endorsement Key | EK Certificate |
| **enroll-01** | Validate device identity (MakeCredential/ActivateCredential) | IDevID Certificate |

### Unified Enrollment Flow

```
+----------------------------------------------------------------------+
|  1. Device boots with TPM (virtual or hardware)                      |
|  2. Device connects to platform ACME endpoint                        |
|  3. Platform determines enrollment strategy from:                    |
|     +-- EAB credential -> EAB strategy                               |
|     +-- vTPM signature -> PreProvision/EKOnly strategy               |
|     +-- EK attestation -> Attestation strategy                       |
|                                                                       |
|  4. Authentication based on strategy:                                |
|     +-- Full PreProvision: Already enrolled (skip to step 6)         |
|     +-- EAB: Validate HMAC signature, mark EAB as used               |
|     +-- EKOnly: Proceed to challenges                                |
|     +-- Attestation: Validate EK matches profile fingerprint         |
|                                                                       |
|  5. Enrollment challenges (if needed):                               |
|     +-- endorse-01: Issue EK certificate (if not pre-issued)         |
|     +-- enroll-01: Issue IDevID certificate                          |
|                                                                       |
|  6. Platform sends app.App configuration to device                   |
|  7. Device is now enrolled with full identity                        |
|  8. Device profile marked as enrolled in QuicBaaS IAM                |
+----------------------------------------------------------------------+
```

### EAB Delivery Methods

| Method | Description | Use Case |
|--------|-------------|----------|
| **QR Code** | Display in web UI, device scans | IoT setup, kiosks |
| **Secure File** | Download encrypted credentials file | Fleet management |
| **API** | Programmatic access | Infrastructure-as-code |

### vTPM Retention Policy

| Setting | Behavior | Trade-off |
|---------|----------|-----------|
| `retain_image: false` | One-time download, then deleted | Most secure |
| `retain_image: true` | Keep encrypted copy | Enables disaster recovery |

---

## Part 4: Multi-Tenant DNS Architecture

### Uniform Tenant Model

All systems are treated identically - each has a `TenantID` from platform config:

```yaml
# Platform config - tenant_id defaults to "platform" if not specified
app:
  tenant_id: "platform"    # or "acme-corp", "tenant-xyz", etc.
```

**Key principles:**
- No hardcoded "platform" logic - all tenants are equal
- Zones owned by tenants via `Zone.TenantID`
- Systems with same `TenantID` share zones and security boundary
- Single tenant can have multiple zones across multiple nodes
- Authorization = simple ownership check

### Zone Ownership Model

```
TENANTS (all treated uniformly):
+-- "platform"              (default tenant for infrastructure)
|   +-- example.internal.   (zone owned by "platform")
|   +-- example.com.        (zone owned by "platform")
|   +-- [nodes: server1, server2, ...]
|
+-- "acme-corp"             (customer tenant)
|   +-- acme-internal.local.
|   +-- acme-services.io.
|   +-- [nodes: device1, device2, ...]
|
+-- "tenant-xyz"            (customer tenant)
    +-- xyz.internal.
    +-- xyz-app.com.
    +-- [nodes: node1, node2, ...]
```

### DNSSEC Key Namespace

```
KMS Key Paths (uniform structure):
+-- dnssec/platform/example-internal/ksk
+-- dnssec/platform/example-internal/zsk
+-- dnssec/acme-corp/acme-services-io/ksk
+-- dnssec/acme-corp/acme-services-io/zsk
+-- dnssec/tenant-xyz/xyz-app-com/zsk
```

### Authorization Rules

| Caller Tenant | Zone Owner | Action | Result |
|---------------|------------|--------|--------|
| X | X | CRUD | Allowed (same tenant) |
| X | Y | Any | Denied (different tenant) |
| Any | Any | Read (DNS query) | Allowed (DNS resolution) |

**Note:** Cross-tenant administrative access is handled via IAM roles/permissions, not hardcoded tenant logic.

### Registration Behavior Matrix

| CN Type | Zone Match | Caller Tenant | Config Flag | Result |
|---------|------------|---------------|-------------|--------|
| `server.example.internal` | Zone exists | platform | - | Add A record (if owner) |
| `server.example.internal` | Zone exists | acme-corp | - | Denied (wrong tenant) |
| `api.acme-corp.io` | Zone exists | acme-corp | - | Add A record (owner) |
| `api.acme-corp.io` | Zone exists | tenant-xyz | - | Denied (wrong tenant) |
| `app.newdomain.io` | No match | platform | `AllowExternal=true` | Create zone (owner: platform) |
| `app.newdomain.io` | No match | acme-corp | `AllowExternal=true` | Create zone (owner: acme-corp) |
| `svc.custom.local` | No match | acme-corp | `AllowInternal=true` | Create zone (owner: acme-corp) |

---

## Part 5: Implementation Code

### Zone Entity with Tenant Ownership

**File: `pkg/dns/entities/zone.go`**

```go
type Zone struct {
    ID          uint64              `json:"id"`
    Name        string              `json:"name"`
    TenantID    string              `json:"tenant_id"`  // Required: owner tenant
    TTL         uint32              `json:"ttl"`
    Internal    bool                `json:"internal"`
    Description string              `json:"description,omitempty"`
    RecordSet   RecordSet           `json:"record_set"`
    CreatedAt   time.Time           `json:"created_at,omitempty"`
    UpdatedAt   time.Time           `json:"updated_at,omitempty"`
}

// IsOwnedBy returns true if the zone is owned by the specified tenant
func (z *Zone) IsOwnedBy(tenantID string) bool {
    return z.TenantID == tenantID
}
```

### DNS Error Types

**File: `pkg/dns/errors.go`**

```go
var (
    ErrUnauthorizedZoneAccess = errors.New("unauthorized zone access: caller tenant does not own zone")
    ErrMissingTenantContext   = errors.New("missing tenant context")
    ErrMissingTenantID        = errors.New("zone requires tenant_id")
)
```

### DNSSEC Key Management

**File: `pkg/dns/dnssec_keystore.go`**

```go
// buildKeyPath constructs a tenant-aware KMS path for DNSSEC keys
// All tenants (including "platform") use the same path structure: dnssec/{tenant}/{zone}/{keytype}
func (ks *KMSKeyStore) buildKeyPath(tenantID, zoneName string, keyType KeyType) string {
    // Sanitize zone name for path
    safeZoneName := strings.ReplaceAll(strings.TrimSuffix(zoneName, "."), ".", "-")

    keyTypeSuffix := map[KeyType]string{
        KeyTypeKSK: "ksk",
        KeyTypeZSK: "zsk",
    }[keyType]

    // Uniform path structure: dnssec/{tenant}/{zone}/{keytype}
    // Examples:
    //   dnssec/platform/example-internal/ksk
    //   dnssec/acme-corp/acme-services-io/zsk
    return fmt.Sprintf("dnssec/%s/%s/%s", tenantID, safeZoneName, keyTypeSuffix)
}

// GenerateKSK generates a tenant-scoped KSK
func (ks *KMSKeyStore) GenerateKSK(ctx context.Context, tenantID, zoneName string, algorithm uint8) (*dns.DNSKEY, error) {
    keyPath := ks.buildKeyPath(tenantID, zoneName, KeyTypeKSK)
    // ... generate key at tenant-scoped path ...
}

// GenerateZoneKeys generates KSK and ZSK for a zone (auto-generates if not specified)
func (ks *KMSKeyStore) GenerateZoneKeys(ctx context.Context, zone *entities.Zone) error {
    // KSK - Key Signing Key
    kskPath := ks.buildKeyPath(zone.TenantID, zone.Name, KeyTypeKSK)
    if _, err := ks.kms.GenerateKey(ctx, kskPath, ks.algorithm); err != nil {
        return fmt.Errorf("failed to generate KSK: %w", err)
    }

    // ZSK - Zone Signing Key
    zskPath := ks.buildKeyPath(zone.TenantID, zone.Name, KeyTypeZSK)
    if _, err := ks.kms.GenerateKey(ctx, zskPath, ks.algorithm); err != nil {
        return fmt.Errorf("failed to generate ZSK: %w", err)
    }

    return nil
}
```

### Authorization Checks in Service Layer

**File: `pkg/dns/service.go`**

```go
// authorizeZoneAccess checks if the caller can access/modify a zone
// Simple ownership check - app's tenant must match zone's tenant
func (s *Service) authorizeZoneAccess(zone *entities.Zone, action string) error {
    appTenant := s.params.App.TenantID
    if appTenant == "" {
        return ErrMissingTenantContext
    }

    // Simple ownership check - all tenants treated uniformly
    if !zone.IsOwnedBy(appTenant) {
        s.params.Config.Logger.Warn("unauthorized zone access attempt",
            slog.String("app_tenant", appTenant),
            slog.String("zone_tenant", zone.TenantID),
            slog.String("zone", zone.Name),
            slog.String("action", action))
        return ErrUnauthorizedZoneAccess
    }

    return nil
}

// Note: Cross-tenant administrative access should be handled via IAM roles/permissions
// at the API layer, not in the DNS service. The service enforces pure tenant isolation.

// Save saves a zone with authorization check
func (s *Service) Save(ctx context.Context, zone *entities.Zone) error {
    // TenantID is required
    if zone.TenantID == "" {
        return ErrMissingTenantID
    }

    // Fine-grained ownership check
    session := iam.SessionFromContext(ctx)
    if session != nil && !zone.IsOwnedBy(session.TenantID) {
        return ErrUnauthorizedZoneAccess
    }

    // Check authorization for existing zones
    if existing, err := s.zoneDAO.Get(ctx, zone.ID); err == nil {
        if err := s.authorizeZoneAccess(existing, "write"); err != nil {
            return err
        }
    }

    // Generate DNSSEC keys if not exists
    if s.dnssecSvc != nil && s.dnssecSvc.IsEnabled() {
        if err := s.dnssecSvc.EnsureZoneKeys(ctx, zone); err != nil {
            return fmt.Errorf("failed to setup DNSSEC keys: %w", err)
        }
        if err := s.dnssecSvc.SignZone(ctx, zone); err != nil {
            return fmt.Errorf("failed to sign zone: %w", err)
        }
    }

    return s.zoneDAO.Save(ctx, zone)
}
```

### Multi-Tenant Zone Registration

**File: `pkg/dns/service.go`**

```go
func (s *Service) RegisterWebservice(ctx context.Context, cn string) error {
    // Get tenant from app config (required)
    appTenant := s.params.App.TenantID
    if appTenant == "" {
        return ErrMissingTenantContext
    }

    // ... existing normalization code ...

    // Check if CN matches configured zones
    if internalZoneName != "" && strings.HasSuffix(cn, internalZoneName) {
        zone, err := s.InternalZone(ctx)
        if err != nil {
            return fmt.Errorf("failed to get internal zone: %w", err)
        }
        // Verify app owns this zone
        if err := s.authorizeZoneAccess(zone, "write"); err != nil {
            return err
        }
        // ... add A record ...
    } else if publicZoneName != "" && strings.HasSuffix(cn, publicZoneName) {
        // ... similar for public zone ...
    } else {
        // CN doesn't match any configured zone - create new zone owned by app's tenant
        return s.registerWebserviceNewZone(ctx, cn, appTenant)
    }
    // ... rest of existing code ...
}

// registerWebserviceNewZone creates a tenant-scoped zone
func (s *Service) registerWebserviceNewZone(ctx context.Context, cn, tenantID string) error {
    // Parse domain
    _, _, rootDomain, tld, err := ParseDomainName(strings.TrimSuffix(cn, "."))
    if err != nil {
        return fmt.Errorf("failed to parse CN %s: %w", cn, err)
    }

    isPublicTLD := IsTLD(tld)

    // Check registration permissions
    if isPublicTLD {
        if !s.params.Config.AllowExternalRegistration {
            return fmt.Errorf("CN %s requires external registration which is disabled", cn)
        }
    } else {
        if !s.params.Config.AllowInternalRegistration {
            return fmt.Errorf("CN %s requires internal registration which is disabled", cn)
        }
    }

    // Determine IP
    var ip string
    if isPublicTLD {
        ip = s.params.PublicIPv4.String()
    } else {
        ip = s.params.PrivateIPv4.String()
    }

    if ip == "" || ip == "<nil>" {
        return fmt.Errorf("no IP address available")
    }

    // Build zone name
    zoneName := rootDomain
    if !strings.HasSuffix(zoneName, ".") {
        zoneName += "."
    }

    // Check if zone already exists
    existingZone, err := s.Zone(ctx, zoneName)
    if err == nil && existingZone != nil {
        // Verify caller can modify this zone
        if err := s.authorizeZoneAccess(existingZone, "write"); err != nil {
            return err
        }
        // Add A record to existing zone
        hostname := extractHostnameFromCN(cn, zoneName)
        existingZone.AddARecord(&entities.ARecord{Name: hostname, Value: ip, TTL: 3600})
        return s.Save(ctx, existingZone)
    }

    // Create new zone owned by caller's tenant
    hostname := extractHostnameFromCN(cn, zoneName)
    zone := s.createMinimalZone(zoneName, hostname, ip, !isPublicTLD, tenantID)

    s.params.Config.Logger.Info("creating new DNS zone",
        slog.String("zone", zoneName),
        slog.String("tenant", tenantID),
        slog.String("hostname", hostname))

    return s.Save(ctx, zone)
}

// createMinimalZone creates a new zone with tenant ownership
func (s *Service) createMinimalZone(zoneName, hostname, ip string, internal bool, tenantID string) *entities.Zone {
    return &entities.Zone{
        ID:          util.NewID([]byte(zoneName)),
        Name:        zoneName,
        TenantID:    tenantID,  // Set tenant ownership
        TTL:         3600,
        Internal:    internal,
        Description: fmt.Sprintf("Auto-created zone for %s.%s", hostname, zoneName),
        RecordSet: entities.RecordSet{
            SOARecord: entities.SOARecord{
                Name:       zoneName,
                MName:      fmt.Sprintf("ns1.%s", zoneName),
                RName:      fmt.Sprintf("hostmaster.%s", zoneName),
                Serial:     1,
                Refresh:    86400,
                Retry:      7200,
                Expire:     86400,
                MinimumTTL: 3600,
                TTL:        3600,
            },
            NSRecords: []*entities.NSRecord{
                {Name: zoneName, Value: fmt.Sprintf("ns1.%s", zoneName), TTL: 3600},
            },
            ARecords: []*entities.ARecord{
                {Name: "@", Value: ip, TTL: 3600},
                {Name: "ns1", Value: ip, TTL: 3600},
                {Name: hostname, Value: ip, TTL: 3600},
            },
        },
        CreatedAt: time.Now(),
    }
}
```

### DNSSEC Service Tenant Support

**File: `pkg/dns/dnssec.go`**

```go
// SignZoneWithTenant signs a zone using tenant-scoped DNSSEC keys
func (d *DNSSECService) SignZoneWithTenant(zone *entities.Zone, tenantID string) error {
    // Use tenant-scoped key path
    ksk, err := d.keystore.GetOrGenerateKSK(d.ctx, tenantID, zone.Name, d.config.Algorithm)
    if err != nil {
        return fmt.Errorf("failed to get/generate KSK for tenant %s: %w", tenantID, err)
    }

    zsk, err := d.keystore.GetOrGenerateZSK(d.ctx, tenantID, zone.Name, d.config.Algorithm)
    if err != nil {
        return fmt.Errorf("failed to get/generate ZSK for tenant %s: %w", tenantID, err)
    }

    // ... sign zone with tenant keys ...
}
```

### ABAC Policy Definitions

**File: `configs/policies/dns.yaml`**

```yaml
# DNS Zone Owner Policy
# Allows tenant members to manage their own zones
name: dns-zone-owner
description: Tenant members can manage zones they own
resources:
  - "dns:zone:*"
subjects:
  roles:
    - dns-admin
    - dns-operator
conditions:
  - "subject.tenant_id == resource.tenant_id"
actions:
  - read
  - write
  - delete
  - sign
effect: allow
priority: 100

---
# DNS Zone Read Policy
# Allows any authenticated user to read zones (for DNS resolution)
name: dns-zone-read
description: Any authenticated user can read zones
resources:
  - "dns:zone:*"
subjects:
  authenticated: true
actions:
  - read
effect: allow
priority: 50
```

### Handler with Resource Context

**File: `pkg/webservice/v1/router/dns.go`**

```go
func (h *DNSHandler) UpdateZone(w http.ResponseWriter, r *http.Request) {
    zone, err := h.parseZoneFromRequest(r)
    if err != nil {
        h.error(w, r, err)
        return
    }

    // Set resource context for ABAC evaluation
    // AuthzMiddleware uses this for policy evaluation
    ctx := authz.WithResource(r.Context(), authz.Resource{
        Type:     "dns:zone",
        ID:       zone.Name,
        TenantID: zone.TenantID,
        Attributes: map[string]interface{}{
            "internal": zone.Internal,
        },
    })

    // Service call - includes fine-grained ownership check
    if err := h.dnsService.Save(ctx, zone); err != nil {
        h.error(w, r, err)
        return
    }

    h.success(w, r, zone)
}
```

---

## Part 6: User Journeys

### Journey 1: New User Registration

```
1. ACCOUNT CREATION
+----------------------------------------------------------------------+
|  User visits https://platform.example.com/register                   |
|    |                                                                  |
|    v                                                                  |
|  WebAuthn registration (FIDO2 passkey or security key)              |
|    |                                                                  |
|    v                                                                  |
|  Platform generates: tenant_id = "550e8400-e29b-41d4-..."           |
|    |                                                                  |
|    v                                                                  |
|  QuicBaaS IAM creates:                                               |
|    - Tenant namespace                                                |
|    - User as tenant owner                                            |
|    - OIDC identity                                                   |
|    - Default policies                                                |
|    |                                                                  |
|    v                                                                  |
|  User redirected to tenant dashboard                                 |
+----------------------------------------------------------------------+
```

### Journey 2: Adding Team Members

```
2. USER INVITATION
+----------------------------------------------------------------------+
|  Tenant owner: "Invite user" -> enters email                          |
|    |                                                                  |
|    v                                                                  |
|  Platform sends invite link with one-time token                      |
|    |                                                                  |
|    v                                                                  |
|  Invited user clicks link -> WebAuthn registration                    |
|    |                                                                  |
|    v                                                                  |
|  User added to tenant with specified role                            |
|    |                                                                  |
|    v                                                                  |
|  Both users share same tenant_id and resources                       |
+----------------------------------------------------------------------+
```

### Journey 3: Creating Device Profiles

```
3. DEVICE PROFILE CREATION
+----------------------------------------------------------------------+
|  Tenant admin: "Create Device Profile"                               |
|    |                                                                  |
|    v                                                                  |
|  Choose enrollment strategy:                                         |
|    [ ] Full Pre-Provision (vTPM with EK+IDevID)                     |
|    [ ] EK-Only vTPM (vTPM with EK, enroll via ACME)                 |
|    [x] EAB (Physical device with EAB credential)                    |
|    [ ] Attestation (Known hardware TPM)                              |
|    |                                                                  |
|    v                                                                  |
|  Configure device app.App template:                                  |
|    - Tenant ID: (auto-filled from session)                           |
|    - DNS zones: ["internal.example.com"]                             |
|    - Services: ["dns", "webserver"]                                  |
|    |                                                                  |
|    v                                                                  |
|  Generate credentials:                                               |
|    EAB strategy -> Generate EAB (kid + hmac_key)                     |
|    |                                                                  |
|    v                                                                  |
|  Deliver credentials:                                                |
|    [QR Code] [Download File] [Copy API Call]                        |
+----------------------------------------------------------------------+
```

### Journey 4: Device Enrollment

```
4. DEVICE ENROLLMENT (EAB Strategy)
+----------------------------------------------------------------------+
|  Physical device boots with hardware TPM                             |
|    |                                                                  |
|    v                                                                  |
|  Device provisioned with EAB credential (QR scan / file)            |
|    |                                                                  |
|    v                                                                  |
|  Device -> Platform ACME: POST /acme/new-account                     |
|    { externalAccountBinding: { kid, signature } }                   |
|    |                                                                  |
|    v                                                                  |
|  Platform validates EAB against QuicBaaS IAM:                       |
|    - HMAC signature valid                                            |
|    - EAB not yet used                                                |
|    - Device profile found                                            |
|    |                                                                  |
|    v                                                                  |
|  ACME challenges:                                                    |
|    - endorse-01: Platform issues EK certificate                      |
|    - enroll-01: TPM MakeCredential/ActivateCredential               |
|    |                                                                  |
|    v                                                                  |
|  Platform issues IDevID certificate:                                 |
|    - CN: device-name.tenant-id.platform.example.com                 |
|    - Extension: tenant_id = "550e8400-..."                           |
|    |                                                                  |
|    v                                                                  |
|  Platform sends app.App configuration from device profile            |
|    |                                                                  |
|    v                                                                  |
|  Device profile marked enrolled in QuicBaaS IAM                      |
|    |                                                                  |
|    v                                                                  |
|  Device now operates with full identity                              |
+----------------------------------------------------------------------+
```

### Journey 5: Device Operations

```
5. DEVICE ACCESSING RESOURCES (mTLS)
+----------------------------------------------------------------------+
|  Device -> Platform API (mTLS with IDevID certificate)               |
|    |                                                                  |
|    v                                                                  |
|  AuthMiddleware extracts tenant from cert extension                  |
|    -> IAMSession { tenant_id, device_id, roles }                     |
|    |                                                                  |
|    v                                                                  |
|  AuthzMiddleware: Coarse check "dns:zone:*:write"                   |
|    |                                                                  |
|    v                                                                  |
|  Handler: Load zone, DNS service checks ownership                    |
|    if zone.TenantID != session.TenantID -> 403                       |
|    |                                                                  |
|    v                                                                  |
|  Service performs operation                                          |
|    |                                                                  |
|    v                                                                  |
|  Audit log: { device, tenant, action, resource, result }            |
+----------------------------------------------------------------------+
```

---

## Part 7: TCG TPM 2.0 Identity Provisioning

This section implements the TCG "TPM 2.0 Keys for Device Identity and Attestation" specification v1.10r9, particularly Section 6 on Identity Provisioning.

### Key Concepts

| Term | Definition |
|------|------------|
| **EK** | Endorsement Key - TPM manufacturer-provisioned key proving TPM authenticity |
| **IAK** | Initial Attestation Key - OEM-provisioned restricted signing key for attestation |
| **IDevID** | Initial Device Identity - IEEE 802.1AR device identity certificate |
| **LAK** | Locally-signed Attestation Key - Owner-provisioned AK based on IAK |
| **LDevID** | Locally-signed Device Identity - Owner-provisioned DevID based on IAK/LAK |
| **TCG-CSR-IDEVID** | CSR format for initial device enrollment (version 0x01xxxxxx) |
| **TCG-CSR-LDEVID** | CSR format for local device enrollment (version 0x02xxxxxx) |

### Assurances Provided by Enrollment

Per TCG spec Section 6.1.2, enrollment provides these assurances:

| Assurance | Description | Verification Method |
|-----------|-------------|---------------------|
| **A** | TPM is authentic | Validate EK certificate chain to TPM manufacturer |
| **B** | Specific TPM is authentic | TPM2_ActivateCredential proves EK private key possession |
| **C** | AK is authentic | AK is resident in same TPM as EK (MakeCredential/ActivateCredential) |
| **D** | AK bound to device | Platform Certificate or OEM assertion binds TPM to device |
| **E** | IDevID is authentic | IDevID certified by IAK using TPM2_Certify |

### Strategy 1: Full Pre-Provision (Section 6.2)

OEM IAK + IDevID Single Pass - most secure approach where both IAK and IDevID are created and certified before device deployment.

```
FULL PRE-PROVISION FLOW (Section 6.2.2):
+----------------------------------------------------------------------+
|  1. Platform creates IAK in Endorsement Hierarchy                    |
|     +-> TPM2_CreatePrimary: Restricted, fixedTPM, fixedParent        |
|                                                                       |
|  2. Platform creates IDevID in Endorsement Hierarchy                 |
|     +-> TPM2_CreatePrimary: Unrestricted, fixedTPM, fixedParent      |
|                                                                       |
|  3. Platform certifies IDevID with IAK                               |
|     +-> TPM2_Certify(IDevID, IAK) -> TPM2B_Attest + Signature        |
|                                                                       |
|  4. Build TCG-CSR-IDEVID structure:                                  |
|     +-- prodModel, prodSerial (device identity)                      |
|     +-- EK Certificate                                               |
|     +-- IAK Public Area (TPMT_PUBLIC)                               |
|     +-- IDevID Public Area (TPMT_PUBLIC)                            |
|     +-- IDevID TPM2B_Attest + signature                             |
|                                                                       |
|  5. Sign CSR with IDevID key                                         |
|     +-> TPM2_Hash + TPM2_Sign                                        |
|                                                                       |
|  6. Send TCG-CSR-IDEVID to CA                                       |
|                                                                       |
|  7. CA validates:                                                    |
|     +-- Verify CSR signature with IDevID public key                 |
|     +-- Verify EK Certificate (TPM manufacturer chain)              |
|     +-- Verify IDevID residency via IAK TPM2B_Attest                |
|     +-- Verify IAK attributes (Restricted, fixedTPM, fixedParent)   |
|     +-- Verify IDevID attributes (fixedTPM, fixedParent)            |
|                                                                       |
|  8. CA issues MakeCredential challenge (optional for single-trip)   |
|     +-> Encrypt nonce with EK, bind to IAK Name                      |
|                                                                       |
|  9. Device: TPM2_ActivateCredential -> recover nonce                 |
|                                                                       |
| 10. CA validates nonce, issues IAK + IDevID certificates            |
|                                                                       |
| 11. Certificates stored in TPM NV or device storage                  |
+----------------------------------------------------------------------+
```

**For vTPM Pre-Provision:**
- Platform generates vTPM with EK already provisioned
- IAK and IDevID created during vTPM generation
- Certificates pre-issued before device boots
- Device boots already enrolled (no ACME flow needed)

### Strategy 2: EK-Only vTPM (Section 6.1)

Device has vTPM with EK but no IAK/IDevID yet.

```
EK-ONLY FLOW:
+----------------------------------------------------------------------+
|  PHASE 1: endorse-01 (EK Validation)                                |
|  +-- Device sends EK certificate to CA                              |
|  +-- CA validates EK cert chain to TPM manufacturer                 |
|  +-- CA issues MakeCredential challenge                             |
|  +-- Device: TPM2_ActivateCredential                                |
|  +-- CA validates: TPM is authentic (Assurance A, B)                |
|                                                                       |
|  PHASE 2: enroll-01 (IAK + IDevID Issuance per Section 6.2)         |
|  +-- Device creates IAK + IDevID keys                               |
|  +-- Device builds TCG-CSR-IDEVID                                   |
|  +-- CA validates and issues MakeCredential                         |
|  +-- Device: TPM2_ActivateCredential                                |
|  +-- CA issues IAK + IDevID certificates                            |
+----------------------------------------------------------------------+
```

### Strategy 3: EAB + ACME (Section 6.1 + EAB)

Physical devices with hardware TPM, pre-authorized via EAB.

```
EAB + ACME FLOW:
+----------------------------------------------------------------------+
|  1. Tenant creates EAB credential (kid + HMAC key)                   |
|     +-> Associated with DeviceProfile in QuicBaaS IAM                |
|                                                                       |
|  2. EAB delivered to device (QR, file, API)                          |
|                                                                       |
|  3. Device: ACME new-account with externalAccountBinding             |
|     +-> HMAC proves pre-authorization                                |
|                                                                       |
|  4. Platform validates EAB, marks as used                            |
|                                                                       |
|  5. Proceed with endorse-01 (if no EK cert) + enroll-01             |
|     +-> Full TCG-CSR-IDEVID flow per Section 6.1/6.2                 |
|                                                                       |
|  6. Platform issues IDevID with tenant_id in extension               |
+----------------------------------------------------------------------+
```

### Strategy 4: Attestation (Section 6.6)

Device has known EK fingerprint (from Platform Certificate).

```
ATTESTATION FLOW (Section 6.6.2):
+----------------------------------------------------------------------+
|  1. Platform Certificate binds EK to device (OEM signed)             |
|     +-> Contains EK cert serial number, device model/serial          |
|                                                                       |
|  2. DeviceProfile stores expected EK fingerprint                     |
|                                                                       |
|  3. Device creates LAK in Storage Hierarchy                          |
|     +-> TPM2_Create: Restricted, fixedParent, fixedTPM               |
|                                                                       |
|  4. Build TCG-CSR-LDEVID:                                           |
|     +-- Platform Certificate                                         |
|     +-- EK Certificate                                               |
|     +-- LAK Public Area                                              |
|                                                                       |
|  5. Sign with LAK                                                    |
|     +-> TPM2_Hash + TPM2_Sign                                        |
|                                                                       |
|  6. CA validates:                                                    |
|     +-- Verify Platform Certificate (OEM chain)                      |
|     +-- Verify EK matches Platform Certificate                       |
|     +-- Verify EK fingerprint matches DeviceProfile                  |
|     +-- Issue MakeCredential challenge                               |
|                                                                       |
|  7. Device: TPM2_ActivateCredential (requires EH authorization)     |
|                                                                       |
|  8. CA issues LAK certificate with device info from Platform Cert   |
+----------------------------------------------------------------------+
```

### TCG-CSR-IDEVID Structure

```go
// TCG-CSR-IDEVID structure per TCG Spec Section 13.1
// Version byte 0x01 indicates IDEVID CSR
type TCGCSRIDEVID struct {
    StructVer   [4]byte           // Version 1.0 = 0x01000100
    ContentSize uint32            // Size of csrContents
    SigSize     uint32            // Size of signature
    Content     TCGIDEVIDContent  // CSR content
    Signature   []byte            // DER encoded signature
}

type TCGIDEVIDContent struct {
    StructVer              [4]byte  // Version 1.0 = 0x00000100
    HashAlgoID             uint32   // TCG algorithm ID for CSR hash
    HashSize               uint32   // Size of hash

    // Product identification
    ProdModel              string   // Device model (unterminated)
    ProdSerial             string   // Device serial number
    ProdCAData             []byte   // CA-specific required data

    // Attestation data (for Section 6.1.4 Included Attestation)
    BootEventLog           []byte   // Boot event log

    // TPM keys and certificates
    EKCert                 []byte   // TPM EK certificate
    AttestationPub         []byte   // IAK public area (TPMT_PUBLIC)
    AttestationCreateTkt   []byte   // TPM2_CertifyCreation ticket
    AttestationCertifyInfo []byte   // TPM2_Certify info
    AttestationCertifySig  []byte   // TPM2_Certify signature

    // IDevID key (for single-pass Section 6.2)
    SigningPub             []byte   // IDevID public area
    SigningCertifyInfo     []byte   // TPM2_Certify info for IDevID
    SigningCertifySig      []byte   // TPM2_Certify signature for IDevID
}
```

### TCG-CSR-LDEVID Structure

```go
// TCG-CSR-LDEVID structure per TCG Spec Section 13.2
// Version byte 0x02 indicates LDEVID CSR
type TCGCSRLDEVID struct {
    StructVer   [4]byte           // Version 1.0 = 0x02000100
    ContentSize uint32            // Size of csrContents
    SigSize     uint32            // Size of signature
    Content     TCGLDEVIDContent  // CSR content
    Signature   []byte            // DER encoded signature
}

type TCGLDEVIDContent struct {
    StructVer       [4]byte  // Version 1.1 = 0x02001001
    HashAlgoID      uint32   // TCG algorithm ID
    HashSize        uint32   // Size of hash

    // Certificates for chain of trust
    EKCert          []byte   // TPM EK certificate
    IAKCert         []byte   // IAK certificate (for 6.3, 6.4, 6.5)
    PlatformCert    []byte   // Platform certificate (for 6.6)

    // LDevID/LAK key
    TPMPublic       []byte   // LDevID/LAK TPM2B_Public structure
    CertifyInfo     []byte   // TPM2_Certify info
    CertifyInfoSig  []byte   // TPM2_Certify signature
}
```

### ACME Challenge Mapping

| Challenge | TCG Procedure | Purpose |
|-----------|---------------|---------|
| **endorse-01** | Section 6.1 steps 5-6 | EK validation, issue EK cert if missing |
| **enroll-01** | Section 6.2 full flow | Issue IAK + IDevID certificates |
| **certify-01** | Section 6.3-6.5 | Issue LAK/LDevID based on existing IAK |

### Included Attestation Flow (Section 6.1.4)

```
INCLUDED ATTESTATION FLOW:
+----------------------------------------------------------------------+
|  1. Device freshly booted (RECOMMENDED)                              |
|                                                                       |
|  2. Create IAK with creationPCRs selection                           |
|     +-> TPM2_CreatePrimary with PCR digest in creationData           |
|                                                                       |
|  3. Certify creation with IAK                                        |
|     +-> TPM2_CertifyCreation -> signed attestation + PCR digest      |
|                                                                       |
|  4. Include in TCG-CSR-IDEVID:                                      |
|     +-- Boot event log                                               |
|     +-- Signed attestation structure                                 |
|     +-- Creation data with PCR digest                                |
|                                                                       |
|  5. CA validates:                                                    |
|     +-- EK certificate                                               |
|     +-- IAK attributes                                               |
|     +-- Boot event log matches expected values                       |
|     +-- PCRs meet policy requirements                                |
|                                                                       |
|  6. After MakeCredential/ActivateCredential:                        |
|     +-- Start audited TPM session                                    |
|     +-- Read PCRs to verify no changes since creation                |
|     +-- Close session, send audit log to CA                          |
|                                                                       |
|  7. CA verifies PCRs unchanged, issues certificates                  |
+----------------------------------------------------------------------+
```

### TPM Key Storage Handles

Per TCG Spec Section 7.3.1, persistent key handles:

| Key | Handle | Notes |
|-----|--------|-------|
| **IDevID** | 0x81020000 | OEM persistent |
| **IAK** | 0x81020001 | OEM persistent |

### Certificate Requirements (IEEE 802.1AR)

Per TCG Spec Section 8 and Annex B:

| Requirement | Status | Notes |
|-------------|--------|-------|
| Unique Subject Name | MANDATORY | Never reissued to another device |
| X.500 DN in Subject | MANDATORY | |
| subjectAltName with HardwareModuleName | RECOMMENDED | TCG: MANDATORY |
| subjectKeyIdentifier | RECOMMENDED | |
| Signature Suites: RSA-2048/SHA-256, ECDSA P-256/SHA-256, ECDSA P-384/SHA-384 | At least one | |

### Implementation Files

| Component | File | Description |
|-----------|------|-------------|
| TCG-CSR Structures | `pkg/ca/acme/tcgcsr/types.go` | TCG-CSR-IDEVID/LDEVID structs |
| CSR Builder | `pkg/ca/acme/tcgcsr/builder.go` | Build CSRs from TPM data |
| CSR Validator | `pkg/ca/acme/tcgcsr/validator.go` | Validate CSR per TCG spec |
| ACME endorse-01 | `pkg/ca/acme/challenge/endorse.go` | EK validation challenge |
| ACME enroll-01 | `pkg/ca/acme/challenge/enroll.go` | IAK+IDevID enrollment |
| Device Enrollor | `pkg/device/enrollment/enrollor.go` | Client-side enrollment |
| TPM Key Creator | `pkg/device/enrollment/keys.go` | IAK/IDevID key creation |

### Integration Flow

```
INTEGRATED ENROLLMENT + TENANT FLOW:
+----------------------------------------------------------------------+
|  1. Tenant creates DeviceProfile with enrollment strategy            |
|     +-> Stored in QuicBaaS IAM with TenantID                         |
|                                                                       |
|  2. Based on strategy:                                               |
|     +-- Full Pre-Provision: Generate vTPM + pre-issue certs          |
|     +-- EK-Only: Generate vTPM with EK only                          |
|     +-- EAB: Generate EAB credential for physical device             |
|     +-- Attestation: Store expected EK fingerprint                   |
|                                                                       |
|  3. Device boots, initiates ACME enrollment                          |
|                                                                       |
|  4. Platform matches device to DeviceProfile via:                    |
|     +-- EAB credential (EAB strategy)                               |
|     +-- vTPM signature (Pre-Provision/EK-Only)                      |
|     +-- EK fingerprint (Attestation strategy)                       |
|                                                                       |
|  5. Execute TCG-compliant enrollment per strategy                    |
|     +-> Build TCG-CSR-IDEVID/LDEVID per Section 6                    |
|                                                                       |
|  6. CA issues certificates with:                                     |
|     +-- TenantID in custom extension OID                             |
|     +-- Device model/serial from CSR                                 |
|     +-- HardwareModuleName in subjectAltName                         |
|                                                                       |
|  7. Device receives certificates + app.App configuration             |
|                                                                       |
|  8. DeviceProfile marked enrolled in QuicBaaS IAM                    |
|                                                                       |
|  9. Device uses IDevID for mTLS -> TenantID extracted from cert      |
+----------------------------------------------------------------------+
```

---

## Part 8: Testing Specifications

### Unit Tests (39 tests)

**User Registration:**
1. `TestWebAuthnRegistration_CreatesTenant` - Registration generates tenant UUID
2. `TestWebAuthnRegistration_UniqueTenantsPerUser` - Each user gets unique tenant

**Device Profile:**
3. `TestDeviceProfile_Create_EABStrategy` - Creates profile with EAB credentials
4. `TestDeviceProfile_Create_VTPMStrategy` - Creates profile with vTPM config
5. `TestDeviceProfile_EABGeneration` - EAB kid and HMAC key are unique
6. `TestDeviceProfile_EABSingleUse` - EAB can only be used once

**TCG-CSR Structures:**
7. `TestTCGCSRIDEVID_Build` - Build valid TCG-CSR-IDEVID structure
8. `TestTCGCSRIDEVID_BuildWithAttestation` - Include boot event log + creation attestation
9. `TestTCGCSRIDEVID_SinglePass` - Include IDevID + TPM2_Certify per Section 6.2
10. `TestTCGCSRIDEVID_Validate` - Validate CSR structure and signature
11. `TestTCGCSRIDEVID_ValidateIAKAttributes` - Verify Restricted, fixedTPM, fixedParent
12. `TestTCGCSRIDEVID_ValidateEKCert` - Verify EK certificate chain
13. `TestTCGCSRLDEVID_Build` - Build valid TCG-CSR-LDEVID structure
14. `TestTCGCSRLDEVID_Validate` - Validate LDEVID CSR per Section 6.3-6.6
15. `TestTCGCSR_BigEndianEncoding` - Verify big-endian byte ordering per spec

**Enrollment Challenges:**
16. `TestEndorse01_ValidEKCert` - EK certificate validation passes
17. `TestEndorse01_InvalidEKCert` - Reject invalid EK certificate
18. `TestEndorse01_MakeCredentialChallenge` - Generate MakeCredential blob
19. `TestEnroll01_ValidTCGCSR` - Accept valid TCG-CSR-IDEVID
20. `TestEnroll01_InvalidIAKAttributes` - Reject non-Restricted AK
21. `TestEnroll01_ActivateCredentialPOP` - Verify proof of possession
22. `TestEnroll01_SinglePassIDevID` - Issue IAK + IDevID per Section 6.2
23. `TestCertify01_LAKBasedOnIAK` - LAK certification per Section 6.3
24. `TestCertify01_LDevIDBasedOnIAK` - LDevID certification per Section 6.4

**Enrollment Strategies:**
25. `TestEnrollment_EABValidation` - Valid EAB HMAC passes
26. `TestEnrollment_EABReuse_Rejected` - Used EAB is rejected
27. `TestEnrollment_ProfileLookup` - EAB maps to device profile
28. `TestEnrollment_IDevIDHasTenantExtension` - Certificate includes tenant OID
29. `TestEnrollment_FullPreProvision` - vTPM already enrolled
30. `TestEnrollment_EKOnly` - endorse-01 + enroll-01 flow
31. `TestEnrollment_Attestation` - Platform cert + EK fingerprint

**Certificate Extensions:**
32. `TestCertificate_TenantIDExtension` - Custom OID for tenant
33. `TestCertificate_HardwareModuleName` - subjectAltName per IEEE 802.1AR
34. `TestCertificate_UniqueSubjectName` - Never reissued to another device
35. `TestCertificate_PersistentHandle` - Keys at 0x81020000/0x81020001

**DNS Multi-Tenancy:**
36. `TestZone_IsOwnedBy` - Verify tenant ownership check
37. `TestZone_Save_RequiresTenantID` - Zone without tenant fails
38. `TestZone_OwnershipCheck` - Cross-tenant access denied
39. `TestDNSSEC_KeyPath_IncludesTenant` - Key paths scoped to tenant

### Integration Tests (13 tests)

1. **Full user journey** - Registration -> device profile -> enrollment -> operation
2. **EAB enrollment E2E** - Profile creation -> EAB delivery -> device enrollment
3. **vTPM enrollment E2E** - Profile creation -> vTPM download -> VM boot (pre-enrolled)
4. **Multi-tenant isolation** - Enrolled devices can only access own tenant's resources
5. **DNSSEC key separation** - Each tenant/zone has separate DNSSEC keys
6. **Cross-protocol testing** - All enrollment flows work via REST, gRPC, QUIC
7. **Full Pre-Provision E2E** - vTPM generation -> pre-issued certs -> VM boot -> mTLS
8. **EK-Only E2E** - vTPM with EK -> endorse-01 -> enroll-01 -> IAK+IDevID -> mTLS
9. **EAB + ACME E2E** - EAB credential -> ACME new-account -> TCG-CSR-IDEVID -> certs
10. **Platform Cert E2E** - Known EK hash -> TCG-CSR-LDEVID -> LAK cert -> mTLS
11. **Included Attestation E2E** - Fresh boot -> creation attestation -> PCR validation -> certs
12. **MakeCredential/ActivateCredential E2E** - Full proof of possession flow
13. **Certificate Chain Validation E2E** - EK -> TPM manufacturer -> root

---

## Part 9: Verification Commands

### User Registration

```bash
# WebAuthn registration creates tenant
curl -X POST https://platform.example.com/api/v1/register \
  -H "Content-Type: application/json" \
  -d '{"username": "user@example.com"}'
# Returns: WebAuthn challenge

# Complete WebAuthn registration
# Platform creates: { tenant_id: "550e8400-...", user_id: "..." }
```

### Device Profile Creation

```bash
# Create device profile with EAB strategy
platformctl device-profile create \
  --name "server-01" \
  --strategy eab \
  --config '{"dns": {"zones": ["internal.example.com"]}}'
# Returns: { id: "profile-123", eab: { kid: "...", hmac_key: "..." } }

# Get EAB as QR code
platformctl device-profile eab --id "profile-123" --format qr

# Get EAB as downloadable file
platformctl device-profile eab --id "profile-123" --format file > eab.json
```

### Device Enrollment (EAB)

```bash
# Device enrolls with EAB
curl -X POST https://platform.example.com/acme/new-account \
  -H "Content-Type: application/jose+json" \
  -d '{"protected": "...", "payload": "...", "signature": "..."}'
# EAB validated, ACME enrollment proceeds
# endorse-01 challenge issued
# enroll-01 challenge issued
# IDevID certificate issued with tenant_id extension
```

### Multi-Tenant Zone Isolation

```bash
# Tenant A creates zone (via enrolled device)
platformctl dns zone create --name "example.internal"
# Verify: Zone.TenantID = (from device's IDevID cert)

# Tenant B device cannot modify Tenant A's zone
platformctl dns record add --zone "example.internal" --name "test"
# Expected: Error "unauthorized zone access"

# Same tenant can modify their own zone
platformctl dns record add --zone "example.internal" --name "test"
# Expected: Success
```

### DNSSEC Key Isolation

```bash
# Verify tenant zone keys in KMS
platformctl kms list --prefix "dnssec/"
# Expected per-tenant, per-zone keys:
#   dnssec/{tenant-uuid}/example-internal/ksk
#   dnssec/{tenant-uuid}/example-internal/zsk
```

### vTPM Generation (Pre-Provision Strategy)

```bash
# Create device profile with full pre-provision
platformctl device-profile create \
  --name "vm-01" \
  --strategy full_preprovision \
  --config '{"dns": {"zones": ["cloud.example.com"]}}'
# Platform generates vTPM with EK cert + IDevID

# Download vTPM image (one-time if retain_image=false)
platformctl device-profile vtpm --id "profile-456" > vtpm.img
# Attach to VM, device boots already enrolled
```

---

## References

- [TCG TPM 2.0 Keys for Device Identity and Attestation v1.10r9](https://trustedcomputinggroup.org/resource/tpm-2-0-keys-for-device-identity-and-attestation/)
- [IEEE 802.1AR - Secure Device Identity](https://standards.ieee.org/standard/802_1AR-2018.html)
- [RFC 8555 - ACME Protocol](https://datatracker.ietf.org/doc/html/rfc8555)
- [ROADMAP.md](../ROADMAP.md) - Development roadmap
- [security-model.md](security-model.md) - Security model overview

---

## Revision History

| Date | Changes |
|------|---------|
| 2026-01-18 | Initial document with full engineering design |
| 2026-01-18 | Added complete implementation code snippets |
| 2026-01-18 | Added TCG specification compliance section |
| 2026-01-18 | Added user journeys and verification commands |
