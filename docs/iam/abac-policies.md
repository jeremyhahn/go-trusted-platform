# ABAC Policy Syntax Reference

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [architecture.md](architecture.md) and [api.md](api.md). RBAC is decided upstream; the REST adapter forwards only `spec.rules[]` name, effect, priority, actions and resources, dropping `when`, `unless`, subjects and variables. No `apiVersion` is read.

Complete reference for Trusted Platform IAM's Attribute-Based Access Control policy language.

## Policy Document Structure

```yaml
apiVersion: abac.trustedplatform.io/v1
kind: Policy
metadata:
  name: string                    # Unique policy name
  tenant: string                  # Owning tenant
  description: string             # Human description
  labels: map[string]string       # Arbitrary labels
  priority: int                   # Evaluation order (higher=first)

spec:
  subjects: SubjectSelector       # WHO this applies to
  variables: map[string]Expression # Reusable expressions
  rules: []Rule                   # Authorization rules
```

## Subject Selection

```yaml
subjects:
  # Match specific entities
  users: [alice, bob, charlie]      # Specific user IDs
  groups: [engineering, devops]     # Group memberships
  roles: [admin, developer]         # Role assignments
  services: [api-gateway, worker]   # Service accounts

  # Match by attributes
  match:
    department: engineering         # Exact match
    clearance: { gte: 3 }          # Numeric comparison
    location: { in: [us, eu, uk] } # Set membership
    email: { endswith: @acme.com } # Pattern match

  # Match all authenticated users
  authenticated: true

  # Match all (including anonymous)
  any: true
```

## Rule Structure

```yaml
rules:
  - name: rule-identifier           # Unique within policy
    effect: allow | deny            # Authorization decision
    priority: 100                   # Rule priority (optional)

    actions:                        # WHAT operations
      - read
      - write
      - delete
      - list
      - admin
      - "*"                         # Wildcard (all actions)

    resources:                      # WHICH resources
      - keys/tenant/${subject.tenant}/**
      - indexes/production/*
      - "keys/shared/public-*"

    when:                           # Conditions (ALL must be true)
      - <condition>
      - <condition>

    unless:                         # Negative conditions (ANY fails)
      - <condition>
```

## Condition Operators

### Equality

```yaml
subject.department == "engineering"     # Equals
subject.department != "hr"              # Not equals
subject.department eq "engineering"     # Equals (alternate)
subject.department neq "hr"             # Not equals (alternate)
```

### Numeric Comparison

```yaml
subject.clearance > 3                   # Greater than
subject.clearance >= 3                  # Greater than or equal
subject.clearance < 5                   # Less than
subject.clearance <= 5                  # Less than or equal
resource.size between 0..10MB           # Range (inclusive)
```

### String Patterns

```yaml
subject.email endswith "@acme.com"      # Suffix match
resource.name startswith "report-"      # Prefix match
resource.path contains "/admin/"        # Substring match
resource.name matches "doc-[0-9]+"      # Regex match
resource.name like "report-*-final"     # Glob pattern
```

### Set Membership

```yaml
subject.role in [admin, operator]       # Value in set
subject.role notin [guest, anonymous]   # Value not in set
```

### Collection Operations

```yaml
subject.roles contains admin            # List contains value
subject.roles notcontains guest         # List doesn't contain
subject.roles containsall [a, b]        # List contains ALL values
subject.roles containsany [a, b, c]     # List contains ANY value
subject.groups overlaps [admins, ops]   # Lists have common elements
subject.groups disjoint [banned]        # Lists have no common elements
```

### Existence

```yaml
subject.mfa_verified exists             # Attribute is set
resource.owner notexists                # Attribute is not set
subject.metadata.custom_field exists    # Nested attribute check
```

### Time Operators

```yaml
# Time of day
time.hour between 9..17                 # Hour range (24h format)
time.minute < 30                        # Minute of hour

# Day of week
time.weekday in [mon, tue, wed, thu, fri]  # Weekdays
time.weekday in [sat, sun]              # Weekends
time.weekday notin [sat, sun]           # Not weekends

# Date comparison
time.date before 2025-12-31             # Before date
time.date after 2025-01-01              # After date
time.date between 2025-01-01..2025-12-31# Date range

# Duration / Age
time.since(subject.password_changed) < 90d   # Time since event
time.since(subject.last_login) < 7d     # Recent activity
time.until(resource.expires) > 1h       # Time until event
resource.age < 30d                      # Resource age

# Combined
time.hour between 9..17 and time.weekday in [mon..fri]
```

### Network Operators

```yaml
# IP address
request.ip in 10.0.0.0/8               # Single CIDR
request.ip in [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16]  # Multiple
request.ip notin 0.0.0.0/0             # Exclusion
request.ip == 192.168.1.100            # Exact IP

# Named networks (defined in tenant config)
request.ip in $corporate_network        # Named network reference
request.ip in $allowed_vpns             # Named network list
```

### Logical Operators

```yaml
# Implicit AND - all conditions in 'when' list
when:
  - subject.authenticated
  - request.ip in 10.0.0.0/8
  - time.hour between 9..17

# Explicit AND
when:
  - and:
      - subject.role == admin
      - subject.mfa_verified exists

# Inline AND
when:
  - subject.authenticated and request.ip in 10.0.0.0/8

# Explicit OR
when:
  - or:
      - subject.role == admin
      - resource.owner == subject.id
      - resource.public == true

# Inline OR
when:
  - subject.role == admin or resource.owner == subject.id

# NOT
when:
  - not subject.suspended
  - not (resource.archived and resource.locked)

# Using 'unless' (equivalent to NOT)
unless:
  - subject.suspended
  - resource.deleted

# Complex combinations
when:
  - and:
      - subject.authenticated
      - or:
          - subject.role == admin
          - and:
              - resource.owner == subject.id
              - time.hour between 9..17

# Quantifiers
when:
  - all:                                # All must be true
      - subject.authenticated
      - subject.mfa_verified exists
      - request.ip in $corporate_network

  - any:                                # At least one must be true
      - subject.role == admin
      - subject.role == operator
      - resource.public == true

  - none:                               # None must be true
      - subject.suspended
      - subject.locked
      - resource.deleted
```

## Variable References

### Built-in Variables

```yaml
# Subject variables (from authenticated user/service)
${subject.id}                           # User/service ID
${subject.name}                         # Username
${subject.email}                        # Email address
${subject.tenant}                       # Tenant ID
${subject.roles}                        # List of roles
${subject.groups}                       # List of groups
${subject.attrs.<key>}                  # Custom attribute

# Resource variables (from request context)
${resource.key}                         # Full resource key
${resource.type}                        # Resource type (keys, users, etc.)
${resource.owner}                       # Resource owner ID
${resource.tenant}                      # Resource tenant
${resource.tags.<key>}                  # Resource tag
${resource.meta.<key>}                  # Resource metadata

# Request variables (from current request)
${request.ip}                           # Client IP
${request.method}                       # HTTP method / gRPC method
${request.protocol}                     # rest, grpc, internal
${request.id}                           # Request ID
${request.headers.<key>}                # Request header

# Environment variables (from system)
${env.cluster}                          # Cluster ID
${env.node}                             # Node ID
${env.region}                           # Geographic region
${env.environment}                      # dev, staging, production
```

### Custom Variables

```yaml
spec:
  variables:
    tenant_prefix: "tenant/${subject.tenant}/"
    is_owner: resource.owner == subject.id
    is_admin: subject.roles contains admin
    is_business_hours: time.hour between 9..17 and time.weekday in [mon..fri]

  rules:
    - when:
        - ${is_owner} or ${is_admin}
        - ${is_business_hours}
      resources:
        - keys/${tenant_prefix}**
```

## Resource Patterns

```yaml
resources:
  # Exact match
  - keys/config/database

  # Single-level wildcard
  - keys/users/*/profile           # Matches keys/users/alice/profile

  # Multi-level wildcard
  - keys/tenant/acme/**            # Matches any depth under acme/

  # Variable substitution
  - keys/tenant/${subject.tenant}/**
  - keys/users/${subject.id}/**

  # Glob patterns
  - keys/reports/2024-*-final
  - keys/cache/session-[0-9]*
```

## Complete Examples

### Engineering Team Policy

```yaml
apiVersion: abac.trustedplatform.io/v1
kind: Policy
metadata:
  name: engineering-team-access
  tenant: acme-corp
  description: Access control for engineering team members
  labels:
    team: engineering
    environment: production

spec:
  subjects:
    groups: [engineering]
    match:
      department: engineering
      clearance: { gte: 2 }

  variables:
    tenant_prefix: "tenant/${subject.tenant}/"
    user_prefix: "tenant/${subject.tenant}/users/${subject.id}/"
    is_owner: resource.owner == subject.id
    is_admin: subject.roles contains admin
    is_business_hours: time.hour between 9..17 and time.weekday in [mon, tue, wed, thu, fri]

  rules:
    # Engineers can read all tenant data
    - name: read-tenant-data
      effect: allow
      actions: [read, list]
      resources:
        - keys/${tenant_prefix}**
      when:
        - subject.authenticated
        - request.ip in $corporate_network

    # Engineers can write to their own namespace
    - name: write-own-data
      effect: allow
      actions: [write, delete]
      resources:
        - keys/${user_prefix}**
      when:
        - ${is_business_hours}

    # Engineers can write to shared project data if they own it
    - name: write-project-data
      effect: allow
      actions: [write]
      resources:
        - keys/${tenant_prefix}projects/**
      when:
        - or:
            - ${is_owner}
            - subject.roles contains project-lead

    # Admins have full access
    - name: admin-full-access
      effect: allow
      actions: ["*"]
      resources:
        - keys/${tenant_prefix}**
      when:
        - ${is_admin}
        - subject.mfa_verified exists
        - time.since(subject.mfa_timestamp) < 4h

    # Block access to production data outside business hours
    - name: deny-production-off-hours
      effect: deny
      priority: 1000
      actions: [write, delete]
      resources:
        - keys/${tenant_prefix}production/**
      unless:
        - ${is_business_hours}
        - ${is_admin}

    # Block all cross-tenant access
    - name: deny-cross-tenant
      effect: deny
      priority: 9999
      actions: ["*"]
      resources:
        - keys/tenant/**
      unless:
        - resource.path startswith ${tenant_prefix}
```

### Service Account Policy

```yaml
apiVersion: abac.trustedplatform.io/v1
kind: Policy
metadata:
  name: api-service-policy
  tenant: acme-corp
  description: Policy for API gateway service

spec:
  subjects:
    services: [api-gateway]

  rules:
    - name: encrypt-user-data
      effect: allow
      actions: [crypto:encrypt, crypto:decrypt]
      resources:
        - keys/shared/user-data-key

    - name: read-config
      effect: allow
      actions: [read]
      resources:
        - keys/config/api-gateway/**

    - name: rotate-own-keys
      effect: allow
      actions: [keys:rotate]
      resources:
        - keys/services/api-gateway/**
```

### Read-Only User Policy

```yaml
apiVersion: abac.trustedplatform.io/v1
kind: Policy
metadata:
  name: viewer-policy
  tenant: acme-corp

spec:
  subjects:
    roles: [viewer]

  rules:
    - name: read-only
      effect: allow
      actions: [read, list]
      resources:
        - keys/tenant/${subject.tenant}/**
        - users/tenant/${subject.tenant}/**
      unless:
        - resource.tags.sensitive == true
```

### Contractor Time-Limited Policy

```yaml
apiVersion: abac.trustedplatform.io/v1
kind: Policy
metadata:
  name: contractor-policy
  tenant: acme-corp

spec:
  subjects:
    groups: [contractors]
    match:
      contract_end: { after: ${time.now} }

  variables:
    is_work_hours: time.hour between 8..18 and time.weekday in [mon..fri]

  rules:
    - name: project-access
      effect: allow
      actions: [read, write]
      resources:
        - keys/projects/${subject.attrs.assigned_project}/**
      when:
        - ${is_work_hours}
        - time.date before ${subject.attrs.contract_end}

    - name: deny-sensitive
      effect: deny
      priority: 100
      actions: ["*"]
      resources:
        - keys/**/sensitive/**
        - keys/**/pii/**
        - keys/**/financial/**
```

## Evaluation Order

1. **Explicit deny** rules are evaluated first (sorted by priority)
2. If any deny matches, request is **denied** immediately
3. **Allow** rules are evaluated next (sorted by priority)
4. If any allow matches, request is **allowed**
5. If no rules match, **implicit deny** (default)

## Best Practices

1. **Use variables** for repeated expressions
2. **Start with deny-all**, add specific allows
3. **Use priority** for deny rules to ensure they run first
4. **Keep policies focused** - one policy per logical grouping
5. **Test with dry-run** before applying
6. **Use named networks** instead of hardcoded CIDRs
7. **Require MFA** for sensitive operations
8. **Time-bound access** where appropriate
9. **Document policies** with descriptions and labels
10. **Review regularly** and remove stale policies

## Validation

Policies are validated on create/update:

| Check | Description |
|-------|-------------|
| Schema | YAML structure matches schema |
| Syntax | Condition expressions are valid |
| Resources | Resource patterns are valid |
| Variables | All referenced variables are defined |
| Actions | Actions are valid for resource types |
| Circular | No circular variable references |
| Scope | Policy only references own tenant |
