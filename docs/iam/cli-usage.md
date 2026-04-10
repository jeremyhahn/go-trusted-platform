# IAM CLI Usage Guide

This guide covers the `platformctl iam` command group for managing Identity and Access Management resources.

## Overview

The `platformctl iam` command provides comprehensive management of:

- **Users** - Create, update, delete users and manage role assignments
- **Groups** - Organize users into groups for collective access control
- **Roles** - Define permission sets that can be assigned to users
- **Tenants** - Multi-tenant isolation for organizations
- **Policies** - Fine-grained authorization policies
- **Applications** - OAuth 2.0 client registration and management

## Global Options

All `platformctl` commands support the following global flags:

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--config` | `-c` | `~/.platformctl/config.yaml` | Path to configuration file |
| `--context` | | Current context | Context to use (overrides current-context) |
| `--output` | `-o` | `table` | Output format: `table`, `json`, `yaml` |
| `--verbose` | `-v` | `false` | Enable verbose output |
| `--no-color` | | `false` | Disable colored output |

## Command Reference

### User Management

Manage users including creation, retrieval, updates, and role assignments.

```
platformctl iam user <subcommand>
```

#### user create

Create a new user in a tenant.

```bash
platformctl iam user create --tenant <tenant-id> --email <email> [flags]
```

**Flags:**

| Flag | Required | Description |
|------|----------|-------------|
| `--tenant` | Yes | Tenant ID |
| `--email` | Yes | User email address |
| `--name` | No | User display name |
| `--roles` | No | Comma-separated list of roles to assign |
| `--groups` | No | Comma-separated list of groups to add user to |
| `--attributes` | No | Comma-separated key=value pairs for custom attributes |

**Examples:**

```bash
# Create a basic user
platformctl iam user create --tenant acme --email user@example.com --name "John Doe"

# Create a user with roles
platformctl iam user create --tenant acme --email admin@example.com \
  --name "Admin User" --roles "admin,viewer"

# Create a user with custom attributes
platformctl iam user create --tenant acme --email user@example.com \
  --name "Jane Doe" --attributes "department=engineering,level=senior"
```

#### user get

Retrieve detailed information about a specific user.

```bash
platformctl iam user get <tenant-id> <user-id>
```

**Example:**

```bash
platformctl iam user get acme user-abc123
```

**Sample Output (table):**

```
User ID:     user-abc123
Tenant ID:   acme
Email:       user@example.com
Name:        John Doe
Roles:       admin, viewer
Groups:      engineering
MFA Verified: Yes
Created At:  2025-01-10 14:30:00
```

#### user list

List users in a tenant with optional filtering.

```bash
platformctl iam user list --tenant <tenant-id> [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--tenant` | Required | Tenant ID |
| `--limit` | 50 | Maximum number of users to return |
| `--offset` | 0 | Number of users to skip |
| `--email` | | Filter by email address |
| `--role` | | Filter by role |
| `--group` | | Filter by group |

**Examples:**

```bash
# List all users
platformctl iam user list --tenant acme

# List with pagination
platformctl iam user list --tenant acme --limit 20 --offset 0

# Filter by role
platformctl iam user list --tenant acme --role admin

# Output as JSON
platformctl iam user list --tenant acme -o json
```

#### user update

Update an existing user's properties.

```bash
platformctl iam user update --tenant <tenant-id> --user-id <user-id> [flags]
```

**Flags:**

| Flag | Required | Description |
|------|----------|-------------|
| `--tenant` | Yes | Tenant ID |
| `--user-id` | Yes | User ID to update |
| `--email` | No | New email address |
| `--name` | No | New display name |
| `--roles` | No | Comma-separated list of roles (replaces existing) |
| `--groups` | No | Comma-separated list of groups (replaces existing) |
| `--attributes` | No | Comma-separated key=value pairs (replaces existing) |

**Example:**

```bash
platformctl iam user update --tenant acme --user-id user-abc123 \
  --name "Updated Name" --roles "admin,editor"
```

#### user delete

Delete a user from a tenant.

```bash
platformctl iam user delete <tenant-id> <user-id>
```

**Example:**

```bash
platformctl iam user delete acme user-abc123
```

#### user assign-role

Assign a role to an existing user.

```bash
platformctl iam user assign-role <tenant-id> <user-id> <role>
```

**Example:**

```bash
platformctl iam user assign-role acme user-abc123 admin
```

#### user revoke-role

Revoke a role from a user.

```bash
platformctl iam user revoke-role <tenant-id> <user-id> <role>
```

**Example:**

```bash
platformctl iam user revoke-role acme user-abc123 admin
```

---

### Group Management

Manage groups including creation, listing, and membership control.

```
platformctl iam group <subcommand>
```

#### group create

Create a new group within a tenant.

```bash
platformctl iam group create <group-id> --tenant <tenant-id> [flags]
```

**Flags:**

| Flag | Short | Required | Description |
|------|-------|----------|-------------|
| `--tenant` | `-t` | Yes | Tenant ID |
| `--name` | `-n` | No | Group display name |
| `--description` | `-d` | No | Group description |

**Example:**

```bash
platformctl iam group create engineering --tenant acme \
  --name "Engineering Team" --description "Software engineering department"
```

#### group get

Retrieve detailed information about a specific group.

```bash
platformctl iam group get <tenant-id> <group-id>
```

**Example:**

```bash
platformctl iam group get acme engineering
```

#### group list

List all groups in a tenant.

```bash
platformctl iam group list --tenant <tenant-id> [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--tenant` | `-t` | Required | Tenant ID |
| `--limit` | `-l` | 50 | Maximum number of groups to return |
| `--offset` | `-o` | 0 | Number of groups to skip |

**Example:**

```bash
platformctl iam group list --tenant acme --limit 20
```

#### group update

Update an existing group's properties.

```bash
platformctl iam group update <group-id> --tenant <tenant-id> [flags]
```

**Flags:**

| Flag | Short | Required | Description |
|------|-------|----------|-------------|
| `--tenant` | `-t` | Yes | Tenant ID |
| `--name` | `-n` | No | New group display name |
| `--description` | `-d` | No | New group description |

**Example:**

```bash
platformctl iam group update engineering --tenant acme \
  --name "Platform Engineering" --description "Platform engineering team"
```

#### group delete

Delete a group from a tenant.

```bash
platformctl iam group delete <tenant-id> <group-id>
```

**Example:**

```bash
platformctl iam group delete acme engineering
```

#### group add-member

Add a user to a group.

```bash
platformctl iam group add-member <tenant-id> <group-id> <user-id>
```

**Example:**

```bash
platformctl iam group add-member acme engineering user-abc123
```

#### group remove-member

Remove a user from a group.

```bash
platformctl iam group remove-member <tenant-id> <group-id> <user-id>
```

**Example:**

```bash
platformctl iam group remove-member acme engineering user-abc123
```

---

### Role Management

Manage roles including creation, listing, and permission assignment.

```
platformctl iam role <subcommand>
```

#### role create

Create a new role within a tenant.

```bash
platformctl iam role create <role-id> --tenant <tenant-id> [flags]
```

**Flags:**

| Flag | Short | Required | Description |
|------|-------|----------|-------------|
| `--tenant` | `-t` | Yes | Tenant ID |
| `--name` | `-n` | No | Role display name |
| `--description` | `-d` | No | Role description |
| `--permissions` | `-p` | No | Comma-separated list of permissions |

**Examples:**

```bash
# Create an admin role
platformctl iam role create admin --tenant acme \
  --name "Administrator" --permissions "read,write,delete,admin"

# Create a viewer role
platformctl iam role create viewer --tenant acme \
  --name "Viewer" --permissions "read"
```

#### role get

Retrieve detailed information about a specific role.

```bash
platformctl iam role get <tenant-id> <role-id>
```

**Example:**

```bash
platformctl iam role get acme admin
```

**Sample Output:**

```
Role ID:     admin
Tenant ID:   acme
Name:        Administrator
Description: Full administrative access
Permissions: read, write, delete, admin
Created At:  2025-01-10 14:30:00
```

#### role list

List all roles in a tenant.

```bash
platformctl iam role list --tenant <tenant-id> [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--tenant` | `-t` | Required | Tenant ID |
| `--limit` | `-l` | 50 | Maximum number of roles to return |
| `--offset` | `-o` | 0 | Number of roles to skip |

**Example:**

```bash
platformctl iam role list --tenant acme -o json
```

#### role update

Update an existing role's properties.

```bash
platformctl iam role update <role-id> --tenant <tenant-id> [flags]
```

**Flags:**

| Flag | Short | Required | Description |
|------|-------|----------|-------------|
| `--tenant` | `-t` | Yes | Tenant ID |
| `--name` | `-n` | No | New role display name |
| `--description` | `-d` | No | New role description |
| `--permissions` | `-p` | No | Comma-separated list of permissions |

**Example:**

```bash
platformctl iam role update admin --tenant acme \
  --name "Super Admin" --permissions "read,write,delete,admin,super"
```

#### role delete

Delete a role from a tenant.

```bash
platformctl iam role delete <tenant-id> <role-id>
```

**Example:**

```bash
platformctl iam role delete acme deprecated-role
```

---

### Tenant Management

Manage tenants for multi-tenancy isolation.

```
platformctl iam tenant <subcommand>
```

#### tenant create

Create a new tenant with specified settings.

```bash
platformctl iam tenant create --id <tenant-id> [flags]
```

**Flags:**

| Flag | Required | Description |
|------|----------|-------------|
| `--id` | Yes | Unique tenant identifier |
| `--name` | No | Human-readable tenant name |
| `--max-users` | No | Maximum number of users allowed (0 = unlimited) |
| `--mfa-required` | No | Require MFA for all users |

**Example:**

```bash
platformctl iam tenant create --id acme \
  --name "Acme Corporation" --max-users 100 --mfa-required
```

#### tenant get

Retrieve information about a specific tenant.

```bash
platformctl iam tenant get <tenant-id>
```

**Example:**

```bash
platformctl iam tenant get acme
```

**Sample Output:**

```
ID:          acme
Name:        Acme Corporation
Max Users:   100
MFA Required: Yes
Created At:  2025-01-10 14:30:00
```

#### tenant list

List all tenants with pagination.

```bash
platformctl iam tenant list [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--limit` | `-l` | 50 | Maximum number of tenants to return |
| `--offset` | `-o` | 0 | Number of tenants to skip |

**Example:**

```bash
platformctl iam tenant list --limit 50 --offset 0
```

#### tenant update

Update an existing tenant's settings.

```bash
platformctl iam tenant update --id <tenant-id> [flags]
```

**Flags:**

| Flag | Required | Description |
|------|----------|-------------|
| `--id` | Yes | Tenant ID to update |
| `--name` | No | New tenant name |
| `--max-users` | No | New maximum user count |
| `--mfa-required` | No | Set MFA requirement |

**Example:**

```bash
platformctl iam tenant update --id acme \
  --name "Acme Corp Inc" --max-users 200 --mfa-required
```

#### tenant delete

Delete a tenant and all associated resources.

```bash
platformctl iam tenant delete <tenant-id>
```

**Warning:** This operation is destructive and cannot be undone. All users, groups, roles, and policies associated with this tenant will be deleted.

**Example:**

```bash
platformctl iam tenant delete deprecated-tenant
```

---

### Policy Management

Manage authorization policies for fine-grained access control.

```
platformctl iam policy <subcommand>
```

#### policy create

Create a new authorization policy from a YAML specification file.

```bash
platformctl iam policy create --tenant <tenant-id> --name <policy-name> --file <path> [flags]
```

**Flags:**

| Flag | Required | Description |
|------|----------|-------------|
| `--tenant` | Yes | Tenant ID |
| `--name` | Yes | Policy name |
| `--description` | No | Policy description |
| `--priority` | No | Policy priority (higher = evaluated first) |
| `--file` | Yes | Path to policy YAML file |
| `--labels` | No | Comma-separated key=value labels |

**Example:**

```bash
platformctl iam policy create --tenant acme --name admin-access \
  --file admin-policy.yaml --priority 100 --description "Admin access policy"
```

**Sample Policy YAML:**

```yaml
effect: allow
subjects:
  - role:admin
actions:
  - read
  - write
  - delete
resources:
  - "documents/*"
  - "api/*"
conditions:
  time:
    after: "09:00"
    before: "18:00"
```

#### policy get

Retrieve information about a specific policy.

```bash
platformctl iam policy get <tenant-id> <policy-name>
```

**Example:**

```bash
platformctl iam policy get acme admin-access
```

#### policy list

List all policies for a tenant.

```bash
platformctl iam policy list --tenant <tenant-id> [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--tenant` | | Required | Tenant ID |
| `--limit` | `-l` | 50 | Maximum number of policies to return |
| `--offset` | `-o` | 0 | Number of policies to skip |

**Example:**

```bash
platformctl iam policy list --tenant acme
```

#### policy update

Update an existing policy.

```bash
platformctl iam policy update --tenant <tenant-id> --name <policy-name> [flags]
```

**Flags:**

| Flag | Required | Description |
|------|----------|-------------|
| `--tenant` | Yes | Tenant ID |
| `--name` | Yes | Policy name |
| `--description` | No | New policy description |
| `--priority` | No | New policy priority |
| `--file` | No | Path to updated policy YAML file |
| `--labels` | No | Comma-separated key=value labels |

**Example:**

```bash
platformctl iam policy update --tenant acme --name admin-access \
  --file updated-policy.yaml --priority 200
```

#### policy delete

Delete a policy from a tenant.

```bash
platformctl iam policy delete <tenant-id> <policy-name>
```

**Warning:** Deleting a policy may affect access control for resources.

**Example:**

```bash
platformctl iam policy delete acme deprecated-policy
```

#### policy validate

Validate a policy YAML file without creating or updating.

```bash
platformctl iam policy validate --tenant <tenant-id> --file <path>
```

**Flags:**

| Flag | Required | Description |
|------|----------|-------------|
| `--tenant` | Yes | Tenant ID |
| `--file` | Yes | Path to policy YAML file |

**Example:**

```bash
platformctl iam policy validate --tenant acme --file new-policy.yaml
```

**Sample Output (valid):**

```
Policy is valid
```

**Sample Output (invalid):**

```
Policy validation failed

Errors:
  1. Invalid effect: must be 'allow' or 'deny'
  2. Missing required field: subjects
```

#### policy test

Test policies by simulating an authorization request.

```bash
platformctl iam policy test --tenant <tenant-id> --subject <subject-id> --action <action> --resource <resource> [flags]
```

**Flags:**

| Flag | Required | Description |
|------|----------|-------------|
| `--tenant` | Yes | Tenant ID |
| `--subject` | Yes | Subject/user ID to test |
| `--roles` | No | Comma-separated roles to include |
| `--groups` | No | Comma-separated groups to include |
| `--action` | Yes | Action to test |
| `--resource` | Yes | Resource to test |
| `--context` | No | Comma-separated key=value context attributes |

**Examples:**

```bash
# Test basic access
platformctl iam policy test --tenant acme \
  --subject user-123 --action read --resource documents/secret.pdf

# Test with roles
platformctl iam policy test --tenant acme \
  --subject user-456 --roles admin,user --action write --resource /api/users
```

**Sample Output:**

```
Access ALLOWED

Subject:        user-123
Action:         read
Resource:       documents/secret.pdf
Matched Policy: admin-access
Matched Rule:   allow-all-documents
Evaluation Time: 1.234ms
```

---

### Application Management

Manage OAuth 2.0 applications (clients).

```
platformctl iam app <subcommand>
```

#### app register

Register a new OAuth application in a tenant.

```bash
platformctl iam app register --tenant <tenant-id> --name <app-name> [flags]
```

**Flags:**

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--tenant` | Yes | | Tenant ID |
| `--name` | Yes | | Application name |
| `--redirect-uris` | No | | Comma-separated list of redirect URIs |
| `--grant-types` | No | `authorization_code` | Comma-separated list of grant types |
| `--response-types` | No | `code` | Comma-separated list of response types |
| `--resource-prefix` | No | | Resource prefix for policy matching |

**Grant Types:**

- `authorization_code` - Standard web application flow
- `client_credentials` - Machine-to-machine authentication
- `refresh_token` - Allow token refresh
- `implicit` - Browser-based applications (not recommended)
- `password` - Resource owner password grant (not recommended)

**Response Types:**

- `code` - Authorization code (for authorization_code grant)
- `token` - Access token (for implicit grant)
- `id_token` - OpenID Connect ID token

**Examples:**

```bash
# Register a web application
platformctl iam app register --tenant acme --name "My Web App" \
  --redirect-uris "https://app.example.com/callback" \
  --grant-types "authorization_code,refresh_token"

# Register a machine-to-machine application
platformctl iam app register --tenant acme --name "API Service" \
  --grant-types "client_credentials" \
  --resource-prefix "api"

# Register with multiple redirect URIs
platformctl iam app register --tenant acme --name "Multi-Env App" \
  --redirect-uris "https://app.example.com/callback,https://staging.example.com/callback"
```

**Sample Output:**

```
Application registered successfully: My Web App

Client ID:      abc123-xyz789
Name:           My Web App
Tenant ID:      acme
Redirect URIs:  https://app.example.com/callback
Grant Types:    authorization_code, refresh_token
Response Types: code
Created At:     2025-01-10 14:30:00

IMPORTANT: Save this client secret securely. It will not be shown again.
Client Secret:  secret_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

#### app get

Retrieve detailed information about an OAuth application.

```bash
platformctl iam app get <tenant-id> <client-id>
```

**Example:**

```bash
platformctl iam app get acme abc123-client-id
```

#### app list

List OAuth applications in a tenant.

```bash
platformctl iam app list --tenant <tenant-id> [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--tenant` | Required | Tenant ID |
| `--limit` | 50 | Maximum number of applications to return |
| `--offset` | 0 | Number of applications to skip |

**Example:**

```bash
platformctl iam app list --tenant acme --limit 20
```

#### app update

Update an existing OAuth application's properties.

```bash
platformctl iam app update --tenant <tenant-id> --client-id <client-id> [flags]
```

**Flags:**

| Flag | Required | Description |
|------|----------|-------------|
| `--tenant` | Yes | Tenant ID |
| `--client-id` | Yes | Client ID |
| `--name` | No | New application name |
| `--redirect-uris` | No | Comma-separated list of redirect URIs |
| `--grant-types` | No | Comma-separated list of grant types |
| `--response-types` | No | Comma-separated list of response types |
| `--resource-prefix` | No | Resource prefix for policy matching |

**Examples:**

```bash
# Update application name
platformctl iam app update --tenant acme --client-id abc123 --name "New Name"

# Update redirect URIs
platformctl iam app update --tenant acme --client-id abc123 \
  --redirect-uris "https://new.example.com/callback"

# Update grant types
platformctl iam app update --tenant acme --client-id abc123 \
  --grant-types "authorization_code,client_credentials,refresh_token"
```

#### app delete

Delete an OAuth application from a tenant.

```bash
platformctl iam app delete <tenant-id> <client-id>
```

**Warning:** This operation cannot be undone. All tokens issued for this application will be invalidated.

**Example:**

```bash
platformctl iam app delete acme abc123-client-id
```

#### app rotate-secret

Rotate the client secret for an OAuth application.

```bash
platformctl iam app rotate-secret <tenant-id> <client-id>
```

**Example:**

```bash
platformctl iam app rotate-secret acme abc123-client-id
```

**Sample Output:**

```
Client secret rotated successfully for: My Web App

Client ID: abc123-client-id
Name:      My Web App

IMPORTANT: Save this new client secret securely. It will not be shown again.
New Client Secret: secret_yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy
```

---

## Common Workflows

### 1. Create a New Tenant with Admin User

```bash
# Create the tenant
platformctl iam tenant create --id acme \
  --name "Acme Corporation" --max-users 100

# Create admin role
platformctl iam role create admin --tenant acme \
  --name "Administrator" --permissions "read,write,delete,admin"

# Create admin user with role
platformctl iam user create --tenant acme \
  --email admin@acme.com --name "Admin User" --roles admin
```

### 2. Set Up Roles and Assign to Users

```bash
# Create roles
platformctl iam role create editor --tenant acme \
  --name "Editor" --permissions "read,write"

platformctl iam role create viewer --tenant acme \
  --name "Viewer" --permissions "read"

# Assign roles to existing users
platformctl iam user assign-role acme user-123 editor
platformctl iam user assign-role acme user-456 viewer
```

### 3. Create and Test Authorization Policies

```bash
# Create a policy file: document-access.yaml
cat > document-access.yaml << 'EOF'
effect: allow
subjects:
  - role:editor
  - role:admin
actions:
  - read
  - write
resources:
  - "documents/*"
EOF

# Validate the policy
platformctl iam policy validate --tenant acme --file document-access.yaml

# Create the policy
platformctl iam policy create --tenant acme --name document-access \
  --file document-access.yaml --priority 100

# Test the policy
platformctl iam policy test --tenant acme \
  --subject user-123 --roles editor --action write --resource documents/report.pdf
```

### 4. Register an OAuth Application

```bash
# Register a web application
platformctl iam app register --tenant acme --name "Customer Portal" \
  --redirect-uris "https://portal.acme.com/callback,https://portal.acme.com/silent-refresh" \
  --grant-types "authorization_code,refresh_token" \
  --response-types "code"

# Save the client ID and secret securely!

# Later, rotate the secret if needed
platformctl iam app rotate-secret acme <client-id>
```

### 5. Organize Users with Groups

```bash
# Create groups
platformctl iam group create engineering --tenant acme \
  --name "Engineering" --description "Engineering department"

platformctl iam group create marketing --tenant acme \
  --name "Marketing" --description "Marketing department"

# Add users to groups
platformctl iam group add-member acme engineering user-123
platformctl iam group add-member acme engineering user-456
platformctl iam group add-member acme marketing user-789

# List group members
platformctl iam group get acme engineering
```

## Output Formats

All commands support three output formats:

### Table (default)

Human-readable tabular format:

```bash
platformctl iam user list --tenant acme
```

### JSON

Machine-readable JSON:

```bash
platformctl iam user list --tenant acme -o json
```

### YAML

Machine-readable YAML:

```bash
platformctl iam user list --tenant acme -o yaml
```

## Error Handling

Common error messages and their meanings:

| Error | Description |
|-------|-------------|
| `missing tenant ID` | The `--tenant` flag is required but was not provided |
| `missing user ID` | A user ID argument is required |
| `missing email` | The `--email` flag is required for user creation |
| `user not found` | The specified user does not exist |
| `tenant not found` | The specified tenant does not exist |
| `policy validation failed` | The policy YAML contains errors |
| `failed to connect` | Cannot connect to the platform service |

## See Also

- [IAM Architecture](architecture.md) - Overview of the IAM system
- [Authorization](authorization.md) - Authorization concepts and flows
- [ABAC Policies](abac-policies.md) - Attribute-based access control policy reference
- [API Reference](api-reference.md) - Complete API documentation
