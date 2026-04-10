// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

// Package iam provides CLI commands for Identity and Access Management operations.
//
// This package implements the platformctl CLI interface for the IAM subsystem,
// providing comprehensive commands for managing users, groups, roles, tenants,
// policies, and applications. Commands communicate with the platformd daemon
// via the configured protocol (Unix socket, gRPC, REST, or QUIC).
//
// # Command Structure
//
// The IAM commands are organized hierarchically under the "iam" root command:
//
//	platformctl iam <resource> <action> [flags]
//
// Available resources:
//
//   - user: Manage users and their role/group assignments
//   - group: Manage groups and membership
//   - role: Manage roles and permissions
//   - tenant: Manage tenants (organizations)
//   - policy: Manage authorization policies
//   - app: Manage OAuth applications
//
// # User Commands
//
// User management operations:
//
//	platformctl iam user create --tenant <id> --email <email> [--name <name>] [--roles <roles>]
//	platformctl iam user get <tenant> <user-id>
//	platformctl iam user list --tenant <id> [--limit <n>] [--offset <n>]
//	platformctl iam user update <tenant> <user-id> [--name <name>] [--email <email>]
//	platformctl iam user delete <tenant> <user-id>
//	platformctl iam user assign-role <tenant> <user-id> <role-id>
//	platformctl iam user revoke-role <tenant> <user-id> <role-id>
//
// # Group Commands
//
// Group management operations:
//
//	platformctl iam group create --tenant <id> --name <name> [--description <desc>]
//	platformctl iam group get <tenant> <group-id>
//	platformctl iam group list --tenant <id>
//	platformctl iam group update <tenant> <group-id> [--name <name>] [--description <desc>]
//	platformctl iam group delete <tenant> <group-id>
//	platformctl iam group add-member <tenant> <group-id> <user-id>
//	platformctl iam group remove-member <tenant> <group-id> <user-id>
//
// # Role Commands
//
// Role management operations:
//
//	platformctl iam role create --tenant <id> --name <name> [--permissions <perms>]
//	platformctl iam role get <tenant> <role-id>
//	platformctl iam role list --tenant <id>
//	platformctl iam role update <tenant> <role-id> [--name <name>] [--permissions <perms>]
//	platformctl iam role delete <tenant> <role-id>
//
// # Tenant Commands
//
// Tenant management operations:
//
//	platformctl iam tenant create --id <id> --name <name>
//	platformctl iam tenant get <tenant-id>
//	platformctl iam tenant list
//	platformctl iam tenant update <tenant-id> [--name <name>]
//	platformctl iam tenant delete <tenant-id>
//
// # Policy Commands
//
// Policy management operations:
//
//	platformctl iam policy create --tenant <id> --name <name> --spec-file <path>
//	platformctl iam policy get <tenant> <policy-name>
//	platformctl iam policy list --tenant <id>
//	platformctl iam policy update <tenant> <policy-name> [--spec-file <path>]
//	platformctl iam policy delete <tenant> <policy-name>
//	platformctl iam policy validate --tenant <id> --spec-file <path>
//	platformctl iam policy test --tenant <id> --subject <id> --action <action> --resource <resource>
//
// # Application Commands
//
// OAuth application management:
//
//	platformctl iam app create --tenant <id> --name <name> [--redirect-uris <uris>]
//	platformctl iam app get <tenant> <client-id>
//	platformctl iam app list --tenant <id>
//	platformctl iam app update <tenant> <client-id> [--name <name>]
//	platformctl iam app delete <tenant> <client-id>
//	platformctl iam app rotate-secret <tenant> <client-id>
//
// # Common Flags
//
// All commands support these common flags inherited from the root command:
//
//	--config <path>    Path to configuration file
//	--socket <path>    Unix socket path for daemon communication
//	--host <host>      Daemon host for remote connections
//	--port <port>      Daemon port for remote connections
//	--protocol <proto> Communication protocol (unix, grpc, rest, quic)
//	--tls              Enable TLS for secure connections
//	--output <format>  Output format (json, yaml, table)
//	--verbose          Enable verbose output
//
// # Output Formats
//
// Commands support multiple output formats:
//
//   - table: Human-readable tabular format (default)
//   - json: JSON format for scripting
//   - yaml: YAML format for configuration management
//
// Example:
//
//	platformctl iam user list --tenant my-tenant --output json
//
// # Error Handling
//
// All commands use typed errors defined in errors.go. Errors are reported with
// descriptive messages and appropriate exit codes for scripting integration.
//
// # Examples
//
// Create a complete IAM setup:
//
//	# Create a tenant
//	platformctl iam tenant create --id acme-corp --name "ACME Corporation"
//
//	# Create an admin role
//	platformctl iam role create --tenant acme-corp --name admin \
//	    --permissions "users:*,groups:*,roles:read"
//
//	# Create a user and assign the admin role
//	platformctl iam user create --tenant acme-corp --email admin@acme.com --name "Admin"
//	platformctl iam user assign-role acme-corp <user-id> admin
//
//	# Create a policy
//	platformctl iam policy create --tenant acme-corp --name admin-policy \
//	    --spec-file ./policies/admin.yaml
package iam
