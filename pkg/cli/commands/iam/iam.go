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

package iam

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// NewCommand creates the iam root command for Identity and Access Management operations
func NewCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "iam",
		Short: "Identity and Access Management operations",
		Long: `Manage users, groups, roles, tenants, policies, and applications.

The IAM subsystem provides comprehensive identity and access management including:
  - User management (create, update, delete, list)
  - Group management with membership control
  - Role management with assignment capabilities
  - Tenant administration
  - Policy creation and validation
  - Application (OAuth client) management

Examples:
  # List all users in a tenant
  platformctl iam user list --tenant my-tenant

  # Create a new user
  platformctl iam user create --tenant my-tenant --email user@example.com --name "John Doe"

  # Assign a role to a user
  platformctl iam user assign-role my-tenant user-123 admin

  # List all roles
  platformctl iam role list --tenant my-tenant

  # Create a new application
  platformctl iam app create --tenant my-tenant --name "My App" --redirect-uris "https://app.example.com/callback"`,
	}

	// Add subcommands
	cmd.AddCommand(NewUserCommand(getFlags))
	cmd.AddCommand(NewGroupCommand(getFlags))
	cmd.AddCommand(NewRoleCommand(getFlags))
	cmd.AddCommand(NewTenantCommand(getFlags))
	cmd.AddCommand(NewPolicyCommand(getFlags))
	cmd.AddCommand(NewAppCommand(getFlags))

	return cmd
}
