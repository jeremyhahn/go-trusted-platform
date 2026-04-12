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
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	iamsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// =============================================================================
// formatAppTimestamp Tests
// =============================================================================

func TestFormatAppTimestamp(t *testing.T) {
	t.Run("zero returns dash", func(t *testing.T) {
		assert.Equal(t, "-", formatAppTimestamp(time.Time{}))
	})

	t.Run("valid timestamp", func(t *testing.T) {
		ts := time.Now()
		result := formatAppTimestamp(ts)
		assert.NotEmpty(t, result)
		assert.NotEqual(t, "-", result)
	})
}

// =============================================================================
// formatPermissions Tests
// =============================================================================

func TestFormatPermissions(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		assert.Equal(t, "(none)", formatPermissions(nil))
	})

	t.Run("empty slice", func(t *testing.T) {
		assert.Equal(t, "(none)", formatPermissions([]string{}))
	})

	t.Run("single permission", func(t *testing.T) {
		assert.Equal(t, "read", formatPermissions([]string{"read"}))
	})

	t.Run("three permissions", func(t *testing.T) {
		result := formatPermissions([]string{"read", "write", "delete"})
		assert.Equal(t, "read, write, delete", result)
	})

	t.Run("more than three truncated", func(t *testing.T) {
		result := formatPermissions([]string{"read", "write", "delete", "admin", "super"})
		assert.Contains(t, result, "read")
		assert.Contains(t, result, "+2 more")
	})
}

// =============================================================================
// printAppDetails Tests
// =============================================================================

func TestPrintAppDetails(t *testing.T) {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

	now := time.Now()
	app := &iamsvc.App{
		ClientID:       "client-123",
		Name:           "test-app",
		TenantID:       "tenant-1",
		RedirectURIs:   []string{"https://example.com/callback"},
		GrantTypes:     []string{"authorization_code"},
		ResponseTypes:  []string{"code"},
		ResourcePrefix: "app:",
		CreatedAt:      now,
		UpdatedAt:      &now,
	}

	printAppDetails(printer, app)
	out := output.String()
	assert.Contains(t, out, "client-123")
	assert.Contains(t, out, "test-app")
	assert.Contains(t, out, "tenant-1")
	assert.Contains(t, out, "app:")
}

func TestPrintAppDetails_NoResourcePrefix(t *testing.T) {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

	app := &iamsvc.App{
		ClientID: "client-456",
		Name:     "minimal-app",
		TenantID: "tenant-2",
	}

	printAppDetails(printer, app)
	out := output.String()
	assert.Contains(t, out, "client-456")
	assert.NotContains(t, out, "Resource Prefix")
}

// =============================================================================
// printGroupDetails Tests
// =============================================================================

func TestPrintGroupDetails_Full(t *testing.T) {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

	now := time.Now()
	group := &iamsvc.Group{
		ID:          "group-1",
		TenantID:    "tenant-1",
		Name:        "admins",
		Description: "Admin group",
		Members:     []string{"user-1", "user-2"},
		CreatedAt:   now,
		UpdatedAt:   &now,
	}

	printGroupDetails(printer, group)
	out := output.String()
	assert.Contains(t, out, "group-1")
	assert.Contains(t, out, "admins")
	assert.Contains(t, out, "Admin group")
	assert.Contains(t, out, "user-1")
}

func TestPrintGroupDetails_Minimal(t *testing.T) {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

	group := &iamsvc.Group{
		ID:        "group-2",
		TenantID:  "tenant-1",
		CreatedAt: time.Now(),
	}

	printGroupDetails(printer, group)
	out := output.String()
	assert.Contains(t, out, "group-2")
	assert.Contains(t, out, "(none)")
}

// =============================================================================
// printRoleDetails Tests
// =============================================================================

func TestPrintRoleDetails_Full(t *testing.T) {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

	now := time.Now()
	role := &iamsvc.Role{
		ID:          "role-1",
		TenantID:    "tenant-1",
		Name:        "admin",
		Description: "Admin role",
		Permissions: []string{"read", "write", "delete"},
		CreatedAt:   now,
		UpdatedAt:   &now,
	}

	printRoleDetails(printer, role)
	out := output.String()
	assert.Contains(t, out, "role-1")
	assert.Contains(t, out, "admin")
	assert.Contains(t, out, "Admin role")
	assert.Contains(t, out, "read")
}

func TestPrintRoleDetails_NoPermissions(t *testing.T) {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

	role := &iamsvc.Role{
		ID:        "role-2",
		TenantID:  "tenant-1",
		CreatedAt: time.Now(),
	}

	printRoleDetails(printer, role)
	out := output.String()
	assert.Contains(t, out, "role-2")
	assert.Contains(t, out, "(none)")
}

// =============================================================================
// printUserDetails Tests
// =============================================================================

func TestPrintUserDetails_Full(t *testing.T) {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

	now := time.Now()
	user := &iamsvc.User{
		ID:          "user-1",
		TenantID:    "tenant-1",
		Email:       "admin@example.com",
		Name:        "Admin User",
		Roles:       []string{"admin"},
		Groups:      []string{"admins"},
		Attributes:  map[string]string{"dept": "eng"},
		MfaVerified: true,
		CreatedAt:   now,
		UpdatedAt:   &now,
		LastAuth:    &now,
	}

	printUserDetails(printer, user)
	out := output.String()
	assert.Contains(t, out, "user-1")
	assert.Contains(t, out, "admin@example.com")
	assert.Contains(t, out, "Admin User")
	assert.Contains(t, out, "dept=eng")
	assert.Contains(t, out, "Yes")
}

func TestPrintUserDetails_Minimal(t *testing.T) {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

	user := &iamsvc.User{
		ID:        "user-2",
		TenantID:  "tenant-1",
		Email:     "user@example.com",
		CreatedAt: time.Now(),
	}

	printUserDetails(printer, user)
	out := output.String()
	assert.Contains(t, out, "user-2")
	assert.Contains(t, out, "user@example.com")
	assert.Contains(t, out, "No")
}

// =============================================================================
// printTenantDetails Tests
// =============================================================================

func TestPrintTenantDetails_Full(t *testing.T) {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

	now := time.Now()
	tenant := &iamsvc.Tenant{
		ID:   "tenant-1",
		Name: "Test Tenant",
		Settings: &iamsvc.TenantSettings{
			MaxUsers:    100,
			MfaRequired: true,
		},
		CreatedAt: now,
		UpdatedAt: &now,
	}

	printTenantDetails(printer, tenant)
	out := output.String()
	assert.Contains(t, out, "tenant-1")
	assert.Contains(t, out, "Test Tenant")
	assert.Contains(t, out, "100")
	assert.Contains(t, out, "Yes")
}

func TestPrintTenantDetails_Minimal(t *testing.T) {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

	tenant := &iamsvc.Tenant{
		ID:        "tenant-2",
		Name:      "Minimal",
		CreatedAt: time.Now(),
	}

	printTenantDetails(printer, tenant)
	out := output.String()
	assert.Contains(t, out, "tenant-2")
	assert.Contains(t, out, "Minimal")
}

func TestPrintTenantDetails_UnlimitedUsers(t *testing.T) {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

	tenant := &iamsvc.Tenant{
		ID:   "tenant-3",
		Name: "Unlimited",
		Settings: &iamsvc.TenantSettings{
			MaxUsers:    0,
			MfaRequired: false,
		},
		CreatedAt: time.Now(),
	}

	printTenantDetails(printer, tenant)
	out := output.String()
	assert.Contains(t, out, "unlimited")
	assert.Contains(t, out, "No")
}

// =============================================================================
// printPolicyDetails Tests
// =============================================================================

func TestPrintPolicyDetails_Full(t *testing.T) {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

	now := time.Now()
	policy := &iamsvc.Policy{
		Name:        "test-policy",
		TenantID:    "tenant-1",
		Description: "Test policy description",
		Priority:    10,
		Labels:      map[string]string{"env": "prod"},
		CreatedAt:   now,
		UpdatedAt:   &now,
	}

	printPolicyDetails(printer, policy)
	out := output.String()
	assert.Contains(t, out, "test-policy")
	assert.Contains(t, out, "tenant-1")
	assert.Contains(t, out, "Test policy description")
	assert.Contains(t, out, "10")
	assert.Contains(t, out, "env=prod")
}

func TestPrintPolicyDetails_Minimal(t *testing.T) {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

	policy := &iamsvc.Policy{
		Name:      "minimal-policy",
		TenantID:  "tenant-1",
		Priority:  1,
		CreatedAt: time.Now(),
	}

	printPolicyDetails(printer, policy)
	out := output.String()
	assert.Contains(t, out, "minimal-policy")
	assert.NotContains(t, out, "Description")
}
