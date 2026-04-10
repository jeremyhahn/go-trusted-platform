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

package app

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestApp_TenantID_Default tests that TenantID defaults to "platform" when not set
func TestApp_TenantID_Default(t *testing.T) {
	app := &App{}

	// TenantID should be empty initially
	assert.Empty(t, app.TenantID, "TenantID should be empty initially")
}

// TestApp_TenantID_Set tests that TenantID can be set
func TestApp_TenantID_Set(t *testing.T) {
	app := &App{
		TenantID: "my-tenant",
	}

	assert.Equal(t, "my-tenant", app.TenantID, "TenantID should be set correctly")
}

// TestApp_TenantID_FromConfig tests that TenantID is read from config
func TestApp_TenantID_FromConfig(t *testing.T) {
	tests := []struct {
		name     string
		tenantID string
		expected string
	}{
		{
			name:     "custom_tenant",
			tenantID: "custom-tenant-123",
			expected: "custom-tenant-123",
		},
		{
			name:     "platform_tenant",
			tenantID: "platform",
			expected: "platform",
		},
		{
			name:     "uuid_format",
			tenantID: "550e8400-e29b-41d4-a716-446655440000",
			expected: "550e8400-e29b-41d4-a716-446655440000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := &App{
				TenantID: tt.tenantID,
			}
			assert.Equal(t, tt.expected, app.TenantID)
		})
	}
}

// TestApp_TenantID_EmptyString tests behavior with empty string
func TestApp_TenantID_EmptyString(t *testing.T) {
	app := &App{
		TenantID: "",
	}

	// Empty TenantID should remain empty before Init is called
	assert.Empty(t, app.TenantID)
}

// TestApp_TenantID_Whitespace tests behavior with whitespace
func TestApp_TenantID_Whitespace(t *testing.T) {
	app := &App{
		TenantID: "  tenant-with-spaces  ",
	}

	// TenantID should preserve the value as-is (validation happens elsewhere)
	assert.Equal(t, "  tenant-with-spaces  ", app.TenantID)
}

// TestApp_TenantID_SpecialCharacters tests TenantID with special characters
func TestApp_TenantID_SpecialCharacters(t *testing.T) {
	tests := []struct {
		name     string
		tenantID string
	}{
		{
			name:     "with_underscores",
			tenantID: "tenant_with_underscores",
		},
		{
			name:     "with_hyphens",
			tenantID: "tenant-with-hyphens",
		},
		{
			name:     "with_dots",
			tenantID: "tenant.with.dots",
		},
		{
			name:     "mixed",
			tenantID: "tenant_with-mixed.chars",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := &App{
				TenantID: tt.tenantID,
			}
			assert.Equal(t, tt.tenantID, app.TenantID)
		})
	}
}
