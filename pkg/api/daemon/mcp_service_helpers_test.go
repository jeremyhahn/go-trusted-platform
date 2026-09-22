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

package daemon

import (
	"testing"
	"time"

	sdkiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
)

func TestMCPHelperUserToMap(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	oneHourAgo := now.Add(-1 * time.Hour)
	twoHoursAgo := now.Add(-2 * time.Hour)

	t.Run("fully populated user", func(t *testing.T) {
		user := &sdkiam.User{
			ID:          "user-123",
			TenantID:    "tenant-456",
			Email:       "test@example.com",
			DisplayName: "Test User",
			Roles:       []string{"admin", "developer"},
			Groups:      []string{"group-a", "group-b"},
			Metadata:    map[string]string{"department": "engineering", "location": "remote"},
			// AuthMethods is what now drives the mfa_verified wire field:
			// quicbaas v0.8.0 replaced User.MFAEnabled with the account's
			// permitted-method policy, and a non-empty list is an account
			// pinned to strong authentication.
			AuthMethods: []string{"webauthn"},
			CreatedAt:   twoHoursAgo,
			UpdatedAt:   oneHourAgo,
			LastLoginAt: &now,
		}

		result := sdkUserToMap(user)

		// Verify required fields
		if result["id"] != "user-123" {
			t.Errorf("expected id 'user-123', got %v", result["id"])
		}
		if result["tenant_id"] != "tenant-456" {
			t.Errorf("expected tenant_id 'tenant-456', got %v", result["tenant_id"])
		}
		if result["email"] != "test@example.com" {
			t.Errorf("expected email 'test@example.com', got %v", result["email"])
		}

		// Verify optional fields
		if result["name"] != "Test User" {
			t.Errorf("expected name 'Test User', got %v", result["name"])
		}

		roles, ok := result["roles"].([]string)
		if !ok {
			t.Fatalf("expected roles to be []string, got %T", result["roles"])
		}
		if len(roles) != 2 || roles[0] != "admin" || roles[1] != "developer" {
			t.Errorf("expected roles [admin, developer], got %v", roles)
		}

		groups, ok := result["groups"].([]string)
		if !ok {
			t.Fatalf("expected groups to be []string, got %T", result["groups"])
		}
		if len(groups) != 2 || groups[0] != "group-a" || groups[1] != "group-b" {
			t.Errorf("expected groups [group-a, group-b], got %v", groups)
		}

		attrs, ok := result["attributes"].(map[string]string)
		if !ok {
			t.Fatalf("expected attributes to be map[string]string, got %T", result["attributes"])
		}
		if attrs["department"] != "engineering" || attrs["location"] != "remote" {
			t.Errorf("expected attributes {department:engineering, location:remote}, got %v", attrs)
		}

		if result["mfa_verified"] != true {
			t.Errorf("expected mfa_verified true, got %v", result["mfa_verified"])
		}

		// Verify timestamps are present and formatted correctly
		createdAt, ok := result["created_at"].(string)
		if !ok {
			t.Fatalf("expected created_at to be string, got %T", result["created_at"])
		}
		_, err := time.Parse(time.RFC3339, createdAt)
		if err != nil {
			t.Errorf("created_at is not valid RFC3339: %v", err)
		}

		updatedAt, ok := result["updated_at"].(string)
		if !ok {
			t.Fatalf("expected updated_at to be string, got %T", result["updated_at"])
		}
		_, err = time.Parse(time.RFC3339, updatedAt)
		if err != nil {
			t.Errorf("updated_at is not valid RFC3339: %v", err)
		}

		lastAuth, ok := result["last_auth"].(string)
		if !ok {
			t.Fatalf("expected last_auth to be string, got %T", result["last_auth"])
		}
		_, err = time.Parse(time.RFC3339, lastAuth)
		if err != nil {
			t.Errorf("last_auth is not valid RFC3339: %v", err)
		}
	})

	t.Run("minimal user with required fields only", func(t *testing.T) {
		user := &sdkiam.User{
			ID:       "user-minimal",
			TenantID: "tenant-minimal",
			Email:    "minimal@example.com",
		}

		result := sdkUserToMap(user)

		// Verify required fields are present
		if result["id"] != "user-minimal" {
			t.Errorf("expected id 'user-minimal', got %v", result["id"])
		}
		if result["tenant_id"] != "tenant-minimal" {
			t.Errorf("expected tenant_id 'tenant-minimal', got %v", result["tenant_id"])
		}
		if result["email"] != "minimal@example.com" {
			t.Errorf("expected email 'minimal@example.com', got %v", result["email"])
		}

		// Verify optional fields are NOT present (empty values should be omitted)
		if _, exists := result["name"]; exists {
			t.Errorf("name should not be present for empty string, got %v", result["name"])
		}
		if _, exists := result["roles"]; exists {
			t.Errorf("roles should not be present for empty slice, got %v", result["roles"])
		}
		if _, exists := result["groups"]; exists {
			t.Errorf("groups should not be present for empty slice, got %v", result["groups"])
		}
		if _, exists := result["attributes"]; exists {
			t.Errorf("attributes should not be present for empty map, got %v", result["attributes"])
		}
		if _, exists := result["mfa_verified"]; exists {
			t.Errorf("mfa_verified should not be present when false, got %v", result["mfa_verified"])
		}
		if _, exists := result["created_at"]; exists {
			t.Errorf("created_at should not be present for zero time, got %v", result["created_at"])
		}
		if _, exists := result["updated_at"]; exists {
			t.Errorf("updated_at should not be present for zero time, got %v", result["updated_at"])
		}
		if _, exists := result["last_auth"]; exists {
			t.Errorf("last_auth should not be present for nil pointer, got %v", result["last_auth"])
		}
	})

	t.Run("user with empty slices and maps", func(t *testing.T) {
		user := &sdkiam.User{
			ID:       "user-empty-collections",
			TenantID: "tenant-empty",
			Email:    "empty@example.com",
			Roles:    []string{},
			Groups:   []string{},
			Metadata: map[string]string{},
		}

		result := sdkUserToMap(user)

		// Verify required fields
		if result["id"] != "user-empty-collections" {
			t.Errorf("expected id 'user-empty-collections', got %v", result["id"])
		}

		// Empty slices and maps should not be included
		if _, exists := result["name"]; exists {
			t.Errorf("empty name should not be present")
		}
		if _, exists := result["roles"]; exists {
			t.Errorf("empty roles should not be present")
		}
		if _, exists := result["groups"]; exists {
			t.Errorf("empty groups should not be present")
		}
		if _, exists := result["attributes"]; exists {
			t.Errorf("empty attributes should not be present")
		}
	})

	t.Run("user with mfa_verified false", func(t *testing.T) {
		user := &sdkiam.User{
			ID:       "user-no-mfa",
			TenantID: "tenant-no-mfa",
			Email:    "nomfa@example.com",
		}

		result := sdkUserToMap(user)

		// MFAEnabled=false should not be included in the map
		if _, exists := result["mfa_verified"]; exists {
			t.Errorf("mfa_verified=false should not be present in map")
		}
	})

	t.Run("user with single role and group", func(t *testing.T) {
		user := &sdkiam.User{
			ID:       "user-single",
			TenantID: "tenant-single",
			Email:    "single@example.com",
			Roles:    []string{"viewer"},
			Groups:   []string{"readers"},
		}

		result := sdkUserToMap(user)

		roles, ok := result["roles"].([]string)
		if !ok {
			t.Fatalf("expected roles to be []string, got %T", result["roles"])
		}
		if len(roles) != 1 || roles[0] != "viewer" {
			t.Errorf("expected roles [viewer], got %v", roles)
		}

		groups, ok := result["groups"].([]string)
		if !ok {
			t.Fatalf("expected groups to be []string, got %T", result["groups"])
		}
		if len(groups) != 1 || groups[0] != "readers" {
			t.Errorf("expected groups [readers], got %v", groups)
		}
	})

	t.Run("user with only timestamps set", func(t *testing.T) {
		ts := time.Now()
		user := &sdkiam.User{
			ID:          "user-timestamps",
			TenantID:    "tenant-timestamps",
			Email:       "timestamps@example.com",
			CreatedAt:   ts,
			UpdatedAt:   ts,
			LastLoginAt: &ts,
		}

		result := sdkUserToMap(user)

		// All timestamps should be present
		if _, exists := result["created_at"]; !exists {
			t.Error("created_at should be present")
		}
		if _, exists := result["updated_at"]; !exists {
			t.Error("updated_at should be present")
		}
		if _, exists := result["last_auth"]; !exists {
			t.Error("last_auth should be present")
		}
	})
}

func TestMCPHelperGroupToMap(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	oneHourAgo := now.Add(-1 * time.Hour)

	t.Run("fully populated group", func(t *testing.T) {
		group := &sdkiam.Group{
			ID:          "group-123",
			TenantID:    "tenant-456",
			Name:        "Engineering Team",
			Description: "Software engineering department",
			MemberCount: 3,
			CreatedAt:   oneHourAgo,
			UpdatedAt:   now,
		}

		result := sdkGroupToMap(group)

		// Verify required fields
		if result["id"] != "group-123" {
			t.Errorf("expected id 'group-123', got %v", result["id"])
		}
		if result["tenant_id"] != "tenant-456" {
			t.Errorf("expected tenant_id 'tenant-456', got %v", result["tenant_id"])
		}

		// Verify optional fields
		if result["name"] != "Engineering Team" {
			t.Errorf("expected name 'Engineering Team', got %v", result["name"])
		}
		if result["description"] != "Software engineering department" {
			t.Errorf("expected description 'Software engineering department', got %v", result["description"])
		}

		// Verify timestamps
		createdAt, ok := result["created_at"].(string)
		if !ok {
			t.Fatalf("expected created_at to be string, got %T", result["created_at"])
		}
		_, err := time.Parse(time.RFC3339, createdAt)
		if err != nil {
			t.Errorf("created_at is not valid RFC3339: %v", err)
		}

		updatedAt, ok := result["updated_at"].(string)
		if !ok {
			t.Fatalf("expected updated_at to be string, got %T", result["updated_at"])
		}
		_, err = time.Parse(time.RFC3339, updatedAt)
		if err != nil {
			t.Errorf("updated_at is not valid RFC3339: %v", err)
		}
	})

	t.Run("nil group returns nil", func(t *testing.T) {
		result := sdkGroupToMap(nil)
		if result != nil {
			t.Errorf("expected nil for nil group, got %v", result)
		}
	})

	t.Run("minimal group with required fields only", func(t *testing.T) {
		group := &sdkiam.Group{
			ID:       "group-minimal",
			TenantID: "tenant-minimal",
		}

		result := sdkGroupToMap(group)

		// Verify required fields
		if result["id"] != "group-minimal" {
			t.Errorf("expected id 'group-minimal', got %v", result["id"])
		}
		if result["tenant_id"] != "tenant-minimal" {
			t.Errorf("expected tenant_id 'tenant-minimal', got %v", result["tenant_id"])
		}

		// Verify optional fields are NOT present
		if _, exists := result["name"]; exists {
			t.Errorf("name should not be present for empty string")
		}
		if _, exists := result["description"]; exists {
			t.Errorf("description should not be present for empty string")
		}
		if _, exists := result["created_at"]; exists {
			t.Errorf("created_at should not be present for zero time")
		}
		if _, exists := result["updated_at"]; exists {
			t.Errorf("updated_at should not be present for zero time")
		}
	})

	t.Run("group with empty name and description", func(t *testing.T) {
		group := &sdkiam.Group{
			ID:          "group-empty-strings",
			TenantID:    "tenant-empty-strings",
			Name:        "",
			Description: "",
		}

		result := sdkGroupToMap(group)

		if _, exists := result["name"]; exists {
			t.Errorf("empty name should not be present")
		}
		if _, exists := result["description"]; exists {
			t.Errorf("empty description should not be present")
		}
	})

	t.Run("group with only timestamps", func(t *testing.T) {
		ts := time.Now()
		group := &sdkiam.Group{
			ID:        "group-timestamps",
			TenantID:  "tenant-timestamps",
			CreatedAt: ts,
			UpdatedAt: ts,
		}

		result := sdkGroupToMap(group)

		if _, exists := result["created_at"]; !exists {
			t.Error("created_at should be present")
		}
		if _, exists := result["updated_at"]; !exists {
			t.Error("updated_at should be present")
		}
	})
}

func TestMCPHelperTenantToMap(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	oneHourAgo := now.Add(-1 * time.Hour)

	t.Run("fully populated tenant", func(t *testing.T) {
		tenant := &sdkiam.Tenant{
			ID:   "tenant-123",
			Name: "Acme Corporation",
			Settings: map[string]string{
				"mfa_required": "true",
				"max_users":    "100",
			},
			CreatedAt: oneHourAgo,
			UpdatedAt: now,
		}

		result := sdkTenantToMap(tenant)

		// Verify required fields
		if result["id"] != "tenant-123" {
			t.Errorf("expected id 'tenant-123', got %v", result["id"])
		}

		// Verify optional fields
		if result["name"] != "Acme Corporation" {
			t.Errorf("expected name 'Acme Corporation', got %v", result["name"])
		}

		// Verify settings (stored as map[string]string)
		settings, ok := result["settings"].(map[string]string)
		if !ok {
			t.Fatalf("expected settings to be map[string]string, got %T", result["settings"])
		}
		if settings["mfa_required"] != "true" {
			t.Errorf("expected mfa_required 'true', got %v", settings["mfa_required"])
		}
		if settings["max_users"] != "100" {
			t.Errorf("expected max_users '100', got %v", settings["max_users"])
		}

		// Verify timestamps
		createdAt, ok := result["created_at"].(string)
		if !ok {
			t.Fatalf("expected created_at to be string, got %T", result["created_at"])
		}
		_, err := time.Parse(time.RFC3339, createdAt)
		if err != nil {
			t.Errorf("created_at is not valid RFC3339: %v", err)
		}

		updatedAt, ok := result["updated_at"].(string)
		if !ok {
			t.Fatalf("expected updated_at to be string, got %T", result["updated_at"])
		}
		_, err = time.Parse(time.RFC3339, updatedAt)
		if err != nil {
			t.Errorf("updated_at is not valid RFC3339: %v", err)
		}
	})

	t.Run("nil tenant returns nil", func(t *testing.T) {
		result := sdkTenantToMap(nil)
		if result != nil {
			t.Errorf("expected nil for nil tenant, got %v", result)
		}
	})

	t.Run("minimal tenant with id only", func(t *testing.T) {
		tenant := &sdkiam.Tenant{
			ID: "tenant-minimal",
		}

		result := sdkTenantToMap(tenant)

		// Verify required fields
		if result["id"] != "tenant-minimal" {
			t.Errorf("expected id 'tenant-minimal', got %v", result["id"])
		}

		// Verify optional fields are NOT present
		if _, exists := result["name"]; exists {
			t.Errorf("name should not be present for empty string")
		}
		if _, exists := result["settings"]; exists {
			t.Errorf("settings should not be present for nil/empty settings")
		}
		if _, exists := result["created_at"]; exists {
			t.Errorf("created_at should not be present for zero time")
		}
		if _, exists := result["updated_at"]; exists {
			t.Errorf("updated_at should not be present for zero time")
		}
	})

	t.Run("tenant with nil settings", func(t *testing.T) {
		tenant := &sdkiam.Tenant{
			ID:       "tenant-no-settings",
			Name:     "No Settings Corp",
			Settings: nil,
		}

		result := sdkTenantToMap(tenant)

		if result["name"] != "No Settings Corp" {
			t.Errorf("expected name 'No Settings Corp', got %v", result["name"])
		}

		if _, exists := result["settings"]; exists {
			t.Errorf("settings should not be present for nil settings")
		}
	})

	t.Run("tenant with empty name", func(t *testing.T) {
		tenant := &sdkiam.Tenant{
			ID:   "tenant-empty-name",
			Name: "",
		}

		result := sdkTenantToMap(tenant)

		if _, exists := result["name"]; exists {
			t.Errorf("empty name should not be present")
		}
	})

	t.Run("tenant with empty settings map", func(t *testing.T) {
		tenant := &sdkiam.Tenant{
			ID:       "tenant-empty-settings",
			Name:     "Empty Settings Corp",
			Settings: map[string]string{},
		}

		result := sdkTenantToMap(tenant)

		// Empty settings map should not be present
		if _, exists := result["settings"]; exists {
			t.Errorf("empty settings map should not be present")
		}
	})

	t.Run("tenant with only timestamps", func(t *testing.T) {
		ts := time.Now()
		tenant := &sdkiam.Tenant{
			ID:        "tenant-timestamps",
			CreatedAt: ts,
			UpdatedAt: ts,
		}

		result := sdkTenantToMap(tenant)

		if _, exists := result["created_at"]; !exists {
			t.Error("created_at should be present")
		}
		if _, exists := result["updated_at"]; !exists {
			t.Error("updated_at should be present")
		}
	})
}
