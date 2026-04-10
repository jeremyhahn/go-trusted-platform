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

	iampb "github.com/jeremyhahn/go-quicbaas/api/proto/iam"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestMCPHelperUserToMap(t *testing.T) {
	now := time.Now()
	oneHourAgo := now.Add(-1 * time.Hour)
	twoHoursAgo := now.Add(-2 * time.Hour)

	t.Run("fully populated user", func(t *testing.T) {
		user := &iampb.User{
			Id:          "user-123",
			TenantId:    "tenant-456",
			Email:       "test@example.com",
			Name:        "Test User",
			Roles:       []string{"admin", "developer"},
			Groups:      []string{"group-a", "group-b"},
			Attributes:  map[string]string{"department": "engineering", "location": "remote"},
			MfaVerified: true,
			CreatedAt:   timestamppb.New(twoHoursAgo),
			UpdatedAt:   timestamppb.New(oneHourAgo),
			LastAuth:    timestamppb.New(now),
		}

		result := userToMap(user)

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
		user := &iampb.User{
			Id:       "user-minimal",
			TenantId: "tenant-minimal",
			Email:    "minimal@example.com",
		}

		result := userToMap(user)

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
			t.Errorf("created_at should not be present for nil timestamp, got %v", result["created_at"])
		}
		if _, exists := result["updated_at"]; exists {
			t.Errorf("updated_at should not be present for nil timestamp, got %v", result["updated_at"])
		}
		if _, exists := result["last_auth"]; exists {
			t.Errorf("last_auth should not be present for nil timestamp, got %v", result["last_auth"])
		}
	})

	t.Run("user with empty slices and maps", func(t *testing.T) {
		user := &iampb.User{
			Id:         "user-empty-collections",
			TenantId:   "tenant-empty",
			Email:      "empty@example.com",
			Name:       "",
			Roles:      []string{},
			Groups:     []string{},
			Attributes: map[string]string{},
		}

		result := userToMap(user)

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
		user := &iampb.User{
			Id:          "user-no-mfa",
			TenantId:    "tenant-no-mfa",
			Email:       "nomfa@example.com",
			MfaVerified: false,
		}

		result := userToMap(user)

		// MfaVerified=false should not be included in the map
		if _, exists := result["mfa_verified"]; exists {
			t.Errorf("mfa_verified=false should not be present in map")
		}
	})

	t.Run("user with single role and group", func(t *testing.T) {
		user := &iampb.User{
			Id:       "user-single",
			TenantId: "tenant-single",
			Email:    "single@example.com",
			Roles:    []string{"viewer"},
			Groups:   []string{"readers"},
		}

		result := userToMap(user)

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
		now := time.Now()
		user := &iampb.User{
			Id:        "user-timestamps",
			TenantId:  "tenant-timestamps",
			Email:     "timestamps@example.com",
			CreatedAt: timestamppb.New(now),
			UpdatedAt: timestamppb.New(now),
			LastAuth:  timestamppb.New(now),
		}

		result := userToMap(user)

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
	now := time.Now()
	oneHourAgo := now.Add(-1 * time.Hour)

	t.Run("fully populated group", func(t *testing.T) {
		group := &iampb.Group{
			Id:          "group-123",
			TenantId:    "tenant-456",
			Name:        "Engineering Team",
			Description: "Software engineering department",
			Members:     []string{"user-1", "user-2", "user-3"},
			CreatedAt:   timestamppb.New(oneHourAgo),
			UpdatedAt:   timestamppb.New(now),
		}

		result := groupToMap(group)

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

		members, ok := result["members"].([]string)
		if !ok {
			t.Fatalf("expected members to be []string, got %T", result["members"])
		}
		if len(members) != 3 {
			t.Errorf("expected 3 members, got %d", len(members))
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
		result := groupToMap(nil)
		if result != nil {
			t.Errorf("expected nil for nil group, got %v", result)
		}
	})

	t.Run("minimal group with required fields only", func(t *testing.T) {
		group := &iampb.Group{
			Id:       "group-minimal",
			TenantId: "tenant-minimal",
		}

		result := groupToMap(group)

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
		if _, exists := result["members"]; exists {
			t.Errorf("members should not be present for nil slice")
		}
		if _, exists := result["created_at"]; exists {
			t.Errorf("created_at should not be present for nil timestamp")
		}
		if _, exists := result["updated_at"]; exists {
			t.Errorf("updated_at should not be present for nil timestamp")
		}
	})

	t.Run("group with empty members list", func(t *testing.T) {
		group := &iampb.Group{
			Id:          "group-no-members",
			TenantId:    "tenant-no-members",
			Name:        "Empty Group",
			Description: "A group with no members",
			Members:     []string{},
		}

		result := groupToMap(group)

		// Empty members slice should not be included
		if _, exists := result["members"]; exists {
			t.Errorf("empty members should not be present")
		}

		// Name and description should be present
		if result["name"] != "Empty Group" {
			t.Errorf("expected name 'Empty Group', got %v", result["name"])
		}
		if result["description"] != "A group with no members" {
			t.Errorf("expected description 'A group with no members', got %v", result["description"])
		}
	})

	t.Run("group with single member", func(t *testing.T) {
		group := &iampb.Group{
			Id:       "group-single",
			TenantId: "tenant-single",
			Members:  []string{"only-member"},
		}

		result := groupToMap(group)

		members, ok := result["members"].([]string)
		if !ok {
			t.Fatalf("expected members to be []string, got %T", result["members"])
		}
		if len(members) != 1 || members[0] != "only-member" {
			t.Errorf("expected members [only-member], got %v", members)
		}
	})

	t.Run("group with empty name and description", func(t *testing.T) {
		group := &iampb.Group{
			Id:          "group-empty-strings",
			TenantId:    "tenant-empty-strings",
			Name:        "",
			Description: "",
		}

		result := groupToMap(group)

		if _, exists := result["name"]; exists {
			t.Errorf("empty name should not be present")
		}
		if _, exists := result["description"]; exists {
			t.Errorf("empty description should not be present")
		}
	})

	t.Run("group with only timestamps", func(t *testing.T) {
		now := time.Now()
		group := &iampb.Group{
			Id:        "group-timestamps",
			TenantId:  "tenant-timestamps",
			CreatedAt: timestamppb.New(now),
			UpdatedAt: timestamppb.New(now),
		}

		result := groupToMap(group)

		if _, exists := result["created_at"]; !exists {
			t.Error("created_at should be present")
		}
		if _, exists := result["updated_at"]; !exists {
			t.Error("updated_at should be present")
		}
	})
}

func TestMCPHelperTenantToMap(t *testing.T) {
	now := time.Now()
	oneHourAgo := now.Add(-1 * time.Hour)

	t.Run("fully populated tenant", func(t *testing.T) {
		tenant := &iampb.Tenant{
			Id:   "tenant-123",
			Name: "Acme Corporation",
			Settings: &iampb.TenantSettings{
				MaxUsers:    100,
				MfaRequired: true,
			},
			CreatedAt: timestamppb.New(oneHourAgo),
			UpdatedAt: timestamppb.New(now),
		}

		result := tenantToMap(tenant)

		// Verify required fields
		if result["id"] != "tenant-123" {
			t.Errorf("expected id 'tenant-123', got %v", result["id"])
		}

		// Verify optional fields
		if result["name"] != "Acme Corporation" {
			t.Errorf("expected name 'Acme Corporation', got %v", result["name"])
		}

		// Verify settings
		settings, ok := result["settings"].(map[string]interface{})
		if !ok {
			t.Fatalf("expected settings to be map[string]interface{}, got %T", result["settings"])
		}
		if settings["max_users"] != int32(100) {
			t.Errorf("expected max_users 100, got %v (type %T)", settings["max_users"], settings["max_users"])
		}
		if settings["mfa_required"] != true {
			t.Errorf("expected mfa_required true, got %v", settings["mfa_required"])
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
		result := tenantToMap(nil)
		if result != nil {
			t.Errorf("expected nil for nil tenant, got %v", result)
		}
	})

	t.Run("minimal tenant with id only", func(t *testing.T) {
		tenant := &iampb.Tenant{
			Id: "tenant-minimal",
		}

		result := tenantToMap(tenant)

		// Verify required fields
		if result["id"] != "tenant-minimal" {
			t.Errorf("expected id 'tenant-minimal', got %v", result["id"])
		}

		// Verify optional fields are NOT present
		if _, exists := result["name"]; exists {
			t.Errorf("name should not be present for empty string")
		}
		if _, exists := result["settings"]; exists {
			t.Errorf("settings should not be present for nil settings")
		}
		if _, exists := result["created_at"]; exists {
			t.Errorf("created_at should not be present for nil timestamp")
		}
		if _, exists := result["updated_at"]; exists {
			t.Errorf("updated_at should not be present for nil timestamp")
		}
	})

	t.Run("tenant with nil settings", func(t *testing.T) {
		tenant := &iampb.Tenant{
			Id:       "tenant-no-settings",
			Name:     "No Settings Corp",
			Settings: nil,
		}

		result := tenantToMap(tenant)

		if result["name"] != "No Settings Corp" {
			t.Errorf("expected name 'No Settings Corp', got %v", result["name"])
		}

		if _, exists := result["settings"]; exists {
			t.Errorf("settings should not be present for nil settings")
		}
	})

	t.Run("tenant with empty name", func(t *testing.T) {
		tenant := &iampb.Tenant{
			Id:   "tenant-empty-name",
			Name: "",
		}

		result := tenantToMap(tenant)

		if _, exists := result["name"]; exists {
			t.Errorf("empty name should not be present")
		}
	})

	t.Run("tenant with default settings values", func(t *testing.T) {
		tenant := &iampb.Tenant{
			Id:   "tenant-default-settings",
			Name: "Default Settings Corp",
			Settings: &iampb.TenantSettings{
				MaxUsers:    0,
				MfaRequired: false,
			},
		}

		result := tenantToMap(tenant)

		// Settings should still be present even with zero/false values
		settings, ok := result["settings"].(map[string]interface{})
		if !ok {
			t.Fatalf("expected settings to be map[string]interface{}, got %T", result["settings"])
		}

		if settings["max_users"] != int32(0) {
			t.Errorf("expected max_users 0, got %v", settings["max_users"])
		}
		if settings["mfa_required"] != false {
			t.Errorf("expected mfa_required false, got %v", settings["mfa_required"])
		}
	})

	t.Run("tenant with only timestamps", func(t *testing.T) {
		now := time.Now()
		tenant := &iampb.Tenant{
			Id:        "tenant-timestamps",
			CreatedAt: timestamppb.New(now),
			UpdatedAt: timestamppb.New(now),
		}

		result := tenantToMap(tenant)

		if _, exists := result["created_at"]; !exists {
			t.Error("created_at should be present")
		}
		if _, exists := result["updated_at"]; !exists {
			t.Error("updated_at should be present")
		}
	})

	t.Run("tenant with large max_users value", func(t *testing.T) {
		tenant := &iampb.Tenant{
			Id: "tenant-large-max",
			Settings: &iampb.TenantSettings{
				MaxUsers: 2147483647, // max int32
			},
		}

		result := tenantToMap(tenant)

		settings, ok := result["settings"].(map[string]interface{})
		if !ok {
			t.Fatalf("expected settings to be map[string]interface{}, got %T", result["settings"])
		}
		if settings["max_users"] != int32(2147483647) {
			t.Errorf("expected max_users 2147483647, got %v", settings["max_users"])
		}
	})
}
