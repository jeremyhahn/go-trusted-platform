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

package device

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testTemplateServiceDatastore(t *testing.T) *Datastore {
	logger := logging.DefaultLogger()
	mockStorage := quicbaas.NewMockStorage()
	err := mockStorage.Start(context.Background())
	require.NoError(t, err)
	return NewDatastore(mockStorage, logger)
}

func testTemplateServiceDatastoreWithMock(t *testing.T) (*Datastore, *quicbaas.MockStorage) {
	logger := logging.DefaultLogger()
	mockStorage := quicbaas.NewMockStorage()
	err := mockStorage.Start(context.Background())
	require.NoError(t, err)
	return NewDatastore(mockStorage, logger), mockStorage
}

// testConfigYAML returns a sample platform config as raw YAML bytes for testing.
func testConfigYAML(domain, hostname string) []byte {
	return []byte("domain: " + domain + "\nhostname: " + hostname + "\n")
}

// testFullConfigYAML returns a richer platform config with nested structures
// for verifying deep merge behavior.
func testFullConfigYAML() []byte {
	return []byte(`domain: compute.example.com
hostname: compute
os:
  hostname: compute
  packages:
    - bash
    - vim
network:
  dns:
    nameservers:
      - 127.0.0.1
  interfaces:
    - name: eth0
      type: static
      ipv4-address: 198.18.0.3/24
`)
}

func TestNewTemplateService(t *testing.T) {
	ds := testTemplateServiceDatastore(t)

	service, err := NewTemplateService(ds)
	require.NoError(t, err)
	require.NotNil(t, service)
	assert.NotNil(t, service.templateDAO)
	assert.NotNil(t, service.profileDAO)
}

func TestTemplateService_Save(t *testing.T) {
	ds := testTemplateServiceDatastore(t)
	ctx := context.Background()

	service, err := NewTemplateService(ds)
	require.NoError(t, err)

	template := &entities.DeviceTemplate{
		ID:          1,
		TenantID:    "tenant-1",
		Name:        "edge-server-template",
		Description: "Template for edge servers",
		Role:        entities.DeviceRoleEdge,
		Config:      testConfigYAML("example.com", "edge-01"),
	}

	err = service.Save(ctx, template)
	assert.NoError(t, err)
	assert.False(t, template.CreatedAt.IsZero())
	assert.False(t, template.UpdatedAt.IsZero())
}

func TestTemplateService_Save_InvalidID(t *testing.T) {
	ds := testTemplateServiceDatastore(t)
	ctx := context.Background()

	service, err := NewTemplateService(ds)
	require.NoError(t, err)

	template := &entities.DeviceTemplate{
		ID:   0,
		Name: "invalid-template",
	}

	err = service.Save(ctx, template)
	assert.Error(t, err)
	assert.IsType(t, ErrInvalidTemplateID{}, err)
}

func TestTemplateService_Save_NilTemplate(t *testing.T) {
	ds := testTemplateServiceDatastore(t)
	ctx := context.Background()

	service, err := NewTemplateService(ds)
	require.NoError(t, err)

	err = service.Save(ctx, nil)
	assert.Error(t, err)
	assert.IsType(t, ErrNilTemplate{}, err)
}

func TestTemplateService_Save_DAOError(t *testing.T) {
	ds, mockStorage := testTemplateServiceDatastoreWithMock(t)
	ctx := context.Background()

	service, err := NewTemplateService(ds)
	require.NoError(t, err)

	mockStorage.PutError = errors.New("storage write failed")

	template := &entities.DeviceTemplate{
		ID:   1,
		Name: "test-template",
	}

	err = service.Save(ctx, template)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to save template")
}

func TestTemplateService_Get(t *testing.T) {
	ds := testTemplateServiceDatastore(t)
	ctx := context.Background()

	service, err := NewTemplateService(ds)
	require.NoError(t, err)

	template := &entities.DeviceTemplate{
		ID:          100,
		TenantID:    "tenant-1",
		Name:        "server-template",
		Description: "Server template",
		Role:        entities.DeviceRoleServer,
	}

	err = service.Save(ctx, template)
	require.NoError(t, err)

	retrieved, err := service.Get(ctx, template.ID)
	require.NoError(t, err)
	assert.Equal(t, template.ID, retrieved.ID)
	assert.Equal(t, template.TenantID, retrieved.TenantID)
	assert.Equal(t, template.Name, retrieved.Name)
	assert.Equal(t, template.Description, retrieved.Description)
	assert.Equal(t, template.Role, retrieved.Role)
}

func TestTemplateService_Get_InvalidID(t *testing.T) {
	ds := testTemplateServiceDatastore(t)
	ctx := context.Background()

	service, err := NewTemplateService(ds)
	require.NoError(t, err)

	_, err = service.Get(ctx, 0)
	assert.Error(t, err)
	assert.IsType(t, ErrInvalidTemplateID{}, err)
}

func TestTemplateService_Get_NotFound(t *testing.T) {
	ds := testTemplateServiceDatastore(t)
	ctx := context.Background()

	service, err := NewTemplateService(ds)
	require.NoError(t, err)

	_, err = service.Get(ctx, 9999)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get template")
}

func TestTemplateService_Delete(t *testing.T) {
	ds := testTemplateServiceDatastore(t)
	ctx := context.Background()

	service, err := NewTemplateService(ds)
	require.NoError(t, err)

	template := &entities.DeviceTemplate{
		ID:       200,
		TenantID: "tenant-1",
		Name:     "delete-template",
	}

	err = service.Save(ctx, template)
	require.NoError(t, err)

	// Verify it exists
	retrieved, err := service.Get(ctx, template.ID)
	require.NoError(t, err)
	assert.Equal(t, template.ID, retrieved.ID)

	// Delete it
	err = service.Delete(ctx, template)
	assert.NoError(t, err)

	// Verify it's deleted
	_, err = service.Get(ctx, template.ID)
	assert.Error(t, err)
}

func TestTemplateService_Delete_NilTemplate(t *testing.T) {
	ds := testTemplateServiceDatastore(t)
	ctx := context.Background()

	service, err := NewTemplateService(ds)
	require.NoError(t, err)

	err = service.Delete(ctx, nil)
	assert.Error(t, err)
	assert.IsType(t, ErrNilTemplate{}, err)
}

func TestTemplateService_Delete_InvalidID(t *testing.T) {
	ds := testTemplateServiceDatastore(t)
	ctx := context.Background()

	service, err := NewTemplateService(ds)
	require.NoError(t, err)

	template := &entities.DeviceTemplate{
		ID: 0,
	}

	err = service.Delete(ctx, template)
	assert.Error(t, err)
	assert.IsType(t, ErrInvalidTemplateID{}, err)
}

func TestTemplateService_Delete_DAOError(t *testing.T) {
	ds, mockStorage := testTemplateServiceDatastoreWithMock(t)
	ctx := context.Background()

	service, err := NewTemplateService(ds)
	require.NoError(t, err)

	mockStorage.DeleteError = errors.New("storage delete failed")

	template := &entities.DeviceTemplate{
		ID:   1,
		Name: "test-template",
	}

	err = service.Delete(ctx, template)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete template")
}

func TestTemplateService_Update(t *testing.T) {
	ds := testTemplateServiceDatastore(t)
	ctx := context.Background()

	service, err := NewTemplateService(ds)
	require.NoError(t, err)

	template := &entities.DeviceTemplate{
		ID:          300,
		TenantID:    "tenant-1",
		Name:        "original-template",
		Description: "Original description",
	}

	err = service.Save(ctx, template)
	require.NoError(t, err)

	// Update the template
	template.Name = "updated-template"
	template.Description = "Updated description"

	err = service.Update(ctx, template)
	require.NoError(t, err)

	// Verify the update
	retrieved, err := service.Get(ctx, template.ID)
	require.NoError(t, err)
	assert.Equal(t, "updated-template", retrieved.Name)
	assert.Equal(t, "Updated description", retrieved.Description)
}

func TestTemplateService_Update_NotFound(t *testing.T) {
	ds := testTemplateServiceDatastore(t)
	ctx := context.Background()

	service, err := NewTemplateService(ds)
	require.NoError(t, err)

	template := &entities.DeviceTemplate{
		ID:   9999,
		Name: "non-existent",
	}

	err = service.Update(ctx, template)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get template for update")
}

func TestTemplateService_Update_NilTemplate(t *testing.T) {
	ds := testTemplateServiceDatastore(t)
	ctx := context.Background()

	service, err := NewTemplateService(ds)
	require.NoError(t, err)

	err = service.Update(ctx, nil)
	assert.Error(t, err)
	assert.IsType(t, ErrNilTemplate{}, err)
}

func TestTemplateService_Update_InvalidID(t *testing.T) {
	ds := testTemplateServiceDatastore(t)
	ctx := context.Background()

	service, err := NewTemplateService(ds)
	require.NoError(t, err)

	template := &entities.DeviceTemplate{
		ID: 0,
	}

	err = service.Update(ctx, template)
	assert.Error(t, err)
	assert.IsType(t, ErrInvalidTemplateID{}, err)
}

func TestTemplateService_Update_SaveError(t *testing.T) {
	ds, mockStorage := testTemplateServiceDatastoreWithMock(t)
	ctx := context.Background()

	service, err := NewTemplateService(ds)
	require.NoError(t, err)

	template := &entities.DeviceTemplate{
		ID:   1,
		Name: "original-template",
	}

	// First save should succeed
	err = service.Save(ctx, template)
	require.NoError(t, err)

	// Now inject put error for the update
	mockStorage.PutError = errors.New("storage write failed")

	template.Name = "updated-template"
	err = service.Update(ctx, template)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to update template")
}

func TestTemplateService_Count(t *testing.T) {
	ds := testTemplateServiceDatastore(t)
	ctx := context.Background()

	service, err := NewTemplateService(ds)
	require.NoError(t, err)

	initialCount, err := service.Count(ctx)
	require.NoError(t, err)

	templates := []*entities.DeviceTemplate{
		{ID: 1, Name: "template-1"},
		{ID: 2, Name: "template-2"},
		{ID: 3, Name: "template-3"},
	}

	for _, tmpl := range templates {
		err = service.Save(ctx, tmpl)
		require.NoError(t, err)
	}

	count, err := service.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, initialCount+3, count)
}

func TestTemplateService_Count_DAOError(t *testing.T) {
	ds, mockStorage := testTemplateServiceDatastoreWithMock(t)
	ctx := context.Background()

	service, err := NewTemplateService(ds)
	require.NoError(t, err)

	mockStorage.ListError = errors.New("storage list failed")

	_, err = service.Count(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to count templates")
}

func TestTemplateService_Page(t *testing.T) {
	ds := testTemplateServiceDatastore(t)
	ctx := context.Background()

	service, err := NewTemplateService(ds)
	require.NoError(t, err)

	// Create test templates
	for i := 1; i <= 10; i++ {
		tmpl := &entities.DeviceTemplate{
			ID:   uint64(i),
			Name: "template-" + string(rune('0'+i)),
		}
		err = service.Save(ctx, tmpl)
		require.NoError(t, err)
	}

	pageQuery := datastore.PageQuery{
		Page:      1,
		PageSize:  5,
		SortOrder: datastore.SORT_ASCENDING,
	}

	result, err := service.Page(ctx, pageQuery)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(result.Entities), 5)
	assert.Equal(t, 1, result.Page)
	assert.Equal(t, 5, result.PageSize)
}

func TestTemplateService_Page_DAOError(t *testing.T) {
	ds, mockStorage := testTemplateServiceDatastoreWithMock(t)
	ctx := context.Background()

	service, err := NewTemplateService(ds)
	require.NoError(t, err)

	mockStorage.ListError = errors.New("storage list failed")

	pageQuery := datastore.PageQuery{
		Page:      1,
		PageSize:  5,
		SortOrder: datastore.SORT_ASCENDING,
	}

	_, err = service.Page(ctx, pageQuery)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to page templates")
}

func TestTemplateService_FindByName(t *testing.T) {
	ds := testTemplateServiceDatastore(t)
	ctx := context.Background()

	service, err := NewTemplateService(ds)
	require.NoError(t, err)

	template := &entities.DeviceTemplate{
		ID:       1,
		TenantID: "tenant-1",
		Name:     "edge-server",
		Role:     entities.DeviceRoleEdge,
	}

	err = service.Save(ctx, template)
	require.NoError(t, err)

	found, err := service.FindByName(ctx, "tenant-1", "edge-server")
	require.NoError(t, err)
	assert.Equal(t, template.ID, found.ID)
	assert.Equal(t, template.Name, found.Name)
	assert.Equal(t, template.TenantID, found.TenantID)
}

func TestTemplateService_FindByName_EmptyName(t *testing.T) {
	ds := testTemplateServiceDatastore(t)
	ctx := context.Background()

	service, err := NewTemplateService(ds)
	require.NoError(t, err)

	_, err = service.FindByName(ctx, "tenant-1", "")
	assert.Error(t, err)
	assert.IsType(t, ErrTemplateNameRequired{}, err)
}

func TestTemplateService_FindByName_NotFound(t *testing.T) {
	ds := testTemplateServiceDatastore(t)
	ctx := context.Background()

	service, err := NewTemplateService(ds)
	require.NoError(t, err)

	_, err = service.FindByName(ctx, "tenant-1", "non-existent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestTemplateService_FindByName_WrongTenant(t *testing.T) {
	ds := testTemplateServiceDatastore(t)
	ctx := context.Background()

	service, err := NewTemplateService(ds)
	require.NoError(t, err)

	template := &entities.DeviceTemplate{
		ID:       1,
		TenantID: "tenant-1",
		Name:     "edge-server",
	}

	err = service.Save(ctx, template)
	require.NoError(t, err)

	// Search with different tenant
	_, err = service.FindByName(ctx, "tenant-2", "edge-server")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestTemplateService_ToProfile(t *testing.T) {
	ds := testTemplateServiceDatastore(t)
	ctx := context.Background()

	service, err := NewTemplateService(ds)
	require.NoError(t, err)

	template := &entities.DeviceTemplate{
		ID:       1,
		TenantID: "tenant-1",
		Name:     "edge-server-template",
		Role:     entities.DeviceRoleEdge,
		Config:   testConfigYAML("example.com", "edge-01"),
		MatchRules: &entities.ProfileMatchRules{
			MACPrefix: "52:54:00",
			Model:     "EdgeBox",
		},
	}

	err = service.Save(ctx, template)
	require.NoError(t, err)

	overrides := &entities.DeviceProfile{
		Name:  "edge-01-profile",
		Model: "EdgeBox-v2",
	}

	profile, err := service.ToProfile(ctx, template.ID, overrides)
	require.NoError(t, err)

	// ID should be zero (unsaved)
	assert.Equal(t, uint64(0), profile.ID)

	// TenantID from template
	assert.Equal(t, "tenant-1", profile.TenantID)

	// Overrides applied
	assert.Equal(t, "edge-01-profile", profile.Name)
	assert.Equal(t, "EdgeBox-v2", profile.Model)

	// Role from template (not overridden with empty)
	assert.Equal(t, entities.DeviceRoleEdge, profile.Role)

	// Config deep-copied into PlatformdConfig inline
	assert.NotNil(t, profile.PlatformdConfig)
	assert.Equal(t, "inline", profile.PlatformdConfig.ConfigType)
	inlineConfig, ok := profile.PlatformdConfig.Inline.(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, "example.com", inlineConfig["domain"])
	assert.Equal(t, "edge-01", inlineConfig["hostname"])

	// Config also stored in profile.Config for direct delivery
	assert.NotNil(t, profile.Config)
	configMap, ok := profile.Config.(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, "example.com", configMap["domain"])
	assert.Equal(t, "edge-01", configMap["hostname"])

	// Match rules deep-copied
	assert.NotNil(t, profile.MatchRules)
	assert.Equal(t, "52:54:00", profile.MatchRules.MACPrefix)
	assert.Equal(t, "EdgeBox", profile.MatchRules.Model)
}

func TestTemplateService_ToProfile_NotFound(t *testing.T) {
	ds := testTemplateServiceDatastore(t)
	ctx := context.Background()

	service, err := NewTemplateService(ds)
	require.NoError(t, err)

	_, err = service.ToProfile(ctx, 9999, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get template for profile conversion")
}

func TestTemplateService_ToProfile_InvalidID(t *testing.T) {
	ds := testTemplateServiceDatastore(t)
	ctx := context.Background()

	service, err := NewTemplateService(ds)
	require.NoError(t, err)

	_, err = service.ToProfile(ctx, 0, nil)
	assert.Error(t, err)
	assert.IsType(t, ErrInvalidTemplateID{}, err)
}

func TestTemplateService_ToProfile_NilOverrides(t *testing.T) {
	ds := testTemplateServiceDatastore(t)
	ctx := context.Background()

	service, err := NewTemplateService(ds)
	require.NoError(t, err)

	template := &entities.DeviceTemplate{
		ID:       1,
		TenantID: "tenant-1",
		Name:     "basic-template",
		Role:     entities.DeviceRoleServer,
		Config:   testConfigYAML("example.com", "srv-01"),
	}

	err = service.Save(ctx, template)
	require.NoError(t, err)

	profile, err := service.ToProfile(ctx, template.ID, nil)
	require.NoError(t, err)

	assert.Equal(t, uint64(0), profile.ID)
	assert.Equal(t, "tenant-1", profile.TenantID)
	assert.Equal(t, entities.DeviceRoleServer, profile.Role)
	assert.NotNil(t, profile.PlatformdConfig)
	assert.NotNil(t, profile.Config)
}

func TestTemplateService_ToProfile_NoConfig(t *testing.T) {
	ds := testTemplateServiceDatastore(t)
	ctx := context.Background()

	service, err := NewTemplateService(ds)
	require.NoError(t, err)

	template := &entities.DeviceTemplate{
		ID:       1,
		TenantID: "tenant-1",
		Name:     "minimal-template",
		Role:     entities.DeviceRoleClient,
	}

	err = service.Save(ctx, template)
	require.NoError(t, err)

	profile, err := service.ToProfile(ctx, template.ID, nil)
	require.NoError(t, err)

	assert.Equal(t, uint64(0), profile.ID)
	assert.Equal(t, "tenant-1", profile.TenantID)
	assert.Equal(t, entities.DeviceRoleClient, profile.Role)
	assert.Nil(t, profile.PlatformdConfig)
	assert.Nil(t, profile.Config)
}

func TestTemplateService_ToProfile_OverrideTenantID(t *testing.T) {
	ds := testTemplateServiceDatastore(t)
	ctx := context.Background()

	service, err := NewTemplateService(ds)
	require.NoError(t, err)

	template := &entities.DeviceTemplate{
		ID:       1,
		TenantID: "tenant-1",
		Name:     "template-1",
		Role:     entities.DeviceRoleServer,
	}

	err = service.Save(ctx, template)
	require.NoError(t, err)

	overrides := &entities.DeviceProfile{
		TenantID: "tenant-2",
	}

	profile, err := service.ToProfile(ctx, template.ID, overrides)
	require.NoError(t, err)

	assert.Equal(t, "tenant-2", profile.TenantID)
}

func TestTemplateService_WithConfig(t *testing.T) {
	ds := testTemplateServiceDatastore(t)
	ctx := context.Background()

	service, err := NewTemplateService(ds)
	require.NoError(t, err)

	template := &entities.DeviceTemplate{
		ID:       400,
		TenantID: "tenant-1",
		Name:     "full-config-template",
		Role:     entities.DeviceRoleServer,
		Config:   testConfigYAML("production.example.com", "node-01"),
		MatchRules: &entities.ProfileMatchRules{
			MACPrefix:    "52:54:00",
			SerialPrefix: "SN100",
		},
	}

	err = service.Save(ctx, template)
	require.NoError(t, err)

	retrieved, err := service.Get(ctx, template.ID)
	require.NoError(t, err)
	assert.NotNil(t, retrieved.Config)
	assert.Contains(t, string(retrieved.Config), "production.example.com")
	assert.NotNil(t, retrieved.MatchRules)
	assert.Equal(t, "52:54:00", retrieved.MatchRules.MACPrefix)
	assert.Equal(t, "SN100", retrieved.MatchRules.SerialPrefix)
}

func TestTemplateService_CountAfterDeletion(t *testing.T) {
	ds := testTemplateServiceDatastore(t)
	ctx := context.Background()

	service, err := NewTemplateService(ds)
	require.NoError(t, err)

	template := &entities.DeviceTemplate{
		ID:   1500,
		Name: "count-template",
	}

	err = service.Save(ctx, template)
	require.NoError(t, err)

	count1, err := service.Count(ctx)
	require.NoError(t, err)

	err = service.Delete(ctx, template)
	require.NoError(t, err)

	count2, err := service.Count(ctx)
	require.NoError(t, err)

	assert.Equal(t, count1-1, count2)
}

func TestTemplateService_ToProfile_DeepCopyConfig(t *testing.T) {
	ds := testTemplateServiceDatastore(t)
	ctx := context.Background()

	service, err := NewTemplateService(ds)
	require.NoError(t, err)

	template := &entities.DeviceTemplate{
		ID:       1,
		TenantID: "tenant-1",
		Name:     "deep-copy-template",
		Role:     entities.DeviceRoleServer,
		Config:   testConfigYAML("original.com", "srv-01"),
		MatchRules: &entities.ProfileMatchRules{
			MACPrefix: "aa:bb:cc",
		},
	}

	err = service.Save(ctx, template)
	require.NoError(t, err)

	profile, err := service.ToProfile(ctx, template.ID, nil)
	require.NoError(t, err)

	// Modify the original template config bytes after conversion
	template.Config = testConfigYAML("modified.com", "srv-02")

	// Profile config should still reference original values
	inlineConfig, ok := profile.PlatformdConfig.Inline.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "original.com", inlineConfig["domain"])

	// profile.Config should also have original values
	configMap, ok := profile.Config.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "original.com", configMap["domain"])

	// Modify the profile's match rules
	profile.MatchRules.MACPrefix = "dd:ee:ff"

	// Re-fetch the template and verify its match rules are unchanged
	retrieved, err := service.Get(ctx, template.ID)
	require.NoError(t, err)
	assert.Equal(t, "aa:bb:cc", retrieved.MatchRules.MACPrefix)
}

func TestTemplateService_ToProfile_OverrideNetworkConfig(t *testing.T) {
	ds := testTemplateServiceDatastore(t)
	ctx := context.Background()

	service, err := NewTemplateService(ds)
	require.NoError(t, err)

	template := &entities.DeviceTemplate{
		ID:       1,
		TenantID: "tenant-1",
		Name:     "network-template",
		Role:     entities.DeviceRoleGateway,
	}

	err = service.Save(ctx, template)
	require.NoError(t, err)

	overrides := &entities.DeviceProfile{
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultEnrollmentNetwork: {
				VLAN:     100,
				StaticIP: "192.168.1.10",
			},
			entities.DefaultPostEnrollmentNetwork: {
				VLAN:     200,
				StaticIP: "10.0.0.10",
			},
			entities.DefaultFailureNetwork: {
				VLAN: 999,
			},
		},
		WorkloadPCR: 15,
	}

	profile, err := service.ToProfile(ctx, template.ID, overrides)
	require.NoError(t, err)

	assert.NotNil(t, profile.GetEnrollmentNetworkConfig())
	assert.Equal(t, uint16(100), profile.GetEnrollmentNetworkConfig().VLAN)
	assert.NotNil(t, profile.GetPostEnrollmentNetworkConfig())
	assert.Equal(t, uint16(200), profile.GetPostEnrollmentNetworkConfig().VLAN)
	assert.NotNil(t, profile.GetFailureNetworkConfig())
	assert.Equal(t, uint16(999), profile.GetFailureNetworkConfig().VLAN)
	assert.Equal(t, 15, profile.WorkloadPCR)
}

func TestTemplateService_ToProfileWithConfigOverrides(t *testing.T) {
	ds := testTemplateServiceDatastore(t)
	ctx := context.Background()

	service, err := NewTemplateService(ds)
	require.NoError(t, err)

	template := &entities.DeviceTemplate{
		ID:       1,
		TenantID: "tenant-1",
		Name:     "compute-template",
		Role:     entities.DeviceRoleServer,
		Config:   testFullConfigYAML(),
	}

	err = service.Save(ctx, template)
	require.NoError(t, err)

	// Config overrides change the hostname and IP while preserving other fields
	configOverrides := map[string]interface{}{
		"hostname": "lab-node-3",
		"os": map[string]interface{}{
			"hostname": "lab-node-3",
		},
		"network": map[string]interface{}{
			"interfaces": []interface{}{
				map[string]interface{}{
					"name":         "eth0",
					"type":         "static",
					"ipv4-address": "198.18.0.104/24",
				},
			},
		},
	}

	overrides := &entities.DeviceProfile{
		Name: "lab-node-3",
	}

	profile, err := service.ToProfileWithConfigOverrides(ctx, template.ID, overrides, configOverrides)
	require.NoError(t, err)

	// Verify the profile name was overridden
	assert.Equal(t, "lab-node-3", profile.Name)

	// Verify the config was deep-merged
	configMap, ok := profile.Config.(map[string]interface{})
	require.True(t, ok)

	// hostname should be overridden
	assert.Equal(t, "lab-node-3", configMap["hostname"])

	// domain should be preserved from the template
	assert.Equal(t, "compute.example.com", configMap["domain"])

	// os.hostname should be overridden
	osMap, ok := configMap["os"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "lab-node-3", osMap["hostname"])

	// os.packages should be preserved from template
	packages, ok := osMap["packages"].([]interface{})
	require.True(t, ok)
	assert.Contains(t, packages, "bash")
	assert.Contains(t, packages, "vim")

	// PlatformdConfig.Inline should also have the merged config
	inlineConfig, ok := profile.PlatformdConfig.Inline.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "lab-node-3", inlineConfig["hostname"])
	assert.Equal(t, "compute.example.com", inlineConfig["domain"])
}

func TestTemplateService_ToProfileWithConfigOverrides_NilOverrides(t *testing.T) {
	ds := testTemplateServiceDatastore(t)
	ctx := context.Background()

	service, err := NewTemplateService(ds)
	require.NoError(t, err)

	template := &entities.DeviceTemplate{
		ID:       1,
		TenantID: "tenant-1",
		Name:     "compute-template",
		Role:     entities.DeviceRoleServer,
		Config:   testConfigYAML("example.com", "srv-01"),
	}

	err = service.Save(ctx, template)
	require.NoError(t, err)

	// No config overrides -- should return template config as-is
	profile, err := service.ToProfileWithConfigOverrides(ctx, template.ID, nil, nil)
	require.NoError(t, err)

	configMap, ok := profile.Config.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "example.com", configMap["domain"])
	assert.Equal(t, "srv-01", configMap["hostname"])
}

func TestTemplateService_ToProfileWithConfigOverrides_InvalidID(t *testing.T) {
	ds := testTemplateServiceDatastore(t)
	ctx := context.Background()

	service, err := NewTemplateService(ds)
	require.NoError(t, err)

	_, err = service.ToProfileWithConfigOverrides(ctx, 0, nil, nil)
	assert.Error(t, err)
	assert.IsType(t, ErrInvalidTemplateID{}, err)
}

// TestNewRoleTemplate verifies the seeder's role-keyed template carries the
// role as both name and role, keeps the config verbatim, and derives a
// deterministic ID from the role.
func TestNewRoleTemplate(t *testing.T) {
	for _, role := range []string{"control-plane", "gateway", "worker"} {
		t.Run(role, func(t *testing.T) {
			tmpl, err := NewRoleTemplate(role, []byte(`{"domain":"example.com"}`))
			require.NoError(t, err)
			assert.Equal(t, util.NewID([]byte(role)), tmpl.ID)
			assert.Equal(t, role, tmpl.Name)
			assert.Equal(t, entities.DeviceRole(role), tmpl.Role)
			assert.Equal(t, []byte(`{"domain":"example.com"}`), tmpl.Config)
		})
	}
}

// TestNewRoleTemplate_UnknownRole verifies an out-of-vocabulary role is
// rejected with the typed entity error instead of being stored as unknown.
func TestNewRoleTemplate_UnknownRole(t *testing.T) {
	tmpl, err := NewRoleTemplate("compute", []byte(`{}`))
	assert.Nil(t, tmpl)
	var unknown entities.ErrUnknownDeviceRole
	require.ErrorAs(t, err, &unknown)
	assert.Equal(t, "compute", unknown.Role)
}

// TestNewRoleTemplate_AliasKeysTheCanonicalRecord verifies an alias or case
// variant resolves to the same template record as the canonical spelling.
func TestNewRoleTemplate_AliasKeysTheCanonicalRecord(t *testing.T) {
	canonical, err := NewRoleTemplate("load-balancer", []byte(`{}`))
	require.NoError(t, err)
	alias, err := NewRoleTemplate("LoadBalancer", []byte(`{}`))
	require.NoError(t, err)
	assert.Equal(t, canonical.ID, alias.ID)
	assert.Equal(t, "load-balancer", alias.Name)
	assert.Equal(t, entities.DeviceRoleLoadBalancer, alias.Role)
}
