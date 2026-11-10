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
      ipv4-address: 10.4.200.3/24
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

// TestTemplateService_Save_NameRequired pins that an unnamed template is
// rejected before it reaches storage: a template is found by name
// (FindByName, `platformctl device register --template`), so an unnamed
// one could never be used.
func TestTemplateService_Save_NameRequired(t *testing.T) {
	ds := testTemplateServiceDatastore(t)
	ctx := context.Background()

	service, err := NewTemplateService(ds)
	require.NoError(t, err)

	err = service.Save(ctx, &entities.DeviceTemplate{ID: 1})
	assert.IsType(t, ErrTemplateNameRequired{}, err)

	count, err := service.Count(ctx)
	require.NoError(t, err)
	assert.Zero(t, count)
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

// TestTemplateService_ToProfile_UnknownRoleKeepsTemplateRole pins #497:
// REST, gRPC, QUIC and MCP all decode an absent override role as
// DeviceRoleUnknown, which used to replace the template's role. A known
// override role still wins.
func TestTemplateService_ToProfile_UnknownRoleKeepsTemplateRole(t *testing.T) {
	ds := testTemplateServiceDatastore(t)
	ctx := context.Background()

	service, err := NewTemplateService(ds)
	require.NoError(t, err)

	template := &entities.DeviceTemplate{ID: 1, Name: "gateway", Role: entities.DeviceRoleGateway}
	require.NoError(t, service.Save(ctx, template))

	kept, err := service.ToProfile(ctx, template.ID, &entities.DeviceProfile{
		Name: "edge-01",
		Role: entities.DeviceRoleUnknown,
	})
	require.NoError(t, err)
	assert.Equal(t, entities.DeviceRoleGateway, kept.Role)

	replaced, err := service.ToProfile(ctx, template.ID, &entities.DeviceProfile{Role: entities.DeviceRoleEdge})
	require.NoError(t, err)
	assert.Equal(t, entities.DeviceRoleEdge, replaced.Role)
}

// A prestaged EK certificate override travels with the EK serial and MAC
// it binds; dropping it left the profile unable to match the hardware EK.
func TestTemplateService_ToProfile_CarriesEKCertOverride(t *testing.T) {
	ds := testTemplateServiceDatastore(t)
	ctx := context.Background()

	service, err := NewTemplateService(ds)
	require.NoError(t, err)

	template := &entities.DeviceTemplate{ID: 1, Name: "edge", Role: entities.DeviceRoleEdge}
	require.NoError(t, service.Save(ctx, template))

	const ekCert = "-----BEGIN CERTIFICATE-----\nprestaged\n-----END CERTIFICATE-----\n"
	profile, err := service.ToProfile(ctx, template.ID, &entities.DeviceProfile{EKSerial: "EK-1", EKCert: ekCert})
	require.NoError(t, err)
	assert.Equal(t, ekCert, profile.EKCert)

	bare, err := service.ToProfile(ctx, template.ID, &entities.DeviceProfile{EKSerial: "EK-2"})
	require.NoError(t, err)
	assert.Empty(t, bare.EKCert, "no override leaves no prestaged certificate")
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
		"hostname": "host-03",
		"os": map[string]interface{}{
			"hostname": "host-03",
		},
		"network": map[string]interface{}{
			"interfaces": []interface{}{
				map[string]interface{}{
					"name":         "eth0",
					"type":         "static",
					"ipv4-address": "10.4.200.104/24",
				},
			},
		},
	}

	overrides := &entities.DeviceProfile{
		Name: "host-03",
	}

	profile, err := service.ToProfileWithConfigOverrides(ctx, template.ID, overrides, configOverrides)
	require.NoError(t, err)

	// Verify the profile name was overridden
	assert.Equal(t, "host-03", profile.Name)

	// Verify the config was deep-merged
	configMap, ok := profile.Config.(map[string]interface{})
	require.True(t, ok)

	// hostname should be overridden
	assert.Equal(t, "host-03", configMap["hostname"])

	// domain should be preserved from the template
	assert.Equal(t, "compute.example.com", configMap["domain"])

	// os.hostname should be overridden
	osMap, ok := configMap["os"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "host-03", osMap["hostname"])

	// os.packages should be preserved from template
	packages, ok := osMap["packages"].([]interface{})
	require.True(t, ok)
	assert.Contains(t, packages, "bash")
	assert.Contains(t, packages, "vim")

	// PlatformdConfig.Inline should also have the merged config
	inlineConfig, ok := profile.PlatformdConfig.Inline.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "host-03", inlineConfig["hostname"])
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

// TestCreateProfileFromTemplate stores the derived profile under a fresh ID,
// so every transport that calls it creates rather than merely converts.
func TestCreateProfileFromTemplate(t *testing.T) {
	ds := testTemplateServiceDatastore(t)
	ctx := context.Background()
	templates, err := NewTemplateService(ds)
	require.NoError(t, err)
	profiles, err := NewProfileService(ds)
	require.NoError(t, err)
	require.NoError(t, templates.Save(ctx, &entities.DeviceTemplate{ID: 2510, Name: "edge", Role: entities.DeviceRoleWorker}))

	profile, err := CreateProfileFromTemplate(ctx, templates, profiles, 2510, &entities.DeviceProfile{Name: "edge-01"})
	require.NoError(t, err)
	require.NotZero(t, profile.ID)

	stored, err := profiles.Get(ctx, profile.ID)
	require.NoError(t, err, "the derived profile is saved")
	assert.Equal(t, "edge-01", stored.Name)
	assert.Equal(t, entities.DeviceRoleWorker, stored.Role)
}

// TestCreateProfileFromTemplate_Errors names the missing dependency and
// passes the template service's typed errors through unchanged.
func TestCreateProfileFromTemplate_Errors(t *testing.T) {
	ds := testTemplateServiceDatastore(t)
	ctx := context.Background()
	templates, err := NewTemplateService(ds)
	require.NoError(t, err)
	profiles, err := NewProfileService(ds)
	require.NoError(t, err)

	_, err = CreateProfileFromTemplate(ctx, nil, profiles, 2510, nil)
	assert.ErrorIs(t, err, ErrTemplateProfileDependency{Name: "template service"})
	_, err = CreateProfileFromTemplate(ctx, templates, nil, 2510, nil)
	assert.ErrorIs(t, err, ErrTemplateProfileDependency{Name: "profile service"})
	_, err = CreateProfileFromTemplate(ctx, templates, profiles, 0, nil)
	assert.ErrorAs(t, err, &ErrInvalidTemplateID{})
	_, err = CreateProfileFromTemplate(ctx, templates, profiles, 404, nil)
	assert.Error(t, err, "an unknown template")

	count, err := profiles.Count(ctx)
	require.NoError(t, err)
	assert.Zero(t, count, "a failed create stores no profile")
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

// TestTemplateService_ToProfile_OverrideIdentityAndZone verifies the identity
// binding (EK serial, MAC) and the profile-level zone in overrides reach the
// profile. Before #378 the merge dropped all three while honouring the
// networks beside them, so the create-from-template route answered 201 with a
// profile that had lost the operator's binding.
func TestTemplateService_ToProfile_OverrideIdentityAndZone(t *testing.T) {
	ds := testTemplateServiceDatastore(t)
	ctx := context.Background()

	service, err := NewTemplateService(ds)
	require.NoError(t, err)

	template := &entities.DeviceTemplate{
		ID:       21,
		TenantID: "tenant-1",
		Name:     "worker-template",
		Role:     entities.DeviceRoleWorker,
	}
	require.NoError(t, service.Save(ctx, template))

	profile, err := service.ToProfile(ctx, template.ID, &entities.DeviceProfile{
		EKSerial:   "EK-0001",
		MACAddress: "52:54:00:aa:bb:cc",
		Zone:       "lab",
		Networks: map[string]*entities.NetworkPhaseConfig{
			"lab-dmz": {VLAN: 42, StaticIP: "10.42.0.7"},
		},
		PostEnrollmentNetwork: "lab-dmz",
	})
	require.NoError(t, err)

	assert.Equal(t, "EK-0001", profile.EKSerial)
	assert.Equal(t, "52:54:00:aa:bb:cc", profile.MACAddress)
	assert.Equal(t, "lab", profile.Zone)
	// The network beside them still arrives, and the selector resolves to it.
	require.NotNil(t, profile.GetPostEnrollmentNetworkConfig())
	assert.Equal(t, "10.42.0.7", profile.GetPostEnrollmentNetworkConfig().StaticIP)
}

// TestTemplateService_ToProfile_EmptyIdentityLeavesZeroValues is the negative:
// overrides that carry none of the identity fields produce zero values, not
// garbage, and do not disturb what the template supplied.
func TestTemplateService_ToProfile_EmptyIdentityLeavesZeroValues(t *testing.T) {
	ds := testTemplateServiceDatastore(t)
	ctx := context.Background()

	service, err := NewTemplateService(ds)
	require.NoError(t, err)

	template := &entities.DeviceTemplate{
		ID:       22,
		TenantID: "tenant-1",
		Name:     "worker-template",
		Role:     entities.DeviceRoleWorker,
	}
	require.NoError(t, service.Save(ctx, template))

	profile, err := service.ToProfile(ctx, template.ID, &entities.DeviceProfile{Name: "bare"})
	require.NoError(t, err)

	assert.Equal(t, "bare", profile.Name)
	assert.Empty(t, profile.EKSerial)
	assert.Empty(t, profile.MACAddress)
	assert.Empty(t, profile.Zone)
	assert.Empty(t, profile.EnrollmentNetwork)
	assert.Empty(t, profile.PostEnrollmentNetwork)
	assert.Empty(t, profile.FailureNetwork)
	assert.Nil(t, profile.Networks)
	assert.Equal(t, "tenant-1", profile.TenantID)
	assert.Equal(t, entities.DeviceRoleWorker, profile.Role)
}
