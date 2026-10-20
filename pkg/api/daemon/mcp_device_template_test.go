// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"context"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// newMCPDeviceTemplateRegistry builds the MCP tool registry over the
// daemon's MCP service provider with the real profile and template
// services, so a tool call lands in the same store REST writes to.
func newMCPDeviceTemplateRegistry(t *testing.T) (*mcp.ToolRegistry, realTemplateServices) {
	t.Helper()
	svcs := newRealTemplateServices(t)
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DeviceProfileService:  svcs.profiles,
		DeviceTemplateService: svcs.templates,
	})
	return mcp.NewToolRegistry(provider, logging.DefaultLogger()), svcs
}

// toolResultID parses the string id an MCP tool result carries.
func toolResultID(t *testing.T, result interface{}) uint64 {
	t.Helper()
	obj, ok := result.(map[string]interface{})
	require.True(t, ok, "result is %T, want map", result)
	idText, ok := obj["id"].(string)
	require.True(t, ok, "id must be a string, got %T", obj["id"])
	id, err := strconv.ParseUint(idText, 10, 64)
	require.NoError(t, err)
	return id
}

func TestMCPDeviceTemplateCreate(t *testing.T) {
	registry, svcs := newMCPDeviceTemplateRegistry(t)
	ctx := context.Background()

	result, err := registry.ExecuteTool(ctx, "device_template_create", map[string]interface{}{
		"tenant_id": "tenant-1",
		"name":      "edge",
		"role":      "edge",
		"config":    testTemplateConfigYAML,
	})
	require.NoError(t, err)
	id := toolResultID(t, result)
	require.NotZero(t, id, "the provider assigns an id")

	stored, err := svcs.templates.Get(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, "edge", stored.Name)
	assert.Equal(t, "tenant-1", stored.TenantID)
	assert.Equal(t, entities.DeviceRoleEdge, stored.Role)
	assert.Equal(t, testTemplateConfigYAML, string(stored.Config))
}

func TestMCPDeviceTemplateCreate_Errors(t *testing.T) {
	ctx := context.Background()

	t.Run("NoTemplateService", func(t *testing.T) {
		provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})
		_, err := provider.DeviceTemplateCreate(ctx, &entities.DeviceTemplate{Name: "edge"})
		var unavailable ErrServiceNotAvailable
		require.ErrorAs(t, err, &unavailable)
	})

	t.Run("UnnamedTemplateIsNotStored", func(t *testing.T) {
		svcs := newRealTemplateServices(t)
		provider := NewMCPServiceProvider(&MCPServiceProviderConfig{DeviceTemplateService: svcs.templates})
		_, err := provider.DeviceTemplateCreate(ctx, &entities.DeviceTemplate{Role: entities.DeviceRoleEdge})
		var nameRequired device.ErrTemplateNameRequired
		require.ErrorAs(t, err, &nameRequired)
		count, err := svcs.templates.Count(ctx)
		require.NoError(t, err)
		assert.Zero(t, count)
	})
}

func TestMCPDeviceTemplateGetListUpdateDelete(t *testing.T) {
	registry, svcs := newMCPDeviceTemplateRegistry(t)
	ctx := context.Background()
	stored := storeTestTemplate(t, svcs, "edge")
	id := strconv.FormatUint(stored.ID, 10)

	got, err := registry.ExecuteTool(ctx, "device_template_get", map[string]interface{}{"id": id})
	require.NoError(t, err)
	assert.Equal(t, stored.ID, toolResultID(t, got))

	listed, err := registry.ExecuteTool(ctx, "device_template_list", map[string]interface{}{})
	require.NoError(t, err)
	page := listed.(map[string]interface{})
	assert.Equal(t, 1, page["total"])
	require.Len(t, page["templates"], 1)

	_, err = registry.ExecuteTool(ctx, "device_template_update", map[string]interface{}{
		"id":   id,
		"name": "edge-v2",
		"role": "gateway",
	})
	require.NoError(t, err)
	reread, err := svcs.templates.Get(ctx, stored.ID)
	require.NoError(t, err)
	assert.Equal(t, "edge-v2", reread.Name)
	assert.Equal(t, entities.DeviceRoleGateway, reread.Role)
	assert.True(t, stored.CreatedAt.Equal(reread.CreatedAt), "an update keeps the creation time")

	_, err = registry.ExecuteTool(ctx, "device_template_delete", map[string]interface{}{"id": id})
	require.NoError(t, err)
	_, err = svcs.templates.Get(ctx, stored.ID)
	require.Error(t, err, "the deleted template is still stored")
}

func TestMCPDeviceTemplateGetListUpdateDelete_Errors(t *testing.T) {
	ctx := context.Background()

	t.Run("NoTemplateService", func(t *testing.T) {
		provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})
		var unavailable ErrServiceNotAvailable
		_, err := provider.DeviceTemplateGet(ctx, 1)
		require.ErrorAs(t, err, &unavailable)
		_, _, err = provider.DeviceTemplateList(ctx, 1, 10)
		require.ErrorAs(t, err, &unavailable)
		_, err = provider.DeviceTemplateUpdate(ctx, &entities.DeviceTemplate{ID: 1, Name: "edge"})
		require.ErrorAs(t, err, &unavailable)
		require.ErrorAs(t, provider.DeviceTemplateDelete(ctx, 1), &unavailable)
	})

	t.Run("UnknownTemplateIsNotFound", func(t *testing.T) {
		svcs := newRealTemplateServices(t)
		provider := NewMCPServiceProvider(&MCPServiceProviderConfig{DeviceTemplateService: svcs.templates})
		const absent = uint64(4242)
		_, err := provider.DeviceTemplateGet(ctx, absent)
		assert.Equal(t, codes.NotFound, status.Code(err), "get: %v", err)
		_, err = provider.DeviceTemplateUpdate(ctx, &entities.DeviceTemplate{ID: absent, Name: "edge"})
		assert.Equal(t, codes.NotFound, status.Code(err), "update: %v", err)
		err = provider.DeviceTemplateDelete(ctx, absent)
		assert.Equal(t, codes.NotFound, status.Code(err), "delete: %v", err)
	})
}

func TestMCPDeviceProfileFromTemplate(t *testing.T) {
	registry, svcs := newMCPDeviceTemplateRegistry(t)
	ctx := context.Background()
	template := &entities.DeviceTemplate{
		ID:     7101,
		Name:   "gateway",
		Role:   entities.DeviceRoleGateway,
		Config: []byte(testTemplateConfigYAML),
	}
	require.NoError(t, svcs.templates.Save(ctx, template))

	result, err := registry.ExecuteTool(ctx, "profile_create_from_template", map[string]interface{}{
		"template_id": strconv.FormatUint(template.ID, 10),
		"overrides":   map[string]interface{}{"name": "gw-01", "ek_serial": "EK-MCP"},
	})
	require.NoError(t, err)
	id := toolResultID(t, result)

	stored, err := svcs.profiles.Get(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, "gw-01", stored.Name)
	assert.Equal(t, "EK-MCP", stored.EKSerial)
	assert.Equal(t, entities.DeviceRoleGateway, stored.Role, "role comes from the template")
	assert.Equal(t, map[string]interface{}{"hostname": "edge-01", "domain": "example.com"}, stored.Config,
		"config comes from the template")
}

func TestMCPDeviceProfileFromTemplate_Errors(t *testing.T) {
	ctx := context.Background()
	svcs := newRealTemplateServices(t)

	t.Run("UnknownTemplate", func(t *testing.T) {
		provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
			DeviceProfileService:  svcs.profiles,
			DeviceTemplateService: svcs.templates,
		})
		_, err := provider.DeviceProfileFromTemplate(ctx, 4242, &entities.DeviceProfile{})
		require.Error(t, err)
		count, err := svcs.profiles.Count(ctx)
		require.NoError(t, err)
		assert.Zero(t, count, "no profile is stored for an unknown template")
	})

	t.Run("NoTemplateService", func(t *testing.T) {
		provider := NewMCPServiceProvider(&MCPServiceProviderConfig{DeviceProfileService: svcs.profiles})
		_, err := provider.DeviceProfileFromTemplate(ctx, 1, &entities.DeviceProfile{})
		var unavailable ErrServiceNotAvailable
		require.ErrorAs(t, err, &unavailable)
	})

	t.Run("NoProfileService", func(t *testing.T) {
		provider := NewMCPServiceProvider(&MCPServiceProviderConfig{DeviceTemplateService: svcs.templates})
		_, err := provider.DeviceProfileFromTemplate(ctx, 1, &entities.DeviceProfile{})
		var unavailable ErrServiceNotAvailable
		require.ErrorAs(t, err, &unavailable)
	})
}
