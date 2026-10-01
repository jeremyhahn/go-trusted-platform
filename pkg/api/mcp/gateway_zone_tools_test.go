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

package mcp

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// TestZoneTools_CreateParsesEveryField checks gateway_zone_create carries the
// whole zone schema to the service provider.
func TestZoneTools_CreateParsesEveryField(t *testing.T) {
	svc := &mockServiceProvider{}
	r := NewToolRegistry(svc, logging.NewLogger(slog.LevelError, io.Discard))

	_, err := r.ExecuteTool(context.Background(), "gateway_zone_create", map[string]interface{}{
		"name":         "lab",
		"offset":       float64(9),
		"port_classes": []interface{}{"hypervisor", "gateway"},
		"isolate_from": []interface{}{"storage"},
		"allow_to": []interface{}{
			map[string]interface{}{"zone": "control-plane", "services": []interface{}{"dns"}},
			"not-an-object",
			map[string]interface{}{"services": []interface{}{"x"}},
		},
		"services":          []interface{}{"ssh"},
		"isolate":           true,
		"privileged_access": map[string]interface{}{"reason": "lab dns", "approved_by": "owner"},
	})
	require.NoError(t, err)

	req := svc.lastZoneCreate
	require.NotNil(t, req)
	cfg := req.ZoneConfig()
	assert.Equal(t, zone.Zone("lab"), cfg.Name)
	assert.Equal(t, zone.Offset(9), cfg.Offset)
	assert.Equal(t, []zone.PortClass{zone.PortClassHypervisor, zone.PortClassGateway}, cfg.PortClasses)
	assert.Equal(t, []zone.Zone{zone.ZoneStorage}, cfg.IsolateFrom)
	require.Len(t, cfg.AllowTo, 1, "malformed allow_to entries are skipped")
	assert.Equal(t, zone.ZonePath{Zone: zone.ZoneControlPlane, Services: []string{"dns"}}, cfg.AllowTo[0])
	assert.Equal(t, []string{"ssh"}, cfg.Services)
	assert.True(t, cfg.Isolate)
	require.NotNil(t, cfg.PrivilegedAccess)
	assert.Equal(t, "owner", cfg.PrivilegedAccess.ApprovedBy)
}

// TestZoneTools_UpdateUsesTheNamedZone checks gateway_zone_update keeps the
// zone name apart from the policy fields.
func TestZoneTools_UpdateUsesTheNamedZone(t *testing.T) {
	svc := &mockServiceProvider{}
	r := NewToolRegistry(svc, logging.NewLogger(slog.LevelError, io.Discard))

	_, err := r.ExecuteTool(context.Background(), "gateway_zone_update", map[string]interface{}{
		"name":     "storage",
		"isolate":  true,
		"services": []interface{}{"nvme-tcp"},
	})
	require.NoError(t, err)
	assert.Equal(t, "storage", svc.lastZoneUpdateName)
	cfg := svc.lastZoneUpdate.ZoneConfig("storage")
	assert.Equal(t, zone.ZoneStorage, cfg.Name)
	assert.Nil(t, cfg.PrivilegedAccess)
	assert.Nil(t, cfg.AllowTo)
}

// TestZoneTools_NameRequired refuses create, update and delete without a
// name, and the retired assign tool is gone.
func TestZoneTools_NameRequired(t *testing.T) {
	r := NewToolRegistry(&mockServiceProvider{}, logging.NewLogger(slog.LevelError, io.Discard))
	for _, tool := range []string{"gateway_zone_create", "gateway_zone_update", "gateway_zone_delete"} {
		_, err := r.ExecuteTool(context.Background(), tool, map[string]interface{}{})
		assert.ErrorIs(t, err, ErrNetworkZoneNameRequired, tool)
	}
	_, err := r.ExecuteTool(context.Background(), "gateway_zone_assign", map[string]interface{}{"network": "a", "zone": "b"})
	assert.Error(t, err, "networks are zones: there is nothing to assign")
}

// TestZoneTools_ListAndDelete returns the zones and the delete result.
func TestZoneTools_ListAndDelete(t *testing.T) {
	r := NewToolRegistry(&mockServiceProvider{}, logging.NewLogger(slog.LevelError, io.Discard))
	ctx := context.Background()

	out, err := r.ExecuteTool(ctx, "gateway_zone_list", map[string]interface{}{"lifecycle_role": "quarantine"})
	require.NoError(t, err)
	assert.Contains(t, out, "zones")

	out, err = r.ExecuteTool(ctx, "gateway_zone_delete", map[string]interface{}{"name": "lab"})
	require.NoError(t, err)
	assert.Equal(t, map[string]interface{}{"success": true, "restart_required": false}, out)
}
