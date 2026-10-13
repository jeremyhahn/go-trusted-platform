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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

func TestMCPDeviceProfileMatch(t *testing.T) {
	registry, svcs := newMCPDeviceTemplateRegistry(t)
	ctx := context.Background()
	profile := &entities.DeviceProfile{
		ID:         8201,
		Name:       "rack-b",
		MatchRules: &entities.ProfileMatchRules{SerialPrefix: "SN200"},
	}
	require.NoError(t, svcs.profiles.Save(ctx, profile))

	result, err := registry.ExecuteTool(ctx, "profile_find_matching", map[string]interface{}{"serial": "SN200-ABC"})
	require.NoError(t, err)
	assert.Equal(t, profile.ID, toolResultID(t, result))
}

// A missing profile is NotFound over MCP, as it is over gRPC, so the SDK
// client reports the same error on every transport.
func TestMCPDeviceProfile_NotFound(t *testing.T) {
	registry, _ := newMCPDeviceTemplateRegistry(t)
	ctx := context.Background()

	calls := map[string]map[string]interface{}{
		"profile_get_by_id":      {"id": "4242"},
		"profile_delete_by_id":   {"id": "4242"},
		"profile_find_matching":  {"serial": "SN999"},
		"profile_find_by_mac":    {"mac_address": "02:00:00:00:00:99"},
		"profile_find_by_serial": {"serial": "SN999"},
	}
	for tool, args := range calls {
		t.Run(tool, func(t *testing.T) {
			_, err := registry.ExecuteTool(ctx, tool, args)
			assert.Equal(t, codes.NotFound, status.Code(err), "err = %v", err)
		})
	}
}

func TestMCPDeviceProfileMatch_NoProfileService(t *testing.T) {
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})
	_, err := provider.DeviceProfileMatch(context.Background(), "", "SN200", "")
	var unavailable ErrServiceNotAvailable
	require.ErrorAs(t, err, &unavailable)
}

// The single-attribute lookups reach the profile service's MAC-prefix and
// serial-prefix searches through the stored profiles.
func TestMCPDeviceProfileFindByMACAndSerial(t *testing.T) {
	registry, svcs := newMCPDeviceTemplateRegistry(t)
	ctx := context.Background()
	byMAC := &entities.DeviceProfile{
		ID:         8301,
		Name:       "rack-mac",
		MatchRules: &entities.ProfileMatchRules{MACPrefix: "52:54:00"},
	}
	bySerial := &entities.DeviceProfile{
		ID:         8302,
		Name:       "rack-serial",
		MatchRules: &entities.ProfileMatchRules{SerialPrefix: "SN300"},
	}
	require.NoError(t, svcs.profiles.Save(ctx, byMAC))
	require.NoError(t, svcs.profiles.Save(ctx, bySerial))

	result, err := registry.ExecuteTool(ctx, "profile_find_by_mac", map[string]interface{}{"mac_address": "52:54:00:12:34:56"})
	require.NoError(t, err)
	assert.Equal(t, byMAC.ID, toolResultID(t, result))

	result, err = registry.ExecuteTool(ctx, "profile_find_by_serial", map[string]interface{}{"serial": "SN300-XYZ"})
	require.NoError(t, err)
	assert.Equal(t, bySerial.ID, toolResultID(t, result))
}

func TestMCPDeviceProfileFindByMACAndSerial_NoProfileService(t *testing.T) {
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})
	var unavailable ErrServiceNotAvailable

	_, err := provider.DeviceProfileFindByMAC(context.Background(), "52:54:00:12:34:56")
	require.ErrorAs(t, err, &unavailable)

	_, err = provider.DeviceProfileFindBySerial(context.Background(), "SN300")
	require.ErrorAs(t, err, &unavailable)
}
