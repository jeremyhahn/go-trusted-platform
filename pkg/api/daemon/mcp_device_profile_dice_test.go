package daemon

import (
	"context"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// Invalid DICE fields are invalid input on every MCP profile write path
// through the real profile service, not a server fault (#1699, Codex round 3).
func TestMCPDeviceProfile_InvalidDICEFields_AreInvalidArgument(t *testing.T) {
	registry, svcs := newMCPDeviceTemplateRegistry(t)
	ctx := context.Background()
	require.NoError(t, svcs.profiles.Save(ctx, &entities.DeviceProfile{
		ID: 1699, Name: "avr", Role: entities.DeviceRoleWorker,
	}))
	template := &entities.DeviceTemplate{
		ID: 7199, Name: "avr-template", Role: entities.DeviceRoleWorker,
		Config: []byte(testTemplateConfigYAML),
	}
	require.NoError(t, svcs.templates.Save(ctx, template))

	for _, field := range []struct{ key, value string }{
		{"dice_device_id", "zz"},
		{"golden_fw_hash", "aa"},
	} {
		t.Run(field.key, func(t *testing.T) {
			_, err := registry.ExecuteTool(ctx, "profile_create", map[string]interface{}{
				"name": "avr-new", "role": "worker", field.key: field.value,
			})
			require.Error(t, err)
			assert.Equal(t, codes.InvalidArgument, mcpErrorClass(err), "create: %v", err)

			_, err = registry.ExecuteTool(ctx, "profile_update_by_id", map[string]interface{}{
				"id": 1699, field.key: field.value,
			})
			require.Error(t, err)
			assert.Equal(t, codes.InvalidArgument, mcpErrorClass(err), "update: %v", err)

			_, err = registry.ExecuteTool(ctx, "profile_create_from_template", map[string]interface{}{
				"template_id": strconv.FormatUint(template.ID, 10),
				"overrides":   map[string]interface{}{"name": "avr-derived", field.key: field.value},
			})
			require.Error(t, err)
			assert.Equal(t, codes.InvalidArgument, mcpErrorClass(err), "from template: %v", err)
		})
	}
}
