//go:build integration

package device

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// toolServer answers every MCP tools/call as platformd does: a
// CallToolResult whose text block holds output, the tool's JSON output.
func toolServer(t *testing.T, output json.RawMessage) *MCPAdapter {
	t.Helper()
	result, err := mcpwire.NewCallToolResult(output)
	require.NoError(t, err)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": result})
		if err != nil {
			t.Errorf("marshal tool response: %v", err)
			return
		}
		if _, err := w.Write(body); err != nil {
			t.Errorf("write tool response: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	return &MCPAdapter{endpoint: server.URL, client: server.Client()}
}

// assignedProfileToolResult renders profile the way the daemon's
// profile_assign_to_device tool does: the entity's JSON with its uint64 id
// as a decimal string.
func assignedProfileToolResult(t *testing.T, profile *entities.DeviceProfile) json.RawMessage {
	t.Helper()
	encoded, err := json.Marshal(profile)
	require.NoError(t, err)
	var obj map[string]any
	require.NoError(t, json.Unmarshal(encoded, &obj))
	obj["id"] = "554110910726213"
	result, err := json.Marshal(obj)
	require.NoError(t, err)
	return result
}

func TestMCPAssignProfileToDevice_DecodesTheStringID(t *testing.T) {
	adapter := toolServer(t, assignedProfileToolResult(t, &entities.DeviceProfile{
		Name:     "assign-me",
		EKSerial: "ASSIGN-EK-d28b1c6b",
		Assigned: true,
	}))

	result, err := adapter.AssignProfileToDevice(context.Background(), AssignProfileToDeviceOptions{
		ProfileID: "554110910726213",
		EKSerial:  "ASSIGN-EK-d28b1c6b",
	})
	require.NoError(t, err)
	require.NotNil(t, result.Profile)
	assert.Equal(t, uint64(554110910726213), result.Profile.ID)
	assert.Equal(t, "ASSIGN-EK-d28b1c6b", result.Profile.EKSerial)
	assert.True(t, result.Profile.Assigned)
}

func TestMCPAssignProfileToDevice_RejectsAMalformedResult(t *testing.T) {
	adapter := toolServer(t, json.RawMessage(`[]`))

	_, err := adapter.AssignProfileToDevice(context.Background(), AssignProfileToDeviceOptions{
		ProfileID: "1",
		EKSerial:  "EK-1",
	})
	var adapterErr *MCPAdapterError
	require.True(t, errors.As(err, &adapterErr), "got %v", err)
	assert.Equal(t, "AssignProfileToDevice", adapterErr.Operation)
}
