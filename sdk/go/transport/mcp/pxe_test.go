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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// Every PXEService method has a tool, an argument builder and a reply decoder.
func TestPXETools_CoverEveryMethod(t *testing.T) {
	desc := platformv1.PXEService_ServiceDesc
	for _, m := range desc.Methods {
		method := "/" + desc.ServiceName + "/" + m.MethodName
		assert.NotEmpty(t, MethodTools()[method], "%s has no tool", method)
		assert.Contains(t, mcpArgBuilders, method)
		assert.Contains(t, mcpReplyDecoders, method)
	}
	assert.Len(t, pxeToolMap, len(desc.Methods))
}

// A request travels under its proto field names, an enum by name.
func TestPXETools_BuildTheRequestArguments(t *testing.T) {
	build := mcpArgBuilders[platformv1.PXEService_UpdateState_FullMethodName]

	args, err := build(&platformv1.UpdatePXEStateRequest{
		DeviceId: "dev-1",
		State:    platformv1.ProvisioningState_PROVISIONING_STATE_INSTALLING,
		Reason:   "booted",
	})

	require.NoError(t, err)
	assert.Equal(t, map[string]interface{}{
		"device_id": "dev-1",
		"state":     "PROVISIONING_STATE_INSTALLING",
		"reason":    "booted",
	}, args)
}

func TestPXETools_RefuseAnArgumentOfAnotherType(t *testing.T) {
	build := mcpArgBuilders[platformv1.PXEService_UpdateState_FullMethodName]

	_, err := build("dev-1")

	var unexpected ErrUnexpectedArgsType
	require.True(t, errors.As(err, &unexpected), "error = %v", err)
	assert.Equal(t, platformv1.PXEService_UpdateState_FullMethodName, unexpected.Method)
}

// A tool result decodes into the gRPC response, nested messages included.
func TestPXETools_DecodeTheResult(t *testing.T) {
	decode := mcpReplyDecoders[platformv1.PXEService_ListDevices_FullMethodName]
	reply := &platformv1.ListPXEDevicesResponse{}

	err := decode(map[string]interface{}{
		"devices": []interface{}{map[string]interface{}{
			"id": "dev-1", "mac_address": "aa:bb:cc:dd:ee:01", "state": "PROVISIONING_STATE_QUARANTINED", "current_vlan": 999,
		}},
		"total_count": 1,
	}, reply)

	require.NoError(t, err)
	require.Len(t, reply.GetDevices(), 1)
	device := reply.GetDevices()[0]
	assert.Equal(t, "dev-1", device.GetId())
	assert.Equal(t, "aa:bb:cc:dd:ee:01", device.GetMacAddress())
	assert.Equal(t, platformv1.ProvisioningState_PROVISIONING_STATE_QUARANTINED, device.GetState())
	assert.Equal(t, uint32(999), device.GetCurrentVlan())
	assert.Equal(t, int32(1), reply.GetTotalCount())
}

func TestPXETools_RefuseAResultTheResponseCannotHold(t *testing.T) {
	decode := mcpReplyDecoders[platformv1.PXEService_GetStatus_FullMethodName]

	err := decode(map[string]interface{}{"status": "running"}, &platformv1.GetPXEStatusResponse{})

	var unmarshal ErrUnmarshalFailed
	assert.True(t, errors.As(err, &unmarshal), "error = %v", err)
}
