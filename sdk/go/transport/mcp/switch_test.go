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

// Every SwitchService method has a tool, an argument builder and a reply
// decoder.
func TestSwitchTools_CoverEveryMethod(t *testing.T) {
	desc := platformv1.SwitchService_ServiceDesc
	for _, m := range desc.Methods {
		method := "/" + desc.ServiceName + "/" + m.MethodName
		assert.NotEmpty(t, MethodTools()[method], "%s has no tool", method)
		assert.Contains(t, mcpArgBuilders, method)
		assert.Contains(t, mcpReplyDecoders, method)
	}
	assert.Len(t, switchToolMap, len(desc.Methods))
}

// A request travels under its proto field names.
func TestSwitchTools_BuildTheRequestArguments(t *testing.T) {
	build := mcpArgBuilders[platformv1.SwitchService_SetPortVLAN_FullMethodName]

	args, err := build(&platformv1.SetSwitchPortVLANRequest{SwitchName: "core-1", PortName: "eth1", VlanId: 20})

	require.NoError(t, err)
	assert.Equal(t, map[string]interface{}{
		"switch_name": "core-1",
		"port_name":   "eth1",
		"vlan_id":     float64(20),
	}, args)
}

func TestSwitchTools_RefuseAnArgumentOfAnotherType(t *testing.T) {
	build := mcpArgBuilders[platformv1.SwitchService_EnablePort_FullMethodName]

	_, err := build("eth1")

	var unexpected ErrUnexpectedArgsType
	require.True(t, errors.As(err, &unexpected), "error = %v", err)
	assert.Equal(t, platformv1.SwitchService_EnablePort_FullMethodName, unexpected.Method)
}

// A tool result decodes into the gRPC response, nested messages included.
func TestSwitchTools_DecodeTheResult(t *testing.T) {
	decode := mcpReplyDecoders[platformv1.SwitchService_ListPorts_FullMethodName]
	reply := &platformv1.ListSwitchPortsResponse{}

	err := decode(map[string]interface{}{"ports": []interface{}{map[string]interface{}{
		"port": "eth1", "mode": "trunk", "trunk_vlans": []interface{}{10, 20}, "native_vlan": 10, "enabled": true,
	}}}, reply)

	require.NoError(t, err)
	require.Len(t, reply.GetPorts(), 1)
	port := reply.GetPorts()[0]
	assert.Equal(t, "eth1", port.GetPort())
	assert.Equal(t, "trunk", port.GetMode())
	assert.Equal(t, []uint32{10, 20}, port.GetTrunkVlans())
	assert.Equal(t, uint32(10), port.GetNativeVlan())
	assert.True(t, port.GetEnabled())
}

func TestSwitchTools_RefuseAResultTheResponseCannotHold(t *testing.T) {
	decode := mcpReplyDecoders[platformv1.SwitchService_GetPortStatus_FullMethodName]

	err := decode(map[string]interface{}{"port": "eth1"}, &platformv1.GetSwitchPortStatusResponse{})

	var unmarshal ErrUnmarshalFailed
	assert.True(t, errors.As(err, &unmarshal), "error = %v", err)
}
