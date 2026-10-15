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

// Every BMCService method has a tool, an argument builder and a reply decoder.
func TestBMCTools_CoverEveryMethod(t *testing.T) {
	desc := platformv1.BMCService_ServiceDesc
	for _, m := range desc.Methods {
		method := "/" + desc.ServiceName + "/" + m.MethodName
		assert.NotEmpty(t, MethodTools()[method], "%s has no tool", method)
		assert.Contains(t, mcpArgBuilders, method)
		assert.Contains(t, mcpReplyDecoders, method)
	}
	assert.Len(t, bmcToolMap, len(desc.Methods))
}

// A request travels under its proto field names: the profile ID as a decimal
// string and an enum by name.
func TestBMCTools_BuildTheRequestArguments(t *testing.T) {
	build := mcpArgBuilders[platformv1.BMCService_SetBootDevice_FullMethodName]

	args, err := build(&platformv1.BMCSetBootDeviceRequest{
		ProfileId:  7,
		Device:     platformv1.BMCBootDevice_BMC_BOOT_DEVICE_PXE,
		Persistent: true,
	})

	require.NoError(t, err)
	assert.Equal(t, map[string]interface{}{
		"profile_id": "7",
		"device":     "BMC_BOOT_DEVICE_PXE",
		"persistent": true,
	}, args)
}

func TestBMCTools_RefuseAnArgumentOfAnotherType(t *testing.T) {
	build := mcpArgBuilders[platformv1.BMCService_SetBootDevice_FullMethodName]

	_, err := build("pxe")

	var unexpected ErrUnexpectedArgsType
	require.True(t, errors.As(err, &unexpected), "error = %v", err)
	assert.Equal(t, platformv1.BMCService_SetBootDevice_FullMethodName, unexpected.Method)
}

// A tool result decodes into the gRPC response, nested messages included.
func TestBMCTools_DecodeTheResult(t *testing.T) {
	decode := mcpReplyDecoders[platformv1.BMCService_ListUsers_FullMethodName]
	reply := &platformv1.BMCListUsersResponse{}

	err := decode(map[string]interface{}{"users": []interface{}{map[string]interface{}{
		"slot": 2, "username": "ops", "enabled": true, "privilege": "BMC_USER_PRIVILEGE_OPERATOR",
	}}}, reply)

	require.NoError(t, err)
	require.Len(t, reply.GetUsers(), 1)
	user := reply.GetUsers()[0]
	assert.Equal(t, uint32(2), user.GetSlot())
	assert.Equal(t, "ops", user.GetUsername())
	assert.True(t, user.GetEnabled())
	assert.Equal(t, platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_OPERATOR, user.GetPrivilege())
}

func TestBMCTools_RefuseAResultTheResponseCannotHold(t *testing.T) {
	decode := mcpReplyDecoders[platformv1.BMCService_CreateUser_FullMethodName]

	err := decode(map[string]interface{}{"slot": "many"}, &platformv1.BMCCreateUserResponse{})

	var unmarshal ErrUnmarshalFailed
	assert.True(t, errors.As(err, &unmarshal), "error = %v", err)
}
