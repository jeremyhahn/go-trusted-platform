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

// Device argument mapping for the MCP transport.
//
// The device_get and device_delete tools (pkg/api/mcp/tools.go) take the
// device as "device_id", a decimal string, while the pb requests carry a
// uint64 "id". The generic JSON round-trip would send {"id": N}, which the
// tools ignore, so these methods build their arguments explicitly.

import (
	"strconv"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func init() {
	mcpArgBuilders[platformv1.DeviceService_GetDevice_FullMethodName] = buildDeviceGetArgs
	mcpArgBuilders[platformv1.DeviceService_DeleteDevice_FullMethodName] = buildDeviceDeleteArgs
}

// buildDeviceGetArgs builds the device_get tool arguments.
func buildDeviceGetArgs(args interface{}) (map[string]interface{}, error) {
	req, ok := args.(*platformv1.GetDeviceRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.DeviceService_GetDevice_FullMethodName}
	}
	return deviceIDArgs(req.GetId()), nil
}

// buildDeviceDeleteArgs builds the device_delete tool arguments.
func buildDeviceDeleteArgs(args interface{}) (map[string]interface{}, error) {
	req, ok := args.(*platformv1.DeleteDeviceRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.DeviceService_DeleteDevice_FullMethodName}
	}
	return deviceIDArgs(req.GetId()), nil
}

// deviceIDArgs sends the device ID as a decimal string, the repo-wide
// uint64-on-the-wire convention.
func deviceIDArgs(id uint64) map[string]interface{} {
	return map[string]interface{}{"device_id": strconv.FormatUint(id, 10)}
}
