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

package rest

// Provisioning Gateway over REST.
//
// The daemon serves the gateway's device reports under
// /api/v1/provisioning/devices/{mac} (pkg/webservice/v1/rest/pxe/gateway.go).
// Every RPC names a device by MAC, so the MAC is the path segment and the
// rest of the request (port_id, state, status, ...) stays in the body.
// GetBootConfig has no server route yet (docs/provisioning/api.md §4).

import (
	"net/http"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// provisioningDevicesPath is the collection every gateway device report
// names its device under.
const provisioningDevicesPath = "/api/v1/provisioning/devices"

func init() {
	mac := []pathParam{{placeholder: "{mac}", field: "mac_address"}}
	templatedRouteTable[platformv1.ProvisioningGateway_RegisterPXEDevice_FullMethodName] = templatedRoute{
		path:       provisioningDevicesPath + "/{mac}/register",
		method:     http.MethodPost,
		pathParams: mac,
	}
	templatedRouteTable[platformv1.ProvisioningGateway_GetBootConfig_FullMethodName] = templatedRoute{
		path:       provisioningDevicesPath + "/{mac}/boot-config",
		method:     http.MethodGet,
		pathParams: mac,
	}
	templatedRouteTable[platformv1.ProvisioningGateway_ReportDeviceState_FullMethodName] = templatedRoute{
		path:       provisioningDevicesPath + "/{mac}/state",
		method:     http.MethodPost,
		pathParams: mac,
	}
	templatedRouteTable[platformv1.ProvisioningGateway_NotifyInstallComplete_FullMethodName] = templatedRoute{
		path:       provisioningDevicesPath + "/{mac}/install-complete",
		method:     http.MethodPost,
		pathParams: mac,
	}

	// encoding/json would send the timestamp as {seconds, nanos}; the server
	// decodes with protojson, which takes an RFC 3339 string.
	restRequestEncoders[platformv1.ProvisioningGateway_NotifyInstallComplete_FullMethodName] = requestEncoder(
		platformv1.ProvisioningGateway_NotifyInstallComplete_FullMethodName,
		func(r *platformv1.NotifyInstallCompleteRequest) (map[string]interface{}, error) {
			body := map[string]interface{}{"status": r.GetStatus()}
			if r.GetTimestamp() != nil {
				body["timestamp"] = r.GetTimestamp().AsTime().Format(time.RFC3339Nano)
			}
			return body, nil
		})
}
