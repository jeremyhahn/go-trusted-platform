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

// LUKS over REST.
//
// The daemon serves LUKS under /api/v1/luks (pkg/api/daemon/luks_rest.go).
// Status, ListSlots and Info are GETs that name the device in ?device=. The
// request bodies are the pb messages as encoding/json writes them, whose
// snake_case keys the daemon decodes. The status, slot, info and enroll
// replies are the daemon's domain JSON (Go-named keys, string keyslot types),
// decoded by the canonical wire decoders in sdk/go/services/luks; the
// removed / unlocked / changed replies match the pb shape and decode directly.

import (
	"net/http"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	lukssdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/luks"
)

func init() {
	device := []queryParam{{name: "device", field: "device"}}
	templatedRouteTable[platformv1.LUKSService_Status_FullMethodName] = templatedRoute{
		path:        "/api/v1/luks/status",
		method:      http.MethodGet,
		queryParams: device,
	}
	templatedRouteTable[platformv1.LUKSService_ListSlots_FullMethodName] = templatedRoute{
		path:        "/api/v1/luks/slots",
		method:      http.MethodGet,
		queryParams: device,
	}
	templatedRouteTable[platformv1.LUKSService_Info_FullMethodName] = templatedRoute{
		path:        "/api/v1/luks/info",
		method:      http.MethodGet,
		queryParams: device,
	}

	restResponseDecoders[platformv1.LUKSService_Status_FullMethodName] =
		wireDecoder(platformv1.LUKSService_Status_FullMethodName, lukssdk.DecodeStatusJSON)
	restResponseDecoders[platformv1.LUKSService_ListSlots_FullMethodName] =
		wireDecoder(platformv1.LUKSService_ListSlots_FullMethodName, lukssdk.DecodeListSlotsJSON)
	restResponseDecoders[platformv1.LUKSService_Info_FullMethodName] =
		wireDecoder(platformv1.LUKSService_Info_FullMethodName, lukssdk.DecodeInfoJSON)
	restResponseDecoders[platformv1.LUKSService_EnrollPassphrase_FullMethodName] =
		wireDecoder(platformv1.LUKSService_EnrollPassphrase_FullMethodName, lukssdk.DecodeEnrollPassphraseJSON)
	restResponseDecoders[platformv1.LUKSService_EnrollFIDO2_FullMethodName] =
		wireDecoder(platformv1.LUKSService_EnrollFIDO2_FullMethodName, lukssdk.DecodeEnrollFIDO2JSON)
	restResponseDecoders[platformv1.LUKSService_EnrollTPM_FullMethodName] =
		wireDecoder(platformv1.LUKSService_EnrollTPM_FullMethodName, lukssdk.DecodeEnrollTPMJSON)
	restResponseDecoders[platformv1.LUKSService_EnrollRecovery_FullMethodName] =
		wireDecoder(platformv1.LUKSService_EnrollRecovery_FullMethodName, lukssdk.DecodeEnrollRecoveryJSON)
}
