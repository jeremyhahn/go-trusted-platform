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

// vTPM over REST.
//
// The daemon serves vTPM bundles under /api/v1/vtpm/bundles
// (pkg/webservice/v1/rest/vtpm/router.go), every route behind the admin gate.
// The bundle id is a path segment. ReadVTPMPCR names the PCR in ?pcr_index=,
// since a zero index cannot be a path segment; ExtendVTPMPCR carries it in the
// body. The runtime replies carry the pb field names and decode directly; the
// create, list and delete bodies are the daemon's domain JSON, translated by
// the wire codec in sdk/go/services/vtpm.

import (
	"net/http"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	vtpmsdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/vtpm"
)

func init() {
	const bundles = "/api/v1/vtpm/bundles"
	bundleID := []pathParam{{placeholder: "{id}", field: "bundle_id"}}

	routes := map[string]templatedRoute{
		platformv1.VTPMService_CreateBundle_FullMethodName: {
			path:   bundles,
			method: http.MethodPost,
		},
		platformv1.VTPMService_ListBundles_FullMethodName: {
			path:   bundles,
			method: http.MethodGet,
			queryParams: []queryParam{
				{name: "mode", field: "options.mode"},
				{name: "labels", field: "options.labels"},
				{name: "limit", field: "options.limit"},
				{name: "offset", field: "options.offset"},
				{name: "device_profile_id", field: "options.device_profile_id"},
			},
		},
		platformv1.VTPMService_DeleteBundle_FullMethodName: {
			path:       bundles + "/{id}",
			method:     http.MethodDelete,
			pathParams: []pathParam{{placeholder: "{id}", field: "id"}},
		},
		platformv1.VTPMService_StartVTPM_FullMethodName: {
			path:       bundles + "/{id}/start",
			method:     http.MethodPost,
			pathParams: bundleID,
		},
		platformv1.VTPMService_StopVTPM_FullMethodName: {
			path:       bundles + "/{id}/stop",
			method:     http.MethodPost,
			pathParams: bundleID,
		},
		platformv1.VTPMService_IsVTPMRunning_FullMethodName: {
			path:       bundles + "/{id}/state",
			method:     http.MethodGet,
			pathParams: bundleID,
		},
		platformv1.VTPMService_QuoteVTPM_FullMethodName: {
			path:       bundles + "/{id}/quote",
			method:     http.MethodPost,
			pathParams: bundleID,
		},
		platformv1.VTPMService_SealVTPM_FullMethodName: {
			path:       bundles + "/{id}/seal",
			method:     http.MethodPost,
			pathParams: bundleID,
		},
		platformv1.VTPMService_UnsealVTPM_FullMethodName: {
			path:       bundles + "/{id}/unseal",
			method:     http.MethodPost,
			pathParams: bundleID,
		},
		platformv1.VTPMService_ExtendVTPMPCR_FullMethodName: {
			path:       bundles + "/{id}/pcrs/extend",
			method:     http.MethodPost,
			pathParams: bundleID,
		},
		platformv1.VTPMService_ReadVTPMPCR_FullMethodName: {
			path:        bundles + "/{id}/pcrs",
			method:      http.MethodGet,
			pathParams:  bundleID,
			queryParams: []queryParam{{name: "pcr_index", field: "pcr_index"}},
		},
	}
	for method, route := range routes {
		templatedRouteTable[method] = route
	}

	restRequestEncoders[platformv1.VTPMService_CreateBundle_FullMethodName] =
		requestEncoder(platformv1.VTPMService_CreateBundle_FullMethodName, vtpmsdk.EncodeCreateBundleRequest)

	restResponseDecoders[platformv1.VTPMService_CreateBundle_FullMethodName] =
		wireDecoder(platformv1.VTPMService_CreateBundle_FullMethodName, vtpmsdk.DecodeCreateBundleJSON)
	restResponseDecoders[platformv1.VTPMService_ListBundles_FullMethodName] =
		wireDecoder(platformv1.VTPMService_ListBundles_FullMethodName, vtpmsdk.DecodeListBundlesJSON)
	restResponseDecoders[platformv1.VTPMService_DeleteBundle_FullMethodName] =
		wireDecoder(platformv1.VTPMService_DeleteBundle_FullMethodName, vtpmsdk.DecodeDeleteBundleJSON)
}
