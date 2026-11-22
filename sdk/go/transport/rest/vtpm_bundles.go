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

import (
	"net/http"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	vtpmsdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/vtpm"
)

// init claims the vTPM bundle reads at the routes both the webservice
// (pkg/webservice/v1/rest/vtpm/router.go) and the daemon
// (pkg/api/rest/vtpm_handlers.go) serve, with the bundle id as {id}.
func init() {
	const bundle = "/api/v1/vtpm/bundles/{id}"
	id := []pathParam{{placeholder: "{id}", field: "id"}}

	routes := map[string]templatedRoute{
		platformv1.VTPMService_GetBundle_FullMethodName: {
			path: bundle, method: http.MethodGet, pathParams: id,
		},
		platformv1.VTPMService_ValidateBundle_FullMethodName: {
			path: bundle + "/validate", method: http.MethodPost, pathParams: id,
		},
		platformv1.VTPMService_GetBundlePath_FullMethodName: {
			path: bundle + "/path", method: http.MethodGet, pathParams: id,
		},
		platformv1.VTPMService_GetTPMSocketPath_FullMethodName: {
			path: bundle + "/tpm-socket", method: http.MethodGet, pathParams: id,
		},
		platformv1.VTPMService_GetNVRAMPath_FullMethodName: {
			path: bundle + "/nvram", method: http.MethodGet, pathParams: id,
		},
	}
	for method, route := range routes {
		templatedRouteTable[method] = route
	}

	restResponseDecoders[platformv1.VTPMService_GetBundle_FullMethodName] =
		wireDecoder(platformv1.VTPMService_GetBundle_FullMethodName, vtpmsdk.DecodeGetBundleJSON)
	restResponseDecoders[platformv1.VTPMService_ValidateBundle_FullMethodName] =
		wireDecoder(platformv1.VTPMService_ValidateBundle_FullMethodName, vtpmsdk.DecodeValidateBundleJSON)
}
