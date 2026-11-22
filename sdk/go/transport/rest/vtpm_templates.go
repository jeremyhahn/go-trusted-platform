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

// vTPM templates over REST.
//
// Both servers serve templates under /api/v1/vtpm/templates
// (pkg/webservice/v1/rest/vtpm/router.go, pkg/api/rest/vtpm_handlers.go). The
// template id is a path segment; clone takes options.template_id there and
// {hostname, labels} as the body. Every body and reply is the domain's JSON,
// translated by the wire codec in sdk/go/services/vtpm.

import (
	"net/http"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	vtpmsdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/vtpm"
)

func init() {
	const templates = "/api/v1/vtpm/templates"
	templateID := []pathParam{{placeholder: "{id}", field: "id"}}

	routes := map[string]templatedRoute{
		platformv1.VTPMService_CreateTemplate_FullMethodName: {
			path:   templates,
			method: http.MethodPost,
		},
		platformv1.VTPMService_ListTemplates_FullMethodName: {
			path:   templates,
			method: http.MethodGet,
		},
		platformv1.VTPMService_GetTemplate_FullMethodName: {
			path:       templates + "/{id}",
			method:     http.MethodGet,
			pathParams: templateID,
		},
		platformv1.VTPMService_DeleteTemplate_FullMethodName: {
			path:       templates + "/{id}",
			method:     http.MethodDelete,
			pathParams: templateID,
		},
		platformv1.VTPMService_CloneTemplate_FullMethodName: {
			path:       templates + "/{id}/clone",
			method:     http.MethodPost,
			pathParams: []pathParam{{placeholder: "{id}", field: "options.template_id"}},
		},
	}
	for method, route := range routes {
		templatedRouteTable[method] = route
	}

	restRequestEncoders[platformv1.VTPMService_CreateTemplate_FullMethodName] =
		requestEncoder(platformv1.VTPMService_CreateTemplate_FullMethodName, vtpmsdk.EncodeCreateTemplateRequest)
	restRequestEncoders[platformv1.VTPMService_CloneTemplate_FullMethodName] =
		requestEncoder(platformv1.VTPMService_CloneTemplate_FullMethodName, vtpmsdk.EncodeCloneTemplateRequest)

	restResponseDecoders[platformv1.VTPMService_CreateTemplate_FullMethodName] =
		wireDecoder(platformv1.VTPMService_CreateTemplate_FullMethodName, vtpmsdk.DecodeCreateTemplateJSON)
	restResponseDecoders[platformv1.VTPMService_GetTemplate_FullMethodName] =
		wireDecoder(platformv1.VTPMService_GetTemplate_FullMethodName, vtpmsdk.DecodeTemplateJSON)
	restResponseDecoders[platformv1.VTPMService_ListTemplates_FullMethodName] =
		wireDecoder(platformv1.VTPMService_ListTemplates_FullMethodName, vtpmsdk.DecodeListTemplatesJSON)
	restResponseDecoders[platformv1.VTPMService_DeleteTemplate_FullMethodName] =
		wireDecoder(platformv1.VTPMService_DeleteTemplate_FullMethodName, vtpmsdk.DecodeDeleteTemplateJSON)
	restResponseDecoders[platformv1.VTPMService_CloneTemplate_FullMethodName] =
		wireDecoder(platformv1.VTPMService_CloneTemplate_FullMethodName, vtpmsdk.DecodeCloneTemplateJSON)
}
