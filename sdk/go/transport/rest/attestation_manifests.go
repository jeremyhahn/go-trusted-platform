// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.
package rest

import (
	"net/http"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// Attestation manifest reads (#452, #1967). The webservice and the daemon
// both serve them under /api/v1/attestation/manifests, the id as a path
// segment, and answer the pb reply as protojson, which decodes generically.
// The server drops the ListManifests filters, so none are sent.
func init() {
	templatedRouteTable[platformv1.AttestationService_GetManifest_FullMethodName] =
		itemRoute("/api/v1/attestation/manifests/{id}", http.MethodGet, "{id}", "id")
	templatedRouteTable[platformv1.AttestationService_DeleteManifest_FullMethodName] =
		itemRoute("/api/v1/attestation/manifests/{id}", http.MethodDelete, "{id}", "id")

	grpcMethodToRESTMap[platformv1.AttestationService_ListManifests_FullMethodName] = struct {
		path   string
		method string
	}{"/api/v1/attestation/manifests", http.MethodGet}
}
