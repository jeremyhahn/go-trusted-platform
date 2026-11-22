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

// The webservice and the daemon serve VM and container attestation
// collection at POST /api/v1/attestation/{vm,container}/{id}; the handler
// takes the subject id from the path, and the rest of the request (the VM
// quote config and nonce) travels in the body. The protojson reply decodes
// generically.
func init() {
	templatedRouteTable[platformv1.AttestationService_CollectVMAttestation_FullMethodName] =
		itemRoute("/api/v1/attestation/vm/{id}", http.MethodPost, "{id}", "vm_id")
	templatedRouteTable[platformv1.AttestationService_CollectContainerAttestation_FullMethodName] =
		itemRoute("/api/v1/attestation/container/{id}", http.MethodPost, "{id}", "container_id")
}
