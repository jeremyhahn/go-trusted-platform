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
)

// The SDN deletes, in the shape both the daemon and the webservice serve:
// DeleteVLAN names the VLAN in the path and its bridge in the query,
// DeletePolicy names the policy in the path. A zero vlan_id or an empty
// policy_id leaves the path field unset and is refused before the wire.
func init() {
	templatedRouteTable[platformv1.SDNService_DeleteVLAN_FullMethodName] = templatedRoute{
		path:        "/api/v1/sdn/vlans/{vlan_id}",
		method:      http.MethodDelete,
		pathParams:  []pathParam{{placeholder: "{vlan_id}", field: "vlan_id"}},
		queryParams: []queryParam{{name: "bridge_id", field: "bridge_id"}},
	}
	templatedRouteTable[platformv1.SDNService_DeletePolicy_FullMethodName] =
		itemRoute("/api/v1/sdn/policies/{id}", http.MethodDelete, "{id}", "policy_id")
}
