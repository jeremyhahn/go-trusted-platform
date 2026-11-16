package rest

import (
	"net/http"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// The SDN deletes, in the shape both the daemon and the webservice serve:
// DeleteVLAN carries vlan_id in the path and bridge_id in the query;
// DeletePolicy carries policy_id in the path. A zero vlan_id or an empty
// policy_id leaves the path field unset, so the call is refused before the
// wire. The bodies still go through sdnBodyEncoder (sdn.go).
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
