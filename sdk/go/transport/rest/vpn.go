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

// vpnBasePath is the daemon REST root of the VPN control plane
// (pkg/api/rest/vpn_handlers.go).
const vpnBasePath = "/api/v1/vpn"

// init registers the VPNService routes. Item routes carry the device or
// policy name in the path and the tenant in the query; list and status
// routes carry their optional filter in the query.
func init() {
	tenantQuery := []queryParam{{name: "tenant_id", field: "tenant_id"}}

	templatedRouteTable[platformv1.VPNService_EnrolPeer_FullMethodName] = templatedRoute{
		path:   vpnBasePath + "/peers",
		method: http.MethodPost,
	}
	templatedRouteTable[platformv1.VPNService_ListPeers_FullMethodName] = templatedRoute{
		path:        vpnBasePath + "/peers",
		method:      http.MethodGet,
		queryParams: tenantQuery,
	}
	templatedRouteTable[platformv1.VPNService_RevokePeer_FullMethodName] = templatedRoute{
		path:        vpnBasePath + "/peers/{device}",
		method:      http.MethodDelete,
		pathParams:  []pathParam{{placeholder: "{device}", field: "device_id"}},
		queryParams: tenantQuery,
	}
	templatedRouteTable[platformv1.VPNService_GetStatus_FullMethodName] = templatedRoute{
		path:        vpnBasePath + "/status",
		method:      http.MethodGet,
		queryParams: []queryParam{{name: "gateway_id", field: "gateway_id"}},
	}
	templatedRouteTable[platformv1.VPNService_ListPosturePolicies_FullMethodName] = templatedRoute{
		path:        vpnBasePath + "/posture-policies",
		method:      http.MethodGet,
		queryParams: tenantQuery,
	}
	templatedRouteTable[platformv1.VPNService_GetPosturePolicy_FullMethodName] = templatedRoute{
		path:        vpnBasePath + "/posture-policies/{name}",
		method:      http.MethodGet,
		pathParams:  []pathParam{{placeholder: "{name}", field: "name"}},
		queryParams: tenantQuery,
	}
	templatedRouteTable[platformv1.VPNService_SetPosturePolicy_FullMethodName] = templatedRoute{
		path:       vpnBasePath + "/posture-policies/{name}",
		method:     http.MethodPut,
		pathParams: []pathParam{{placeholder: "{name}", field: "policy.name"}},
	}
	templatedRouteTable[platformv1.VPNService_DeletePosturePolicy_FullMethodName] = templatedRoute{
		path:        vpnBasePath + "/posture-policies/{name}",
		method:      http.MethodDelete,
		pathParams:  []pathParam{{placeholder: "{name}", field: "name"}},
		queryParams: tenantQuery,
	}

	// The enrol and set bodies are the peer and the policy themselves, not
	// the request messages that wrap them.
	restRequestEncoders[platformv1.VPNService_EnrolPeer_FullMethodName] = encodeEnrolVPNPeer
	restRequestEncoders[platformv1.VPNService_SetPosturePolicy_FullMethodName] = encodeSetVPNPosturePolicy
}

// encodeEnrolVPNPeer sends the peer as the enrol body.
func encodeEnrolVPNPeer(body interface{}) (interface{}, error) {
	in, ok := body.(*platformv1.EnrolVPNPeerRequest)
	if !ok {
		return nil, ErrUnexpectedRequestType{Method: platformv1.VPNService_EnrolPeer_FullMethodName}
	}
	if in.GetPeer() == nil {
		return &platformv1.VPNPeer{}, nil
	}
	return in.GetPeer(), nil
}

// encodeSetVPNPosturePolicy sends the policy as the set body; its name
// travels in the path.
func encodeSetVPNPosturePolicy(body interface{}) (interface{}, error) {
	in, ok := body.(*platformv1.SetVPNPosturePolicyRequest)
	if !ok {
		return nil, ErrUnexpectedRequestType{Method: platformv1.VPNService_SetPosturePolicy_FullMethodName}
	}
	return in.GetPolicy(), nil
}
