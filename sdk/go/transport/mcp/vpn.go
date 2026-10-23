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

package mcp

import (
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// init maps the VPNService methods to the daemon's vpn_* tools
// (pkg/api/mcp/vpn_tools.go). The enrol and set tools take the peer and the
// policy fields flat, so those two requests need builders; every other
// request already has the tool's argument names.
func init() {
	for method, tool := range map[string]string{
		platformv1.VPNService_EnrolPeer_FullMethodName:           "vpn_peer_enrol",
		platformv1.VPNService_ListPeers_FullMethodName:           "vpn_peer_list",
		platformv1.VPNService_RevokePeer_FullMethodName:          "vpn_peer_revoke",
		platformv1.VPNService_GetStatus_FullMethodName:           "vpn_status",
		platformv1.VPNService_GetPosturePolicy_FullMethodName:    "vpn_posture_policy_get",
		platformv1.VPNService_SetPosturePolicy_FullMethodName:    "vpn_posture_policy_set",
		platformv1.VPNService_DeletePosturePolicy_FullMethodName: "vpn_posture_policy_delete",
		platformv1.VPNService_ListPosturePolicies_FullMethodName: "vpn_posture_policy_list",
	} {
		grpcMethodToMCPToolMap[method] = tool
	}
	mcpArgBuilders[platformv1.VPNService_EnrolPeer_FullMethodName] = buildVPNEnrolPeerArgs
	mcpArgBuilders[platformv1.VPNService_SetPosturePolicy_FullMethodName] = buildVPNSetPosturePolicyArgs
}

// buildVPNEnrolPeerArgs flattens the peer into the vpn_peer_enrol arguments.
func buildVPNEnrolPeerArgs(args interface{}) (map[string]interface{}, error) {
	in, ok := args.(*platformv1.EnrolVPNPeerRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.VPNService_EnrolPeer_FullMethodName}
	}
	peer := in.GetPeer()
	return map[string]interface{}{
		"tenant_id": peer.GetTenantId(),
		"device_id": peer.GetDeviceId(),
		"zones":     peer.GetZones(),
	}, nil
}

// buildVPNSetPosturePolicyArgs flattens the policy into the
// vpn_posture_policy_set arguments.
func buildVPNSetPosturePolicyArgs(args interface{}) (map[string]interface{}, error) {
	in, ok := args.(*platformv1.SetVPNPosturePolicyRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.VPNService_SetPosturePolicy_FullMethodName}
	}
	policy := in.GetPolicy()
	return map[string]interface{}{
		"tenant_id": policy.GetTenantId(),
		"name":      policy.GetName(),
		"module":    policy.GetModule(),
	}, nil
}
