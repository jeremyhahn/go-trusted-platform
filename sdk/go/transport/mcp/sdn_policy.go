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
	sdnsdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/sdn"
)

// SDN policy MCP mapping. The daemon's sdn_apply_policy, sdn_get_policy and
// sdn_list_policies tools speak the REST policy JSON (pkg/api/rest
// CreatePolicyRequest and PolicyResponse), translated by the policy wire
// codec in sdk/go/services/sdn that the REST transport shares.

func init() {
	for method, tool := range map[string]string{
		platformv1.SDNService_ApplyPolicy_FullMethodName:  "sdn_apply_policy",
		platformv1.SDNService_GetPolicy_FullMethodName:    "sdn_get_policy",
		platformv1.SDNService_ListPolicies_FullMethodName: "sdn_list_policies",
	} {
		grpcMethodToMCPToolMap[method] = tool
	}

	mcpArgBuilders[platformv1.SDNService_ApplyPolicy_FullMethodName] = buildSDNApplyPolicyArgs
	mcpArgBuilders[platformv1.SDNService_ListPolicies_FullMethodName] = buildSDNListPoliciesArgs

	mcpReplyDecoders[platformv1.SDNService_ApplyPolicy_FullMethodName] =
		wireDecoder(platformv1.SDNService_ApplyPolicy_FullMethodName, sdnsdk.DecodeApplyPolicyJSON)
	mcpReplyDecoders[platformv1.SDNService_GetPolicy_FullMethodName] =
		wireDecoder(platformv1.SDNService_GetPolicy_FullMethodName, sdnsdk.DecodeGetPolicyJSON)
	mcpReplyDecoders[platformv1.SDNService_ListPolicies_FullMethodName] =
		wireDecoder(platformv1.SDNService_ListPolicies_FullMethodName, sdnsdk.DecodeListPoliciesJSON)
}

func buildSDNApplyPolicyArgs(args interface{}) (map[string]interface{}, error) {
	in, ok := args.(*platformv1.ApplyPolicyRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.SDNService_ApplyPolicy_FullMethodName}
	}
	return sdnsdk.EncodeApplyPolicyRequest(in)
}

func buildSDNListPoliciesArgs(args interface{}) (map[string]interface{}, error) {
	const method = platformv1.SDNService_ListPolicies_FullMethodName
	in, ok := args.(*platformv1.ListPoliciesRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: method}
	}
	if err := refuseUncarried(method, "", in, "type", "target_id"); err != nil {
		return nil, err
	}
	return map[string]interface{}{"type": in.GetType(), "target_id": in.GetTargetId()}, nil
}
