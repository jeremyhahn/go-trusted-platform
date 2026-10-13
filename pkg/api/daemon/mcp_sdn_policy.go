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

package daemon

import (
	"context"
	"encoding/json"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// The MCP policy tools call the shared SDNService that gRPC, REST, QUIC and
// the Unix socket use, and speak the REST policy document, so a policy created
// on any transport is the same policy on every other one.

// applySDNPolicy applies a policy given as the REST create-policy JSON body and
// returns the stored policy in the REST response shape.
func applySDNPolicy(ctx context.Context, svc *SDNService, body json.RawMessage) (interface{}, error) {
	if svc == nil {
		return nil, ErrServiceNotAvailable{Service: "sdn"}
	}
	var req rest.CreatePolicyRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, ErrSDNInvalidPolicy{Reason: err.Error()}
	}
	applyReq, err := rest.PolicyRequestToProto(req)
	if err != nil {
		return nil, ErrSDNInvalidPolicy{Reason: err.Error()}
	}
	resp, err := svc.ApplyPolicy(ctx, applyReq)
	if err != nil {
		return nil, err
	}
	return rest.PolicyToResponse(resp.GetPolicy()), nil
}

// getSDNPolicy returns the policy with the given ID or name in the REST
// response shape.
func getSDNPolicy(ctx context.Context, svc *SDNService, policyID string) (interface{}, error) {
	if svc == nil {
		return nil, ErrServiceNotAvailable{Service: "sdn"}
	}
	resp, err := svc.GetPolicy(ctx, &platformv1.GetPolicyRequest{PolicyId: policyID})
	if err != nil {
		return nil, namePolicyNotFound(policyID, err)
	}
	return rest.PolicyToResponse(resp.GetPolicy()), nil
}

// listSDNPolicies returns the policies matching the optional type and target
// filters in the REST response shape.
func listSDNPolicies(ctx context.Context, svc *SDNService, policyType, targetID string) ([]interface{}, error) {
	if svc == nil {
		return nil, ErrServiceNotAvailable{Service: "sdn"}
	}
	resp, err := svc.ListPolicies(ctx, &platformv1.ListPoliciesRequest{Type: policyType, TargetId: targetID})
	if err != nil {
		return nil, err
	}
	policies := make([]interface{}, 0, len(resp.GetPolicies()))
	for _, policy := range resp.GetPolicies() {
		policies = append(policies, rest.PolicyToResponse(policy))
	}
	return policies, nil
}

// deleteSDNPolicy deletes the policy with the given ID or name.
func deleteSDNPolicy(ctx context.Context, svc *SDNService, policyID string) error {
	if svc == nil {
		return ErrServiceNotAvailable{Service: "sdn"}
	}
	_, err := svc.DeletePolicy(ctx, &platformv1.DeletePolicyRequest{PolicyId: policyID})
	return namePolicyNotFound(policyID, err)
}

// namePolicyNotFound turns the SDNService's NotFound into ErrSDNPolicyNotFound
// naming the requested policy, and returns any other error unchanged.
func namePolicyNotFound(policyID string, err error) error {
	if err != nil && status.Code(err) == codes.NotFound {
		return ErrSDNPolicyNotFound{PolicyID: policyID}
	}
	return err
}
