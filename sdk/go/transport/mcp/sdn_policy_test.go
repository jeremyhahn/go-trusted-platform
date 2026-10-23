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
	"errors"
	"testing"

	"google.golang.org/grpc/codes"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdnsdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/sdn"
)

// policyResult is a policy as sdn_get_policy answers with it.
func policyResult() map[string]interface{} {
	return map[string]interface{}{
		"id":      "p1",
		"name":    "web",
		"type":    "acl",
		"enabled": true,
		"status":  "active",
		"rules": []interface{}{map[string]interface{}{
			"rule_id": "r1", "source_ip": "10.0.0.0/8", "destination_port": 443,
			"action": "rate-limit", "action_value": "1mbit",
		}},
		"targets":    []interface{}{map[string]interface{}{"type": "port", "id": "eth1"}},
		"schedule":   map[string]interface{}{"days": []interface{}{"mon"}, "enabled": true},
		"hit_count":  3,
		"created_at": "2026-01-02T03:04:05Z",
		"updated_at": "0001-01-01T00:00:00Z",
	}
}

func requirePolicy(t *testing.T, policy *platformv1.Policy) {
	t.Helper()
	config := policy.GetConfig()
	rule := config.GetRules()[0]
	if policy.GetId() != "p1" || config.GetName() != "web" ||
		config.GetType() != platformv1.PolicyType_POLICY_TYPE_ACL || !config.GetEnabled() ||
		policy.GetStatus() != platformv1.PolicyStatus_POLICY_STATUS_ACTIVE || policy.GetHitCount() != 3 {
		t.Errorf("policy = %+v", policy)
	}
	if rule.GetRuleId() != "r1" || rule.GetMatch().GetSourceIp() != "10.0.0.0/8" ||
		rule.GetMatch().GetDestinationPort() != 443 ||
		rule.GetAction() != platformv1.PolicyRuleAction_POLICY_RULE_ACTION_RATE_LIMIT || rule.GetActionValue() != "1mbit" {
		t.Errorf("rule = %+v", rule)
	}
	if target := config.GetTargets()[0]; target.GetType() != platformv1.PolicyTargetType_POLICY_TARGET_TYPE_PORT || target.GetId() != "eth1" {
		t.Errorf("target = %+v", target)
	}
	if schedule := config.GetSchedule(); schedule.GetDays()[0] != "mon" || !schedule.GetEnabled() {
		t.Errorf("schedule = %+v", schedule)
	}
	if policy.GetCreatedAt().AsTime().Year() != 2026 || policy.GetUpdatedAt() != nil {
		t.Errorf("timestamps = %v, %v", policy.GetCreatedAt(), policy.GetUpdatedAt())
	}
}

func TestSDNMCP_ApplyPolicy_RoundTrip(t *testing.T) {
	reply := &platformv1.ApplyPolicyResponse{}
	calls, err := invokePhase35(t, map[string]interface{}{"sdn_apply_policy": policyResult()},
		platformv1.SDNService_ApplyPolicy_FullMethodName, &platformv1.ApplyPolicyRequest{
			PolicyId: "p1",
			Config: &platformv1.PolicyConfig{
				Name: "web", Type: platformv1.PolicyType_POLICY_TYPE_ACL, Enabled: true,
				Rules: []*platformv1.PolicyRule{{
					RuleId: "r1",
					Match:  &platformv1.PolicyRuleMatch{SourceIp: "10.0.0.0/8", DestinationPort: 443},
					Action: platformv1.PolicyRuleAction_POLICY_RULE_ACTION_RATE_LIMIT, ActionValue: "1mbit",
				}},
				Targets:  []*platformv1.PolicyTarget{{Type: platformv1.PolicyTargetType_POLICY_TARGET_TYPE_PORT, Id: "eth1"}},
				Schedule: &platformv1.PolicySchedule{Days: []string{"mon"}, Enabled: true},
			},
		}, reply)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	args := calls[0].Arguments
	if args["id"] != "p1" || args["name"] != "web" || args["type"] != "acl" || args["enabled"] != true {
		t.Errorf("policy args = %+v", args)
	}
	rule := args["rules"].([]interface{})[0].(map[string]interface{})
	if rule["source_ip"] != "10.0.0.0/8" || rule["destination_port"] != float64(443) || rule["action"] != "rate-limit" {
		t.Errorf("rule args = %+v", rule)
	}
	if target := args["targets"].([]interface{})[0].(map[string]interface{}); target["type"] != "port" || target["id"] != "eth1" {
		t.Errorf("target args = %+v", target)
	}
	if schedule := args["schedule"].(map[string]interface{}); schedule["enabled"] != true {
		t.Errorf("schedule args = %+v", schedule)
	}
	requirePolicy(t, reply.GetPolicy())
}

func TestSDNMCP_GetPolicy_RoundTrip(t *testing.T) {
	reply := &platformv1.GetPolicyResponse{}
	calls, err := invokePhase35(t, map[string]interface{}{"sdn_get_policy": policyResult()},
		platformv1.SDNService_GetPolicy_FullMethodName, &platformv1.GetPolicyRequest{PolicyId: "p1"}, reply)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if calls[0].Arguments["policy_id"] != "p1" {
		t.Errorf("call = %+v", calls[0])
	}
	requirePolicy(t, reply.GetPolicy())
}

func TestSDNMCP_ListPolicies_RoundTrip(t *testing.T) {
	reply := &platformv1.ListPoliciesResponse{}
	_, err := invokePhase35(t, map[string]interface{}{
		"sdn_list_policies": map[string]interface{}{"policies": []interface{}{policyResult()}},
	}, platformv1.SDNService_ListPolicies_FullMethodName, &platformv1.ListPoliciesRequest{}, reply)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if len(reply.GetPolicies()) != 1 {
		t.Fatalf("policies = %+v", reply.GetPolicies())
	}
	requirePolicy(t, reply.GetPolicies()[0])
}

// TestSDNMCP_PolicyResult_UnknownEnumName checks a policy naming an enum
// value the pb does not define fails Internal instead of decoding as
// unspecified.
func TestSDNMCP_PolicyResult_UnknownEnumName(t *testing.T) {
	tests := []struct {
		field  string
		mutate func(map[string]interface{})
	}{
		{"policy type", func(p map[string]interface{}) { p["type"] = "bogus" }},
		{"policy status", func(p map[string]interface{}) { p["status"] = "bogus" }},
		{"rule action", func(p map[string]interface{}) {
			p["rules"] = []interface{}{map[string]interface{}{"action": "bogus"}}
		}},
		{"target type", func(p map[string]interface{}) {
			p["targets"] = []interface{}{map[string]interface{}{"type": "bogus"}}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			result := policyResult()
			tt.mutate(result)

			err := mcpReplyDecoders[platformv1.SDNService_GetPolicy_FullMethodName](result, &platformv1.GetPolicyResponse{})
			var unknown *sdnsdk.ErrUnknownWireValue
			if !errors.As(err, &unknown) || unknown.Kind != tt.field || unknown.Value != "bogus" {
				t.Fatalf("err = %v, want ErrUnknownWireValue for %s", err, tt.field)
			}

			_, err = invokePhase35(t, map[string]interface{}{"sdn_get_policy": result},
				platformv1.SDNService_GetPolicy_FullMethodName, &platformv1.GetPolicyRequest{PolicyId: "p1"},
				&platformv1.GetPolicyResponse{})
			requireCode(t, err, codes.Internal)
		})
	}
}

func TestSDNMCP_PolicyDecoders_RejectMalformedResult(t *testing.T) {
	for method, reply := range map[string]interface{}{
		platformv1.SDNService_ApplyPolicy_FullMethodName:  &platformv1.ApplyPolicyResponse{},
		platformv1.SDNService_GetPolicy_FullMethodName:    &platformv1.GetPolicyResponse{},
		platformv1.SDNService_ListPolicies_FullMethodName: &platformv1.ListPoliciesResponse{},
	} {
		if err := mcpReplyDecoders[method]("not an object", reply); err == nil {
			t.Errorf("%s decoded a string result", method)
		}
	}

	bad := map[string]interface{}{"policies": []interface{}{map[string]interface{}{"type": "bogus"}}}
	if err := mcpReplyDecoders[platformv1.SDNService_ListPolicies_FullMethodName](bad, &platformv1.ListPoliciesResponse{}); err == nil {
		t.Error("ListPolicies decoded a policy with an unknown type")
	}
}
