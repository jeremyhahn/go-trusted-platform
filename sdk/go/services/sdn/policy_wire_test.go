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

package sdn

import (
	"errors"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// daemonPolicyJSON is a policy as pkg/api/rest PolicyToResponse writes it.
const daemonPolicyJSON = `{
	"id": "p1", "name": "web", "type": "qos", "priority": 5, "enabled": true,
	"rules": [{"rule_id": "r1", "source_ip": "10.0.0.0/8", "destination_port": 443,
		"vlan_id": 20, "action": "rate-limit", "action_value": "1mbit"}],
	"targets": [{"type": "port", "id": "eth1", "zone": "dmz"}],
	"schedule": {"days": ["mon"], "enabled": true},
	"status": "active", "hit_count": 3, "byte_count": 9,
	"created_at": "2026-01-02T03:04:05Z", "updated_at": "0001-01-01T00:00:00Z"
}`

func TestEncodeApplyPolicyRequest_FlattensTheConfig(t *testing.T) {
	body, err := EncodeApplyPolicyRequest(&platformv1.ApplyPolicyRequest{
		PolicyId: "p1",
		Config: &platformv1.PolicyConfig{
			Name: "web", Type: platformv1.PolicyType_POLICY_TYPE_QOS, Priority: 5, Enabled: true,
			Rules: []*platformv1.PolicyRule{{
				RuleId: "r1",
				Match:  &platformv1.PolicyRuleMatch{SourceIp: "10.0.0.0/8", DestinationPort: 443, VlanId: 20},
				Action: platformv1.PolicyRuleAction_POLICY_RULE_ACTION_RATE_LIMIT, ActionValue: "1mbit",
			}},
			Targets:  []*platformv1.PolicyTarget{{Type: platformv1.PolicyTargetType_POLICY_TARGET_TYPE_PORT, Id: "eth1"}},
			Schedule: &platformv1.PolicySchedule{Days: []string{"mon"}, Enabled: true},
		},
	})
	if err != nil {
		t.Fatalf("EncodeApplyPolicyRequest: %v", err)
	}

	if body["id"] != "p1" || body["name"] != "web" || body["type"] != "qos" ||
		body["priority"] != float64(5) || body["enabled"] != true {
		t.Errorf("body = %+v", body)
	}
	if _, nested := body["config"]; nested {
		t.Error("the config must be flattened, not nested")
	}
	rule := body["rules"].([]interface{})[0].(map[string]interface{})
	if rule["source_ip"] != "10.0.0.0/8" || rule["destination_port"] != float64(443) ||
		rule["vlan_id"] != float64(20) || rule["action"] != "rate-limit" || rule["action_value"] != "1mbit" {
		t.Errorf("rule = %+v", rule)
	}
	if target := body["targets"].([]interface{})[0].(map[string]interface{}); target["type"] != "port" || target["id"] != "eth1" {
		t.Errorf("target = %+v", target)
	}
	if schedule := body["schedule"].(map[string]interface{}); schedule["enabled"] != true {
		t.Errorf("schedule = %+v", schedule)
	}
}

func TestEncodeApplyPolicyRequest_UnspecifiedEnumsAreOmitted(t *testing.T) {
	body, err := EncodeApplyPolicyRequest(&platformv1.ApplyPolicyRequest{Config: &platformv1.PolicyConfig{Name: "web"}})
	if err != nil {
		t.Fatalf("EncodeApplyPolicyRequest: %v", err)
	}
	if _, ok := body["type"]; ok {
		t.Errorf("an unspecified type must not be sent: %+v", body)
	}
	if _, ok := body["id"]; ok {
		t.Errorf("an empty policy id must not be sent: %+v", body)
	}
}

func TestDecodeApplyPolicyJSON(t *testing.T) {
	resp, err := DecodeApplyPolicyJSON([]byte(daemonPolicyJSON))
	if err != nil {
		t.Fatalf("DecodeApplyPolicyJSON: %v", err)
	}
	if !resp.GetStatus().GetSuccess() {
		t.Errorf("status = %+v", resp.GetStatus())
	}

	policy := resp.GetPolicy()
	config := policy.GetConfig()
	if policy.GetId() != "p1" || config.GetName() != "web" || config.GetType() != platformv1.PolicyType_POLICY_TYPE_QOS ||
		config.GetPriority() != 5 || policy.GetStatus() != platformv1.PolicyStatus_POLICY_STATUS_ACTIVE ||
		policy.GetHitCount() != 3 || policy.GetByteCount() != 9 {
		t.Errorf("policy = %+v", policy)
	}
	rule := config.GetRules()[0]
	if rule.GetMatch().GetVlanId() != 20 || rule.GetAction() != platformv1.PolicyRuleAction_POLICY_RULE_ACTION_RATE_LIMIT {
		t.Errorf("rule = %+v", rule)
	}
	if target := config.GetTargets()[0]; target.GetType() != platformv1.PolicyTargetType_POLICY_TARGET_TYPE_PORT || target.GetZone() != "dmz" {
		t.Errorf("target = %+v", target)
	}
	if policy.GetCreatedAt().AsTime().Year() != 2026 || policy.GetUpdatedAt() != nil {
		t.Errorf("timestamps = %v, %v", policy.GetCreatedAt(), policy.GetUpdatedAt())
	}
}

func TestDecodePolicyJSON_RefusesUnknownEnumNames(t *testing.T) {
	tests := []struct {
		kind string
		body string
	}{
		{"policy type", `{"type": "bogus"}`},
		{"policy status", `{"status": "bogus"}`},
		{"rule action", `{"rules": [{"action": "bogus"}]}`},
		{"target type", `{"targets": [{"type": "bogus", "id": "eth1"}]}`},
	}
	for _, tt := range tests {
		t.Run(tt.kind, func(t *testing.T) {
			_, err := DecodeGetPolicyJSON([]byte(tt.body))
			var unknown *ErrUnknownWireValue
			if !errors.As(err, &unknown) || unknown.Kind != tt.kind || unknown.Value != "bogus" {
				t.Fatalf("err = %v, want ErrUnknownWireValue for %s", err, tt.kind)
			}
		})
	}
}

func TestDecodePolicyJSON_RefusesMalformedJSON(t *testing.T) {
	decoders := map[string]func([]byte) error{
		"apply": func(data []byte) error { _, err := DecodeApplyPolicyJSON(data); return err },
		"get":   func(data []byte) error { _, err := DecodeGetPolicyJSON(data); return err },
		"list":  func(data []byte) error { _, err := DecodeListPoliciesJSON(data); return err },
	}
	for name, decode := range decoders {
		var decodeErr *ErrWireDecode
		if err := decode([]byte(`"not an object"`)); !errors.As(err, &decodeErr) {
			t.Errorf("%s: err = %v, want ErrWireDecode", name, err)
		}
	}
}

func TestDecodeListPoliciesJSON(t *testing.T) {
	resp, err := DecodeListPoliciesJSON([]byte(`{"policies": [` + daemonPolicyJSON + `], "count": 1}`))
	if err != nil {
		t.Fatalf("DecodeListPoliciesJSON: %v", err)
	}
	if len(resp.GetPolicies()) != 1 || resp.GetPolicies()[0].GetId() != "p1" {
		t.Errorf("policies = %+v", resp.GetPolicies())
	}

	if _, err := DecodeListPoliciesJSON([]byte(`{"policies": [{"type": "bogus"}]}`)); err == nil {
		t.Error("a policy with an unknown type was decoded")
	}
}

func TestPolicyEnumNames(t *testing.T) {
	if got := enumName("POLICY_RULE_ACTION_RATE_LIMIT", policyRuleActionPrefix); got != "rate-limit" {
		t.Errorf("enumName = %q", got)
	}
	if got := enumName("POLICY_TYPE_UNSPECIFIED", policyTypePrefix); got != "" {
		t.Errorf("enumName(UNSPECIFIED) = %q", got)
	}
	if got, err := enumValue(platformv1.PolicyRuleAction_value, policyRuleActionPrefix, "rule action", "rate-limit"); err != nil ||
		got != int32(platformv1.PolicyRuleAction_POLICY_RULE_ACTION_RATE_LIMIT) {
		t.Errorf("enumValue = %d, %v", got, err)
	}
	if got, err := enumValue(platformv1.PolicyType_value, policyTypePrefix, "policy type", ""); err != nil || got != 0 {
		t.Errorf("enumValue(\"\") = %d, %v", got, err)
	}
}
