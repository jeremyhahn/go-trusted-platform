// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-only

package rest

import (
	"net/http"
	"testing"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var testPolicyTime = time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)

// fullPolicyBody sets every field of a REST policy body to a distinct value.
const fullPolicyBody = `{
	"id": "policy-1",
	"name": "web",
	"description": "web tier",
	"type": "firewall",
	"priority": 200,
	"enabled": true,
	"rules": [{
		"rule_id": "r1", "priority": 10,
		"source_ip": "10.0.0.0/24", "destination_ip": "10.0.1.5",
		"source_port": 1024, "destination_port": 443,
		"protocol": "tcp", "direction": "ingress", "interface": "eth0",
		"vlan_id": 100, "dscp": 46, "application": "https",
		"action": "rate-limit", "action_value": "10mbps", "log": true, "counter": true
	}],
	"targets": [{"type": "bridge", "id": "br0", "direction": "both", "zone": "tenant"}],
	"schedule": {"start_time": "08:00", "end_time": "18:00", "days": ["mon"], "timezone": "UTC", "enabled": true}
}`

// testPolicy is fullPolicyBody as the SDN service holds it.
func testPolicy() *platformv1.Policy {
	return &platformv1.Policy{
		Id:     "policy-1",
		Config: testPolicyConfig(),
		Status: platformv1.PolicyStatus_POLICY_STATUS_ACTIVE,

		HitCount:  3,
		ByteCount: 4,
		CreatedAt: timestamppb.New(testPolicyTime),
		UpdatedAt: timestamppb.New(testPolicyTime.Add(time.Minute)),
	}
}

func testPolicyConfig() *platformv1.PolicyConfig {
	return &platformv1.PolicyConfig{
		Name:        "web",
		Description: "web tier",
		Type:        platformv1.PolicyType_POLICY_TYPE_FIREWALL,
		Priority:    200,
		Enabled:     true,
		Rules: []*platformv1.PolicyRule{{
			RuleId:   "r1",
			Priority: 10,
			Match: &platformv1.PolicyRuleMatch{
				SourceIp: "10.0.0.0/24", DestinationIp: "10.0.1.5",
				SourcePort: 1024, DestinationPort: 443,
				Protocol: "tcp", Direction: "ingress", Interface: "eth0",
				VlanId: 100, Dscp: 46, Application: "https",
			},
			Action:      platformv1.PolicyRuleAction_POLICY_RULE_ACTION_RATE_LIMIT,
			ActionValue: "10mbps",
			Log:         true,
			Counter:     true,
		}},
		Targets: []*platformv1.PolicyTarget{{
			Type: platformv1.PolicyTargetType_POLICY_TARGET_TYPE_BRIDGE, Id: "br0", Direction: "both", Zone: "tenant",
		}},
		Schedule: &platformv1.PolicySchedule{
			StartTime: "08:00", EndTime: "18:00", Days: []string{"mon"}, Timezone: "UTC", Enabled: true,
		},
	}
}

// testPolicyResponse is testPolicy in its REST form.
func testPolicyResponse() PolicyResponse {
	return PolicyResponse{
		ID:          "policy-1",
		Name:        "web",
		Description: "web tier",
		Type:        "firewall",
		Priority:    200,
		Enabled:     true,
		Status:      "active",
		Rules: []PolicyRule{{
			RuleID: "r1", Priority: 10,
			SourceIP: "10.0.0.0/24", DestinationIP: "10.0.1.5",
			SourcePort: 1024, DestinationPort: 443,
			Protocol: "tcp", Direction: "ingress", Interface: "eth0",
			VLANID: 100, DSCP: 46, Application: "https",
			Action: "rate-limit", ActionValue: "10mbps", Log: true, Counter: true,
		}},
		Targets: []PolicyTarget{{Type: "bridge", ID: "br0", Direction: "both", Zone: "tenant"}},
		Schedule: &PolicySchedule{
			StartTime: "08:00", EndTime: "18:00", Days: []string{"mon"}, Timezone: "UTC", Enabled: true,
		},
		HitCount:  3,
		ByteCount: 4,
		CreatedAt: testPolicyTime,
		UpdatedAt: testPolicyTime.Add(time.Minute),
	}
}

func TestCreatePolicy(t *testing.T) {
	t.Run("applies the policy through the shared service", func(t *testing.T) {
		control := &mockSDNControlService{policy: testPolicy()}

		w := serveSDN(controlRouter(control), http.MethodPost, "/api/v1/sdn/policies", []byte(fullPolicyBody))

		require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
		want := &platformv1.ApplyPolicyRequest{PolicyId: "policy-1", Config: testPolicyConfig()}
		assert.True(t, proto.Equal(want, control.applyPolicyReq), "got %v", control.applyPolicyReq)

		var resp PolicyResponse
		decodeSDNResponse(t, w.Body, &resp)
		assert.Equal(t, testPolicyResponse(), resp)
	})

	t.Run("rejects a malformed body without calling the service", func(t *testing.T) {
		control := &mockSDNControlService{}

		w := serveSDN(controlRouter(control), http.MethodPost, "/api/v1/sdn/policies", []byte("bad"))

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Nil(t, control.applyPolicyReq)
	})

	invalidBodies := []struct {
		name  string
		body  string
		field string
	}{
		{"type", `{"name":"p","type":"bogus"}`, "type"},
		{"rule action", `{"name":"p","rules":[{"action":"permit"}]}`, "rule action"},
		{"target type", `{"name":"p","targets":[{"type":"zone","id":"z"}]}`, "target type"},
	}
	for _, tc := range invalidBodies {
		t.Run("rejects an unknown "+tc.name+" without calling the service", func(t *testing.T) {
			control := &mockSDNControlService{}

			w := serveSDN(controlRouter(control), http.MethodPost, "/api/v1/sdn/policies", []byte(tc.body))

			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.Contains(t, w.Body.String(), tc.field)
			assert.Nil(t, control.applyPolicyReq)
		})
	}

	for _, tc := range serviceErrorCases {
		t.Run("maps "+tc.name, func(t *testing.T) {
			control := &mockSDNControlService{err: tc.err}

			w := serveSDN(controlRouter(control), http.MethodPost, "/api/v1/sdn/policies", []byte(`{"name":"p"}`))

			assert.Equal(t, tc.want, w.Code)
		})
	}

	t.Run("answers 503 without the shared service", func(t *testing.T) {
		w := serveSDN(controlRouter(nil), http.MethodPost, "/api/v1/sdn/policies", []byte(`{"name":"p"}`))

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestListPolicies(t *testing.T) {
	t.Run("lists the service's policies with the query filters", func(t *testing.T) {
		control := &mockSDNControlService{
			listPoliciesResp: &platformv1.ListPoliciesResponse{Policies: []*platformv1.Policy{testPolicy()}},
		}

		w := serveSDN(controlRouter(control), http.MethodGet, "/api/v1/sdn/policies?type=firewall&target_id=br0", nil)

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		require.NotNil(t, control.listPoliciesReq)
		assert.Equal(t, "firewall", control.listPoliciesReq.GetType())
		assert.Equal(t, "br0", control.listPoliciesReq.GetTargetId())

		var resp SDNPolicyListResponse
		decodeSDNResponse(t, w.Body, &resp)
		assert.Equal(t, 1, resp.Count)
		assert.Equal(t, []PolicyResponse{testPolicyResponse()}, resp.Policies)
	})

	t.Run("answers an empty list when the service holds none", func(t *testing.T) {
		control := &mockSDNControlService{listPoliciesResp: &platformv1.ListPoliciesResponse{}}

		w := serveSDN(controlRouter(control), http.MethodGet, "/api/v1/sdn/policies", nil)

		require.Equal(t, http.StatusOK, w.Code)
		var resp SDNPolicyListResponse
		decodeSDNResponse(t, w.Body, &resp)
		assert.NotNil(t, resp.Policies, "an empty list is [], not null")
		assert.Empty(t, resp.Policies)
		assert.Zero(t, resp.Count)
	})

	for _, tc := range serviceErrorCases {
		t.Run("maps "+tc.name, func(t *testing.T) {
			control := &mockSDNControlService{err: tc.err}

			w := serveSDN(controlRouter(control), http.MethodGet, "/api/v1/sdn/policies", nil)

			assert.Equal(t, tc.want, w.Code)
		})
	}

	t.Run("answers 503 without the shared service", func(t *testing.T) {
		w := serveSDN(controlRouter(nil), http.MethodGet, "/api/v1/sdn/policies", nil)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestGetPolicy(t *testing.T) {
	t.Run("gets the policy from the shared service", func(t *testing.T) {
		control := &mockSDNControlService{policy: testPolicy()}

		w := serveSDN(controlRouter(control), http.MethodGet, "/api/v1/sdn/policies/web", nil)

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		require.NotNil(t, control.getPolicyReq)
		assert.Equal(t, "web", control.getPolicyReq.GetPolicyId())

		var resp PolicyResponse
		decodeSDNResponse(t, w.Body, &resp)
		assert.Equal(t, testPolicyResponse(), resp)
	})

	for _, tc := range serviceErrorCases {
		t.Run("maps "+tc.name, func(t *testing.T) {
			control := &mockSDNControlService{err: tc.err}

			w := serveSDN(controlRouter(control), http.MethodGet, "/api/v1/sdn/policies/web", nil)

			assert.Equal(t, tc.want, w.Code)
		})
	}

	t.Run("answers 503 without the shared service", func(t *testing.T) {
		w := serveSDN(controlRouter(nil), http.MethodGet, "/api/v1/sdn/policies/web", nil)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestDeletePolicy(t *testing.T) {
	t.Run("deletes the policy through the shared service", func(t *testing.T) {
		control := &mockSDNControlService{}

		w := serveSDN(controlRouter(control), http.MethodDelete, "/api/v1/sdn/policies/policy-1", nil)

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		require.NotNil(t, control.deletePolicyReq)
		assert.Equal(t, "policy-1", control.deletePolicyReq.GetPolicyId())

		var resp SDNActionResponse
		decodeSDNResponse(t, w.Body, &resp)
		assert.Equal(t, SDNActionResponse{
			ResourceID:   "policy-1",
			ResourceType: "policy",
			Action:       "delete",
			Success:      true,
			Message:      "policy deleted successfully",
		}, resp)
	})

	for _, tc := range serviceErrorCases {
		t.Run("maps "+tc.name, func(t *testing.T) {
			control := &mockSDNControlService{err: tc.err}

			w := serveSDN(controlRouter(control), http.MethodDelete, "/api/v1/sdn/policies/policy-1", nil)

			assert.Equal(t, tc.want, w.Code)
		})
	}

	t.Run("answers 503 without the shared service", func(t *testing.T) {
		w := serveSDN(controlRouter(nil), http.MethodDelete, "/api/v1/sdn/policies/policy-1", nil)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestProtoEnumValue(t *testing.T) {
	values := platformv1.PolicyRuleAction_value

	t.Run("resolves lower-case dashed names", func(t *testing.T) {
		for name, want := range map[string]platformv1.PolicyRuleAction{
			"":           platformv1.PolicyRuleAction_POLICY_RULE_ACTION_UNSPECIFIED,
			"allow":      platformv1.PolicyRuleAction_POLICY_RULE_ACTION_ALLOW,
			"DENY":       platformv1.PolicyRuleAction_POLICY_RULE_ACTION_DENY,
			"rate-limit": platformv1.PolicyRuleAction_POLICY_RULE_ACTION_RATE_LIMIT,
		} {
			got, err := protoEnumValue(values, policyRuleActionPrefix, "rule action", name)
			require.NoError(t, err, name)
			assert.Equal(t, int32(want), got, name)
		}
	})

	t.Run("rejects a name the proto does not define", func(t *testing.T) {
		_, err := protoEnumValue(values, policyRuleActionPrefix, "rule action", "permit")

		assert.Equal(t, ErrInvalidPolicyField{Field: "rule action", Value: "permit"}, err)
	})
}

func TestProtoEnumName(t *testing.T) {
	assert.Equal(t, "rate-limit", protoEnumName(platformv1.PolicyRuleAction_POLICY_RULE_ACTION_RATE_LIMIT.String(), policyRuleActionPrefix))
	assert.Equal(t, "firewall", protoEnumName(platformv1.PolicyType_POLICY_TYPE_FIREWALL.String(), policyTypePrefix))
	assert.Empty(t, protoEnumName(platformv1.PolicyStatus_POLICY_STATUS_UNSPECIFIED.String(), policyStatusPrefix))
}

func TestPolicyToResponse(t *testing.T) {
	t.Run("converts every field", func(t *testing.T) {
		assert.Equal(t, testPolicyResponse(), PolicyToResponse(testPolicy()))
	})

	t.Run("tolerates an empty policy", func(t *testing.T) {
		resp := PolicyToResponse(&platformv1.Policy{Id: "p"})

		assert.Equal(t, "p", resp.ID)
		assert.Empty(t, resp.Type)
		assert.Empty(t, resp.Status)
		assert.NotNil(t, resp.Rules)
		assert.NotNil(t, resp.Targets)
		assert.Nil(t, resp.Schedule)
		assert.True(t, resp.CreatedAt.IsZero())
	})
}

func TestErrInvalidPolicyField(t *testing.T) {
	assert.Equal(t, `invalid policy rule action "permit"`, ErrInvalidPolicyField{Field: "rule action", Value: "permit"}.Error())
	assert.Equal(t, `invalid policy type ""`, ErrInvalidPolicyField{Field: "type"}.Error())
}
