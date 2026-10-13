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
	"strings"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// SDN policy MCP mapping. The daemon's sdn_apply_policy, sdn_get_policy and
// sdn_list_policies tools speak the REST policy JSON (pkg/api/rest
// CreatePolicyRequest and PolicyResponse): rule matches are inlined and the
// enums travel as lowercase names, so the wire types below mirror that shape
// and convert to and from the pb messages.

const (
	policyTypePrefix       = "POLICY_TYPE_"
	policyStatusPrefix     = "POLICY_STATUS_"
	policyRuleActionPrefix = "POLICY_RULE_ACTION_"
	policyTargetTypePrefix = "POLICY_TARGET_TYPE_"
)

// policyRequestWire is the policy body sdn_apply_policy takes.
type policyRequestWire struct {
	ID          string              `json:"id,omitempty"`
	Name        string              `json:"name"`
	Description string              `json:"description,omitempty"`
	Type        string              `json:"type,omitempty"`
	Priority    int32               `json:"priority,omitempty"`
	Enabled     bool                `json:"enabled"`
	Rules       []policyRuleWire    `json:"rules,omitempty"`
	Targets     []policyTargetWire  `json:"targets,omitempty"`
	Schedule    *policyScheduleWire `json:"schedule,omitempty"`
}

// policyRuleWire is a pb PolicyRule with its match fields inlined.
type policyRuleWire struct {
	RuleID          string `json:"rule_id,omitempty"`
	Priority        int32  `json:"priority,omitempty"`
	SourceIP        string `json:"source_ip,omitempty"`
	DestinationIP   string `json:"destination_ip,omitempty"`
	SourcePort      uint32 `json:"source_port,omitempty"`
	DestinationPort uint32 `json:"destination_port,omitempty"`
	Protocol        string `json:"protocol,omitempty"`
	Direction       string `json:"direction,omitempty"`
	Interface       string `json:"interface,omitempty"`
	VLANID          uint32 `json:"vlan_id,omitempty"`
	DSCP            uint32 `json:"dscp,omitempty"`
	Application     string `json:"application,omitempty"`
	Action          string `json:"action,omitempty"`
	ActionValue     string `json:"action_value,omitempty"`
	Log             bool   `json:"log,omitempty"`
	Counter         bool   `json:"counter,omitempty"`
}

type policyTargetWire struct {
	Type      string `json:"type"`
	ID        string `json:"id"`
	Direction string `json:"direction,omitempty"`
	Zone      string `json:"zone,omitempty"`
}

type policyScheduleWire struct {
	StartTime string   `json:"start_time,omitempty"`
	EndTime   string   `json:"end_time,omitempty"`
	Days      []string `json:"days,omitempty"`
	Timezone  string   `json:"timezone,omitempty"`
	Enabled   bool     `json:"enabled"`
}

// policyResponseWire is the policy the sdn_*_policy tools answer with.
type policyResponseWire struct {
	policyRequestWire
	Status    string    `json:"status"`
	HitCount  uint64    `json:"hit_count"`
	ByteCount uint64    `json:"byte_count"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

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

	for method, decode := range map[string]mcpReplyDecoder{
		platformv1.SDNService_ApplyPolicy_FullMethodName:  decodeSDNApplyPolicyResult,
		platformv1.SDNService_GetPolicy_FullMethodName:    decodeSDNGetPolicyResult,
		platformv1.SDNService_ListPolicies_FullMethodName: decodeSDNListPoliciesResult,
	} {
		mcpReplyDecoders[method] = decode
	}
}

// enumName writes a pb enum value name the way the REST policy JSON does:
// without its prefix, lowercase, "-" for "_", and "" for UNSPECIFIED.
func enumName(name, prefix string) string {
	name = strings.TrimPrefix(name, prefix)
	if name == "UNSPECIFIED" {
		return ""
	}
	return strings.ToLower(strings.ReplaceAll(name, "_", "-"))
}

// enumValue is the inverse of enumName; "" is the unspecified value. A name
// the pb enum does not define is ErrUnknownEnumName.
func enumValue(values map[string]int32, prefix, field, name string) (int32, error) {
	if name == "" {
		return 0, nil
	}
	value, ok := values[prefix+strings.ToUpper(strings.ReplaceAll(name, "-", "_"))]
	if !ok {
		return 0, ErrUnknownEnumName{Field: field, Name: name}
	}
	return value, nil
}

func buildSDNApplyPolicyArgs(args interface{}) (map[string]interface{}, error) {
	in, ok := args.(*platformv1.ApplyPolicyRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.SDNService_ApplyPolicy_FullMethodName}
	}
	return structToMap(policyConfigToWire(in.GetPolicyId(), in.GetConfig()))
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

func policyConfigToWire(id string, config *platformv1.PolicyConfig) policyRequestWire {
	wire := policyRequestWire{
		ID:          id,
		Name:        config.GetName(),
		Description: config.GetDescription(),
		Type:        enumName(config.GetType().String(), policyTypePrefix),
		Priority:    config.GetPriority(),
		Enabled:     config.GetEnabled(),
	}
	for _, rule := range config.GetRules() {
		match := rule.GetMatch()
		wire.Rules = append(wire.Rules, policyRuleWire{
			RuleID:          rule.GetRuleId(),
			Priority:        rule.GetPriority(),
			SourceIP:        match.GetSourceIp(),
			DestinationIP:   match.GetDestinationIp(),
			SourcePort:      match.GetSourcePort(),
			DestinationPort: match.GetDestinationPort(),
			Protocol:        match.GetProtocol(),
			Direction:       match.GetDirection(),
			Interface:       match.GetInterface(),
			VLANID:          match.GetVlanId(),
			DSCP:            match.GetDscp(),
			Application:     match.GetApplication(),
			Action:          enumName(rule.GetAction().String(), policyRuleActionPrefix),
			ActionValue:     rule.GetActionValue(),
			Log:             rule.GetLog(),
			Counter:         rule.GetCounter(),
		})
	}
	for _, target := range config.GetTargets() {
		wire.Targets = append(wire.Targets, policyTargetWire{
			Type:      enumName(target.GetType().String(), policyTargetTypePrefix),
			ID:        target.GetId(),
			Direction: target.GetDirection(),
			Zone:      target.GetZone(),
		})
	}
	if schedule := config.GetSchedule(); schedule != nil {
		wire.Schedule = &policyScheduleWire{
			StartTime: schedule.GetStartTime(),
			EndTime:   schedule.GetEndTime(),
			Days:      schedule.GetDays(),
			Timezone:  schedule.GetTimezone(),
			Enabled:   schedule.GetEnabled(),
		}
	}
	return wire
}

// policyFromWire converts a policy the tools answer with to the pb Policy.
func policyFromWire(wire policyResponseWire) (*platformv1.Policy, error) {
	policyType, err := enumValue(platformv1.PolicyType_value, policyTypePrefix, "policy type", wire.Type)
	if err != nil {
		return nil, err
	}
	policyStatus, err := enumValue(platformv1.PolicyStatus_value, policyStatusPrefix, "policy status", wire.Status)
	if err != nil {
		return nil, err
	}
	config := &platformv1.PolicyConfig{
		Name:        wire.Name,
		Description: wire.Description,
		Type:        platformv1.PolicyType(policyType),
		Priority:    wire.Priority,
		Enabled:     wire.Enabled,
	}
	for _, rule := range wire.Rules {
		action, err := enumValue(platformv1.PolicyRuleAction_value, policyRuleActionPrefix, "rule action", rule.Action)
		if err != nil {
			return nil, err
		}
		config.Rules = append(config.Rules, &platformv1.PolicyRule{
			RuleId:   rule.RuleID,
			Priority: rule.Priority,
			Match: &platformv1.PolicyRuleMatch{
				SourceIp:        rule.SourceIP,
				DestinationIp:   rule.DestinationIP,
				SourcePort:      rule.SourcePort,
				DestinationPort: rule.DestinationPort,
				Protocol:        rule.Protocol,
				Direction:       rule.Direction,
				Interface:       rule.Interface,
				VlanId:          rule.VLANID,
				Dscp:            rule.DSCP,
				Application:     rule.Application,
			},
			Action:      platformv1.PolicyRuleAction(action),
			ActionValue: rule.ActionValue,
			Log:         rule.Log,
			Counter:     rule.Counter,
		})
	}
	for _, target := range wire.Targets {
		targetType, err := enumValue(platformv1.PolicyTargetType_value, policyTargetTypePrefix, "target type", target.Type)
		if err != nil {
			return nil, err
		}
		config.Targets = append(config.Targets, &platformv1.PolicyTarget{
			Type:      platformv1.PolicyTargetType(targetType),
			Id:        target.ID,
			Direction: target.Direction,
			Zone:      target.Zone,
		})
	}
	if schedule := wire.Schedule; schedule != nil {
		config.Schedule = &platformv1.PolicySchedule{
			StartTime: schedule.StartTime,
			EndTime:   schedule.EndTime,
			Days:      schedule.Days,
			Timezone:  schedule.Timezone,
			Enabled:   schedule.Enabled,
		}
	}
	return &platformv1.Policy{
		Id:        wire.ID,
		Config:    config,
		Status:    platformv1.PolicyStatus(policyStatus),
		HitCount:  wire.HitCount,
		ByteCount: wire.ByteCount,
		CreatedAt: timestampOrNil(wire.CreatedAt),
		UpdatedAt: timestampOrNil(wire.UpdatedAt),
	}, nil
}

// decodePolicyResult decodes the single policy a tool answers with.
func decodePolicyResult(result interface{}) (*platformv1.Policy, error) {
	var wire policyResponseWire
	if err := decodeToolResult(result, &wire); err != nil {
		return nil, err
	}
	return policyFromWire(wire)
}

func decodeSDNApplyPolicyResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.ApplyPolicyResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.SDNService_ApplyPolicy_FullMethodName}
	}
	policy, err := decodePolicyResult(result)
	if err != nil {
		return err
	}
	out.Policy = policy
	return nil
}

func decodeSDNGetPolicyResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.GetPolicyResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.SDNService_GetPolicy_FullMethodName}
	}
	policy, err := decodePolicyResult(result)
	if err != nil {
		return err
	}
	out.Policy = policy
	return nil
}

func decodeSDNListPoliciesResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.ListPoliciesResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.SDNService_ListPolicies_FullMethodName}
	}
	var wire struct {
		Policies []policyResponseWire `json:"policies"`
	}
	if err := decodeToolResult(result, &wire); err != nil {
		return err
	}
	policies := make([]*platformv1.Policy, 0, len(wire.Policies))
	for _, item := range wire.Policies {
		policy, err := policyFromWire(item)
		if err != nil {
			return err
		}
		policies = append(policies, policy)
	}
	out.Policies = policies
	return nil
}
