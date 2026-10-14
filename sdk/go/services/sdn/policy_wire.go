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

// Policy wire codec. The daemon's REST policy routes and its sdn_*_policy MCP
// tools speak the same policy JSON (pkg/api/rest CreatePolicyRequest and
// PolicyResponse): rule matches are inlined and the enums travel as
// lowercase names. The REST and MCP transports both translate through the
// functions below, so the two cannot drift apart.

import (
	"encoding/json"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

const (
	policyTypePrefix       = "POLICY_TYPE_"
	policyStatusPrefix     = "POLICY_STATUS_"
	policyRuleActionPrefix = "POLICY_RULE_ACTION_"
	policyTargetTypePrefix = "POLICY_TARGET_TYPE_"
)

// policyRequestWire is the policy body ApplyPolicy sends.
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

// policyResponseWire is the policy the daemon answers with.
type policyResponseWire struct {
	policyRequestWire
	Status    string    `json:"status"`
	HitCount  uint64    `json:"hit_count"`
	ByteCount uint64    `json:"byte_count"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// EncodeApplyPolicyRequest flattens an ApplyPolicyRequest into the daemon's
// policy body: policy_id becomes id and the config fields sit at the top.
func EncodeApplyPolicyRequest(req *platformv1.ApplyPolicyRequest) (map[string]interface{}, error) {
	data, err := json.Marshal(policyConfigToWire(req.GetPolicyId(), req.GetConfig()))
	if err != nil {
		return nil, &ErrWireEncode{Message: "apply policy", Err: err}
	}
	var body map[string]interface{}
	if err := json.Unmarshal(data, &body); err != nil {
		return nil, &ErrWireEncode{Message: "apply policy", Err: err}
	}
	return body, nil
}

// DecodeApplyPolicyJSON decodes the policy the daemon answers an apply with.
func DecodeApplyPolicyJSON(data []byte) (*platformv1.ApplyPolicyResponse, error) {
	policy, err := decodePolicyJSON(data, "apply policy")
	if err != nil {
		return nil, err
	}
	return &platformv1.ApplyPolicyResponse{
		Status: &platformv1.Status{Success: true, Message: "policy applied successfully"},
		Policy: policy,
	}, nil
}

// DecodeGetPolicyJSON decodes the policy the daemon answers a get with.
func DecodeGetPolicyJSON(data []byte) (*platformv1.GetPolicyResponse, error) {
	policy, err := decodePolicyJSON(data, "get policy")
	if err != nil {
		return nil, err
	}
	return &platformv1.GetPolicyResponse{Policy: policy}, nil
}

// DecodeListPoliciesJSON decodes the {"policies": [...]} list the daemon
// answers with.
func DecodeListPoliciesJSON(data []byte) (*platformv1.ListPoliciesResponse, error) {
	var wire struct {
		Policies []policyResponseWire `json:"policies"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, &ErrWireDecode{Message: "list policies", Err: err}
	}
	policies := make([]*platformv1.Policy, 0, len(wire.Policies))
	for _, item := range wire.Policies {
		policy, err := policyFromWire(item)
		if err != nil {
			return nil, err
		}
		policies = append(policies, policy)
	}
	return &platformv1.ListPoliciesResponse{Policies: policies}, nil
}

func decodePolicyJSON(data []byte, message string) (*platformv1.Policy, error) {
	var wire policyResponseWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, &ErrWireDecode{Message: message, Err: err}
	}
	return policyFromWire(wire)
}

// enumName writes a pb enum value name the way the policy JSON does:
// without its prefix, lowercase, "-" for "_", and "" for UNSPECIFIED.
func enumName(name, prefix string) string {
	name = strings.TrimPrefix(name, prefix)
	if name == "UNSPECIFIED" {
		return ""
	}
	return strings.ToLower(strings.ReplaceAll(name, "_", "-"))
}

// enumValue is the inverse of enumName; "" is the unspecified value. A name
// the pb enum does not define is ErrUnknownWireValue.
func enumValue(values map[string]int32, prefix, kind, name string) (int32, error) {
	if name == "" {
		return 0, nil
	}
	value, ok := values[prefix+strings.ToUpper(strings.ReplaceAll(name, "-", "_"))]
	if !ok {
		return 0, &ErrUnknownWireValue{Kind: kind, Value: name}
	}
	return value, nil
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

// policyFromWire converts a policy the daemon answers with to the pb Policy.
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

// timestampOrNil leaves a zero time unset rather than sending the epoch
// of year one.
func timestampOrNil(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}
