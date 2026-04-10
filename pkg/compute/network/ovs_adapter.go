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

package network

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
)

// OVSFlowControllerAdapter adapts the SDN policy OVSFlowController to the
// compute/network FlowController interface.
type OVSFlowControllerAdapter struct {
	controller *policy.OVSFlowController
	ruleIndex  sync.Map // map[ruleID]matchString for deletion
	logger     *slog.Logger
}

// OVSFlowControllerAdapterOption configures the adapter.
type OVSFlowControllerAdapterOption func(*OVSFlowControllerAdapter)

// WithOVSAdapterLogger sets the logger for the adapter.
func WithOVSAdapterLogger(logger *slog.Logger) OVSFlowControllerAdapterOption {
	return func(a *OVSFlowControllerAdapter) {
		a.logger = logger
	}
}

// NewOVSFlowControllerAdapter creates a new adapter wrapping the OVS flow controller.
func NewOVSFlowControllerAdapter(
	controller *policy.OVSFlowController,
	opts ...OVSFlowControllerAdapterOption,
) (*OVSFlowControllerAdapter, error) {
	if controller == nil {
		return nil, ErrInvalidConfig{Field: "controller", Reason: "OVS controller cannot be nil"}
	}

	a := &OVSFlowControllerAdapter{
		controller: controller,
	}

	for _, opt := range opts {
		opt(a)
	}

	if a.logger == nil {
		a.logger = slog.Default()
	}

	return a, nil
}

// AddFlow adds a flow rule to the switch.
func (a *OVSFlowControllerAdapter) AddFlow(ctx context.Context, bridge string, rule *FlowRule) error {
	select {
	case <-ctx.Done():
		return ErrContextCanceled{Operation: "AddFlow"}
	default:
	}

	if rule == nil {
		return ErrInvalidConfig{Field: "rule", Reason: "rule cannot be nil"}
	}

	if rule.ID == "" {
		return ErrInvalidConfig{Field: "ID", Reason: "rule ID cannot be empty"}
	}

	// Convert FlowRule to OVS match/actions strings
	matchStr := a.buildMatchString(rule)
	actionsStr := a.buildActionsString(rule)

	// Install the flow
	if err := a.controller.InstallFlow(bridge, int(rule.Priority), matchStr, actionsStr); err != nil {
		return ErrFlowRule{
			PortID:    rule.PortID,
			RuleID:    rule.ID,
			Operation: "AddFlow",
			Reason:    "failed to install flow",
			Cause:     err,
		}
	}

	// Track rule ID to match string for later deletion
	a.ruleIndex.Store(rule.ID, matchStr)

	a.logger.Debug("added flow rule",
		"rule_id", rule.ID,
		"port_id", rule.PortID,
		"bridge", bridge,
		"match", matchStr,
		"actions", actionsStr,
	)

	return nil
}

// DeleteFlow removes a flow rule from the switch.
func (a *OVSFlowControllerAdapter) DeleteFlow(ctx context.Context, bridge string, ruleID string) error {
	select {
	case <-ctx.Done():
		return ErrContextCanceled{Operation: "DeleteFlow"}
	default:
	}

	if ruleID == "" {
		return ErrInvalidConfig{Field: "ruleID", Reason: "rule ID cannot be empty"}
	}

	// Look up the match string for this rule
	matchVal, ok := a.ruleIndex.Load(ruleID)
	if !ok {
		// Rule not found in index, nothing to delete
		return nil
	}

	matchStr := matchVal.(string)

	// Delete the flow
	if err := a.controller.DeleteFlow(bridge, matchStr); err != nil {
		return ErrFlowRule{
			RuleID:    ruleID,
			Operation: "DeleteFlow",
			Reason:    "failed to delete flow",
			Cause:     err,
		}
	}

	// Remove from index
	a.ruleIndex.Delete(ruleID)

	a.logger.Debug("deleted flow rule",
		"rule_id", ruleID,
		"bridge", bridge,
	)

	return nil
}

// ModifyFlow modifies an existing flow rule.
func (a *OVSFlowControllerAdapter) ModifyFlow(ctx context.Context, bridge string, rule *FlowRule) error {
	select {
	case <-ctx.Done():
		return ErrContextCanceled{Operation: "ModifyFlow"}
	default:
	}

	if rule == nil {
		return ErrInvalidConfig{Field: "rule", Reason: "rule cannot be nil"}
	}

	// OVS doesn't have native modify - delete and re-add
	if err := a.DeleteFlow(ctx, bridge, rule.ID); err != nil {
		// Ignore "not found" errors during modify
		a.logger.Debug("delete during modify failed (may not exist)",
			"rule_id", rule.ID,
			"error", err,
		)
	}

	return a.AddFlow(ctx, bridge, rule)
}

// GetFlows returns all flows for a bridge.
func (a *OVSFlowControllerAdapter) GetFlows(ctx context.Context, bridge string) ([]*FlowRule, error) {
	select {
	case <-ctx.Done():
		return nil, ErrContextCanceled{Operation: "GetFlows"}
	default:
	}

	flowStrings, err := a.controller.ListFlows(bridge)
	if err != nil {
		return nil, ErrFlowRule{
			Operation: "GetFlows",
			Reason:    "failed to list flows",
			Cause:     err,
		}
	}

	// Parse flow strings back to FlowRule (best effort)
	rules := make([]*FlowRule, 0, len(flowStrings))
	for _, flowStr := range flowStrings {
		rule := a.parseFlowString(flowStr)
		if rule != nil {
			rules = append(rules, rule)
		}
	}

	return rules, nil
}

// SetPortVLAN sets the VLAN tag for a port.
func (a *OVSFlowControllerAdapter) SetPortVLAN(ctx context.Context, bridge string, portID string, vlan uint16) error {
	select {
	case <-ctx.Done():
		return ErrContextCanceled{Operation: "SetPortVLAN"}
	default:
	}

	if portID == "" {
		return ErrInvalidConfig{Field: "portID", Reason: "port ID cannot be empty"}
	}

	if err := a.controller.SetPortVLAN(ctx, portID, int64(vlan)); err != nil {
		return ErrVLANFailed{
			PortID: portID,
			ToVLAN: vlan,
			Reason: "failed to set port VLAN",
			Cause:  err,
		}
	}

	a.logger.Debug("set port VLAN",
		"port_id", portID,
		"vlan", vlan,
	)

	return nil
}

// buildMatchString converts a FlowMatch to an OVS match string.
func (a *OVSFlowControllerAdapter) buildMatchString(rule *FlowRule) string {
	if rule.Match == nil {
		return ""
	}

	var parts []string

	if rule.Match.InPort > 0 {
		parts = append(parts, fmt.Sprintf("in_port=%d", rule.Match.InPort))
	}

	if rule.Match.EthSrc != "" {
		parts = append(parts, fmt.Sprintf("dl_src=%s", rule.Match.EthSrc))
	}

	if rule.Match.EthDst != "" {
		parts = append(parts, fmt.Sprintf("dl_dst=%s", rule.Match.EthDst))
	}

	if rule.Match.EthType > 0 {
		parts = append(parts, fmt.Sprintf("dl_type=0x%04x", rule.Match.EthType))
	}

	if rule.Match.VLANID > 0 {
		parts = append(parts, fmt.Sprintf("dl_vlan=%d", rule.Match.VLANID))
	}

	if rule.Match.IPSrc != "" {
		parts = append(parts, fmt.Sprintf("nw_src=%s", rule.Match.IPSrc))
	}

	if rule.Match.IPDst != "" {
		parts = append(parts, fmt.Sprintf("nw_dst=%s", rule.Match.IPDst))
	}

	if rule.Match.IPProto > 0 {
		parts = append(parts, fmt.Sprintf("nw_proto=%d", rule.Match.IPProto))
	}

	if rule.Match.SrcPort > 0 {
		parts = append(parts, fmt.Sprintf("tp_src=%d", rule.Match.SrcPort))
	}

	if rule.Match.DstPort > 0 {
		parts = append(parts, fmt.Sprintf("tp_dst=%d", rule.Match.DstPort))
	}

	return strings.Join(parts, ",")
}

// buildActionsString converts FlowActions to an OVS actions string.
func (a *OVSFlowControllerAdapter) buildActionsString(rule *FlowRule) string {
	if len(rule.Actions) == 0 {
		return "drop"
	}

	var parts []string

	for _, action := range rule.Actions {
		switch action.Type {
		case FlowActionTypeOutput:
			if action.Port > 0 {
				parts = append(parts, fmt.Sprintf("output:%d", action.Port))
			} else {
				parts = append(parts, "normal")
			}
		case FlowActionTypeDrop:
			parts = append(parts, "drop")
		case FlowActionTypeSetVLAN:
			parts = append(parts, fmt.Sprintf("mod_vlan_vid:%d", action.VLAN))
		case FlowActionTypeStripVLAN:
			parts = append(parts, "strip_vlan")
		case FlowActionTypeSetField:
			parts = append(parts, fmt.Sprintf("set_field:%s->%s", action.Value, action.Field))
		case FlowActionTypeController:
			parts = append(parts, "controller")
		case FlowActionTypeFlood:
			parts = append(parts, "flood")
		}
	}

	if len(parts) == 0 {
		return "normal"
	}

	return strings.Join(parts, ",")
}

// parseFlowString parses an OVS flow string back to a FlowRule (best effort).
func (a *OVSFlowControllerAdapter) parseFlowString(flowStr string) *FlowRule {
	rule := &FlowRule{
		Match:    &FlowMatch{},
		Metadata: make(map[string]string),
	}

	parts := strings.Split(flowStr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}

		key := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])

		switch key {
		case "priority":
			if p, err := strconv.ParseUint(value, 10, 16); err == nil {
				rule.Priority = uint16(p)
			}
		case "in_port":
			if p, err := strconv.ParseUint(value, 10, 32); err == nil {
				rule.Match.InPort = uint32(p)
			}
		case "dl_vlan":
			if v, err := strconv.ParseUint(value, 10, 16); err == nil {
				rule.Match.VLANID = uint16(v)
				rule.VLAN = uint16(v)
			}
		case "dl_src":
			rule.Match.EthSrc = value
		case "dl_dst":
			rule.Match.EthDst = value
		case "nw_src":
			rule.Match.IPSrc = value
		case "nw_dst":
			rule.Match.IPDst = value
		case "nw_proto":
			if p, err := strconv.ParseUint(value, 10, 8); err == nil {
				rule.Match.IPProto = uint8(p)
			}
		case "tp_src":
			if p, err := strconv.ParseUint(value, 10, 16); err == nil {
				rule.Match.SrcPort = uint16(p)
			}
		case "tp_dst":
			if p, err := strconv.ParseUint(value, 10, 16); err == nil {
				rule.Match.DstPort = uint16(p)
			}
		}
	}

	return rule
}

// Ensure OVSFlowControllerAdapter implements FlowController
var _ FlowController = (*OVSFlowControllerAdapter)(nil)
