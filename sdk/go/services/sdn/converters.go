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
	"strings"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// String-to-domain enum maps (for CLI input parsing)

// StringToBridgeType maps user-facing bridge type strings to domain BridgeType.
var StringToBridgeType = map[string]BridgeType{
	"ovs":   BridgeTypeOVS,
	"linux": BridgeTypeLinux,
	"vxlan": BridgeTypeVXLAN,
}

// StringToPortType maps user-facing port type strings to domain PortType.
var StringToPortType = map[string]PortType{
	"internal": PortTypeInternal,
	"physical": PortTypePhysical,
	"tap":      PortTypeTap,
	"veth":     PortTypeVeth,
	"vxlan":    PortTypeVXLAN,
	"gre":      PortTypeGRE,
}

// StringToFlowActionType maps user-facing action type strings to domain FlowActionType.
var StringToFlowActionType = map[string]FlowActionType{
	"output":     FlowActionOutput,
	"drop":       FlowActionDrop,
	"set_vlan":   FlowActionSetVLAN,
	"strip_vlan": FlowActionStripVLAN,
	"set_field":  FlowActionSetField,
	"goto_table": FlowActionGotoTable,
	"controller": FlowActionController,
	"normal":     FlowActionOutput,
	"flood":      FlowActionOutput,
}

// StringToPolicyType maps user-facing policy type strings to domain PolicyType.
var StringToPolicyType = map[string]PolicyType{
	"acl":      PolicyTypeACL,
	"qos":      PolicyTypeQoS,
	"nat":      PolicyTypeNAT,
	"firewall": PolicyTypeFirewall,
	"routing":  PolicyTypeRouting,
}

// IntToFlowTable maps table number to domain FlowTable.
var IntToFlowTable = map[int]FlowTable{
	0:   FlowTable0,
	1:   FlowTable1,
	2:   FlowTable2,
	3:   FlowTable3,
	255: FlowTableDrop,
}

// ParseBridgeType parses a user-facing bridge type string to a domain BridgeType.
func ParseBridgeType(s string) (BridgeType, bool) {
	bt, ok := StringToBridgeType[strings.ToLower(strings.TrimSpace(s))]
	return bt, ok
}

// ParsePortType parses a user-facing port type string to a domain PortType.
func ParsePortType(s string) (PortType, bool) {
	pt, ok := StringToPortType[strings.ToLower(strings.TrimSpace(s))]
	return pt, ok
}

// ParseFlowActionType parses a user-facing action type string to a domain FlowActionType.
func ParseFlowActionType(s string) (FlowActionType, bool) {
	at, ok := StringToFlowActionType[strings.ToLower(strings.TrimSpace(s))]
	return at, ok
}

// ParsePolicyType parses a user-facing policy type string to a domain PolicyType.
func ParsePolicyType(s string) (PolicyType, bool) {
	pt, ok := StringToPolicyType[strings.ToLower(strings.TrimSpace(s))]
	return pt, ok
}

// ParseFlowTable parses a table number to a domain FlowTable.
func ParseFlowTable(table int) FlowTable {
	ft, ok := IntToFlowTable[table]
	if !ok {
		return FlowTableUnspecified
	}
	return ft
}

// Domain-to-proto enum maps

// bridgeTypeToProto maps domain BridgeType to proto BridgeType.
var bridgeTypeToProto = map[BridgeType]platformv1.BridgeType{
	BridgeTypeUnspecified: platformv1.BridgeType_BRIDGE_TYPE_UNSPECIFIED,
	BridgeTypeOVS:         platformv1.BridgeType_BRIDGE_TYPE_OVS,
	BridgeTypeLinux:       platformv1.BridgeType_BRIDGE_TYPE_LINUX,
	BridgeTypeVXLAN:       platformv1.BridgeType_BRIDGE_TYPE_VXLAN,
}

// portTypeToProto maps domain PortType to proto PortType.
var portTypeToProto = map[PortType]platformv1.PortType{
	PortTypeUnspecified: platformv1.PortType_PORT_TYPE_UNSPECIFIED,
	PortTypeInternal:    platformv1.PortType_PORT_TYPE_INTERNAL,
	PortTypePhysical:    platformv1.PortType_PORT_TYPE_PHYSICAL,
	PortTypeTap:         platformv1.PortType_PORT_TYPE_TAP,
	PortTypeVeth:        platformv1.PortType_PORT_TYPE_VETH,
	PortTypeVXLAN:       platformv1.PortType_PORT_TYPE_VXLAN,
	PortTypeGRE:         platformv1.PortType_PORT_TYPE_GRE,
}

// flowActionTypeToProto maps domain FlowActionType to proto FlowActionType.
var flowActionTypeToProto = map[FlowActionType]platformv1.FlowActionType{
	FlowActionUnspecified: platformv1.FlowActionType_FLOW_ACTION_UNSPECIFIED,
	FlowActionOutput:      platformv1.FlowActionType_FLOW_ACTION_OUTPUT,
	FlowActionDrop:        platformv1.FlowActionType_FLOW_ACTION_DROP,
	FlowActionSetVLAN:     platformv1.FlowActionType_FLOW_ACTION_SET_VLAN,
	FlowActionStripVLAN:   platformv1.FlowActionType_FLOW_ACTION_STRIP_VLAN,
	FlowActionSetField:    platformv1.FlowActionType_FLOW_ACTION_SET_FIELD,
	FlowActionGotoTable:   platformv1.FlowActionType_FLOW_ACTION_GOTO_TABLE,
	FlowActionController:  platformv1.FlowActionType_FLOW_ACTION_CONTROLLER,
}

// flowTableToProto maps domain FlowTable to proto FlowTable.
var flowTableToProto = map[FlowTable]platformv1.FlowTable{
	FlowTableUnspecified: platformv1.FlowTable_FLOW_TABLE_UNSPECIFIED,
	FlowTable0:           platformv1.FlowTable_FLOW_TABLE_0,
	FlowTable1:           platformv1.FlowTable_FLOW_TABLE_1,
	FlowTable2:           platformv1.FlowTable_FLOW_TABLE_2,
	FlowTable3:           platformv1.FlowTable_FLOW_TABLE_3,
	FlowTableDrop:        platformv1.FlowTable_FLOW_TABLE_DROP,
}

// policyTypeToProto maps domain PolicyType to proto PolicyType.
var policyTypeToProto = map[PolicyType]platformv1.PolicyType{
	PolicyTypeUnspecified: platformv1.PolicyType_POLICY_TYPE_UNSPECIFIED,
	PolicyTypeACL:         platformv1.PolicyType_POLICY_TYPE_ACL,
	PolicyTypeQoS:         platformv1.PolicyType_POLICY_TYPE_QOS,
	PolicyTypeNAT:         platformv1.PolicyType_POLICY_TYPE_NAT,
	PolicyTypeFirewall:    platformv1.PolicyType_POLICY_TYPE_FIREWALL,
	PolicyTypeRouting:     platformv1.PolicyType_POLICY_TYPE_ROUTING,
}

// policyTargetTypeToProto maps domain PolicyTargetType to proto PolicyTargetType.
var policyTargetTypeToProto = map[PolicyTargetType]platformv1.PolicyTargetType{
	PolicyTargetTypeUnspecified: platformv1.PolicyTargetType_POLICY_TARGET_TYPE_UNSPECIFIED,
	PolicyTargetTypeBridge:      platformv1.PolicyTargetType_POLICY_TARGET_TYPE_BRIDGE,
	PolicyTargetTypePort:        platformv1.PolicyTargetType_POLICY_TARGET_TYPE_PORT,
}

// Domain-to-proto converters

// BridgeConfigToProto converts a domain BridgeConfig to a proto BridgeConfig.
func BridgeConfigToProto(cfg *BridgeConfig) *platformv1.BridgeConfig {
	if cfg == nil {
		return nil
	}
	bt, ok := bridgeTypeToProto[cfg.Type]
	if !ok {
		bt = platformv1.BridgeType_BRIDGE_TYPE_UNSPECIFIED
	}
	return &platformv1.BridgeConfig{
		Name:       cfg.Name,
		Type:       bt,
		DatapathId: cfg.DatapathID,
		StpEnabled: cfg.STPEnabled,
		Mtu:        cfg.MTU,
		Options:    cfg.Options,
		Labels:     cfg.Labels,
	}
}

// PortConfigToProto converts a domain PortConfig to a proto PortConfig.
func PortConfigToProto(cfg *PortConfig) *platformv1.PortConfig {
	if cfg == nil {
		return nil
	}
	pt, ok := portTypeToProto[cfg.Type]
	if !ok {
		pt = platformv1.PortType_PORT_TYPE_UNSPECIFIED
	}
	return &platformv1.PortConfig{
		Name:       cfg.Name,
		Type:       pt,
		Vlan:       cfg.VLAN,
		MacAddress: cfg.MACAddress,
		Mtu:        cfg.MTU,
		Options:    cfg.Options,
		Labels:     cfg.Labels,
	}
}

// FlowMatchToProto converts a domain FlowMatch to a proto FlowMatch.
func FlowMatchToProto(m *FlowMatch) *platformv1.FlowMatch {
	if m == nil {
		return nil
	}
	return &platformv1.FlowMatch{
		InPort:  m.InPort,
		EthSrc:  m.EthSrc,
		EthDst:  m.EthDst,
		EthType: m.EthType,
		IpSrc:   m.IPSrc,
		IpDst:   m.IPDst,
	}
}

// FlowActionToProto converts a domain FlowAction to a proto FlowAction.
func FlowActionToProto(a *FlowAction) *platformv1.FlowAction {
	if a == nil {
		return nil
	}
	at, ok := flowActionTypeToProto[a.Type]
	if !ok {
		at = platformv1.FlowActionType_FLOW_ACTION_UNSPECIFIED
	}
	return &platformv1.FlowAction{
		Type: at,
		Port: a.Port,
	}
}

// FlowConfigToProto converts a domain FlowConfig to a proto FlowConfig.
func FlowConfigToProto(cfg *FlowConfig) *platformv1.FlowConfig {
	if cfg == nil {
		return nil
	}
	ft, ok := flowTableToProto[cfg.Table]
	if !ok {
		ft = platformv1.FlowTable_FLOW_TABLE_UNSPECIFIED
	}

	var actions []*platformv1.FlowAction
	for _, a := range cfg.Actions {
		actions = append(actions, FlowActionToProto(a))
	}

	return &platformv1.FlowConfig{
		BridgeId: cfg.BridgeID,
		Table:    ft,
		Priority: cfg.Priority,
		Match:    FlowMatchToProto(cfg.Match),
		Actions:  actions,
		Metadata: cfg.Metadata,
	}
}

// VLANConfigToProto converts a domain VLANConfig to a proto VLANConfig.
func VLANConfigToProto(cfg *VLANConfig) *platformv1.VLANConfig {
	if cfg == nil {
		return nil
	}
	return &platformv1.VLANConfig{
		VlanId:   cfg.VlanID,
		Name:     cfg.Name,
		BridgeId: cfg.BridgeID,
		Labels:   cfg.Labels,
	}
}

// PolicyTargetToProto converts a domain PolicyTarget to a proto PolicyTarget.
func PolicyTargetToProto(t *PolicyTarget) *platformv1.PolicyTarget {
	if t == nil {
		return nil
	}
	tt, ok := policyTargetTypeToProto[t.Type]
	if !ok {
		tt = platformv1.PolicyTargetType_POLICY_TARGET_TYPE_UNSPECIFIED
	}
	return &platformv1.PolicyTarget{
		Type: tt,
		Id:   t.ID,
	}
}

// PolicyConfigToProto converts a domain PolicyConfig to a proto PolicyConfig.
func PolicyConfigToProto(cfg *PolicyConfig) *platformv1.PolicyConfig {
	if cfg == nil {
		return nil
	}
	pt, ok := policyTypeToProto[cfg.Type]
	if !ok {
		pt = platformv1.PolicyType_POLICY_TYPE_UNSPECIFIED
	}

	var targets []*platformv1.PolicyTarget
	for _, t := range cfg.Targets {
		targets = append(targets, PolicyTargetToProto(t))
	}

	return &platformv1.PolicyConfig{
		Name:        cfg.Name,
		Description: cfg.Description,
		Type:        pt,
		Priority:    cfg.Priority,
		Enabled:     cfg.Enabled,
		Targets:     targets,
	}
}

// LabelSelectorToProto converts a domain LabelSelector to a proto LabelSelector.
func LabelSelectorToProto(sel *LabelSelector) *platformv1.LabelSelector {
	if sel == nil {
		return nil
	}
	return &platformv1.LabelSelector{
		MatchLabels: sel.MatchLabels,
	}
}

// PaginationToProto converts pagination parameters to a proto PaginationRequest.
func PaginationToProto(pageSize uint32) *platformv1.PaginationRequest {
	if pageSize == 0 {
		return nil
	}
	return &platformv1.PaginationRequest{
		PageSize: pageSize,
	}
}

// FlowTableToProto converts a domain FlowTable to a proto FlowTable.
func FlowTableToProto(ft FlowTable) platformv1.FlowTable {
	p, ok := flowTableToProto[ft]
	if !ok {
		return platformv1.FlowTable_FLOW_TABLE_UNSPECIFIED
	}
	return p
}

// VNIConfigToProto converts a domain VNIConfig to a proto VNIConfig.
func VNIConfigToProto(cfg *VNIConfig) *platformv1.VNIConfig {
	if cfg == nil {
		return nil
	}
	return &platformv1.VNIConfig{
		Vni:  cfg.VNI,
		Vlan: cfg.VLAN,
		Name: cfg.Name,
	}
}
