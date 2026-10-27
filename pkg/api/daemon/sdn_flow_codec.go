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
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// The flow codec converts between the platform.v1 flow messages and the OVS
// flow grammar the ovs package encodes (pkg/sdn/ovs parseMatchString and
// parseActions). A FlowConfig the grammar cannot carry exactly is refused:
// a dropped match field installs a broader flow, and a dropped action makes
// the flow do less than it was written to.

const (
	etherTypeIPv4 = 0x0800
	etherTypeIPv6 = 0x86dd
	ipProtoTCP    = 6
	ipProtoUDP    = 17

	maxVLANID     = 4095
	maxEtherType  = 0xffff
	maxIPProto    = 0xff
	maxL4Port     = 0xffff
	maxUint16     = 0xffff
	maxGotoTarget = 0xfe // OFPTT_MAX (OpenFlow 1.3 §7.2.2)
)

// flowRange is one numeric FlowConfig field and its largest valid value.
type flowRange struct {
	field string
	value uint32
	max   uint32
}

func checkFlowRanges(ranges []flowRange) error {
	for _, r := range ranges {
		if r.value > r.max {
			return ErrUnencodableFlow{Field: r.field, Reason: fmt.Sprintf("%d exceeds %d", r.value, r.max)}
		}
	}
	return nil
}

// flowConfigToOVSTerms returns the OVS match and actions strings of config.
// table is the OVS table the flow is installed in.
func flowConfigToOVSTerms(config *platformv1.FlowConfig, table int) (string, string, error) {
	err := checkFlowRanges([]flowRange{
		{"priority", config.GetPriority(), maxUint16},
		{"idle_timeout", config.GetIdleTimeout(), maxUint16},
		{"hard_timeout", config.GetHardTimeout(), maxUint16},
	})
	if err != nil {
		return "", "", err
	}
	match, err := flowMatchToOVS(config.GetMatch())
	if err != nil {
		return "", "", err
	}
	actions, err := flowActionsToOVS(config.GetActions(), table)
	if err != nil {
		return "", "", err
	}
	return match, actions, nil
}

// flowMatchToOVS returns the OVS match string of match. The terms are
// ordered so each OXM prerequisite (OpenFlow 1.3 §7.2.3.6) precedes the
// field that needs it, and an IP or transport field with no eth_type or
// ip_proto gets the one it implies.
func flowMatchToOVS(match *platformv1.FlowMatch) (string, error) {
	if match == nil {
		return "", nil
	}
	if len(match.GetMetadata()) > 0 {
		return "", ErrUnencodableFlow{Field: "match.metadata", Reason: "the OVS flow grammar has no metadata match"}
	}
	err := checkFlowRanges([]flowRange{
		{"match.vlan_id", match.GetVlanId(), maxVLANID},
		{"match.eth_type", match.GetEthType(), maxEtherType},
		{"match.ip_proto", match.GetIpProto(), maxIPProto},
		{"match.tcp_src", match.GetTcpSrc(), maxL4Port},
		{"match.tcp_dst", match.GetTcpDst(), maxL4Port},
		{"match.udp_src", match.GetUdpSrc(), maxL4Port},
		{"match.udp_dst", match.GetUdpDst(), maxL4Port},
	})
	if err != nil {
		return "", err
	}

	var terms []string
	if match.GetInPort() != "" {
		terms = append(terms, "in_port="+match.GetInPort())
	}
	if match.GetVlanId() > 0 {
		terms = append(terms, fmt.Sprintf("dl_vlan=%d", match.GetVlanId()))
	}
	if match.GetEthSrc() != "" {
		terms = append(terms, "dl_src="+match.GetEthSrc())
	}
	if match.GetEthDst() != "" {
		terms = append(terms, "dl_dst="+match.GetEthDst())
	}
	ipTerms, err := flowIPMatchTerms(match)
	if err != nil {
		return "", err
	}
	terms = append(terms, ipTerms...)
	return strings.Join(terms, ","), nil
}

// flowIPMatchTerms returns the dl_type, nw_proto, address and transport
// port terms of match.
func flowIPMatchTerms(match *platformv1.FlowMatch) ([]string, error) {
	proto, err := flowIPProto(match)
	if err != nil {
		return nil, err
	}
	src, err := flowIPTerm("src", match.GetIpSrc())
	if err != nil {
		return nil, err
	}
	dst, err := flowIPTerm("dst", match.GetIpDst())
	if err != nil {
		return nil, err
	}

	ethType := match.GetEthType()
	for _, addr := range []flowIPAddrTerm{src, dst} {
		if addr.ethType == 0 {
			continue
		}
		if ethType == 0 {
			ethType = addr.ethType
		}
		if ethType != addr.ethType {
			return nil, ErrUnencodableFlow{
				Field:  "match.ip_" + addr.dir,
				Reason: fmt.Sprintf("address family does not match eth_type 0x%04x", ethType),
			}
		}
	}
	if proto != 0 && ethType == 0 {
		ethType = etherTypeIPv4
	}

	var terms []string
	if ethType != 0 {
		terms = append(terms, fmt.Sprintf("dl_type=0x%04x", ethType))
	}
	if proto != 0 {
		terms = append(terms, fmt.Sprintf("nw_proto=%d", proto))
	}
	for _, addr := range []flowIPAddrTerm{src, dst} {
		if addr.term != "" {
			terms = append(terms, addr.term)
		}
	}

	srcPort, dstPort := match.GetTcpSrc(), match.GetTcpDst()
	if proto == ipProtoUDP {
		srcPort, dstPort = match.GetUdpSrc(), match.GetUdpDst()
	}
	if srcPort > 0 {
		terms = append(terms, fmt.Sprintf("tp_src=%d", srcPort))
	}
	if dstPort > 0 {
		terms = append(terms, fmt.Sprintf("tp_dst=%d", dstPort))
	}
	return terms, nil
}

// flowIPProto returns the IP protocol the match names: ip_proto, or the
// protocol its TCP or UDP ports imply.
func flowIPProto(match *platformv1.FlowMatch) (uint32, error) {
	proto := match.GetIpProto()
	tcp := match.GetTcpSrc() > 0 || match.GetTcpDst() > 0
	udp := match.GetUdpSrc() > 0 || match.GetUdpDst() > 0
	if tcp && udp {
		return 0, ErrUnencodableFlow{Field: "match", Reason: "tcp and udp ports cannot both be matched"}
	}

	var implied uint32
	switch {
	case tcp:
		implied = ipProtoTCP
	case udp:
		implied = ipProtoUDP
	default:
		return proto, nil
	}
	if proto != 0 && proto != implied {
		return 0, ErrUnencodableFlow{
			Field:  "match.ip_proto",
			Reason: fmt.Sprintf("%d conflicts with the transport ports (protocol %d)", proto, implied),
		}
	}
	return implied, nil
}

// flowIPAddrTerm is one IP address match term and the EtherType it needs.
type flowIPAddrTerm struct {
	dir     string
	term    string
	ethType uint32
}

// flowIPTerm returns the match term of an IP address or prefix: nw_src or
// nw_dst for IPv4, ipv6_src or ipv6_dst for IPv6.
func flowIPTerm(dir, value string) (flowIPAddrTerm, error) {
	if value == "" {
		return flowIPAddrTerm{dir: dir}, nil
	}
	var addr netip.Addr
	if prefix, err := netip.ParsePrefix(value); err == nil {
		addr = prefix.Addr()
	} else if parsed, err := netip.ParseAddr(value); err == nil && parsed.Zone() == "" {
		addr = parsed
	} else {
		return flowIPAddrTerm{}, ErrUnencodableFlow{Field: "match.ip_" + dir, Reason: fmt.Sprintf("%q is not an IP address or prefix", value)}
	}
	if addr.Is4() {
		return flowIPAddrTerm{dir: dir, term: "nw_" + dir + "=" + value, ethType: etherTypeIPv4}, nil
	}
	return flowIPAddrTerm{dir: dir, term: "ipv6_" + dir + "=" + value, ethType: etherTypeIPv6}, nil
}

// flowActionEncoder returns the OVS action of one FlowAction. table is the
// OVS table of the flow the action belongs to.
type flowActionEncoder func(action *platformv1.FlowAction, table int) (string, error)

var flowActionEncoders = map[platformv1.FlowActionType]flowActionEncoder{
	platformv1.FlowActionType_FLOW_ACTION_OUTPUT:     encodeOutputAction,
	platformv1.FlowActionType_FLOW_ACTION_DROP:       fixedFlowAction("drop"),
	platformv1.FlowActionType_FLOW_ACTION_SET_VLAN:   encodeSetVLANAction,
	platformv1.FlowActionType_FLOW_ACTION_STRIP_VLAN: fixedFlowAction("strip_vlan"),
	platformv1.FlowActionType_FLOW_ACTION_SET_FIELD:  encodeSetFieldAction,
	platformv1.FlowActionType_FLOW_ACTION_GOTO_TABLE: encodeGotoTableAction,
	platformv1.FlowActionType_FLOW_ACTION_CONTROLLER: fixedFlowAction("CONTROLLER"),
}

// flowActionsToOVS returns the OVS actions string of actions.
func flowActionsToOVS(actions []*platformv1.FlowAction, table int) (string, error) {
	parts := make([]string, 0, len(actions))
	for i, action := range actions {
		encode, ok := flowActionEncoders[action.GetType()]
		if !ok {
			return "", ErrUnencodableFlow{
				Field:  fmt.Sprintf("actions[%d].type", i),
				Reason: "unsupported action type " + action.GetType().String(),
			}
		}
		part, err := encode(action, table)
		if err != nil {
			return "", err
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, ","), nil
}

func fixedFlowAction(ovsAction string) flowActionEncoder {
	return func(*platformv1.FlowAction, int) (string, error) {
		return ovsAction, nil
	}
}

// encodeOutputAction outputs to a port; an empty port means NORMAL
// forwarding (the L2/L3 pipeline).
func encodeOutputAction(action *platformv1.FlowAction, _ int) (string, error) {
	if action.GetPort() == "" {
		return "NORMAL", nil
	}
	return "output:" + action.GetPort(), nil
}

func encodeSetVLANAction(action *platformv1.FlowAction, _ int) (string, error) {
	if err := checkFlowRanges([]flowRange{{"actions.vlan_id", action.GetVlanId(), maxVLANID}}); err != nil {
		return "", err
	}
	return fmt.Sprintf("mod_vlan_vid:%d", action.GetVlanId()), nil
}

// encodeSetFieldAction writes value into field (set_field:VALUE->FIELD).
// The ovs package validates the field name and the value's form; a comma
// or a second arrow would splice another action into the string.
func encodeSetFieldAction(action *platformv1.FlowAction, _ int) (string, error) {
	field, value := action.GetField(), action.GetValue()
	if field == "" || value == "" {
		return "", ErrUnencodableFlow{Field: "actions.field", Reason: "set_field needs a field and a value"}
	}
	for _, s := range []string{field, value} {
		if strings.ContainsAny(s, ", ()") || strings.Contains(s, "->") {
			return "", ErrUnencodableFlow{Field: "actions.field", Reason: fmt.Sprintf("%q is not a single set_field term", s)}
		}
	}
	return "set_field:" + value + "->" + field, nil
}

// encodeGotoTableAction continues the pipeline at a later table. OpenFlow
// 1.3 §5.1 lets a flow go only to a table greater than its own.
func encodeGotoTableAction(action *platformv1.FlowAction, table int) (string, error) {
	target := action.GetTableId()
	if int64(target) <= int64(table) || target > maxGotoTarget {
		return "", ErrUnencodableFlow{
			Field:  "actions.table_id",
			Reason: fmt.Sprintf("goto_table %d must be greater than the flow's table %d and at most %d", target, table, maxGotoTarget),
		}
	}
	return fmt.Sprintf("goto_table:%d", target), nil
}

// ovsMatchToPb returns the FlowMatch of an OVS match string. A term with no
// FlowMatch field (ct_state, a register, a protocol shorthand, ...) is kept
// in metadata, term name to value, so a listed flow loses nothing; AddFlow
// refuses metadata, so such a flow is reported but cannot be re-added.
func ovsMatchToPb(matchStr string) *platformv1.FlowMatch {
	if strings.TrimSpace(matchStr) == "" {
		return nil
	}
	match := &platformv1.FlowMatch{}
	var tpSrc, tpDst uint32
	for _, part := range strings.Split(matchStr, ",") {
		key, value, _ := strings.Cut(strings.TrimSpace(part), "=")
		if key == "" {
			continue
		}
		switch key {
		case "tp_src":
			if n, ok := parseFlowUint(value); ok {
				tpSrc = n
				continue
			}
		case "tp_dst":
			if n, ok := parseFlowUint(value); ok {
				tpDst = n
				continue
			}
		default:
			if decode, ok := flowMatchDecoders[key]; ok && decode(match, value) {
				continue
			}
		}
		if match.Metadata == nil {
			match.Metadata = make(map[string]string)
		}
		match.Metadata[key] = value
	}

	if match.GetIpProto() == ipProtoUDP {
		match.UdpSrc, match.UdpDst = tpSrc, tpDst
	} else {
		match.TcpSrc, match.TcpDst = tpSrc, tpDst
	}
	return match
}

// flowMatchDecoder sets the FlowMatch field of one OVS match term and
// reports whether value was valid for it.
type flowMatchDecoder func(match *platformv1.FlowMatch, value string) bool

func setFlowString(set func(*platformv1.FlowMatch, string)) flowMatchDecoder {
	return func(match *platformv1.FlowMatch, value string) bool {
		set(match, value)
		return true
	}
}

func setFlowUint(set func(*platformv1.FlowMatch, uint32)) flowMatchDecoder {
	return func(match *platformv1.FlowMatch, value string) bool {
		n, ok := parseFlowUint(value)
		if ok {
			set(match, n)
		}
		return ok
	}
}

var flowMatchDecoders = map[string]flowMatchDecoder{
	"in_port":  setFlowString(func(m *platformv1.FlowMatch, v string) { m.InPort = v }),
	"dl_src":   setFlowString(func(m *platformv1.FlowMatch, v string) { m.EthSrc = v }),
	"dl_dst":   setFlowString(func(m *platformv1.FlowMatch, v string) { m.EthDst = v }),
	"nw_src":   setFlowString(func(m *platformv1.FlowMatch, v string) { m.IpSrc = v }),
	"nw_dst":   setFlowString(func(m *platformv1.FlowMatch, v string) { m.IpDst = v }),
	"ipv6_src": setFlowString(func(m *platformv1.FlowMatch, v string) { m.IpSrc = v }),
	"ipv6_dst": setFlowString(func(m *platformv1.FlowMatch, v string) { m.IpDst = v }),
	"dl_vlan":  setFlowUint(func(m *platformv1.FlowMatch, n uint32) { m.VlanId = n }),
	"dl_type":  setFlowUint(func(m *platformv1.FlowMatch, n uint32) { m.EthType = n }),
	"nw_proto": setFlowUint(func(m *platformv1.FlowMatch, n uint32) { m.IpProto = n }),
}

// parseFlowUint parses a decimal or 0x-prefixed hex match value.
func parseFlowUint(value string) (uint32, bool) {
	n, err := strconv.ParseUint(value, 0, 32)
	if err != nil {
		return 0, false
	}
	return uint32(n), true
}

// ovsActionsToPb returns the FlowActions of an OVS actions string. An
// action with no FlowActionType (resubmit, ct, load, ...) is left out: the
// FlowAction message has nowhere to carry it.
func ovsActionsToPb(actionsStr string) []*platformv1.FlowAction {
	var actions []*platformv1.FlowAction
	for _, part := range strings.Split(actionsStr, ",") {
		if action := ovsActionToPb(strings.TrimSpace(part)); action != nil {
			actions = append(actions, action)
		}
	}
	return actions
}

// ovsKeywordActions are the OVS actions that take no argument.
var ovsKeywordActions = map[string]*platformv1.FlowAction{
	"normal":     {Type: platformv1.FlowActionType_FLOW_ACTION_OUTPUT},
	"drop":       {Type: platformv1.FlowActionType_FLOW_ACTION_DROP},
	"strip_vlan": {Type: platformv1.FlowActionType_FLOW_ACTION_STRIP_VLAN},
	"controller": {Type: platformv1.FlowActionType_FLOW_ACTION_CONTROLLER},
}

func ovsActionToPb(part string) *platformv1.FlowAction {
	lower := strings.ToLower(part)
	if action, ok := ovsKeywordActions[lower]; ok {
		return &platformv1.FlowAction{Type: action.GetType()}
	}

	name, arg, _ := strings.Cut(part, ":")
	switch strings.ToLower(name) {
	case "output":
		return &platformv1.FlowAction{Type: platformv1.FlowActionType_FLOW_ACTION_OUTPUT, Port: arg}
	case "controller":
		return &platformv1.FlowAction{Type: platformv1.FlowActionType_FLOW_ACTION_CONTROLLER}
	case "mod_vlan_vid":
		if vlan, ok := parseFlowUint(arg); ok {
			return &platformv1.FlowAction{Type: platformv1.FlowActionType_FLOW_ACTION_SET_VLAN, VlanId: vlan}
		}
	case "goto_table":
		if table, ok := parseFlowUint(arg); ok {
			return &platformv1.FlowAction{Type: platformv1.FlowActionType_FLOW_ACTION_GOTO_TABLE, TableId: table}
		}
	case "set_field":
		if value, field, ok := strings.Cut(arg, "->"); ok {
			return &platformv1.FlowAction{Type: platformv1.FlowActionType_FLOW_ACTION_SET_FIELD, Field: field, Value: value}
		}
	}
	return nil
}
