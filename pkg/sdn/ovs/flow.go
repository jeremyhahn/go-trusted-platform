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

package ovs

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/openflow"
)

// AddFlow adds an OpenFlow rule to a bridge using native OpenFlow protocol.
func (c *Client) AddFlow(ctx context.Context, bridgeName string, flow *FlowMod) error {
	if bridgeName == "" {
		return ErrInvalidBridgeName
	}
	if flow == nil {
		return ErrInvalidFlow
	}

	if err := c.ensureConnected(ctx); err != nil {
		return err
	}

	ofClient, err := c.getOpenFlowClient(ctx, bridgeName)
	if err != nil {
		return &WrappedError{Msg: "failed to get OpenFlow client", Err: err}
	}

	// Convert OVS FlowMod to OpenFlow FlowMod
	ofFlow, err := convertToOpenFlow(flow)
	if err != nil {
		return &WrappedError{Msg: "failed to convert flow", Err: err}
	}

	if err := ofClient.AddFlow(ctx, ofFlow); err != nil {
		return &WrappedError{Msg: "failed to add flow", Err: err}
	}

	return nil
}

// AddFlows adds a batch of OpenFlow rules to a bridge in a single OpenFlow
// transaction (all flow mods followed by one barrier) using native OpenFlow
// protocol. An empty batch is a no-op. When the switch rejects individual
// flows the returned error wraps openflow.ErrBatchPartialFailure identifying
// the failed flows by index.
func (c *Client) AddFlows(ctx context.Context, bridgeName string, flows []*FlowMod) error {
	if bridgeName == "" {
		return ErrInvalidBridgeName
	}
	for _, flow := range flows {
		if flow == nil {
			return ErrInvalidFlow
		}
	}
	if len(flows) == 0 {
		return nil
	}

	// Convert before dialing so invalid specs fail fast
	ofFlows := make([]*openflow.FlowMod, 0, len(flows))
	for _, flow := range flows {
		ofFlow, err := convertToOpenFlow(flow)
		if err != nil {
			return &WrappedError{Msg: "failed to convert flow", Err: err}
		}
		ofFlows = append(ofFlows, ofFlow)
	}

	if err := c.ensureConnected(ctx); err != nil {
		return err
	}

	ofClient, err := c.getOpenFlowClient(ctx, bridgeName)
	if err != nil {
		return &WrappedError{Msg: "failed to get OpenFlow client", Err: err}
	}

	if err := ofClient.SendFlowMods(ctx, ofFlows); err != nil {
		return &WrappedError{Msg: "failed to add flows", Err: err}
	}

	return nil
}

// DeleteFlow deletes an OpenFlow rule from a bridge using native OpenFlow protocol.
func (c *Client) DeleteFlow(ctx context.Context, bridgeName string, match string) error {
	if bridgeName == "" {
		return ErrInvalidBridgeName
	}
	if match == "" {
		return ErrInvalidFlow
	}

	if err := c.ensureConnected(ctx); err != nil {
		return err
	}

	ofClient, err := c.getOpenFlowClient(ctx, bridgeName)
	if err != nil {
		return &WrappedError{Msg: "failed to get OpenFlow client", Err: err}
	}

	// Build OpenFlow FlowMod for delete
	ofFlow := openflow.NewFlowMod(0)
	ofFlow.Command = openflow.OFPFCDelete
	ofFlow.TableID = openflow.OFPTTAll
	ofFlow.OutPort = openflow.OFPPAny
	ofFlow.OutGroup = 0xffffffff

	// Parse match string and add to flow
	if err := parseMatchString(ofFlow.Match, match); err != nil {
		return &WrappedError{Msg: "failed to parse match", Err: err}
	}

	if err := ofClient.DeleteFlow(ctx, ofFlow); err != nil {
		return &WrappedError{Msg: "failed to delete flow", Err: err}
	}

	return nil
}

// DeleteFlowsByCookie deletes all OpenFlow rules on a bridge whose cookie
// matches cookie under cookieMask, across all tables, using a single
// OFPFC_DELETE flow mod. A zero cookieMask is rejected because it would
// wildcard the cookie and delete every flow on the bridge; use
// DeleteAllFlows for that intent.
func (c *Client) DeleteFlowsByCookie(ctx context.Context, bridgeName string, cookie, cookieMask uint64) error {
	if bridgeName == "" {
		return ErrInvalidBridgeName
	}
	if cookieMask == 0 {
		return ErrInvalidCookieMask
	}

	if err := c.ensureConnected(ctx); err != nil {
		return err
	}

	ofClient, err := c.getOpenFlowClient(ctx, bridgeName)
	if err != nil {
		return &WrappedError{Msg: "failed to get OpenFlow client", Err: err}
	}

	ofFlow := openflow.NewFlowMod(0)
	ofFlow.TableID = openflow.OFPTTAll
	ofFlow.Cookie = cookie
	ofFlow.CookieMask = cookieMask

	if err := ofClient.DeleteFlow(ctx, ofFlow); err != nil {
		return &WrappedError{Msg: "failed to delete flows by cookie", Err: err}
	}

	return nil
}

// DeleteFlowStrict deletes the single OpenFlow rule whose table, priority,
// and match exactly equal the given flow (OFPFC_DELETE_STRICT). When the
// flow carries a cookie the delete is additionally restricted to that exact
// cookie value, so flows owned by other subsystems with an identical match
// are never removed.
func (c *Client) DeleteFlowStrict(ctx context.Context, bridgeName string, flow *FlowMod) error {
	if bridgeName == "" {
		return ErrInvalidBridgeName
	}
	if flow == nil {
		return ErrInvalidFlow
	}

	// Convert before dialing so invalid specs fail fast.
	ofFlow, err := convertToOpenFlow(flow)
	if err != nil {
		return &WrappedError{Msg: "failed to convert flow", Err: err}
	}
	// Actions are irrelevant for a delete; strip them so the wire message
	// carries only the identifying header and match.
	ofFlow.Instructions = nil

	// convertToOpenFlow has parsed and set the cookie; a strict delete
	// matches it exactly.
	if flow.Cookie != "" {
		ofFlow.CookieMask = ^uint64(0)
	}

	if err := c.ensureConnected(ctx); err != nil {
		return err
	}

	ofClient, err := c.getOpenFlowClient(ctx, bridgeName)
	if err != nil {
		return &WrappedError{Msg: "failed to get OpenFlow client", Err: err}
	}

	if err := ofClient.DeleteFlowStrict(ctx, ofFlow); err != nil {
		return &WrappedError{Msg: "failed to delete flow strict", Err: err}
	}

	return nil
}

// ListFlows returns all OpenFlow rules on a bridge using native OpenFlow protocol.
func (c *Client) ListFlows(ctx context.Context, bridgeName string) ([]*Flow, error) {
	if bridgeName == "" {
		return nil, ErrInvalidBridgeName
	}

	if err := c.ensureConnected(ctx); err != nil {
		return nil, err
	}

	ofClient, err := c.getOpenFlowClient(ctx, bridgeName)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to get OpenFlow client", Err: err}
	}

	// Get flow stats
	stats, err := ofClient.GetFlowStats(ctx, nil)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to get flow stats", Err: err}
	}

	// Convert to Flow type
	flows := make([]*Flow, 0, len(stats))
	for _, stat := range stats {
		flow := &Flow{
			Table:       int(stat.TableID),
			Priority:    int(stat.Priority),
			Duration:    int(stat.DurationSec),
			IdleAge:     int(stat.IdleTimeout),
			HardAge:     int(stat.HardTimeout),
			Cookie:      fmt.Sprintf("0x%x", stat.Cookie),
			PacketCount: int64(stat.PacketCount),
			ByteCount:   int64(stat.ByteCount),
		}
		flows = append(flows, flow)
	}

	return flows, nil
}

// DeleteAllFlows deletes all OpenFlow rules from a bridge using native OpenFlow protocol.
func (c *Client) DeleteAllFlows(ctx context.Context, bridgeName string) error {
	if bridgeName == "" {
		return ErrInvalidBridgeName
	}

	if err := c.ensureConnected(ctx); err != nil {
		return err
	}

	ofClient, err := c.getOpenFlowClient(ctx, bridgeName)
	if err != nil {
		return &WrappedError{Msg: "failed to get OpenFlow client", Err: err}
	}

	if err := ofClient.DeleteAllFlows(ctx); err != nil {
		return &WrappedError{Msg: "failed to delete all flows", Err: err}
	}

	return nil
}

// ModifyFlow modifies an existing OpenFlow rule using native OpenFlow protocol.
func (c *Client) ModifyFlow(ctx context.Context, bridgeName string, flow *FlowMod) error {
	if bridgeName == "" {
		return ErrInvalidBridgeName
	}
	if flow == nil {
		return ErrInvalidFlow
	}

	if err := c.ensureConnected(ctx); err != nil {
		return err
	}

	ofClient, err := c.getOpenFlowClient(ctx, bridgeName)
	if err != nil {
		return &WrappedError{Msg: "failed to get OpenFlow client", Err: err}
	}

	// Convert OVS FlowMod to OpenFlow FlowMod
	ofFlow, err := convertToOpenFlow(flow)
	if err != nil {
		return &WrappedError{Msg: "failed to convert flow", Err: err}
	}

	if err := ofClient.ModifyFlow(ctx, ofFlow); err != nil {
		return &WrappedError{Msg: "failed to modify flow", Err: err}
	}

	return nil
}

// GetFlowStats returns statistics for flows matching the criteria using
// native OpenFlow protocol. match uses the ovs-ofctl grammar and may include
// a "table=N" key to scope the request to one table; each returned Flow
// carries its rendered match string.
func (c *Client) GetFlowStats(ctx context.Context, bridgeName string, match string) ([]*Flow, error) {
	if bridgeName == "" {
		return nil, ErrInvalidBridgeName
	}

	if err := c.ensureConnected(ctx); err != nil {
		return nil, err
	}

	ofClient, err := c.getOpenFlowClient(ctx, bridgeName)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to get OpenFlow client", Err: err}
	}

	// Build match for flow stats request. The ovs-ofctl grammar allows a
	// "table=N" key alongside match fields; it scopes the stats request
	// rather than matching a packet field.
	matchFields, filter, err := splitStatsFilter(match)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to parse match", Err: err}
	}
	filter.Match = openflow.NewMatch()
	if matchFields != "" {
		if err := parseMatchString(filter.Match, matchFields); err != nil {
			return nil, &WrappedError{Msg: "failed to parse match", Err: err}
		}
	}

	stats, err := ofClient.QueryFlowStats(ctx, filter)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to get flow stats", Err: err}
	}

	// Convert to Flow type
	flows := make([]*Flow, 0, len(stats))
	for _, stat := range stats {
		flow := &Flow{
			Table:       int(stat.TableID),
			Priority:    int(stat.Priority),
			Match:       formatMatchString(stat.Match),
			Duration:    int(stat.DurationSec),
			IdleAge:     int(stat.IdleTimeout),
			HardAge:     int(stat.HardTimeout),
			Cookie:      fmt.Sprintf("0x%x", stat.Cookie),
			PacketCount: int64(stat.PacketCount),
			ByteCount:   int64(stat.ByteCount),
		}
		flows = append(flows, flow)
	}

	return flows, nil
}

// splitStatsFilter separates the keys of an ovs-ofctl dump-flows filter
// that scope the stats request rather than match a packet field — "table=N"
// and "cookie=VALUE[/MASK]" — from the match fields. A cookie without a
// mask must match exactly.
func splitStatsFilter(match string) (string, openflow.FlowStatsFilter, error) {
	filter := openflow.FlowStatsFilter{TableID: openflow.OFPTTAll}
	if match == "" {
		return "", filter, nil
	}

	fields := make([]string, 0, 4)
	for _, part := range strings.Split(match, ",") {
		trimmed := strings.TrimSpace(part)
		if value, ok := strings.CutPrefix(trimmed, "table="); ok {
			table, err := strconv.ParseUint(value, 10, 8)
			if err != nil {
				return "", filter, &MessageError{Msg: fmt.Sprintf("invalid table: %s", value)}
			}
			filter.TableID = uint8(table)
			continue
		}
		if value, ok := strings.CutPrefix(trimmed, "cookie="); ok {
			cookie, mask, err := parseValueMask(value, 64)
			if err != nil {
				return "", filter, &MessageError{Msg: fmt.Sprintf("invalid cookie: %s", value)}
			}
			filter.Cookie, filter.CookieMask = cookie, mask
			continue
		}
		if trimmed != "" {
			fields = append(fields, trimmed)
		}
	}

	return strings.Join(fields, ","), filter, nil
}

// convertToOpenFlow converts an OVS FlowMod to an OpenFlow FlowMod
func convertToOpenFlow(flow *FlowMod) (*openflow.FlowMod, error) {
	ofFlow := openflow.NewFlowMod(0)
	ofFlow.TableID = uint8(flow.Table)
	ofFlow.Priority = uint16(flow.Priority)
	ofFlow.IdleTimeout = uint16(flow.IdleTimeout)
	ofFlow.HardTimeout = uint16(flow.HardTimeout)

	// Parse cookie. An unparseable cookie is an error rather than a zero:
	// the cookie is how the flow's owner deletes it (#614).
	if flow.Cookie != "" {
		cookie, err := parseCookie(flow.Cookie)
		if err != nil {
			return nil, &ErrInvalidCookie{Cookie: flow.Cookie, Err: err}
		}
		ofFlow.Cookie = cookie
	}

	// Parse match string
	if flow.Match != "" {
		if err := parseMatchString(ofFlow.Match, flow.Match); err != nil {
			return nil, &WrappedError{Msg: "failed to parse match", Err: err}
		}
	}

	// Parse actions string
	if flow.Actions != "" {
		actions, gotoTable, err := parseActions(flow.Actions)
		if err != nil {
			return nil, &WrappedError{Msg: "failed to parse actions", Err: err}
		}
		if len(actions) > 0 {
			ofFlow.Instructions = append(ofFlow.Instructions,
				openflow.NewInstructionApplyActions(actions...))
		}
		if gotoTable != nil {
			ofFlow.Instructions = append(ofFlow.Instructions,
				openflow.NewInstructionGotoTable(*gotoTable))
		}
	}

	return ofFlow, nil
}

// parseMatchString parses ovs-ofctl style match string into OpenFlow match
func parseMatchString(match *openflow.Match, matchStr string) error {
	// Parse key=value pairs from match string
	parts := strings.Split(matchStr, ",")

	// First pass: extract protocol to determine TCP vs UDP for port
	// matching and ICMPv4 vs ICMPv6 for type/code matching. A protocol
	// shorthand ("tcp", "icmp6", ...) names the protocol too.
	var ipProto uint8
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "nw_proto=") {
			value := strings.TrimPrefix(part, "nw_proto=")
			proto, err := strconv.ParseUint(value, 10, 8)
			if err == nil {
				ipProto = uint8(proto)
			}
			break
		}
		if sh, ok := matchShorthands[part]; ok && sh.proto != 0 {
			ipProto = sh.proto
			break
		}
	}

	// Second pass: parse all fields
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			sh, ok := matchShorthands[part]
			if !ok {
				return &MessageError{Msg: fmt.Sprintf("unsupported match field: %s", part)}
			}
			match.AddEthType(sh.ethType)
			if sh.proto != 0 {
				match.AddIPProto(sh.proto)
			}
			continue
		}

		key := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])

		if index, ok := regIndex(key); ok {
			regValue, regMask, err := parseValueMask(value, 32)
			if err != nil {
				return &MessageError{Msg: fmt.Sprintf("invalid %s: %s", key, value)}
			}
			match.AddReg(index, uint32(regValue), uint32(regMask))
			continue
		}

		switch key {
		case "in_port":
			port, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return &MessageError{Msg: fmt.Sprintf("invalid in_port: %s", value)}
			}
			match.AddInPort(uint32(port))

		case "dl_src":
			mac, err := net.ParseMAC(value)
			if err != nil {
				return &MessageError{Msg: fmt.Sprintf("invalid dl_src: %s", value)}
			}
			match.AddEthSrc(mac)

		case "dl_dst":
			mac, err := net.ParseMAC(value)
			if err != nil {
				return &MessageError{Msg: fmt.Sprintf("invalid dl_dst: %s", value)}
			}
			match.AddEthDst(mac)

		case "dl_type":
			ethType, err := parseHexOrDecimal(value)
			if err != nil {
				return &MessageError{Msg: fmt.Sprintf("invalid dl_type: %s", value)}
			}
			match.AddEthType(uint16(ethType))

		case "dl_vlan":
			vlan, err := strconv.ParseUint(value, 10, 16)
			if err != nil {
				return &MessageError{Msg: fmt.Sprintf("invalid dl_vlan: %s", value)}
			}
			match.AddVLANVid(uint16(vlan))

		case "vlan_vid":
			// The raw OXM VLAN_VID, value[/mask], where 0x1000 is
			// OFPVID_PRESENT: vlan_vid=0x1000/0x1000 matches every tagged
			// frame whatever its VID, which dl_vlan cannot say (the NAT64
			// hand-off strips the tag of exactly those frames, #614).
			vid, vidMask, err := parseValueMask(value, 13)
			if err != nil {
				return &MessageError{Msg: fmt.Sprintf("invalid vlan_vid: %s", value)}
			}
			raw := make([]byte, 2)
			openflow.ByteOrder.PutUint16(raw, uint16(vid))
			var mask []byte
			if vidMask != 0x1fff {
				mask = make([]byte, 2)
				openflow.ByteOrder.PutUint16(mask, uint16(vidMask))
			}
			match.AddField(openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBVlanVid, raw, mask)

		case "nw_src":
			// Check for CIDR notation (e.g., 192.168.1.0/24)
			if strings.Contains(value, "/") {
				_, ipNet, err := net.ParseCIDR(value)
				if err != nil {
					return &MessageError{Msg: fmt.Sprintf("invalid nw_src CIDR: %s", value)}
				}
				match.AddIPv4SrcMasked(ipNet.IP, ipNet.Mask)
			} else {
				ip := net.ParseIP(value)
				if ip == nil {
					return &MessageError{Msg: fmt.Sprintf("invalid nw_src: %s", value)}
				}
				match.AddIPv4Src(ip)
			}

		case "nw_dst":
			// Check for CIDR notation (e.g., 10.0.200.0/24)
			if strings.Contains(value, "/") {
				_, ipNet, err := net.ParseCIDR(value)
				if err != nil {
					return &MessageError{Msg: fmt.Sprintf("invalid nw_dst CIDR: %s", value)}
				}
				match.AddIPv4DstMasked(ipNet.IP, ipNet.Mask)
			} else {
				ip := net.ParseIP(value)
				if ip == nil {
					return &MessageError{Msg: fmt.Sprintf("invalid nw_dst: %s", value)}
				}
				match.AddIPv4Dst(ip)
			}

		case "nw_proto":
			proto, err := strconv.ParseUint(value, 10, 8)
			if err != nil {
				return &MessageError{Msg: fmt.Sprintf("invalid nw_proto: %s", value)}
			}
			match.AddIPProto(uint8(proto))

		case "tp_src":
			port, err := strconv.ParseUint(value, 10, 16)
			if err != nil {
				return &MessageError{Msg: fmt.Sprintf("invalid tp_src: %s", value)}
			}
			// Use correct method based on protocol (17=UDP, 6=TCP)
			if ipProto == 17 {
				match.AddUDPSrc(uint16(port))
			} else {
				match.AddTCPSrc(uint16(port))
			}

		case "tp_dst":
			port, err := strconv.ParseUint(value, 10, 16)
			if err != nil {
				return &MessageError{Msg: fmt.Sprintf("invalid tp_dst: %s", value)}
			}
			// Use correct method based on protocol (17=UDP, 6=TCP)
			if ipProto == 17 {
				match.AddUDPDst(uint16(port))
			} else {
				match.AddTCPDst(uint16(port))
			}

		case "ct_state":
			value, mask, err := parseCTState(value)
			if err != nil {
				return err
			}
			match.AddCTState(value, mask)

		case "ct_zone":
			zone, err := strconv.ParseUint(value, 10, 16)
			if err != nil {
				return &MessageError{Msg: fmt.Sprintf("invalid ct_zone: %s", value)}
			}
			match.AddCTZone(uint16(zone))

		case "ct_mark":
			mark, mask, err := parseCTMark(value)
			if err != nil {
				return err
			}
			match.AddCTMark(mark, mask)

		case "icmp_type", "icmp_code", "icmpv6_type", "icmpv6_code":
			v, err := strconv.ParseUint(value, 10, 8)
			if err != nil {
				return &MessageError{Msg: fmt.Sprintf("invalid %s: %s", key, value)}
			}
			match.AddField(openflow.OFPXMCOpenflowBasic, icmpField(key, ipProto), []byte{uint8(v)}, nil)

		case "ipv6_src", "ipv6_dst":
			addr, mask, err := parseIPv6Match(value)
			if err != nil {
				return &MessageError{Msg: fmt.Sprintf("invalid %s: %s", key, value)}
			}
			field := uint8(openflow.OFPXMTOFBIPv6Src)
			if key == "ipv6_dst" {
				field = openflow.OFPXMTOFBIPv6Dst
			}
			match.AddField(openflow.OFPXMCOpenflowBasic, field, addr, mask)

		default:
			// A field this grammar does not know must not be dropped: the
			// flow would be installed broader than it was written.
			return &MessageError{Msg: fmt.Sprintf("unsupported match field: %s", key)}
		}
	}

	return nil
}

// matchShorthand is what an ovs-ofctl protocol keyword stands for.
type matchShorthand struct {
	ethType uint16
	proto   uint8
}

// matchShorthands are the ovs-ofctl protocol keywords the grammar accepts.
var matchShorthands = map[string]matchShorthand{
	"ip":    {ethType: 0x0800},
	"ipv6":  {ethType: 0x86dd},
	"arp":   {ethType: 0x0806},
	"icmp":  {ethType: 0x0800, proto: 1},
	"tcp":   {ethType: 0x0800, proto: 6},
	"udp":   {ethType: 0x0800, proto: 17},
	"sctp":  {ethType: 0x0800, proto: 132},
	"icmp6": {ethType: 0x86dd, proto: 58},
	"tcp6":  {ethType: 0x86dd, proto: 6},
	"udp6":  {ethType: 0x86dd, proto: 17},
	"sctp6": {ethType: 0x86dd, proto: 132},
}

// icmpField picks the OXM field for an ICMP type or code match: the ICMPv6
// field when the key says so or the flow matches ICMPv6 (nw_proto=58),
// as ovs-ofctl does for icmp_type/icmp_code.
func icmpField(key string, ipProto uint8) uint8 {
	v6 := strings.HasPrefix(key, "icmpv6_") || ipProto == 58
	isCode := strings.HasSuffix(key, "_code")
	switch {
	case v6 && isCode:
		return openflow.OFPXMTOFBICMPv6Code
	case v6:
		return openflow.OFPXMTOFBICMPv6Type
	case isCode:
		return openflow.OFPXMTOFBICMPv4Code
	default:
		return openflow.OFPXMTOFBICMPv4Type
	}
}

// parseIPv6Match parses an IPv6 address or CIDR into an OXM value and,
// for a prefix shorter than /128, its mask.
func parseIPv6Match(value string) ([]byte, []byte, error) {
	if strings.Contains(value, "/") {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !prefix.Addr().Is6() || prefix.Addr().Is4In6() {
			return nil, nil, &MessageError{Msg: "not an IPv6 prefix"}
		}
		addr := prefix.Masked().Addr().As16()
		if prefix.Bits() == 128 {
			return addr[:], nil, nil
		}
		mask := net.CIDRMask(prefix.Bits(), 128)
		return addr[:], []byte(mask), nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil || !addr.Is6() || addr.Is4In6() {
		return nil, nil, &MessageError{Msg: "not an IPv6 address"}
	}
	b := addr.As16()
	return b[:], nil, nil
}

// regIndex reports whether key names a register ("reg0".."reg15").
func regIndex(key string) (uint8, bool) {
	digits, ok := strings.CutPrefix(key, "reg")
	if !ok || digits == "" {
		return 0, false
	}
	n, err := strconv.ParseUint(digits, 10, 8)
	if err != nil || n >= openflow.NXRegCount {
		return 0, false
	}
	return uint8(n), true
}

// parseValueMask parses "value" or "value/mask" (decimal or 0x-hex) of at
// most bits bits. Without a mask every bit is matched.
func parseValueMask(spec string, bits int) (uint64, uint64, error) {
	full := ^uint64(0) >> (64 - bits)
	valueStr, maskStr, masked := strings.Cut(spec, "/")
	value, err := strconv.ParseUint(valueStr, 0, bits)
	if err != nil {
		return 0, 0, err
	}
	if !masked {
		return value, full, nil
	}
	mask, err := strconv.ParseUint(maskStr, 0, bits)
	if err != nil {
		return 0, 0, err
	}
	return value, mask, nil
}

// ctStateBits maps ct_state bit names from the ovs-ofctl match grammar to
// the CS_* bit values defined by the OpenFlow Nicira conntrack extension.
var ctStateBits = map[string]uint32{
	"new":  openflow.CTStateNew,
	"est":  openflow.CTStateEst,
	"rel":  openflow.CTStateRel,
	"rpl":  openflow.CTStateRpl,
	"inv":  openflow.CTStateInv,
	"trk":  openflow.CTStateTrk,
	"snat": openflow.CTStateSNAT,
	"dnat": openflow.CTStateDNAT,
}

// parseCTState parses an ovs-ofctl ct_state specification such as
// "+new-est+trk". A "+bit" sets the bit in both value and mask (bit must be
// set); a "-bit" sets the bit in the mask only (bit must be clear).
func parseCTState(spec string) (uint32, uint32, error) {
	if spec == "" {
		return 0, 0, &MessageError{Msg: "empty ct_state"}
	}

	var value, mask uint32
	for len(spec) > 0 {
		set := false
		switch spec[0] {
		case '+':
			set = true
		case '-':
		default:
			return 0, 0, &MessageError{Msg: fmt.Sprintf("invalid ct_state flag prefix: %s", spec)}
		}
		spec = spec[1:]

		end := strings.IndexAny(spec, "+-")
		if end == -1 {
			end = len(spec)
		}
		name := spec[:end]
		spec = spec[end:]

		bit, ok := ctStateBits[name]
		if !ok {
			return 0, 0, &MessageError{Msg: fmt.Sprintf("unknown ct_state bit: %s", name)}
		}
		mask |= bit
		if set {
			value |= bit
		}
	}

	return value, mask, nil
}

// parseCTMark parses an ovs-ofctl ct_mark specification "N" or "N/mask"
// where both parts accept hex (0x-prefixed) or decimal notation. A bare
// value implies an exact (full-mask) match.
func parseCTMark(spec string) (uint32, uint32, error) {
	markStr, maskStr, hasMask := strings.Cut(spec, "/")

	mark, err := parseHexOrDecimal(markStr)
	if err != nil || mark > 0xffffffff {
		return 0, 0, &MessageError{Msg: fmt.Sprintf("invalid ct_mark: %s", spec)}
	}

	mask := uint64(0xffffffff)
	if hasMask {
		mask, err = parseHexOrDecimal(maskStr)
		if err != nil || mask > 0xffffffff {
			return 0, 0, &MessageError{Msg: fmt.Sprintf("invalid ct_mark mask: %s", spec)}
		}
	}

	return uint32(mark), uint32(mask), nil
}

// ctStateFlagOrder renders ct_state bits in ovs-ofctl's canonical order.
var ctStateFlagOrder = []struct {
	bit  uint32
	name string
}{
	{openflow.CTStateNew, "new"},
	{openflow.CTStateEst, "est"},
	{openflow.CTStateRel, "rel"},
	{openflow.CTStateRpl, "rpl"},
	{openflow.CTStateInv, "inv"},
	{openflow.CTStateTrk, "trk"},
	{openflow.CTStateSNAT, "snat"},
	{openflow.CTStateDNAT, "dnat"},
}

// formatCTState renders a masked ct_state value in the ovs-ofctl match
// grammar accepted by parseCTState (e.g. "+inv+trk").
func formatCTState(value, mask uint32) string {
	var b strings.Builder
	for _, flag := range ctStateFlagOrder {
		if mask&flag.bit == 0 {
			continue
		}
		if value&flag.bit != 0 {
			b.WriteByte('+')
		} else {
			b.WriteByte('-')
		}
		b.WriteString(flag.name)
	}
	return b.String()
}

// formatIPv4Field renders an OXM IPv4 value (optionally masked) as an
// ovs-ofctl address or CIDR string.
func formatIPv4Field(field openflow.OXMField) string {
	ip := net.IP(field.Value).String()
	if !field.HasMask {
		return ip
	}
	ones, bits := net.IPMask(field.Mask).Size()
	if bits == 0 {
		// Non-contiguous mask: render the dotted mask form.
		return ip + "/" + net.IP(field.Mask).String()
	}
	return fmt.Sprintf("%s/%d", ip, ones)
}

// formatMatchString renders an OXM match in the ovs-ofctl match grammar
// parsed by parseMatchString. Fields without a representation in that
// grammar are omitted.
func formatMatchString(match *openflow.Match) string {
	if match == nil {
		return ""
	}

	parts := make([]string, 0, len(match.Fields))
	for _, field := range match.Fields {
		if part := formatMatchField(field); part != "" {
			parts = append(parts, part)
		}
	}
	return strings.Join(parts, ",")
}

// formatMatchField renders one OXM field, returning "" for fields outside
// the parseMatchString grammar.
func formatMatchField(field openflow.OXMField) string {
	switch field.Class {
	case openflow.OFPXMCOpenflowBasic:
		return formatBasicMatchField(field)
	case openflow.OFPXMCNxm1:
		return formatNXMMatchField(field)
	}
	return ""
}

// formatBasicMatchField renders an OFPXMC_OPENFLOW_BASIC field.
func formatBasicMatchField(field openflow.OXMField) string {
	switch int(field.Field) {
	case openflow.OFPXMTOFBInPort:
		if len(field.Value) == 4 {
			return fmt.Sprintf("in_port=%d", openflow.ByteOrder.Uint32(field.Value))
		}
	case openflow.OFPXMTOFBEthSrc:
		if len(field.Value) == 6 {
			return "dl_src=" + net.HardwareAddr(field.Value).String()
		}
	case openflow.OFPXMTOFBEthDst:
		if len(field.Value) == 6 {
			return "dl_dst=" + net.HardwareAddr(field.Value).String()
		}
	case openflow.OFPXMTOFBEthType:
		if len(field.Value) == 2 {
			return fmt.Sprintf("dl_type=0x%04x", openflow.ByteOrder.Uint16(field.Value))
		}
	case openflow.OFPXMTOFBVlanVid:
		if len(field.Value) == 2 && field.HasMask && len(field.Mask) == 2 {
			return fmt.Sprintf("vlan_vid=0x%x/0x%x", openflow.ByteOrder.Uint16(field.Value), openflow.ByteOrder.Uint16(field.Mask))
		}
		if len(field.Value) == 2 {
			// Strip OFPVID_PRESENT (bit 12) to recover the VLAN ID.
			return fmt.Sprintf("dl_vlan=%d", openflow.ByteOrder.Uint16(field.Value)&0x0fff)
		}
	case openflow.OFPXMTOFBIPv4Src:
		if len(field.Value) == 4 {
			return "nw_src=" + formatIPv4Field(field)
		}
	case openflow.OFPXMTOFBIPv4Dst:
		if len(field.Value) == 4 {
			return "nw_dst=" + formatIPv4Field(field)
		}
	case openflow.OFPXMTOFBIPProto:
		if len(field.Value) == 1 {
			return fmt.Sprintf("nw_proto=%d", field.Value[0])
		}
	case openflow.OFPXMTOFBTCPSrc, openflow.OFPXMTOFBUDPSrc:
		if len(field.Value) == 2 {
			return fmt.Sprintf("tp_src=%d", openflow.ByteOrder.Uint16(field.Value))
		}
	case openflow.OFPXMTOFBTCPDst, openflow.OFPXMTOFBUDPDst:
		if len(field.Value) == 2 {
			return fmt.Sprintf("tp_dst=%d", openflow.ByteOrder.Uint16(field.Value))
		}
	case openflow.OFPXMTOFBICMPv4Type, openflow.OFPXMTOFBICMPv6Type:
		if len(field.Value) == 1 {
			return fmt.Sprintf("icmp_type=%d", field.Value[0])
		}
	case openflow.OFPXMTOFBICMPv4Code, openflow.OFPXMTOFBICMPv6Code:
		if len(field.Value) == 1 {
			return fmt.Sprintf("icmp_code=%d", field.Value[0])
		}
	case openflow.OFPXMTOFBIPv6Src, openflow.OFPXMTOFBIPv6Dst:
		if len(field.Value) == 16 {
			name := "ipv6_src="
			if field.Field == openflow.OFPXMTOFBIPv6Dst {
				name = "ipv6_dst="
			}
			addr := netip.AddrFrom16([16]byte(field.Value))
			if field.HasMask && len(field.Mask) == 16 {
				ones, _ := net.IPMask(field.Mask).Size()
				return name + netip.PrefixFrom(addr, ones).String()
			}
			return name + addr.String()
		}
	}
	return ""
}

// formatNXMMatchField renders an OFPXMC_NXM_1 (conntrack extension) field.
func formatNXMMatchField(field openflow.OXMField) string {
	switch field.Field {
	case openflow.NXMFieldCTState:
		if len(field.Value) == openflow.CTStateLength {
			value := openflow.ByteOrder.Uint32(field.Value)
			mask := value
			if field.HasMask && len(field.Mask) == openflow.CTStateLength {
				mask = openflow.ByteOrder.Uint32(field.Mask)
			}
			return "ct_state=" + formatCTState(value, mask)
		}
	case openflow.NXMFieldCTZone:
		if len(field.Value) == openflow.CTZoneLength {
			return fmt.Sprintf("ct_zone=%d", openflow.ByteOrder.Uint16(field.Value))
		}
	case openflow.NXMFieldCTMark:
		if len(field.Value) == openflow.CTMarkLength {
			mark := fmt.Sprintf("ct_mark=0x%x", openflow.ByteOrder.Uint32(field.Value))
			if field.HasMask && len(field.Mask) == openflow.CTMarkLength {
				mark += fmt.Sprintf("/0x%x", openflow.ByteOrder.Uint32(field.Mask))
			}
			return mark
		}
	default:
		if field.Field < openflow.NXRegCount && len(field.Value) == 4 {
			reg := fmt.Sprintf("reg%d=0x%x", field.Field, openflow.ByteOrder.Uint32(field.Value))
			if field.HasMask && len(field.Mask) == 4 {
				reg += fmt.Sprintf("/0x%x", openflow.ByteOrder.Uint32(field.Mask))
			}
			return reg
		}
	}
	return ""
}

// parseActionsString parses ovs-ofctl style actions string into OpenFlow
// actions, discarding any trailing goto_table instruction. Callers that need
// the goto-table target use parseActions directly.
func parseActionsString(actionsStr string) ([]openflow.Action, error) {
	actions, _, err := parseActions(actionsStr)
	return actions, err
}

// parseActions parses an ovs-ofctl style actions string into OpenFlow
// actions plus an optional goto-table instruction target. Splitting honors
// parentheses so composite actions such as ct(commit,zone=5) survive intact.
func parseActions(actionsStr string) ([]openflow.Action, *uint8, error) {
	var actions []openflow.Action
	var gotoTable *uint8

	parts := splitTopLevel(actionsStr)
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Normalize to uppercase for keyword comparison
		upperPart := strings.ToUpper(part)

		switch {
		case upperPart == "DROP":
			// DROP means no actions
			return []openflow.Action{}, nil, nil

		case upperPart == "NORMAL":
			actions = append(actions, openflow.NewActionOutput(openflow.OFPPNormal, 0))

		case upperPart == "FLOOD":
			actions = append(actions, openflow.NewActionOutput(openflow.OFPPFlood, 0))

		case upperPart == "ALL":
			actions = append(actions, openflow.NewActionOutput(openflow.OFPPAll, 0))

		case upperPart == "CONTROLLER":
			actions = append(actions, openflow.NewActionOutput(openflow.OFPPController, 65535))

		case upperPart == "LOCAL":
			actions = append(actions, openflow.NewActionOutput(openflow.OFPPLocal, 0))

		case upperPart == "IN_PORT":
			actions = append(actions, openflow.NewActionOutput(openflow.OFPPInPort, 0))

		case strings.HasPrefix(part, "output:"):
			portStr := strings.TrimPrefix(part, "output:")
			port, err := strconv.ParseUint(portStr, 10, 32)
			if err != nil {
				return nil, nil, &MessageError{Msg: fmt.Sprintf("invalid output port: %s", portStr)}
			}
			actions = append(actions, openflow.NewActionOutput(uint32(port), 0))

		case strings.HasPrefix(part, "mod_vlan_vid:"):
			vlanStr := strings.TrimPrefix(part, "mod_vlan_vid:")
			vlan, err := strconv.ParseUint(vlanStr, 10, 16)
			if err != nil {
				return nil, nil, &MessageError{Msg: fmt.Sprintf("invalid VLAN ID: %s", vlanStr)}
			}
			// Push VLAN if not already present, then set VID
			actions = append(actions, openflow.NewActionPushVLAN(0x8100))
			value := make([]byte, 2)
			openflow.ByteOrder.PutUint16(value, uint16(vlan)|0x1000) // Set OFPVID_PRESENT
			actions = append(actions, openflow.NewActionSetField(
				openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBVlanVid, value))

		case upperPart == "STRIP_VLAN":
			actions = append(actions, openflow.NewActionPopVLAN())

		case strings.HasPrefix(part, "mod_dl_src:"):
			macStr := strings.TrimPrefix(part, "mod_dl_src:")
			mac, err := net.ParseMAC(macStr)
			if err != nil {
				return nil, nil, &MessageError{Msg: fmt.Sprintf("invalid MAC: %s", macStr)}
			}
			actions = append(actions, openflow.NewActionSetField(
				openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBEthSrc, mac))

		case strings.HasPrefix(part, "mod_dl_dst:"):
			macStr := strings.TrimPrefix(part, "mod_dl_dst:")
			mac, err := net.ParseMAC(macStr)
			if err != nil {
				return nil, nil, &MessageError{Msg: fmt.Sprintf("invalid MAC: %s", macStr)}
			}
			actions = append(actions, openflow.NewActionSetField(
				openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBEthDst, mac))

		case strings.HasPrefix(part, "mod_nw_src:"):
			ipStr := strings.TrimPrefix(part, "mod_nw_src:")
			ip := net.ParseIP(ipStr)
			if ip == nil {
				return nil, nil, &MessageError{Msg: fmt.Sprintf("invalid IP: %s", ipStr)}
			}
			actions = append(actions, openflow.NewActionSetField(
				openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBIPv4Src, ip.To4()))

		case strings.HasPrefix(part, "mod_nw_dst:"):
			ipStr := strings.TrimPrefix(part, "mod_nw_dst:")
			ip := net.ParseIP(ipStr)
			if ip == nil {
				return nil, nil, &MessageError{Msg: fmt.Sprintf("invalid IP: %s", ipStr)}
			}
			actions = append(actions, openflow.NewActionSetField(
				openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBIPv4Dst, ip.To4()))

		case strings.HasPrefix(part, "ct("):
			ct, err := parseCTAction(part)
			if err != nil {
				return nil, nil, err
			}
			actions = append(actions, ct)

		case strings.HasPrefix(part, "group:"):
			groupStr := strings.TrimPrefix(part, "group:")
			group, err := strconv.ParseUint(groupStr, 10, 32)
			if err != nil {
				return nil, nil, &MessageError{Msg: fmt.Sprintf("invalid group: %s", groupStr)}
			}
			actions = append(actions, openflow.NewActionGroup(uint32(group)))

		case strings.HasPrefix(part, "goto_table:"):
			tableStr := strings.TrimPrefix(part, "goto_table:")
			table, err := strconv.ParseUint(tableStr, 10, 8)
			if err != nil {
				return nil, nil, &MessageError{Msg: fmt.Sprintf("invalid goto_table: %s", tableStr)}
			}
			target := uint8(table)
			gotoTable = &target

		case strings.HasPrefix(part, "load:"):
			load, err := parseRegLoad(part)
			if err != nil {
				return nil, nil, err
			}
			actions = append(actions, load)

		case strings.HasPrefix(part, "resubmit("):
			resubmit, err := parseResubmit(part)
			if err != nil {
				return nil, nil, err
			}
			actions = append(actions, resubmit)

		case strings.HasPrefix(part, "set_field:"):
			setField, err := parseSetField(part)
			if err != nil {
				return nil, nil, err
			}
			actions = append(actions, setField)

		default:
			// An action this grammar does not know must not be dropped:
			// the flow would do less than it was written to.
			return nil, nil, &MessageError{Msg: fmt.Sprintf("unsupported action: %s", part)}
		}
	}

	return actions, gotoTable, nil
}

// parseRegLoad parses "load:VALUE->DST[RANGE]" where DST is NXM_NX_REGn or
// regN and RANGE is empty (the whole register), "k" (one bit) or "a..b".
func parseRegLoad(spec string) (*openflow.ActionRegLoad, error) {
	valueStr, dst, ok := strings.Cut(strings.TrimPrefix(spec, "load:"), "->")
	if !ok {
		return nil, &MessageError{Msg: fmt.Sprintf("invalid load (want load:VALUE->REG[RANGE]): %s", spec)}
	}
	value, err := strconv.ParseUint(valueStr, 0, 64)
	if err != nil {
		return nil, &MessageError{Msg: fmt.Sprintf("invalid load value: %s", valueStr)}
	}
	name, rangeSpec, ok := strings.Cut(dst, "[")
	if !ok || !strings.HasSuffix(rangeSpec, "]") {
		return nil, &MessageError{Msg: fmt.Sprintf("invalid load destination: %s", dst)}
	}
	index, ok := regIndex(strings.ToLower(strings.TrimPrefix(name, "NXM_NX_")))
	if !ok {
		return nil, &MessageError{Msg: fmt.Sprintf("unsupported load destination: %s", name)}
	}
	offset, nbits, err := parseBitRange(strings.TrimSuffix(rangeSpec, "]"), openflow.NXRegBits)
	if err != nil {
		return nil, err
	}
	return openflow.NewActionRegLoad(index, offset, nbits, value)
}

// parseBitRange parses an NXM bit range: "" (all width bits), "k" or
// "a..b".
func parseBitRange(spec string, width int) (uint16, uint16, error) {
	if spec == "" {
		return 0, uint16(width), nil
	}
	startStr, endStr, isRange := strings.Cut(spec, "..")
	start, err := strconv.ParseUint(startStr, 10, 8)
	if err != nil {
		return 0, 0, &MessageError{Msg: fmt.Sprintf("invalid bit range: %s", spec)}
	}
	end := start
	if isRange {
		end, err = strconv.ParseUint(endStr, 10, 8)
		if err != nil || end < start {
			return 0, 0, &MessageError{Msg: fmt.Sprintf("invalid bit range: %s", spec)}
		}
	}
	return uint16(start), uint16(end - start + 1), nil
}

// parseResubmit parses "resubmit(PORT,TABLE)" where PORT is empty or
// in_port (the packet's own) or a number below 0xff00.
func parseResubmit(spec string) (*openflow.ActionResubmit, error) {
	inner, ok := strings.CutSuffix(strings.TrimPrefix(spec, "resubmit("), ")")
	if !ok {
		return nil, &MessageError{Msg: fmt.Sprintf("invalid resubmit: %s", spec)}
	}
	portStr, tableStr, ok := strings.Cut(inner, ",")
	if !ok || tableStr == "" {
		return nil, &MessageError{Msg: fmt.Sprintf("resubmit needs a table (resubmit(,T)): %s", spec)}
	}
	table, err := strconv.ParseUint(tableStr, 10, 8)
	if err != nil || table == 0xff {
		return nil, &MessageError{Msg: fmt.Sprintf("invalid resubmit table: %s", tableStr)}
	}
	action := openflow.NewActionResubmit(uint8(table))
	if portStr != "" && portStr != "in_port" {
		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil || port >= 0xff00 {
			return nil, &MessageError{Msg: fmt.Sprintf("invalid resubmit port: %s", portStr)}
		}
		action.InPort = uint16(port)
	}
	return action, nil
}

// setFieldParser turns a set_field value into the OXM field it writes.
type setFieldParser func(value string) (uint8, []byte, error)

// setFieldParsers are the set_field destinations the grammar accepts.
var setFieldParsers = map[string]setFieldParser{
	"eth_src":  macSetField(openflow.OFPXMTOFBEthSrc),
	"eth_dst":  macSetField(openflow.OFPXMTOFBEthDst),
	"ip_src":   ipv4SetField(openflow.OFPXMTOFBIPv4Src),
	"ip_dst":   ipv4SetField(openflow.OFPXMTOFBIPv4Dst),
	"nw_src":   ipv4SetField(openflow.OFPXMTOFBIPv4Src),
	"nw_dst":   ipv4SetField(openflow.OFPXMTOFBIPv4Dst),
	"ipv4_src": ipv4SetField(openflow.OFPXMTOFBIPv4Src),
	"ipv4_dst": ipv4SetField(openflow.OFPXMTOFBIPv4Dst),
}

// macSetField parses a MAC for an Ethernet address field.
func macSetField(field uint8) setFieldParser {
	return func(value string) (uint8, []byte, error) {
		mac, err := net.ParseMAC(value)
		if err != nil {
			return 0, nil, &MessageError{Msg: fmt.Sprintf("invalid MAC: %s", value)}
		}
		return field, mac, nil
	}
}

// ipv4SetField parses an IPv4 address for an IPv4 address field.
func ipv4SetField(field uint8) setFieldParser {
	return func(value string) (uint8, []byte, error) {
		addr, err := netip.ParseAddr(value)
		if err != nil || !addr.Is4() {
			return 0, nil, &MessageError{Msg: fmt.Sprintf("invalid IPv4 address: %s", value)}
		}
		b := addr.As4()
		return field, b[:], nil
	}
}

// parseSetField parses "set_field:VALUE->FIELD".
func parseSetField(spec string) (*openflow.ActionSetField, error) {
	value, fieldName, ok := strings.Cut(strings.TrimPrefix(spec, "set_field:"), "->")
	if !ok {
		return nil, &MessageError{Msg: fmt.Sprintf("invalid set_field (want set_field:VALUE->FIELD): %s", spec)}
	}
	parse, ok := setFieldParsers[fieldName]
	if !ok {
		return nil, &MessageError{Msg: fmt.Sprintf("unsupported set_field destination: %s", fieldName)}
	}
	field, b, err := parse(value)
	if err != nil {
		return nil, err
	}
	return openflow.NewActionSetField(openflow.OFPXMCOpenflowBasic, field, b), nil
}

// splitTopLevel splits a comma-separated action list on commas that are not
// nested inside parentheses, preserving composite actions like
// ct(commit,zone=5,nat(src=192.0.2.1)) as single tokens.
func splitTopLevel(s string) []string {
	var parts []string
	depth := 0
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				parts = append(parts, s[start:i])
				start = i + 1
			}
		}
	}
	parts = append(parts, s[start:])
	return parts
}

// parseCTAction parses a ct(...) action specification into an OpenFlow
// conntrack action. Supported arguments: commit, table=N, zone=N, bare nat
// (apply the zone's committed NAT state to tracked packets),
// nat(src=IP[-IP][:pmin-pmax]), and nat(dst=IP[:port]).
func parseCTAction(spec string) (*openflow.ActionCT, error) {
	if !strings.HasPrefix(spec, "ct(") || !strings.HasSuffix(spec, ")") {
		return nil, &MessageError{Msg: fmt.Sprintf("invalid ct action: %s", spec)}
	}

	action := &openflow.ActionCT{RecircTable: openflow.CTRecircNone}

	inner := spec[len("ct(") : len(spec)-1]
	if inner == "" {
		return action, nil
	}

	for _, arg := range splitTopLevel(inner) {
		arg = strings.TrimSpace(arg)
		switch {
		case arg == "commit":
			action.Flags |= openflow.NXCTFCommit

		case arg == "nat":
			// Bare nat: no flags or range. OVS applies the NAT state
			// already committed for this connection in the ct zone,
			// translating established and reply-direction packets.
			action.Actions = append(action.Actions, &openflow.ActionNAT{})

		case strings.HasPrefix(arg, "table="):
			table, err := strconv.ParseUint(strings.TrimPrefix(arg, "table="), 10, 8)
			if err != nil {
				return nil, &MessageError{Msg: fmt.Sprintf("invalid ct table: %s", arg)}
			}
			action.RecircTable = uint8(table)

		case strings.HasPrefix(arg, "zone="):
			zone, err := strconv.ParseUint(strings.TrimPrefix(arg, "zone="), 10, 16)
			if err != nil {
				return nil, &MessageError{Msg: fmt.Sprintf("invalid ct zone: %s", arg)}
			}
			action.Zone = uint16(zone)

		case strings.HasPrefix(arg, "nat("):
			nat, err := parseNATAction(arg)
			if err != nil {
				return nil, err
			}
			action.Actions = append(action.Actions, nat)

		default:
			return nil, &MessageError{Msg: fmt.Sprintf("unsupported ct argument: %s", arg)}
		}
	}

	return action, nil
}

// parseNATAction parses a nat(...) specification nested inside a ct action.
// Grammar: nat(src=IP[-IP][:pmin-pmax]) for source NAT and nat(dst=IP[:port])
// for destination NAT. IPv4 only, matching the encoder.
func parseNATAction(spec string) (*openflow.ActionNAT, error) {
	if !strings.HasPrefix(spec, "nat(") || !strings.HasSuffix(spec, ")") {
		return nil, &MessageError{Msg: fmt.Sprintf("invalid nat action: %s", spec)}
	}

	inner := spec[len("nat(") : len(spec)-1]
	dir, value, ok := strings.Cut(inner, "=")
	if !ok || value == "" {
		return nil, &MessageError{Msg: fmt.Sprintf("invalid nat argument: %s", spec)}
	}

	addrPart, portPart, hasPorts := strings.Cut(value, ":")

	switch dir {
	case "src":
		minStr, maxStr, hasRange := strings.Cut(addrPart, "-")
		minAddr, err := parseNATAddr(minStr)
		if err != nil {
			return nil, err
		}
		maxAddr := netip.Addr{}
		if hasRange {
			maxAddr, err = parseNATAddr(maxStr)
			if err != nil {
				return nil, err
			}
		}
		var pmin, pmax uint16
		if hasPorts {
			pmin, pmax, err = parseNATPortRange(portPart)
			if err != nil {
				return nil, err
			}
		}
		return openflow.NewActionNATSrc(minAddr, maxAddr, pmin, pmax), nil

	case "dst":
		addr, err := parseNATAddr(addrPart)
		if err != nil {
			return nil, err
		}
		var port uint16
		if hasPorts {
			p, err := strconv.ParseUint(portPart, 10, 16)
			if err != nil {
				return nil, &MessageError{Msg: fmt.Sprintf("invalid nat port: %s", portPart)}
			}
			port = uint16(p)
		}
		return openflow.NewActionNATDst(addr, port), nil
	}

	return nil, &MessageError{Msg: fmt.Sprintf("invalid nat direction: %s", dir)}
}

// parseNATAddr parses an IPv4 address for a NAT range endpoint.
func parseNATAddr(s string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(s)
	if err != nil || !addr.Is4() {
		return netip.Addr{}, &MessageError{Msg: fmt.Sprintf("invalid nat IPv4 address: %s", s)}
	}
	return addr, nil
}

// parseNATPortRange parses "pmin-pmax" or a single "pmin".
func parseNATPortRange(s string) (uint16, uint16, error) {
	minStr, maxStr, hasRange := strings.Cut(s, "-")
	pmin, err := strconv.ParseUint(minStr, 10, 16)
	if err != nil {
		return 0, 0, &MessageError{Msg: fmt.Sprintf("invalid nat port range: %s", s)}
	}
	pmax := pmin
	if hasRange {
		pmax, err = strconv.ParseUint(maxStr, 10, 16)
		if err != nil {
			return 0, 0, &MessageError{Msg: fmt.Sprintf("invalid nat port range: %s", s)}
		}
	}
	return uint16(pmin), uint16(pmax), nil
}

// parseCookie parses a cookie string (hex or decimal) into uint64
func parseCookie(s string) (uint64, error) {
	return parseHexOrDecimal(s)
}

// parseHexOrDecimal parses a string as hex (if prefixed with 0x) or decimal
func parseHexOrDecimal(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return strconv.ParseUint(s[2:], 16, 64)
	}
	return strconv.ParseUint(s, 10, 64)
}

// FlowMatchBuilder helps build flow match specifications
type FlowMatchBuilder struct {
	matches []string
}

// NewFlowMatchBuilder creates a new flow match builder
func NewFlowMatchBuilder() *FlowMatchBuilder {
	return &FlowMatchBuilder{
		matches: make([]string, 0),
	}
}

// InPort adds an input port match
func (b *FlowMatchBuilder) InPort(port string) *FlowMatchBuilder {
	b.matches = append(b.matches, fmt.Sprintf("in_port=%s", port))
	return b
}

// DLSrc adds a source MAC address match
func (b *FlowMatchBuilder) DLSrc(mac string) *FlowMatchBuilder {
	b.matches = append(b.matches, fmt.Sprintf("dl_src=%s", mac))
	return b
}

// DLDst adds a destination MAC address match
func (b *FlowMatchBuilder) DLDst(mac string) *FlowMatchBuilder {
	b.matches = append(b.matches, fmt.Sprintf("dl_dst=%s", mac))
	return b
}

// DLType adds an EtherType match
func (b *FlowMatchBuilder) DLType(etherType string) *FlowMatchBuilder {
	b.matches = append(b.matches, fmt.Sprintf("dl_type=%s", etherType))
	return b
}

// NWSrc adds a source IP address match
func (b *FlowMatchBuilder) NWSrc(ip string) *FlowMatchBuilder {
	b.matches = append(b.matches, fmt.Sprintf("nw_src=%s", ip))
	return b
}

// NWDst adds a destination IP address match
func (b *FlowMatchBuilder) NWDst(ip string) *FlowMatchBuilder {
	b.matches = append(b.matches, fmt.Sprintf("nw_dst=%s", ip))
	return b
}

// NWProto adds a protocol match
func (b *FlowMatchBuilder) NWProto(proto int) *FlowMatchBuilder {
	b.matches = append(b.matches, fmt.Sprintf("nw_proto=%d", proto))
	return b
}

// TPSrc adds a source transport port match
func (b *FlowMatchBuilder) TPSrc(port int) *FlowMatchBuilder {
	b.matches = append(b.matches, fmt.Sprintf("tp_src=%d", port))
	return b
}

// TPDst adds a destination transport port match
func (b *FlowMatchBuilder) TPDst(port int) *FlowMatchBuilder {
	b.matches = append(b.matches, fmt.Sprintf("tp_dst=%d", port))
	return b
}

// VLANTag adds a VLAN tag match
func (b *FlowMatchBuilder) VLANTag(vlan int) *FlowMatchBuilder {
	b.matches = append(b.matches, fmt.Sprintf("dl_vlan=%d", vlan))
	return b
}

// Build builds the final match string
func (b *FlowMatchBuilder) Build() string {
	return strings.Join(b.matches, ",")
}

// FlowActionBuilder helps build flow action specifications
type FlowActionBuilder struct {
	actions []string
}

// NewFlowActionBuilder creates a new flow action builder
func NewFlowActionBuilder() *FlowActionBuilder {
	return &FlowActionBuilder{
		actions: make([]string, 0),
	}
}

// Output adds an output action
func (b *FlowActionBuilder) Output(port string) *FlowActionBuilder {
	b.actions = append(b.actions, fmt.Sprintf("output:%s", port))
	return b
}

// Drop adds a drop action
func (b *FlowActionBuilder) Drop() *FlowActionBuilder {
	b.actions = append(b.actions, "drop")
	return b
}

// Normal forwards using normal L2/L3 switching
func (b *FlowActionBuilder) Normal() *FlowActionBuilder {
	b.actions = append(b.actions, "NORMAL")
	return b
}

// Flood forwards to all ports except input port
func (b *FlowActionBuilder) Flood() *FlowActionBuilder {
	b.actions = append(b.actions, "FLOOD")
	return b
}

// ModVLAN modifies the VLAN tag
func (b *FlowActionBuilder) ModVLAN(vlan int) *FlowActionBuilder {
	b.actions = append(b.actions, fmt.Sprintf("mod_vlan_vid:%d", vlan))
	return b
}

// StripVLAN removes the VLAN tag
func (b *FlowActionBuilder) StripVLAN() *FlowActionBuilder {
	b.actions = append(b.actions, "strip_vlan")
	return b
}

// SetDLSrc sets the source MAC address
func (b *FlowActionBuilder) SetDLSrc(mac string) *FlowActionBuilder {
	b.actions = append(b.actions, fmt.Sprintf("mod_dl_src:%s", mac))
	return b
}

// SetDLDst sets the destination MAC address
func (b *FlowActionBuilder) SetDLDst(mac string) *FlowActionBuilder {
	b.actions = append(b.actions, fmt.Sprintf("mod_dl_dst:%s", mac))
	return b
}

// SetNWSrc sets the source IP address
func (b *FlowActionBuilder) SetNWSrc(ip string) *FlowActionBuilder {
	b.actions = append(b.actions, fmt.Sprintf("mod_nw_src:%s", ip))
	return b
}

// SetNWDst sets the destination IP address
func (b *FlowActionBuilder) SetNWDst(ip string) *FlowActionBuilder {
	b.actions = append(b.actions, fmt.Sprintf("mod_nw_dst:%s", ip))
	return b
}

// Resubmit resubmits to another table
func (b *FlowActionBuilder) Resubmit(table int) *FlowActionBuilder {
	b.actions = append(b.actions, fmt.Sprintf("resubmit(,%d)", table))
	return b
}

// Build builds the final action string
func (b *FlowActionBuilder) Build() string {
	return strings.Join(b.actions, ",")
}
