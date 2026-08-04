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

// GetFlowStats returns statistics for flows matching the criteria using native OpenFlow protocol.
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

	// Build match for flow stats request
	ofMatch := openflow.NewMatch()
	if match != "" {
		if err := parseMatchString(ofMatch, match); err != nil {
			return nil, &WrappedError{Msg: "failed to parse match", Err: err}
		}
	}

	stats, err := ofClient.GetFlowStats(ctx, ofMatch)
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

// convertToOpenFlow converts an OVS FlowMod to an OpenFlow FlowMod
func convertToOpenFlow(flow *FlowMod) (*openflow.FlowMod, error) {
	ofFlow := openflow.NewFlowMod(0)
	ofFlow.TableID = uint8(flow.Table)
	ofFlow.Priority = uint16(flow.Priority)
	ofFlow.IdleTimeout = uint16(flow.IdleTimeout)
	ofFlow.HardTimeout = uint16(flow.HardTimeout)

	// Parse cookie
	if flow.Cookie != "" {
		cookie, err := parseCookie(flow.Cookie)
		if err == nil {
			ofFlow.Cookie = cookie
		}
	}

	// Parse match string
	if flow.Match != "" {
		if err := parseMatchString(ofFlow.Match, flow.Match); err != nil {
			return nil, &WrappedError{Msg: "failed to parse match", Err: err}
		}
	}

	// Parse actions string
	if flow.Actions != "" {
		actions, err := parseActionsString(flow.Actions)
		if err != nil {
			return nil, &WrappedError{Msg: "failed to parse actions", Err: err}
		}
		if len(actions) > 0 {
			ofFlow.Instructions = append(ofFlow.Instructions,
				openflow.NewInstructionApplyActions(actions...))
		}
	}

	return ofFlow, nil
}

// parseMatchString parses ovs-ofctl style match string into OpenFlow match
func parseMatchString(match *openflow.Match, matchStr string) error {
	// Parse key=value pairs from match string
	parts := strings.Split(matchStr, ",")

	// First pass: extract protocol to determine TCP vs UDP for port matching
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
	}

	// Second pass: parse all fields
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
		}
	}

	return nil
}

// parseActionsString parses ovs-ofctl style actions string into OpenFlow actions
func parseActionsString(actionsStr string) ([]openflow.Action, error) {
	var actions []openflow.Action

	parts := strings.Split(actionsStr, ",")
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
			return []openflow.Action{}, nil

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
				return nil, &MessageError{Msg: fmt.Sprintf("invalid output port: %s", portStr)}
			}
			actions = append(actions, openflow.NewActionOutput(uint32(port), 0))

		case strings.HasPrefix(part, "mod_vlan_vid:"):
			vlanStr := strings.TrimPrefix(part, "mod_vlan_vid:")
			vlan, err := strconv.ParseUint(vlanStr, 10, 16)
			if err != nil {
				return nil, &MessageError{Msg: fmt.Sprintf("invalid VLAN ID: %s", vlanStr)}
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
				return nil, &MessageError{Msg: fmt.Sprintf("invalid MAC: %s", macStr)}
			}
			actions = append(actions, openflow.NewActionSetField(
				openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBEthSrc, mac))

		case strings.HasPrefix(part, "mod_dl_dst:"):
			macStr := strings.TrimPrefix(part, "mod_dl_dst:")
			mac, err := net.ParseMAC(macStr)
			if err != nil {
				return nil, &MessageError{Msg: fmt.Sprintf("invalid MAC: %s", macStr)}
			}
			actions = append(actions, openflow.NewActionSetField(
				openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBEthDst, mac))

		case strings.HasPrefix(part, "mod_nw_src:"):
			ipStr := strings.TrimPrefix(part, "mod_nw_src:")
			ip := net.ParseIP(ipStr)
			if ip == nil {
				return nil, &MessageError{Msg: fmt.Sprintf("invalid IP: %s", ipStr)}
			}
			actions = append(actions, openflow.NewActionSetField(
				openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBIPv4Src, ip.To4()))

		case strings.HasPrefix(part, "mod_nw_dst:"):
			ipStr := strings.TrimPrefix(part, "mod_nw_dst:")
			ip := net.ParseIP(ipStr)
			if ip == nil {
				return nil, &MessageError{Msg: fmt.Sprintf("invalid IP: %s", ipStr)}
			}
			actions = append(actions, openflow.NewActionSetField(
				openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBIPv4Dst, ip.To4()))
		}
	}

	return actions, nil
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
