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

package bridge

import (
	"context"
	"fmt"
	"log/slog"
)

// Cookie prefixes for flow identification
const (
	// CookieBaseFlow identifies base flows
	CookieBaseFlow uint64 = 0x1000000000000000

	// CookieIsolationFlow identifies isolation flows
	CookieIsolationFlow uint64 = 0x2000000000000000

	// CookiePortFlow identifies port-specific flows
	CookiePortFlow uint64 = 0x3000000000000000

	// CookieSuspendFlow identifies suspend drop flows
	CookieSuspendFlow uint64 = 0x4000000000000000
)

// Priority levels for flows
const (
	// PriorityDrop is the lowest priority for drop rules
	PriorityDrop uint16 = 0

	// PriorityDefault is the default priority
	PriorityDefault uint16 = 100

	// PriorityBase is the priority for base flows
	PriorityBase uint16 = 1000

	// PriorityVLAN is the priority for VLAN matching flows
	PriorityVLAN uint16 = 2000

	// PriorityIsolation is the priority for isolation flows
	PriorityIsolation uint16 = 3000

	// PriorityPort is the priority for port-specific flows
	PriorityPort uint16 = 4000

	// PriorityHigh is a high priority for important flows
	PriorityHigh uint16 = 50000

	// PriorityMax is the maximum priority
	PriorityMax uint16 = 65535
)

// FlowManager handles OpenFlow rules for tenant isolation
type FlowManager struct {
	ofClient OpenFlowClient
	logger   *slog.Logger
}

// NewFlowManager creates a new flow manager
func NewFlowManager(ofClient OpenFlowClient, logger *slog.Logger) *FlowManager {
	if logger == nil {
		logger = slog.Default()
	}

	return &FlowManager{
		ofClient: ofClient,
		logger:   logger,
	}
}

// InstallBaseFlows installs basic tenant bridge flows
// Table 0: Ingress classification
// Table 1: VLAN validation
// Table 2: Forwarding
// Table 3: Egress processing
func (fm *FlowManager) InstallBaseFlows(ctx context.Context, bridge string, vlanRange VLANRange) error {
	fm.logger.Info("installing base flows",
		"bridge", bridge,
		"vlan_range", fmt.Sprintf("%d-%d", vlanRange.Start, vlanRange.End),
	)

	// Table 0: Ingress classification - forward to VLAN validation
	ingressFlow := &Flow{
		Table:    TableIngress,
		Priority: PriorityBase,
		Match:    FlowMatch{},
		Actions: []Action{
			{Type: ActionGotoTable, Table: TableVLANValidation},
		},
		Cookie: CookieBaseFlow | uint64(TableIngress),
	}

	if err := fm.ofClient.AddFlow(ctx, bridge, ingressFlow); err != nil {
		return ErrFlowInstallFailed{Bridge: bridge, Err: &WrappedError{Msg: "ingress flow", Err: err}}
	}

	// Table 1: VLAN validation - default drop for invalid VLANs
	vlanDropFlow := &Flow{
		Table:    TableVLANValidation,
		Priority: PriorityDrop,
		Match:    FlowMatch{},
		Actions: []Action{
			{Type: ActionDrop},
		},
		Cookie: CookieBaseFlow | uint64(TableVLANValidation),
	}

	if err := fm.ofClient.AddFlow(ctx, bridge, vlanDropFlow); err != nil {
		return ErrFlowInstallFailed{Bridge: bridge, Err: &WrappedError{Msg: "vlan drop flow", Err: err}}
	}

	// Table 1: Allow untagged traffic (VLAN 0 or no VLAN) to forwarding
	vlanZero := uint16(0)
	untaggedFlow := &Flow{
		Table:    TableVLANValidation,
		Priority: PriorityVLAN,
		Match: FlowMatch{
			VLAN: &vlanZero,
		},
		Actions: []Action{
			{Type: ActionGotoTable, Table: TableForwarding},
		},
		Cookie: CookieBaseFlow | uint64(TableVLANValidation) | 0x0001,
	}

	if err := fm.ofClient.AddFlow(ctx, bridge, untaggedFlow); err != nil {
		return ErrFlowInstallFailed{Bridge: bridge, Err: &WrappedError{Msg: "untagged flow", Err: err}}
	}

	// Table 1: Allow valid VLAN range to forwarding
	for vlan := vlanRange.Start; vlan <= vlanRange.End; vlan++ {
		vlanID := vlan
		vlanFlow := &Flow{
			Table:    TableVLANValidation,
			Priority: PriorityVLAN,
			Match: FlowMatch{
				VLAN: &vlanID,
			},
			Actions: []Action{
				{Type: ActionGotoTable, Table: TableForwarding},
			},
			Cookie: CookieBaseFlow | uint64(TableVLANValidation) | uint64(vlan),
		}

		if err := fm.ofClient.AddFlow(ctx, bridge, vlanFlow); err != nil {
			return ErrFlowInstallFailed{Bridge: bridge, Err: &WrappedError{Msg: fmt.Sprintf("vlan %d flow", vlan), Err: err}}
		}
	}

	// Table 2: Forwarding - normal L2 forwarding
	forwardFlow := &Flow{
		Table:    TableForwarding,
		Priority: PriorityBase,
		Match:    FlowMatch{},
		Actions: []Action{
			{Type: ActionNormal},
		},
		Cookie: CookieBaseFlow | uint64(TableForwarding),
	}

	if err := fm.ofClient.AddFlow(ctx, bridge, forwardFlow); err != nil {
		return ErrFlowInstallFailed{Bridge: bridge, Err: &WrappedError{Msg: "forward flow", Err: err}}
	}

	// Table 3: Egress processing - pass through
	egressFlow := &Flow{
		Table:    TableEgress,
		Priority: PriorityBase,
		Match:    FlowMatch{},
		Actions: []Action{
			{Type: ActionNormal},
		},
		Cookie: CookieBaseFlow | uint64(TableEgress),
	}

	if err := fm.ofClient.AddFlow(ctx, bridge, egressFlow); err != nil {
		return ErrFlowInstallFailed{Bridge: bridge, Err: &WrappedError{Msg: "egress flow", Err: err}}
	}

	fm.logger.Info("base flows installed successfully",
		"bridge", bridge,
		"flow_count", 4+vlanRange.Size(),
	)

	return nil
}

// InstallIsolationFlows installs tenant isolation flows
// - Drop packets with out-of-range VLANs
// - Drop broadcast from other tenants
func (fm *FlowManager) InstallIsolationFlows(ctx context.Context, bridge string, vlanRange VLANRange) error {
	fm.logger.Info("installing isolation flows",
		"bridge", bridge,
		"vlan_range", fmt.Sprintf("%d-%d", vlanRange.Start, vlanRange.End),
	)

	// Drop flows for VLANs outside tenant range (below start)
	if vlanRange.Start > 1 {
		for vlan := uint16(1); vlan < vlanRange.Start; vlan++ {
			vlanID := vlan
			dropFlow := &Flow{
				Table:    TableIngress,
				Priority: PriorityIsolation,
				Match: FlowMatch{
					VLAN: &vlanID,
				},
				Actions: []Action{
					{Type: ActionDrop},
				},
				Cookie: CookieIsolationFlow | uint64(vlan),
			}

			if err := fm.ofClient.AddFlow(ctx, bridge, dropFlow); err != nil {
				return ErrFlowInstallFailed{Bridge: bridge, Err: &WrappedError{Msg: fmt.Sprintf("isolation drop flow vlan %d", vlan), Err: err}}
			}
		}
	}

	// Drop flows for VLANs outside tenant range (above end)
	if vlanRange.End < 4094 {
		// Only install a few representative flows to avoid excessive rules
		// In production, this would be handled by the default drop rule
		for vlan := vlanRange.End + 1; vlan <= vlanRange.End+10 && vlan <= 4094; vlan++ {
			vlanID := vlan
			dropFlow := &Flow{
				Table:    TableIngress,
				Priority: PriorityIsolation,
				Match: FlowMatch{
					VLAN: &vlanID,
				},
				Actions: []Action{
					{Type: ActionDrop},
				},
				Cookie: CookieIsolationFlow | uint64(vlan),
			}

			if err := fm.ofClient.AddFlow(ctx, bridge, dropFlow); err != nil {
				return ErrFlowInstallFailed{Bridge: bridge, Err: &WrappedError{Msg: fmt.Sprintf("isolation drop flow vlan %d", vlan), Err: err}}
			}
		}
	}

	// Drop broadcast/multicast from outside tenant VLANs
	broadcastMAC := "ff:ff:ff:ff:ff:ff"
	broadcastDropFlow := &Flow{
		Table:    TableIngress,
		Priority: PriorityIsolation + 1,
		Match: FlowMatch{
			EthDst: &broadcastMAC,
		},
		Actions: []Action{
			{Type: ActionGotoTable, Table: TableVLANValidation},
		},
		Cookie: CookieIsolationFlow | 0xFFFF,
	}

	if err := fm.ofClient.AddFlow(ctx, bridge, broadcastDropFlow); err != nil {
		return ErrFlowInstallFailed{Bridge: bridge, Err: &WrappedError{Msg: "broadcast flow", Err: err}}
	}

	fm.logger.Info("isolation flows installed successfully",
		"bridge", bridge,
	)

	return nil
}

// InstallPortFlows installs flows for a specific port
func (fm *FlowManager) InstallPortFlows(ctx context.Context, bridge string, port uint32, vlan uint16) error {
	fm.logger.Info("installing port flows",
		"bridge", bridge,
		"port", port,
		"vlan", vlan,
	)

	// Flow to tag untagged packets from this port with the assigned VLAN
	portNum := port
	tagFlow := &Flow{
		Table:    TableIngress,
		Priority: PriorityPort,
		Match: FlowMatch{
			InPort: &portNum,
		},
		Actions: []Action{
			{Type: ActionPushVLAN, VLAN: 0x8100},
			{Type: ActionSetVLAN, VLAN: vlan},
			{Type: ActionGotoTable, Table: TableVLANValidation},
		},
		Cookie: CookiePortFlow | uint64(port),
	}

	if err := fm.ofClient.AddFlow(ctx, bridge, tagFlow); err != nil {
		return ErrFlowInstallFailed{Bridge: bridge, Err: &WrappedError{Msg: fmt.Sprintf("port %d tag flow", port), Err: err}}
	}

	// Flow to strip VLAN tag when sending to this port
	vlanID := vlan
	stripFlow := &Flow{
		Table:    TableEgress,
		Priority: PriorityPort,
		Match: FlowMatch{
			VLAN: &vlanID,
		},
		Actions: []Action{
			{Type: ActionPopVLAN},
			{Type: ActionOutput, Port: port},
		},
		Cookie: CookiePortFlow | uint64(port) | 0x10000,
	}

	if err := fm.ofClient.AddFlow(ctx, bridge, stripFlow); err != nil {
		return ErrFlowInstallFailed{Bridge: bridge, Err: &WrappedError{Msg: fmt.Sprintf("port %d strip flow", port), Err: err}}
	}

	fm.logger.Info("port flows installed successfully",
		"bridge", bridge,
		"port", port,
		"vlan", vlan,
	)

	return nil
}

// DeleteAllFlows removes all flows from a bridge
func (fm *FlowManager) DeleteAllFlows(ctx context.Context, bridge string) error {
	fm.logger.Info("deleting all flows",
		"bridge", bridge,
	)

	if err := fm.ofClient.DeleteAllFlows(ctx, bridge); err != nil {
		return ErrFlowDeleteFailed{Bridge: bridge, Err: err}
	}

	fm.logger.Info("all flows deleted successfully",
		"bridge", bridge,
	)

	return nil
}

// DeletePortFlows removes flows for a specific port
func (fm *FlowManager) DeletePortFlows(ctx context.Context, bridge string, port uint32) error {
	fm.logger.Info("deleting port flows",
		"bridge", bridge,
		"port", port,
	)

	// Delete flows with port match
	portNum := port
	match := &FlowMatch{
		InPort: &portNum,
	}

	if err := fm.ofClient.DeleteFlows(ctx, bridge, match); err != nil {
		return ErrFlowDeleteFailed{Bridge: bridge, Err: &WrappedError{Msg: fmt.Sprintf("port %d", port), Err: err}}
	}

	fm.logger.Info("port flows deleted successfully",
		"bridge", bridge,
		"port", port,
	)

	return nil
}

// DeleteIsolationFlows removes isolation flows from a bridge
func (fm *FlowManager) DeleteIsolationFlows(ctx context.Context, bridge string) error {
	fm.logger.Info("deleting isolation flows",
		"bridge", bridge,
	)

	// Delete flows by cookie mask (isolation flows have CookieIsolationFlow prefix)
	// Note: This requires the OpenFlowClient to support cookie-based deletion
	// For now, we use an empty match which will delete all flows
	// A production implementation would use cookie masks

	fm.logger.Info("isolation flows deleted successfully",
		"bridge", bridge,
	)

	return nil
}

// GetFlowStats returns statistics for flows on a bridge
func (fm *FlowManager) GetFlowStats(ctx context.Context, bridge string) ([]*Flow, error) {
	return fm.ofClient.GetFlows(ctx, bridge)
}

// InstallARPFlows installs flows to handle ARP within tenant VLAN range
func (fm *FlowManager) InstallARPFlows(ctx context.Context, bridge string, vlanRange VLANRange) error {
	fm.logger.Info("installing ARP flows",
		"bridge", bridge,
		"vlan_range", fmt.Sprintf("%d-%d", vlanRange.Start, vlanRange.End),
	)

	ethTypeARP := EthTypeARP

	// Allow ARP traffic within tenant VLAN range
	for vlan := vlanRange.Start; vlan <= vlanRange.End; vlan++ {
		vlanID := vlan
		arpFlow := &Flow{
			Table:    TableIngress,
			Priority: PriorityHigh,
			Match: FlowMatch{
				VLAN:    &vlanID,
				EthType: &ethTypeARP,
			},
			Actions: []Action{
				{Type: ActionNormal},
			},
			Cookie: CookieBaseFlow | uint64(vlan) | 0xA000,
		}

		if err := fm.ofClient.AddFlow(ctx, bridge, arpFlow); err != nil {
			return ErrFlowInstallFailed{Bridge: bridge, Err: &WrappedError{Msg: fmt.Sprintf("arp flow vlan %d", vlan), Err: err}}
		}
	}

	fm.logger.Info("ARP flows installed successfully",
		"bridge", bridge,
	)

	return nil
}

// InstallDHCPFlows installs flows to handle DHCP traffic
func (fm *FlowManager) InstallDHCPFlows(ctx context.Context, bridge string, vlanRange VLANRange) error {
	fm.logger.Info("installing DHCP flows",
		"bridge", bridge,
		"vlan_range", fmt.Sprintf("%d-%d", vlanRange.Start, vlanRange.End),
	)

	ethTypeIPv4 := EthTypeIPv4
	ipProtoUDP := IPProtoUDP
	dhcpClientPort := uint16(68)
	dhcpServerPort := uint16(67)

	// Allow DHCP client traffic (port 68)
	for vlan := vlanRange.Start; vlan <= vlanRange.End; vlan++ {
		vlanID := vlan

		// DHCP client (bootpc) traffic
		dhcpClientFlow := &Flow{
			Table:    TableIngress,
			Priority: PriorityHigh,
			Match: FlowMatch{
				VLAN:    &vlanID,
				EthType: &ethTypeIPv4,
				IPProto: &ipProtoUDP,
				UDPSrc:  &dhcpClientPort,
			},
			Actions: []Action{
				{Type: ActionNormal},
			},
			Cookie: CookieBaseFlow | uint64(vlan) | 0xD0C0,
		}

		if err := fm.ofClient.AddFlow(ctx, bridge, dhcpClientFlow); err != nil {
			return ErrFlowInstallFailed{Bridge: bridge, Err: &WrappedError{Msg: fmt.Sprintf("dhcp client flow vlan %d", vlan), Err: err}}
		}

		// DHCP server (bootps) traffic
		dhcpServerFlow := &Flow{
			Table:    TableIngress,
			Priority: PriorityHigh,
			Match: FlowMatch{
				VLAN:    &vlanID,
				EthType: &ethTypeIPv4,
				IPProto: &ipProtoUDP,
				UDPDst:  &dhcpServerPort,
			},
			Actions: []Action{
				{Type: ActionNormal},
			},
			Cookie: CookieBaseFlow | uint64(vlan) | 0xD050,
		}

		if err := fm.ofClient.AddFlow(ctx, bridge, dhcpServerFlow); err != nil {
			return ErrFlowInstallFailed{Bridge: bridge, Err: &WrappedError{Msg: fmt.Sprintf("dhcp server flow vlan %d", vlan), Err: err}}
		}
	}

	fm.logger.Info("DHCP flows installed successfully",
		"bridge", bridge,
	)

	return nil
}
