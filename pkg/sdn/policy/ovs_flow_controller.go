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

package policy

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
)

// ovsClient is the part of *ovs.Client the flow controller drives.
type ovsClient interface {
	AddFlow(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error
	AddFlows(ctx context.Context, bridgeName string, flows []*ovs.FlowMod) error
	DeleteFlow(ctx context.Context, bridgeName string, match string) error
	ListFlows(ctx context.Context, bridgeName string) ([]*ovs.Flow, error)
	UpdatePort(ctx context.Context, name string, updates map[string]interface{}) error
	SetPortState(ctx context.Context, portName string, state ovs.PortState) error
	GetOFPort(ctx context.Context, portName string) (int32, error)
}

// OVSFlowController implements FlowController using an OVS client
type OVSFlowController struct {
	client  ovsClient
	timeout time.Duration
}

// NewOVSFlowController creates a new OVS flow controller
func NewOVSFlowController(client *ovs.Client) (*OVSFlowController, error) {
	if client == nil {
		return nil, ErrInvalidClient
	}

	return &OVSFlowController{
		client:  client,
		timeout: 30 * time.Second,
	}, nil
}

// SetTimeout sets the operation timeout
func (c *OVSFlowController) SetTimeout(timeout time.Duration) {
	c.timeout = timeout
}

// InstallFlow installs an OpenFlow rule
func (c *OVSFlowController) InstallFlow(bridgeName string, priority int, match string, actions string) error {
	if bridgeName == "" {
		return ErrInvalidBridgeName
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	// Create FlowMod for the rule
	flow := &ovs.FlowMod{
		Table:    0,
		Priority: priority,
		Match:    match,
		Actions:  actions,
	}

	if err := c.client.AddFlow(ctx, bridgeName, flow); err != nil {
		return &WrappedError{Msg: "failed to install flow", Err: err}
	}

	return nil
}

// InstallFlows installs a batch of OpenFlow rules in a single OpenFlow
// transaction (all flow mods followed by one barrier). An empty batch is a
// no-op. When the switch rejects individual rules the returned error wraps
// openflow.ErrBatchPartialFailure identifying the failed rules by index.
func (c *OVSFlowController) InstallFlows(bridgeName string, rules []zoneflows.FlowRule) error {
	if bridgeName == "" {
		return ErrInvalidBridgeName
	}
	if len(rules) == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	flows := make([]*ovs.FlowMod, 0, len(rules))
	for _, rule := range rules {
		flows = append(flows, &ovs.FlowMod{
			Table:    rule.Table,
			Priority: rule.Priority,
			Match:    rule.Match,
			Actions:  rule.Actions,
			Cookie:   rule.Cookie,
		})
	}

	if err := c.client.AddFlows(ctx, bridgeName, flows); err != nil {
		return &WrappedError{Msg: "failed to install flows", Err: err}
	}

	return nil
}

// DeleteFlow deletes OpenFlow rules matching the criteria
func (c *OVSFlowController) DeleteFlow(bridgeName string, match string) error {
	if bridgeName == "" {
		return ErrInvalidBridgeName
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	if err := c.client.DeleteFlow(ctx, bridgeName, match); err != nil {
		return &WrappedError{Msg: "failed to delete flow", Err: err}
	}

	return nil
}

// DeleteFlowsByPort deletes all flows for a specific port
func (c *OVSFlowController) DeleteFlowsByPort(bridgeName string, portID string) error {
	if bridgeName == "" {
		return ErrInvalidBridgeName
	}

	if portID == "" {
		return ErrInvalidPortID
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	// Build match string for port
	match := fmt.Sprintf("in_port=%s", portID)

	if err := c.client.DeleteFlow(ctx, bridgeName, match); err != nil {
		return &WrappedError{Msg: fmt.Sprintf("failed to delete flows for port %s", portID), Err: err}
	}

	return nil
}

// ListFlows returns all flows for a bridge
func (c *OVSFlowController) ListFlows(bridgeName string) ([]string, error) {
	if bridgeName == "" {
		return nil, ErrInvalidBridgeName
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	flows, err := c.client.ListFlows(ctx, bridgeName)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to list flows", Err: err}
	}

	// Convert flows to string representations
	result := make([]string, 0, len(flows))
	for _, flow := range flows {
		flowStr := formatFlow(flow)
		result = append(result, flowStr)
	}

	return result, nil
}

// SetPortVLAN makes a port an access port on vlan using OVSDB: tag=vlan,
// no trunks, vlan_mode=access, so a port that was a trunk becomes a clean
// access port (a quarantined trunk keeps none of its role's VLANs).
func (c *OVSFlowController) SetPortVLAN(ctx context.Context, portName string, vlan int64) error {
	if portName == "" {
		return ErrInvalidPortID
	}

	if vlan < 0 || vlan > 4095 {
		return ErrInvalidVLAN
	}

	updates := map[string]interface{}{
		"tag":       vlan,
		"trunks":    ovs.Set{Set: []interface{}{}},
		"vlan_mode": "access",
	}
	if err := c.client.UpdatePort(ctx, portName, updates); err != nil {
		return &WrappedError{Msg: fmt.Sprintf("failed to set VLAN for port %s", portName), Err: err}
	}

	return nil
}

// SetPortTrunk makes a port an 802.1Q trunk using OVSDB: trunks=allowed,
// and with a native VLAN tag=native, vlan_mode=native-untagged (untagged
// frames, such as a factory NIC's PXE, land on the native VLAN); without one
// the tag is cleared and vlan_mode=trunk.
func (c *OVSFlowController) SetPortTrunk(ctx context.Context, portName string, allowed []uint16, native uint16) error {
	if portName == "" {
		return ErrInvalidPortID
	}
	if len(allowed) == 0 {
		return ErrInvalidVLAN
	}
	trunks := make([]interface{}, len(allowed))
	for i, v := range allowed {
		if v < 1 || v > 4094 {
			return ErrInvalidVLAN
		}
		trunks[i] = int64(v)
	}
	if native > 4094 {
		return ErrInvalidVLAN
	}

	updates := map[string]interface{}{
		"trunks":    ovs.Set{Set: trunks},
		"tag":       ovs.Set{Set: []interface{}{}},
		"vlan_mode": "trunk",
	}
	if native != 0 {
		updates["tag"] = int64(native)
		updates["vlan_mode"] = "native-untagged"
	}
	if err := c.client.UpdatePort(ctx, portName, updates); err != nil {
		return &WrappedError{Msg: fmt.Sprintf("failed to set trunk for port %s", portName), Err: err}
	}
	return nil
}

// SetPortState sets the admin state of a port (up/down) which can be used to block ports
func (c *OVSFlowController) SetPortState(ctx context.Context, portName string, state ovs.PortState) error {
	if portName == "" {
		return ErrInvalidPortID
	}

	if err := c.client.SetPortState(ctx, portName, state); err != nil {
		return &WrappedError{Msg: fmt.Sprintf("failed to set port state for %s", portName), Err: err}
	}

	return nil
}

// GetOFPort retrieves the OpenFlow port number for a port name
func (c *OVSFlowController) GetOFPort(ctx context.Context, portName string) (int32, error) {
	if portName == "" {
		return 0, ErrInvalidPortID
	}

	ofPort, err := c.client.GetOFPort(ctx, portName)
	if err != nil {
		return 0, &WrappedError{Msg: fmt.Sprintf("failed to get OF port for %s", portName), Err: err}
	}

	return ofPort, nil
}

// formatFlow formats a Flow into a string representation
func formatFlow(flow *ovs.Flow) string {
	var parts []string

	parts = append(parts, fmt.Sprintf("table=%d", flow.Table))
	parts = append(parts, fmt.Sprintf("priority=%d", flow.Priority))

	if flow.Match != "" {
		parts = append(parts, flow.Match)
	}

	if flow.Cookie != "" {
		parts = append(parts, fmt.Sprintf("cookie=%s", flow.Cookie))
	}

	if flow.Duration > 0 {
		parts = append(parts, fmt.Sprintf("duration=%ds", flow.Duration))
	}

	if flow.IdleAge > 0 {
		parts = append(parts, fmt.Sprintf("idle_age=%ds", flow.IdleAge))
	}

	if flow.PacketCount > 0 {
		parts = append(parts, fmt.Sprintf("n_packets=%d", flow.PacketCount))
	}

	if flow.ByteCount > 0 {
		parts = append(parts, fmt.Sprintf("n_bytes=%d", flow.ByteCount))
	}

	if flow.Actions != "" {
		parts = append(parts, fmt.Sprintf("actions=%s", flow.Actions))
	}

	return strings.Join(parts, ",")
}
