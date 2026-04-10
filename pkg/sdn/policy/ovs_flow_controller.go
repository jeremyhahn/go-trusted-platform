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
)

// OVSFlowController implements FlowController using an OVS client
type OVSFlowController struct {
	client  *ovs.Client
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
		return fmt.Errorf("failed to install flow: %w", err)
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
		return fmt.Errorf("failed to delete flow: %w", err)
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
		return fmt.Errorf("failed to delete flows for port %s: %w", portID, err)
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
		return nil, fmt.Errorf("failed to list flows: %w", err)
	}

	// Convert flows to string representations
	result := make([]string, 0, len(flows))
	for _, flow := range flows {
		flowStr := formatFlow(flow)
		result = append(result, flowStr)
	}

	return result, nil
}

// SetPortVLAN sets the VLAN tag for a port using OVSDB
func (c *OVSFlowController) SetPortVLAN(ctx context.Context, portName string, vlan int64) error {
	if portName == "" {
		return ErrInvalidPortID
	}

	if vlan < 0 || vlan > 4095 {
		return ErrInvalidVLAN
	}

	if err := c.client.SetPortVLAN(ctx, portName, vlan); err != nil {
		return fmt.Errorf("failed to set VLAN for port %s: %w", portName, err)
	}

	return nil
}

// SetPortState sets the admin state of a port (up/down) which can be used to block ports
func (c *OVSFlowController) SetPortState(ctx context.Context, portName string, state ovs.PortState) error {
	if portName == "" {
		return ErrInvalidPortID
	}

	if err := c.client.SetPortState(ctx, portName, state); err != nil {
		return fmt.Errorf("failed to set port state for %s: %w", portName, err)
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
		return 0, fmt.Errorf("failed to get OF port for %s: %w", portName, err)
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
