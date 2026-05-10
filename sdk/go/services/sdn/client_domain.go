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
	"context"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
)

// Domain-typed convenience methods
//
// These methods accept domain types instead of proto types, enabling callers
// to avoid importing platformv1 directly.

// CreateBridgeDomain creates a new bridge using domain types.
func (c *Client) CreateBridgeDomain(ctx context.Context, config *BridgeConfig) (*platformv1.Bridge, error) {
	return c.CreateBridge(ctx, BridgeConfigToProto(config))
}

// ListBridgesDomain lists bridges using domain types for filtering.
func (c *Client) ListBridgesDomain(ctx context.Context, selector *LabelSelector, pageSize uint32) ([]*platformv1.Bridge, *common.PageResult, error) {
	return c.ListBridges(ctx, LabelSelectorToProto(selector), PaginationToProto(pageSize))
}

// DeleteBridgeDomain deletes a bridge, optionally flushing flows first.
func (c *Client) DeleteBridgeDomain(ctx context.Context, bridgeID string, force bool, flushFlows bool) error {
	if flushFlows {
		_, flushErr := c.FlushFlows(ctx, bridgeID, platformv1.FlowTable_FLOW_TABLE_UNSPECIFIED)
		if flushErr != nil {
			return &ErrFlushFlowsFailed{BridgeID: bridgeID, Cause: flushErr}
		}
	}
	return c.DeleteBridge(ctx, bridgeID, force)
}

// AddPortDomain adds a port to a bridge using domain types.
func (c *Client) AddPortDomain(ctx context.Context, bridgeID string, config *PortConfig) (*platformv1.Port, error) {
	return c.AddPort(ctx, bridgeID, PortConfigToProto(config))
}

// AddFlowDomain adds a flow rule using domain types.
func (c *Client) AddFlowDomain(ctx context.Context, config *FlowConfig) (*platformv1.Flow, error) {
	return c.AddFlow(ctx, FlowConfigToProto(config))
}

// ListFlowsDomain lists flows using domain types for filtering.
func (c *Client) ListFlowsDomain(ctx context.Context, bridgeID string, table FlowTable, pageSize uint32) ([]*platformv1.Flow, *common.PageResult, error) {
	return c.ListFlows(ctx, bridgeID, FlowTableToProto(table), PaginationToProto(pageSize))
}

// FlushFlowsDomain removes all flows from a bridge or table using domain types.
func (c *Client) FlushFlowsDomain(ctx context.Context, bridgeID string, table FlowTable) (uint32, error) {
	return c.FlushFlows(ctx, bridgeID, FlowTableToProto(table))
}

// CreateVLANDomain creates a new VLAN using domain types.
func (c *Client) CreateVLANDomain(ctx context.Context, config *VLANConfig) (*platformv1.VLAN, error) {
	return c.CreateVLAN(ctx, VLANConfigToProto(config))
}

// ListVLANsDomain lists VLANs using domain types for filtering.
func (c *Client) ListVLANsDomain(ctx context.Context, bridgeID string, selector *LabelSelector) ([]*platformv1.VLAN, error) {
	return c.ListVLANs(ctx, bridgeID, LabelSelectorToProto(selector))
}

// ApplyPolicyDomain applies a network policy using domain types.
func (c *Client) ApplyPolicyDomain(ctx context.Context, policyID string, config *PolicyConfig) (*platformv1.Policy, error) {
	return c.ApplyPolicy(ctx, policyID, PolicyConfigToProto(config))
}

// ListPoliciesDomain lists policies using domain types for filtering.
func (c *Client) ListPoliciesDomain(ctx context.Context, policyType, targetID string, pageSize uint32) ([]*platformv1.Policy, error) {
	return c.ListPolicies(ctx, policyType, targetID, PaginationToProto(pageSize))
}
