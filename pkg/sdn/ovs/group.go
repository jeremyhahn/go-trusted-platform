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

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/openflow"
)

// GroupClient programs OpenFlow group table entries on a bridge. It is a
// deliberately small interface (kept separate from ClientInterface) so
// consumers that only need group programming — such as the gateway load
// balancer — can be tested with a compact fake.
type GroupClient interface {
	// AddGroup installs a new group entry on the bridge.
	AddGroup(ctx context.Context, bridgeName string, group *openflow.GroupMod) error

	// ModifyGroup replaces the buckets of an existing group entry.
	ModifyGroup(ctx context.Context, bridgeName string, group *openflow.GroupMod) error

	// DeleteGroup removes the group with the given ID. Passing
	// openflow.OFPGAll removes every group on the bridge.
	DeleteGroup(ctx context.Context, bridgeName string, groupID uint32) error

	// GetGroupDesc returns the descriptions of every group installed on
	// the bridge.
	GetGroupDesc(ctx context.Context, bridgeName string) ([]openflow.GroupDesc, error)
}

// Compile-time check: Client implements GroupClient.
var _ GroupClient = (*Client)(nil)

// AddGroup installs a new OpenFlow group entry on a bridge.
func (c *Client) AddGroup(ctx context.Context, bridgeName string, group *openflow.GroupMod) error {
	if bridgeName == "" {
		return ErrInvalidBridgeName
	}
	if group == nil {
		return ErrInvalidFlow
	}

	if err := c.ensureConnected(ctx); err != nil {
		return err
	}

	ofClient, err := c.getOpenFlowClient(ctx, bridgeName)
	if err != nil {
		return &WrappedError{Msg: "failed to get OpenFlow client", Err: err}
	}

	if err := ofClient.AddGroup(ctx, group); err != nil {
		return &WrappedError{Msg: "failed to add group", Err: err}
	}
	return nil
}

// ModifyGroup replaces the buckets of an existing OpenFlow group entry on a
// bridge. A group mod with zero buckets is legal and leaves the group
// installed with no forwarding targets (packets selecting it are dropped).
func (c *Client) ModifyGroup(ctx context.Context, bridgeName string, group *openflow.GroupMod) error {
	if bridgeName == "" {
		return ErrInvalidBridgeName
	}
	if group == nil {
		return ErrInvalidFlow
	}

	if err := c.ensureConnected(ctx); err != nil {
		return err
	}

	ofClient, err := c.getOpenFlowClient(ctx, bridgeName)
	if err != nil {
		return &WrappedError{Msg: "failed to get OpenFlow client", Err: err}
	}

	if err := ofClient.ModifyGroup(ctx, group); err != nil {
		return &WrappedError{Msg: "failed to modify group", Err: err}
	}
	return nil
}

// DeleteGroup removes the OpenFlow group with the given ID from a bridge.
func (c *Client) DeleteGroup(ctx context.Context, bridgeName string, groupID uint32) error {
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

	if err := ofClient.DeleteGroup(ctx, groupID); err != nil {
		return &WrappedError{Msg: "failed to delete group", Err: err}
	}
	return nil
}

// GetGroupDesc returns the descriptions of every OpenFlow group installed on
// a bridge.
func (c *Client) GetGroupDesc(ctx context.Context, bridgeName string) ([]openflow.GroupDesc, error) {
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

	groups, err := ofClient.GetGroupDesc(ctx)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to get group descriptions", Err: err}
	}
	return groups, nil
}
