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

// Package gateway provides a client for gateway service operations.
package gateway

import (
	"context"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

// Client provides access to gateway service operations.
type Client struct {
	grpc platformv1.GatewayServiceClient
}

// NewClient creates a new gateway service client from a transport adapter.
func NewClient(conn transport.Adapter) (*Client, error) {
	if conn == nil {
		return nil, common.ErrNilConnection
	}
	grpcConn := conn.Connection()
	if grpcConn == nil {
		return nil, common.ErrNilConnection
	}
	return &Client{
		grpc: platformv1.NewGatewayServiceClient(grpcConn),
	}, nil
}

// NewClientFromGRPC creates a new gateway service client from a gRPC client.
// This is useful when you already have a gRPC client from the platform.Client.
func NewClientFromGRPC(grpcClient platformv1.GatewayServiceClient) *Client {
	return &Client{
		grpc: grpcClient,
	}
}

// Gateway Node Operations

// GetStatus returns the current gateway status.
func (c *Client) GetStatus(ctx context.Context) (*platformv1.GatewayStatus, error) {
	resp, err := c.grpc.GetGatewayStatus(ctx, &platformv1.GetGatewayStatusRequest{})
	if err != nil {
		return nil, &ErrGetStatusFailed{Cause: err}
	}
	return resp.Status, nil
}

// GetSnapshot returns one gateway's telemetry snapshot: the datapath state
// its services report (BGP sessions and BFD, tunnels, uplink policy routes,
// the host filter, NAT, the base pipeline and per-service health). An empty
// gatewayID reads the gateway the node runs itself; a named one reads the
// report the control plane holds.
func (c *Client) GetSnapshot(ctx context.Context, gatewayID string) (*platformv1.GatewaySnapshot, error) {
	resp, err := c.grpc.GetGatewaySnapshot(ctx, &platformv1.GetGatewaySnapshotRequest{GatewayId: gatewayID})
	if err != nil {
		return nil, &ErrGetSnapshotFailed{GatewayID: gatewayID, Cause: err}
	}
	return resp.GetSnapshot(), nil
}

// ListSnapshots returns every reported gateway's telemetry snapshot, newest
// report first.
func (c *Client) ListSnapshots(ctx context.Context) ([]*platformv1.GatewaySnapshot, error) {
	resp, err := c.grpc.ListGatewaySnapshots(ctx, &platformv1.ListGatewaySnapshotsRequest{})
	if err != nil {
		return nil, &ErrListSnapshotsFailed{Cause: err}
	}
	return resp.GetSnapshots(), nil
}

// GetAdmittedVTEP returns one remote VTEP the gateway admitted to the overlay,
// with the device and attestation verdict that admitted it. An empty gatewayID
// reads the gateway the node runs itself.
func (c *Client) GetAdmittedVTEP(ctx context.Context, gatewayID, vtep string) (*platformv1.GatewayAdmittedVTEP, error) {
	resp, err := c.grpc.GetGatewayAdmittedVTEP(ctx, &platformv1.GetGatewayAdmittedVTEPRequest{GatewayId: gatewayID, Vtep: vtep})
	if err != nil {
		return nil, &ErrGetAdmittedVTEPFailed{GatewayID: gatewayID, VTEP: vtep, Cause: err}
	}
	return resp.GetVtep(), nil
}

// ListAdmittedVTEPs returns every remote VTEP the gateway admitted to the
// overlay. An empty gatewayID reads the gateway the node runs itself.
func (c *Client) ListAdmittedVTEPs(ctx context.Context, gatewayID string) ([]*platformv1.GatewayAdmittedVTEP, error) {
	resp, err := c.grpc.ListGatewayAdmittedVTEPs(ctx, &platformv1.ListGatewayAdmittedVTEPsRequest{GatewayId: gatewayID})
	if err != nil {
		return nil, &ErrListAdmittedVTEPsFailed{GatewayID: gatewayID, Cause: err}
	}
	return resp.GetVteps(), nil
}

// SetMode sets the gateway operating mode(s).
func (c *Client) SetMode(ctx context.Context, modes uint32) (*platformv1.GatewayStatus, error) {
	resp, err := c.grpc.SetGatewayMode(ctx, &platformv1.SetGatewayModeRequest{Modes: modes})
	if err != nil {
		return nil, &ErrSetModeFailed{Cause: err}
	}
	return resp.GatewayStatus, nil
}

// SetModeFromStrings sets the gateway operating mode(s) from string names.
// Accepts mode names like "overlay", "edge", "transit".
func (c *Client) SetModeFromStrings(ctx context.Context, modes []string) (*platformv1.GatewayStatus, error) {
	modeBitmask, err := ModesFromNames(modes)
	if err != nil {
		return nil, &ErrSetModeFailed{Cause: err}
	}
	return c.SetMode(ctx, modeBitmask)
}

// BGP Operations

// GetBGPStatus returns the BGP status.
func (c *Client) GetBGPStatus(ctx context.Context) (*platformv1.BGPStatus, error) {
	resp, err := c.grpc.GetBGPStatus(ctx, &platformv1.GetBGPStatusRequest{})
	if err != nil {
		return nil, &ErrGetBGPStatusFailed{Cause: err}
	}
	return resp.Status, nil
}

// ListBGPPeers lists all BGP peers.
func (c *Client) ListBGPPeers(ctx context.Context) ([]*platformv1.BGPPeer, error) {
	resp, err := c.grpc.ListBGPPeers(ctx, &platformv1.ListBGPPeersRequest{})
	if err != nil {
		return nil, &ErrListBGPPeersFailed{Cause: err}
	}
	return resp.Peers, nil
}

// AnnouncePrefix announces a prefix via BGP.
func (c *Client) AnnouncePrefix(ctx context.Context, prefix, nextHop string) error {
	_, err := c.grpc.AnnouncePrefix(ctx, &platformv1.AnnouncePrefixRequest{
		Prefix:  prefix,
		NextHop: nextHop,
	})
	if err != nil {
		return &ErrAnnouncePrefixFailed{Prefix: prefix, Cause: err}
	}
	return nil
}

// WithdrawPrefix withdraws a prefix from BGP.
func (c *Client) WithdrawPrefix(ctx context.Context, prefix string) error {
	_, err := c.grpc.WithdrawPrefix(ctx, &platformv1.WithdrawPrefixRequest{Prefix: prefix})
	if err != nil {
		return &ErrWithdrawPrefixFailed{Prefix: prefix, Cause: err}
	}
	return nil
}

// ListAnnouncedPrefixes lists all announced prefixes.
func (c *Client) ListAnnouncedPrefixes(ctx context.Context) ([]*platformv1.AnnouncedPrefix, error) {
	resp, err := c.grpc.ListAnnouncedPrefixes(ctx, &platformv1.ListAnnouncedPrefixesRequest{})
	if err != nil {
		return nil, &ErrListAnnouncedPrefixesFailed{Cause: err}
	}
	return resp.Prefixes, nil
}

// IPAM Operations

// ListIPAMPools lists IPAM pools, optionally filtered by zone.
// An empty zone returns all pools.
func (c *Client) ListIPAMPools(ctx context.Context, zone string) ([]*platformv1.IPAMPool, error) {
	resp, err := c.grpc.ListIPAMPools(ctx, &platformv1.ListIPAMPoolsRequest{Zone: zone})
	if err != nil {
		return nil, &ErrListIPAMPoolsFailed{Cause: err}
	}
	return resp.Pools, nil
}

// CreateIPAMPool creates a new IP address management pool.
func (c *Client) CreateIPAMPool(ctx context.Context, req *platformv1.CreateIPAMPoolRequest) (*platformv1.IPAMPool, error) {
	resp, err := c.grpc.CreateIPAMPool(ctx, req)
	if err != nil {
		return nil, &ErrCreateIPAMPoolFailed{Name: req.GetName(), Cause: err}
	}
	return resp.Pool, nil
}

// GetIPAMPool retrieves an IPAM pool by ID.
func (c *Client) GetIPAMPool(ctx context.Context, poolID string) (*platformv1.IPAMPool, error) {
	resp, err := c.grpc.GetIPAMPool(ctx, &platformv1.GetIPAMPoolRequest{Id: poolID})
	if err != nil {
		return nil, &ErrGetIPAMPoolFailed{ID: poolID, Cause: err}
	}
	return resp.Pool, nil
}

// UpdateIPAMPool updates mutable fields of an IPAM pool.
// The CIDR is immutable and cannot be changed after pool creation.
func (c *Client) UpdateIPAMPool(ctx context.Context, req *platformv1.UpdateIPAMPoolRequest) (*platformv1.IPAMPool, error) {
	resp, err := c.grpc.UpdateIPAMPool(ctx, req)
	if err != nil {
		return nil, &ErrUpdateIPAMPoolFailed{ID: req.GetId(), Cause: err}
	}
	return resp.Pool, nil
}

// DeleteIPAMPool deletes an IPAM pool.
// Returns ErrDeleteIPAMPoolFailed when the pool has active allocations or does not exist.
func (c *Client) DeleteIPAMPool(ctx context.Context, poolID string) error {
	_, err := c.grpc.DeleteIPAMPool(ctx, &platformv1.DeleteIPAMPoolRequest{Id: poolID})
	if err != nil {
		return &ErrDeleteIPAMPoolFailed{ID: poolID, Cause: err}
	}
	return nil
}

// AllocateIP allocates an IP address from a pool.
func (c *Client) AllocateIP(ctx context.Context, poolID, deviceID, hostname string) (*platformv1.IPAllocation, error) {
	resp, err := c.grpc.AllocateIP(ctx, &platformv1.AllocateIPRequest{
		PoolId:   poolID,
		DeviceId: deviceID,
		Hostname: hostname,
	})
	if err != nil {
		return nil, &ErrAllocateIPFailed{PoolID: poolID, Cause: err}
	}
	return resp.Allocation, nil
}

// ReleaseIP releases an allocated IP address.
func (c *Client) ReleaseIP(ctx context.Context, ip string) error {
	_, err := c.grpc.ReleaseIP(ctx, &platformv1.ReleaseIPRequest{Ip: ip})
	if err != nil {
		return &ErrReleaseIPFailed{IP: ip, Cause: err}
	}
	return nil
}

// ListAllocations lists IP allocations, optionally filtered by pool.
func (c *Client) ListAllocations(ctx context.Context, poolID string) ([]*platformv1.IPAllocation, error) {
	resp, err := c.grpc.ListAllocations(ctx, &platformv1.ListAllocationsRequest{PoolId: poolID})
	if err != nil {
		return nil, &ErrListAllocationsFailed{Cause: err}
	}
	return resp.Allocations, nil
}
