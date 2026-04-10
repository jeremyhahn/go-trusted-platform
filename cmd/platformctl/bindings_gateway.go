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

package main

import (
	"log/slog"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/platform"
)

// GatewayBinding exposes gateway service methods to the Wails frontend.
type GatewayBinding struct {
	logger *slog.Logger
	conn   *ConnectionBinding
}

// NewGatewayBinding creates a new GatewayBinding.
func NewGatewayBinding(logger *slog.Logger, conn *ConnectionBinding) *GatewayBinding {
	return &GatewayBinding{logger: logger, conn: conn}
}

// getClient returns the current platform client or an error.
func (b *GatewayBinding) getClient() (platform.Client, error) {
	cl, err := b.conn.loadClient()
	if err != nil {
		return nil, err
	}
	return *cl, nil
}

// GetGatewayStatus returns the current gateway status.
func (b *GatewayBinding) GetGatewayStatus() (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Gateway().GetGatewayStatus(b.conn.ctx, &platformv1.GetGatewayStatusRequest{})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// SetGatewayMode sets the gateway mode bitmask.
func (b *GatewayBinding) SetGatewayMode(modes uint32) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Gateway().SetGatewayMode(b.conn.ctx, &platformv1.SetGatewayModeRequest{
		Modes: modes,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// GetBGPStatus returns the current BGP routing status.
func (b *GatewayBinding) GetBGPStatus() (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Gateway().GetBGPStatus(b.conn.ctx, &platformv1.GetBGPStatusRequest{})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// ListBGPPeers returns all configured BGP peers.
func (b *GatewayBinding) ListBGPPeers() (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Gateway().ListBGPPeers(b.conn.ctx, &platformv1.ListBGPPeersRequest{})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// AnnouncePrefix announces a network prefix via BGP.
func (b *GatewayBinding) AnnouncePrefix(prefix, nextHop string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Gateway().AnnouncePrefix(b.conn.ctx, &platformv1.AnnouncePrefixRequest{
		Prefix:  prefix,
		NextHop: nextHop,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// WithdrawPrefix withdraws a previously announced prefix.
func (b *GatewayBinding) WithdrawPrefix(prefix string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Gateway().WithdrawPrefix(b.conn.ctx, &platformv1.WithdrawPrefixRequest{
		Prefix: prefix,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// ListAnnouncedPrefixes returns all currently announced prefixes.
func (b *GatewayBinding) ListAnnouncedPrefixes() (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Gateway().ListAnnouncedPrefixes(b.conn.ctx, &platformv1.ListAnnouncedPrefixesRequest{})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// ListIPAMPools returns all IPAM pools.
func (b *GatewayBinding) ListIPAMPools() (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Gateway().ListIPAMPools(b.conn.ctx, &platformv1.ListIPAMPoolsRequest{})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// AllocateIP allocates an IP address from an IPAM pool.
func (b *GatewayBinding) AllocateIP(poolID, deviceID, hostname string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Gateway().AllocateIP(b.conn.ctx, &platformv1.AllocateIPRequest{
		PoolId:   poolID,
		DeviceId: deviceID,
		Hostname: hostname,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// ReleaseIP releases a previously allocated IP address.
func (b *GatewayBinding) ReleaseIP(ip string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Gateway().ReleaseIP(b.conn.ctx, &platformv1.ReleaseIPRequest{
		Ip: ip,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// ListAllocations returns all IP allocations, optionally filtered by pool.
func (b *GatewayBinding) ListAllocations(poolID string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Gateway().ListAllocations(b.conn.ctx, &platformv1.ListAllocationsRequest{
		PoolId: poolID,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}
