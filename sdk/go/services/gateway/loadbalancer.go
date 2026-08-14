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

package gateway

import (
	"context"
	"fmt"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// Load Balancer VIP Operations

// AddVIP installs a load-balanced virtual IP on the gateway's OVS
// group-select + conntrack datapath.
func (c *Client) AddVIP(ctx context.Context, vip *platformv1.VIPConfig) (*platformv1.VIPStatus, error) {
	resp, err := c.grpc.AddVIP(ctx, &platformv1.AddVIPRequest{Vip: vip})
	if err != nil {
		return nil, &ErrAddVIPFailed{Address: vip.GetAddress(), Cause: err}
	}
	return resp.Vip, nil
}

// RemoveVIP tears down a load-balanced virtual IP.
func (c *Client) RemoveVIP(ctx context.Context, protocol, address string, port uint32) error {
	_, err := c.grpc.RemoveVIP(ctx, &platformv1.RemoveVIPRequest{
		Protocol: protocol,
		Address:  address,
		Port:     port,
	})
	if err != nil {
		return &ErrRemoveVIPFailed{Address: address, Cause: err}
	}
	return nil
}

// GetVIP returns the status of one load-balanced virtual IP.
func (c *Client) GetVIP(ctx context.Context, protocol, address string, port uint32) (*platformv1.VIPStatus, error) {
	resp, err := c.grpc.GetVIP(ctx, &platformv1.GetVIPRequest{
		Protocol: protocol,
		Address:  address,
		Port:     port,
	})
	if err != nil {
		return nil, &ErrGetVIPFailed{Address: address, Cause: err}
	}
	return resp.Vip, nil
}

// ListVIPs returns the status of every load-balanced virtual IP.
func (c *Client) ListVIPs(ctx context.Context) ([]*platformv1.VIPStatus, error) {
	resp, err := c.grpc.ListVIPs(ctx, &platformv1.ListVIPsRequest{})
	if err != nil {
		return nil, &ErrListVIPsFailed{Cause: err}
	}
	return resp.Vips, nil
}

// SetVIPBackends replaces the backend set of a load-balanced virtual IP.
func (c *Client) SetVIPBackends(ctx context.Context, protocol, address string, port uint32, backends []*platformv1.VIPBackend) (*platformv1.VIPStatus, error) {
	resp, err := c.grpc.SetVIPBackends(ctx, &platformv1.SetVIPBackendsRequest{
		Protocol: protocol,
		Address:  address,
		Port:     port,
		Backends: backends,
	})
	if err != nil {
		return nil, &ErrSetVIPBackendsFailed{Address: address, Cause: err}
	}
	return resp.Vip, nil
}

// GetLBStatus returns the load balancer service health snapshot.
func (c *Client) GetLBStatus(ctx context.Context) (*platformv1.LBStatus, error) {
	resp, err := c.grpc.GetLBStatus(ctx, &platformv1.GetLBStatusRequest{})
	if err != nil {
		return nil, &ErrGetLBStatusFailed{Cause: err}
	}
	return resp.Status, nil
}

// Load Balancer Error Types

// ErrAddVIPFailed is returned when a VIP could not be added.
type ErrAddVIPFailed struct {
	Address string
	Cause   error
}

func (e *ErrAddVIPFailed) Error() string {
	return fmt.Sprintf("failed to add VIP %s: %v", e.Address, e.Cause)
}

func (e *ErrAddVIPFailed) Unwrap() error { return e.Cause }

// ErrRemoveVIPFailed is returned when a VIP could not be removed.
type ErrRemoveVIPFailed struct {
	Address string
	Cause   error
}

func (e *ErrRemoveVIPFailed) Error() string {
	return fmt.Sprintf("failed to remove VIP %s: %v", e.Address, e.Cause)
}

func (e *ErrRemoveVIPFailed) Unwrap() error { return e.Cause }

// ErrGetVIPFailed is returned when a VIP could not be retrieved.
type ErrGetVIPFailed struct {
	Address string
	Cause   error
}

func (e *ErrGetVIPFailed) Error() string {
	return fmt.Sprintf("failed to get VIP %s: %v", e.Address, e.Cause)
}

func (e *ErrGetVIPFailed) Unwrap() error { return e.Cause }

// ErrListVIPsFailed is returned when the VIP list could not be retrieved.
type ErrListVIPsFailed struct {
	Cause error
}

func (e *ErrListVIPsFailed) Error() string {
	return fmt.Sprintf("failed to list VIPs: %v", e.Cause)
}

func (e *ErrListVIPsFailed) Unwrap() error { return e.Cause }

// ErrSetVIPBackendsFailed is returned when a VIP's backends could not be
// replaced.
type ErrSetVIPBackendsFailed struct {
	Address string
	Cause   error
}

func (e *ErrSetVIPBackendsFailed) Error() string {
	return fmt.Sprintf("failed to set VIP backends for %s: %v", e.Address, e.Cause)
}

func (e *ErrSetVIPBackendsFailed) Unwrap() error { return e.Cause }

// ErrGetLBStatusFailed is returned when the load balancer status could not
// be retrieved.
type ErrGetLBStatusFailed struct {
	Cause error
}

func (e *ErrGetLBStatusFailed) Error() string {
	return fmt.Sprintf("failed to get load balancer status: %v", e.Cause)
}

func (e *ErrGetLBStatusFailed) Unwrap() error { return e.Cause }
