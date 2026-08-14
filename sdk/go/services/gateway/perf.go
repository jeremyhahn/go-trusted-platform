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

// Performance Verification Operations
//
// All results are REAL measurements: GetPerfFlows times an actual flow
// install / teardown cycle on the daemon's OVS bridge, GetPerfDatapath
// and GetPerfConntrack read live ovs-vswitchd counters.

// GetPerfFlows measures flow-programming throughput. count == 0 selects
// the daemon default (1000); batch selects the single-barrier batched
// install path; bridge == "" selects the daemon's default bridge.
func (c *Client) GetPerfFlows(ctx context.Context, count uint32, batch bool, bridge string) (*platformv1.GetPerfFlowsResponse, error) {
	resp, err := c.grpc.GetPerfFlows(ctx, &platformv1.GetPerfFlowsRequest{
		Count:  count,
		Batch:  batch,
		Bridge: bridge,
	})
	if err != nil {
		return nil, &ErrPerfFlowsFailed{Cause: err}
	}
	return resp, nil
}

// GetPerfDatapath reads the live datapath lookup counters, offloaded
// flow count, and hardware offload configuration state.
func (c *Client) GetPerfDatapath(ctx context.Context, bridge string) (*platformv1.GetPerfDatapathResponse, error) {
	resp, err := c.grpc.GetPerfDatapath(ctx, &platformv1.GetPerfDatapathRequest{Bridge: bridge})
	if err != nil {
		return nil, &ErrPerfDatapathFailed{Cause: err}
	}
	return resp, nil
}

// GetPerfConntrack summarizes the connection tracking table. A nil zone
// summarizes every zone.
func (c *Client) GetPerfConntrack(ctx context.Context, zone *uint32) (*platformv1.GetPerfConntrackResponse, error) {
	resp, err := c.grpc.GetPerfConntrack(ctx, &platformv1.GetPerfConntrackRequest{Zone: zone})
	if err != nil {
		return nil, &ErrPerfConntrackFailed{Cause: err}
	}
	return resp, nil
}

// Performance Verification Error Types

// ErrPerfFlowsFailed is returned when the flow measurement fails.
type ErrPerfFlowsFailed struct {
	Cause error
}

func (e *ErrPerfFlowsFailed) Error() string {
	return fmt.Sprintf("failed to measure flow programming: %v", e.Cause)
}

func (e *ErrPerfFlowsFailed) Unwrap() error { return e.Cause }

// ErrPerfDatapathFailed is returned when the datapath counters could not
// be read.
type ErrPerfDatapathFailed struct {
	Cause error
}

func (e *ErrPerfDatapathFailed) Error() string {
	return fmt.Sprintf("failed to read datapath counters: %v", e.Cause)
}

func (e *ErrPerfDatapathFailed) Unwrap() error { return e.Cause }

// ErrPerfConntrackFailed is returned when the conntrack summary could
// not be read.
type ErrPerfConntrackFailed struct {
	Cause error
}

func (e *ErrPerfConntrackFailed) Error() string {
	return fmt.Sprintf("failed to read conntrack summary: %v", e.Cause)
}

func (e *ErrPerfConntrackFailed) Unwrap() error { return e.Cause }
