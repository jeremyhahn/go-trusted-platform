// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package daemon

import (
	"context"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// gatewaySnapshotTools serves the MCP gateway_snapshot and
// gateway_snapshots tools from the gateway gRPC service, so the MCP
// transport answers from the same implementation as gRPC and QUIC (#594).
// With no reader wired the gateway service is not configured on this node,
// and every tool answers ErrServiceNotAvailable (Unavailable), as the QUIC
// and REST transports do.
type gatewaySnapshotTools struct {
	reader GatewaySnapshotReader
}

// GatewaySnapshot returns one gateway's telemetry snapshot.
func (t gatewaySnapshotTools) GatewaySnapshot(ctx context.Context, gatewayID string) (interface{}, error) {
	if t.reader == nil {
		return nil, ErrServiceNotAvailable{Service: "gateway"}
	}
	resp, err := t.reader.GetGatewaySnapshot(ctx, &platformv1.GetGatewaySnapshotRequest{GatewayId: gatewayID})
	if err != nil {
		return nil, err
	}
	return resp.GetSnapshot(), nil
}

// GatewaySnapshots returns every reported gateway's telemetry snapshot.
func (t gatewaySnapshotTools) GatewaySnapshots(ctx context.Context) ([]interface{}, error) {
	if t.reader == nil {
		return nil, ErrServiceNotAvailable{Service: "gateway"}
	}
	resp, err := t.reader.ListGatewaySnapshots(ctx, &platformv1.ListGatewaySnapshotsRequest{})
	if err != nil {
		return nil, err
	}
	out := make([]interface{}, 0, len(resp.GetSnapshots()))
	for _, snap := range resp.GetSnapshots() {
		out = append(out, snap)
	}
	return out, nil
}

// GatewayAdmittedVTEP returns one VTEP the gateway reported as admitted.
func (t gatewaySnapshotTools) GatewayAdmittedVTEP(ctx context.Context, gatewayID, vtep string) (interface{}, error) {
	if t.reader == nil {
		return nil, ErrServiceNotAvailable{Service: "gateway"}
	}
	resp, err := t.reader.GetGatewayAdmittedVTEP(ctx, &platformv1.GetGatewayAdmittedVTEPRequest{GatewayId: gatewayID, Vtep: vtep})
	if err != nil {
		return nil, err
	}
	return resp.GetVtep(), nil
}

// GatewayAdmittedVTEPs returns every VTEP the gateway reported as admitted.
func (t gatewaySnapshotTools) GatewayAdmittedVTEPs(ctx context.Context, gatewayID string) ([]interface{}, error) {
	if t.reader == nil {
		return nil, ErrServiceNotAvailable{Service: "gateway"}
	}
	resp, err := t.reader.ListGatewayAdmittedVTEPs(ctx, &platformv1.ListGatewayAdmittedVTEPsRequest{GatewayId: gatewayID})
	if err != nil {
		return nil, err
	}
	out := make([]interface{}, 0, len(resp.GetVteps()))
	for _, vtep := range resp.GetVteps() {
		out = append(out, vtep)
	}
	return out, nil
}
