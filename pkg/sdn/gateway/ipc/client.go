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

package ipc

import (
	"context"
	"encoding/json"

	"google.golang.org/grpc"

	ipcv1 "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/ipc/gen"
	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util/peercred"
)

// Client is the supervisor's (or a parser process's) handle on one child's
// socket.
type Client struct {
	conn     *grpc.ClientConn
	control  ipcv1.ProcessControlServiceClient
	datapath ipcv1.DatapathServiceClient
}

// Dial connects to the Unix socket at path. The connection is lazy: the
// first RPC fails with the transport error when nothing listens yet.
func Dial(path string) (*Client, error) {
	if path == "" {
		return nil, &ErrSocketPath{Path: path, Op: "dial", Cause: ErrEmptySocketPath}
	}
	conn, err := grpc.NewClient("unix:"+path,
		grpc.WithTransportCredentials(peercred.NewUnixTransportCredentials()),
	)
	if err != nil {
		return nil, &ErrSocketPath{Path: path, Op: "dial", Cause: err}
	}
	return &Client{
		conn:     conn,
		control:  ipcv1.NewProcessControlServiceClient(conn),
		datapath: ipcv1.NewDatapathServiceClient(conn),
	}, nil
}

// Status returns the child's state and per-service reports.
func (c *Client) Status(ctx context.Context) (*ipcv1.StatusResponse, error) {
	return c.control.Status(ctx, &ipcv1.StatusRequest{})
}

// Snapshot returns the child's telemetry snapshot.
func (c *Client) Snapshot(ctx context.Context) (*gwstate.Snapshot, error) {
	resp, err := c.control.Snapshot(ctx, &ipcv1.SnapshotRequest{})
	if err != nil {
		return nil, err
	}
	var snap gwstate.Snapshot
	if err := json.Unmarshal(resp.GetSnapshotJson(), &snap); err != nil {
		return nil, &ErrDocument{Document: "snapshot", Cause: err}
	}
	return &snap, nil
}

// ApplyDesired forwards the desired configuration to the datapath process.
// The returned state is what the child recorded; a non-nil error of type
// *ErrRemoteApply carries the child's apply failure beside that state.
func (c *Client) ApplyDesired(ctx context.Context, desired *gwstate.DesiredConfig) (gwstate.DesiredConfigState, error) {
	body, err := json.Marshal(desired)
	if err != nil {
		return gwstate.DesiredConfigState{}, &ErrDocument{Document: "desired config", Cause: err}
	}
	resp, err := c.datapath.ApplyDesired(ctx, &ipcv1.ApplyDesiredRequest{DesiredJson: body})
	if err != nil {
		return gwstate.DesiredConfigState{}, err
	}
	var state gwstate.DesiredConfigState
	if err := json.Unmarshal(resp.GetStateJson(), &state); err != nil {
		return gwstate.DesiredConfigState{}, &ErrDocument{Document: "desired config state", Cause: err}
	}
	if resp.GetApplyError() != "" {
		return state, &ErrRemoteApply{Message: resp.GetApplyError()}
	}
	return state, nil
}

// Close releases the connection.
func (c *Client) Close() error {
	return c.conn.Close()
}
