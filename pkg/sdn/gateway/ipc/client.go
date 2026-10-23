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
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"

	ipcv1 "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/ipc/gen"
	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util/peercred"
)

// Client is the supervisor's (or a parser process's) handle on one child's
// socket.
type Client struct {
	path     string
	conn     *grpc.ClientConn
	control  ipcv1.ProcessControlServiceClient
	datapath ipcv1.DatapathServiceClient
	services ipcv1.GatewayServicesServiceClient
}

// Reconnect backoff for the child's socket. gRPC's default backoff starts at
// one second and grows by 1.6x, so a supervisor that dials a freshly
// launched child before it listens stays shut out for 1s, 2.6s, 5.2s, 9.3s
// after its first refused connect: a child that takes a little over five
// seconds to listen is not reached until about nine, against a ten second
// ready timeout. A refused connect on a local socket costs nothing, so the
// retry follows the supervisor's own poll instead.
const (
	reconnectBaseDelay = 20 * time.Millisecond
	reconnectMaxDelay  = 200 * time.Millisecond
	// minConnectTimeout is gRPC's own default.
	minConnectTimeout = 20 * time.Second
)

// Dial connects to the Unix socket at path. The connection is lazy: the
// first RPC fails with the transport error when nothing listens yet, and the
// channel retries within reconnectMaxDelay once something does.
func Dial(path string) (*Client, error) {
	if path == "" {
		return nil, &ErrSocketPath{Path: path, Op: "dial", Cause: ErrEmptySocketPath}
	}
	conn, err := grpc.NewClient("unix:"+path,
		grpc.WithTransportCredentials(peercred.NewUnixTransportCredentials()),
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff: backoff.Config{
				BaseDelay:  reconnectBaseDelay,
				Multiplier: backoff.DefaultConfig.Multiplier,
				Jitter:     backoff.DefaultConfig.Jitter,
				MaxDelay:   reconnectMaxDelay,
			},
			// Left zero, a connect attempt would get only the backoff
			// delay to finish its handshake.
			MinConnectTimeout: minConnectTimeout,
		}),
	)
	if err != nil {
		return nil, &ErrSocketPath{Path: path, Op: "dial", Cause: err}
	}
	return &Client{
		path:     path,
		conn:     conn,
		control:  ipcv1.NewProcessControlServiceClient(conn),
		datapath: ipcv1.NewDatapathServiceClient(conn),
		services: ipcv1.NewGatewayServicesServiceClient(conn),
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

// InstallVPNPeer asks the datapath child to install a VPN peer. A plane's
// refusal is in the response; the error is the RPC's own. *Client is the
// transport vpn.DatapathPlane forwards over.
func (c *Client) InstallVPNPeer(ctx context.Context, req *ipcv1.InstallVPNPeerRequest) (*ipcv1.InstallVPNPeerResponse, error) {
	return c.datapath.InstallVPNPeer(ctx, req)
}

// RemoveVPNPeer asks the datapath child to remove a VPN peer, the same way
// as InstallVPNPeer.
func (c *Client) RemoveVPNPeer(ctx context.Context, req *ipcv1.RemoveVPNPeerRequest) (*ipcv1.RemoveVPNPeerResponse, error) {
	return c.datapath.RemoveVPNPeer(ctx, req)
}

// Close releases the connection.
func (c *Client) Close() error {
	return c.conn.Close()
}
