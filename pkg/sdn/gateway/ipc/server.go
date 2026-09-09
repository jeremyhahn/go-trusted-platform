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

// Package ipc is the gatewayd supervisor <-> service-process contract
// (#557): gRPC over a Unix socket, authenticated only by the kernel's
// SO_PEERCRED. A `gatewayd service run <process>` child serves it; the
// supervisor and, for the datapath process, the parser children call it.
package ipc

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"sync/atomic"

	"google.golang.org/grpc"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	ipcv1 "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/ipc/gen"
	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util/peercred"
)

// Node is what the server reports and drives: the child's own gateway.
// *gateway.Gateway satisfies it.
type Node interface {
	GetState() gateway.GatewayState
	ServiceReports() []gateway.ServiceReport
	Snapshot() *gwstate.Snapshot
	Apply(ctx context.Context, desired *gwstate.DesiredConfig) error
	DesiredConfigState() gwstate.DesiredConfigState
}

// stateToProto maps the gateway state machine onto the wire enum.
var stateToProto = map[gateway.GatewayState]ipcv1.ProcessState{
	gateway.GatewayStateUnknown:      ipcv1.ProcessState_PROCESS_STATE_UNSPECIFIED,
	gateway.GatewayStateInitializing: ipcv1.ProcessState_PROCESS_STATE_INITIALIZING,
	gateway.GatewayStateRunning:      ipcv1.ProcessState_PROCESS_STATE_RUNNING,
	gateway.GatewayStateDegraded:     ipcv1.ProcessState_PROCESS_STATE_DEGRADED,
	gateway.GatewayStateStopping:     ipcv1.ProcessState_PROCESS_STATE_STOPPING,
	gateway.GatewayStateStopped:      ipcv1.ProcessState_PROCESS_STATE_STOPPED,
	gateway.GatewayStateError:        ipcv1.ProcessState_PROCESS_STATE_ERROR,
}

// Server serves ProcessControlService and DatapathService for one child
// process over a Unix socket.
type Server struct {
	ipcv1.UnimplementedProcessControlServiceServer
	ipcv1.UnimplementedDatapathServiceServer

	node     Node
	policy   Policy
	grpc     *grpc.Server
	listener net.Listener
	startErr atomic.Pointer[string]
}

// NewServer builds a server for node under policy. Nothing listens until
// Listen.
func NewServer(node Node, policy Policy) *Server {
	s := &Server{node: node, policy: policy}
	s.grpc = grpc.NewServer(
		grpc.Creds(peercred.NewUnixTransportCredentials(peercred.WithRequireCredentials(true))),
		grpc.ChainUnaryInterceptor(
			peercred.UnixCredentialsUnaryInterceptorRequired(),
			policy.unaryInterceptor(),
		),
	)
	ipcv1.RegisterProcessControlServiceServer(s.grpc, s)
	ipcv1.RegisterDatapathServiceServer(s.grpc, s)
	return s
}

// SetStartError records the child's Gateway.Start failure so Status can
// carry it to the supervisor; nil clears it.
func (s *Server) SetStartError(err error) {
	if err == nil {
		s.startErr.Store(nil)
		return
	}
	text := err.Error()
	s.startErr.Store(&text)
}

// Listen binds the Unix socket at path with the given mode and group. A
// stale socket file from a previous instance is removed first; any other
// file at the path is an error. gid < 0 leaves the group as created.
func (s *Server) Listen(path string, mode os.FileMode, gid int) error {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return &ErrSocketPath{Path: path, Op: "refusing to replace non-socket", Cause: os.ErrExist}
		}
		if err := os.Remove(path); err != nil {
			return &ErrSocketPath{Path: path, Op: "remove stale socket", Cause: err}
		}
	} else if !os.IsNotExist(err) {
		return &ErrSocketPath{Path: path, Op: "stat", Cause: err}
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return &ErrSocketPath{Path: path, Op: "listen", Cause: err}
	}
	if gid >= 0 {
		if err := os.Chown(path, -1, gid); err != nil {
			_ = listener.Close()
			return &ErrSocketPath{Path: path, Op: "chown", Cause: err}
		}
	}
	if err := os.Chmod(path, mode); err != nil {
		_ = listener.Close()
		return &ErrSocketPath{Path: path, Op: "chmod", Cause: err}
	}
	s.listener = listener
	return nil
}

// Serve accepts connections until Stop. It returns nil after a Stop.
func (s *Server) Serve() error {
	if s.listener == nil {
		return &ErrServerNotListening{}
	}
	if err := s.grpc.Serve(s.listener); err != nil && err != grpc.ErrServerStopped {
		return err
	}
	return nil
}

// Stop stops serving and closes the socket.
func (s *Server) Stop() {
	s.grpc.GracefulStop()
}

// Addr returns the bound socket path, or "" before Listen.
func (s *Server) Addr() string {
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

// Status implements ProcessControlService.
func (s *Server) Status(context.Context, *ipcv1.StatusRequest) (*ipcv1.StatusResponse, error) {
	reports := s.node.ServiceReports()
	resp := &ipcv1.StatusResponse{
		State:    stateToProto[s.node.GetState()],
		Services: make([]*ipcv1.ServiceStatus, 0, len(reports)),
	}
	for _, r := range reports {
		status := &ipcv1.ServiceStatus{Name: r.Name, Active: r.Active, Healthy: r.Health == nil}
		if r.Health != nil {
			status.HealthError = r.Health.Error()
		}
		resp.Services = append(resp.Services, status)
	}
	if text := s.startErr.Load(); text != nil {
		resp.StartError = *text
	}
	return resp, nil
}

// Snapshot implements ProcessControlService.
func (s *Server) Snapshot(context.Context, *ipcv1.SnapshotRequest) (*ipcv1.SnapshotResponse, error) {
	body, err := json.Marshal(s.node.Snapshot())
	if err != nil {
		return nil, &ErrDocument{Document: "snapshot", Cause: err}
	}
	return &ipcv1.SnapshotResponse{SnapshotJson: body}, nil
}

// ApplyDesired implements DatapathService: the document is applied through
// the child's gateway and the reconciliation state is returned with the
// apply error beside it, so a failed apply still reports what it recorded.
func (s *Server) ApplyDesired(ctx context.Context, req *ipcv1.ApplyDesiredRequest) (*ipcv1.ApplyDesiredResponse, error) {
	var desired gwstate.DesiredConfig
	if err := json.Unmarshal(req.GetDesiredJson(), &desired); err != nil {
		return nil, &ErrDocument{Document: "desired config", Cause: err}
	}
	applyErr := s.node.Apply(ctx, &desired)
	state, err := json.Marshal(s.node.DesiredConfigState())
	if err != nil {
		return nil, &ErrDocument{Document: "desired config state", Cause: err}
	}
	resp := &ipcv1.ApplyDesiredResponse{StateJson: state}
	if applyErr != nil {
		resp.ApplyError = applyErr.Error()
	}
	return resp, nil
}
