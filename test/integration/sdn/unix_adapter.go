//go:build integration

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
	"fmt"
	"os"
	"strings"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"google.golang.org/grpc"
)

// =============================================================================
// Unix Constants
// =============================================================================

const (
	// EnvPlatformdUnixSDN is the environment variable for the Unix socket path.
	EnvPlatformdUnixSDN = "PLATFORMD_SOCKET"

	// DefaultPlatformdUnixSDN is the default platformd Unix socket path.
	DefaultPlatformdUnixSDN = "/run/platformd.sock"

	// DefaultUnixTimeoutSDN is the default timeout for Unix socket operations.
	DefaultUnixTimeoutSDN = 60 * time.Second
)

// =============================================================================
// Error Types
// =============================================================================

// ErrUnixSDNConnectionFailed indicates a Unix socket connection failure.
type ErrUnixSDNConnectionFailed struct {
	Path string
	Err  error
}

func (e ErrUnixSDNConnectionFailed) Error() string {
	return fmt.Sprintf("Unix connection to %s failed: %v", e.Path, e.Err)
}

func (e ErrUnixSDNConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrUnixSDNBackendUnavailable indicates the backend is unavailable.
type ErrUnixSDNBackendUnavailable struct {
	Err error
}

func (e ErrUnixSDNBackendUnavailable) Error() string {
	return fmt.Sprintf("Unix backend unavailable: %v", e.Err)
}

func (e ErrUnixSDNBackendUnavailable) Unwrap() error {
	return e.Err
}

// ErrUnixSDNRPCFailed indicates an RPC call failure.
type ErrUnixSDNRPCFailed struct {
	Method string
	Err    error
}

func (e ErrUnixSDNRPCFailed) Error() string {
	return fmt.Sprintf("Unix RPC %s failed: %v", e.Method, e.Err)
}

func (e ErrUnixSDNRPCFailed) Unwrap() error {
	return e.Err
}

// =============================================================================
// Unix Adapter
// =============================================================================

// UnixAdapter implements SDNCommands using gRPC over Unix sockets.
// This adapter uses the local Unix domain socket for IPC with platformd.
type UnixAdapter struct {
	conn       *grpc.ClientConn
	socketPath string
	timeout    time.Duration
	sdn        platformv1.SDNServiceClient
}

// NewUnixAdapter creates a new Unix socket adapter for integration testing.
func NewUnixAdapter() *UnixAdapter {
	socketPath := os.Getenv(EnvPlatformdUnixSDN)
	if socketPath == "" {
		socketPath = DefaultPlatformdUnixSDN
	}

	return &UnixAdapter{
		socketPath: socketPath,
		timeout:    DefaultUnixTimeoutSDN,
	}
}

// Name returns the protocol adapter identifier.
func (s *UnixAdapter) Name() string {
	return "Unix"
}

// Setup establishes the gRPC connection over Unix socket and creates the
// SDN service client. Unix domain sockets use insecure transport credentials
// because TLS is not needed for local IPC -- the kernel enforces access
// control via file permissions and SO_PEERCRED.
func (s *UnixAdapter) Setup(ctx context.Context) error {
	if _, err := os.Stat(s.socketPath); os.IsNotExist(err) {
		return ErrUnixSDNConnectionFailed{Path: s.socketPath, Err: err}
	}

	conn, err := grpc.NewClient("unix://"+s.socketPath,
		helpers.GRPCUnixCredentials(),
	)
	if err != nil {
		return ErrUnixSDNConnectionFailed{Path: s.socketPath, Err: err}
	}

	s.conn = conn
	s.sdn = platformv1.NewSDNServiceClient(conn)

	// Verify connectivity by attempting a ListBridges call
	_, err = s.sdn.ListBridges(ctx, &platformv1.ListBridgesRequest{})
	if err != nil {
		closeErr := s.conn.Close()
		if closeErr != nil {
			return ErrUnixSDNBackendUnavailable{
				Err: fmt.Errorf("%w; close error: %v", err, closeErr),
			}
		}
		return ErrUnixSDNBackendUnavailable{Err: err}
	}

	return nil
}

// Teardown closes the Unix socket connection.
func (s *UnixAdapter) Teardown() error {
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

// =============================================================================
// Bridge Commands
// =============================================================================

// BridgeCreate creates a new bridge via Unix socket.
func (s *UnixAdapter) BridgeCreate(ctx context.Context, opts BridgeCreateOptions) (*BridgeCreateResult, error) {
	bridgeType, ok := bridgeTypeFromString[strings.ToLower(opts.Type)]
	if !ok {
		bridgeType = platformv1.BridgeType_BRIDGE_TYPE_UNSPECIFIED
	}

	req := &platformv1.CreateBridgeRequest{
		Config: &platformv1.BridgeConfig{
			Name:       opts.Name,
			Type:       bridgeType,
			DatapathId: opts.DatapathID,
			StpEnabled: opts.STP,
			Mtu:        uint32(opts.MTU),
			Labels:     opts.Tags,
		},
	}

	resp, err := s.sdn.CreateBridge(ctx, req)
	if err != nil {
		return nil, ErrUnixSDNRPCFailed{Method: "CreateBridge", Err: err}
	}

	bridge := resp.GetBridge()
	if bridge == nil {
		return &BridgeCreateResult{
			BridgeID: opts.BridgeID,
			Name:     opts.Name,
			Type:     opts.Type,
		}, nil
	}

	return bridgeToCreateResult(bridge), nil
}

// BridgeGet retrieves a bridge by ID via Unix socket.
func (s *UnixAdapter) BridgeGet(ctx context.Context, bridgeID string) (*BridgeGetResult, error) {
	req := &platformv1.GetBridgeRequest{
		Id: bridgeID,
	}

	resp, err := s.sdn.GetBridge(ctx, req)
	if err != nil {
		return nil, ErrUnixSDNRPCFailed{Method: "GetBridge", Err: err}
	}

	bridge := resp.GetBridge()
	if bridge == nil {
		return &BridgeGetResult{
			BridgeID: bridgeID,
		}, nil
	}

	return bridgeToGetResult(bridge), nil
}

// BridgeDelete deletes a bridge via Unix socket.
func (s *UnixAdapter) BridgeDelete(ctx context.Context, bridgeID string, opts BridgeDeleteOptions) (*BridgeDeleteResult, error) {
	req := &platformv1.DeleteBridgeRequest{
		Id:    bridgeID,
		Force: opts.Force,
	}

	resp, err := s.sdn.DeleteBridge(ctx, req)
	if err != nil {
		return nil, ErrUnixSDNRPCFailed{Method: "DeleteBridge", Err: err}
	}

	deleted := false
	if status := resp.GetStatus(); status != nil {
		deleted = status.GetSuccess()
	}

	return &BridgeDeleteResult{
		BridgeID: bridgeID,
		Deleted:  deleted,
	}, nil
}

// BridgeList lists bridges via Unix socket.
func (s *UnixAdapter) BridgeList(ctx context.Context, opts BridgeListOptions) (*BridgeListResult, error) {
	req := &platformv1.ListBridgesRequest{}

	if opts.Limit > 0 {
		req.Pagination = &platformv1.PaginationRequest{
			PageSize: uint32(opts.Limit),
		}
	}

	resp, err := s.sdn.ListBridges(ctx, req)
	if err != nil {
		return nil, ErrUnixSDNRPCFailed{Method: "ListBridges", Err: err}
	}

	bridges := make([]BridgeSummary, 0, len(resp.GetBridges()))
	for _, b := range resp.GetBridges() {
		bridges = append(bridges, bridgeToSummary(b))
	}

	var totalCount int32
	var hasMore bool
	var nextCursor string
	if pagination := resp.GetPagination(); pagination != nil {
		totalCount = int32(pagination.GetTotalItems())
		hasMore = pagination.GetPage() < pagination.GetTotalPages()
		nextCursor = fmt.Sprintf("%d", pagination.GetPage()+1)
	} else {
		totalCount = int32(len(bridges))
	}

	return &BridgeListResult{
		Bridges:    bridges,
		TotalCount: totalCount,
		HasMore:    hasMore,
		NextCursor: nextCursor,
	}, nil
}

// =============================================================================
// Port Commands
// =============================================================================

// PortAdd adds a port to a bridge via Unix socket.
func (s *UnixAdapter) PortAdd(ctx context.Context, opts PortAddOptions) (*PortAddResult, error) {
	portType, ok := portTypeFromString[strings.ToLower(opts.Type)]
	if !ok {
		portType = platformv1.PortType_PORT_TYPE_UNSPECIFIED
	}

	trunks := make([]uint32, len(opts.Trunks))
	for i, t := range opts.Trunks {
		trunks[i] = uint32(t)
	}

	req := &platformv1.AddPortRequest{
		BridgeId: opts.BridgeID,
		Config: &platformv1.PortConfig{
			Name:       opts.Name,
			Type:       portType,
			Vlan:       uint32(opts.Tag),
			TrunkVlans: trunks,
			MacAddress: opts.MAC,
			Mtu:        uint32(opts.MTU),
			Options:    opts.Options,
		},
	}

	resp, err := s.sdn.AddPort(ctx, req)
	if err != nil {
		return nil, ErrUnixSDNRPCFailed{Method: "AddPort", Err: err}
	}

	port := resp.GetPort()
	if port == nil {
		return &PortAddResult{
			BridgeID: opts.BridgeID,
			PortID:   opts.PortID,
			Name:     opts.Name,
			Type:     opts.Type,
		}, nil
	}

	return portToAddResult(port), nil
}

// PortDelete deletes a port from a bridge via Unix socket.
func (s *UnixAdapter) PortDelete(ctx context.Context, bridgeID, portID string) (*PortDeleteResult, error) {
	req := &platformv1.DeletePortRequest{
		BridgeId: bridgeID,
		PortId:   portID,
	}

	resp, err := s.sdn.DeletePort(ctx, req)
	if err != nil {
		return nil, ErrUnixSDNRPCFailed{Method: "DeletePort", Err: err}
	}

	deleted := false
	if status := resp.GetStatus(); status != nil {
		deleted = status.GetSuccess()
	}

	return &PortDeleteResult{
		BridgeID: bridgeID,
		PortID:   portID,
		Deleted:  deleted,
	}, nil
}

// PortGetState gets the state of a port via Unix socket.
// Uses the GetPort RPC and extracts state information from the Port message.
func (s *UnixAdapter) PortGetState(ctx context.Context, bridgeID, portID string) (*PortStateResult, error) {
	req := &platformv1.GetPortRequest{
		BridgeId: bridgeID,
		PortId:   portID,
	}

	resp, err := s.sdn.GetPort(ctx, req)
	if err != nil {
		return nil, ErrUnixSDNRPCFailed{Method: "GetPort", Err: err}
	}

	port := resp.GetPort()
	if port == nil {
		return &PortStateResult{
			BridgeID: bridgeID,
			PortID:   portID,
		}, nil
	}

	return portToStateResult(port), nil
}

// PortSetState sets the state of a port via Unix socket.
func (s *UnixAdapter) PortSetState(ctx context.Context, bridgeID, portID string, opts PortSetStateOptions) (*PortStateResult, error) {
	req := &platformv1.SetPortStateRequest{
		BridgeId:     bridgeID,
		PortId:       portID,
		AdminState:   opts.AdminState,
		IngressRate:  opts.IngressRate,
		EgressRate:   opts.EgressRate,
		IngressBurst: opts.IngressBurst,
		EgressBurst:  opts.EgressBurst,
	}

	resp, err := s.sdn.SetPortState(ctx, req)
	if err != nil {
		return nil, ErrUnixSDNRPCFailed{Method: "SetPortState", Err: err}
	}

	port := resp.GetPort()
	if port == nil {
		return &PortStateResult{
			BridgeID: bridgeID,
			PortID:   portID,
		}, nil
	}

	return portToStateResult(port), nil
}

// PortGetStats gets statistics for a port via Unix socket.
func (s *UnixAdapter) PortGetStats(ctx context.Context, bridgeID, portID string) (*PortStatsResult, error) {
	req := &platformv1.GetPortStatsRequest{
		BridgeId: bridgeID,
		PortId:   portID,
	}

	resp, err := s.sdn.GetPortStats(ctx, req)
	if err != nil {
		return nil, ErrUnixSDNRPCFailed{Method: "GetPortStats", Err: err}
	}

	stats := resp.GetStats()
	if stats == nil {
		return &PortStatsResult{
			BridgeID:    bridgeID,
			PortID:      portID,
			RetrievedAt: time.Now(),
		}, nil
	}

	return &PortStatsResult{
		BridgeID:    bridgeID,
		PortID:      portID,
		RxPackets:   stats.GetPacketsReceived(),
		TxPackets:   stats.GetPacketsSent(),
		RxBytes:     stats.GetBytesReceived(),
		TxBytes:     stats.GetBytesSent(),
		RxErrors:    stats.GetErrors(),
		RxDropped:   stats.GetDropped(),
		RetrievedAt: time.Now(),
	}, nil
}

// =============================================================================
// Flow Commands
// =============================================================================

// FlowAdd adds a flow to a bridge via Unix socket.
func (s *UnixAdapter) FlowAdd(ctx context.Context, opts FlowAddOptions) (*FlowAddResult, error) {
	req := &platformv1.AddFlowRequest{Config: flowConfigToProto(opts)}

	resp, err := s.sdn.AddFlow(ctx, req)
	if err != nil {
		return nil, ErrUnixSDNRPCFailed{Method: "AddFlow", Err: err}
	}

	flow := resp.GetFlow()
	if flow == nil {
		return &FlowAddResult{
			BridgeID: opts.BridgeID,
			FlowID:   opts.FlowID,
			Table:    opts.Table,
			Priority: opts.Priority,
		}, nil
	}

	return flowToAddResult(flow, opts.BridgeID), nil
}

// FlowDelete deletes a flow from a bridge via Unix socket.
func (s *UnixAdapter) FlowDelete(ctx context.Context, bridgeID, flowID string) (*FlowDeleteResult, error) {
	req := &platformv1.DeleteFlowRequest{
		BridgeId: bridgeID,
		FlowId:   flowID,
	}

	resp, err := s.sdn.DeleteFlow(ctx, req)
	if err != nil {
		return nil, ErrUnixSDNRPCFailed{Method: "DeleteFlow", Err: err}
	}

	deleted := false
	if status := resp.GetStatus(); status != nil {
		deleted = status.GetSuccess()
	}

	return &FlowDeleteResult{
		BridgeID: bridgeID,
		FlowID:   flowID,
		Deleted:  deleted,
	}, nil
}

// FlowList lists flows on a bridge via Unix socket.
func (s *UnixAdapter) FlowList(ctx context.Context, bridgeID string, opts FlowListOptions) (*FlowListResult, error) {
	req := &platformv1.ListFlowsRequest{
		BridgeId: bridgeID,
		Table:    platformv1.FlowTable(opts.Table),
	}

	if opts.Limit > 0 {
		req.Pagination = &platformv1.PaginationRequest{
			PageSize: uint32(opts.Limit),
		}
	}

	resp, err := s.sdn.ListFlows(ctx, req)
	if err != nil {
		return nil, ErrUnixSDNRPCFailed{Method: "ListFlows", Err: err}
	}

	flows := make([]FlowSummary, 0, len(resp.GetFlows()))
	for _, f := range resp.GetFlows() {
		flows = append(flows, flowToSummary(f))
	}

	var totalCount int32
	var hasMore bool
	var nextCursor string
	if pagination := resp.GetPagination(); pagination != nil {
		totalCount = int32(pagination.GetTotalItems())
		hasMore = pagination.GetPage() < pagination.GetTotalPages()
		nextCursor = fmt.Sprintf("%d", pagination.GetPage()+1)
	} else {
		totalCount = int32(len(flows))
	}

	return &FlowListResult{
		BridgeID:   bridgeID,
		Flows:      flows,
		TotalCount: totalCount,
		HasMore:    hasMore,
		NextCursor: nextCursor,
	}, nil
}

// =============================================================================
// VLAN Commands
// =============================================================================

// VLANCreate creates a VLAN via Unix socket.
func (s *UnixAdapter) VLANCreate(ctx context.Context, opts VLANCreateOptions) (*VLANCreateResult, error) {
	var bridgeID string
	if len(opts.BridgeIDs) > 0 {
		bridgeID = opts.BridgeIDs[0]
	}

	ports := make([]string, 0, len(opts.Tagged)+len(opts.Untagged))
	ports = append(ports, opts.Tagged...)
	ports = append(ports, opts.Untagged...)

	req := &platformv1.CreateVLANRequest{
		Config: &platformv1.VLANConfig{
			VlanId:   uint32(opts.VLANID),
			Name:     opts.Name,
			BridgeId: bridgeID,
			Ports:    ports,
		},
	}

	resp, err := s.sdn.CreateVLAN(ctx, req)
	if err != nil {
		return nil, ErrUnixSDNRPCFailed{Method: "CreateVLAN", Err: err}
	}

	vlan := resp.GetVlan()
	if vlan == nil {
		return &VLANCreateResult{
			VLANID:      opts.VLANID,
			Name:        opts.Name,
			Description: opts.Description,
		}, nil
	}

	return vlanToCreateResult(vlan, opts.Description), nil
}

// VLANDelete deletes a VLAN via Unix socket.
func (s *UnixAdapter) VLANDelete(ctx context.Context, bridgeID string, vlanID int32) (*VLANDeleteResult, error) {
	req := &platformv1.DeleteVLANRequest{
		BridgeId: bridgeID,
		VlanId:   uint32(vlanID),
	}
	resp, err := s.sdn.DeleteVLAN(ctx, req)
	if err != nil {
		return nil, ErrUnixSDNRPCFailed{Method: "DeleteVLAN", Err: err}
	}

	deleted := false
	if status := resp.GetStatus(); status != nil {
		deleted = status.GetSuccess()
	}

	return &VLANDeleteResult{
		VLANID:  vlanID,
		Deleted: deleted,
	}, nil
}

// VLANList lists VLANs via Unix socket.
func (s *UnixAdapter) VLANList(ctx context.Context, opts VLANListOptions) (*VLANListResult, error) {
	req := &platformv1.ListVLANsRequest{
		BridgeId: opts.BridgeID,
	}

	resp, err := s.sdn.ListVLANs(ctx, req)
	if err != nil {
		return nil, ErrUnixSDNRPCFailed{Method: "ListVLANs", Err: err}
	}

	vlans := make([]VLANSummary, 0, len(resp.GetVlans()))
	for _, v := range resp.GetVlans() {
		vlans = append(vlans, vlanToSummary(v))
	}

	return &VLANListResult{
		VLANs:      vlans,
		TotalCount: int32(len(vlans)),
	}, nil
}

// =============================================================================
// Policy Commands
// =============================================================================

// PolicyApply applies a network policy via Unix socket.
func (s *UnixAdapter) PolicyApply(ctx context.Context, opts PolicyApplyOptions) (*PolicyApplyResult, error) {
	policyType, ok := policyTypeFromString[strings.ToLower(opts.Type)]
	if !ok {
		policyType = platformv1.PolicyType_POLICY_TYPE_UNSPECIFIED
	}

	protoRules := make([]*platformv1.PolicyRule, 0, len(opts.Rules))
	for _, r := range opts.Rules {
		protoRules = append(protoRules, policyRuleToProto(r))
	}

	protoTargets := make([]*platformv1.PolicyTarget, 0, len(opts.Targets))
	for _, t := range opts.Targets {
		protoTargets = append(protoTargets, policyTargetToProto(t))
	}

	var protoSchedule *platformv1.PolicySchedule
	if opts.Schedule != nil {
		protoSchedule = policyScheduleToProto(opts.Schedule)
	}

	req := &platformv1.ApplyPolicyRequest{
		PolicyId: opts.PolicyID,
		Config: &platformv1.PolicyConfig{
			Name:        opts.Name,
			Description: opts.Description,
			Type:        policyType,
			Priority:    opts.Priority,
			Enabled:     opts.Enabled,
			Rules:       protoRules,
			Targets:     protoTargets,
			Schedule:    protoSchedule,
		},
	}

	resp, err := s.sdn.ApplyPolicy(ctx, req)
	if err != nil {
		return nil, ErrUnixSDNRPCFailed{Method: "ApplyPolicy", Err: err}
	}

	policy := resp.GetPolicy()
	if policy == nil {
		return &PolicyApplyResult{
			PolicyID: opts.PolicyID,
			Name:     opts.Name,
			Type:     opts.Type,
		}, nil
	}

	return policyToApplyResult(policy), nil
}

// PolicyGet retrieves a policy by ID via Unix socket.
func (s *UnixAdapter) PolicyGet(ctx context.Context, policyID string) (*PolicyGetResult, error) {
	req := &platformv1.GetPolicyRequest{
		PolicyId: policyID,
	}

	resp, err := s.sdn.GetPolicy(ctx, req)
	if err != nil {
		return nil, ErrUnixSDNRPCFailed{Method: "GetPolicy", Err: err}
	}

	policy := resp.GetPolicy()
	if policy == nil {
		return &PolicyGetResult{
			PolicyID: policyID,
		}, nil
	}

	return policyToGetResult(policy), nil
}

// PolicyList lists policies via Unix socket.
func (s *UnixAdapter) PolicyList(ctx context.Context, opts PolicyListOptions) (*PolicyListResult, error) {
	req := &platformv1.ListPoliciesRequest{
		Type:     opts.Type,
		TargetId: opts.TargetID,
	}

	if opts.Limit > 0 {
		req.Pagination = &platformv1.PaginationRequest{
			PageSize: uint32(opts.Limit),
		}
	}

	resp, err := s.sdn.ListPolicies(ctx, req)
	if err != nil {
		return nil, ErrUnixSDNRPCFailed{Method: "ListPolicies", Err: err}
	}

	policies := make([]PolicySummary, 0, len(resp.GetPolicies()))
	for _, p := range resp.GetPolicies() {
		policies = append(policies, policyToSummary(p))
	}

	var totalCount int32
	var hasMore bool
	var nextCursor string
	if pagination := resp.GetPagination(); pagination != nil {
		totalCount = int32(pagination.GetTotalItems())
		hasMore = pagination.GetPage() < pagination.GetTotalPages()
		nextCursor = fmt.Sprintf("%d", pagination.GetPage()+1)
	} else {
		totalCount = int32(len(policies))
	}

	return &PolicyListResult{
		Policies:   policies,
		TotalCount: totalCount,
		HasMore:    hasMore,
		NextCursor: nextCursor,
	}, nil
}

// =============================================================================
// Compile-time Interface Verification
// =============================================================================

// Ensure UnixAdapter implements SDNCommands interface.
var _ SDNCommands = (*UnixAdapter)(nil)
