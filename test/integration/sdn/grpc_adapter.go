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
	"google.golang.org/protobuf/types/known/timestamppb"
)

// =============================================================================
// Constants
// =============================================================================

const (
	// grpcAdapterDialTimeout is the timeout for establishing gRPC connection.
	grpcAdapterDialTimeout = 5 * time.Second
)

// =============================================================================
// Error Types
// =============================================================================

// ErrGRPCConnectionFailed indicates a gRPC connection failure.
type ErrGRPCConnectionFailed struct {
	Endpoint string
	Err      error
}

func (e ErrGRPCConnectionFailed) Error() string {
	return fmt.Sprintf("gRPC connection to %s failed: %v", e.Endpoint, e.Err)
}

func (e ErrGRPCConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrGRPCCallFailed indicates a gRPC method call failure.
type ErrGRPCCallFailed struct {
	Method string
	Err    error
}

func (e ErrGRPCCallFailed) Error() string {
	return fmt.Sprintf("gRPC call %s failed: %v", e.Method, e.Err)
}

func (e ErrGRPCCallFailed) Unwrap() error {
	return e.Err
}

// ErrGRPCBackendUnavailable indicates the backend is unavailable.
type ErrGRPCBackendUnavailable struct {
	Endpoint string
	Err      error
}

func (e ErrGRPCBackendUnavailable) Error() string {
	return fmt.Sprintf("gRPC backend at %s unavailable: %v", e.Endpoint, e.Err)
}

func (e ErrGRPCBackendUnavailable) Unwrap() error {
	return e.Err
}

// =============================================================================
// String-to-Proto Enum Dispatch Maps
// =============================================================================

// bridgeTypeFromString maps string bridge types to protobuf BridgeType enum values.
var bridgeTypeFromString = map[string]platformv1.BridgeType{
	"ovs":   platformv1.BridgeType_BRIDGE_TYPE_OVS,
	"linux": platformv1.BridgeType_BRIDGE_TYPE_LINUX,
	"vxlan": platformv1.BridgeType_BRIDGE_TYPE_VXLAN,
}

// bridgeTypeToString maps protobuf BridgeType enum values to lowercase strings.
var bridgeTypeToString = map[platformv1.BridgeType]string{
	platformv1.BridgeType_BRIDGE_TYPE_UNSPECIFIED: "unspecified",
	platformv1.BridgeType_BRIDGE_TYPE_OVS:         "ovs",
	platformv1.BridgeType_BRIDGE_TYPE_LINUX:       "linux",
	platformv1.BridgeType_BRIDGE_TYPE_VXLAN:       "vxlan",
}

// bridgeStatusToString maps protobuf BridgeStatus enum values to lowercase strings.
var bridgeStatusToString = map[platformv1.BridgeStatus]string{
	platformv1.BridgeStatus_BRIDGE_STATUS_UNSPECIFIED: "unspecified",
	platformv1.BridgeStatus_BRIDGE_STATUS_UP:          "up",
	platformv1.BridgeStatus_BRIDGE_STATUS_DOWN:        "down",
	platformv1.BridgeStatus_BRIDGE_STATUS_ERROR:       "error",
}

// portTypeFromString maps string port types to protobuf PortType enum values.
var portTypeFromString = map[string]platformv1.PortType{
	"internal": platformv1.PortType_PORT_TYPE_INTERNAL,
	"physical": platformv1.PortType_PORT_TYPE_PHYSICAL,
	"tap":      platformv1.PortType_PORT_TYPE_TAP,
	"veth":     platformv1.PortType_PORT_TYPE_VETH,
	"vxlan":    platformv1.PortType_PORT_TYPE_VXLAN,
	"gre":      platformv1.PortType_PORT_TYPE_GRE,
}

// portTypeToString maps protobuf PortType enum values to lowercase strings.
var portTypeToString = map[platformv1.PortType]string{
	platformv1.PortType_PORT_TYPE_UNSPECIFIED: "unspecified",
	platformv1.PortType_PORT_TYPE_INTERNAL:    "internal",
	platformv1.PortType_PORT_TYPE_PHYSICAL:    "physical",
	platformv1.PortType_PORT_TYPE_TAP:         "tap",
	platformv1.PortType_PORT_TYPE_VETH:        "veth",
	platformv1.PortType_PORT_TYPE_VXLAN:       "vxlan",
	platformv1.PortType_PORT_TYPE_GRE:         "gre",
}

// portStatusToString maps protobuf PortStatus enum values to lowercase strings.
var portStatusToString = map[platformv1.PortStatus]string{
	platformv1.PortStatus_PORT_STATUS_UNSPECIFIED: "unspecified",
	platformv1.PortStatus_PORT_STATUS_UP:          "up",
	platformv1.PortStatus_PORT_STATUS_DOWN:        "down",
	platformv1.PortStatus_PORT_STATUS_BLOCKED:     "blocked",
	platformv1.PortStatus_PORT_STATUS_LEARNING:    "learning",
	platformv1.PortStatus_PORT_STATUS_FORWARDING:  "forwarding",
}

// flowActionTypeFromString maps string flow action types to protobuf FlowActionType values.
var flowActionTypeFromString = map[string]platformv1.FlowActionType{
	"output":     platformv1.FlowActionType_FLOW_ACTION_OUTPUT,
	"drop":       platformv1.FlowActionType_FLOW_ACTION_DROP,
	"set_vlan":   platformv1.FlowActionType_FLOW_ACTION_SET_VLAN,
	"push_vlan":  platformv1.FlowActionType_FLOW_ACTION_SET_VLAN,
	"strip_vlan": platformv1.FlowActionType_FLOW_ACTION_STRIP_VLAN,
	"pop_vlan":   platformv1.FlowActionType_FLOW_ACTION_STRIP_VLAN,
	"set_field":  platformv1.FlowActionType_FLOW_ACTION_SET_FIELD,
	"goto_table": platformv1.FlowActionType_FLOW_ACTION_GOTO_TABLE,
	"controller": platformv1.FlowActionType_FLOW_ACTION_CONTROLLER,
}

// flowActionTypeToString maps protobuf FlowActionType enum values to lowercase strings.
var flowActionTypeToString = map[platformv1.FlowActionType]string{
	platformv1.FlowActionType_FLOW_ACTION_UNSPECIFIED: "unspecified",
	platformv1.FlowActionType_FLOW_ACTION_OUTPUT:      "output",
	platformv1.FlowActionType_FLOW_ACTION_DROP:        "drop",
	platformv1.FlowActionType_FLOW_ACTION_SET_VLAN:    "set_vlan",
	platformv1.FlowActionType_FLOW_ACTION_STRIP_VLAN:  "strip_vlan",
	platformv1.FlowActionType_FLOW_ACTION_SET_FIELD:   "set_field",
	platformv1.FlowActionType_FLOW_ACTION_GOTO_TABLE:  "goto_table",
	platformv1.FlowActionType_FLOW_ACTION_CONTROLLER:  "controller",
}

// policyTypeFromString maps string policy types to protobuf PolicyType enum values.
var policyTypeFromString = map[string]platformv1.PolicyType{
	"acl":      platformv1.PolicyType_POLICY_TYPE_ACL,
	"qos":      platformv1.PolicyType_POLICY_TYPE_QOS,
	"nat":      platformv1.PolicyType_POLICY_TYPE_NAT,
	"firewall": platformv1.PolicyType_POLICY_TYPE_FIREWALL,
	"routing":  platformv1.PolicyType_POLICY_TYPE_ROUTING,
}

// policyTypeToString maps protobuf PolicyType enum values to lowercase strings.
var policyTypeToString = map[platformv1.PolicyType]string{
	platformv1.PolicyType_POLICY_TYPE_UNSPECIFIED: "unspecified",
	platformv1.PolicyType_POLICY_TYPE_ACL:         "acl",
	platformv1.PolicyType_POLICY_TYPE_QOS:         "qos",
	platformv1.PolicyType_POLICY_TYPE_NAT:         "nat",
	platformv1.PolicyType_POLICY_TYPE_FIREWALL:    "firewall",
	platformv1.PolicyType_POLICY_TYPE_ROUTING:     "routing",
}

// policyStatusToString maps protobuf PolicyStatus enum values to lowercase strings.
var policyStatusToString = map[platformv1.PolicyStatus]string{
	platformv1.PolicyStatus_POLICY_STATUS_UNSPECIFIED: "unspecified",
	platformv1.PolicyStatus_POLICY_STATUS_ACTIVE:      "active",
	platformv1.PolicyStatus_POLICY_STATUS_INACTIVE:    "inactive",
	platformv1.PolicyStatus_POLICY_STATUS_ERROR:       "error",
	platformv1.PolicyStatus_POLICY_STATUS_PENDING:     "pending",
}

// policyRuleActionFromString maps string actions to protobuf PolicyRuleAction enum values.
var policyRuleActionFromString = map[string]platformv1.PolicyRuleAction{
	"allow":      platformv1.PolicyRuleAction_POLICY_RULE_ACTION_ALLOW,
	"deny":       platformv1.PolicyRuleAction_POLICY_RULE_ACTION_DENY,
	"rate-limit": platformv1.PolicyRuleAction_POLICY_RULE_ACTION_RATE_LIMIT,
	"redirect":   platformv1.PolicyRuleAction_POLICY_RULE_ACTION_REDIRECT,
	"mirror":     platformv1.PolicyRuleAction_POLICY_RULE_ACTION_MIRROR,
	"log":        platformv1.PolicyRuleAction_POLICY_RULE_ACTION_LOG,
}

// policyRuleActionToString maps protobuf PolicyRuleAction enum values to lowercase strings.
var policyRuleActionToString = map[platformv1.PolicyRuleAction]string{
	platformv1.PolicyRuleAction_POLICY_RULE_ACTION_UNSPECIFIED: "unspecified",
	platformv1.PolicyRuleAction_POLICY_RULE_ACTION_ALLOW:       "allow",
	platformv1.PolicyRuleAction_POLICY_RULE_ACTION_DENY:        "deny",
	platformv1.PolicyRuleAction_POLICY_RULE_ACTION_RATE_LIMIT:  "rate-limit",
	platformv1.PolicyRuleAction_POLICY_RULE_ACTION_REDIRECT:    "redirect",
	platformv1.PolicyRuleAction_POLICY_RULE_ACTION_MIRROR:      "mirror",
	platformv1.PolicyRuleAction_POLICY_RULE_ACTION_LOG:         "log",
}

// policyTargetTypeFromString maps string target types to protobuf PolicyTargetType enum values.
var policyTargetTypeFromString = map[string]platformv1.PolicyTargetType{
	"bridge":    platformv1.PolicyTargetType_POLICY_TARGET_TYPE_BRIDGE,
	"port":      platformv1.PolicyTargetType_POLICY_TARGET_TYPE_PORT,
	"vlan":      platformv1.PolicyTargetType_POLICY_TARGET_TYPE_VLAN,
	"interface": platformv1.PolicyTargetType_POLICY_TARGET_TYPE_INTERFACE,
}

// policyTargetTypeToString maps protobuf PolicyTargetType enum values to lowercase strings.
var policyTargetTypeToString = map[platformv1.PolicyTargetType]string{
	platformv1.PolicyTargetType_POLICY_TARGET_TYPE_UNSPECIFIED: "unspecified",
	platformv1.PolicyTargetType_POLICY_TARGET_TYPE_BRIDGE:      "bridge",
	platformv1.PolicyTargetType_POLICY_TARGET_TYPE_PORT:        "port",
	platformv1.PolicyTargetType_POLICY_TARGET_TYPE_VLAN:        "vlan",
	platformv1.PolicyTargetType_POLICY_TARGET_TYPE_INTERFACE:   "interface",
}

// =============================================================================
// gRPC Adapter
// =============================================================================

// GRPCAdapter implements SDNCommands using gRPC calls to platformd.
// This adapter makes gRPC calls to the platformd server for testing
// the gRPC transport layer consistency with other protocol adapters.
type GRPCAdapter struct {
	conn     *grpc.ClientConn
	endpoint string
	sdn      platformv1.SDNServiceClient
}

// NewGRPCAdapter creates a new gRPC protocol adapter instance.
func NewGRPCAdapter() *GRPCAdapter {
	endpoint := os.Getenv("PLATFORM_GRPC_ENDPOINT")
	if endpoint == "" {
		endpoint = GetServiceEndpoints().PlatformdGRPC
	}

	return &GRPCAdapter{
		endpoint: endpoint,
	}
}

// Name returns the protocol adapter identifier.
func (g *GRPCAdapter) Name() string {
	return "gRPC"
}

// Setup initializes the gRPC connection to platformd and creates the SDN service client.
// Uses grpc.NewClient for lazy connection establishment, then verifies connectivity
// with a ListBridges call to ensure the backend is reachable.
func (g *GRPCAdapter) Setup(ctx context.Context) error {
	conn, err := grpc.NewClient(g.endpoint,
		helpers.GRPCTransportCredentials(),
	)
	if err != nil {
		return ErrGRPCConnectionFailed{Endpoint: g.endpoint, Err: err}
	}

	g.conn = conn
	g.sdn = platformv1.NewSDNServiceClient(conn)

	// Verify connectivity by attempting a ListBridges call
	verifyCtx, verifyCancel := context.WithTimeout(ctx, grpcAdapterDialTimeout)
	defer verifyCancel()

	_, err = g.sdn.ListBridges(verifyCtx, &platformv1.ListBridgesRequest{})
	if err != nil {
		closeErr := g.conn.Close()
		if closeErr != nil {
			return ErrGRPCBackendUnavailable{
				Endpoint: g.endpoint,
				Err:      fmt.Errorf("%w; close error: %v", err, closeErr),
			}
		}
		return ErrGRPCBackendUnavailable{Endpoint: g.endpoint, Err: err}
	}

	return nil
}

// Teardown closes the gRPC connection.
func (g *GRPCAdapter) Teardown() error {
	if g.conn != nil {
		return g.conn.Close()
	}
	return nil
}

// =============================================================================
// Bridge Commands
// =============================================================================

// BridgeCreate creates a new bridge via gRPC.
func (g *GRPCAdapter) BridgeCreate(ctx context.Context, opts BridgeCreateOptions) (*BridgeCreateResult, error) {
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

	resp, err := g.sdn.CreateBridge(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "CreateBridge", Err: err}
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

// BridgeGet retrieves a bridge by ID via gRPC.
func (g *GRPCAdapter) BridgeGet(ctx context.Context, bridgeID string) (*BridgeGetResult, error) {
	req := &platformv1.GetBridgeRequest{
		Id: bridgeID,
	}

	resp, err := g.sdn.GetBridge(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetBridge", Err: err}
	}

	bridge := resp.GetBridge()
	if bridge == nil {
		return &BridgeGetResult{
			BridgeID: bridgeID,
		}, nil
	}

	return bridgeToGetResult(bridge), nil
}

// BridgeDelete deletes a bridge via gRPC.
func (g *GRPCAdapter) BridgeDelete(ctx context.Context, bridgeID string, opts BridgeDeleteOptions) (*BridgeDeleteResult, error) {
	req := &platformv1.DeleteBridgeRequest{
		Id:    bridgeID,
		Force: opts.Force,
	}

	resp, err := g.sdn.DeleteBridge(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "DeleteBridge", Err: err}
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

// BridgeList lists bridges via gRPC.
func (g *GRPCAdapter) BridgeList(ctx context.Context, opts BridgeListOptions) (*BridgeListResult, error) {
	req := &platformv1.ListBridgesRequest{}

	if opts.Limit > 0 {
		req.Pagination = &platformv1.PaginationRequest{
			PageSize: uint32(opts.Limit),
		}
	}

	resp, err := g.sdn.ListBridges(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "ListBridges", Err: err}
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

// PortAdd adds a port to a bridge via gRPC.
func (g *GRPCAdapter) PortAdd(ctx context.Context, opts PortAddOptions) (*PortAddResult, error) {
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

	resp, err := g.sdn.AddPort(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "AddPort", Err: err}
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

// PortDelete deletes a port from a bridge via gRPC.
func (g *GRPCAdapter) PortDelete(ctx context.Context, bridgeID, portID string) (*PortDeleteResult, error) {
	req := &platformv1.DeletePortRequest{
		BridgeId: bridgeID,
		PortId:   portID,
	}

	resp, err := g.sdn.DeletePort(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "DeletePort", Err: err}
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

// PortGetState gets the state of a port via gRPC.
// Uses the GetPort RPC and extracts state information from the Port message.
func (g *GRPCAdapter) PortGetState(ctx context.Context, bridgeID, portID string) (*PortStateResult, error) {
	req := &platformv1.GetPortRequest{
		BridgeId: bridgeID,
		PortId:   portID,
	}

	resp, err := g.sdn.GetPort(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetPort", Err: err}
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

// PortSetState sets the state of a port via gRPC.
func (g *GRPCAdapter) PortSetState(ctx context.Context, bridgeID, portID string, opts PortSetStateOptions) (*PortStateResult, error) {
	req := &platformv1.SetPortStateRequest{
		BridgeId:     bridgeID,
		PortId:       portID,
		AdminState:   opts.AdminState,
		IngressRate:  opts.IngressRate,
		EgressRate:   opts.EgressRate,
		IngressBurst: opts.IngressBurst,
		EgressBurst:  opts.EgressBurst,
	}

	resp, err := g.sdn.SetPortState(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "SetPortState", Err: err}
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

// PortGetStats gets statistics for a port via gRPC.
func (g *GRPCAdapter) PortGetStats(ctx context.Context, bridgeID, portID string) (*PortStatsResult, error) {
	req := &platformv1.GetPortStatsRequest{
		BridgeId: bridgeID,
		PortId:   portID,
	}

	resp, err := g.sdn.GetPortStats(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetPortStats", Err: err}
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

// FlowAdd adds a flow to a bridge via gRPC.
func (g *GRPCAdapter) FlowAdd(ctx context.Context, opts FlowAddOptions) (*FlowAddResult, error) {
	req := &platformv1.AddFlowRequest{Config: flowConfigToProto(opts)}

	resp, err := g.sdn.AddFlow(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "AddFlow", Err: err}
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

// FlowDelete deletes a flow from a bridge via gRPC.
func (g *GRPCAdapter) FlowDelete(ctx context.Context, bridgeID, flowID string) (*FlowDeleteResult, error) {
	req := &platformv1.DeleteFlowRequest{
		BridgeId: bridgeID,
		FlowId:   flowID,
	}

	resp, err := g.sdn.DeleteFlow(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "DeleteFlow", Err: err}
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

// FlowList lists flows on a bridge via gRPC.
func (g *GRPCAdapter) FlowList(ctx context.Context, bridgeID string, opts FlowListOptions) (*FlowListResult, error) {
	req := &platformv1.ListFlowsRequest{
		BridgeId: bridgeID,
		Table:    platformv1.FlowTable(opts.Table),
	}

	if opts.Limit > 0 {
		req.Pagination = &platformv1.PaginationRequest{
			PageSize: uint32(opts.Limit),
		}
	}

	resp, err := g.sdn.ListFlows(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "ListFlows", Err: err}
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

// VLANCreate creates a VLAN via gRPC.
func (g *GRPCAdapter) VLANCreate(ctx context.Context, opts VLANCreateOptions) (*VLANCreateResult, error) {
	// Use the first bridge if provided
	var bridgeID string
	if len(opts.BridgeIDs) > 0 {
		bridgeID = opts.BridgeIDs[0]
	}

	// Combine tagged and untagged port IDs
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

	resp, err := g.sdn.CreateVLAN(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "CreateVLAN", Err: err}
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

// VLANDelete deletes a VLAN via gRPC.
func (g *GRPCAdapter) VLANDelete(ctx context.Context, bridgeID string, vlanID int32) (*VLANDeleteResult, error) {
	req := &platformv1.DeleteVLANRequest{
		BridgeId: bridgeID,
		VlanId:   uint32(vlanID),
	}

	resp, err := g.sdn.DeleteVLAN(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "DeleteVLAN", Err: err}
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

// VLANList lists VLANs via gRPC.
func (g *GRPCAdapter) VLANList(ctx context.Context, opts VLANListOptions) (*VLANListResult, error) {
	req := &platformv1.ListVLANsRequest{
		BridgeId: opts.BridgeID,
	}

	resp, err := g.sdn.ListVLANs(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "ListVLANs", Err: err}
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

// PolicyApply applies a network policy via gRPC.
func (g *GRPCAdapter) PolicyApply(ctx context.Context, opts PolicyApplyOptions) (*PolicyApplyResult, error) {
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

	resp, err := g.sdn.ApplyPolicy(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "ApplyPolicy", Err: err}
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

// PolicyGet retrieves a policy by ID via gRPC.
func (g *GRPCAdapter) PolicyGet(ctx context.Context, policyID string) (*PolicyGetResult, error) {
	req := &platformv1.GetPolicyRequest{
		PolicyId: policyID,
	}

	resp, err := g.sdn.GetPolicy(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetPolicy", Err: err}
	}

	policy := resp.GetPolicy()
	if policy == nil {
		return &PolicyGetResult{
			PolicyID: policyID,
		}, nil
	}

	return policyToGetResult(policy), nil
}

// PolicyList lists policies via gRPC.
func (g *GRPCAdapter) PolicyList(ctx context.Context, opts PolicyListOptions) (*PolicyListResult, error) {
	req := &platformv1.ListPoliciesRequest{
		Type:     opts.Type,
		TargetId: opts.TargetID,
	}

	if opts.Limit > 0 {
		req.Pagination = &platformv1.PaginationRequest{
			PageSize: uint32(opts.Limit),
		}
	}

	resp, err := g.sdn.ListPolicies(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "ListPolicies", Err: err}
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
// Proto-to-Result Mapping Helpers
// =============================================================================

// bridgeToCreateResult converts a proto Bridge message to a BridgeCreateResult.
func bridgeToCreateResult(b *platformv1.Bridge) *BridgeCreateResult {
	config := b.GetConfig()

	var portCount int32
	if stats := b.GetStats(); stats != nil {
		portCount = int32(stats.GetTotalPorts())
	}

	return &BridgeCreateResult{
		BridgeID:   b.GetId(),
		Name:       config.GetName(),
		Type:       bridgeTypeToString[config.GetType()],
		DatapathID: config.GetDatapathId(),
		Status:     bridgeStatusToString[b.GetStatus()],
		CreatedAt:  protoTimestampToTime(b.GetCreatedAt()),
		PortCount:  portCount,
	}
}

// bridgeToGetResult converts a proto Bridge message to a BridgeGetResult.
func bridgeToGetResult(b *platformv1.Bridge) *BridgeGetResult {
	config := b.GetConfig()

	var portCount, flowCount int32
	if stats := b.GetStats(); stats != nil {
		portCount = int32(stats.GetTotalPorts())
		flowCount = int32(stats.GetTotalFlows())
	}

	ports := make([]PortSummary, 0, len(b.GetPorts()))
	for _, p := range b.GetPorts() {
		ports = append(ports, portToSummary(p))
	}

	return &BridgeGetResult{
		BridgeID:   b.GetId(),
		Name:       config.GetName(),
		Type:       bridgeTypeToString[config.GetType()],
		DatapathID: config.GetDatapathId(),
		Status:     bridgeStatusToString[b.GetStatus()],
		STP:        config.GetStpEnabled(),
		MTU:        int32(config.GetMtu()),
		PortCount:  portCount,
		FlowCount:  flowCount,
		Tags:       config.GetLabels(),
		CreatedAt:  protoTimestampToTime(b.GetCreatedAt()),
		UpdatedAt:  protoTimestampToTime(b.GetUpdatedAt()),
		Ports:      ports,
	}
}

// bridgeToSummary converts a proto Bridge message to a BridgeSummary.
func bridgeToSummary(b *platformv1.Bridge) BridgeSummary {
	config := b.GetConfig()

	var portCount, flowCount int32
	if stats := b.GetStats(); stats != nil {
		portCount = int32(stats.GetTotalPorts())
		flowCount = int32(stats.GetTotalFlows())
	}

	return BridgeSummary{
		BridgeID:   b.GetId(),
		Name:       config.GetName(),
		Type:       bridgeTypeToString[config.GetType()],
		Status:     bridgeStatusToString[b.GetStatus()],
		PortCount:  portCount,
		FlowCount:  flowCount,
		DatapathID: config.GetDatapathId(),
		CreatedAt:  protoTimestampToTime(b.GetCreatedAt()),
	}
}

// portToAddResult converts a proto Port message to a PortAddResult.
func portToAddResult(p *platformv1.Port) *PortAddResult {
	config := p.GetConfig()

	return &PortAddResult{
		BridgeID:  p.GetBridgeId(),
		PortID:    p.GetId(),
		Name:      config.GetName(),
		Type:      portTypeToString[config.GetType()],
		MAC:       config.GetMacAddress(),
		Status:    portStatusToString[p.GetStatus()],
		CreatedAt: protoTimestampToTime(p.GetCreatedAt()),
	}
}

// portToStateResult converts a proto Port message to a PortStateResult.
func portToStateResult(p *platformv1.Port) *PortStateResult {
	statusStr := portStatusToString[p.GetStatus()]

	// Derive admin state and oper state from the port status
	adminState := "up"
	operState := statusStr
	if p.GetStatus() == platformv1.PortStatus_PORT_STATUS_DOWN {
		adminState = "down"
	}

	return &PortStateResult{
		BridgeID:   p.GetBridgeId(),
		PortID:     p.GetId(),
		AdminState: adminState,
		OperState:  operState,
		UpdatedAt:  protoTimestampToTime(p.GetUpdatedAt()),
	}
}

// portToSummary converts a proto Port message to a PortSummary.
func portToSummary(p *platformv1.Port) PortSummary {
	config := p.GetConfig()
	statusStr := portStatusToString[p.GetStatus()]

	adminState := "up"
	if p.GetStatus() == platformv1.PortStatus_PORT_STATUS_DOWN {
		adminState = "down"
	}

	return PortSummary{
		PortID:     p.GetId(),
		Name:       config.GetName(),
		Type:       portTypeToString[config.GetType()],
		AdminState: adminState,
		OperState:  statusStr,
		MAC:        config.GetMacAddress(),
		Tag:        int32(config.GetVlan()),
	}
}

// flowActionToProto converts a test FlowAction to a proto FlowAction.
func flowActionToProto(a FlowAction) *platformv1.FlowAction {
	actionType, ok := flowActionTypeFromString[strings.ToLower(a.Type)]
	if !ok {
		actionType = platformv1.FlowActionType_FLOW_ACTION_UNSPECIFIED
	}

	return &platformv1.FlowAction{
		Type:    actionType,
		Port:    fmt.Sprintf("%d", a.Port),
		VlanId:  uint32(a.VLANID),
		Field:   a.Field,
		Value:   a.Value,
		TableId: uint32(a.TableID),
	}
}

// flowMatchToProto converts a test FlowMatch to a proto FlowMatch.
func flowMatchToProto(m FlowMatch) *platformv1.FlowMatch {
	return &platformv1.FlowMatch{
		InPort:  fmt.Sprintf("%d", m.InPort),
		VlanId:  uint32(m.DlVLAN),
		EthSrc:  m.DlSrc,
		EthDst:  m.DlDst,
		EthType: uint32(m.DlType),
		IpSrc:   m.NwSrc,
		IpDst:   m.NwDst,
		IpProto: uint32(m.NwProto),
		TcpSrc:  uint32(m.TpSrc),
		TcpDst:  uint32(m.TpDst),
	}
}

// flowConfigToProto converts test flow options into the gRPC FlowConfig.
// Every transport's AddFlow takes this message (MCP in its protojson form),
// so the adapters share one conversion.
func flowConfigToProto(opts FlowAddOptions) *platformv1.FlowConfig {
	protoActions := make([]*platformv1.FlowAction, 0, len(opts.Actions))
	for _, a := range opts.Actions {
		protoActions = append(protoActions, flowActionToProto(a))
	}

	return &platformv1.FlowConfig{
		BridgeId:    opts.BridgeID,
		Table:       platformv1.FlowTable(opts.Table),
		Priority:    uint32(opts.Priority),
		Match:       flowMatchToProto(opts.Match),
		Actions:     protoActions,
		IdleTimeout: uint32(opts.IdleTimeout),
		HardTimeout: uint32(opts.HardTimeout),
	}
}

// protoFlowMatchToTest converts a proto FlowMatch to a test FlowMatch.
func protoFlowMatchToTest(m *platformv1.FlowMatch) FlowMatch {
	if m == nil {
		return FlowMatch{}
	}

	return FlowMatch{
		DlSrc:   m.GetEthSrc(),
		DlDst:   m.GetEthDst(),
		DlType:  int32(m.GetEthType()),
		DlVLAN:  int32(m.GetVlanId()),
		NwSrc:   m.GetIpSrc(),
		NwDst:   m.GetIpDst(),
		NwProto: int32(m.GetIpProto()),
		TpSrc:   int32(m.GetTcpSrc()),
		TpDst:   int32(m.GetTcpDst()),
	}
}

// protoFlowActionToTest converts a proto FlowAction to a test FlowAction.
func protoFlowActionToTest(a *platformv1.FlowAction) FlowAction {
	if a == nil {
		return FlowAction{}
	}

	return FlowAction{
		Type:    flowActionTypeToString[a.GetType()],
		VLANID:  int32(a.GetVlanId()),
		Field:   a.GetField(),
		Value:   a.GetValue(),
		TableID: int32(a.GetTableId()),
	}
}

// flowToAddResult converts a proto Flow message to a FlowAddResult.
func flowToAddResult(f *platformv1.Flow, bridgeID string) *FlowAddResult {
	config := f.GetConfig()

	effectiveBridgeID := bridgeID
	if config.GetBridgeId() != "" {
		effectiveBridgeID = config.GetBridgeId()
	}

	return &FlowAddResult{
		BridgeID:  effectiveBridgeID,
		FlowID:    f.GetId(),
		Table:     int32(config.GetTable()),
		Priority:  int32(config.GetPriority()),
		CreatedAt: protoTimestampToTime(f.GetCreatedAt()),
	}
}

// flowToSummary converts a proto Flow message to a FlowSummary.
func flowToSummary(f *platformv1.Flow) FlowSummary {
	config := f.GetConfig()

	actions := make([]FlowAction, 0, len(config.GetActions()))
	for _, a := range config.GetActions() {
		actions = append(actions, protoFlowActionToTest(a))
	}

	var packetCount, byteCount uint64
	var duration int64
	if stats := f.GetStats(); stats != nil {
		packetCount = stats.GetPacketCount()
		byteCount = stats.GetByteCount()
		duration = int64(stats.GetDurationSeconds())
	}

	return FlowSummary{
		FlowID:      f.GetId(),
		Table:       int32(config.GetTable()),
		Priority:    int32(config.GetPriority()),
		PacketCount: packetCount,
		ByteCount:   byteCount,
		Duration:    duration,
		Match:       protoFlowMatchToTest(config.GetMatch()),
		Actions:     actions,
	}
}

// vlanToCreateResult converts a proto VLAN message to a VLANCreateResult.
func vlanToCreateResult(v *platformv1.VLAN, description string) *VLANCreateResult {
	config := v.GetConfig()

	var portCount int32
	if stats := v.GetStats(); stats != nil {
		portCount = int32(stats.GetPortCount())
	}

	return &VLANCreateResult{
		VLANID:      int32(config.GetVlanId()),
		Name:        config.GetName(),
		Description: description,
		Status:      "active",
		PortCount:   portCount,
		CreatedAt:   protoTimestampToTime(v.GetCreatedAt()),
	}
}

// vlanToSummary converts a proto VLAN message to a VLANSummary.
func vlanToSummary(v *platformv1.VLAN) VLANSummary {
	config := v.GetConfig()

	var portCount int32
	if stats := v.GetStats(); stats != nil {
		portCount = int32(stats.GetPortCount())
	}

	return VLANSummary{
		VLANID:    int32(config.GetVlanId()),
		Name:      config.GetName(),
		Status:    "active",
		PortCount: portCount,
		CreatedAt: protoTimestampToTime(v.GetCreatedAt()),
	}
}

// =============================================================================
// Time Conversion Helpers
// =============================================================================

// protoTimestampToTime converts a protobuf Timestamp pointer to time.Time.
// Returns zero time if the timestamp is nil.
func protoTimestampToTime(ts *timestamppb.Timestamp) time.Time {
	if ts == nil {
		return time.Time{}
	}
	return ts.AsTime()
}

// grpcSDNUnixToTime converts Unix timestamp to time.Time.
func grpcSDNUnixToTime(unix int64) time.Time {
	if unix == 0 {
		return time.Time{}
	}
	return time.Unix(unix, 0)
}

// =============================================================================
// Compile-time Interface Verification
// =============================================================================

// =============================================================================
// Policy Proto-to-Result Mapping Helpers
// =============================================================================

// policyRuleToProto converts a test PolicyRule to a proto PolicyRule.
func policyRuleToProto(r PolicyRule) *platformv1.PolicyRule {
	action, ok := policyRuleActionFromString[strings.ToLower(r.Action)]
	if !ok {
		action = platformv1.PolicyRuleAction_POLICY_RULE_ACTION_UNSPECIFIED
	}

	return &platformv1.PolicyRule{
		RuleId:   r.RuleID,
		Priority: r.Priority,
		Match: &platformv1.PolicyRuleMatch{
			SourceIp:        r.Match.SourceIP,
			DestinationIp:   r.Match.DestinationIP,
			SourcePort:      uint32(r.Match.SourcePort),
			DestinationPort: uint32(r.Match.DestinationPort),
			Protocol:        r.Match.Protocol,
			Direction:       r.Match.Direction,
			Interface:       r.Match.Interface,
			VlanId:          uint32(r.Match.VLANID),
			Dscp:            uint32(r.Match.DSCP),
			Application:     r.Match.Application,
		},
		Action:      action,
		ActionValue: r.ActionValue,
		Log:         r.Log,
		Counter:     r.Counter,
	}
}

// policyTargetToProto converts a test PolicyTarget to a proto PolicyTarget.
func policyTargetToProto(t PolicyTarget) *platformv1.PolicyTarget {
	targetType, ok := policyTargetTypeFromString[strings.ToLower(t.Type)]
	if !ok {
		targetType = platformv1.PolicyTargetType_POLICY_TARGET_TYPE_UNSPECIFIED
	}

	return &platformv1.PolicyTarget{
		Type:      targetType,
		Id:        t.ID,
		Direction: t.Direction,
	}
}

// policyScheduleToProto converts a test PolicySchedule to a proto PolicySchedule.
func policyScheduleToProto(s *PolicySchedule) *platformv1.PolicySchedule {
	if s == nil {
		return nil
	}
	return &platformv1.PolicySchedule{
		StartTime: s.StartTime,
		EndTime:   s.EndTime,
		Days:      s.Days,
		Timezone:  s.Timezone,
		Enabled:   s.Enabled,
	}
}

// policyToApplyResult converts a proto Policy message to a PolicyApplyResult.
func policyToApplyResult(p *platformv1.Policy) *PolicyApplyResult {
	config := p.GetConfig()

	return &PolicyApplyResult{
		PolicyID:    p.GetId(),
		Name:        config.GetName(),
		Type:        policyTypeToString[config.GetType()],
		Status:      policyStatusToString[p.GetStatus()],
		RuleCount:   int32(len(config.GetRules())),
		TargetCount: int32(len(config.GetTargets())),
		AppliedAt:   protoTimestampToTime(p.GetCreatedAt()),
	}
}

// policyToGetResult converts a proto Policy message to a PolicyGetResult.
func policyToGetResult(p *platformv1.Policy) *PolicyGetResult {
	config := p.GetConfig()

	rules := make([]PolicyRule, 0, len(config.GetRules()))
	for _, r := range config.GetRules() {
		match := r.GetMatch()
		rules = append(rules, PolicyRule{
			RuleID:   r.GetRuleId(),
			Priority: r.GetPriority(),
			Match: PolicyMatch{
				SourceIP:        match.GetSourceIp(),
				DestinationIP:   match.GetDestinationIp(),
				SourcePort:      int32(match.GetSourcePort()),
				DestinationPort: int32(match.GetDestinationPort()),
				Protocol:        match.GetProtocol(),
				Direction:       match.GetDirection(),
				Interface:       match.GetInterface(),
				VLANID:          int32(match.GetVlanId()),
				DSCP:            int32(match.GetDscp()),
				Application:     match.GetApplication(),
			},
			Action:      policyRuleActionToString[r.GetAction()],
			ActionValue: r.GetActionValue(),
			Log:         r.GetLog(),
			Counter:     r.GetCounter(),
		})
	}

	targets := make([]PolicyTarget, 0, len(config.GetTargets()))
	for _, t := range config.GetTargets() {
		targets = append(targets, PolicyTarget{
			Type:      policyTargetTypeToString[t.GetType()],
			ID:        t.GetId(),
			Direction: t.GetDirection(),
		})
	}

	var schedule *PolicySchedule
	if s := config.GetSchedule(); s != nil {
		schedule = &PolicySchedule{
			StartTime: s.GetStartTime(),
			EndTime:   s.GetEndTime(),
			Days:      s.GetDays(),
			Timezone:  s.GetTimezone(),
			Enabled:   s.GetEnabled(),
		}
	}

	return &PolicyGetResult{
		PolicyID:    p.GetId(),
		Name:        config.GetName(),
		Description: config.GetDescription(),
		Type:        policyTypeToString[config.GetType()],
		Priority:    config.GetPriority(),
		Enabled:     config.GetEnabled(),
		Status:      policyStatusToString[p.GetStatus()],
		Rules:       rules,
		Targets:     targets,
		Schedule:    schedule,
		HitCount:    p.GetHitCount(),
		ByteCount:   p.GetByteCount(),
		CreatedAt:   protoTimestampToTime(p.GetCreatedAt()),
		UpdatedAt:   protoTimestampToTime(p.GetUpdatedAt()),
	}
}

// policyToSummary converts a proto Policy message to a PolicySummary.
func policyToSummary(p *platformv1.Policy) PolicySummary {
	config := p.GetConfig()

	return PolicySummary{
		PolicyID:    p.GetId(),
		Name:        config.GetName(),
		Type:        policyTypeToString[config.GetType()],
		Priority:    config.GetPriority(),
		Enabled:     config.GetEnabled(),
		Status:      policyStatusToString[p.GetStatus()],
		RuleCount:   int32(len(config.GetRules())),
		TargetCount: int32(len(config.GetTargets())),
		HitCount:    p.GetHitCount(),
		CreatedAt:   protoTimestampToTime(p.GetCreatedAt()),
	}
}

// Ensure GRPCAdapter implements SDNCommands interface.
var _ SDNCommands = (*GRPCAdapter)(nil)
