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
	"cmp"
	"context"
	"errors"
	"math"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// registerClusterGRPCService builds the platform.v1.ClusterService the
// daemon serves and registers it on every non-nil server (the TCP listener
// and the Unix socket). The service is grpcapi.ClusterGRPCService over a
// clusterGRPCBackend; the backend is returned so Daemon.SetClusterService
// can hand it the same ClusterServicer the MCP cluster tools use.
func registerClusterGRPCService(
	logger *logging.Logger,
	servers ...*grpc.Server,
) (*grpcapi.ClusterGRPCService, *clusterGRPCBackend) {
	backend := newClusterGRPCBackend()
	service := grpcapi.NewClusterGRPCService(logger, backend)
	for _, server := range servers {
		if server != nil {
			platformv1.RegisterClusterServiceServer(server, service)
		}
	}
	return service, backend
}

// clusterServicerRef boxes a ClusterServicer so an atomic.Pointer can hold
// any implementation; atomic.Value panics when the concrete type changes.
type clusterServicerRef struct {
	svc ClusterServicer
}

// clusterGRPCBackend implements grpcapi.ClusterService on top of the
// daemon's ClusterServicer. It holds the servicer behind an atomic pointer:
// the gRPC service is registered before the servicer exists, and requests
// read it without a lock. Until a servicer is set every operation returns
// grpcapi.ErrClusterServiceUnavailable (gRPC Unavailable, REST 503).
type clusterGRPCBackend struct {
	ref atomic.Pointer[clusterServicerRef]
	now func() time.Time
}

func newClusterGRPCBackend() *clusterGRPCBackend {
	return &clusterGRPCBackend{now: time.Now}
}

// set installs svc as the servicer behind every cluster RPC. A nil svc
// clears it, so the RPCs report the service as unavailable again.
func (b *clusterGRPCBackend) set(svc ClusterServicer) {
	if svc == nil {
		b.ref.Store(nil)
		return
	}
	b.ref.Store(&clusterServicerRef{svc: svc})
}

func (b *clusterGRPCBackend) servicer() (ClusterServicer, error) {
	ref := b.ref.Load()
	if ref == nil {
		return nil, grpcapi.ErrClusterServiceUnavailable{}
	}
	return ref.svc, nil
}

// Bootstrap initializes a new cluster with this node as its first member.
// The node's addresses come from the daemon's cluster configuration; the
// request's cluster and node names are echoed in the response.
func (b *clusterGRPCBackend) Bootstrap(
	ctx context.Context,
	req *grpcapi.ClusterBootstrapRequest,
) (*grpcapi.ClusterBootstrapResponse, error) {
	svc, err := b.servicer()
	if err != nil {
		return nil, err
	}
	if err := svc.Bootstrap(ctx); err != nil {
		return nil, err
	}
	st, err := svc.Status(ctx)
	if err != nil {
		return nil, err
	}
	return &grpcapi.ClusterBootstrapResponse{
		Cluster: clusterInfoToGRPC(req.ClusterName, st, nil),
		Node:    localClusterNode(svc, req.NodeName),
	}, nil
}

// Join adds this node to the cluster reachable through the seed addresses.
func (b *clusterGRPCBackend) Join(
	ctx context.Context,
	req *grpcapi.ClusterJoinRequest,
) (*grpcapi.ClusterJoinResponse, error) {
	svc, err := b.servicer()
	if err != nil {
		return nil, err
	}
	if err := svc.Join(ctx, req.SeedAddresses); err != nil {
		return nil, err
	}
	st, err := svc.Status(ctx)
	if err != nil {
		return nil, err
	}
	return &grpcapi.ClusterJoinResponse{
		Cluster: clusterInfoToGRPC("", st, nil),
		Node:    localClusterNode(svc, req.NodeName),
	}, nil
}

// Leave removes this node from the cluster. An empty NodeID means this
// node; any other node must be asked directly. A non-zero TimeoutSeconds
// bounds the leave, and running out of it reports ErrLeaveTimeout.
func (b *clusterGRPCBackend) Leave(
	ctx context.Context,
	req *grpcapi.ClusterLeaveRequest,
) (*grpcapi.ClusterLeaveResponse, error) {
	svc, err := b.servicer()
	if err != nil {
		return nil, err
	}
	local := formatClusterNodeID(svc.NodeID())
	if req.NodeID != "" && req.NodeID != local {
		return nil, grpcapi.ErrLeaveNodeNotLocal{NodeID: req.NodeID, LocalNodeID: local}
	}
	if req.TimeoutSeconds > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(req.TimeoutSeconds)*time.Second)
		defer cancel()
	}
	if err := svc.Leave(ctx); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, grpcapi.ErrLeaveTimeout{}
		}
		return nil, err
	}
	return &grpcapi.ClusterLeaveResponse{
		Success: true,
		Message: "node " + local + " left the cluster",
	}, nil
}

// GetStatus reports the cluster state and this node; with IncludeNodes it
// also lists every member.
func (b *clusterGRPCBackend) GetStatus(
	ctx context.Context,
	req *grpcapi.ClusterGetStatusRequest,
) (*grpcapi.ClusterGetStatusResponse, error) {
	svc, err := b.servicer()
	if err != nil {
		return nil, err
	}
	st, err := svc.Status(ctx)
	if err != nil {
		return nil, err
	}
	resp := &grpcapi.ClusterGetStatusResponse{
		LocalNode: localClusterNode(svc, ""),
		Timestamp: b.now().Unix(),
	}
	if !req.IncludeNodes {
		resp.Cluster = clusterInfoToGRPC("", st, nil)
		return resp, nil
	}

	nodes, err := svc.Nodes(ctx)
	if err != nil {
		return nil, err
	}
	var leader *ClusterNodeInfo
	if nodes != nil {
		leader = nodes.Leader
		resp.Nodes = make([]*grpcapi.ClusterNodeInfo, 0, len(nodes.Nodes))
		for _, n := range nodes.Nodes {
			node := clusterNodeToGRPC(n)
			if n.ID == svc.NodeID() {
				resp.LocalNode = node
			}
			resp.Nodes = append(resp.Nodes, node)
		}
	}
	resp.Cluster = clusterInfoToGRPC("", st, leader)
	return resp, nil
}

// clusterNodeSortKeys maps the ListNodes sort_by values to comparators.
// An empty sort_by keeps the cluster service's order.
var clusterNodeSortKeys = map[string]func(a, b ClusterNodeInfo) int{
	"id":      func(a, b ClusterNodeInfo) int { return cmp.Compare(a.ID, b.ID) },
	"address": func(a, b ClusterNodeInfo) int { return strings.Compare(a.Address, b.Address) },
}

// ListNodes lists cluster members, filtered by role, state and metadata
// labels, then sorted and paginated. Pages are 1-based; a zero page size
// returns every matching node on one page.
func (b *clusterGRPCBackend) ListNodes(
	ctx context.Context,
	req *grpcapi.ClusterListNodesRequest,
) (*grpcapi.ClusterListNodesResponse, error) {
	compare, sortable := clusterNodeSortKeys[req.SortBy]
	if req.SortBy != "" && !sortable {
		return nil, grpcapi.ErrUnsupportedNodeSortField{Field: req.SortBy}
	}
	svc, err := b.servicer()
	if err != nil {
		return nil, err
	}
	nodes, err := svc.Nodes(ctx)
	if err != nil {
		return nil, err
	}

	var members []ClusterNodeInfo
	if nodes != nil {
		members = slices.Clone(nodes.Nodes)
	}
	if sortable {
		slices.SortStableFunc(members, func(a, b ClusterNodeInfo) int {
			if req.Ascending {
				return compare(a, b)
			}
			return compare(b, a)
		})
	}

	matched := make([]*grpcapi.ClusterNodeInfo, 0, len(members))
	for _, n := range members {
		node := clusterNodeToGRPC(n)
		if clusterNodeMatches(node, req) {
			matched = append(matched, node)
		}
	}
	return paginateClusterNodes(matched, req.Page, req.PageSize), nil
}

// clusterNodeMatches reports whether node passes the request's role, state
// and label filters. An empty filter matches every node.
func clusterNodeMatches(node *grpcapi.ClusterNodeInfo, req *grpcapi.ClusterListNodesRequest) bool {
	if len(req.Roles) > 0 && !slices.Contains(req.Roles, node.Role) {
		return false
	}
	if len(req.States) > 0 && !slices.Contains(req.States, node.State) {
		return false
	}
	for key, want := range req.MatchLabels {
		if got, ok := node.Metadata[key]; !ok || got != want {
			return false
		}
	}
	return true
}

// paginateClusterNodes returns the requested 1-based page of nodes.
func paginateClusterNodes(nodes []*grpcapi.ClusterNodeInfo, page, pageSize uint32) *grpcapi.ClusterListNodesResponse {
	total := clusterCount(len(nodes))
	if page == 0 {
		page = 1
	}
	if pageSize == 0 {
		pageSize = max(total, 1)
	}
	totalPages := total / pageSize
	if total%pageSize > 0 {
		totalPages++
	}

	start := uint64(page-1) * uint64(pageSize)
	end := min(start+uint64(pageSize), uint64(total))
	pageNodes := []*grpcapi.ClusterNodeInfo{}
	if start < end {
		pageNodes = nodes[start:end]
	}
	return &grpcapi.ClusterListNodesResponse{
		Nodes:      pageNodes,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
		TotalItems: uint64(total),
	}
}

// clusterStates maps ClusterStatusInfo.State (the pkg/cluster
// ClusterState values) to the gRPC cluster state. Unknown states map to
// ClusterStateUnspecified.
var clusterStates = map[string]grpcapi.ClusterStateType{
	"bootstrapping": grpcapi.ClusterStateInitializing,
	"joining":       grpcapi.ClusterStateInitializing,
	"running":       grpcapi.ClusterStateHealthy,
	"degraded":      grpcapi.ClusterStateDegraded,
	"uninitialized": grpcapi.ClusterStateUnavailable,
	"leaving":       grpcapi.ClusterStateUnavailable,
	"stopped":       grpcapi.ClusterStateUnavailable,
}

// clusterNodeCondition is the gRPC state and health of one node state.
type clusterNodeCondition struct {
	state  grpcapi.NodeStateType
	health grpcapi.HealthStatusType
}

// clusterNodeConditions maps ClusterNodeInfo.State (the pkg/cluster
// NodeState strings) to the gRPC node state and health. Unknown states map
// to the unspecified values.
var clusterNodeConditions = map[string]clusterNodeCondition{
	"healthy":   {grpcapi.NodeStateActive, grpcapi.HealthStatusHealthy},
	"suspect":   {grpcapi.NodeStateUnreachable, grpcapi.HealthStatusDegraded},
	"unhealthy": {grpcapi.NodeStateFailed, grpcapi.HealthStatusUnhealthy},
	"leaving":   {grpcapi.NodeStateLeaving, grpcapi.HealthStatusUnspecified},
}

// clusterInfoToGRPC builds the cluster summary from the servicer status.
// leader, when known, supplies the leader's address.
func clusterInfoToGRPC(name string, st *ClusterStatusInfo, leader *ClusterNodeInfo) *grpcapi.ClusterInfoData {
	if st == nil {
		st = &ClusterStatusInfo{}
	}
	info := &grpcapi.ClusterInfoData{
		Name:         name,
		State:        clusterStates[st.State],
		TotalNodes:   clusterCount(st.NodeCount),
		HealthyNodes: clusterCount(st.HealthyCount),
		Term:         st.Term,
		CreatedAt:    unixOrZero(st.StartedAt),
	}
	if st.LeaderID != 0 {
		info.LeaderID = formatClusterNodeID(st.LeaderID)
	}
	if leader != nil {
		info.LeaderAddress = leader.Address
	}
	if st.ErrorMessage != "" {
		info.Metadata = map[string]string{"error_message": st.ErrorMessage}
	}
	return info
}

// clusterNodeToGRPC converts one servicer node. The node's "host:port"
// address is split into Address and Port.
func clusterNodeToGRPC(n ClusterNodeInfo) *grpcapi.ClusterNodeInfo {
	host, port := splitClusterAddress(n.Address)
	role := grpcapi.NodeRoleFollower
	if n.IsLeader {
		role = grpcapi.NodeRoleLeader
	}
	condition := clusterNodeConditions[n.State]
	return &grpcapi.ClusterNodeInfo{
		ID:            formatClusterNodeID(n.ID),
		Address:       host,
		Port:          port,
		Role:          role,
		State:         condition.state,
		Health:        condition.health,
		JoinedAt:      unixOrZero(n.JoinTime),
		LastHeartbeat: unixOrZero(n.LastSeen),
		Metadata:      n.Metadata,
	}
}

// localClusterNode describes the serving node after a successful
// membership change.
func localClusterNode(svc ClusterServicer, name string) *grpcapi.ClusterNodeInfo {
	role := grpcapi.NodeRoleFollower
	if svc.IsLeader() {
		role = grpcapi.NodeRoleLeader
	}
	return &grpcapi.ClusterNodeInfo{
		ID:    formatClusterNodeID(svc.NodeID()),
		Name:  name,
		Role:  role,
		State: grpcapi.NodeStateActive,
	}
}

func formatClusterNodeID(id uint64) string {
	return strconv.FormatUint(id, 10)
}

// splitClusterAddress splits "host:port". An address without a valid port
// is returned whole with port 0.
func splitClusterAddress(address string) (string, uint32) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return address, 0
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return address, 0
	}
	return host, uint32(port)
}

// clusterCount converts a node count to the wire width, clamping negatives
// to zero.
func clusterCount(n int) uint32 {
	if n <= 0 {
		return 0
	}
	if uint64(n) > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(n)
}

var _ grpcapi.ClusterService = (*clusterGRPCBackend)(nil)
