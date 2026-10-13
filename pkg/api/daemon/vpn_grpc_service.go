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

package daemon

import (
	"context"
	"errors"
	"maps"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vpn"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// VPNBackend is the control-plane VPN service the transports bind to. It is
// satisfied by *vpn.Service.
type VPNBackend interface {
	EnrolPeer(ctx context.Context, peer vpn.Peer) (*vpn.Peer, error)
	ListPeers(ctx context.Context, tenantID string) ([]*vpn.Peer, error)
	RevokePeer(ctx context.Context, tenantID, deviceID string) error
	Status(ctx context.Context, gatewayID string) ([]vpn.GatewayStatus, error)
	GetPosturePolicy(ctx context.Context, tenantID, name string) (*vpn.PosturePolicy, error)
	SetPosturePolicy(ctx context.Context, policy vpn.PosturePolicy) (*vpn.PosturePolicy, error)
	DeletePosturePolicy(ctx context.Context, tenantID, name string) error
	ListPosturePolicies(ctx context.Context, tenantID string) ([]*vpn.PosturePolicy, error)
}

// Ensure the control-plane VPN service satisfies the backend contract.
var _ VPNBackend = (*vpn.Service)(nil)

// vpnServiceName is the service name the not-configured status carries.
const vpnServiceName = "vpn"

// VPNGRPCService implements the platform.v1 VPNService backed by the
// control-plane vpn.Service. The same instance is registered on the TCP gRPC
// server and the Unix-socket gRPC server, and backs the REST, QUIC, and MCP
// transports, so every protocol answers from the same store.
type VPNGRPCService struct {
	platformv1.UnimplementedVPNServiceServer

	backend VPNBackend
	logger  *logging.Logger
}

// NewVPNGRPCService creates the VPN gRPC service. A nil backend means the node
// has no control-plane store; every RPC then answers the typed
// not-configured status rather than panicking.
func NewVPNGRPCService(logger *logging.Logger, backend VPNBackend) *VPNGRPCService {
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	return &VPNGRPCService{logger: logger, backend: backend}
}

// buildVPNControlPlane builds the control-plane VPN service on the platform
// store, or returns nil when the daemon runs without one.
func buildVPNControlPlane(config *Config, logger *logging.Logger) *vpn.Service {
	storage := platformStorage(config)
	if storage == nil {
		return nil
	}
	service, err := vpn.NewService(storage, logger)
	if err != nil {
		logger.Error(err, "vpn control plane unavailable")
		return nil
	}
	return service
}

// Backend returns the configured backend.
func (s *VPNGRPCService) Backend() VPNBackend { return s.backend }

// requireBackend answers the not-configured status when the node has no VPN
// control plane.
func (s *VPNGRPCService) requireBackend() error {
	if s.backend == nil {
		return serviceNotConfigured(vpnServiceName, "the vpn control plane is not configured on this node")
	}
	return nil
}

// EnrolPeer enrols a device as a VPN peer of a tenant.
//
// Permission: vpn:write.
func (s *VPNGRPCService) EnrolPeer(ctx context.Context, req *platformv1.EnrolVPNPeerRequest) (*platformv1.EnrolVPNPeerResponse, error) {
	if err := s.requireBackend(); err != nil {
		return nil, err
	}
	if req.GetPeer() == nil {
		return nil, vpnErrToGRPC(&vpn.ErrInvalidArgument{Field: "peer", Reason: "is required"})
	}
	peer, err := s.backend.EnrolPeer(ctx, vpn.Peer{
		TenantID: req.GetPeer().GetTenantId(),
		DeviceID: req.GetPeer().GetDeviceId(),
		Zones:    req.GetPeer().GetZones(),
	})
	if err != nil {
		s.logger.Error(err, "vpn peer enrolment failed")
		return nil, vpnErrToGRPC(err)
	}
	return &platformv1.EnrolVPNPeerResponse{Peer: vpnPeerToPb(peer)}, nil
}

// ListPeers lists the enrolled peers of one tenant, or of all.
//
// Permission: vpn:read.
func (s *VPNGRPCService) ListPeers(ctx context.Context, req *platformv1.ListVPNPeersRequest) (*platformv1.ListVPNPeersResponse, error) {
	if err := s.requireBackend(); err != nil {
		return nil, err
	}
	peers, err := s.backend.ListPeers(ctx, req.GetTenantId())
	if err != nil {
		s.logger.Error(err, "vpn peer list failed")
		return nil, vpnErrToGRPC(err)
	}
	out := make([]*platformv1.VPNPeer, 0, len(peers))
	for _, peer := range peers {
		out = append(out, vpnPeerToPb(peer))
	}
	return &platformv1.ListVPNPeersResponse{Peers: out}, nil
}

// RevokePeer removes an enrolment.
//
// Permission: vpn:write.
func (s *VPNGRPCService) RevokePeer(ctx context.Context, req *platformv1.RevokeVPNPeerRequest) (*platformv1.RevokeVPNPeerResponse, error) {
	if err := s.requireBackend(); err != nil {
		return nil, err
	}
	if err := s.backend.RevokePeer(ctx, req.GetTenantId(), req.GetDeviceId()); err != nil {
		s.logger.Error(err, "vpn peer revocation failed")
		return nil, vpnErrToGRPC(err)
	}
	return &platformv1.RevokeVPNPeerResponse{}, nil
}

// GetStatus returns the VPN session state the gateways last reported.
//
// Permission: vpn:read.
func (s *VPNGRPCService) GetStatus(ctx context.Context, req *platformv1.GetVPNStatusRequest) (*platformv1.GetVPNStatusResponse, error) {
	if err := s.requireBackend(); err != nil {
		return nil, err
	}
	gateways, err := s.backend.Status(ctx, req.GetGatewayId())
	if err != nil {
		s.logger.Error(err, "vpn status query failed")
		return nil, vpnErrToGRPC(err)
	}
	out := make([]*platformv1.VPNGatewayStatus, 0, len(gateways))
	for i := range gateways {
		out = append(out, vpnGatewayStatusToPb(&gateways[i]))
	}
	return &platformv1.GetVPNStatusResponse{Gateways: out}, nil
}

// GetPosturePolicy returns one tenant posture policy.
//
// Permission: vpn:admin.
func (s *VPNGRPCService) GetPosturePolicy(ctx context.Context, req *platformv1.GetVPNPosturePolicyRequest) (*platformv1.GetVPNPosturePolicyResponse, error) {
	if err := s.requireBackend(); err != nil {
		return nil, err
	}
	policy, err := s.backend.GetPosturePolicy(ctx, req.GetTenantId(), req.GetName())
	if err != nil {
		return nil, vpnErrToGRPC(err)
	}
	return &platformv1.GetVPNPosturePolicyResponse{Policy: vpnPosturePolicyToPb(policy)}, nil
}

// SetPosturePolicy creates or replaces a tenant posture policy. A module that
// does not compile is refused and nothing is stored.
//
// Permission: vpn:admin.
func (s *VPNGRPCService) SetPosturePolicy(ctx context.Context, req *platformv1.SetVPNPosturePolicyRequest) (*platformv1.SetVPNPosturePolicyResponse, error) {
	if err := s.requireBackend(); err != nil {
		return nil, err
	}
	if req.GetPolicy() == nil {
		return nil, vpnErrToGRPC(&vpn.ErrInvalidArgument{Field: "policy", Reason: "is required"})
	}
	policy, err := s.backend.SetPosturePolicy(ctx, vpn.PosturePolicy{
		TenantID: req.GetPolicy().GetTenantId(),
		Name:     req.GetPolicy().GetName(),
		Module:   req.GetPolicy().GetModule(),
	})
	if err != nil {
		s.logger.Error(err, "vpn posture policy update failed")
		return nil, vpnErrToGRPC(err)
	}
	return &platformv1.SetVPNPosturePolicyResponse{Policy: vpnPosturePolicyToPb(policy)}, nil
}

// DeletePosturePolicy removes a tenant posture policy.
//
// Permission: vpn:admin.
func (s *VPNGRPCService) DeletePosturePolicy(ctx context.Context, req *platformv1.DeleteVPNPosturePolicyRequest) (*platformv1.DeleteVPNPosturePolicyResponse, error) {
	if err := s.requireBackend(); err != nil {
		return nil, err
	}
	if err := s.backend.DeletePosturePolicy(ctx, req.GetTenantId(), req.GetName()); err != nil {
		s.logger.Error(err, "vpn posture policy delete failed")
		return nil, vpnErrToGRPC(err)
	}
	return &platformv1.DeleteVPNPosturePolicyResponse{}, nil
}

// ListPosturePolicies lists the posture policies of one tenant, or of all.
//
// Permission: vpn:admin.
func (s *VPNGRPCService) ListPosturePolicies(ctx context.Context, req *platformv1.ListVPNPosturePoliciesRequest) (*platformv1.ListVPNPosturePoliciesResponse, error) {
	if err := s.requireBackend(); err != nil {
		return nil, err
	}
	policies, err := s.backend.ListPosturePolicies(ctx, req.GetTenantId())
	if err != nil {
		s.logger.Error(err, "vpn posture policy list failed")
		return nil, vpnErrToGRPC(err)
	}
	out := make([]*platformv1.VPNPosturePolicy, 0, len(policies))
	for _, policy := range policies {
		out = append(out, vpnPosturePolicyToPb(policy))
	}
	return &platformv1.ListVPNPosturePoliciesResponse{Policies: out}, nil
}

// vpnErrToGRPC maps the control-plane VPN errors onto gRPC status codes. An
// unrecognised error is Internal, never a success.
func vpnErrToGRPC(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return status.FromContextError(err).Err()
	}

	var (
		invalidArgument  *vpn.ErrInvalidArgument
		invalidPolicy    *vpn.ErrInvalidPosturePolicy
		peerNotFound     *vpn.ErrPeerNotFound
		policyNotFound   *vpn.ErrPosturePolicyNotFound
		gatewayNotFound  *vpn.ErrGatewayNotFound
		keyCollision     *vpn.ErrKeyCollision
		storeUnavailable *vpn.ErrStoreUnavailable
		engineDown       *vpn.ErrPolicyEngineUnavailable
		statusDown       *vpn.ErrStatusUnavailable
	)
	switch {
	case errors.As(err, &invalidArgument), errors.As(err, &invalidPolicy):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.As(err, &peerNotFound), errors.As(err, &policyNotFound), errors.As(err, &gatewayNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.As(err, &keyCollision):
		return status.Error(codes.Aborted, err.Error())
	case errors.As(err, &storeUnavailable), errors.As(err, &engineDown), errors.As(err, &statusDown):
		return status.Error(codes.Unavailable, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}

func vpnPeerToPb(peer *vpn.Peer) *platformv1.VPNPeer {
	return &platformv1.VPNPeer{
		TenantId:       peer.TenantID,
		DeviceId:       peer.DeviceID,
		Zones:          peer.Zones,
		EnrolledAtUnix: unixOrZero(peer.EnrolledAt),
	}
}

func vpnPosturePolicyToPb(policy *vpn.PosturePolicy) *platformv1.VPNPosturePolicy {
	return &platformv1.VPNPosturePolicy{
		TenantId:      policy.TenantID,
		Name:          policy.Name,
		Module:        policy.Module,
		UpdatedAtUnix: unixOrZero(policy.UpdatedAt),
	}
}

// vpnGatewayStatusToPb projects one gateway's reported VPN section. A gateway
// that reports without a VPN section has reporting=false.
func vpnGatewayStatusToPb(gateway *vpn.GatewayStatus) *platformv1.VPNGatewayStatus {
	out := &platformv1.VPNGatewayStatus{
		GatewayId:      gateway.GatewayID,
		ReportedAtUnix: unixOrZero(gateway.ReportedAt),
	}
	state := gateway.VPN
	if state == nil {
		return out
	}
	out.Reporting = true
	out.Running = state.Running
	out.Admissions = state.Admissions
	out.Refusals = state.Refusals
	out.LastRefusal = state.LastRefusal
	out.EnrolledPeers = clampUint32(state.EnrolledPeers)
	out.PosturePolicyErrors = state.PosturePolicyErrors
	for _, peer := range state.RejectedPeers {
		out.RejectedPeers = append(out.RejectedPeers, &platformv1.VPNRejectedPeer{
			TenantId: peer.TenantID,
			DeviceId: peer.DeviceID,
			Reason:   peer.Reason,
		})
	}
	if len(state.LeasesByDataPlane) > 0 {
		out.LeasesByDataPlane = make(map[string]uint32, len(state.LeasesByDataPlane))
		for plane, count := range maps.All(state.LeasesByDataPlane) {
			out.LeasesByDataPlane[plane] = clampUint32(count)
		}
	}
	out.Leases = make([]*platformv1.VPNLease, 0, len(state.Leases))
	for i := range state.Leases {
		out.Leases = append(out.Leases, vpnLeaseToPb(&state.Leases[i]))
	}
	return out
}

func vpnLeaseToPb(lease *gwstate.VPNLeaseState) *platformv1.VPNLease {
	return &platformv1.VPNLease{
		Id:            lease.ID,
		TenantId:      lease.TenantID,
		DeviceId:      lease.DeviceID,
		Address:       lease.Address,
		DataPlane:     lease.DataPlane,
		Zones:         lease.Zones,
		IssuedAtUnix:  unixOrZero(lease.IssuedAt),
		ExpiresAtUnix: unixOrZero(lease.ExpiresAt),
		Renewals:      clampUint32(lease.Renewals),
	}
}

// clampUint32 converts a non-negative count, saturating instead of wrapping.
func clampUint32(n int) uint32 {
	switch {
	case n < 0:
		return 0
	case uint64(n) > uint64(^uint32(0)):
		return ^uint32(0)
	default:
		return uint32(n)
	}
}
