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
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"google.golang.org/grpc"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
)

// =============================================================================
// Error Types
// =============================================================================

// ErrOverlayGRPCConnectionFailed indicates a gRPC connection failure.
type ErrOverlayGRPCConnectionFailed struct {
	Endpoint string
	Err      error
}

func (e ErrOverlayGRPCConnectionFailed) Error() string {
	return fmt.Sprintf("overlay gRPC connection to %s failed: %v", e.Endpoint, e.Err)
}

func (e ErrOverlayGRPCConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrOverlayGRPCBackendUnavailable indicates the backend is unavailable.
type ErrOverlayGRPCBackendUnavailable struct {
	Endpoint string
	Err      error
}

func (e ErrOverlayGRPCBackendUnavailable) Error() string {
	return fmt.Sprintf("overlay gRPC backend at %s unavailable: %v", e.Endpoint, e.Err)
}

func (e ErrOverlayGRPCBackendUnavailable) Unwrap() error {
	return e.Err
}

// =============================================================================
// Overlay gRPC Adapter
// =============================================================================

// OverlayGRPCAdapter implements OverlayCommands using gRPC calls to platformd.
type OverlayGRPCAdapter struct {
	conn          *grpc.ClientConn
	endpoint      string
	overlayClient platformv1.OverlayServiceClient
	gatewayClient platformv1.GatewayServiceClient
}

// NewOverlayGRPCAdapter creates a new overlay gRPC adapter.
func NewOverlayGRPCAdapter() *OverlayGRPCAdapter {
	endpoint := os.Getenv("PLATFORM_GRPC_ENDPOINT")
	if endpoint == "" {
		endpoint = GetServiceEndpoints().PlatformdGRPC
	}

	return &OverlayGRPCAdapter{
		endpoint: endpoint,
	}
}

// Name returns the protocol adapter identifier.
func (g *OverlayGRPCAdapter) Name() string {
	return "gRPC"
}

// Setup initializes the gRPC connection using the modern NewClient API
// with mTLS credentials from helpers. The parent context controls the
// overall timeout for the connectivity verification call.
func (g *OverlayGRPCAdapter) Setup(ctx context.Context) error {
	conn, err := grpc.NewClient(g.endpoint,
		helpers.GRPCTransportCredentials(),
	)
	if err != nil {
		return ErrOverlayGRPCConnectionFailed{Endpoint: g.endpoint, Err: err}
	}

	g.conn = conn
	g.overlayClient = platformv1.NewOverlayServiceClient(conn)
	g.gatewayClient = platformv1.NewGatewayServiceClient(conn)

	// Verify connectivity using the parent context timeout rather than
	// a separate short timeout that can cause broken pipe errors.
	_, err = g.overlayClient.GetOverlayStatus(ctx, &platformv1.GetOverlayStatusRequest{})
	if err != nil {
		g.conn.Close()
		g.conn = nil
		g.overlayClient = nil
		g.gatewayClient = nil
		return ErrOverlayGRPCBackendUnavailable{Endpoint: g.endpoint, Err: err}
	}

	return nil
}

// Teardown closes the gRPC connection.
func (g *OverlayGRPCAdapter) Teardown() error {
	if g.conn != nil {
		return g.conn.Close()
	}
	return nil
}

// =============================================================================
// Overlay Status Commands
// =============================================================================

// OverlayStatus returns the current overlay network status.
func (g *OverlayGRPCAdapter) OverlayStatus(ctx context.Context) (*OverlayStatusResult, error) {
	resp, err := g.overlayClient.GetOverlayStatus(ctx, &platformv1.GetOverlayStatusRequest{})
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetOverlayStatus", Err: err}
	}

	vtepIP, _ := netip.ParseAddr(resp.Status.VtepIp)

	return &OverlayStatusResult{
		NodeID:         resp.Status.NodeId,
		VTEPIP:         vtepIP,
		VXLANPort:      uint16(resp.Status.VxlanPort),
		VNICount:       int(resp.Status.VniCount),
		VTEPCount:      int(resp.Status.VtepCount),
		RemoteMACCount: int(resp.Status.RemoteMacCount),
		TunnelCount:    int(resp.Status.TunnelCount),
	}, nil
}

// =============================================================================
// VTEP Commands
// =============================================================================

// VTEPList returns all known VTEPs.
func (g *OverlayGRPCAdapter) VTEPList(ctx context.Context) (*VTEPListResult, error) {
	resp, err := g.overlayClient.ListVTEPs(ctx, &platformv1.ListVTEPsRequest{})
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "ListVTEPs", Err: err}
	}

	vteps := make([]VTEPInfo, len(resp.Vteps))
	for i, v := range resp.Vteps {
		ip, _ := netip.ParseAddr(v.Ip)
		var lastSeen time.Time
		if v.LastSeen != nil {
			lastSeen = v.LastSeen.AsTime()
		}
		vteps[i] = VTEPInfo{
			NodeID:   v.NodeId,
			IP:       ip,
			Healthy:  v.Healthy,
			LastSeen: lastSeen,
		}
	}

	return &VTEPListResult{
		VTEPs:      vteps,
		TotalCount: len(vteps),
	}, nil
}

// VTEPGet returns details for a specific VTEP.
func (g *OverlayGRPCAdapter) VTEPGet(ctx context.Context, nodeID string) (*VTEPGetResult, error) {
	resp, err := g.overlayClient.GetVTEP(ctx, &platformv1.GetVTEPRequest{NodeId: nodeID})
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetVTEP", Err: err}
	}

	ip, _ := netip.ParseAddr(resp.Vtep.Ip)
	var lastSeen time.Time
	if resp.Vtep.LastSeen != nil {
		lastSeen = resp.Vtep.LastSeen.AsTime()
	}

	vnis := make([]uint32, len(resp.Vtep.Vnis))
	copy(vnis, resp.Vtep.Vnis)

	return &VTEPGetResult{
		VTEPInfo: VTEPInfo{
			NodeID:   resp.Vtep.NodeId,
			IP:       ip,
			Healthy:  resp.Vtep.Healthy,
			LastSeen: lastSeen,
		},
		VNIs: vnis,
	}, nil
}

// =============================================================================
// VNI Commands
// =============================================================================

// VNICreate creates a new VNI.
func (g *OverlayGRPCAdapter) VNICreate(ctx context.Context, opts VNICreateOptions) (*VNICreateResult, error) {
	resp, err := g.overlayClient.CreateVNI(ctx, &platformv1.CreateVNIRequest{
		Config: &platformv1.VNIConfig{
			Vni:  opts.VNI,
			Vlan: uint32(opts.VLAN),
			Name: opts.Name,
		},
	})
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "CreateVNI", Err: err}
	}

	var createdAt time.Time
	if resp.Vni != nil && resp.Vni.CreatedAt != nil {
		createdAt = resp.Vni.CreatedAt.AsTime()
	}
	var vniVal uint32
	var vlanVal uint16
	var name string
	if resp.Vni != nil && resp.Vni.Config != nil {
		vniVal = resp.Vni.Config.Vni
		vlanVal = uint16(resp.Vni.Config.Vlan)
		name = resp.Vni.Config.Name
	}
	return &VNICreateResult{
		VNI:       vniVal,
		VLAN:      vlanVal,
		Name:      name,
		CreatedAt: createdAt,
	}, nil
}

// VNIDelete deletes a VNI.
func (g *OverlayGRPCAdapter) VNIDelete(ctx context.Context, vni uint32) (*VNIDeleteResult, error) {
	resp, err := g.overlayClient.DeleteVNI(ctx, &platformv1.DeleteVNIRequest{Vni: vni})
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "DeleteVNI", Err: err}
	}

	deleted := resp.Status != nil && resp.Status.Success
	return &VNIDeleteResult{
		VNI:     vni,
		Deleted: deleted,
	}, nil
}

// VNIList lists all VNIs.
func (g *OverlayGRPCAdapter) VNIList(ctx context.Context) (*VNIListResult, error) {
	resp, err := g.overlayClient.ListVNIs(ctx, &platformv1.ListVNIsRequest{})
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "ListVNIs", Err: err}
	}

	vnis := make([]VNIInfo, len(resp.Vnis))
	for i, v := range resp.Vnis {
		var vniVal uint32
		var vlanVal uint16
		var name string
		if v.Config != nil {
			vniVal = v.Config.Vni
			vlanVal = uint16(v.Config.Vlan)
			name = v.Config.Name
		}
		var createdAt time.Time
		if v.CreatedAt != nil {
			createdAt = v.CreatedAt.AsTime()
		}
		vnis[i] = VNIInfo{
			VNI:       vniVal,
			VLAN:      vlanVal,
			Name:      name,
			MACCount:  int(v.MacCount),
			CreatedAt: createdAt,
		}
	}

	return &VNIListResult{
		VNIs:       vnis,
		TotalCount: len(vnis),
	}, nil
}

// =============================================================================
// Tunnel Commands
// =============================================================================

// TunnelList lists all tunnels.
func (g *OverlayGRPCAdapter) TunnelList(ctx context.Context, opts TunnelListOptions) (*TunnelListResult, error) {
	resp, err := g.overlayClient.ListTunnels(ctx, &platformv1.ListTunnelsRequest{Vni: opts.VNI})
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "ListTunnels", Err: err}
	}

	tunnels := make([]TunnelInfo, len(resp.Tunnels))
	for i, t := range resp.Tunnels {
		localVTEP, _ := netip.ParseAddr(t.LocalVtep)
		remoteVTEP, _ := netip.ParseAddr(t.RemoteVtep)
		tunnels[i] = TunnelInfo{
			LocalVTEP:  localVTEP,
			RemoteVTEP: remoteVTEP,
			VNI:        t.Vni,
			State:      t.State,
			BytesSent:  t.BytesTx,
			BytesRecv:  t.BytesRx,
		}
	}

	return &TunnelListResult{
		Tunnels:    tunnels,
		TotalCount: len(tunnels),
	}, nil
}

// =============================================================================
// MAC Commands
// =============================================================================

// MACList lists remote MACs.
func (g *OverlayGRPCAdapter) MACList(ctx context.Context, opts MACListOptions) (*MACListResult, error) {
	resp, err := g.overlayClient.ListRemoteMACs(ctx, &platformv1.ListRemoteMACsRequest{Vni: opts.VNI})
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "ListRemoteMACs", Err: err}
	}

	macs := make([]RemoteMACInfo, len(resp.Macs))
	for i, m := range resp.Macs {
		mac, _ := net.ParseMAC(m.Mac)
		remoteVTEP, _ := netip.ParseAddr(m.RemoteVtep)
		var learnedAt time.Time
		if m.LearnedAt != nil {
			learnedAt = m.LearnedAt.AsTime()
		}
		macs[i] = RemoteMACInfo{
			MAC:        mac,
			VNI:        m.Vni,
			RemoteVTEP: remoteVTEP,
			LearnedAt:  learnedAt,
		}
	}

	return &MACListResult{
		MACs:       macs,
		TotalCount: len(macs),
	}, nil
}

// MACForget removes a learned MAC.
func (g *OverlayGRPCAdapter) MACForget(ctx context.Context, mac string, vni uint32) (*MACForgetResult, error) {
	resp, err := g.overlayClient.ForgetMAC(ctx, &platformv1.ForgetMACRequest{Mac: mac, Vni: vni})
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "ForgetMAC", Err: err}
	}

	deleted := resp.Status != nil && resp.Status.Success
	return &MACForgetResult{
		MAC:     mac,
		VNI:     vni,
		Deleted: deleted,
	}, nil
}

// =============================================================================
// Gateway Commands
// =============================================================================

// GatewayStatus returns gateway status.
func (g *OverlayGRPCAdapter) GatewayStatus(ctx context.Context) (*GatewayStatusResult, error) {
	resp, err := g.gatewayClient.GetGatewayStatus(ctx, &platformv1.GetGatewayStatusRequest{})
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetGatewayStatus", Err: err}
	}

	// Convert modes bitmask to string slice
	var modes []string
	if resp.Status.Modes&uint32(platformv1.GatewayModeEnum_GATEWAY_MODE_OVERLAY) != 0 {
		modes = append(modes, "overlay")
	}
	if resp.Status.Modes&uint32(platformv1.GatewayModeEnum_GATEWAY_MODE_EDGE) != 0 {
		modes = append(modes, "edge")
	}
	if resp.Status.Modes&uint32(platformv1.GatewayModeEnum_GATEWAY_MODE_TRANSIT) != 0 {
		modes = append(modes, "transit")
	}

	return &GatewayStatusResult{
		NodeID:     resp.Status.NodeId,
		Modes:      modes,
		Tier:       resp.Status.Tier,
		Healthy:    resp.Status.Healthy,
		Reputation: resp.Status.Reputation,
		Age:        time.Duration(resp.Status.UptimeSeconds) * time.Second,
	}, nil
}

// GatewaySetMode sets gateway modes.
func (g *OverlayGRPCAdapter) GatewaySetMode(ctx context.Context, opts GatewayModeOptions) (*GatewayModeResult, error) {
	// Convert mode strings to bitmask
	var modesBitmask uint32
	for _, mode := range opts.Modes {
		switch mode {
		case "overlay":
			modesBitmask |= uint32(platformv1.GatewayModeEnum_GATEWAY_MODE_OVERLAY)
		case "edge":
			modesBitmask |= uint32(platformv1.GatewayModeEnum_GATEWAY_MODE_EDGE)
		case "transit":
			modesBitmask |= uint32(platformv1.GatewayModeEnum_GATEWAY_MODE_TRANSIT)
		}
	}

	resp, err := g.gatewayClient.SetGatewayMode(ctx, &platformv1.SetGatewayModeRequest{Modes: modesBitmask})
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "SetGatewayMode", Err: err}
	}

	success := resp.Status != nil && resp.Status.Success

	// Convert response modes back to strings
	var resultModes []string
	if resp.GatewayStatus != nil {
		if resp.GatewayStatus.Modes&uint32(platformv1.GatewayModeEnum_GATEWAY_MODE_OVERLAY) != 0 {
			resultModes = append(resultModes, "overlay")
		}
		if resp.GatewayStatus.Modes&uint32(platformv1.GatewayModeEnum_GATEWAY_MODE_EDGE) != 0 {
			resultModes = append(resultModes, "edge")
		}
		if resp.GatewayStatus.Modes&uint32(platformv1.GatewayModeEnum_GATEWAY_MODE_TRANSIT) != 0 {
			resultModes = append(resultModes, "transit")
		}
	}

	return &GatewayModeResult{
		Modes:   resultModes,
		Success: success,
	}, nil
}

// =============================================================================
// BGP Commands
// =============================================================================

// BGPStatus returns BGP status.
func (g *OverlayGRPCAdapter) BGPStatus(ctx context.Context) (*BGPStatusResult, error) {
	resp, err := g.gatewayClient.GetBGPStatus(ctx, &platformv1.GetBGPStatusRequest{})
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetBGPStatus", Err: err}
	}

	return &BGPStatusResult{
		Enabled:          resp.Status.Running,
		ASN:              resp.Status.LocalAsn,
		RouterID:         resp.Status.RouterId,
		PeerCount:        int(resp.Status.PeerCount),
		EstablishedCount: int(resp.Status.EstablishedPeers),
	}, nil
}

// BGPPeers returns BGP peers.
func (g *OverlayGRPCAdapter) BGPPeers(ctx context.Context) (*BGPPeersResult, error) {
	resp, err := g.gatewayClient.ListBGPPeers(ctx, &platformv1.ListBGPPeersRequest{})
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "ListBGPPeers", Err: err}
	}

	peers := make([]BGPPeerInfo, len(resp.Peers))
	for i, p := range resp.Peers {
		var uptime time.Duration
		if p.Uptime != nil {
			uptime = time.Since(p.Uptime.AsTime())
		}
		peers[i] = BGPPeerInfo{
			Address:      p.Address,
			RemoteASN:    p.Asn,
			State:        p.State,
			Uptime:       uptime,
			PrefixesRecv: int(p.PrefixesReceived),
			PrefixesSent: int(p.PrefixesSent),
			Description:  p.Description,
		}
	}

	return &BGPPeersResult{
		Peers:      peers,
		TotalCount: len(peers),
	}, nil
}

// BGPPrefixes returns announced prefixes.
func (g *OverlayGRPCAdapter) BGPPrefixes(ctx context.Context) (*BGPPrefixesResult, error) {
	resp, err := g.gatewayClient.ListAnnouncedPrefixes(ctx, &platformv1.ListAnnouncedPrefixesRequest{})
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "ListAnnouncedPrefixes", Err: err}
	}

	prefixes := make([]BGPPrefixInfo, len(resp.Prefixes))
	for i, p := range resp.Prefixes {
		prefixes[i] = BGPPrefixInfo{
			Prefix:  p.Prefix,
			NextHop: p.NextHop,
		}
	}

	return &BGPPrefixesResult{
		Prefixes:   prefixes,
		TotalCount: len(prefixes),
	}, nil
}

// BGPAnnounce announces a prefix.
func (g *OverlayGRPCAdapter) BGPAnnounce(ctx context.Context, opts BGPAnnounceOptions) (*BGPAnnounceResult, error) {
	resp, err := g.gatewayClient.AnnouncePrefix(ctx, &platformv1.AnnouncePrefixRequest{
		Prefix:  opts.Prefix,
		NextHop: opts.NextHop,
	})
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "AnnouncePrefix", Err: err}
	}

	success := resp.Status != nil && resp.Status.Success
	return &BGPAnnounceResult{
		Prefix:  opts.Prefix,
		Success: success,
	}, nil
}

// BGPWithdraw withdraws a prefix.
func (g *OverlayGRPCAdapter) BGPWithdraw(ctx context.Context, prefix string) (*BGPWithdrawResult, error) {
	resp, err := g.gatewayClient.WithdrawPrefix(ctx, &platformv1.WithdrawPrefixRequest{Prefix: prefix})
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "WithdrawPrefix", Err: err}
	}

	success := resp.Status != nil && resp.Status.Success
	return &BGPWithdrawResult{
		Prefix:  prefix,
		Success: success,
	}, nil
}

// =============================================================================
// IPAM Commands
// =============================================================================

// IPAMPoolList lists IPAM pools.
func (g *OverlayGRPCAdapter) IPAMPoolList(ctx context.Context) (*IPAMPoolListResult, error) {
	resp, err := g.gatewayClient.ListIPAMPools(ctx, &platformv1.ListIPAMPoolsRequest{})
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "ListIPAMPools", Err: err}
	}

	pools := make([]IPAMPoolInfo, len(resp.Pools))
	for i, p := range resp.Pools {
		var utilizationPct float64
		if p.Total > 0 {
			utilizationPct = float64(p.Allocated) / float64(p.Total) * 100
		}
		pools[i] = IPAMPoolInfo{
			ID:             p.Id,
			CIDR:           p.Cidr,
			Gateway:        p.Gateway,
			TotalIPs:       int64(p.Total),
			AllocatedIPs:   int64(p.Allocated),
			AvailableIPs:   int64(p.Available),
			UtilizationPct: utilizationPct,
		}
	}

	return &IPAMPoolListResult{
		Pools:      pools,
		TotalCount: len(pools),
	}, nil
}

// IPAMPoolCreate creates an IPAM pool.
func (g *OverlayGRPCAdapter) IPAMPoolCreate(ctx context.Context, opts IPAMPoolCreateOptions) (*IPAMPoolCreateResult, error) {
	// Note: This API may not exist in the current proto definition
	// Fall back to not implemented for now
	return nil, ErrGRPCNotImplemented{Method: "IPAMPoolCreate"}
}

// IPAMPoolDelete deletes an IPAM pool.
func (g *OverlayGRPCAdapter) IPAMPoolDelete(ctx context.Context, poolID string) (*IPAMPoolDeleteResult, error) {
	// Note: This API may not exist in the current proto definition
	return nil, ErrGRPCNotImplemented{Method: "IPAMPoolDelete"}
}

// IPAMAllocate allocates an IP.
func (g *OverlayGRPCAdapter) IPAMAllocate(ctx context.Context, opts IPAMAllocateOptions) (*IPAMAllocateResult, error) {
	resp, err := g.gatewayClient.AllocateIP(ctx, &platformv1.AllocateIPRequest{
		PoolId:   opts.PoolID,
		DeviceId: opts.DeviceID,
		Hostname: opts.Hostname,
	})
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "AllocateIP", Err: err}
	}

	ip, _ := netip.ParseAddr(resp.Allocation.Ip)
	var leaseExpiry time.Time
	if resp.Allocation.ExpiresAt != nil {
		leaseExpiry = resp.Allocation.ExpiresAt.AsTime()
	}

	return &IPAMAllocateResult{
		IP:          ip,
		PoolID:      resp.Allocation.PoolId,
		DeviceID:    resp.Allocation.DeviceId,
		Hostname:    resp.Allocation.Hostname,
		LeaseExpiry: leaseExpiry,
	}, nil
}

// IPAMRelease releases an IP.
func (g *OverlayGRPCAdapter) IPAMRelease(ctx context.Context, ip string) (*IPAMReleaseResult, error) {
	resp, err := g.gatewayClient.ReleaseIP(ctx, &platformv1.ReleaseIPRequest{Ip: ip})
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "ReleaseIP", Err: err}
	}

	released := resp.Status != nil && resp.Status.Success
	return &IPAMReleaseResult{
		IP:       ip,
		Released: released,
	}, nil
}

// IPAMList lists IPAM allocations.
func (g *OverlayGRPCAdapter) IPAMList(ctx context.Context, opts IPAMListOptions) (*IPAMListResult, error) {
	resp, err := g.gatewayClient.ListAllocations(ctx, &platformv1.ListAllocationsRequest{PoolId: opts.PoolID})
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "ListAllocations", Err: err}
	}

	allocations := make([]IPAMAllocationInfo, len(resp.Allocations))
	for i, a := range resp.Allocations {
		ip, _ := netip.ParseAddr(a.Ip)
		var allocatedAt, leaseExpiry time.Time
		if a.AllocatedAt != nil {
			allocatedAt = a.AllocatedAt.AsTime()
		}
		if a.ExpiresAt != nil {
			leaseExpiry = a.ExpiresAt.AsTime()
		}
		allocations[i] = IPAMAllocationInfo{
			IP:          ip,
			PoolID:      a.PoolId,
			DeviceID:    a.DeviceId,
			Hostname:    a.Hostname,
			AllocatedAt: allocatedAt,
			LeaseExpiry: leaseExpiry,
		}
	}

	return &IPAMListResult{
		Allocations: allocations,
		TotalCount:  len(allocations),
	}, nil
}

// =============================================================================
// Compile-time Interface Verification
// =============================================================================

var _ OverlayCommands = (*OverlayGRPCAdapter)(nil)
