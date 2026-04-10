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
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"google.golang.org/grpc"
)

// =============================================================================
// Constants
// =============================================================================

const (
	// sdnGRPCDialTimeout is the timeout for establishing gRPC connection.
	sdnGRPCDialTimeout = 5 * time.Second
)

// =============================================================================
// Error Types
// =============================================================================

// ErrSDNGRPCBackendUnavailable indicates the backend is unavailable.
type ErrSDNGRPCBackendUnavailable struct {
	Endpoint string
	Err      error
}

func (e ErrSDNGRPCBackendUnavailable) Error() string {
	return fmt.Sprintf("SDN gRPC backend at %s unavailable: %v", e.Endpoint, e.Err)
}

func (e ErrSDNGRPCBackendUnavailable) Unwrap() error {
	return e.Err
}

// =============================================================================
// gRPC Adapter Implementation
// =============================================================================

// SDNGRPCAdapter implements SDNTestAdapter using gRPC calls to platformd.
type SDNGRPCAdapter struct {
	endpoint string
	conn     *grpc.ClientConn
	overlay  platformv1.OverlayServiceClient
	gateway  platformv1.GatewayServiceClient
}

// NewSDNGRPCAdapter creates a new gRPC adapter for SDN integration testing.
func NewSDNGRPCAdapter() *SDNGRPCAdapter {
	return &SDNGRPCAdapter{}
}

// Name returns the protocol adapter identifier.
func (g *SDNGRPCAdapter) Name() string {
	return "gRPC"
}

// Setup initializes the gRPC connection to platformd.
// Uses grpc.NewClient for lazy connection establishment, then verifies
// connectivity with a status call to ensure the backend is reachable.
func (g *SDNGRPCAdapter) Setup(ctx context.Context) error {
	endpoints := GetServiceEndpoints()
	g.endpoint = endpoints.PlatformdGRPC

	conn, err := grpc.NewClient(g.endpoint,
		helpers.GRPCTransportCredentials(),
	)
	if err != nil {
		return ErrAdapterSetupFailed{Protocol: "gRPC", Err: err}
	}

	g.conn = conn
	g.overlay = platformv1.NewOverlayServiceClient(conn)
	g.gateway = platformv1.NewGatewayServiceClient(conn)

	// Verify connectivity with a status call using the same short timeout
	verifyCtx, verifyCancel := context.WithTimeout(ctx, sdnGRPCDialTimeout)
	defer verifyCancel()

	_, err = g.overlay.GetOverlayStatus(verifyCtx, &platformv1.GetOverlayStatusRequest{})
	if err != nil {
		closeErr := g.conn.Close()
		if closeErr != nil {
			return ErrSDNGRPCBackendUnavailable{
				Endpoint: g.endpoint,
				Err:      fmt.Errorf("%w; close error: %v", err, closeErr),
			}
		}
		return ErrSDNGRPCBackendUnavailable{Endpoint: g.endpoint, Err: err}
	}

	return nil
}

// Teardown closes the gRPC connection.
func (g *SDNGRPCAdapter) Teardown() error {
	if g.conn != nil {
		return g.conn.Close()
	}
	return nil
}

// =============================================================================
// Overlay Operations
// =============================================================================

// ListVTEPs returns all discovered VTEPs via gRPC.
func (g *SDNGRPCAdapter) ListVTEPs(ctx context.Context) (*VTEPListResponse, error) {
	resp, err := g.overlay.ListVTEPs(ctx, &platformv1.ListVTEPsRequest{})
	if err != nil {
		return nil, fmt.Errorf("gRPC ListVTEPs failed: %w", err)
	}

	vteps := make([]VTEPEntry, 0, len(resp.Vteps))
	for _, v := range resp.Vteps {
		ip, _ := netip.ParseAddr(v.Ip)
		state := "unknown"
		if v.Healthy {
			state = "healthy"
		}
		var lastSeen time.Time
		if v.LastSeen != nil {
			lastSeen = v.LastSeen.AsTime()
		}
		vteps = append(vteps, VTEPEntry{
			NodeID:   v.NodeId,
			IP:       ip,
			State:    state,
			LastSeen: lastSeen,
		})
	}

	return &VTEPListResponse{
		VTEPs:      vteps,
		TotalCount: len(vteps),
	}, nil
}

// CreateVNI creates a new VNI via gRPC.
func (g *SDNGRPCAdapter) CreateVNI(ctx context.Context, vni uint32) error {
	_, err := g.overlay.CreateVNI(ctx, &platformv1.CreateVNIRequest{
		Config: &platformv1.VNIConfig{
			Vni: vni,
		},
	})
	if err != nil {
		return fmt.Errorf("gRPC CreateVNI failed: %w", err)
	}
	return nil
}

// DeleteVNI removes a VNI via gRPC.
func (g *SDNGRPCAdapter) DeleteVNI(ctx context.Context, vni uint32) error {
	_, err := g.overlay.DeleteVNI(ctx, &platformv1.DeleteVNIRequest{
		Vni: vni,
	})
	if err != nil {
		return fmt.Errorf("gRPC DeleteVNI failed: %w", err)
	}
	return nil
}

// ListTunnels returns all active tunnels via gRPC.
func (g *SDNGRPCAdapter) ListTunnels(ctx context.Context) (*TunnelListResponse, error) {
	resp, err := g.overlay.ListTunnels(ctx, &platformv1.ListTunnelsRequest{})
	if err != nil {
		return nil, fmt.Errorf("gRPC ListTunnels failed: %w", err)
	}

	tunnels := make([]TunnelEntry, 0, len(resp.Tunnels))
	for _, t := range resp.Tunnels {
		localVTEP, _ := netip.ParseAddr(t.LocalVtep)
		remoteVTEP, _ := netip.ParseAddr(t.RemoteVtep)
		tunnels = append(tunnels, TunnelEntry{
			LocalVTEP:  localVTEP,
			RemoteVTEP: remoteVTEP,
			VNI:        t.Vni,
			State:      t.State,
			BytesSent:  t.BytesTx,
			BytesRecv:  t.BytesRx,
		})
	}

	return &TunnelListResponse{
		Tunnels:    tunnels,
		TotalCount: len(tunnels),
	}, nil
}

// ListRemoteMACs returns all learned remote MACs for a VNI via gRPC.
func (g *SDNGRPCAdapter) ListRemoteMACs(ctx context.Context, vni uint32) (*RemoteMACListResponse, error) {
	resp, err := g.overlay.ListRemoteMACs(ctx, &platformv1.ListRemoteMACsRequest{
		Vni: vni,
	})
	if err != nil {
		return nil, fmt.Errorf("gRPC ListRemoteMACs failed: %w", err)
	}

	macs := make([]RemoteMACEntry, 0, len(resp.Macs))
	for _, m := range resp.Macs {
		mac, _ := net.ParseMAC(m.Mac)
		remoteVTEP, _ := netip.ParseAddr(m.RemoteVtep)
		var learnedAt time.Time
		if m.LearnedAt != nil {
			learnedAt = m.LearnedAt.AsTime()
		}
		macs = append(macs, RemoteMACEntry{
			MAC:        mac,
			VNI:        m.Vni,
			RemoteVTEP: remoteVTEP,
			LearnedAt:  learnedAt,
		})
	}

	return &RemoteMACListResponse{
		MACs:       macs,
		TotalCount: len(macs),
	}, nil
}

// =============================================================================
// Gateway Operations
// =============================================================================

// GetGatewayStatus returns the gateway status via gRPC.
func (g *SDNGRPCAdapter) GetGatewayStatus(ctx context.Context) (*GatewayStatusResponse, error) {
	resp, err := g.gateway.GetGatewayStatus(ctx, &platformv1.GetGatewayStatusRequest{})
	if err != nil {
		return nil, fmt.Errorf("gRPC GetGatewayStatus failed: %w", err)
	}

	status := resp.Status
	modes := GatewayMode(status.Modes)

	return &GatewayStatusResponse{
		NodeID:     status.NodeId,
		Modes:      modes,
		Tier:       status.Tier,
		Healthy:    status.Healthy,
		Reputation: status.Reputation,
		Age:        time.Duration(status.UptimeSeconds) * time.Second,
	}, nil
}

// SetGatewayMode sets the gateway mode via gRPC.
func (g *SDNGRPCAdapter) SetGatewayMode(ctx context.Context, mode GatewayMode) error {
	_, err := g.gateway.SetGatewayMode(ctx, &platformv1.SetGatewayModeRequest{
		Modes: uint32(mode),
	})
	if err != nil {
		return fmt.Errorf("gRPC SetGatewayMode failed: %w", err)
	}
	return nil
}

// =============================================================================
// BGP Operations
// =============================================================================

// GetBGPStatus returns the BGP status via gRPC.
func (g *SDNGRPCAdapter) GetBGPStatus(ctx context.Context) (*BGPStatusResponse, error) {
	resp, err := g.gateway.GetBGPStatus(ctx, &platformv1.GetBGPStatusRequest{})
	if err != nil {
		return nil, fmt.Errorf("gRPC GetBGPStatus failed: %w", err)
	}

	status := resp.Status
	return &BGPStatusResponse{
		Enabled:          status.Running,
		ASN:              status.LocalAsn,
		RouterID:         status.RouterId,
		PeerCount:        int(status.PeerCount),
		EstablishedCount: int(status.EstablishedPeers),
	}, nil
}

// ListBGPPeers returns all BGP peers via gRPC.
func (g *SDNGRPCAdapter) ListBGPPeers(ctx context.Context) (*BGPPeerListResponse, error) {
	resp, err := g.gateway.ListBGPPeers(ctx, &platformv1.ListBGPPeersRequest{})
	if err != nil {
		return nil, fmt.Errorf("gRPC ListBGPPeers failed: %w", err)
	}

	peers := make([]BGPPeerEntry, 0, len(resp.Peers))
	for _, p := range resp.Peers {
		var uptime time.Duration
		if p.Uptime != nil {
			uptime = time.Since(p.Uptime.AsTime())
		}
		peers = append(peers, BGPPeerEntry{
			Address:      p.Address,
			RemoteASN:    p.Asn,
			State:        p.State,
			Uptime:       uptime,
			PrefixesRecv: int(p.PrefixesReceived),
			PrefixesSent: int(p.PrefixesSent),
			Description:  p.Description,
		})
	}

	return &BGPPeerListResponse{
		Peers:      peers,
		TotalCount: len(peers),
	}, nil
}

// AnnouncePrefix announces a BGP prefix via gRPC.
func (g *SDNGRPCAdapter) AnnouncePrefix(ctx context.Context, prefix string) error {
	_, err := g.gateway.AnnouncePrefix(ctx, &platformv1.AnnouncePrefixRequest{
		Prefix: prefix,
	})
	if err != nil {
		return fmt.Errorf("gRPC AnnouncePrefix failed: %w", err)
	}
	return nil
}

// WithdrawPrefix withdraws a BGP prefix via gRPC.
func (g *SDNGRPCAdapter) WithdrawPrefix(ctx context.Context, prefix string) error {
	_, err := g.gateway.WithdrawPrefix(ctx, &platformv1.WithdrawPrefixRequest{
		Prefix: prefix,
	})
	if err != nil {
		return fmt.Errorf("gRPC WithdrawPrefix failed: %w", err)
	}
	return nil
}

// =============================================================================
// IPAM Operations
// =============================================================================

// ListPools returns all IPAM pools via gRPC.
func (g *SDNGRPCAdapter) ListPools(ctx context.Context) (*IPAMPoolListResponse, error) {
	resp, err := g.gateway.ListIPAMPools(ctx, &platformv1.ListIPAMPoolsRequest{})
	if err != nil {
		return nil, fmt.Errorf("gRPC ListIPAMPools failed: %w", err)
	}

	pools := make([]IPAMPoolEntry, 0, len(resp.Pools))
	for _, p := range resp.Pools {
		pools = append(pools, IPAMPoolEntry{
			ID:           p.Id,
			CIDR:         p.Cidr,
			Gateway:      p.Gateway,
			TotalIPs:     int64(p.Total),
			AllocatedIPs: int64(p.Allocated),
			AvailableIPs: int64(p.Available),
		})
	}

	return &IPAMPoolListResponse{
		Pools:      pools,
		TotalCount: len(pools),
	}, nil
}

// AllocateIP allocates an IP from a pool via gRPC.
func (g *SDNGRPCAdapter) AllocateIP(ctx context.Context, poolID string) (*IPAllocationResponse, error) {
	resp, err := g.gateway.AllocateIP(ctx, &platformv1.AllocateIPRequest{
		PoolId: poolID,
	})
	if err != nil {
		return nil, fmt.Errorf("gRPC AllocateIP failed: %w", err)
	}

	alloc := resp.Allocation
	ip, _ := netip.ParseAddr(alloc.Ip)
	var expiry time.Time
	if alloc.ExpiresAt != nil {
		expiry = alloc.ExpiresAt.AsTime()
	}

	return &IPAllocationResponse{
		IP:          ip,
		PoolID:      alloc.PoolId,
		LeaseExpiry: expiry,
	}, nil
}

// ReleaseIP releases an allocated IP via gRPC.
func (g *SDNGRPCAdapter) ReleaseIP(ctx context.Context, poolID, ip string) error {
	_, err := g.gateway.ReleaseIP(ctx, &platformv1.ReleaseIPRequest{
		Ip: ip,
	})
	if err != nil {
		return fmt.Errorf("gRPC ReleaseIP failed: %w", err)
	}
	return nil
}

// =============================================================================
// DHCP Operations
// =============================================================================

// GetDHCPStatus returns the DHCP server status via gRPC.
// Note: DHCP status is not currently exposed via gRPC; returns not implemented error.
func (g *SDNGRPCAdapter) GetDHCPStatus(ctx context.Context) (*DHCPStatusResponse, error) {
	return nil, ErrAdapterNotImplemented{Protocol: "gRPC", Operation: "GetDHCPStatus"}
}

// ListLeases returns all DHCP leases via gRPC.
// Note: DHCP leases are not currently exposed via gRPC; returns not implemented error.
func (g *SDNGRPCAdapter) ListLeases(ctx context.Context) (*DHCPLeaseListResponse, error) {
	return nil, ErrAdapterNotImplemented{Protocol: "gRPC", Operation: "ListLeases"}
}

// Ensure SDNGRPCAdapter implements SDNTestAdapter interface.
var _ SDNTestAdapter = (*SDNGRPCAdapter)(nil)
