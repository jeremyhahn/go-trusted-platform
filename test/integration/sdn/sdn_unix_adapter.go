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
	// sdnUnixDialTimeout is the timeout for establishing Unix socket connection.
	sdnUnixDialTimeout = 5 * time.Second
)

// =============================================================================
// Error Types
// =============================================================================

// ErrSDNUnixBackendUnavailable indicates the backend is unavailable.
type ErrSDNUnixBackendUnavailable struct {
	SocketPath string
	Err        error
}

func (e ErrSDNUnixBackendUnavailable) Error() string {
	return fmt.Sprintf("SDN Unix backend at %s unavailable: %v", e.SocketPath, e.Err)
}

func (e ErrSDNUnixBackendUnavailable) Unwrap() error {
	return e.Err
}

// =============================================================================
// Unix Socket Adapter Implementation
// =============================================================================

// SDNUnixAdapter implements SDNTestAdapter using gRPC over Unix socket.
// This provides local IPC for CLI tools and local processes.
type SDNUnixAdapter struct {
	socketPath string
	conn       *grpc.ClientConn
	overlay    platformv1.OverlayServiceClient
	gateway    platformv1.GatewayServiceClient
}

// NewSDNUnixAdapter creates a new Unix socket adapter for SDN integration testing.
func NewSDNUnixAdapter() *SDNUnixAdapter {
	return &SDNUnixAdapter{}
}

// Name returns the protocol adapter identifier.
func (u *SDNUnixAdapter) Name() string {
	return "Unix"
}

// Setup initializes the Unix socket connection to platformd.
// Uses a short timeout to fail fast when the server is unavailable.
func (u *SDNUnixAdapter) Setup(ctx context.Context) error {
	endpoints := GetServiceEndpoints()
	u.socketPath = endpoints.PlatformdSock

	conn, err := grpc.NewClient("unix://"+u.socketPath,
		helpers.GRPCUnixCredentials(),
	)
	if err != nil {
		return ErrAdapterSetupFailed{Protocol: "Unix", Err: err}
	}

	u.conn = conn
	u.overlay = platformv1.NewOverlayServiceClient(conn)
	u.gateway = platformv1.NewGatewayServiceClient(conn)

	// Verify connectivity with a status call using the same short timeout
	verifyCtx, verifyCancel := context.WithTimeout(ctx, sdnUnixDialTimeout)
	defer verifyCancel()

	_, err = u.overlay.GetOverlayStatus(verifyCtx, &platformv1.GetOverlayStatusRequest{})
	if err != nil {
		closeErr := u.conn.Close()
		if closeErr != nil {
			return ErrSDNUnixBackendUnavailable{
				SocketPath: u.socketPath,
				Err:        fmt.Errorf("%w; close error: %v", err, closeErr),
			}
		}
		return ErrSDNUnixBackendUnavailable{SocketPath: u.socketPath, Err: err}
	}

	return nil
}

// Teardown closes the Unix socket connection.
func (u *SDNUnixAdapter) Teardown() error {
	if u.conn != nil {
		return u.conn.Close()
	}
	return nil
}

// =============================================================================
// Overlay Operations
// =============================================================================

// ListVTEPs returns all discovered VTEPs via Unix socket.
func (u *SDNUnixAdapter) ListVTEPs(ctx context.Context) (*VTEPListResponse, error) {
	resp, err := u.overlay.ListVTEPs(ctx, &platformv1.ListVTEPsRequest{})
	if err != nil {
		return nil, fmt.Errorf("Unix ListVTEPs failed: %w", err)
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

// CreateVNI creates a new VNI via Unix socket.
func (u *SDNUnixAdapter) CreateVNI(ctx context.Context, vni uint32) error {
	_, err := u.overlay.CreateVNI(ctx, &platformv1.CreateVNIRequest{
		Config: &platformv1.VNIConfig{
			Vni: vni,
		},
	})
	if err != nil {
		return fmt.Errorf("Unix CreateVNI failed: %w", err)
	}
	return nil
}

// DeleteVNI removes a VNI via Unix socket.
func (u *SDNUnixAdapter) DeleteVNI(ctx context.Context, vni uint32) error {
	_, err := u.overlay.DeleteVNI(ctx, &platformv1.DeleteVNIRequest{
		Vni: vni,
	})
	if err != nil {
		return fmt.Errorf("Unix DeleteVNI failed: %w", err)
	}
	return nil
}

// ListTunnels returns all active tunnels via Unix socket.
func (u *SDNUnixAdapter) ListTunnels(ctx context.Context) (*TunnelListResponse, error) {
	resp, err := u.overlay.ListTunnels(ctx, &platformv1.ListTunnelsRequest{})
	if err != nil {
		return nil, fmt.Errorf("Unix ListTunnels failed: %w", err)
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

// ListRemoteMACs returns all learned remote MACs for a VNI via Unix socket.
func (u *SDNUnixAdapter) ListRemoteMACs(ctx context.Context, vni uint32) (*RemoteMACListResponse, error) {
	resp, err := u.overlay.ListRemoteMACs(ctx, &platformv1.ListRemoteMACsRequest{
		Vni: vni,
	})
	if err != nil {
		return nil, fmt.Errorf("Unix ListRemoteMACs failed: %w", err)
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

// GetGatewayStatus returns the gateway status via Unix socket.
func (u *SDNUnixAdapter) GetGatewayStatus(ctx context.Context) (*GatewayStatusResponse, error) {
	resp, err := u.gateway.GetGatewayStatus(ctx, &platformv1.GetGatewayStatusRequest{})
	if err != nil {
		return nil, fmt.Errorf("Unix GetGatewayStatus failed: %w", err)
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

// SetGatewayMode sets the gateway mode via Unix socket.
func (u *SDNUnixAdapter) SetGatewayMode(ctx context.Context, mode GatewayMode) error {
	_, err := u.gateway.SetGatewayMode(ctx, &platformv1.SetGatewayModeRequest{
		Modes: uint32(mode),
	})
	if err != nil {
		return fmt.Errorf("Unix SetGatewayMode failed: %w", err)
	}
	return nil
}

// =============================================================================
// BGP Operations
// =============================================================================

// GetBGPStatus returns the BGP status via Unix socket.
func (u *SDNUnixAdapter) GetBGPStatus(ctx context.Context) (*BGPStatusResponse, error) {
	resp, err := u.gateway.GetBGPStatus(ctx, &platformv1.GetBGPStatusRequest{})
	if err != nil {
		return nil, fmt.Errorf("Unix GetBGPStatus failed: %w", err)
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

// ListBGPPeers returns all BGP peers via Unix socket.
func (u *SDNUnixAdapter) ListBGPPeers(ctx context.Context) (*BGPPeerListResponse, error) {
	resp, err := u.gateway.ListBGPPeers(ctx, &platformv1.ListBGPPeersRequest{})
	if err != nil {
		return nil, fmt.Errorf("Unix ListBGPPeers failed: %w", err)
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

// AnnouncePrefix announces a BGP prefix via Unix socket.
func (u *SDNUnixAdapter) AnnouncePrefix(ctx context.Context, prefix string) error {
	_, err := u.gateway.AnnouncePrefix(ctx, &platformv1.AnnouncePrefixRequest{
		Prefix: prefix,
	})
	if err != nil {
		return fmt.Errorf("Unix AnnouncePrefix failed: %w", err)
	}
	return nil
}

// WithdrawPrefix withdraws a BGP prefix via Unix socket.
func (u *SDNUnixAdapter) WithdrawPrefix(ctx context.Context, prefix string) error {
	_, err := u.gateway.WithdrawPrefix(ctx, &platformv1.WithdrawPrefixRequest{
		Prefix: prefix,
	})
	if err != nil {
		return fmt.Errorf("Unix WithdrawPrefix failed: %w", err)
	}
	return nil
}

// =============================================================================
// IPAM Operations
// =============================================================================

// ListPools returns all IPAM pools via Unix socket.
func (u *SDNUnixAdapter) ListPools(ctx context.Context) (*IPAMPoolListResponse, error) {
	resp, err := u.gateway.ListIPAMPools(ctx, &platformv1.ListIPAMPoolsRequest{})
	if err != nil {
		return nil, fmt.Errorf("Unix ListIPAMPools failed: %w", err)
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

// AllocateIP allocates an IP from a pool via Unix socket.
func (u *SDNUnixAdapter) AllocateIP(ctx context.Context, poolID string) (*IPAllocationResponse, error) {
	resp, err := u.gateway.AllocateIP(ctx, &platformv1.AllocateIPRequest{
		PoolId: poolID,
	})
	if err != nil {
		return nil, fmt.Errorf("Unix AllocateIP failed: %w", err)
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

// ReleaseIP releases an allocated IP via Unix socket.
func (u *SDNUnixAdapter) ReleaseIP(ctx context.Context, poolID, ip string) error {
	_, err := u.gateway.ReleaseIP(ctx, &platformv1.ReleaseIPRequest{
		Ip: ip,
	})
	if err != nil {
		return fmt.Errorf("Unix ReleaseIP failed: %w", err)
	}
	return nil
}

// =============================================================================
// DHCP Operations
// =============================================================================

// GetDHCPStatus returns the DHCP server status via Unix socket.
// Note: DHCP status is not currently exposed via gRPC; returns not implemented error.
func (u *SDNUnixAdapter) GetDHCPStatus(ctx context.Context) (*DHCPStatusResponse, error) {
	return nil, ErrAdapterNotImplemented{Protocol: "Unix", Operation: "GetDHCPStatus"}
}

// ListLeases returns all DHCP leases via Unix socket.
// Note: DHCP leases are not currently exposed via gRPC; returns not implemented error.
func (u *SDNUnixAdapter) ListLeases(ctx context.Context) (*DHCPLeaseListResponse, error) {
	return nil, ErrAdapterNotImplemented{Protocol: "Unix", Operation: "ListLeases"}
}

// Ensure SDNUnixAdapter implements SDNTestAdapter interface.
var _ SDNTestAdapter = (*SDNUnixAdapter)(nil)
