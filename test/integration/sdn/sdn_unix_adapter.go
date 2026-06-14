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
	sdn        platformv1.SDNServiceClient
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
	u.sdn = platformv1.NewSDNServiceClient(conn)

	// Verify connectivity with a zone list call; this does not require an
	// overlay controller, so it succeeds as long as platformd is reachable.
	verifyCtx, verifyCancel := context.WithTimeout(ctx, sdnUnixDialTimeout)
	defer verifyCancel()

	_, err = u.sdn.ListNetworkZones(verifyCtx, &platformv1.ListNetworkZonesRequest{})
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

// CreatePool creates a new IPAM pool via Unix socket.
func (u *SDNUnixAdapter) CreatePool(ctx context.Context, req IPAMPoolCreateRequest) (*IPAMPoolEntry, error) {
	protoReq := &platformv1.CreateIPAMPoolRequest{
		Id:          req.ID,
		Name:        req.Name,
		Cidr:        req.CIDR,
		Gateway:     req.Gateway,
		Zone:        req.Zone,
		Description: req.Description,
	}
	if req.LeaseDuration > 0 {
		protoReq.DefaultLeaseDurationNanos = req.LeaseDuration.Nanoseconds()
	}

	resp, err := u.gateway.CreateIPAMPool(ctx, protoReq)
	if err != nil {
		return nil, fmt.Errorf("Unix CreateIPAMPool failed: %w", err)
	}

	return grpcPoolToEntry(resp.Pool), nil
}

// GetPool retrieves an IPAM pool by ID via Unix socket.
func (u *SDNUnixAdapter) GetPool(ctx context.Context, poolID string) (*IPAMPoolEntry, error) {
	resp, err := u.gateway.GetIPAMPool(ctx, &platformv1.GetIPAMPoolRequest{Id: poolID})
	if err != nil {
		return nil, fmt.Errorf("Unix GetIPAMPool failed: %w", err)
	}

	return grpcPoolToEntry(resp.Pool), nil
}

// UpdatePool updates mutable fields of an IPAM pool via Unix socket.
func (u *SDNUnixAdapter) UpdatePool(ctx context.Context, poolID string, req IPAMPoolUpdateRequest) (*IPAMPoolEntry, error) {
	protoReq := &platformv1.UpdateIPAMPoolRequest{
		Id:          poolID,
		Name:        req.Name,
		Gateway:     req.Gateway,
		Zone:        req.Zone,
		Description: req.Description,
	}
	if req.LeaseDuration > 0 {
		protoReq.DefaultLeaseDurationNanos = req.LeaseDuration.Nanoseconds()
	}

	resp, err := u.gateway.UpdateIPAMPool(ctx, protoReq)
	if err != nil {
		return nil, fmt.Errorf("Unix UpdateIPAMPool failed: %w", err)
	}

	return grpcPoolToEntry(resp.Pool), nil
}

// DeletePool removes an IPAM pool by ID via Unix socket.
func (u *SDNUnixAdapter) DeletePool(ctx context.Context, poolID string) error {
	_, err := u.gateway.DeleteIPAMPool(ctx, &platformv1.DeleteIPAMPoolRequest{Id: poolID})
	if err != nil {
		return fmt.Errorf("Unix DeleteIPAMPool failed: %w", err)
	}
	return nil
}

// ListPools returns all IPAM pools, optionally filtered by zone, via Unix socket.
func (u *SDNUnixAdapter) ListPools(ctx context.Context, zone string) (*IPAMPoolListResponse, error) {
	resp, err := u.gateway.ListIPAMPools(ctx, &platformv1.ListIPAMPoolsRequest{Zone: zone})
	if err != nil {
		return nil, fmt.Errorf("Unix ListIPAMPools failed: %w", err)
	}

	pools := make([]IPAMPoolEntry, 0, len(resp.Pools))
	for _, p := range resp.Pools {
		pools = append(pools, *grpcPoolToEntry(p))
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

// =============================================================================
// Network Zone Operations
// =============================================================================

// CreateZone creates a new network trust zone via gRPC over Unix socket.
func (u *SDNUnixAdapter) CreateZone(ctx context.Context, req ZoneCreateRequest) (*ZoneEntry, error) {
	resp, err := u.sdn.CreateNetworkZone(ctx, &platformv1.CreateNetworkZoneRequest{
		Config: &platformv1.NetworkZoneConfig{
			Name:             req.Name,
			InternetIngress:  req.InternetIngress,
			Isolate:          req.Isolate,
			IsolatePerTenant: req.IsolatePerTenant,
			Oob:              req.OOB,
			LifecycleRole:    req.LifecycleRole,
		},
	})
	if err != nil {
		return nil, err
	}
	return grpcNetworkZoneToEntry(resp.GetZone()), nil
}

// UpdateZone updates an existing network trust zone via gRPC over Unix socket.
func (u *SDNUnixAdapter) UpdateZone(ctx context.Context, name string, req ZoneUpdateRequest) (*ZoneEntry, error) {
	resp, err := u.sdn.UpdateNetworkZone(ctx, &platformv1.UpdateNetworkZoneRequest{
		Name: name,
		Config: &platformv1.NetworkZoneConfig{
			Name:             name,
			InternetIngress:  req.InternetIngress,
			Isolate:          req.Isolate,
			IsolatePerTenant: req.IsolatePerTenant,
			Oob:              req.OOB,
			LifecycleRole:    req.LifecycleRole,
		},
	})
	if err != nil {
		return nil, err
	}
	return grpcNetworkZoneToEntry(resp.GetZone()), nil
}

// DeleteZone deletes a network trust zone via gRPC over Unix socket.
func (u *SDNUnixAdapter) DeleteZone(ctx context.Context, name string) (bool, error) {
	resp, err := u.sdn.DeleteNetworkZone(ctx, &platformv1.DeleteNetworkZoneRequest{Name: name})
	if err != nil {
		return false, err
	}
	return resp.GetRestartRequired(), nil
}

// ListZones returns all network trust zones via gRPC over Unix socket.
func (u *SDNUnixAdapter) ListZones(ctx context.Context, lifecycleRole string) (*ZoneListResponse, error) {
	resp, err := u.sdn.ListNetworkZones(ctx, &platformv1.ListNetworkZonesRequest{
		LifecycleRole: lifecycleRole,
	})
	if err != nil {
		return nil, err
	}
	zones := make([]ZoneEntry, 0, len(resp.GetZones()))
	for _, z := range resp.GetZones() {
		if e := grpcNetworkZoneToEntry(z); e != nil {
			zones = append(zones, *e)
		}
	}
	return &ZoneListResponse{Zones: zones, TotalCount: len(zones)}, nil
}

// AssignZone assigns a network segment to a trust zone via gRPC over Unix socket.
func (u *SDNUnixAdapter) AssignZone(ctx context.Context, network string, zoneName string) (bool, error) {
	resp, err := u.sdn.AssignNetworkZone(ctx, &platformv1.AssignNetworkZoneRequest{
		Network: network,
		Zone:    zoneName,
	})
	if err != nil {
		return false, err
	}
	return resp.GetRestartRequired(), nil
}

// Ensure SDNUnixAdapter implements SDNTestAdapter interface.
var _ SDNTestAdapter = (*SDNUnixAdapter)(nil)
