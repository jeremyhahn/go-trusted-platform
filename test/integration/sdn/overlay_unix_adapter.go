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
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"google.golang.org/grpc"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// =============================================================================
// Unix Socket Constants
// =============================================================================

const (
	// EnvPlatformdOverlaySocket is the environment variable for the Unix socket path.
	EnvPlatformdOverlaySocket = "PLATFORMD_SOCKET"

	// DefaultPlatformdOverlaySocket is the default platformd Unix socket path.
	DefaultPlatformdOverlaySocket = "/run/platformd.sock"

	// overlayUnixDialTimeout is the timeout for establishing Unix socket connection.
	overlayUnixDialTimeout = 5 * time.Second
)

// =============================================================================
// Error Types
// =============================================================================

// ErrOverlayUnixConnectionFailed indicates a Unix socket connection failure.
type ErrOverlayUnixConnectionFailed struct {
	Path string
	Err  error
}

func (e ErrOverlayUnixConnectionFailed) Error() string {
	return fmt.Sprintf("overlay Unix connection to %s failed: %v", e.Path, e.Err)
}

func (e ErrOverlayUnixConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrOverlayUnixBackendUnavailable indicates the backend is unavailable.
type ErrOverlayUnixBackendUnavailable struct {
	Err error
}

func (e ErrOverlayUnixBackendUnavailable) Error() string {
	return fmt.Sprintf("overlay Unix backend unavailable: %v", e.Err)
}

func (e ErrOverlayUnixBackendUnavailable) Unwrap() error {
	return e.Err
}

// ErrOverlayUnixRPCFailed indicates an RPC call failure.
type ErrOverlayUnixRPCFailed struct {
	Method string
	Err    error
}

func (e ErrOverlayUnixRPCFailed) Error() string {
	return fmt.Sprintf("overlay Unix RPC %s failed: %v", e.Method, e.Err)
}

func (e ErrOverlayUnixRPCFailed) Unwrap() error {
	return e.Err
}

// ErrOverlayUnixInvalidResponse indicates an invalid response from the server.
type ErrOverlayUnixInvalidResponse struct {
	Method  string
	Details string
}

func (e ErrOverlayUnixInvalidResponse) Error() string {
	return fmt.Sprintf("overlay Unix RPC %s returned invalid response: %s", e.Method, e.Details)
}

// ErrOverlayUnixParseIP indicates failure to parse an IP address.
type ErrOverlayUnixParseIP struct {
	IP  string
	Err error
}

func (e ErrOverlayUnixParseIP) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("failed to parse IP address %q: %v", e.IP, e.Err)
	}
	return fmt.Sprintf("failed to parse IP address %q", e.IP)
}

func (e ErrOverlayUnixParseIP) Unwrap() error {
	return e.Err
}

// ErrOverlayUnixParseMAC indicates failure to parse a MAC address.
type ErrOverlayUnixParseMAC struct {
	MAC string
	Err error
}

func (e ErrOverlayUnixParseMAC) Error() string {
	return fmt.Sprintf("failed to parse MAC address %q: %v", e.MAC, e.Err)
}

func (e ErrOverlayUnixParseMAC) Unwrap() error {
	return e.Err
}

// =============================================================================
// Overlay Unix Socket Adapter
// =============================================================================

// OverlayUnixAdapter implements OverlayCommands using gRPC over Unix sockets.
// This adapter uses the local Unix domain socket for IPC with platformd.
type OverlayUnixAdapter struct {
	socketPath string
	conn       *grpc.ClientConn
	overlay    platformv1.OverlayServiceClient
	gateway    platformv1.GatewayServiceClient
}

// NewOverlayUnixAdapter creates a new Unix socket adapter for overlay integration testing.
func NewOverlayUnixAdapter() *OverlayUnixAdapter {
	return &OverlayUnixAdapter{}
}

// Name returns the protocol adapter identifier.
func (a *OverlayUnixAdapter) Name() string {
	return "Unix"
}

// Setup initializes the gRPC connection over Unix socket.
// Uses a short timeout to fail fast when the server is unavailable.
func (a *OverlayUnixAdapter) Setup(ctx context.Context) error {
	a.socketPath = os.Getenv(EnvPlatformdOverlaySocket)
	if a.socketPath == "" {
		a.socketPath = DefaultPlatformdOverlaySocket
	}

	conn, err := grpc.NewClient("unix://"+a.socketPath,
		helpers.GRPCUnixCredentials(),
	)
	if err != nil {
		return ErrOverlayUnixConnectionFailed{Path: a.socketPath, Err: err}
	}

	a.conn = conn
	a.overlay = platformv1.NewOverlayServiceClient(conn)
	a.gateway = platformv1.NewGatewayServiceClient(conn)

	// Verify connectivity with a status call using the same short timeout
	verifyCtx, verifyCancel := context.WithTimeout(ctx, overlayUnixDialTimeout)
	defer verifyCancel()

	_, err = a.overlay.GetOverlayStatus(verifyCtx, &platformv1.GetOverlayStatusRequest{})
	if err != nil {
		closeErr := a.conn.Close()
		if closeErr != nil {
			return ErrOverlayUnixBackendUnavailable{Err: fmt.Errorf("%w; close error: %v", err, closeErr)}
		}
		return ErrOverlayUnixBackendUnavailable{Err: err}
	}

	return nil
}

// Teardown closes the gRPC connection.
func (a *OverlayUnixAdapter) Teardown() error {
	if a.conn != nil {
		return a.conn.Close()
	}
	return nil
}

// =============================================================================
// Overlay Status Operations
// =============================================================================

// OverlayStatus retrieves the overall overlay network status via Unix socket.
func (a *OverlayUnixAdapter) OverlayStatus(ctx context.Context) (*OverlayStatusResult, error) {
	resp, err := a.overlay.GetOverlayStatus(ctx, &platformv1.GetOverlayStatusRequest{})
	if err != nil {
		return nil, ErrOverlayUnixRPCFailed{Method: "GetOverlayStatus", Err: err}
	}

	if resp.Status == nil {
		return nil, ErrOverlayUnixInvalidResponse{Method: "GetOverlayStatus", Details: "nil status"}
	}

	vtepIP, err := overlayUnixParseIPAddr(resp.Status.VtepIp)
	if err != nil {
		return nil, ErrOverlayUnixParseIP{IP: resp.Status.VtepIp, Err: err}
	}

	return &OverlayStatusResult{
		NodeID:          resp.Status.NodeId,
		VTEPIP:          vtepIP,
		ControllerState: "active", // Derive from healthy field
		UnderlayMTU:     int(resp.Status.UnderlayMtu),
		VXLANPort:       uint16(resp.Status.VxlanPort),
		VNICount:        int(resp.Status.VniCount),
		VTEPCount:       int(resp.Status.VtepCount),
		RemoteMACCount:  int(resp.Status.RemoteMacCount),
		TunnelCount:     int(resp.Status.TunnelCount),
	}, nil
}

// =============================================================================
// VTEP Operations
// =============================================================================

// VTEPList lists all VTEPs via Unix socket.
func (a *OverlayUnixAdapter) VTEPList(ctx context.Context) (*VTEPListResult, error) {
	resp, err := a.overlay.ListVTEPs(ctx, &platformv1.ListVTEPsRequest{})
	if err != nil {
		return nil, ErrOverlayUnixRPCFailed{Method: "ListVTEPs", Err: err}
	}

	vteps := make([]VTEPInfo, 0, len(resp.Vteps))
	for _, v := range resp.Vteps {
		ip, parseErr := overlayUnixParseIPAddr(v.Ip)
		if parseErr != nil {
			return nil, ErrOverlayUnixParseIP{IP: v.Ip, Err: parseErr}
		}

		var lastSeen time.Time
		if v.LastSeen != nil {
			lastSeen = v.LastSeen.AsTime()
		}

		vteps = append(vteps, VTEPInfo{
			NodeID:   v.NodeId,
			IP:       ip,
			Healthy:  v.Healthy,
			LastSeen: lastSeen,
		})
	}

	return &VTEPListResult{
		VTEPs:      vteps,
		TotalCount: len(vteps),
	}, nil
}

// VTEPGet retrieves a specific VTEP by node ID via Unix socket.
func (a *OverlayUnixAdapter) VTEPGet(ctx context.Context, nodeID string) (*VTEPGetResult, error) {
	resp, err := a.overlay.GetVTEP(ctx, &platformv1.GetVTEPRequest{
		NodeId: nodeID,
	})
	if err != nil {
		return nil, ErrOverlayUnixRPCFailed{Method: "GetVTEP", Err: err}
	}

	if resp.Vtep == nil {
		return nil, ErrOverlayUnixInvalidResponse{Method: "GetVTEP", Details: "nil vtep"}
	}

	ip, parseErr := overlayUnixParseIPAddr(resp.Vtep.Ip)
	if parseErr != nil {
		return nil, ErrOverlayUnixParseIP{IP: resp.Vtep.Ip, Err: parseErr}
	}

	var lastSeen time.Time
	if resp.Vtep.LastSeen != nil {
		lastSeen = resp.Vtep.LastSeen.AsTime()
	}

	// Get VNIs from proto response - ensure non-nil slice
	vnis := resp.Vtep.Vnis
	if vnis == nil {
		vnis = []uint32{}
	}

	return &VTEPGetResult{
		VTEPInfo: VTEPInfo{
			NodeID:   resp.Vtep.NodeId,
			IP:       ip,
			Healthy:  resp.Vtep.Healthy,
			LastSeen: lastSeen,
		},
		VNIs:      vnis,
		MACCount:  int(resp.Vtep.MacCount),
		BytesSent: resp.Vtep.BytesSent,
		BytesRecv: resp.Vtep.BytesRecv,
	}, nil
}

// =============================================================================
// VNI Operations
// =============================================================================

// VNICreate creates a new VNI via Unix socket.
func (a *OverlayUnixAdapter) VNICreate(ctx context.Context, opts VNICreateOptions) (*VNICreateResult, error) {
	resp, err := a.overlay.CreateVNI(ctx, &platformv1.CreateVNIRequest{
		Config: &platformv1.VNIConfig{
			Vni:  opts.VNI,
			Vlan: uint32(opts.VLAN),
			Name: opts.Name,
		},
	})
	if err != nil {
		return nil, ErrOverlayUnixRPCFailed{Method: "CreateVNI", Err: err}
	}

	if resp.Vni == nil || resp.Vni.Config == nil {
		return nil, ErrOverlayUnixInvalidResponse{Method: "CreateVNI", Details: "nil vni or config"}
	}

	var createdAt time.Time
	if resp.Vni.CreatedAt != nil {
		createdAt = resp.Vni.CreatedAt.AsTime()
	}

	return &VNICreateResult{
		VNI:       resp.Vni.Config.Vni,
		VLAN:      uint16(resp.Vni.Config.Vlan),
		Name:      resp.Vni.Config.Name,
		CreatedAt: createdAt,
	}, nil
}

// VNIDelete deletes a VNI via Unix socket.
func (a *OverlayUnixAdapter) VNIDelete(ctx context.Context, vni uint32) (*VNIDeleteResult, error) {
	resp, err := a.overlay.DeleteVNI(ctx, &platformv1.DeleteVNIRequest{
		Vni: vni,
	})
	if err != nil {
		return nil, ErrOverlayUnixRPCFailed{Method: "DeleteVNI", Err: err}
	}

	deleted := resp.Status != nil && resp.Status.Success

	return &VNIDeleteResult{
		VNI:     vni,
		Deleted: deleted,
	}, nil
}

// VNIList lists all VNIs via Unix socket.
func (a *OverlayUnixAdapter) VNIList(ctx context.Context) (*VNIListResult, error) {
	resp, err := a.overlay.ListVNIs(ctx, &platformv1.ListVNIsRequest{})
	if err != nil {
		return nil, ErrOverlayUnixRPCFailed{Method: "ListVNIs", Err: err}
	}

	vnis := make([]VNIInfo, 0, len(resp.Vnis))
	for _, v := range resp.Vnis {
		var vni uint32
		var vlan uint16
		var name string

		if v.Config != nil {
			vni = v.Config.Vni
			vlan = uint16(v.Config.Vlan)
			name = v.Config.Name
		}

		var createdAt time.Time
		if v.CreatedAt != nil {
			createdAt = v.CreatedAt.AsTime()
		}

		vnis = append(vnis, VNIInfo{
			VNI:       vni,
			VLAN:      vlan,
			Name:      name,
			MACCount:  int(v.MacCount),
			CreatedAt: createdAt,
		})
	}

	return &VNIListResult{
		VNIs:       vnis,
		TotalCount: len(vnis),
	}, nil
}

// =============================================================================
// Tunnel Operations
// =============================================================================

// TunnelList lists all tunnels via Unix socket.
func (a *OverlayUnixAdapter) TunnelList(ctx context.Context, opts TunnelListOptions) (*TunnelListResult, error) {
	resp, err := a.overlay.ListTunnels(ctx, &platformv1.ListTunnelsRequest{
		Vni: opts.VNI,
	})
	if err != nil {
		return nil, ErrOverlayUnixRPCFailed{Method: "ListTunnels", Err: err}
	}

	tunnels := make([]TunnelInfo, 0, len(resp.Tunnels))
	for _, t := range resp.Tunnels {
		localVTEP, parseErr := overlayUnixParseIPAddr(t.LocalVtep)
		if parseErr != nil {
			return nil, ErrOverlayUnixParseIP{IP: t.LocalVtep, Err: parseErr}
		}

		remoteVTEP, parseErr := overlayUnixParseIPAddr(t.RemoteVtep)
		if parseErr != nil {
			return nil, ErrOverlayUnixParseIP{IP: t.RemoteVtep, Err: parseErr}
		}

		tunnels = append(tunnels, TunnelInfo{
			LocalVTEP:  localVTEP,
			RemoteVTEP: remoteVTEP,
			VNI:        t.Vni,
			State:      t.State,
			BytesSent:  t.BytesTx,
			BytesRecv:  t.BytesRx,
		})
	}

	return &TunnelListResult{
		Tunnels:    tunnels,
		TotalCount: len(tunnels),
	}, nil
}

// =============================================================================
// MAC Operations
// =============================================================================

// MACList lists all remote MACs via Unix socket.
func (a *OverlayUnixAdapter) MACList(ctx context.Context, opts MACListOptions) (*MACListResult, error) {
	resp, err := a.overlay.ListRemoteMACs(ctx, &platformv1.ListRemoteMACsRequest{
		Vni: opts.VNI,
	})
	if err != nil {
		return nil, ErrOverlayUnixRPCFailed{Method: "ListRemoteMACs", Err: err}
	}

	macs := make([]RemoteMACInfo, 0, len(resp.Macs))
	for _, m := range resp.Macs {
		mac, parseErr := net.ParseMAC(m.Mac)
		if parseErr != nil {
			return nil, ErrOverlayUnixParseMAC{MAC: m.Mac, Err: parseErr}
		}

		remoteVTEP, parseErr := overlayUnixParseIPAddr(m.RemoteVtep)
		if parseErr != nil {
			return nil, ErrOverlayUnixParseIP{IP: m.RemoteVtep, Err: parseErr}
		}

		var learnedAt time.Time
		if m.LearnedAt != nil {
			learnedAt = m.LearnedAt.AsTime()
		}

		macs = append(macs, RemoteMACInfo{
			MAC:        mac,
			VNI:        m.Vni,
			RemoteVTEP: remoteVTEP,
			LearnedAt:  learnedAt,
		})
	}

	return &MACListResult{
		MACs:       macs,
		TotalCount: len(macs),
	}, nil
}

// MACForget forgets a remote MAC via Unix socket.
func (a *OverlayUnixAdapter) MACForget(ctx context.Context, mac string, vni uint32) (*MACForgetResult, error) {
	resp, err := a.overlay.ForgetMAC(ctx, &platformv1.ForgetMACRequest{
		Mac: mac,
		Vni: vni,
	})
	if err != nil {
		return nil, ErrOverlayUnixRPCFailed{Method: "ForgetMAC", Err: err}
	}

	deleted := resp.Status != nil && resp.Status.Success

	return &MACForgetResult{
		MAC:     mac,
		VNI:     vni,
		Deleted: deleted,
	}, nil
}

// =============================================================================
// Gateway Operations
// =============================================================================

// GatewayStatus retrieves gateway status via Unix socket.
func (a *OverlayUnixAdapter) GatewayStatus(ctx context.Context) (*GatewayStatusResult, error) {
	resp, err := a.gateway.GetGatewayStatus(ctx, &platformv1.GetGatewayStatusRequest{})
	if err != nil {
		return nil, ErrOverlayUnixRPCFailed{Method: "GetGatewayStatus", Err: err}
	}

	if resp.Status == nil {
		return nil, ErrOverlayUnixInvalidResponse{Method: "GetGatewayStatus", Details: "nil status"}
	}

	modes := overlayUnixGatewayModesFromBitmask(resp.Status.Modes)

	return &GatewayStatusResult{
		NodeID:     resp.Status.NodeId,
		Modes:      modes,
		Tier:       resp.Status.Tier,
		Healthy:    resp.Status.Healthy,
		Reputation: resp.Status.Reputation,
		Age:        time.Duration(resp.Status.UptimeSeconds) * time.Second,
	}, nil
}

// GatewaySetMode sets gateway mode via Unix socket.
func (a *OverlayUnixAdapter) GatewaySetMode(ctx context.Context, opts GatewayModeOptions) (*GatewayModeResult, error) {
	modesBitmask := overlayUnixGatewayModesToBitmask(opts.Modes)

	resp, err := a.gateway.SetGatewayMode(ctx, &platformv1.SetGatewayModeRequest{
		Modes: modesBitmask,
	})
	if err != nil {
		return nil, ErrOverlayUnixRPCFailed{Method: "SetGatewayMode", Err: err}
	}

	success := resp.Status != nil && resp.Status.Success

	var resultModes []string
	if resp.GatewayStatus != nil {
		resultModes = overlayUnixGatewayModesFromBitmask(resp.GatewayStatus.Modes)
	}

	return &GatewayModeResult{
		Modes:   resultModes,
		Success: success,
	}, nil
}

// =============================================================================
// BGP Operations
// =============================================================================

// BGPStatus retrieves BGP status via Unix socket.
func (a *OverlayUnixAdapter) BGPStatus(ctx context.Context) (*BGPStatusResult, error) {
	resp, err := a.gateway.GetBGPStatus(ctx, &platformv1.GetBGPStatusRequest{})
	if err != nil {
		return nil, ErrOverlayUnixRPCFailed{Method: "GetBGPStatus", Err: err}
	}

	if resp.Status == nil {
		return nil, ErrOverlayUnixInvalidResponse{Method: "GetBGPStatus", Details: "nil status"}
	}

	return &BGPStatusResult{
		Enabled:          resp.Status.Running,
		ASN:              resp.Status.LocalAsn,
		RouterID:         resp.Status.RouterId,
		PeerCount:        int(resp.Status.PeerCount),
		EstablishedCount: int(resp.Status.EstablishedPeers),
	}, nil
}

// BGPPeers lists BGP peers via Unix socket.
func (a *OverlayUnixAdapter) BGPPeers(ctx context.Context) (*BGPPeersResult, error) {
	resp, err := a.gateway.ListBGPPeers(ctx, &platformv1.ListBGPPeersRequest{})
	if err != nil {
		return nil, ErrOverlayUnixRPCFailed{Method: "ListBGPPeers", Err: err}
	}

	peers := make([]BGPPeerInfo, 0, len(resp.Peers))
	for _, p := range resp.Peers {
		var uptime time.Duration
		if p.Uptime != nil {
			uptime = time.Since(p.Uptime.AsTime())
		}

		peers = append(peers, BGPPeerInfo{
			Address:      p.Address,
			RemoteASN:    p.Asn,
			State:        p.State,
			Uptime:       uptime,
			PrefixesRecv: int(p.PrefixesReceived),
			PrefixesSent: int(p.PrefixesSent),
			Description:  p.Description,
		})
	}

	return &BGPPeersResult{
		Peers:      peers,
		TotalCount: len(peers),
	}, nil
}

// BGPPrefixes lists announced BGP prefixes via Unix socket.
func (a *OverlayUnixAdapter) BGPPrefixes(ctx context.Context) (*BGPPrefixesResult, error) {
	resp, err := a.gateway.ListAnnouncedPrefixes(ctx, &platformv1.ListAnnouncedPrefixesRequest{})
	if err != nil {
		return nil, ErrOverlayUnixRPCFailed{Method: "ListAnnouncedPrefixes", Err: err}
	}

	prefixes := make([]BGPPrefixInfo, 0, len(resp.Prefixes))
	for _, p := range resp.Prefixes {
		prefixes = append(prefixes, BGPPrefixInfo{
			Prefix:  p.Prefix,
			NextHop: p.NextHop,
		})
	}

	return &BGPPrefixesResult{
		Prefixes:   prefixes,
		TotalCount: len(prefixes),
	}, nil
}

// BGPAnnounce announces a BGP prefix via Unix socket.
func (a *OverlayUnixAdapter) BGPAnnounce(ctx context.Context, opts BGPAnnounceOptions) (*BGPAnnounceResult, error) {
	resp, err := a.gateway.AnnouncePrefix(ctx, &platformv1.AnnouncePrefixRequest{
		Prefix:  opts.Prefix,
		NextHop: opts.NextHop,
	})
	if err != nil {
		return nil, ErrOverlayUnixRPCFailed{Method: "AnnouncePrefix", Err: err}
	}

	success := resp.Status != nil && resp.Status.Success

	return &BGPAnnounceResult{
		Prefix:  opts.Prefix,
		Success: success,
	}, nil
}

// BGPWithdraw withdraws a BGP prefix via Unix socket.
func (a *OverlayUnixAdapter) BGPWithdraw(ctx context.Context, prefix string) (*BGPWithdrawResult, error) {
	resp, err := a.gateway.WithdrawPrefix(ctx, &platformv1.WithdrawPrefixRequest{
		Prefix: prefix,
	})
	if err != nil {
		return nil, ErrOverlayUnixRPCFailed{Method: "WithdrawPrefix", Err: err}
	}

	success := resp.Status != nil && resp.Status.Success

	return &BGPWithdrawResult{
		Prefix:  prefix,
		Success: success,
	}, nil
}

// =============================================================================
// IPAM Operations
// =============================================================================

// IPAMPoolList lists IPAM pools via Unix socket.
func (a *OverlayUnixAdapter) IPAMPoolList(ctx context.Context) (*IPAMPoolListResult, error) {
	resp, err := a.gateway.ListIPAMPools(ctx, &platformv1.ListIPAMPoolsRequest{})
	if err != nil {
		return nil, ErrOverlayUnixRPCFailed{Method: "ListIPAMPools", Err: err}
	}

	pools := make([]IPAMPoolInfo, 0, len(resp.Pools))
	for _, p := range resp.Pools {
		var utilizationPct float64
		if p.Total > 0 {
			utilizationPct = float64(p.Allocated) / float64(p.Total) * 100
		}

		pools = append(pools, IPAMPoolInfo{
			ID:             p.Id,
			CIDR:           p.Cidr,
			Gateway:        p.Gateway,
			TotalIPs:       int64(p.Total),
			AllocatedIPs:   int64(p.Allocated),
			AvailableIPs:   int64(p.Available),
			UtilizationPct: utilizationPct,
		})
	}

	return &IPAMPoolListResult{
		Pools:      pools,
		TotalCount: len(pools),
	}, nil
}

// IPAMPoolCreate creates an IPAM pool via Unix socket.
// Note: The gateway proto does not define a CreateIPAMPool RPC, so this returns not implemented.
func (a *OverlayUnixAdapter) IPAMPoolCreate(ctx context.Context, opts IPAMPoolCreateOptions) (*IPAMPoolCreateResult, error) {
	return nil, ErrAdapterNotImplemented{Protocol: "Unix", Operation: "IPAMPoolCreate"}
}

// IPAMPoolDelete deletes an IPAM pool via Unix socket.
// Note: The gateway proto does not define a DeleteIPAMPool RPC, so this returns not implemented.
func (a *OverlayUnixAdapter) IPAMPoolDelete(ctx context.Context, poolID string) (*IPAMPoolDeleteResult, error) {
	return nil, ErrAdapterNotImplemented{Protocol: "Unix", Operation: "IPAMPoolDelete"}
}

// IPAMAllocate allocates an IP address from a pool via Unix socket.
func (a *OverlayUnixAdapter) IPAMAllocate(ctx context.Context, opts IPAMAllocateOptions) (*IPAMAllocateResult, error) {
	resp, err := a.gateway.AllocateIP(ctx, &platformv1.AllocateIPRequest{
		PoolId:   opts.PoolID,
		DeviceId: opts.DeviceID,
		Hostname: opts.Hostname,
	})
	if err != nil {
		return nil, ErrOverlayUnixRPCFailed{Method: "AllocateIP", Err: err}
	}

	if resp.Allocation == nil {
		return nil, ErrOverlayUnixInvalidResponse{Method: "AllocateIP", Details: "nil allocation"}
	}

	ip, parseErr := netip.ParseAddr(resp.Allocation.Ip)
	if parseErr != nil {
		return nil, ErrOverlayUnixParseIP{IP: resp.Allocation.Ip, Err: parseErr}
	}

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

// IPAMRelease releases an IP address via Unix socket.
func (a *OverlayUnixAdapter) IPAMRelease(ctx context.Context, ip string) (*IPAMReleaseResult, error) {
	resp, err := a.gateway.ReleaseIP(ctx, &platformv1.ReleaseIPRequest{
		Ip: ip,
	})
	if err != nil {
		return nil, ErrOverlayUnixRPCFailed{Method: "ReleaseIP", Err: err}
	}

	released := resp.Status != nil && resp.Status.Success

	return &IPAMReleaseResult{
		IP:       ip,
		Released: released,
	}, nil
}

// IPAMList lists IPAM allocations via Unix socket.
func (a *OverlayUnixAdapter) IPAMList(ctx context.Context, opts IPAMListOptions) (*IPAMListResult, error) {
	resp, err := a.gateway.ListAllocations(ctx, &platformv1.ListAllocationsRequest{
		PoolId: opts.PoolID,
	})
	if err != nil {
		return nil, ErrOverlayUnixRPCFailed{Method: "ListAllocations", Err: err}
	}

	allocations := make([]IPAMAllocationInfo, 0, len(resp.Allocations))
	for _, alloc := range resp.Allocations {
		ip, parseErr := netip.ParseAddr(alloc.Ip)
		if parseErr != nil {
			return nil, ErrOverlayUnixParseIP{IP: alloc.Ip, Err: parseErr}
		}

		var allocatedAt, leaseExpiry time.Time
		if alloc.AllocatedAt != nil {
			allocatedAt = alloc.AllocatedAt.AsTime()
		}
		if alloc.ExpiresAt != nil {
			leaseExpiry = alloc.ExpiresAt.AsTime()
		}

		allocations = append(allocations, IPAMAllocationInfo{
			IP:          ip,
			PoolID:      alloc.PoolId,
			DeviceID:    alloc.DeviceId,
			Hostname:    alloc.Hostname,
			AllocatedAt: allocatedAt,
			LeaseExpiry: leaseExpiry,
		})
	}

	return &IPAMListResult{
		Allocations: allocations,
		TotalCount:  len(allocations),
	}, nil
}

// =============================================================================
// Helper Functions
// =============================================================================

// overlayUnixParseIPAddr parses an IP address string into a netip.Addr.
func overlayUnixParseIPAddr(ipStr string) (netip.Addr, error) {
	if ipStr == "" {
		return netip.Addr{}, nil
	}
	return netip.ParseAddr(ipStr)
}

// overlayUnixGatewayModesFromBitmask converts a bitmask to a slice of mode strings.
func overlayUnixGatewayModesFromBitmask(modes uint32) []string {
	var result []string
	if modes&uint32(platformv1.GatewayModeEnum_GATEWAY_MODE_OVERLAY) != 0 {
		result = append(result, "overlay")
	}
	if modes&uint32(platformv1.GatewayModeEnum_GATEWAY_MODE_EDGE) != 0 {
		result = append(result, "edge")
	}
	if modes&uint32(platformv1.GatewayModeEnum_GATEWAY_MODE_TRANSIT) != 0 {
		result = append(result, "transit")
	}
	return result
}

// overlayUnixGatewayModesToBitmask converts a slice of mode strings to a bitmask.
func overlayUnixGatewayModesToBitmask(modes []string) uint32 {
	var bitmask uint32
	for _, mode := range modes {
		switch strings.ToLower(mode) {
		case "overlay":
			bitmask |= uint32(platformv1.GatewayModeEnum_GATEWAY_MODE_OVERLAY)
		case "edge":
			bitmask |= uint32(platformv1.GatewayModeEnum_GATEWAY_MODE_EDGE)
		case "transit":
			bitmask |= uint32(platformv1.GatewayModeEnum_GATEWAY_MODE_TRANSIT)
		}
	}
	return bitmask
}

// =============================================================================
// Compile-time Interface Verification
// =============================================================================

// Ensure OverlayUnixAdapter implements OverlayCommands interface.
var _ OverlayCommands = (*OverlayUnixAdapter)(nil)
