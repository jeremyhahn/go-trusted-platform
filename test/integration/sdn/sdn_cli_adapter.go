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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"time"
)

// =============================================================================
// CLI Adapter Implementation
// =============================================================================

// SDNCLIAdapter implements SDNTestAdapter using platformctl CLI commands.
// This adapter executes the platformctl binary and parses JSON output.
type SDNCLIAdapter struct {
	binaryPath string
}

// NewSDNCLIAdapter creates a new CLI adapter for SDN integration testing.
func NewSDNCLIAdapter() *SDNCLIAdapter {
	return &SDNCLIAdapter{}
}

// Name returns the protocol adapter identifier.
func (c *SDNCLIAdapter) Name() string {
	return "CLI"
}

// Setup locates the platformctl binary.
func (c *SDNCLIAdapter) Setup(ctx context.Context) error {
	// Check common locations for platformctl
	paths := []string{
		"platformctl",
		"/usr/local/bin/platformctl",
		"/usr/bin/platformctl",
		"./bin/platformctl",
		"../../bin/platformctl",
	}

	for _, p := range paths {
		if _, err := exec.LookPath(p); err == nil {
			c.binaryPath = p
			return nil
		}
	}

	// Check if PLATFORMCTL_PATH is set
	if envPath := os.Getenv("PLATFORMCTL_PATH"); envPath != "" {
		if _, err := os.Stat(envPath); err == nil {
			c.binaryPath = envPath
			return nil
		}
	}

	return ErrAdapterSetupFailed{Protocol: "CLI", Err: fmt.Errorf("platformctl binary not found")}
}

// Teardown is a no-op for CLI adapter.
func (c *SDNCLIAdapter) Teardown() error {
	return nil
}

// =============================================================================
// CLI Execution Helper
// =============================================================================

// runCommand executes a platformctl command and returns JSON output.
func (c *SDNCLIAdapter) runCommand(ctx context.Context, args ...string) ([]byte, error) {
	// Append --output json for structured output
	args = append(args, "--output", "json")

	cmd := exec.CommandContext(ctx, c.binaryPath, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("command failed: %w, stderr: %s", err, stderr.String())
	}

	return stdout.Bytes(), nil
}

// =============================================================================
// Overlay Operations
// =============================================================================

// ListVTEPs returns all discovered VTEPs via CLI.
func (c *SDNCLIAdapter) ListVTEPs(ctx context.Context) (*VTEPListResponse, error) {
	output, err := c.runCommand(ctx, "sdn", "overlay", "vtep", "list")
	if err != nil {
		return nil, err
	}

	var resp cliVTEPListResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse VTEP list: %w", err)
	}

	return resp.toResponse(), nil
}

// CreateVNI creates a new VNI via CLI.
func (c *SDNCLIAdapter) CreateVNI(ctx context.Context, vni uint32) error {
	_, err := c.runCommand(ctx, "sdn", "overlay", "vni", "create", fmt.Sprintf("%d", vni))
	return err
}

// DeleteVNI removes a VNI via CLI.
func (c *SDNCLIAdapter) DeleteVNI(ctx context.Context, vni uint32) error {
	_, err := c.runCommand(ctx, "sdn", "overlay", "vni", "delete", fmt.Sprintf("%d", vni))
	return err
}

// ListTunnels returns all active tunnels via CLI.
func (c *SDNCLIAdapter) ListTunnels(ctx context.Context) (*TunnelListResponse, error) {
	output, err := c.runCommand(ctx, "sdn", "overlay", "tunnel", "list")
	if err != nil {
		return nil, err
	}

	var resp cliTunnelListResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse tunnel list: %w", err)
	}

	return resp.toResponse(), nil
}

// ListRemoteMACs returns all learned remote MACs for a VNI via CLI.
func (c *SDNCLIAdapter) ListRemoteMACs(ctx context.Context, vni uint32) (*RemoteMACListResponse, error) {
	output, err := c.runCommand(ctx, "sdn", "overlay", "mac", "list", "--vni", fmt.Sprintf("%d", vni))
	if err != nil {
		return nil, err
	}

	var resp cliRemoteMACListResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse remote MAC list: %w", err)
	}

	return resp.toResponse(), nil
}

// =============================================================================
// Gateway Operations
// =============================================================================

// GetGatewayStatus returns the gateway status via CLI.
func (c *SDNCLIAdapter) GetGatewayStatus(ctx context.Context) (*GatewayStatusResponse, error) {
	output, err := c.runCommand(ctx, "sdn", "gateway", "status")
	if err != nil {
		return nil, err
	}

	var resp cliGatewayStatusResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse gateway status: %w", err)
	}

	return resp.toResponse(), nil
}

// SetGatewayMode sets the gateway mode via CLI.
func (c *SDNCLIAdapter) SetGatewayMode(ctx context.Context, mode GatewayMode) error {
	_, err := c.runCommand(ctx, "sdn", "gateway", "mode", "set", mode.String())
	return err
}

// =============================================================================
// BGP Operations
// =============================================================================

// GetBGPStatus returns the BGP status via CLI.
func (c *SDNCLIAdapter) GetBGPStatus(ctx context.Context) (*BGPStatusResponse, error) {
	output, err := c.runCommand(ctx, "sdn", "gateway", "bgp", "status")
	if err != nil {
		return nil, err
	}

	var resp cliBGPStatusResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse BGP status: %w", err)
	}

	return resp.toResponse(), nil
}

// ListBGPPeers returns all BGP peers via CLI.
func (c *SDNCLIAdapter) ListBGPPeers(ctx context.Context) (*BGPPeerListResponse, error) {
	output, err := c.runCommand(ctx, "sdn", "gateway", "bgp", "peer", "list")
	if err != nil {
		return nil, err
	}

	var resp cliBGPPeerListResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse BGP peer list: %w", err)
	}

	return resp.toResponse(), nil
}

// AnnouncePrefix announces a BGP prefix via CLI.
func (c *SDNCLIAdapter) AnnouncePrefix(ctx context.Context, prefix string) error {
	_, err := c.runCommand(ctx, "sdn", "gateway", "bgp", "announce", prefix)
	return err
}

// WithdrawPrefix withdraws a BGP prefix via CLI.
func (c *SDNCLIAdapter) WithdrawPrefix(ctx context.Context, prefix string) error {
	_, err := c.runCommand(ctx, "sdn", "gateway", "bgp", "withdraw", prefix)
	return err
}

// =============================================================================
// IPAM Operations
// =============================================================================

// ListPools returns all IPAM pools via CLI.
func (c *SDNCLIAdapter) ListPools(ctx context.Context) (*IPAMPoolListResponse, error) {
	output, err := c.runCommand(ctx, "sdn", "ipam", "pool", "list")
	if err != nil {
		return nil, err
	}

	var resp cliIPAMPoolListResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse IPAM pool list: %w", err)
	}

	return resp.toResponse(), nil
}

// AllocateIP allocates an IP from a pool via CLI.
func (c *SDNCLIAdapter) AllocateIP(ctx context.Context, poolID string) (*IPAllocationResponse, error) {
	output, err := c.runCommand(ctx, "sdn", "ipam", "allocate", "--pool", poolID)
	if err != nil {
		return nil, err
	}

	var resp cliIPAllocationResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse IP allocation: %w", err)
	}

	return resp.toResponse(), nil
}

// ReleaseIP releases an allocated IP via CLI.
func (c *SDNCLIAdapter) ReleaseIP(ctx context.Context, poolID, ip string) error {
	_, err := c.runCommand(ctx, "sdn", "ipam", "release", "--pool", poolID, ip)
	return err
}

// =============================================================================
// DHCP Operations
// =============================================================================

// GetDHCPStatus returns the DHCP server status via CLI.
func (c *SDNCLIAdapter) GetDHCPStatus(ctx context.Context) (*DHCPStatusResponse, error) {
	output, err := c.runCommand(ctx, "sdn", "dhcp", "status")
	if err != nil {
		return nil, err
	}

	var resp cliDHCPStatusResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse DHCP status: %w", err)
	}

	return resp.toResponse(), nil
}

// ListLeases returns all DHCP leases via CLI.
func (c *SDNCLIAdapter) ListLeases(ctx context.Context) (*DHCPLeaseListResponse, error) {
	output, err := c.runCommand(ctx, "sdn", "dhcp", "lease", "list")
	if err != nil {
		return nil, err
	}

	var resp cliDHCPLeaseListResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse DHCP lease list: %w", err)
	}

	return resp.toResponse(), nil
}

// =============================================================================
// CLI Response Types
// =============================================================================

type cliVTEPListResponse struct {
	VTEPs      []cliVTEPEntry `json:"vteps"`
	TotalCount int            `json:"total_count"`
}

type cliVTEPEntry struct {
	NodeID     string `json:"node_id"`
	IP         string `json:"ip"`
	State      string `json:"state"`
	IsLocal    bool   `json:"is_local"`
	TunnelPort uint16 `json:"tunnel_port"`
	LastSeen   int64  `json:"last_seen"`
	VNICount   int    `json:"vni_count"`
	BytesSent  uint64 `json:"bytes_sent"`
	BytesRecv  uint64 `json:"bytes_recv"`
}

func (r *cliVTEPListResponse) toResponse() *VTEPListResponse {
	vteps := make([]VTEPEntry, 0, len(r.VTEPs))
	for _, v := range r.VTEPs {
		ip, _ := netip.ParseAddr(v.IP)
		vteps = append(vteps, VTEPEntry{
			NodeID:     v.NodeID,
			IP:         ip,
			State:      v.State,
			IsLocal:    v.IsLocal,
			TunnelPort: v.TunnelPort,
			LastSeen:   time.Unix(v.LastSeen, 0),
			VNICount:   v.VNICount,
			BytesSent:  v.BytesSent,
			BytesRecv:  v.BytesRecv,
		})
	}
	return &VTEPListResponse{
		VTEPs:      vteps,
		TotalCount: r.TotalCount,
	}
}

type cliTunnelListResponse struct {
	Tunnels    []cliTunnelEntry `json:"tunnels"`
	TotalCount int              `json:"total_count"`
}

type cliTunnelEntry struct {
	LocalVTEP  string `json:"local_vtep"`
	RemoteVTEP string `json:"remote_vtep"`
	VNI        uint32 `json:"vni"`
	State      string `json:"state"`
	PortName   string `json:"port_name"`
	BytesSent  uint64 `json:"bytes_sent"`
	BytesRecv  uint64 `json:"bytes_recv"`
	CreatedAt  int64  `json:"created_at"`
}

func (r *cliTunnelListResponse) toResponse() *TunnelListResponse {
	tunnels := make([]TunnelEntry, 0, len(r.Tunnels))
	for _, t := range r.Tunnels {
		localVTEP, _ := netip.ParseAddr(t.LocalVTEP)
		remoteVTEP, _ := netip.ParseAddr(t.RemoteVTEP)
		tunnels = append(tunnels, TunnelEntry{
			LocalVTEP:  localVTEP,
			RemoteVTEP: remoteVTEP,
			VNI:        t.VNI,
			State:      t.State,
			PortName:   t.PortName,
			BytesSent:  t.BytesSent,
			BytesRecv:  t.BytesRecv,
			CreatedAt:  time.Unix(t.CreatedAt, 0),
		})
	}
	return &TunnelListResponse{
		Tunnels:    tunnels,
		TotalCount: r.TotalCount,
	}
}

type cliRemoteMACListResponse struct {
	MACs       []cliRemoteMACEntry `json:"macs"`
	TotalCount int                 `json:"total_count"`
}

type cliRemoteMACEntry struct {
	MAC        string `json:"mac"`
	IP         string `json:"ip"`
	VNI        uint32 `json:"vni"`
	RemoteVTEP string `json:"remote_vtep"`
	Source     string `json:"source"`
	LearnedAt  int64  `json:"learned_at"`
	ExpiresAt  int64  `json:"expires_at"`
}

func (r *cliRemoteMACListResponse) toResponse() *RemoteMACListResponse {
	macs := make([]RemoteMACEntry, 0, len(r.MACs))
	for _, m := range r.MACs {
		mac, _ := net.ParseMAC(m.MAC)
		ip, _ := netip.ParseAddr(m.IP)
		remoteVTEP, _ := netip.ParseAddr(m.RemoteVTEP)
		macs = append(macs, RemoteMACEntry{
			MAC:        mac,
			IP:         ip,
			VNI:        m.VNI,
			RemoteVTEP: remoteVTEP,
			Source:     m.Source,
			LearnedAt:  time.Unix(m.LearnedAt, 0),
			ExpiresAt:  time.Unix(m.ExpiresAt, 0),
		})
	}
	return &RemoteMACListResponse{
		MACs:       macs,
		TotalCount: r.TotalCount,
	}
}

type cliGatewayStatusResponse struct {
	NodeID         string   `json:"node_id"`
	Modes          []string `json:"modes"`
	Tier           string   `json:"tier"`
	Healthy        bool     `json:"healthy"`
	Reputation     float64  `json:"reputation"`
	AgeSec         int64    `json:"age_sec"`
	UptimePct      float64  `json:"uptime_pct"`
	IPv6Pool       string   `json:"ipv6_pool"`
	IPv4Pool       string   `json:"ipv4_pool"`
	BGPEnabled     bool     `json:"bgp_enabled"`
	EVPNEnabled    bool     `json:"evpn_enabled"`
	TransitEnabled bool     `json:"transit_enabled"`
}

func (r *cliGatewayStatusResponse) toResponse() *GatewayStatusResponse {
	var modes GatewayMode
	for _, m := range r.Modes {
		switch m {
		case "overlay":
			modes |= GatewayModeOverlay
		case "edge":
			modes |= GatewayModeEdge
		case "transit":
			modes |= GatewayModeTransit
		}
	}
	return &GatewayStatusResponse{
		NodeID:         r.NodeID,
		Modes:          modes,
		Tier:           r.Tier,
		Healthy:        r.Healthy,
		Reputation:     r.Reputation,
		Age:            time.Duration(r.AgeSec) * time.Second,
		UptimePct:      r.UptimePct,
		IPv6Pool:       r.IPv6Pool,
		IPv4Pool:       r.IPv4Pool,
		BGPEnabled:     r.BGPEnabled,
		EVPNEnabled:    r.EVPNEnabled,
		TransitEnabled: r.TransitEnabled,
	}
}

type cliBGPStatusResponse struct {
	Enabled          bool   `json:"enabled"`
	ASN              uint32 `json:"asn"`
	RouterID         string `json:"router_id"`
	State            string `json:"state"`
	PeerCount        int    `json:"peer_count"`
	EstablishedCount int    `json:"established_count"`
	EVPNEnabled      bool   `json:"evpn_enabled"`
	TransitEnabled   bool   `json:"transit_enabled"`
	RPKIEnabled      bool   `json:"rpki_enabled"`
}

func (r *cliBGPStatusResponse) toResponse() *BGPStatusResponse {
	return &BGPStatusResponse{
		Enabled:          r.Enabled,
		ASN:              r.ASN,
		RouterID:         r.RouterID,
		State:            r.State,
		PeerCount:        r.PeerCount,
		EstablishedCount: r.EstablishedCount,
		EVPNEnabled:      r.EVPNEnabled,
		TransitEnabled:   r.TransitEnabled,
		RPKIEnabled:      r.RPKIEnabled,
	}
}

type cliBGPPeerListResponse struct {
	Peers      []cliBGPPeerEntry `json:"peers"`
	TotalCount int               `json:"total_count"`
}

type cliBGPPeerEntry struct {
	Address      string `json:"address"`
	RemoteASN    uint32 `json:"remote_asn"`
	State        string `json:"state"`
	UptimeSec    int64  `json:"uptime_sec"`
	PrefixesRecv int    `json:"prefixes_recv"`
	PrefixesSent int    `json:"prefixes_sent"`
	Description  string `json:"description"`
	LastError    string `json:"last_error"`
}

func (r *cliBGPPeerListResponse) toResponse() *BGPPeerListResponse {
	peers := make([]BGPPeerEntry, 0, len(r.Peers))
	for _, p := range r.Peers {
		peers = append(peers, BGPPeerEntry{
			Address:      p.Address,
			RemoteASN:    p.RemoteASN,
			State:        p.State,
			Uptime:       time.Duration(p.UptimeSec) * time.Second,
			PrefixesRecv: p.PrefixesRecv,
			PrefixesSent: p.PrefixesSent,
			Description:  p.Description,
			LastError:    p.LastError,
		})
	}
	return &BGPPeerListResponse{
		Peers:      peers,
		TotalCount: r.TotalCount,
	}
}

type cliIPAMPoolListResponse struct {
	Pools      []cliIPAMPoolEntry `json:"pools"`
	TotalCount int                `json:"total_count"`
}

type cliIPAMPoolEntry struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	CIDR             string   `json:"cidr"`
	Gateway          string   `json:"gateway"`
	TotalIPs         int64    `json:"total_ips"`
	AllocatedIPs     int64    `json:"allocated_ips"`
	AvailableIPs     int64    `json:"available_ips"`
	UtilizationPct   float64  `json:"utilization_pct"`
	DNS              []string `json:"dns"`
	LeaseDurationSec int64    `json:"lease_duration_sec"`
}

func (r *cliIPAMPoolListResponse) toResponse() *IPAMPoolListResponse {
	pools := make([]IPAMPoolEntry, 0, len(r.Pools))
	for _, p := range r.Pools {
		pools = append(pools, IPAMPoolEntry{
			ID:             p.ID,
			Name:           p.Name,
			CIDR:           p.CIDR,
			Gateway:        p.Gateway,
			TotalIPs:       p.TotalIPs,
			AllocatedIPs:   p.AllocatedIPs,
			AvailableIPs:   p.AvailableIPs,
			UtilizationPct: p.UtilizationPct,
			DNS:            p.DNS,
			LeaseDuration:  time.Duration(p.LeaseDurationSec) * time.Second,
		})
	}
	return &IPAMPoolListResponse{
		Pools:      pools,
		TotalCount: r.TotalCount,
	}
}

type cliIPAllocationResponse struct {
	IP          string   `json:"ip"`
	PoolID      string   `json:"pool_id"`
	LeaseExpiry int64    `json:"lease_expiry"`
	Gateway     string   `json:"gateway"`
	DNS         []string `json:"dns"`
	SubnetMask  string   `json:"subnet_mask"`
}

func (r *cliIPAllocationResponse) toResponse() *IPAllocationResponse {
	ip, _ := netip.ParseAddr(r.IP)
	return &IPAllocationResponse{
		IP:          ip,
		PoolID:      r.PoolID,
		LeaseExpiry: time.Unix(r.LeaseExpiry, 0),
		Gateway:     r.Gateway,
		DNS:         r.DNS,
		SubnetMask:  r.SubnetMask,
	}
}

type cliDHCPStatusResponse struct {
	Running         bool   `json:"running"`
	Interface       string `json:"interface"`
	StartedAt       int64  `json:"started_at"`
	UptimeSec       int64  `json:"uptime_sec"`
	PacketsReceived uint64 `json:"packets_received"`
	PacketsSent     uint64 `json:"packets_sent"`
	ActiveLeases    int    `json:"active_leases"`
	Stats           struct {
		DiscoverCount uint64 `json:"discover_count"`
		OfferCount    uint64 `json:"offer_count"`
		RequestCount  uint64 `json:"request_count"`
		AckCount      uint64 `json:"ack_count"`
		NakCount      uint64 `json:"nak_count"`
		ReleaseCount  uint64 `json:"release_count"`
		DeclineCount  uint64 `json:"decline_count"`
		InformCount   uint64 `json:"inform_count"`
		ErrorCount    uint64 `json:"error_count"`
	} `json:"stats"`
}

func (r *cliDHCPStatusResponse) toResponse() *DHCPStatusResponse {
	return &DHCPStatusResponse{
		Running:         r.Running,
		Interface:       r.Interface,
		StartedAt:       time.Unix(r.StartedAt, 0),
		Uptime:          time.Duration(r.UptimeSec) * time.Second,
		PacketsReceived: r.PacketsReceived,
		PacketsSent:     r.PacketsSent,
		ActiveLeases:    r.ActiveLeases,
		Stats: DHCPStats{
			DiscoverCount: r.Stats.DiscoverCount,
			OfferCount:    r.Stats.OfferCount,
			RequestCount:  r.Stats.RequestCount,
			AckCount:      r.Stats.AckCount,
			NakCount:      r.Stats.NakCount,
			ReleaseCount:  r.Stats.ReleaseCount,
			DeclineCount:  r.Stats.DeclineCount,
			InformCount:   r.Stats.InformCount,
			ErrorCount:    r.Stats.ErrorCount,
		},
	}
}

type cliDHCPLeaseListResponse struct {
	Leases     []cliDHCPLeaseEntry `json:"leases"`
	TotalCount int                 `json:"total_count"`
}

type cliDHCPLeaseEntry struct {
	IP          string `json:"ip"`
	MAC         string `json:"mac"`
	Hostname    string `json:"hostname"`
	State       string `json:"state"`
	LeaseStart  int64  `json:"lease_start"`
	LeaseExpiry int64  `json:"lease_expiry"`
	ClientID    string `json:"client_id"`
	PoolID      string `json:"pool_id"`
}

func (r *cliDHCPLeaseListResponse) toResponse() *DHCPLeaseListResponse {
	leases := make([]DHCPLeaseEntry, 0, len(r.Leases))
	for _, l := range r.Leases {
		ip, _ := netip.ParseAddr(l.IP)
		mac, _ := net.ParseMAC(l.MAC)
		leases = append(leases, DHCPLeaseEntry{
			IP:          ip,
			MAC:         mac,
			Hostname:    l.Hostname,
			State:       l.State,
			LeaseStart:  time.Unix(l.LeaseStart, 0),
			LeaseExpiry: time.Unix(l.LeaseExpiry, 0),
			ClientID:    l.ClientID,
			PoolID:      l.PoolID,
		})
	}
	return &DHCPLeaseListResponse{
		Leases:     leases,
		TotalCount: r.TotalCount,
	}
}

// Ensure SDNCLIAdapter implements SDNTestAdapter interface.
var _ SDNTestAdapter = (*SDNCLIAdapter)(nil)
