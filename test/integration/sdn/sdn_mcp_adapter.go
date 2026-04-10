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
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"
)

// =============================================================================
// MCP Adapter Implementation
// =============================================================================

// SDNMCPAdapter implements SDNTestAdapter using MCP (Model Context Protocol) calls.
// MCP is designed for AI/LLM integration with tools and resources.
type SDNMCPAdapter struct {
	baseURL    string
	httpClient *http.Client
}

// NewSDNMCPAdapter creates a new MCP adapter for SDN integration testing.
func NewSDNMCPAdapter() *SDNMCPAdapter {
	return &SDNMCPAdapter{}
}

// Name returns the protocol adapter identifier.
func (m *SDNMCPAdapter) Name() string {
	return "MCP"
}

// Setup initializes the MCP client.
func (m *SDNMCPAdapter) Setup(ctx context.Context) error {
	endpoints := GetServiceEndpoints()
	m.baseURL = "http://" + endpoints.PlatformMCP

	m.httpClient = &http.Client{
		Timeout: 30 * time.Second,
	}

	return nil
}

// Teardown closes the MCP client resources.
func (m *SDNMCPAdapter) Teardown() error {
	if m.httpClient != nil {
		m.httpClient.CloseIdleConnections()
	}
	return nil
}

// =============================================================================
// MCP Request/Response Types
// =============================================================================

// mcpRequest represents an MCP tool call request.
type mcpRequest struct {
	Method string                 `json:"method"`
	Params map[string]interface{} `json:"params,omitempty"`
}

// mcpResponse represents an MCP tool call response.
type mcpResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *mcpError       `json:"error,omitempty"`
}

// mcpError represents an MCP error.
type mcpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// =============================================================================
// MCP Request Helpers
// =============================================================================

// callTool invokes an MCP tool and returns the raw result.
func (m *SDNMCPAdapter) callTool(ctx context.Context, toolName string, params map[string]interface{}) (json.RawMessage, error) {
	req := mcpRequest{
		Method: "tools/call",
		Params: map[string]interface{}{
			"name":      toolName,
			"arguments": params,
		},
	}

	jsonBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal MCP request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, m.baseURL+"/mcp", bytes.NewReader(jsonBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create MCP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := m.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("MCP request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read MCP response: %w", err)
	}

	var mcpResp mcpResponse
	if err := json.Unmarshal(respBody, &mcpResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal MCP response: %w", err)
	}

	if mcpResp.Error != nil {
		return nil, fmt.Errorf("MCP error (%d): %s", mcpResp.Error.Code, mcpResp.Error.Message)
	}

	return mcpResp.Result, nil
}

// =============================================================================
// Overlay Operations
// =============================================================================

// ListVTEPs returns all discovered VTEPs via MCP.
func (m *SDNMCPAdapter) ListVTEPs(ctx context.Context) (*VTEPListResponse, error) {
	result, err := m.callTool(ctx, "sdn_list_vteps", nil)
	if err != nil {
		return nil, err
	}

	var resp mcpVTEPListResponse
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal VTEPs: %w", err)
	}

	return resp.toResponse(), nil
}

// CreateVNI creates a new VNI via MCP.
func (m *SDNMCPAdapter) CreateVNI(ctx context.Context, vni uint32) error {
	params := map[string]interface{}{
		"vni": vni,
	}

	_, err := m.callTool(ctx, "sdn_create_vni", params)
	return err
}

// DeleteVNI removes a VNI via MCP.
func (m *SDNMCPAdapter) DeleteVNI(ctx context.Context, vni uint32) error {
	params := map[string]interface{}{
		"vni": vni,
	}

	_, err := m.callTool(ctx, "sdn_delete_vni", params)
	return err
}

// ListTunnels returns all active tunnels via MCP.
func (m *SDNMCPAdapter) ListTunnels(ctx context.Context) (*TunnelListResponse, error) {
	result, err := m.callTool(ctx, "sdn_list_tunnels", nil)
	if err != nil {
		return nil, err
	}

	var resp mcpTunnelListResponse
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal tunnels: %w", err)
	}

	return resp.toResponse(), nil
}

// ListRemoteMACs returns all learned remote MACs for a VNI via MCP.
func (m *SDNMCPAdapter) ListRemoteMACs(ctx context.Context, vni uint32) (*RemoteMACListResponse, error) {
	params := map[string]interface{}{
		"vni": vni,
	}

	result, err := m.callTool(ctx, "sdn_list_remote_macs", params)
	if err != nil {
		return nil, err
	}

	var resp mcpRemoteMACListResponse
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal remote MACs: %w", err)
	}

	return resp.toResponse(), nil
}

// =============================================================================
// Gateway Operations
// =============================================================================

// GetGatewayStatus returns the gateway status via MCP.
func (m *SDNMCPAdapter) GetGatewayStatus(ctx context.Context) (*GatewayStatusResponse, error) {
	result, err := m.callTool(ctx, "sdn_gateway_status", nil)
	if err != nil {
		return nil, err
	}

	var resp mcpGatewayStatusResponse
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal gateway status: %w", err)
	}

	return resp.toResponse(), nil
}

// SetGatewayMode sets the gateway mode via MCP.
func (m *SDNMCPAdapter) SetGatewayMode(ctx context.Context, mode GatewayMode) error {
	params := map[string]interface{}{
		"mode": mode.String(),
	}

	_, err := m.callTool(ctx, "sdn_set_gateway_mode", params)
	return err
}

// =============================================================================
// BGP Operations
// =============================================================================

// GetBGPStatus returns the BGP status via MCP.
func (m *SDNMCPAdapter) GetBGPStatus(ctx context.Context) (*BGPStatusResponse, error) {
	result, err := m.callTool(ctx, "sdn_bgp_status", nil)
	if err != nil {
		return nil, err
	}

	var resp mcpBGPStatusResponse
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal BGP status: %w", err)
	}

	return resp.toResponse(), nil
}

// ListBGPPeers returns all BGP peers via MCP.
func (m *SDNMCPAdapter) ListBGPPeers(ctx context.Context) (*BGPPeerListResponse, error) {
	result, err := m.callTool(ctx, "sdn_list_bgp_peers", nil)
	if err != nil {
		return nil, err
	}

	var resp mcpBGPPeerListResponse
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal BGP peers: %w", err)
	}

	return resp.toResponse(), nil
}

// AnnouncePrefix announces a BGP prefix via MCP.
func (m *SDNMCPAdapter) AnnouncePrefix(ctx context.Context, prefix string) error {
	params := map[string]interface{}{
		"prefix": prefix,
	}

	_, err := m.callTool(ctx, "sdn_announce_prefix", params)
	return err
}

// WithdrawPrefix withdraws a BGP prefix via MCP.
func (m *SDNMCPAdapter) WithdrawPrefix(ctx context.Context, prefix string) error {
	params := map[string]interface{}{
		"prefix": prefix,
	}

	_, err := m.callTool(ctx, "sdn_withdraw_prefix", params)
	return err
}

// =============================================================================
// IPAM Operations
// =============================================================================

// ListPools returns all IPAM pools via MCP.
func (m *SDNMCPAdapter) ListPools(ctx context.Context) (*IPAMPoolListResponse, error) {
	result, err := m.callTool(ctx, "sdn_list_ipam_pools", nil)
	if err != nil {
		return nil, err
	}

	var resp mcpIPAMPoolListResponse
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal IPAM pools: %w", err)
	}

	return resp.toResponse(), nil
}

// AllocateIP allocates an IP from a pool via MCP.
func (m *SDNMCPAdapter) AllocateIP(ctx context.Context, poolID string) (*IPAllocationResponse, error) {
	params := map[string]interface{}{
		"pool_id": poolID,
	}

	result, err := m.callTool(ctx, "sdn_allocate_ip", params)
	if err != nil {
		return nil, err
	}

	var resp mcpIPAllocationResponse
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal IP allocation: %w", err)
	}

	return resp.toResponse(), nil
}

// ReleaseIP releases an allocated IP via MCP.
func (m *SDNMCPAdapter) ReleaseIP(ctx context.Context, poolID, ip string) error {
	params := map[string]interface{}{
		"pool_id": poolID,
		"ip":      ip,
	}

	_, err := m.callTool(ctx, "sdn_release_ip", params)
	return err
}

// =============================================================================
// DHCP Operations
// =============================================================================

// GetDHCPStatus returns the DHCP server status via MCP.
func (m *SDNMCPAdapter) GetDHCPStatus(ctx context.Context) (*DHCPStatusResponse, error) {
	result, err := m.callTool(ctx, "sdn_dhcp_status", nil)
	if err != nil {
		return nil, err
	}

	var resp mcpDHCPStatusResponse
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal DHCP status: %w", err)
	}

	return resp.toResponse(), nil
}

// ListLeases returns all DHCP leases via MCP.
func (m *SDNMCPAdapter) ListLeases(ctx context.Context) (*DHCPLeaseListResponse, error) {
	result, err := m.callTool(ctx, "sdn_list_dhcp_leases", nil)
	if err != nil {
		return nil, err
	}

	var resp mcpDHCPLeaseListResponse
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal DHCP leases: %w", err)
	}

	return resp.toResponse(), nil
}

// =============================================================================
// MCP Response Types
// =============================================================================

type mcpVTEPListResponse struct {
	VTEPs      []mcpVTEPEntry `json:"vteps"`
	TotalCount int            `json:"total_count"`
}

type mcpVTEPEntry struct {
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

func (r *mcpVTEPListResponse) toResponse() *VTEPListResponse {
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

type mcpTunnelListResponse struct {
	Tunnels    []mcpTunnelEntry `json:"tunnels"`
	TotalCount int              `json:"total_count"`
}

type mcpTunnelEntry struct {
	LocalVTEP  string `json:"local_vtep"`
	RemoteVTEP string `json:"remote_vtep"`
	VNI        uint32 `json:"vni"`
	State      string `json:"state"`
	PortName   string `json:"port_name"`
	BytesSent  uint64 `json:"bytes_sent"`
	BytesRecv  uint64 `json:"bytes_recv"`
	CreatedAt  int64  `json:"created_at"`
}

func (r *mcpTunnelListResponse) toResponse() *TunnelListResponse {
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

type mcpRemoteMACListResponse struct {
	MACs       []mcpRemoteMACEntry `json:"macs"`
	TotalCount int                 `json:"total_count"`
}

type mcpRemoteMACEntry struct {
	MAC        string `json:"mac"`
	IP         string `json:"ip"`
	VNI        uint32 `json:"vni"`
	RemoteVTEP string `json:"remote_vtep"`
	Source     string `json:"source"`
	LearnedAt  int64  `json:"learned_at"`
	ExpiresAt  int64  `json:"expires_at"`
}

func (r *mcpRemoteMACListResponse) toResponse() *RemoteMACListResponse {
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

type mcpGatewayStatusResponse struct {
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

func (r *mcpGatewayStatusResponse) toResponse() *GatewayStatusResponse {
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

type mcpBGPStatusResponse struct {
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

func (r *mcpBGPStatusResponse) toResponse() *BGPStatusResponse {
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

type mcpBGPPeerListResponse struct {
	Peers      []mcpBGPPeerEntry `json:"peers"`
	TotalCount int               `json:"total_count"`
}

type mcpBGPPeerEntry struct {
	Address      string `json:"address"`
	RemoteASN    uint32 `json:"remote_asn"`
	State        string `json:"state"`
	UptimeSec    int64  `json:"uptime_sec"`
	PrefixesRecv int    `json:"prefixes_recv"`
	PrefixesSent int    `json:"prefixes_sent"`
	Description  string `json:"description"`
	LastError    string `json:"last_error"`
}

func (r *mcpBGPPeerListResponse) toResponse() *BGPPeerListResponse {
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

type mcpIPAMPoolListResponse struct {
	Pools      []mcpIPAMPoolEntry `json:"pools"`
	TotalCount int                `json:"total_count"`
}

type mcpIPAMPoolEntry struct {
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

func (r *mcpIPAMPoolListResponse) toResponse() *IPAMPoolListResponse {
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

type mcpIPAllocationResponse struct {
	IP          string   `json:"ip"`
	PoolID      string   `json:"pool_id"`
	LeaseExpiry int64    `json:"lease_expiry"`
	Gateway     string   `json:"gateway"`
	DNS         []string `json:"dns"`
	SubnetMask  string   `json:"subnet_mask"`
}

func (r *mcpIPAllocationResponse) toResponse() *IPAllocationResponse {
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

type mcpDHCPStatusResponse struct {
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

func (r *mcpDHCPStatusResponse) toResponse() *DHCPStatusResponse {
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

type mcpDHCPLeaseListResponse struct {
	Leases     []mcpDHCPLeaseEntry `json:"leases"`
	TotalCount int                 `json:"total_count"`
}

type mcpDHCPLeaseEntry struct {
	IP          string `json:"ip"`
	MAC         string `json:"mac"`
	Hostname    string `json:"hostname"`
	State       string `json:"state"`
	LeaseStart  int64  `json:"lease_start"`
	LeaseExpiry int64  `json:"lease_expiry"`
	ClientID    string `json:"client_id"`
	PoolID      string `json:"pool_id"`
}

func (r *mcpDHCPLeaseListResponse) toResponse() *DHCPLeaseListResponse {
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

// Ensure SDNMCPAdapter implements SDNTestAdapter interface.
var _ SDNTestAdapter = (*SDNMCPAdapter)(nil)
