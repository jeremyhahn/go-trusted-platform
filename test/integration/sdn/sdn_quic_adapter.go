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
	"net/url"
	"strconv"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// =============================================================================
// QUIC Adapter Implementation
// =============================================================================

// SDNQUICAdapter implements SDNTestAdapter using HTTP/3 over QUIC transport.
type SDNQUICAdapter struct {
	baseURL    string
	httpClient *http.Client
	transport  *http3.Transport
}

// NewSDNQUICAdapter creates a new QUIC adapter for SDN integration testing.
func NewSDNQUICAdapter() *SDNQUICAdapter {
	return &SDNQUICAdapter{}
}

// Name returns the protocol adapter identifier.
func (q *SDNQUICAdapter) Name() string {
	return "QUIC"
}

// Setup initializes the QUIC/HTTP3 client.
func (q *SDNQUICAdapter) Setup(ctx context.Context) error {
	endpoints := GetServiceEndpoints()
	q.baseURL = "https://" + endpoints.PlatformQUIC

	// Configure QUIC transport with TLS (supports mTLS when env vars are set)
	tlsConf := helpers.QUICTLSConfig([]string{"h3"})

	quicConf := &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 15 * time.Second,
	}

	q.transport = &http3.Transport{
		TLSClientConfig: tlsConf,
		QUICConfig:      quicConf,
	}

	q.httpClient = &http.Client{
		Transport: q.transport,
		Timeout:   30 * time.Second,
	}

	return nil
}

// Teardown closes the QUIC transport.
func (q *SDNQUICAdapter) Teardown() error {
	if q.transport != nil {
		if err := q.transport.Close(); err != nil {
			return fmt.Errorf("failed to close QUIC transport: %w", err)
		}
	}
	return nil
}

// =============================================================================
// HTTP Request Helpers
// =============================================================================

// doRequest performs an HTTP/3 request with JSON serialization.
func (q *SDNQUICAdapter) doRequest(ctx context.Context, method, path string, body interface{}) ([]byte, int, error) {
	var reqBody io.Reader
	if body != nil {
		jsonBytes, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to marshal request: %w", err)
		}
		reqBody = bytes.NewReader(jsonBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, q.baseURL+path, reqBody)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := q.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("QUIC request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to read response: %w", err)
	}

	return respBody, resp.StatusCode, nil
}

// handleResponse processes the HTTP response and unmarshals into the target.
func (q *SDNQUICAdapter) handleResponse(respBody []byte, statusCode int, target interface{}) error {
	if statusCode >= 400 {
		return fmt.Errorf("QUIC API error (status %d): %s", statusCode, string(respBody))
	}

	if target != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, target); err != nil {
			return fmt.Errorf("failed to unmarshal response: %w", err)
		}
	}

	return nil
}

// =============================================================================
// Overlay Operations
// =============================================================================

// ListVTEPs returns all discovered VTEPs via QUIC.
func (q *SDNQUICAdapter) ListVTEPs(ctx context.Context) (*VTEPListResponse, error) {
	respBody, statusCode, err := q.doRequest(ctx, http.MethodGet, "/api/v1/sdn/overlay/vteps", nil)
	if err != nil {
		return nil, err
	}

	var resp quicVTEPListResponse
	if err := q.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResponse(), nil
}

// CreateVNI creates a new VNI via QUIC.
func (q *SDNQUICAdapter) CreateVNI(ctx context.Context, vni uint32) error {
	reqBody := map[string]interface{}{
		"vni": vni,
	}

	respBody, statusCode, err := q.doRequest(ctx, http.MethodPost, "/api/v1/sdn/overlay/vnis", reqBody)
	if err != nil {
		return err
	}

	return q.handleResponse(respBody, statusCode, nil)
}

// DeleteVNI removes a VNI via QUIC.
func (q *SDNQUICAdapter) DeleteVNI(ctx context.Context, vni uint32) error {
	path := fmt.Sprintf("/api/v1/sdn/overlay/vnis/%d", vni)
	respBody, statusCode, err := q.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return err
	}

	return q.handleResponse(respBody, statusCode, nil)
}

// ListTunnels returns all active tunnels via QUIC.
func (q *SDNQUICAdapter) ListTunnels(ctx context.Context) (*TunnelListResponse, error) {
	respBody, statusCode, err := q.doRequest(ctx, http.MethodGet, "/api/v1/sdn/overlay/tunnels", nil)
	if err != nil {
		return nil, err
	}

	var resp quicTunnelListResponse
	if err := q.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResponse(), nil
}

// ListRemoteMACs returns all learned remote MACs for a VNI via QUIC.
func (q *SDNQUICAdapter) ListRemoteMACs(ctx context.Context, vni uint32) (*RemoteMACListResponse, error) {
	params := url.Values{}
	params.Set("vni", strconv.FormatUint(uint64(vni), 10))

	path := "/api/v1/sdn/overlay/macs?" + params.Encode()
	respBody, statusCode, err := q.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp quicRemoteMACListResponse
	if err := q.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResponse(), nil
}

// =============================================================================
// Gateway Operations
// =============================================================================

// GetGatewayStatus returns the gateway status via QUIC.
func (q *SDNQUICAdapter) GetGatewayStatus(ctx context.Context) (*GatewayStatusResponse, error) {
	respBody, statusCode, err := q.doRequest(ctx, http.MethodGet, "/api/v1/sdn/gateway/status", nil)
	if err != nil {
		return nil, err
	}

	var resp quicGatewayStatusResponse
	if err := q.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResponse(), nil
}

// SetGatewayMode sets the gateway mode via QUIC.
func (q *SDNQUICAdapter) SetGatewayMode(ctx context.Context, mode GatewayMode) error {
	reqBody := map[string]interface{}{
		"mode": mode.String(),
	}

	respBody, statusCode, err := q.doRequest(ctx, http.MethodPut, "/api/v1/sdn/gateway/mode", reqBody)
	if err != nil {
		return err
	}

	return q.handleResponse(respBody, statusCode, nil)
}

// =============================================================================
// BGP Operations
// =============================================================================

// GetBGPStatus returns the BGP status via QUIC.
func (q *SDNQUICAdapter) GetBGPStatus(ctx context.Context) (*BGPStatusResponse, error) {
	respBody, statusCode, err := q.doRequest(ctx, http.MethodGet, "/api/v1/sdn/gateway/bgp/status", nil)
	if err != nil {
		return nil, err
	}

	var resp quicBGPStatusResponse
	if err := q.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResponse(), nil
}

// ListBGPPeers returns all BGP peers via QUIC.
func (q *SDNQUICAdapter) ListBGPPeers(ctx context.Context) (*BGPPeerListResponse, error) {
	respBody, statusCode, err := q.doRequest(ctx, http.MethodGet, "/api/v1/sdn/gateway/bgp/peers", nil)
	if err != nil {
		return nil, err
	}

	var resp quicBGPPeerListResponse
	if err := q.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResponse(), nil
}

// AnnouncePrefix announces a BGP prefix via QUIC.
func (q *SDNQUICAdapter) AnnouncePrefix(ctx context.Context, prefix string) error {
	reqBody := map[string]interface{}{
		"prefix": prefix,
	}

	respBody, statusCode, err := q.doRequest(ctx, http.MethodPost, "/api/v1/sdn/gateway/bgp/announce", reqBody)
	if err != nil {
		return err
	}

	return q.handleResponse(respBody, statusCode, nil)
}

// WithdrawPrefix withdraws a BGP prefix via QUIC.
func (q *SDNQUICAdapter) WithdrawPrefix(ctx context.Context, prefix string) error {
	reqBody := map[string]interface{}{
		"prefix": prefix,
	}

	respBody, statusCode, err := q.doRequest(ctx, http.MethodPost, "/api/v1/sdn/gateway/bgp/withdraw", reqBody)
	if err != nil {
		return err
	}

	return q.handleResponse(respBody, statusCode, nil)
}

// =============================================================================
// IPAM Operations
// =============================================================================

// ListPools returns all IPAM pools via QUIC.
func (q *SDNQUICAdapter) ListPools(ctx context.Context) (*IPAMPoolListResponse, error) {
	respBody, statusCode, err := q.doRequest(ctx, http.MethodGet, "/api/v1/sdn/ipam/pools", nil)
	if err != nil {
		return nil, err
	}

	var resp quicIPAMPoolListResponse
	if err := q.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResponse(), nil
}

// AllocateIP allocates an IP from a pool via QUIC.
func (q *SDNQUICAdapter) AllocateIP(ctx context.Context, poolID string) (*IPAllocationResponse, error) {
	reqBody := map[string]interface{}{
		"pool_id": poolID,
	}

	respBody, statusCode, err := q.doRequest(ctx, http.MethodPost, "/api/v1/sdn/ipam/allocate", reqBody)
	if err != nil {
		return nil, err
	}

	var resp quicIPAllocationResponse
	if err := q.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResponse(), nil
}

// ReleaseIP releases an allocated IP via QUIC.
func (q *SDNQUICAdapter) ReleaseIP(ctx context.Context, poolID, ip string) error {
	reqBody := map[string]interface{}{
		"pool_id": poolID,
		"ip":      ip,
	}

	respBody, statusCode, err := q.doRequest(ctx, http.MethodPost, "/api/v1/sdn/ipam/release", reqBody)
	if err != nil {
		return err
	}

	return q.handleResponse(respBody, statusCode, nil)
}

// =============================================================================
// DHCP Operations
// =============================================================================

// GetDHCPStatus returns the DHCP server status via QUIC.
func (q *SDNQUICAdapter) GetDHCPStatus(ctx context.Context) (*DHCPStatusResponse, error) {
	respBody, statusCode, err := q.doRequest(ctx, http.MethodGet, "/api/v1/sdn/dhcp/status", nil)
	if err != nil {
		return nil, err
	}

	var resp quicDHCPStatusResponse
	if err := q.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResponse(), nil
}

// ListLeases returns all DHCP leases via QUIC.
func (q *SDNQUICAdapter) ListLeases(ctx context.Context) (*DHCPLeaseListResponse, error) {
	respBody, statusCode, err := q.doRequest(ctx, http.MethodGet, "/api/v1/sdn/dhcp/leases", nil)
	if err != nil {
		return nil, err
	}

	var resp quicDHCPLeaseListResponse
	if err := q.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResponse(), nil
}

// =============================================================================
// QUIC Response Types (reuse structures similar to REST)
// =============================================================================

type quicVTEPListResponse struct {
	VTEPs      []quicVTEPEntry `json:"vteps"`
	TotalCount int             `json:"total_count"`
}

type quicVTEPEntry struct {
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

func (r *quicVTEPListResponse) toResponse() *VTEPListResponse {
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

type quicTunnelListResponse struct {
	Tunnels    []quicTunnelEntry `json:"tunnels"`
	TotalCount int               `json:"total_count"`
}

type quicTunnelEntry struct {
	LocalVTEP  string `json:"local_vtep"`
	RemoteVTEP string `json:"remote_vtep"`
	VNI        uint32 `json:"vni"`
	State      string `json:"state"`
	PortName   string `json:"port_name"`
	BytesSent  uint64 `json:"bytes_sent"`
	BytesRecv  uint64 `json:"bytes_recv"`
	CreatedAt  int64  `json:"created_at"`
}

func (r *quicTunnelListResponse) toResponse() *TunnelListResponse {
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

type quicRemoteMACListResponse struct {
	MACs       []quicRemoteMACEntry `json:"macs"`
	TotalCount int                  `json:"total_count"`
}

type quicRemoteMACEntry struct {
	MAC        string `json:"mac"`
	IP         string `json:"ip"`
	VNI        uint32 `json:"vni"`
	RemoteVTEP string `json:"remote_vtep"`
	Source     string `json:"source"`
	LearnedAt  int64  `json:"learned_at"`
	ExpiresAt  int64  `json:"expires_at"`
}

func (r *quicRemoteMACListResponse) toResponse() *RemoteMACListResponse {
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

type quicGatewayStatusResponse struct {
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

func (r *quicGatewayStatusResponse) toResponse() *GatewayStatusResponse {
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

type quicBGPStatusResponse struct {
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

func (r *quicBGPStatusResponse) toResponse() *BGPStatusResponse {
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

type quicBGPPeerListResponse struct {
	Peers      []quicBGPPeerEntry `json:"peers"`
	TotalCount int                `json:"total_count"`
}

type quicBGPPeerEntry struct {
	Address      string `json:"address"`
	RemoteASN    uint32 `json:"remote_asn"`
	State        string `json:"state"`
	UptimeSec    int64  `json:"uptime_sec"`
	PrefixesRecv int    `json:"prefixes_recv"`
	PrefixesSent int    `json:"prefixes_sent"`
	Description  string `json:"description"`
	LastError    string `json:"last_error"`
}

func (r *quicBGPPeerListResponse) toResponse() *BGPPeerListResponse {
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

type quicIPAMPoolListResponse struct {
	Pools      []quicIPAMPoolEntry `json:"pools"`
	TotalCount int                 `json:"total_count"`
}

type quicIPAMPoolEntry struct {
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

func (r *quicIPAMPoolListResponse) toResponse() *IPAMPoolListResponse {
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

type quicIPAllocationResponse struct {
	IP          string   `json:"ip"`
	PoolID      string   `json:"pool_id"`
	LeaseExpiry int64    `json:"lease_expiry"`
	Gateway     string   `json:"gateway"`
	DNS         []string `json:"dns"`
	SubnetMask  string   `json:"subnet_mask"`
}

func (r *quicIPAllocationResponse) toResponse() *IPAllocationResponse {
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

type quicDHCPStatusResponse struct {
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

func (r *quicDHCPStatusResponse) toResponse() *DHCPStatusResponse {
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

type quicDHCPLeaseListResponse struct {
	Leases     []quicDHCPLeaseEntry `json:"leases"`
	TotalCount int                  `json:"total_count"`
}

type quicDHCPLeaseEntry struct {
	IP          string `json:"ip"`
	MAC         string `json:"mac"`
	Hostname    string `json:"hostname"`
	State       string `json:"state"`
	LeaseStart  int64  `json:"lease_start"`
	LeaseExpiry int64  `json:"lease_expiry"`
	ClientID    string `json:"client_id"`
	PoolID      string `json:"pool_id"`
}

func (r *quicDHCPLeaseListResponse) toResponse() *DHCPLeaseListResponse {
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

// Ensure SDNQUICAdapter implements SDNTestAdapter interface.
var _ SDNTestAdapter = (*SDNQUICAdapter)(nil)
