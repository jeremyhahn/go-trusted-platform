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
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// =============================================================================
// REST Adapter Implementation
// =============================================================================

// SDNRESTAdapter implements SDNTestAdapter using HTTP/REST calls to platformd.
type SDNRESTAdapter struct {
	baseURL    string
	httpClient *http.Client
}

// NewSDNRESTAdapter creates a new REST adapter for SDN integration testing.
func NewSDNRESTAdapter() *SDNRESTAdapter {
	endpoints := GetServiceEndpoints()
	rawEndpoint := endpoints.PlatformAPI
	// Preserve existing scheme; default to https:// for the mTLS REST endpoint.
	var baseURL string
	if strings.HasPrefix(rawEndpoint, "https://") || strings.HasPrefix(rawEndpoint, "http://") {
		baseURL = rawEndpoint
	} else {
		baseURL = "https://" + rawEndpoint
	}
	// Strip any trailing slash so path concatenation is consistent.
	baseURL = strings.TrimRight(baseURL, "/")
	return &SDNRESTAdapter{
		baseURL:    baseURL,
		httpClient: helpers.NewHTTPClient(30 * time.Second),
	}
}

// Name returns the protocol adapter identifier.
func (r *SDNRESTAdapter) Name() string {
	return "REST"
}

// Setup initializes the REST client and verifies connectivity.
func (r *SDNRESTAdapter) Setup(ctx context.Context) error {
	// Verify connectivity by checking health endpoint
	_, statusCode, err := r.doRequest(ctx, http.MethodGet, "/api/v1/sdn/health", nil)
	if err != nil {
		return ErrAdapterSetupFailed{Protocol: "REST", Err: err}
	}
	if statusCode != http.StatusOK && statusCode != http.StatusNotFound {
		return ErrAdapterSetupFailed{Protocol: "REST", Err: fmt.Errorf("health check returned status %d", statusCode)}
	}
	return nil
}

// Teardown cleans up REST client resources.
func (r *SDNRESTAdapter) Teardown() error {
	if r.httpClient != nil {
		r.httpClient.CloseIdleConnections()
	}
	return nil
}

// =============================================================================
// HTTP Request Helpers
// =============================================================================

// doRequest performs an HTTP request with JSON serialization.
func (r *SDNRESTAdapter) doRequest(ctx context.Context, method, path string, body interface{}) ([]byte, int, error) {
	var reqBody io.Reader
	if body != nil {
		jsonBytes, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to marshal request: %w", err)
		}
		reqBody = bytes.NewReader(jsonBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, r.baseURL+path, reqBody)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to read response: %w", err)
	}

	return respBody, resp.StatusCode, nil
}

// handleResponse processes the HTTP response and unmarshals into the target.
func (r *SDNRESTAdapter) handleResponse(respBody []byte, statusCode int, target interface{}) error {
	if statusCode >= 400 {
		return r.parseErrorResponse(respBody, statusCode)
	}

	if target != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, target); err != nil {
			return fmt.Errorf("failed to unmarshal response: %w", err)
		}
	}

	return nil
}

// parseErrorResponse extracts error information from error responses.
func (r *SDNRESTAdapter) parseErrorResponse(respBody []byte, statusCode int) error {
	var errResp struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}

	if err := json.Unmarshal(respBody, &errResp); err != nil {
		return fmt.Errorf("REST API error (status %d): %s", statusCode, string(respBody))
	}

	msg := errResp.Error
	if msg == "" {
		msg = errResp.Message
	}

	return fmt.Errorf("REST API error (status %d): %s", statusCode, msg)
}

// =============================================================================
// Overlay Operations
// =============================================================================

// ListVTEPs returns all discovered VTEPs via REST API.
func (r *SDNRESTAdapter) ListVTEPs(ctx context.Context) (*VTEPListResponse, error) {
	respBody, statusCode, err := r.doRequest(ctx, http.MethodGet, "/api/v1/sdn/overlay/vteps", nil)
	if err != nil {
		return nil, err
	}

	var resp restVTEPListResponse
	if err := r.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResponse(), nil
}

// CreateVNI creates a new VNI via REST API.
func (r *SDNRESTAdapter) CreateVNI(ctx context.Context, vni uint32) error {
	reqBody := map[string]interface{}{
		"vni": vni,
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, "/api/v1/sdn/overlay/vnis", reqBody)
	if err != nil {
		return err
	}

	return r.handleResponse(respBody, statusCode, nil)
}

// DeleteVNI removes a VNI via REST API.
func (r *SDNRESTAdapter) DeleteVNI(ctx context.Context, vni uint32) error {
	path := fmt.Sprintf("/api/v1/sdn/overlay/vnis/%d", vni)
	respBody, statusCode, err := r.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return err
	}

	return r.handleResponse(respBody, statusCode, nil)
}

// ListTunnels returns all active tunnels via REST API.
func (r *SDNRESTAdapter) ListTunnels(ctx context.Context) (*TunnelListResponse, error) {
	respBody, statusCode, err := r.doRequest(ctx, http.MethodGet, "/api/v1/sdn/overlay/tunnels", nil)
	if err != nil {
		return nil, err
	}

	var resp restTunnelListResponse
	if err := r.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResponse(), nil
}

// ListRemoteMACs returns all learned remote MACs for a VNI via REST API.
func (r *SDNRESTAdapter) ListRemoteMACs(ctx context.Context, vni uint32) (*RemoteMACListResponse, error) {
	params := url.Values{}
	params.Set("vni", strconv.FormatUint(uint64(vni), 10))

	path := "/api/v1/sdn/overlay/macs?" + params.Encode()
	respBody, statusCode, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp restRemoteMACListResponse
	if err := r.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResponse(), nil
}

// =============================================================================
// Gateway Operations
// =============================================================================

// GetGatewayStatus returns the gateway status via REST API.
func (r *SDNRESTAdapter) GetGatewayStatus(ctx context.Context) (*GatewayStatusResponse, error) {
	respBody, statusCode, err := r.doRequest(ctx, http.MethodGet, "/api/v1/sdn/gateway/status", nil)
	if err != nil {
		return nil, err
	}

	var resp restGatewayStatusResponse
	if err := r.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResponse(), nil
}

// SetGatewayMode sets the gateway mode via REST API.
func (r *SDNRESTAdapter) SetGatewayMode(ctx context.Context, mode GatewayMode) error {
	reqBody := map[string]interface{}{
		"mode": mode.String(),
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPut, "/api/v1/sdn/gateway/mode", reqBody)
	if err != nil {
		return err
	}

	return r.handleResponse(respBody, statusCode, nil)
}

// =============================================================================
// BGP Operations
// =============================================================================

// GetBGPStatus returns the BGP status via REST API.
func (r *SDNRESTAdapter) GetBGPStatus(ctx context.Context) (*BGPStatusResponse, error) {
	respBody, statusCode, err := r.doRequest(ctx, http.MethodGet, "/api/v1/sdn/gateway/bgp/status", nil)
	if err != nil {
		return nil, err
	}

	var resp restBGPStatusResponse
	if err := r.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResponse(), nil
}

// ListBGPPeers returns all BGP peers via REST API.
func (r *SDNRESTAdapter) ListBGPPeers(ctx context.Context) (*BGPPeerListResponse, error) {
	respBody, statusCode, err := r.doRequest(ctx, http.MethodGet, "/api/v1/sdn/gateway/bgp/peers", nil)
	if err != nil {
		return nil, err
	}

	var resp restBGPPeerListResponse
	if err := r.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResponse(), nil
}

// AnnouncePrefix announces a BGP prefix via REST API.
func (r *SDNRESTAdapter) AnnouncePrefix(ctx context.Context, prefix string) error {
	reqBody := map[string]interface{}{
		"prefix": prefix,
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, "/api/v1/sdn/gateway/bgp/announce", reqBody)
	if err != nil {
		return err
	}

	return r.handleResponse(respBody, statusCode, nil)
}

// WithdrawPrefix withdraws a BGP prefix via REST API.
func (r *SDNRESTAdapter) WithdrawPrefix(ctx context.Context, prefix string) error {
	reqBody := map[string]interface{}{
		"prefix": prefix,
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, "/api/v1/sdn/gateway/bgp/withdraw", reqBody)
	if err != nil {
		return err
	}

	return r.handleResponse(respBody, statusCode, nil)
}

// =============================================================================
// IPAM Operations
// =============================================================================

// CreatePool creates a new IPAM pool via REST API.
func (r *SDNRESTAdapter) CreatePool(ctx context.Context, req IPAMPoolCreateRequest) (*IPAMPoolEntry, error) {
	body := map[string]interface{}{
		"name": req.Name,
		"cidr": req.CIDR,
	}
	if req.ID != "" {
		body["id"] = req.ID
	}
	if req.Gateway != "" {
		body["gateway"] = req.Gateway
	}
	if req.Zone != "" {
		body["zone"] = req.Zone
	}
	if req.Description != "" {
		body["description"] = req.Description
	}
	if req.LeaseDuration > 0 {
		body["default_lease_duration_nanos"] = req.LeaseDuration.Nanoseconds()
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, "/api/v1/sdn/gateway/ipam/pools", body)
	if err != nil {
		return nil, err
	}

	var resp restIPAMPoolEntry
	if err := r.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toEntry(), nil
}

// GetPool retrieves an IPAM pool by ID via REST API.
func (r *SDNRESTAdapter) GetPool(ctx context.Context, poolID string) (*IPAMPoolEntry, error) {
	respBody, statusCode, err := r.doRequest(ctx, http.MethodGet, "/api/v1/sdn/gateway/ipam/pools/"+poolID, nil)
	if err != nil {
		return nil, err
	}

	var resp restIPAMPoolEntry
	if err := r.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toEntry(), nil
}

// UpdatePool updates mutable fields of an IPAM pool via REST API.
func (r *SDNRESTAdapter) UpdatePool(ctx context.Context, poolID string, req IPAMPoolUpdateRequest) (*IPAMPoolEntry, error) {
	body := map[string]interface{}{}
	if req.Name != "" {
		body["name"] = req.Name
	}
	if req.Gateway != "" {
		body["gateway"] = req.Gateway
	}
	if req.Zone != "" {
		body["zone"] = req.Zone
	}
	if req.Description != "" {
		body["description"] = req.Description
	}
	if req.LeaseDuration > 0 {
		body["default_lease_duration_nanos"] = req.LeaseDuration.Nanoseconds()
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPut, "/api/v1/sdn/gateway/ipam/pools/"+poolID, body)
	if err != nil {
		return nil, err
	}

	var resp restIPAMPoolEntry
	if err := r.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toEntry(), nil
}

// DeletePool removes an IPAM pool by ID via REST API.
func (r *SDNRESTAdapter) DeletePool(ctx context.Context, poolID string) error {
	respBody, statusCode, err := r.doRequest(ctx, http.MethodDelete, "/api/v1/sdn/gateway/ipam/pools/"+poolID, nil)
	if err != nil {
		return err
	}
	return r.handleResponse(respBody, statusCode, nil)
}

// ListPools returns all IPAM pools, optionally filtered by zone, via REST API.
func (r *SDNRESTAdapter) ListPools(ctx context.Context, zone string) (*IPAMPoolListResponse, error) {
	path := "/api/v1/sdn/gateway/ipam/pools"
	if zone != "" {
		path += "?zone=" + zone
	}
	respBody, statusCode, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp restIPAMPoolListResponse
	if err := r.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResponse(), nil
}

// AllocateIP allocates an IP from a pool via REST API.
func (r *SDNRESTAdapter) AllocateIP(ctx context.Context, poolID string) (*IPAllocationResponse, error) {
	reqBody := map[string]interface{}{
		"pool_id": poolID,
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, "/api/v1/sdn/ipam/allocate", reqBody)
	if err != nil {
		return nil, err
	}

	var resp restIPAllocationResponse
	if err := r.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResponse(), nil
}

// ReleaseIP releases an allocated IP via REST API.
func (r *SDNRESTAdapter) ReleaseIP(ctx context.Context, poolID, ip string) error {
	reqBody := map[string]interface{}{
		"pool_id": poolID,
		"ip":      ip,
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, "/api/v1/sdn/ipam/release", reqBody)
	if err != nil {
		return err
	}

	return r.handleResponse(respBody, statusCode, nil)
}

// =============================================================================
// DHCP Operations
// =============================================================================

// GetDHCPStatus returns the DHCP server status via REST API.
func (r *SDNRESTAdapter) GetDHCPStatus(ctx context.Context) (*DHCPStatusResponse, error) {
	respBody, statusCode, err := r.doRequest(ctx, http.MethodGet, "/api/v1/sdn/dhcp/status", nil)
	if err != nil {
		return nil, err
	}

	var resp restDHCPStatusResponse
	if err := r.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResponse(), nil
}

// ListLeases returns all DHCP leases via REST API.
func (r *SDNRESTAdapter) ListLeases(ctx context.Context) (*DHCPLeaseListResponse, error) {
	respBody, statusCode, err := r.doRequest(ctx, http.MethodGet, "/api/v1/sdn/dhcp/leases", nil)
	if err != nil {
		return nil, err
	}

	var resp restDHCPLeaseListResponse
	if err := r.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResponse(), nil
}

// =============================================================================
// REST Response Types and Conversion
// =============================================================================

type restVTEPListResponse struct {
	VTEPs      []restVTEPEntry `json:"vteps"`
	TotalCount int             `json:"total_count"`
}

type restVTEPEntry struct {
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

func (r *restVTEPListResponse) toResponse() *VTEPListResponse {
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

type restTunnelListResponse struct {
	Tunnels    []restTunnelEntry `json:"tunnels"`
	TotalCount int               `json:"total_count"`
}

type restTunnelEntry struct {
	LocalVTEP  string `json:"local_vtep"`
	RemoteVTEP string `json:"remote_vtep"`
	VNI        uint32 `json:"vni"`
	State      string `json:"state"`
	PortName   string `json:"port_name"`
	BytesSent  uint64 `json:"bytes_sent"`
	BytesRecv  uint64 `json:"bytes_recv"`
	CreatedAt  int64  `json:"created_at"`
}

func (r *restTunnelListResponse) toResponse() *TunnelListResponse {
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

type restRemoteMACListResponse struct {
	MACs       []restRemoteMACEntry `json:"macs"`
	TotalCount int                  `json:"total_count"`
}

type restRemoteMACEntry struct {
	MAC        string `json:"mac"`
	IP         string `json:"ip"`
	VNI        uint32 `json:"vni"`
	RemoteVTEP string `json:"remote_vtep"`
	Source     string `json:"source"`
	LearnedAt  int64  `json:"learned_at"`
	ExpiresAt  int64  `json:"expires_at"`
}

func (r *restRemoteMACListResponse) toResponse() *RemoteMACListResponse {
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

type restGatewayStatusResponse struct {
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

func (r *restGatewayStatusResponse) toResponse() *GatewayStatusResponse {
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

type restBGPStatusResponse struct {
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

func (r *restBGPStatusResponse) toResponse() *BGPStatusResponse {
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

type restBGPPeerListResponse struct {
	Peers      []restBGPPeerEntry `json:"peers"`
	TotalCount int                `json:"total_count"`
}

type restBGPPeerEntry struct {
	Address      string `json:"address"`
	RemoteASN    uint32 `json:"remote_asn"`
	State        string `json:"state"`
	UptimeSec    int64  `json:"uptime_sec"`
	PrefixesRecv int    `json:"prefixes_recv"`
	PrefixesSent int    `json:"prefixes_sent"`
	Description  string `json:"description"`
	LastError    string `json:"last_error"`
}

func (r *restBGPPeerListResponse) toResponse() *BGPPeerListResponse {
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

type restIPAMPoolListResponse struct {
	Pools      []restIPAMPoolEntry `json:"pools"`
	TotalCount int                 `json:"total_count"`
}

type restIPAMPoolEntry struct {
	ID                        string   `json:"id"`
	Name                      string   `json:"name"`
	CIDR                      string   `json:"cidr"`
	Gateway                   string   `json:"gateway"`
	Zone                      string   `json:"zone"`
	Description               string   `json:"description"`
	TotalIPs                  int64    `json:"total_ips"`
	AllocatedIPs              int64    `json:"allocated_ips"`
	AvailableIPs              int64    `json:"available_ips"`
	UtilizationPct            float64  `json:"utilization_pct"`
	DNS                       []string `json:"dns"`
	LeaseDurationSec          int64    `json:"lease_duration_sec"`
	DefaultLeaseDurationNanos int64    `json:"default_lease_duration_nanos"`
}

func (e *restIPAMPoolEntry) toEntry() *IPAMPoolEntry {
	leaseDur := time.Duration(e.LeaseDurationSec) * time.Second
	if leaseDur == 0 && e.DefaultLeaseDurationNanos > 0 {
		leaseDur = time.Duration(e.DefaultLeaseDurationNanos)
	}
	return &IPAMPoolEntry{
		ID:             e.ID,
		Name:           e.Name,
		CIDR:           e.CIDR,
		Gateway:        e.Gateway,
		Zone:           e.Zone,
		Description:    e.Description,
		TotalIPs:       e.TotalIPs,
		AllocatedIPs:   e.AllocatedIPs,
		AvailableIPs:   e.AvailableIPs,
		UtilizationPct: e.UtilizationPct,
		DNS:            e.DNS,
		LeaseDuration:  leaseDur,
	}
}

func (r *restIPAMPoolListResponse) toResponse() *IPAMPoolListResponse {
	pools := make([]IPAMPoolEntry, 0, len(r.Pools))
	for _, p := range r.Pools {
		pools = append(pools, *p.toEntry())
	}
	return &IPAMPoolListResponse{
		Pools:      pools,
		TotalCount: r.TotalCount,
	}
}

type restIPAllocationResponse struct {
	IP          string   `json:"ip"`
	PoolID      string   `json:"pool_id"`
	LeaseExpiry int64    `json:"lease_expiry"`
	Gateway     string   `json:"gateway"`
	DNS         []string `json:"dns"`
	SubnetMask  string   `json:"subnet_mask"`
}

func (r *restIPAllocationResponse) toResponse() *IPAllocationResponse {
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

type restDHCPStatusResponse struct {
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

func (r *restDHCPStatusResponse) toResponse() *DHCPStatusResponse {
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

type restDHCPLeaseListResponse struct {
	Leases     []restDHCPLeaseEntry `json:"leases"`
	TotalCount int                  `json:"total_count"`
}

type restDHCPLeaseEntry struct {
	IP          string `json:"ip"`
	MAC         string `json:"mac"`
	Hostname    string `json:"hostname"`
	State       string `json:"state"`
	LeaseStart  int64  `json:"lease_start"`
	LeaseExpiry int64  `json:"lease_expiry"`
	ClientID    string `json:"client_id"`
	PoolID      string `json:"pool_id"`
}

func (r *restDHCPLeaseListResponse) toResponse() *DHCPLeaseListResponse {
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

// =============================================================================
// Network Zone Operations
// =============================================================================

// jsonZonePath mirrors gateway.ZonePathSpec.
type jsonZonePath struct {
	Zone     string   `json:"zone"`
	Services []string `json:"services,omitempty"`
}

// jsonPrivilegedAccess mirrors gateway.PrivilegedAccessSpec.
type jsonPrivilegedAccess struct {
	Reason     string `json:"reason"`
	ApprovedBy string `json:"approved_by"`
}

// jsonZoneSpec mirrors gateway.ZoneSpec, the zone body the REST and MCP
// transports share.
type jsonZoneSpec struct {
	Name             string                `json:"name,omitempty"`
	Offset           uint8                 `json:"offset,omitempty"`
	PortClasses      []string              `json:"port_classes,omitempty"`
	InternetIngress  bool                  `json:"internet_ingress,omitempty"`
	IsolateFrom      []string              `json:"isolate_from,omitempty"`
	AllowTo          []jsonZonePath        `json:"allow_to,omitempty"`
	Services         []string              `json:"services,omitempty"`
	Isolate          bool                  `json:"isolate,omitempty"`
	OOB              bool                  `json:"oob,omitempty"`
	LifecycleRole    string                `json:"lifecycle_role,omitempty"`
	PrivilegedAccess *jsonPrivilegedAccess `json:"privileged_access,omitempty"`
}

// jsonZoneView mirrors gateway.ZoneView, the zone response the REST and MCP
// transports share.
type jsonZoneView struct {
	jsonZoneSpec
	Numbering *struct {
		VLAN uint16 `json:"vlan"`
	} `json:"numbering,omitempty"`
	RestartRequired bool      `json:"restart_required,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// newJSONZoneSpec builds the shared zone body from a spec.
func newJSONZoneSpec(name string, spec ZoneSpec) jsonZoneSpec {
	out := jsonZoneSpec{
		Name:            name,
		Offset:          spec.Offset,
		PortClasses:     spec.PortClasses,
		InternetIngress: spec.InternetIngress,
		Services:        spec.Services,
		Isolate:         spec.Isolate,
		OOB:             spec.OOB,
		LifecycleRole:   spec.LifecycleRole,
	}
	for _, p := range spec.AllowTo {
		out.AllowTo = append(out.AllowTo, jsonZonePath{Zone: p.Zone, Services: p.Services})
	}
	if spec.PrivilegedReason != "" || spec.PrivilegedApprovedBy != "" {
		out.PrivilegedAccess = &jsonPrivilegedAccess{Reason: spec.PrivilegedReason, ApprovedBy: spec.PrivilegedApprovedBy}
	}
	return out
}

// toEntry converts the shared zone response to a ZoneEntry.
func (v *jsonZoneView) toEntry() *ZoneEntry {
	e := &ZoneEntry{
		Name:            v.Name,
		Offset:          v.Offset,
		PortClasses:     v.PortClasses,
		InternetIngress: v.InternetIngress,
		Isolate:         v.Isolate,
		OOB:             v.OOB,
		LifecycleRole:   v.LifecycleRole,
		Services:        v.Services,
		RestartRequired: v.RestartRequired,
		CreatedAt:       v.CreatedAt,
		UpdatedAt:       v.UpdatedAt,
	}
	for _, p := range v.AllowTo {
		e.AllowTo = append(e.AllowTo, ZonePathEntry{Zone: p.Zone, Services: p.Services})
	}
	if v.PrivilegedAccess != nil {
		e.PrivilegedApprovedBy = v.PrivilegedAccess.ApprovedBy
	}
	if v.Numbering != nil {
		e.VLAN = v.Numbering.VLAN
	}
	return e
}

// restZoneListResponse mirrors the server's NetworkZoneListResponse.
type restZoneListResponse struct {
	Zones []jsonZoneView `json:"zones"`
	Count int            `json:"count"`
}

// restZoneDeleteResponse mirrors the server's delete response body.
type restZoneDeleteResponse struct {
	Deleted         bool `json:"deleted"`
	RestartRequired bool `json:"restart_required"`
}

// CreateZone creates an owner-defined zone via REST POST /api/v1/sdn/zones.
func (s *SDNRESTAdapter) CreateZone(ctx context.Context, req ZoneCreateRequest) (*ZoneEntry, error) {
	respBody, statusCode, err := s.doRequest(ctx, http.MethodPost, "/api/v1/sdn/zones", newJSONZoneSpec(req.Name, req.ZoneSpec))
	if err != nil {
		return nil, err
	}
	var resp jsonZoneView
	if err := s.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}
	return resp.toEntry(), nil
}

// UpdateZone tunes or replaces a zone via REST PUT /api/v1/sdn/zones/{name}.
func (s *SDNRESTAdapter) UpdateZone(ctx context.Context, name string, req ZoneUpdateRequest) (*ZoneEntry, error) {
	respBody, statusCode, err := s.doRequest(ctx, http.MethodPut, "/api/v1/sdn/zones/"+url.PathEscape(name), newJSONZoneSpec("", req.ZoneSpec))
	if err != nil {
		return nil, err
	}
	var resp jsonZoneView
	if err := s.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}
	return resp.toEntry(), nil
}

// DeleteZone deletes a zone via REST DELETE /api/v1/sdn/zones/{name}.
func (s *SDNRESTAdapter) DeleteZone(ctx context.Context, name string) (bool, error) {
	respBody, statusCode, err := s.doRequest(ctx, http.MethodDelete, "/api/v1/sdn/zones/"+url.PathEscape(name), nil)
	if err != nil {
		return false, err
	}
	var resp restZoneDeleteResponse
	if err := s.handleResponse(respBody, statusCode, &resp); err != nil {
		return false, err
	}
	return resp.RestartRequired, nil
}

// ListZones returns the zones via REST GET /api/v1/sdn/zones.
func (s *SDNRESTAdapter) ListZones(ctx context.Context, lifecycleRole string) (*ZoneListResponse, error) {
	path := "/api/v1/sdn/zones"
	if lifecycleRole != "" {
		path += "?lifecycle_role=" + url.QueryEscape(lifecycleRole)
	}
	respBody, statusCode, err := s.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	var resp restZoneListResponse
	if err := s.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}
	zones := make([]ZoneEntry, 0, len(resp.Zones))
	for _, z := range resp.Zones {
		zones = append(zones, *z.toEntry())
	}
	return &ZoneListResponse{Zones: zones, TotalCount: resp.Count}, nil
}

// Ensure SDNRESTAdapter implements SDNTestAdapter interface.
var _ SDNTestAdapter = (*SDNRESTAdapter)(nil)
