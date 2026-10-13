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
	"os"
	"strconv"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// =============================================================================
// Error Types
// =============================================================================

// ErrOverlayRESTRequestFailed indicates a REST request failure.
type ErrOverlayRESTRequestFailed struct {
	Method     string
	URL        string
	StatusCode int
	Body       string
}

func (e ErrOverlayRESTRequestFailed) Error() string {
	return fmt.Sprintf("overlay REST request failed: %s %s returned status %d: %s",
		e.Method, e.URL, e.StatusCode, e.Body)
}

// ErrOverlayRESTConnectionFailed indicates a connection failure.
type ErrOverlayRESTConnectionFailed struct {
	Endpoint string
	Err      error
}

func (e ErrOverlayRESTConnectionFailed) Error() string {
	return fmt.Sprintf("overlay REST connection to %s failed: %v", e.Endpoint, e.Err)
}

func (e ErrOverlayRESTConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrOverlayRESTDecodeFailed indicates a JSON decoding failure.
type ErrOverlayRESTDecodeFailed struct {
	Operation string
	Err       error
}

func (e ErrOverlayRESTDecodeFailed) Error() string {
	return fmt.Sprintf("overlay REST decode failed for %s: %v", e.Operation, e.Err)
}

func (e ErrOverlayRESTDecodeFailed) Unwrap() error {
	return e.Err
}

// =============================================================================
// REST Adapter
// =============================================================================

// OverlayRESTAdapter implements OverlayCommands using REST API calls.
type OverlayRESTAdapter struct {
	baseURL   string
	client    *http.Client
	authToken string
}

// NewOverlayRESTAdapter creates a new REST adapter with default settings.
func NewOverlayRESTAdapter() *OverlayRESTAdapter {
	endpoint := os.Getenv("PLATFORM_API_ENDPOINT")
	if endpoint == "" {
		endpoint = GetServiceEndpoints().PlatformAPI
	}

	return &OverlayRESTAdapter{
		baseURL: endpoint,
		client:  helpers.NewHTTPClient(60 * time.Second),
	}
}

// Name returns the protocol adapter identifier.
func (r *OverlayRESTAdapter) Name() string {
	return "REST"
}

// Setup verifies connectivity to the REST API.
func (r *OverlayRESTAdapter) Setup(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.baseURL+"/health", nil)
	if err != nil {
		return ErrOverlayRESTConnectionFailed{Endpoint: r.baseURL, Err: err}
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return ErrOverlayRESTConnectionFailed{Endpoint: r.baseURL, Err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return ErrOverlayRESTRequestFailed{
			Method:     http.MethodGet,
			URL:        r.baseURL + "/health",
			StatusCode: resp.StatusCode,
			Body:       string(body),
		}
	}

	return nil
}

// Teardown performs any cleanup (none needed for REST).
func (r *OverlayRESTAdapter) Teardown() error {
	return nil
}

// =============================================================================
// Internal Helpers
// =============================================================================

// doRequest performs an HTTP request and returns the response body.
func (r *OverlayRESTAdapter) doRequest(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, r.baseURL+path, reqBody)
	if err != nil {
		return nil, ErrOverlayRESTConnectionFailed{Endpoint: r.baseURL, Err: err}
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if r.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+r.authToken)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, ErrOverlayRESTConnectionFailed{Endpoint: r.baseURL, Err: err}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, ErrOverlayRESTRequestFailed{
			Method:     method,
			URL:        r.baseURL + path,
			StatusCode: resp.StatusCode,
			Body:       string(respBody),
		}
	}

	return respBody, nil
}

// =============================================================================
// Overlay Status
// =============================================================================

// OverlayStatus retrieves overlay network status via REST API.
func (r *OverlayRESTAdapter) OverlayStatus(ctx context.Context) (*OverlayStatusResult, error) {
	respBody, err := r.doRequest(ctx, http.MethodGet, "/api/v1/sdn/overlay/status", nil)
	if err != nil {
		return nil, err
	}

	var result struct {
		NodeID         string `json:"node_id"`
		VTEPIP         string `json:"vtep_ip"`
		VTEPCount      uint32 `json:"vtep_count"`
		VNICount       uint32 `json:"vni_count"`
		TunnelCount    uint32 `json:"tunnel_count"`
		RemoteMACCount uint32 `json:"remote_mac_count"`
		Healthy        bool   `json:"healthy"`
		UnderlayMTU    int    `json:"underlay_mtu"`
		VXLANPort      uint16 `json:"vxlan_port"`
		Uptime         int64  `json:"uptime_seconds"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, ErrOverlayRESTDecodeFailed{Operation: "overlay_status", Err: err}
	}

	vtepIP, _ := netip.ParseAddr(result.VTEPIP)

	return &OverlayStatusResult{
		NodeID: result.NodeID,
		VTEPIP: vtepIP,
		ControllerState: func() string {
			if result.Healthy {
				return "running"
			}
			return "stopped"
		}(),
		UnderlayMTU:    result.UnderlayMTU,
		VXLANPort:      result.VXLANPort,
		VNICount:       int(result.VNICount),
		VTEPCount:      int(result.VTEPCount),
		RemoteMACCount: int(result.RemoteMACCount),
		TunnelCount:    int(result.TunnelCount),
		Uptime:         time.Duration(result.Uptime) * time.Second,
	}, nil
}

// =============================================================================
// VTEP Commands
// =============================================================================

// VTEPList lists all VTEPs via REST API.
func (r *OverlayRESTAdapter) VTEPList(ctx context.Context) (*VTEPListResult, error) {
	respBody, err := r.doRequest(ctx, http.MethodGet, "/api/v1/sdn/overlay/vteps", nil)
	if err != nil {
		return nil, err
	}

	var result struct {
		VTEPs []struct {
			NodeID   string `json:"node_id"`
			IP       string `json:"ip"`
			Healthy  bool   `json:"healthy"`
			LastSeen string `json:"last_seen"`
			IsLocal  bool   `json:"is_local"`
			Port     int    `json:"port"`
		} `json:"vteps"`
		Count int `json:"count"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, ErrOverlayRESTDecodeFailed{Operation: "vtep_list", Err: err}
	}

	vteps := make([]VTEPInfo, len(result.VTEPs))
	for i, v := range result.VTEPs {
		ip, _ := netip.ParseAddr(v.IP)
		lastSeen, _ := time.Parse(time.RFC3339, v.LastSeen)
		vteps[i] = VTEPInfo{
			NodeID:     v.NodeID,
			IP:         ip,
			Healthy:    v.Healthy,
			LastSeen:   lastSeen,
			IsLocal:    v.IsLocal,
			TunnelPort: v.Port,
		}
	}

	return &VTEPListResult{
		VTEPs:      vteps,
		TotalCount: result.Count,
	}, nil
}

// VTEPGet retrieves a specific VTEP via REST API.
func (r *OverlayRESTAdapter) VTEPGet(ctx context.Context, nodeID string) (*VTEPGetResult, error) {
	path := "/api/v1/sdn/overlay/vteps/" + url.PathEscape(nodeID)
	respBody, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var result struct {
		NodeID    string   `json:"node_id"`
		IP        string   `json:"ip"`
		Healthy   bool     `json:"healthy"`
		LastSeen  string   `json:"last_seen"`
		IsLocal   bool     `json:"is_local"`
		Port      int      `json:"port"`
		VNIs      []uint32 `json:"vnis"`
		MACCount  int      `json:"mac_count"`
		BytesSent uint64   `json:"bytes_sent"`
		BytesRecv uint64   `json:"bytes_recv"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, ErrOverlayRESTDecodeFailed{Operation: "vtep_get", Err: err}
	}

	ip, _ := netip.ParseAddr(result.IP)
	lastSeen, _ := time.Parse(time.RFC3339, result.LastSeen)

	return &VTEPGetResult{
		VTEPInfo: VTEPInfo{
			NodeID:     result.NodeID,
			IP:         ip,
			Healthy:    result.Healthy,
			LastSeen:   lastSeen,
			IsLocal:    result.IsLocal,
			TunnelPort: result.Port,
		},
		VNIs:      result.VNIs,
		MACCount:  result.MACCount,
		BytesSent: result.BytesSent,
		BytesRecv: result.BytesRecv,
	}, nil
}

// =============================================================================
// VNI Commands
// =============================================================================

// VNICreate creates a VNI via REST API.
func (r *OverlayRESTAdapter) VNICreate(ctx context.Context, opts VNICreateOptions) (*VNICreateResult, error) {
	reqBody := map[string]interface{}{
		"vni":  opts.VNI,
		"vlan": opts.VLAN,
		"name": opts.Name,
	}

	respBody, err := r.doRequest(ctx, http.MethodPost, "/api/v1/sdn/overlay/vnis", reqBody)
	if err != nil {
		return nil, err
	}

	var result struct {
		ID     string `json:"id"`
		Config struct {
			VNI  uint32 `json:"vni"`
			VLAN uint32 `json:"vlan"`
			Name string `json:"name"`
		} `json:"config"`
		CreatedAt string `json:"created_at"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, ErrOverlayRESTDecodeFailed{Operation: "vni_create", Err: err}
	}

	createdAt, _ := time.Parse(time.RFC3339, result.CreatedAt)

	return &VNICreateResult{
		VNI:       result.Config.VNI,
		VLAN:      uint16(result.Config.VLAN),
		Name:      result.Config.Name,
		CreatedAt: createdAt,
	}, nil
}

// VNIDelete deletes a VNI via REST API.
func (r *OverlayRESTAdapter) VNIDelete(ctx context.Context, vni uint32) (*VNIDeleteResult, error) {
	path := "/api/v1/sdn/overlay/vnis/" + strconv.FormatUint(uint64(vni), 10)
	_, err := r.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return nil, err
	}

	return &VNIDeleteResult{
		VNI:     vni,
		Deleted: true,
	}, nil
}

// VNIList lists all VNIs via REST API.
func (r *OverlayRESTAdapter) VNIList(ctx context.Context) (*VNIListResult, error) {
	respBody, err := r.doRequest(ctx, http.MethodGet, "/api/v1/sdn/overlay/vnis", nil)
	if err != nil {
		return nil, err
	}

	var result struct {
		VNIs []struct {
			ID     string `json:"id"`
			Config struct {
				VNI  uint32 `json:"vni"`
				VLAN uint32 `json:"vlan"`
				Name string `json:"name"`
			} `json:"config"`
			CreatedAt string `json:"created_at"`
			MACCount  uint32 `json:"mac_count"`
		} `json:"vnis"`
		Count int `json:"count"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, ErrOverlayRESTDecodeFailed{Operation: "vni_list", Err: err}
	}

	vnis := make([]VNIInfo, len(result.VNIs))
	for i, v := range result.VNIs {
		createdAt, _ := time.Parse(time.RFC3339, v.CreatedAt)
		vnis[i] = VNIInfo{
			VNI:       v.Config.VNI,
			VLAN:      uint16(v.Config.VLAN),
			Name:      v.Config.Name,
			MACCount:  int(v.MACCount),
			CreatedAt: createdAt,
		}
	}

	return &VNIListResult{
		VNIs:       vnis,
		TotalCount: result.Count,
	}, nil
}

// =============================================================================
// Tunnel Commands
// =============================================================================

// TunnelList lists tunnels via REST API.
func (r *OverlayRESTAdapter) TunnelList(ctx context.Context, opts TunnelListOptions) (*TunnelListResult, error) {
	path := "/api/v1/sdn/overlay/tunnels"
	if opts.VNI > 0 {
		path += "?vni=" + strconv.FormatUint(uint64(opts.VNI), 10)
	}

	respBody, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var result struct {
		Tunnels []struct {
			LocalVTEP  string `json:"local_vtep"`
			RemoteVTEP string `json:"remote_vtep"`
			VNI        uint32 `json:"vni"`
			State      string `json:"state"`
			BytesTx    uint64 `json:"bytes_tx"`
			BytesRx    uint64 `json:"bytes_rx"`
			Port       string `json:"port"`
		} `json:"tunnels"`
		Count int `json:"count"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, ErrOverlayRESTDecodeFailed{Operation: "tunnel_list", Err: err}
	}

	tunnels := make([]TunnelInfo, len(result.Tunnels))
	for i, t := range result.Tunnels {
		localVTEP, _ := netip.ParseAddr(t.LocalVTEP)
		remoteVTEP, _ := netip.ParseAddr(t.RemoteVTEP)
		tunnels[i] = TunnelInfo{
			LocalVTEP:  localVTEP,
			RemoteVTEP: remoteVTEP,
			VNI:        t.VNI,
			Port:       t.Port,
			State:      t.State,
			BytesSent:  t.BytesTx,
			BytesRecv:  t.BytesRx,
		}
	}

	return &TunnelListResult{
		Tunnels:    tunnels,
		TotalCount: result.Count,
	}, nil
}

// =============================================================================
// MAC Commands
// =============================================================================

// MACList lists remote MACs via REST API.
func (r *OverlayRESTAdapter) MACList(ctx context.Context, opts MACListOptions) (*MACListResult, error) {
	path := "/api/v1/sdn/overlay/macs"
	if opts.VNI > 0 {
		path += "?vni=" + strconv.FormatUint(uint64(opts.VNI), 10)
	}

	respBody, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var result struct {
		MACs []struct {
			MAC        string `json:"mac"`
			IP         string `json:"ip"`
			VNI        uint32 `json:"vni"`
			RemoteVTEP string `json:"remote_vtep"`
			Source     string `json:"source"`
			LearnedAt  string `json:"learned_at"`
			ExpiresAt  string `json:"expires_at"`
		} `json:"macs"`
		Count int `json:"count"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, ErrOverlayRESTDecodeFailed{Operation: "mac_list", Err: err}
	}

	macs := make([]RemoteMACInfo, len(result.MACs))
	for i, m := range result.MACs {
		mac, _ := net.ParseMAC(m.MAC)
		ip, _ := netip.ParseAddr(m.IP)
		remoteVTEP, _ := netip.ParseAddr(m.RemoteVTEP)
		learnedAt, _ := time.Parse(time.RFC3339, m.LearnedAt)
		expiresAt, _ := time.Parse(time.RFC3339, m.ExpiresAt)
		macs[i] = RemoteMACInfo{
			MAC:        mac,
			IP:         ip,
			VNI:        m.VNI,
			RemoteVTEP: remoteVTEP,
			Source:     m.Source,
			LearnedAt:  learnedAt,
			ExpiresAt:  expiresAt,
		}
	}

	return &MACListResult{
		MACs:       macs,
		TotalCount: result.Count,
	}, nil
}

// MACForget forgets a MAC via REST API.
func (r *OverlayRESTAdapter) MACForget(ctx context.Context, mac string, vni uint32) (*MACForgetResult, error) {
	path := "/api/v1/sdn/overlay/macs/" + url.PathEscape(mac)
	if vni > 0 {
		path += "?vni=" + strconv.FormatUint(uint64(vni), 10)
	}

	_, err := r.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return nil, err
	}

	return &MACForgetResult{
		MAC:     mac,
		VNI:     vni,
		Deleted: true,
	}, nil
}

// =============================================================================
// Gateway Commands
// =============================================================================

// GatewayStatus retrieves gateway status via REST API.
func (r *OverlayRESTAdapter) GatewayStatus(ctx context.Context) (*GatewayStatusResult, error) {
	respBody, err := r.doRequest(ctx, http.MethodGet, "/api/v1/sdn/gateway/status", nil)
	if err != nil {
		return nil, err
	}

	var result struct {
		ID             string  `json:"id"`
		NodeID         string  `json:"node_id"`
		Modes          uint32  `json:"modes"`
		Tier           string  `json:"tier"`
		Reputation     float64 `json:"reputation"`
		UptimeSeconds  uint64  `json:"uptime_seconds"`
		Healthy        bool    `json:"healthy"`
		StartedAt      string  `json:"started_at"`
		IPv6Pool       string  `json:"ipv6_pool"`
		IPv4Pool       string  `json:"ipv4_pool"`
		BGPEnabled     bool    `json:"bgp_enabled"`
		EVPNEnabled    bool    `json:"evpn_enabled"`
		TransitEnabled bool    `json:"transit_enabled"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, ErrOverlayRESTDecodeFailed{Operation: "gateway_status", Err: err}
	}

	// Convert modes bitmask to strings
	modes := []string{}
	if result.Modes&1 != 0 {
		modes = append(modes, "overlay")
	}
	if result.Modes&2 != 0 {
		modes = append(modes, "edge")
	}
	if result.Modes&4 != 0 {
		modes = append(modes, "transit")
	}

	return &GatewayStatusResult{
		NodeID:         result.NodeID,
		Modes:          modes,
		Tier:           result.Tier,
		Healthy:        result.Healthy,
		Reputation:     result.Reputation,
		Age:            time.Duration(result.UptimeSeconds) * time.Second,
		UptimePct:      100.0, // REST API doesn't return this directly
		IPv6Pool:       result.IPv6Pool,
		IPv4Pool:       result.IPv4Pool,
		BGPEnabled:     result.BGPEnabled,
		EVPNEnabled:    result.EVPNEnabled,
		TransitEnabled: result.TransitEnabled,
	}, nil
}

func (r *OverlayRESTAdapter) GatewayAdmittedVTEPList(ctx context.Context, gatewayID string) (*GatewayAdmittedVTEPListResult, error) {
	path := "/api/v1/sdn/gateway/overlay/vteps"
	if gatewayID != "" {
		path += "?gateway_id=" + url.QueryEscape(gatewayID)
	}
	respBody, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var result struct {
		VTEPs []restGatewayAdmittedVTEP `json:"vteps"`
		Count int                       `json:"count"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, ErrOverlayRESTDecodeFailed{Operation: "gateway_admitted_vteps", Err: err}
	}
	vteps := make([]GatewayAdmittedVTEPInfo, 0, len(result.VTEPs))
	for _, vtep := range result.VTEPs {
		vteps = append(vteps, vtep.gatewayAdmittedVTEPInfo())
	}
	return &GatewayAdmittedVTEPListResult{VTEPs: vteps, Count: result.Count}, nil
}

func (r *OverlayRESTAdapter) GatewayAdmittedVTEPGet(ctx context.Context, gatewayID, vtep string) (*GatewayAdmittedVTEPGetResult, error) {
	path := "/api/v1/sdn/gateway/overlay/vteps/" + url.PathEscape(vtep)
	if gatewayID != "" {
		path += "?gateway_id=" + url.QueryEscape(gatewayID)
	}
	respBody, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var result restGatewayAdmittedVTEP
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, ErrOverlayRESTDecodeFailed{Operation: "gateway_admitted_vtep", Err: err}
	}
	return &GatewayAdmittedVTEPGetResult{VTEP: result.gatewayAdmittedVTEPInfo()}, nil
}

type restGatewayAdmittedVTEP struct {
	VTEP           string     `json:"vtep"`
	DeviceID       uint64     `json:"device_id"`
	HostID         string     `json:"host_id"`
	Serial         string     `json:"serial"`
	Hostname       string     `json:"hostname"`
	AllocationID   string     `json:"allocation_id"`
	BaselineSource string     `json:"baseline_source"`
	ProfileID      uint64     `json:"profile_id"`
	VerdictAt      *time.Time `json:"verdict_at"`
}

func (v restGatewayAdmittedVTEP) gatewayAdmittedVTEPInfo() GatewayAdmittedVTEPInfo {
	var verdictAt time.Time
	if v.VerdictAt != nil {
		verdictAt = *v.VerdictAt
	}
	return GatewayAdmittedVTEPInfo{
		VTEP:           v.VTEP,
		DeviceID:       v.DeviceID,
		HostID:         v.HostID,
		Serial:         v.Serial,
		Hostname:       v.Hostname,
		AllocationID:   v.AllocationID,
		BaselineSource: v.BaselineSource,
		ProfileID:      v.ProfileID,
		VerdictAt:      verdictAt,
	}
}

// GatewaySetMode sets gateway mode via REST API.
func (r *OverlayRESTAdapter) GatewaySetMode(ctx context.Context, opts GatewayModeOptions) (*GatewayModeResult, error) {
	// Convert modes to bitmask
	var modesMask uint32
	for _, mode := range opts.Modes {
		switch mode {
		case "overlay":
			modesMask |= 1
		case "edge":
			modesMask |= 2
		case "transit":
			modesMask |= 4
		}
	}

	reqBody := map[string]interface{}{
		"modes": modesMask,
	}

	respBody, err := r.doRequest(ctx, http.MethodPut, "/api/v1/sdn/gateway/mode", reqBody)
	if err != nil {
		return nil, err
	}

	var result struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, ErrOverlayRESTDecodeFailed{Operation: "gateway_set_mode", Err: err}
	}

	return &GatewayModeResult{
		Modes:   opts.Modes,
		Success: result.Success,
	}, nil
}

// =============================================================================
// BGP Commands
// =============================================================================

// BGPStatus retrieves BGP status via REST API.
func (r *OverlayRESTAdapter) BGPStatus(ctx context.Context) (*BGPStatusResult, error) {
	respBody, err := r.doRequest(ctx, http.MethodGet, "/api/v1/sdn/gateway/bgp/status", nil)
	if err != nil {
		return nil, err
	}

	var result struct {
		LocalASN          uint32 `json:"local_asn"`
		RouterID          string `json:"router_id"`
		PeerCount         uint32 `json:"peer_count"`
		EstablishedPeers  uint32 `json:"established_peers"`
		PrefixesAnnounced uint32 `json:"prefixes_announced"`
		Running           bool   `json:"running"`
		EVPNEnabled       bool   `json:"evpn_enabled"`
		TransitEnabled    bool   `json:"transit_enabled"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, ErrOverlayRESTDecodeFailed{Operation: "bgp_status", Err: err}
	}

	state := "stopped"
	if result.Running {
		state = "running"
	}

	return &BGPStatusResult{
		Enabled:          result.Running,
		ASN:              result.LocalASN,
		RouterID:         result.RouterID,
		State:            state,
		PeerCount:        int(result.PeerCount),
		EstablishedCount: int(result.EstablishedPeers),
		EVPNEnabled:      result.EVPNEnabled,
		TransitEnabled:   result.TransitEnabled,
	}, nil
}

// BGPPeers lists BGP peers via REST API.
func (r *OverlayRESTAdapter) BGPPeers(ctx context.Context) (*BGPPeersResult, error) {
	respBody, err := r.doRequest(ctx, http.MethodGet, "/api/v1/sdn/gateway/bgp/peers", nil)
	if err != nil {
		return nil, err
	}

	var result struct {
		Peers []struct {
			Address          string `json:"address"`
			ASN              uint32 `json:"asn"`
			State            string `json:"state"`
			Description      string `json:"description"`
			PrefixesReceived uint32 `json:"prefixes_received"`
			PrefixesSent     uint32 `json:"prefixes_sent"`
			Uptime           string `json:"uptime"`
		} `json:"peers"`
		Count int `json:"count"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, ErrOverlayRESTDecodeFailed{Operation: "bgp_peers", Err: err}
	}

	peers := make([]BGPPeerInfo, len(result.Peers))
	for i, p := range result.Peers {
		uptime, _ := time.Parse(time.RFC3339, p.Uptime)
		peers[i] = BGPPeerInfo{
			Address:      p.Address,
			RemoteASN:    p.ASN,
			State:        p.State,
			Uptime:       time.Since(uptime),
			PrefixesRecv: int(p.PrefixesReceived),
			PrefixesSent: int(p.PrefixesSent),
			Description:  p.Description,
		}
	}

	return &BGPPeersResult{
		Peers:      peers,
		TotalCount: result.Count,
	}, nil
}

// BGPPrefixes lists announced prefixes via REST API.
func (r *OverlayRESTAdapter) BGPPrefixes(ctx context.Context) (*BGPPrefixesResult, error) {
	respBody, err := r.doRequest(ctx, http.MethodGet, "/api/v1/sdn/gateway/bgp/prefixes", nil)
	if err != nil {
		return nil, err
	}

	var result struct {
		Prefixes []struct {
			Prefix      string   `json:"prefix"`
			NextHop     string   `json:"next_hop"`
			Origin      string   `json:"origin"`
			ASPath      string   `json:"as_path"`
			LocalPref   uint32   `json:"local_pref"`
			MED         uint32   `json:"med"`
			Communities []string `json:"communities"`
		} `json:"prefixes"`
		Count int `json:"count"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, ErrOverlayRESTDecodeFailed{Operation: "bgp_prefixes", Err: err}
	}

	prefixes := make([]BGPPrefixInfo, len(result.Prefixes))
	for i, p := range result.Prefixes {
		prefixes[i] = BGPPrefixInfo{
			Prefix:      p.Prefix,
			NextHop:     p.NextHop,
			Origin:      p.Origin,
			ASPath:      p.ASPath,
			LocalPref:   p.LocalPref,
			MED:         p.MED,
			Communities: p.Communities,
		}
	}

	return &BGPPrefixesResult{
		Prefixes:   prefixes,
		TotalCount: result.Count,
	}, nil
}

// BGPAnnounce announces a prefix via REST API.
func (r *OverlayRESTAdapter) BGPAnnounce(ctx context.Context, opts BGPAnnounceOptions) (*BGPAnnounceResult, error) {
	reqBody := map[string]interface{}{
		"prefix":   opts.Prefix,
		"next_hop": opts.NextHop,
	}

	_, err := r.doRequest(ctx, http.MethodPost, "/api/v1/sdn/gateway/bgp/prefixes", reqBody)
	if err != nil {
		return nil, err
	}

	return &BGPAnnounceResult{
		Prefix:  opts.Prefix,
		Success: true,
	}, nil
}

// BGPWithdraw withdraws a prefix via REST API.
func (r *OverlayRESTAdapter) BGPWithdraw(ctx context.Context, prefix string) (*BGPWithdrawResult, error) {
	path := "/api/v1/sdn/gateway/bgp/prefixes/" + url.PathEscape(prefix)
	_, err := r.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return nil, err
	}

	return &BGPWithdrawResult{
		Prefix:  prefix,
		Success: true,
	}, nil
}

// =============================================================================
// IPAM Commands
// =============================================================================

// IPAMPoolList lists IPAM pools via REST API.
func (r *OverlayRESTAdapter) IPAMPoolList(ctx context.Context) (*IPAMPoolListResult, error) {
	respBody, err := r.doRequest(ctx, http.MethodGet, "/api/v1/sdn/gateway/ipam/pools", nil)
	if err != nil {
		return nil, err
	}

	var result struct {
		Pools []struct {
			ID            string `json:"id"`
			Name          string `json:"name"`
			CIDR          string `json:"cidr"`
			Gateway       string `json:"gateway"`
			Total         uint32 `json:"total"`
			Allocated     uint32 `json:"allocated"`
			Available     uint32 `json:"available"`
			LeaseDuration int64  `json:"lease_duration_seconds"`
		} `json:"pools"`
		Count int `json:"count"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, ErrOverlayRESTDecodeFailed{Operation: "ipam_pool_list", Err: err}
	}

	pools := make([]IPAMPoolInfo, len(result.Pools))
	for i, p := range result.Pools {
		utilizationPct := float64(0)
		if p.Total > 0 {
			utilizationPct = float64(p.Allocated) / float64(p.Total) * 100
		}
		pools[i] = IPAMPoolInfo{
			ID:             p.ID,
			Name:           p.Name,
			CIDR:           p.CIDR,
			Gateway:        p.Gateway,
			TotalIPs:       int64(p.Total),
			AllocatedIPs:   int64(p.Allocated),
			AvailableIPs:   int64(p.Available),
			UtilizationPct: utilizationPct,
			LeaseDuration:  time.Duration(p.LeaseDuration) * time.Second,
		}
	}

	return &IPAMPoolListResult{
		Pools:      pools,
		TotalCount: result.Count,
	}, nil
}

// IPAMPoolCreate creates an IPAM pool via REST API.
func (r *OverlayRESTAdapter) IPAMPoolCreate(ctx context.Context, opts IPAMPoolCreateOptions) (*IPAMPoolCreateResult, error) {
	reqBody := map[string]interface{}{
		"name":                         opts.Name,
		"cidr":                         opts.CIDR,
		"gateway":                      opts.Gateway,
		"default_lease_duration_nanos": opts.LeaseDuration.Nanoseconds(),
	}

	respBody, err := r.doRequest(ctx, http.MethodPost, "/api/v1/sdn/gateway/ipam/pools", reqBody)
	if err != nil {
		return nil, err
	}

	var result struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		CIDR      string `json:"cidr"`
		CreatedAt string `json:"created_at"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, ErrOverlayRESTDecodeFailed{Operation: "ipam_pool_create", Err: err}
	}

	createdAt, _ := time.Parse(time.RFC3339, result.CreatedAt)

	return &IPAMPoolCreateResult{
		ID:        result.ID,
		Name:      result.Name,
		CIDR:      result.CIDR,
		CreatedAt: createdAt,
	}, nil
}

// IPAMPoolDelete deletes an IPAM pool via REST API.
func (r *OverlayRESTAdapter) IPAMPoolDelete(ctx context.Context, poolID string) (*IPAMPoolDeleteResult, error) {
	path := "/api/v1/sdn/gateway/ipam/pools/" + url.PathEscape(poolID)
	_, err := r.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return nil, err
	}

	return &IPAMPoolDeleteResult{
		ID:      poolID,
		Deleted: true,
	}, nil
}

// IPAMAllocate allocates an IP via REST API.
func (r *OverlayRESTAdapter) IPAMAllocate(ctx context.Context, opts IPAMAllocateOptions) (*IPAMAllocateResult, error) {
	reqBody := map[string]interface{}{
		"pool_id":   opts.PoolID,
		"device_id": opts.DeviceID,
		"hostname":  opts.Hostname,
	}

	respBody, err := r.doRequest(ctx, http.MethodPost, "/api/v1/sdn/gateway/ipam/allocations", reqBody)
	if err != nil {
		return nil, err
	}

	var result struct {
		IP          string `json:"ip"`
		PoolID      string `json:"pool_id"`
		DeviceID    string `json:"device_id"`
		Hostname    string `json:"hostname"`
		AllocatedAt string `json:"allocated_at"`
		ExpiresAt   string `json:"expires_at"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, ErrOverlayRESTDecodeFailed{Operation: "ipam_allocate", Err: err}
	}

	ip, _ := netip.ParseAddr(result.IP)
	expiresAt, _ := time.Parse(time.RFC3339, result.ExpiresAt)

	return &IPAMAllocateResult{
		IP:          ip,
		PoolID:      result.PoolID,
		DeviceID:    result.DeviceID,
		Hostname:    result.Hostname,
		LeaseExpiry: expiresAt,
	}, nil
}

// IPAMRelease releases an IP via REST API.
func (r *OverlayRESTAdapter) IPAMRelease(ctx context.Context, ip string) (*IPAMReleaseResult, error) {
	path := "/api/v1/sdn/gateway/ipam/allocations/" + url.PathEscape(ip)
	_, err := r.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return nil, err
	}

	return &IPAMReleaseResult{
		IP:       ip,
		Released: true,
	}, nil
}

// IPAMList lists IPAM allocations via REST API.
func (r *OverlayRESTAdapter) IPAMList(ctx context.Context, opts IPAMListOptions) (*IPAMListResult, error) {
	path := "/api/v1/sdn/gateway/ipam/allocations"
	if opts.PoolID != "" {
		path += "?pool_id=" + url.QueryEscape(opts.PoolID)
	}

	respBody, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var result struct {
		Allocations []struct {
			IP          string `json:"ip"`
			PoolID      string `json:"pool_id"`
			DeviceID    string `json:"device_id"`
			Hostname    string `json:"hostname"`
			Status      string `json:"status"`
			AllocatedAt string `json:"allocated_at"`
			ExpiresAt   string `json:"expires_at"`
			LastSeen    string `json:"last_seen"`
		} `json:"allocations"`
		Count int `json:"count"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, ErrOverlayRESTDecodeFailed{Operation: "ipam_list", Err: err}
	}

	allocations := make([]IPAMAllocationInfo, len(result.Allocations))
	for i, a := range result.Allocations {
		ip, _ := netip.ParseAddr(a.IP)
		allocatedAt, _ := time.Parse(time.RFC3339, a.AllocatedAt)
		expiresAt, _ := time.Parse(time.RFC3339, a.ExpiresAt)
		lastSeen, _ := time.Parse(time.RFC3339, a.LastSeen)
		allocations[i] = IPAMAllocationInfo{
			IP:          ip,
			PoolID:      a.PoolID,
			DeviceID:    a.DeviceID,
			Hostname:    a.Hostname,
			Status:      a.Status,
			AllocatedAt: allocatedAt,
			LeaseExpiry: expiresAt,
			LastSeen:    lastSeen,
		}
	}

	return &IPAMListResult{
		Allocations: allocations,
		TotalCount:  result.Count,
	}, nil
}

// =============================================================================
// Compile-time Interface Verification
// =============================================================================

// Ensure OverlayRESTAdapter implements OverlayCommands interface.
var _ OverlayCommands = (*OverlayRESTAdapter)(nil)
