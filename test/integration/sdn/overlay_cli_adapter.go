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
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// =============================================================================
// Overlay CLI Adapter
// =============================================================================

// OverlayCLIAdapter implements OverlayCommands using the platformctl CLI tool.
type OverlayCLIAdapter struct {
	binaryPath string
	configPath string
	timeout    time.Duration
}

// NewOverlayCLIAdapter creates a new overlay CLI adapter.
func NewOverlayCLIAdapter() *OverlayCLIAdapter {
	binaryPath := os.Getenv("PLATFORMCTL_PATH")
	if binaryPath == "" {
		binaryPath = "platformctl"
	}

	configPath := os.Getenv("PLATFORMCTL_CONFIG")

	return &OverlayCLIAdapter{
		binaryPath: binaryPath,
		configPath: configPath,
		timeout:    10 * time.Second,
	}
}

// Name returns the protocol adapter identifier.
func (c *OverlayCLIAdapter) Name() string {
	return "CLI"
}

// Setup verifies the CLI binary is available.
func (c *OverlayCLIAdapter) Setup(ctx context.Context) error {
	_, err := exec.LookPath(c.binaryPath)
	if err != nil {
		return ErrCLINotConfigured{}
	}
	return nil
}

// Teardown performs any cleanup (none needed for CLI).
func (c *OverlayCLIAdapter) Teardown() error {
	return nil
}

// =============================================================================
// Internal Helpers
// =============================================================================

func (c *OverlayCLIAdapter) runCommand(ctx context.Context, args ...string) ([]byte, error) {
	cmdArgs := append([]string{"--output", "json"}, args...)
	if c.configPath != "" {
		cmdArgs = append([]string{"--config", c.configPath}, cmdArgs...)
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, c.binaryPath, cmdArgs...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return nil, ErrCLIExecutionFailed{
			Command: strings.Join(cmdArgs, " "),
			Stdout:  stdout.String(),
			Stderr:  stderr.String(),
			Err:     err,
		}
	}

	return stdout.Bytes(), nil
}

func (c *OverlayCLIAdapter) parseJSONOutput(output []byte, v interface{}) error {
	if err := json.Unmarshal(output, v); err != nil {
		return ErrCLIOutputParseFailed{
			Output: string(output),
			Err:    err,
		}
	}
	return nil
}

// =============================================================================
// Overlay Status Commands
// =============================================================================

// OverlayStatus returns the current overlay network status.
func (c *OverlayCLIAdapter) OverlayStatus(ctx context.Context) (*OverlayStatusResult, error) {
	output, err := c.runCommand(ctx, "sdn", "overlay", "status")
	if err != nil {
		return nil, err
	}

	var result struct {
		NodeID          string `json:"node_id"`
		VTEPIP          string `json:"vtep_ip"`
		ControllerState string `json:"controller_state"`
		UnderlayMTU     int    `json:"underlay_mtu"`
		VXLANPort       uint16 `json:"vxlan_port"`
		VNICount        int    `json:"vni_count"`
		VTEPCount       int    `json:"vtep_count"`
		RemoteMACCount  int    `json:"remote_mac_count"`
		TunnelCount     int    `json:"tunnel_count"`
		UptimeSeconds   int64  `json:"uptime_seconds"`
	}

	if err := c.parseJSONOutput(output, &result); err != nil {
		return nil, err
	}

	vtepIP, _ := netip.ParseAddr(result.VTEPIP)

	return &OverlayStatusResult{
		NodeID:          result.NodeID,
		VTEPIP:          vtepIP,
		ControllerState: result.ControllerState,
		UnderlayMTU:     result.UnderlayMTU,
		VXLANPort:       result.VXLANPort,
		VNICount:        result.VNICount,
		VTEPCount:       result.VTEPCount,
		RemoteMACCount:  result.RemoteMACCount,
		TunnelCount:     result.TunnelCount,
		Uptime:          time.Duration(result.UptimeSeconds) * time.Second,
	}, nil
}

// =============================================================================
// VTEP Commands
// =============================================================================

// VTEPList returns all known VTEPs.
func (c *OverlayCLIAdapter) VTEPList(ctx context.Context) (*VTEPListResult, error) {
	output, err := c.runCommand(ctx, "sdn", "overlay", "vtep", "list")
	if err != nil {
		return nil, err
	}

	var result struct {
		VTEPs []struct {
			NodeID     string `json:"node_id"`
			IP         string `json:"ip"`
			Healthy    bool   `json:"healthy"`
			LastSeen   string `json:"last_seen"`
			IsLocal    bool   `json:"is_local"`
			TunnelPort int    `json:"tunnel_port"`
		} `json:"vteps"`
		TotalCount int `json:"total_count"`
	}

	if err := c.parseJSONOutput(output, &result); err != nil {
		return nil, err
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
			TunnelPort: v.TunnelPort,
		}
	}

	return &VTEPListResult{
		VTEPs:      vteps,
		TotalCount: result.TotalCount,
	}, nil
}

// VTEPGet returns details for a specific VTEP.
func (c *OverlayCLIAdapter) VTEPGet(ctx context.Context, nodeID string) (*VTEPGetResult, error) {
	output, err := c.runCommand(ctx, "sdn", "overlay", "vtep", "get", nodeID)
	if err != nil {
		return nil, err
	}

	var result struct {
		NodeID     string   `json:"node_id"`
		IP         string   `json:"ip"`
		Healthy    bool     `json:"healthy"`
		LastSeen   string   `json:"last_seen"`
		IsLocal    bool     `json:"is_local"`
		TunnelPort int      `json:"tunnel_port"`
		VNIs       []uint32 `json:"vnis"`
		MACCount   int      `json:"mac_count"`
		BytesSent  uint64   `json:"bytes_sent"`
		BytesRecv  uint64   `json:"bytes_recv"`
	}

	if err := c.parseJSONOutput(output, &result); err != nil {
		return nil, err
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
			TunnelPort: result.TunnelPort,
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

// VNICreate creates a new VNI.
func (c *OverlayCLIAdapter) VNICreate(ctx context.Context, opts VNICreateOptions) (*VNICreateResult, error) {
	args := []string{"sdn", "overlay", "vni", "create",
		"--vni", strconv.FormatUint(uint64(opts.VNI), 10),
		"--vlan", strconv.FormatUint(uint64(opts.VLAN), 10),
	}

	if opts.Name != "" {
		args = append(args, "--name", opts.Name)
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result struct {
		VNI       uint32 `json:"vni"`
		VLAN      uint16 `json:"vlan"`
		Name      string `json:"name"`
		CreatedAt string `json:"created_at"`
	}

	if err := c.parseJSONOutput(output, &result); err != nil {
		return nil, err
	}

	createdAt, _ := time.Parse(time.RFC3339, result.CreatedAt)

	return &VNICreateResult{
		VNI:       result.VNI,
		VLAN:      result.VLAN,
		Name:      result.Name,
		CreatedAt: createdAt,
	}, nil
}

// VNIDelete deletes a VNI.
func (c *OverlayCLIAdapter) VNIDelete(ctx context.Context, vni uint32) (*VNIDeleteResult, error) {
	output, err := c.runCommand(ctx, "sdn", "overlay", "vni", "delete", strconv.FormatUint(uint64(vni), 10))
	if err != nil {
		return nil, err
	}

	var result struct {
		VNI     uint32 `json:"vni"`
		Deleted bool   `json:"deleted"`
	}

	if err := c.parseJSONOutput(output, &result); err != nil {
		return nil, err
	}

	return &VNIDeleteResult{
		VNI:     result.VNI,
		Deleted: result.Deleted,
	}, nil
}

// VNIList lists all VNIs.
func (c *OverlayCLIAdapter) VNIList(ctx context.Context) (*VNIListResult, error) {
	output, err := c.runCommand(ctx, "sdn", "overlay", "vni", "list")
	if err != nil {
		return nil, err
	}

	var result struct {
		VNIs []struct {
			VNI        uint32 `json:"vni"`
			VLAN       uint16 `json:"vlan"`
			Name       string `json:"name"`
			MACCount   int    `json:"mac_count"`
			TunnelPort string `json:"tunnel_port"`
			CreatedAt  string `json:"created_at"`
		} `json:"vnis"`
		TotalCount int `json:"total_count"`
	}

	if err := c.parseJSONOutput(output, &result); err != nil {
		return nil, err
	}

	vnis := make([]VNIInfo, len(result.VNIs))
	for i, v := range result.VNIs {
		createdAt, _ := time.Parse(time.RFC3339, v.CreatedAt)
		vnis[i] = VNIInfo{
			VNI:        v.VNI,
			VLAN:       v.VLAN,
			Name:       v.Name,
			MACCount:   v.MACCount,
			TunnelPort: v.TunnelPort,
			CreatedAt:  createdAt,
		}
	}

	return &VNIListResult{
		VNIs:       vnis,
		TotalCount: result.TotalCount,
	}, nil
}

// =============================================================================
// Tunnel Commands
// =============================================================================

// TunnelList lists all tunnels.
func (c *OverlayCLIAdapter) TunnelList(ctx context.Context, opts TunnelListOptions) (*TunnelListResult, error) {
	args := []string{"sdn", "overlay", "tunnel", "list"}

	if opts.VNI > 0 {
		args = append(args, "--vni", strconv.FormatUint(uint64(opts.VNI), 10))
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result struct {
		Tunnels []struct {
			LocalVTEP  string `json:"local_vtep"`
			RemoteVTEP string `json:"remote_vtep"`
			VNI        uint32 `json:"vni"`
			Port       string `json:"port"`
			State      string `json:"state"`
			BytesSent  uint64 `json:"bytes_sent"`
			BytesRecv  uint64 `json:"bytes_recv"`
		} `json:"tunnels"`
		TotalCount int `json:"total_count"`
	}

	if err := c.parseJSONOutput(output, &result); err != nil {
		return nil, err
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
			BytesSent:  t.BytesSent,
			BytesRecv:  t.BytesRecv,
		}
	}

	return &TunnelListResult{
		Tunnels:    tunnels,
		TotalCount: result.TotalCount,
	}, nil
}

// =============================================================================
// MAC Commands
// =============================================================================

// MACList lists remote MACs.
func (c *OverlayCLIAdapter) MACList(ctx context.Context, opts MACListOptions) (*MACListResult, error) {
	args := []string{"sdn", "overlay", "mac", "list"}

	if opts.VNI > 0 {
		args = append(args, "--vni", strconv.FormatUint(uint64(opts.VNI), 10))
	}

	output, err := c.runCommand(ctx, args...)
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
		TotalCount int `json:"total_count"`
	}

	if err := c.parseJSONOutput(output, &result); err != nil {
		return nil, err
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
		TotalCount: result.TotalCount,
	}, nil
}

// MACForget removes a learned MAC.
func (c *OverlayCLIAdapter) MACForget(ctx context.Context, mac string, vni uint32) (*MACForgetResult, error) {
	output, err := c.runCommand(ctx, "sdn", "overlay", "mac", "forget", mac,
		"--vni", strconv.FormatUint(uint64(vni), 10))
	if err != nil {
		return nil, err
	}

	var result struct {
		MAC     string `json:"mac"`
		VNI     uint32 `json:"vni"`
		Deleted bool   `json:"deleted"`
	}

	if err := c.parseJSONOutput(output, &result); err != nil {
		return nil, err
	}

	return &MACForgetResult{
		MAC:     result.MAC,
		VNI:     result.VNI,
		Deleted: result.Deleted,
	}, nil
}

// =============================================================================
// Gateway Commands
// =============================================================================

// GatewayStatus returns gateway status.
func (c *OverlayCLIAdapter) GatewayStatus(ctx context.Context) (*GatewayStatusResult, error) {
	output, err := c.runCommand(ctx, "sdn", "gateway", "status")
	if err != nil {
		return nil, err
	}

	var result struct {
		NodeID         string   `json:"node_id"`
		Modes          []string `json:"modes"`
		Tier           string   `json:"tier"`
		Healthy        bool     `json:"healthy"`
		Reputation     float64  `json:"reputation"`
		AgeSeconds     int64    `json:"age_seconds"`
		UptimePct      float64  `json:"uptime_pct"`
		IPv6Pool       string   `json:"ipv6_pool"`
		IPv4Pool       string   `json:"ipv4_pool"`
		BGPEnabled     bool     `json:"bgp_enabled"`
		EVPNEnabled    bool     `json:"evpn_enabled"`
		TransitEnabled bool     `json:"transit_enabled"`
	}

	if err := c.parseJSONOutput(output, &result); err != nil {
		return nil, err
	}

	return &GatewayStatusResult{
		NodeID:         result.NodeID,
		Modes:          result.Modes,
		Tier:           result.Tier,
		Healthy:        result.Healthy,
		Reputation:     result.Reputation,
		Age:            time.Duration(result.AgeSeconds) * time.Second,
		UptimePct:      result.UptimePct,
		IPv6Pool:       result.IPv6Pool,
		IPv4Pool:       result.IPv4Pool,
		BGPEnabled:     result.BGPEnabled,
		EVPNEnabled:    result.EVPNEnabled,
		TransitEnabled: result.TransitEnabled,
	}, nil
}

// GatewaySetMode sets gateway modes.
func (c *OverlayCLIAdapter) GatewaySetMode(ctx context.Context, opts GatewayModeOptions) (*GatewayModeResult, error) {
	args := []string{"sdn", "gateway", "mode", "set",
		"--modes", strings.Join(opts.Modes, ","),
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result struct {
		Modes   []string `json:"modes"`
		Success bool     `json:"success"`
	}

	if err := c.parseJSONOutput(output, &result); err != nil {
		return nil, err
	}

	return &GatewayModeResult{
		Modes:   result.Modes,
		Success: result.Success,
	}, nil
}

// =============================================================================
// BGP Commands
// =============================================================================

// BGPStatus returns BGP status.
func (c *OverlayCLIAdapter) BGPStatus(ctx context.Context) (*BGPStatusResult, error) {
	output, err := c.runCommand(ctx, "sdn", "gateway", "bgp", "status")
	if err != nil {
		return nil, err
	}

	var result struct {
		Enabled          bool   `json:"enabled"`
		ASN              uint32 `json:"asn"`
		RouterID         string `json:"router_id"`
		State            string `json:"state"`
		PeerCount        int    `json:"peer_count"`
		EstablishedCount int    `json:"established_count"`
		EVPNEnabled      bool   `json:"evpn_enabled"`
		TransitEnabled   bool   `json:"transit_enabled"`
	}

	if err := c.parseJSONOutput(output, &result); err != nil {
		return nil, err
	}

	return &BGPStatusResult{
		Enabled:          result.Enabled,
		ASN:              result.ASN,
		RouterID:         result.RouterID,
		State:            result.State,
		PeerCount:        result.PeerCount,
		EstablishedCount: result.EstablishedCount,
		EVPNEnabled:      result.EVPNEnabled,
		TransitEnabled:   result.TransitEnabled,
	}, nil
}

// BGPPeers returns BGP peers.
func (c *OverlayCLIAdapter) BGPPeers(ctx context.Context) (*BGPPeersResult, error) {
	output, err := c.runCommand(ctx, "sdn", "gateway", "bgp", "peers")
	if err != nil {
		return nil, err
	}

	var result struct {
		Peers []struct {
			Address       string `json:"address"`
			RemoteASN     uint32 `json:"remote_asn"`
			State         string `json:"state"`
			UptimeSeconds int64  `json:"uptime_seconds"`
			PrefixesRecv  int    `json:"prefixes_recv"`
			PrefixesSent  int    `json:"prefixes_sent"`
			Description   string `json:"description"`
		} `json:"peers"`
		TotalCount int `json:"total_count"`
	}

	if err := c.parseJSONOutput(output, &result); err != nil {
		return nil, err
	}

	peers := make([]BGPPeerInfo, len(result.Peers))
	for i, p := range result.Peers {
		peers[i] = BGPPeerInfo{
			Address:      p.Address,
			RemoteASN:    p.RemoteASN,
			State:        p.State,
			Uptime:       time.Duration(p.UptimeSeconds) * time.Second,
			PrefixesRecv: p.PrefixesRecv,
			PrefixesSent: p.PrefixesSent,
			Description:  p.Description,
		}
	}

	return &BGPPeersResult{
		Peers:      peers,
		TotalCount: result.TotalCount,
	}, nil
}

// BGPPrefixes returns announced prefixes.
func (c *OverlayCLIAdapter) BGPPrefixes(ctx context.Context) (*BGPPrefixesResult, error) {
	output, err := c.runCommand(ctx, "sdn", "gateway", "bgp", "routes")
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
		TotalCount int `json:"total_count"`
	}

	if err := c.parseJSONOutput(output, &result); err != nil {
		return nil, err
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
		TotalCount: result.TotalCount,
	}, nil
}

// BGPAnnounce announces a prefix.
func (c *OverlayCLIAdapter) BGPAnnounce(ctx context.Context, opts BGPAnnounceOptions) (*BGPAnnounceResult, error) {
	args := []string{"sdn", "gateway", "bgp", "announce",
		"--prefix", opts.Prefix,
		"--next-hop", opts.NextHop,
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result struct {
		Prefix  string `json:"prefix"`
		Success bool   `json:"success"`
	}

	if err := c.parseJSONOutput(output, &result); err != nil {
		return nil, err
	}

	return &BGPAnnounceResult{
		Prefix:  result.Prefix,
		Success: result.Success,
	}, nil
}

// BGPWithdraw withdraws a prefix.
func (c *OverlayCLIAdapter) BGPWithdraw(ctx context.Context, prefix string) (*BGPWithdrawResult, error) {
	output, err := c.runCommand(ctx, "sdn", "gateway", "bgp", "withdraw", "--prefix", prefix)
	if err != nil {
		return nil, err
	}

	var result struct {
		Prefix  string `json:"prefix"`
		Success bool   `json:"success"`
	}

	if err := c.parseJSONOutput(output, &result); err != nil {
		return nil, err
	}

	return &BGPWithdrawResult{
		Prefix:  result.Prefix,
		Success: result.Success,
	}, nil
}

// =============================================================================
// IPAM Commands
// =============================================================================

// IPAMPoolList lists IPAM pools.
func (c *OverlayCLIAdapter) IPAMPoolList(ctx context.Context) (*IPAMPoolListResult, error) {
	output, err := c.runCommand(ctx, "sdn", "ipam", "pool", "list")
	if err != nil {
		return nil, err
	}

	var result struct {
		Pools []struct {
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
		} `json:"pools"`
		TotalCount int `json:"total_count"`
	}

	if err := c.parseJSONOutput(output, &result); err != nil {
		return nil, err
	}

	pools := make([]IPAMPoolInfo, len(result.Pools))
	for i, p := range result.Pools {
		pools[i] = IPAMPoolInfo{
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
		}
	}

	return &IPAMPoolListResult{
		Pools:      pools,
		TotalCount: result.TotalCount,
	}, nil
}

// IPAMPoolCreate creates an IPAM pool.
func (c *OverlayCLIAdapter) IPAMPoolCreate(ctx context.Context, opts IPAMPoolCreateOptions) (*IPAMPoolCreateResult, error) {
	args := []string{"sdn", "ipam", "pool", "create",
		"--name", opts.Name,
		"--cidr", opts.CIDR,
	}

	if opts.Gateway != "" {
		args = append(args, "--gateway", opts.Gateway)
	}
	if len(opts.DNS) > 0 {
		args = append(args, "--dns", strings.Join(opts.DNS, ","))
	}
	if opts.LeaseDuration > 0 {
		args = append(args, "--lease", opts.LeaseDuration.String())
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		CIDR      string `json:"cidr"`
		CreatedAt string `json:"created_at"`
	}

	if err := c.parseJSONOutput(output, &result); err != nil {
		return nil, err
	}

	createdAt, _ := time.Parse(time.RFC3339, result.CreatedAt)

	return &IPAMPoolCreateResult{
		ID:        result.ID,
		Name:      result.Name,
		CIDR:      result.CIDR,
		CreatedAt: createdAt,
	}, nil
}

// IPAMPoolDelete deletes an IPAM pool.
func (c *OverlayCLIAdapter) IPAMPoolDelete(ctx context.Context, poolID string) (*IPAMPoolDeleteResult, error) {
	output, err := c.runCommand(ctx, "sdn", "ipam", "pool", "delete", poolID)
	if err != nil {
		return nil, err
	}

	var result struct {
		ID      string `json:"id"`
		Deleted bool   `json:"deleted"`
	}

	if err := c.parseJSONOutput(output, &result); err != nil {
		return nil, err
	}

	return &IPAMPoolDeleteResult{
		ID:      result.ID,
		Deleted: result.Deleted,
	}, nil
}

// IPAMAllocate allocates an IP.
func (c *OverlayCLIAdapter) IPAMAllocate(ctx context.Context, opts IPAMAllocateOptions) (*IPAMAllocateResult, error) {
	args := []string{"sdn", "ipam", "allocate",
		"--pool", opts.PoolID,
		"--device", opts.DeviceID,
	}

	if opts.Hostname != "" {
		args = append(args, "--hostname", opts.Hostname)
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result struct {
		IP          string `json:"ip"`
		PoolID      string `json:"pool_id"`
		DeviceID    string `json:"device_id"`
		Hostname    string `json:"hostname"`
		LeaseExpiry string `json:"lease_expiry"`
	}

	if err := c.parseJSONOutput(output, &result); err != nil {
		return nil, err
	}

	ip, _ := netip.ParseAddr(result.IP)
	leaseExpiry, _ := time.Parse(time.RFC3339, result.LeaseExpiry)

	return &IPAMAllocateResult{
		IP:          ip,
		PoolID:      result.PoolID,
		DeviceID:    result.DeviceID,
		Hostname:    result.Hostname,
		LeaseExpiry: leaseExpiry,
	}, nil
}

// IPAMRelease releases an IP.
func (c *OverlayCLIAdapter) IPAMRelease(ctx context.Context, ip string) (*IPAMReleaseResult, error) {
	output, err := c.runCommand(ctx, "sdn", "ipam", "release", ip)
	if err != nil {
		return nil, err
	}

	var result struct {
		IP       string `json:"ip"`
		Released bool   `json:"released"`
	}

	if err := c.parseJSONOutput(output, &result); err != nil {
		return nil, err
	}

	return &IPAMReleaseResult{
		IP:       result.IP,
		Released: result.Released,
	}, nil
}

// IPAMList lists IPAM allocations.
func (c *OverlayCLIAdapter) IPAMList(ctx context.Context, opts IPAMListOptions) (*IPAMListResult, error) {
	args := []string{"sdn", "ipam", "allocations"}

	if opts.PoolID != "" {
		args = append(args, "--pool-id", opts.PoolID)
	}

	output, err := c.runCommand(ctx, args...)
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
			LeaseExpiry string `json:"lease_expiry"`
			LastSeen    string `json:"last_seen"`
		} `json:"allocations"`
		TotalCount int `json:"total_count"`
	}

	if err := c.parseJSONOutput(output, &result); err != nil {
		return nil, err
	}

	allocations := make([]IPAMAllocationInfo, len(result.Allocations))
	for i, a := range result.Allocations {
		ip, _ := netip.ParseAddr(a.IP)
		allocatedAt, _ := time.Parse(time.RFC3339, a.AllocatedAt)
		leaseExpiry, _ := time.Parse(time.RFC3339, a.LeaseExpiry)
		lastSeen, _ := time.Parse(time.RFC3339, a.LastSeen)
		allocations[i] = IPAMAllocationInfo{
			IP:          ip,
			PoolID:      a.PoolID,
			DeviceID:    a.DeviceID,
			Hostname:    a.Hostname,
			Status:      a.Status,
			AllocatedAt: allocatedAt,
			LeaseExpiry: leaseExpiry,
			LastSeen:    lastSeen,
		}
	}

	return &IPAMListResult{
		Allocations: allocations,
		TotalCount:  result.TotalCount,
	}, nil
}

// =============================================================================
// Compile-time Interface Verification
// =============================================================================

var _ OverlayCommands = (*OverlayCLIAdapter)(nil)
