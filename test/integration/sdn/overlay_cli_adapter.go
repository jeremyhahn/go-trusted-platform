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
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// =============================================================================
// Overlay CLI Adapter
// =============================================================================

// OverlayCLIAdapter implements OverlayCommands using the platformctl CLI tool.
type OverlayCLIAdapter struct {
	binaryPath string
	socketPath string
	grpcAddr   string
	configPath string
	configDir  string
}

// NewOverlayCLIAdapter creates a new overlay CLI adapter.
func NewOverlayCLIAdapter() *OverlayCLIAdapter {
	return &OverlayCLIAdapter{}
}

// Name returns the protocol adapter identifier.
func (c *OverlayCLIAdapter) Name() string {
	return "CLI"
}

// Setup locates the platformctl binary and creates a temporary config file
// pointing to the test daemon's Unix socket, using the same three-fallback
// convention as sdn_cli_adapter.go.
func (c *OverlayCLIAdapter) Setup(ctx context.Context) error {
	// Resolve binary path: prefer PLATFORMCTL_PATH env var, then well-known locations.
	if envPath := os.Getenv("PLATFORMCTL_PATH"); envPath != "" {
		if _, err := os.Stat(envPath); err == nil {
			c.binaryPath = envPath
		}
	}
	if c.binaryPath == "" {
		for _, p := range []string{"/tmp/platformctl", "platformctl", "/usr/local/bin/platformctl"} {
			if _, err := exec.LookPath(p); err == nil {
				c.binaryPath = p
				break
			}
		}
	}
	if c.binaryPath == "" {
		return ErrAdapterSetupFailed{Protocol: "CLI", Err: fmt.Errorf("platformctl binary not found")}
	}

	// Resolve socket path using the three-fallback convention:
	// PLATFORMD_SOCKET → PLATFORM_UNIX_SOCKET → PLATFORM_SOCKET_PATH → default.
	c.socketPath = os.Getenv(EnvPlatformdSocket)
	if c.socketPath == "" {
		c.socketPath = os.Getenv("PLATFORM_UNIX_SOCKET")
	}
	if c.socketPath == "" {
		c.socketPath = os.Getenv("PLATFORM_SOCKET_PATH")
	}
	if c.socketPath == "" {
		c.socketPath = DefaultPlatformdSocket
	}

	// Resolve gRPC address for the config file.
	c.grpcAddr = os.Getenv(EnvPlatformdGRPCEndpoint)
	if c.grpcAddr == "" {
		c.grpcAddr = DefaultPlatformdGRPCEndpoint
	}

	if err := c.createTestConfig(); err != nil {
		return ErrAdapterSetupFailed{Protocol: "CLI", Err: err}
	}

	return nil
}

// createTestConfig writes a temporary platformctl config file that points
// to the test daemon's Unix socket and gRPC address.
func (c *OverlayCLIAdapter) createTestConfig() error {
	tmpDir, err := os.MkdirTemp("", "platformctl-overlay-*")
	if err != nil {
		return fmt.Errorf("failed to create temp config dir: %w", err)
	}
	c.configDir = tmpDir

	configContent := fmt.Sprintf(`current_context: integration-test
contexts:
  - name: integration-test
    type: local
    local:
      socket_path: %s
      grpc_addr: %s
`, c.socketPath, c.grpcAddr)

	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		return fmt.Errorf("failed to write temp config: %w", err)
	}
	c.configPath = configPath
	log.Printf("[OverlayCLI] created test config at %s (socket=%s)", configPath, c.socketPath)
	return nil
}

// Teardown removes temporary config files created during setup.
func (c *OverlayCLIAdapter) Teardown() error {
	if c.configDir != "" {
		os.RemoveAll(c.configDir)
		c.configDir = ""
		c.configPath = ""
	}
	return nil
}

// =============================================================================
// Internal Helpers
// =============================================================================

// runCommand executes a platformctl command and returns JSON output.
// It prepends --output json and --config/--context flags so every invocation
// connects to the test daemon rather than the system default socket.
func (c *OverlayCLIAdapter) runCommand(ctx context.Context, args ...string) ([]byte, error) {
	fullArgs := []string{"--output", "json"}
	if c.configPath != "" {
		fullArgs = append(fullArgs, "--config", c.configPath, "--context", "integration-test")
	}
	fullArgs = append(fullArgs, args...)

	cmd := exec.CommandContext(ctx, c.binaryPath, fullArgs...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return nil, ErrCLIExecutionFailed{
			Command: strings.Join(fullArgs, " "),
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

// protoTimestamp represents a protobuf Timestamp marshaled to JSON.
type protoTimestamp struct {
	Seconds int64 `json:"seconds"`
	Nanos   int32 `json:"nanos"`
}

func (p *protoTimestamp) Time() time.Time {
	if p == nil {
		return time.Time{}
	}
	return time.Unix(p.Seconds, int64(p.Nanos))
}

// VTEPList returns all known VTEPs.
// The CLI outputs a bare JSON array of VTEPInfo objects (protobuf JSON encoding).
// Proto timestamps marshal as {"seconds": N, "nanos": N} objects.
func (c *OverlayCLIAdapter) VTEPList(ctx context.Context) (*VTEPListResult, error) {
	output, err := c.runCommand(ctx, "sdn", "overlay", "vtep", "list")
	if err != nil {
		return nil, err
	}

	// CLI outputs []*platformv1.VTEPInfo directly - a bare JSON array.
	var wireVTEPs []struct {
		NodeID   string          `json:"node_id"`
		IP       string          `json:"ip"`
		Healthy  bool            `json:"healthy"`
		LastSeen *protoTimestamp `json:"last_seen"`
		Vnis     []uint32        `json:"vnis"`
	}

	if err := c.parseJSONOutput(output, &wireVTEPs); err != nil {
		return nil, err
	}

	vteps := make([]VTEPInfo, len(wireVTEPs))
	for i, v := range wireVTEPs {
		ip, _ := netip.ParseAddr(v.IP)
		vteps[i] = VTEPInfo{
			NodeID:   v.NodeID,
			IP:       ip,
			Healthy:  v.Healthy,
			LastSeen: v.LastSeen.Time(),
		}
	}

	return &VTEPListResult{
		VTEPs:      vteps,
		TotalCount: len(vteps),
	}, nil
}

// VTEPGet returns details for a specific VTEP.
// The CLI outputs a single *platformv1.VTEPInfo (protobuf JSON encoding).
func (c *OverlayCLIAdapter) VTEPGet(ctx context.Context, nodeID string) (*VTEPGetResult, error) {
	output, err := c.runCommand(ctx, "sdn", "overlay", "vtep", "get", nodeID)
	if err != nil {
		return nil, err
	}

	var result struct {
		NodeID   string          `json:"node_id"`
		IP       string          `json:"ip"`
		Healthy  bool            `json:"healthy"`
		LastSeen *protoTimestamp `json:"last_seen"`
		Vnis     []uint32        `json:"vnis"`
	}

	if err := c.parseJSONOutput(output, &result); err != nil {
		return nil, err
	}

	ip, _ := netip.ParseAddr(result.IP)
	vnis := result.Vnis
	if vnis == nil {
		vnis = []uint32{}
	}

	return &VTEPGetResult{
		VTEPInfo: VTEPInfo{
			NodeID:   result.NodeID,
			IP:       ip,
			Healthy:  result.Healthy,
			LastSeen: result.LastSeen.Time(),
		},
		VNIs: vnis,
	}, nil
}

// =============================================================================
// VNI Commands
// =============================================================================

// VNICreate creates a new VNI.
// The CLI outputs a *platformv1.VNI (protobuf JSON), where created_at is a
// proto Timestamp object {"seconds": N, "nanos": N}.
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

	// The CLI outputs *platformv1.VNI — a single VNI object with proto JSON encoding.
	// Fields: id, config{vni,vlan,name}, created_at (proto Timestamp), mac_count.
	var result struct {
		ID     string `json:"id"`
		Config *struct {
			VNI  uint32 `json:"vni"`
			VLAN uint32 `json:"vlan"`
			Name string `json:"name"`
		} `json:"config"`
		CreatedAt *protoTimestamp `json:"created_at"`
		MACCount  uint32          `json:"mac_count"`
	}

	if err := c.parseJSONOutput(output, &result); err != nil {
		return nil, err
	}

	var vni uint32
	var vlan uint16
	var name string
	if result.Config != nil {
		vni = result.Config.VNI
		vlan = uint16(result.Config.VLAN)
		name = result.Config.Name
	}

	return &VNICreateResult{
		VNI:       vni,
		VLAN:      vlan,
		Name:      name,
		CreatedAt: result.CreatedAt.Time(),
	}, nil
}

// VNIDelete deletes a VNI.
// The CLI prints "VNI N deleted successfully\n" (plain text, not JSON).
// A successful command exit (err == nil) means the deletion succeeded.
func (c *OverlayCLIAdapter) VNIDelete(ctx context.Context, vni uint32) (*VNIDeleteResult, error) {
	_, err := c.runCommand(ctx, "sdn", "overlay", "vni", "delete", strconv.FormatUint(uint64(vni), 10))
	if err != nil {
		return nil, err
	}

	return &VNIDeleteResult{
		VNI:     vni,
		Deleted: true,
	}, nil
}

// VNIList lists all VNIs.
// The CLI outputs []*platformv1.VNI as a bare JSON array. Each element has
// proto-style fields: id, config{vni,vlan,name}, created_at (proto Timestamp
// object {"seconds": N, "nanos": N}), mac_count.
func (c *OverlayCLIAdapter) VNIList(ctx context.Context) (*VNIListResult, error) {
	output, err := c.runCommand(ctx, "sdn", "overlay", "vni", "list")
	if err != nil {
		return nil, err
	}

	// The CLI prints the raw []*platformv1.VNI slice — a bare JSON array.
	var wireVNIs []struct {
		ID     string `json:"id"`
		Config *struct {
			VNI  uint32 `json:"vni"`
			VLAN uint32 `json:"vlan"`
			Name string `json:"name"`
		} `json:"config"`
		CreatedAt *protoTimestamp `json:"created_at"`
		MACCount  uint32          `json:"mac_count"`
	}

	if err := c.parseJSONOutput(output, &wireVNIs); err != nil {
		return nil, err
	}

	vnis := make([]VNIInfo, len(wireVNIs))
	for i, v := range wireVNIs {
		vni := VNIInfo{
			CreatedAt: v.CreatedAt.Time(),
		}
		if v.Config != nil {
			vni.VNI = v.Config.VNI
			vni.VLAN = uint16(v.Config.VLAN)
			vni.Name = v.Config.Name
		}
		vnis[i] = vni
	}

	return &VNIListResult{
		VNIs:       vnis,
		TotalCount: len(vnis),
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

	// The CLI prints the gateway's []*platformv1.IPAMPool as a bare array.
	var pools []*platformv1.IPAMPool
	if err := c.parseJSONOutput(output, &pools); err != nil {
		return nil, err
	}
	return ipamPoolListFromProto(pools), nil
}

// IPAMPoolCreate creates an IPAM pool with `sdn ipam pool create`.
//
// The CLI prints the created platformv1.IPAMPool through encoding/json, so the
// output decodes straight back into that type; decoding into a hand-written
// mirror is how this adapter drifted from the command it drives (#730).
func (c *OverlayCLIAdapter) IPAMPoolCreate(ctx context.Context, opts IPAMPoolCreateOptions) (*IPAMPoolCreateResult, error) {
	args := []string{"sdn", "ipam", "pool", "create",
		"--name", opts.Name,
		"--cidr", opts.CIDR,
	}
	if opts.Gateway != "" {
		args = append(args, "--gateway", opts.Gateway)
	}
	if opts.LeaseDuration > 0 {
		args = append(args, "--lease-seconds", strconv.FormatInt(int64(opts.LeaseDuration/time.Second), 10))
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var pool platformv1.IPAMPool
	if err := c.parseJSONOutput(output, &pool); err != nil {
		return nil, err
	}

	return &IPAMPoolCreateResult{
		ID:        pool.GetId(),
		Name:      pool.GetName(),
		CIDR:      pool.GetCidr(),
		CreatedAt: protoTimestampToTime(pool.GetCreatedAt()),
	}, nil
}

// IPAMPoolDelete deletes an IPAM pool with `sdn ipam pool delete --id`.
func (c *OverlayCLIAdapter) IPAMPoolDelete(ctx context.Context, poolID string) (*IPAMPoolDeleteResult, error) {
	output, err := c.runCommand(ctx, "sdn", "ipam", "pool", "delete", "--id", poolID)
	if err != nil {
		return nil, err
	}

	var result struct {
		PoolID  string `json:"pool_id"`
		Deleted bool   `json:"deleted"`
	}
	if err := c.parseJSONOutput(output, &result); err != nil {
		return nil, err
	}

	return &IPAMPoolDeleteResult{
		ID:      result.PoolID,
		Deleted: result.Deleted,
	}, nil
}

// IPAMAllocate allocates an IP with `sdn ipam allocate`.
func (c *OverlayCLIAdapter) IPAMAllocate(ctx context.Context, opts IPAMAllocateOptions) (*IPAMAllocateResult, error) {
	args := []string{"sdn", "ipam", "allocate",
		"--pool-id", opts.PoolID,
		"--device-id", opts.DeviceID,
	}
	if opts.Hostname != "" {
		args = append(args, "--hostname", opts.Hostname)
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var alloc platformv1.IPAllocation
	if err := c.parseJSONOutput(output, &alloc); err != nil {
		return nil, err
	}

	info, err := cliAllocationInfo(&alloc)
	if err != nil {
		return nil, err
	}

	return &IPAMAllocateResult{
		IP:          info.IP,
		PoolID:      info.PoolID,
		DeviceID:    info.DeviceID,
		Hostname:    info.Hostname,
		LeaseExpiry: info.LeaseExpiry,
	}, nil
}

// IPAMRelease releases an IP with `sdn ipam release --ip`.
func (c *OverlayCLIAdapter) IPAMRelease(ctx context.Context, ip string) (*IPAMReleaseResult, error) {
	output, err := c.runCommand(ctx, "sdn", "ipam", "release", "--ip", ip)
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

// IPAMList lists IPAM allocations with `sdn ipam allocations`, which prints
// the []*platformv1.IPAllocation the gateway returned.
func (c *OverlayCLIAdapter) IPAMList(ctx context.Context, opts IPAMListOptions) (*IPAMListResult, error) {
	args := []string{"sdn", "ipam", "allocations"}
	if opts.PoolID != "" {
		args = append(args, "--pool-id", opts.PoolID)
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result []*platformv1.IPAllocation
	if err := c.parseJSONOutput(output, &result); err != nil {
		return nil, err
	}

	allocations := make([]IPAMAllocationInfo, 0, len(result))
	for _, a := range result {
		info, err := cliAllocationInfo(a)
		if err != nil {
			return nil, err
		}
		allocations = append(allocations, info)
	}

	return &IPAMListResult{
		Allocations: allocations,
		TotalCount:  len(allocations),
	}, nil
}

// cliAllocationInfo converts an allocation the CLI printed. An address that
// does not parse is an error: a zero netip.Addr would compare unequal to
// every real address and turn a decoding defect into a "not found" failure.
func cliAllocationInfo(a *platformv1.IPAllocation) (IPAMAllocationInfo, error) {
	ip, err := netip.ParseAddr(a.GetIp())
	if err != nil {
		return IPAMAllocationInfo{}, ErrCLIOutputParseFailed{Output: a.GetIp(), Err: err}
	}
	return IPAMAllocationInfo{
		IP:          ip,
		PoolID:      a.GetPoolId(),
		DeviceID:    a.GetDeviceId(),
		Hostname:    a.GetHostname(),
		AllocatedAt: protoTimestampToTime(a.GetAllocatedAt()),
		LeaseExpiry: protoTimestampToTime(a.GetExpiresAt()),
	}, nil
}

// =============================================================================
// Compile-time Interface Verification
// =============================================================================

var _ OverlayCommands = (*OverlayCLIAdapter)(nil)
