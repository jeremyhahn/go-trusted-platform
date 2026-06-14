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
	"strings"
	"time"
)

// =============================================================================
// CLI Adapter Implementation
// =============================================================================

// SDNCLIAdapter implements SDNTestAdapter using platformctl CLI commands.
// This adapter executes the platformctl binary and parses JSON output.
type SDNCLIAdapter struct {
	binaryPath string
	socketPath string
	grpcAddr   string
	configPath string
	configDir  string
}

// NewSDNCLIAdapter creates a new CLI adapter for SDN integration testing.
func NewSDNCLIAdapter() *SDNCLIAdapter {
	return &SDNCLIAdapter{}
}

// Name returns the protocol adapter identifier.
func (c *SDNCLIAdapter) Name() string {
	return "CLI"
}

// Setup locates the platformctl binary and creates a temporary config file
// pointing to the test daemon's Unix socket.
func (c *SDNCLIAdapter) Setup(ctx context.Context) error {
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

	// Resolve socket path: check all three env vars set by run-integration-tests.sh
	// (PLATFORMD_SOCKET, PLATFORM_UNIX_SOCKET, PLATFORM_SOCKET_PATH) before falling
	// back to the hardcoded default. This mirrors the convention in cli_adapter.go.
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
func (c *SDNCLIAdapter) createTestConfig() error {
	tmpDir, err := os.MkdirTemp("", "platformctl-sdn-*")
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
	log.Printf("[CLI] created test config at %s (socket=%s)", configPath, c.socketPath)
	return nil
}

// Teardown removes temporary config files created during setup.
func (c *SDNCLIAdapter) Teardown() error {
	if c.configDir != "" {
		os.RemoveAll(c.configDir)
		c.configDir = ""
		c.configPath = ""
	}
	return nil
}

// =============================================================================
// CLI Execution Helper
// =============================================================================

// runCommand executes a platformctl command and returns JSON output.
// It prepends --output json and --config/--context flags so every invocation
// connects to the test daemon rather than the system default socket.
func (c *SDNCLIAdapter) runCommand(ctx context.Context, args ...string) ([]byte, error) {
	fullArgs := []string{"--output", "json"}
	if c.configPath != "" {
		fullArgs = append(fullArgs, "--config", c.configPath, "--context", "integration-test")
	}
	fullArgs = append(fullArgs, args...)

	cmd := exec.CommandContext(ctx, c.binaryPath, fullArgs...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("command %q failed: %w; stderr: %s", args[0], err, stderr.String())
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

// CreatePool creates a new IPAM pool via CLI.
func (c *SDNCLIAdapter) CreatePool(ctx context.Context, req IPAMPoolCreateRequest) (*IPAMPoolEntry, error) {
	args := []string{"sdn", "ipam", "pool", "create",
		"--name", req.Name,
		"--cidr", req.CIDR,
	}
	if req.ID != "" {
		args = append(args, "--id", req.ID)
	}
	if req.Gateway != "" {
		args = append(args, "--gateway", req.Gateway)
	}
	if req.Zone != "" {
		args = append(args, "--zone", req.Zone)
	}
	if req.Description != "" {
		args = append(args, "--description", req.Description)
	}
	if req.LeaseDuration > 0 {
		args = append(args, "--lease-seconds", fmt.Sprintf("%d", int64(req.LeaseDuration.Seconds())))
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var entry cliIPAMPoolEntry
	if err := json.Unmarshal(output, &entry); err != nil {
		return nil, fmt.Errorf("failed to parse created pool: %w", err)
	}

	return entry.toEntry(), nil
}

// GetPool retrieves an IPAM pool by ID via CLI.
func (c *SDNCLIAdapter) GetPool(ctx context.Context, poolID string) (*IPAMPoolEntry, error) {
	output, err := c.runCommand(ctx, "sdn", "ipam", "pool", "get", "--id", poolID)
	if err != nil {
		return nil, err
	}

	var entry cliIPAMPoolEntry
	if err := json.Unmarshal(output, &entry); err != nil {
		return nil, fmt.Errorf("failed to parse pool: %w", err)
	}

	return entry.toEntry(), nil
}

// UpdatePool updates mutable fields of an IPAM pool via CLI.
func (c *SDNCLIAdapter) UpdatePool(ctx context.Context, poolID string, req IPAMPoolUpdateRequest) (*IPAMPoolEntry, error) {
	args := []string{"sdn", "ipam", "pool", "update", "--id", poolID}
	if req.Name != "" {
		args = append(args, "--name", req.Name)
	}
	if req.Gateway != "" {
		args = append(args, "--gateway", req.Gateway)
	}
	if req.Zone != "" {
		args = append(args, "--zone", req.Zone)
	}
	if req.Description != "" {
		args = append(args, "--description", req.Description)
	}
	if req.LeaseDuration > 0 {
		args = append(args, "--lease-seconds", fmt.Sprintf("%d", int64(req.LeaseDuration.Seconds())))
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var entry cliIPAMPoolEntry
	if err := json.Unmarshal(output, &entry); err != nil {
		return nil, fmt.Errorf("failed to parse updated pool: %w", err)
	}

	return entry.toEntry(), nil
}

// DeletePool removes an IPAM pool by ID via CLI.
func (c *SDNCLIAdapter) DeletePool(ctx context.Context, poolID string) error {
	_, err := c.runCommand(ctx, "sdn", "ipam", "pool", "delete", "--id", poolID)
	return err
}

// ListPools returns all IPAM pools, optionally filtered by zone, via CLI.
func (c *SDNCLIAdapter) ListPools(ctx context.Context, zone string) (*IPAMPoolListResponse, error) {
	args := []string{"sdn", "ipam", "pool", "list"}
	if zone != "" {
		args = append(args, "--zone", zone)
	}
	output, err := c.runCommand(ctx, args...)
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
	Zone             string   `json:"zone"`
	Description      string   `json:"description"`
	TotalIPs         int64    `json:"total_ips"`
	AllocatedIPs     int64    `json:"allocated_ips"`
	AvailableIPs     int64    `json:"available_ips"`
	UtilizationPct   float64  `json:"utilization_pct"`
	DNS              []string `json:"dns"`
	LeaseDurationSec int64    `json:"lease_duration_sec"`
}

func (e *cliIPAMPoolEntry) toEntry() *IPAMPoolEntry {
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
		LeaseDuration:  time.Duration(e.LeaseDurationSec) * time.Second,
	}
}

func (r *cliIPAMPoolListResponse) toResponse() *IPAMPoolListResponse {
	pools := make([]IPAMPoolEntry, 0, len(r.Pools))
	for _, p := range r.Pools {
		pools = append(pools, *p.toEntry())
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

// =============================================================================
// Network Zone Operations
// =============================================================================

// cliNetworkZoneConfig mirrors the JSON output of platformv1.NetworkZoneConfig.
type cliNetworkZoneConfig struct {
	Name             string `json:"name,omitempty"`
	InternetIngress  bool   `json:"internet_ingress,omitempty"`
	Isolate          bool   `json:"isolate,omitempty"`
	IsolatePerTenant bool   `json:"isolate_per_tenant,omitempty"`
	Oob              bool   `json:"oob,omitempty"`
	LifecycleRole    string `json:"lifecycle_role,omitempty"`
}

// cliNetworkZone mirrors the JSON output of platformv1.NetworkZone.
type cliNetworkZone struct {
	Config          *cliNetworkZoneConfig `json:"config,omitempty"`
	RestartRequired bool                  `json:"restart_required,omitempty"`
	CreatedAt       *cliTimestamp         `json:"created_at,omitempty"`
	UpdatedAt       *cliTimestamp         `json:"updated_at,omitempty"`
}

// cliTimestamp mirrors google.protobuf.Timestamp JSON shape.
type cliTimestamp struct {
	Seconds int64 `json:"seconds,omitempty"`
	Nanos   int32 `json:"nanos,omitempty"`
}

func (t *cliTimestamp) AsTime() time.Time {
	if t == nil {
		return time.Time{}
	}
	return time.Unix(t.Seconds, int64(t.Nanos))
}

func (z *cliNetworkZone) toEntry() *ZoneEntry {
	entry := &ZoneEntry{RestartRequired: z.RestartRequired}
	if z.Config != nil {
		entry.Name = z.Config.Name
		entry.InternetIngress = z.Config.InternetIngress
		entry.Isolate = z.Config.Isolate
		entry.IsolatePerTenant = z.Config.IsolatePerTenant
		entry.OOB = z.Config.Oob
		entry.LifecycleRole = z.Config.LifecycleRole
	}
	entry.CreatedAt = z.CreatedAt.AsTime()
	entry.UpdatedAt = z.UpdatedAt.AsTime()
	return entry
}

// CreateZone creates a new network trust zone via CLI.
func (c *SDNCLIAdapter) CreateZone(ctx context.Context, req ZoneCreateRequest) (*ZoneEntry, error) {
	args := []string{"sdn", "zone", "create", "--name", req.Name}
	if req.InternetIngress {
		args = append(args, "--internet-ingress")
	}
	if req.Isolate {
		args = append(args, "--isolate")
	}
	if req.IsolatePerTenant {
		args = append(args, "--isolate-per-tenant")
	}
	if req.OOB {
		args = append(args, "--oob")
	}
	if req.LifecycleRole != "" {
		args = append(args, "--lifecycle-role", req.LifecycleRole)
	}
	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}
	var z cliNetworkZone
	if err := json.Unmarshal(output, &z); err != nil {
		return nil, fmt.Errorf("failed to parse zone create response: %w", err)
	}
	return z.toEntry(), nil
}

// UpdateZone updates an existing network trust zone via CLI.
func (c *SDNCLIAdapter) UpdateZone(ctx context.Context, name string, req ZoneUpdateRequest) (*ZoneEntry, error) {
	args := []string{"sdn", "zone", "update", "--name", name}
	if req.InternetIngress {
		args = append(args, "--internet-ingress")
	}
	if req.Isolate {
		args = append(args, "--isolate")
	}
	if req.IsolatePerTenant {
		args = append(args, "--isolate-per-tenant")
	}
	if req.OOB {
		args = append(args, "--oob")
	}
	if req.LifecycleRole != "" {
		args = append(args, "--lifecycle-role", req.LifecycleRole)
	}
	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}
	var z cliNetworkZone
	if err := json.Unmarshal(output, &z); err != nil {
		return nil, fmt.Errorf("failed to parse zone update response: %w", err)
	}
	return z.toEntry(), nil
}

// DeleteZone deletes a network trust zone via CLI.
// The CLI outputs a human-readable message rather than JSON for delete; always returns false, nil on success.
func (c *SDNCLIAdapter) DeleteZone(ctx context.Context, name string) (bool, error) {
	_, err := c.runCommand(ctx, "sdn", "zone", "delete", "--name", name)
	if err != nil {
		return false, err
	}
	// CLI does not output structured JSON for delete — treat success as non-restart.
	return false, nil
}

// ListZones returns all network trust zones via CLI.
func (c *SDNCLIAdapter) ListZones(ctx context.Context, lifecycleRole string) (*ZoneListResponse, error) {
	args := []string{"sdn", "zone", "list"}
	if lifecycleRole != "" {
		args = append(args, "--lifecycle-role", lifecycleRole)
	}
	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}
	var zones []cliNetworkZone
	if err := json.Unmarshal(output, &zones); err != nil {
		return nil, fmt.Errorf("failed to parse zone list response: %w", err)
	}
	entries := make([]ZoneEntry, 0, len(zones))
	for _, z := range zones {
		entries = append(entries, *z.toEntry())
	}
	return &ZoneListResponse{Zones: entries, TotalCount: len(entries)}, nil
}

// AssignZone assigns a network segment to a trust zone via CLI.
func (c *SDNCLIAdapter) AssignZone(ctx context.Context, network string, zoneName string) (bool, error) {
	output, err := c.runCommand(ctx, "sdn", "zone", "assign", "--network", network, "--zone", zoneName)
	if err != nil {
		return false, err
	}
	// The assign command prints "Daemon restart required to rebuild flow
	// matrix." when the assignment changes active policy; that line is the
	// CLI's restart-required contract.
	return strings.Contains(strings.ToLower(string(output)), "restart required"), nil
}

// Ensure SDNCLIAdapter implements SDNTestAdapter interface.
var _ SDNTestAdapter = (*SDNCLIAdapter)(nil)
