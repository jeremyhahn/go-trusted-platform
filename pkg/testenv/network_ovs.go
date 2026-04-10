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

//go:build linux

// SPDX-License-Identifier: Apache-2.0

package testenv

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netlink"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
)

// OVSIsolatedNetwork implements IsolatedNetwork using Open vSwitch
// This provides SDN capabilities including programmable flows for policy enforcement
type OVSIsolatedNetwork struct {
	config    *NetworkConfig
	ovsClient *ovs.Client
	nlManager *netlink.Manager
	bridge    *ovs.Bridge
	serverTap string
	clientTap string

	// Phase management
	mu           sync.RWMutex
	portPhases   map[string]*PortPhaseInfo
	provFlowGen  *policy.ProvisioningFlowGenerator
	quarFlowGen  *policy.QuarantineFlowGenerator
	policyEngine policy.PolicyEngine

	// Network options
	opts *OVSNetworkOptions
}

// OVSNetworkOptions holds options for OVS network creation
type OVSNetworkOptions struct {
	// SocketPath is the path to the OVSDB socket
	// Default: /var/run/openvswitch/db.sock
	SocketPath string

	// ServerVLAN is the optional VLAN tag for the server port (0 = no VLAN)
	ServerVLAN uint16

	// ClientVLAN is the optional VLAN tag for the client port (0 = no VLAN)
	ClientVLAN uint16

	// EnableFlowControl enables default flow rules for the bridge
	EnableFlowControl bool

	// ProvisioningVLAN is the VLAN for provisioning ports
	ProvisioningVLAN uint16

	// ProductionVLAN is the default VLAN for production ports
	ProductionVLAN uint16

	// QuarantineVLAN is the VLAN for quarantined ports
	QuarantineVLAN uint16

	// PolicyEngine is the SDN policy engine for flow management
	PolicyEngine policy.PolicyEngine
}

// DefaultOVSSocketPath is the default path to the OVSDB socket
const DefaultOVSSocketPath = "/var/run/openvswitch/db.sock"

// DefaultOVSNetworkOptions returns default OVS network options
func DefaultOVSNetworkOptions() *OVSNetworkOptions {
	return &OVSNetworkOptions{
		SocketPath:        DefaultOVSSocketPath,
		ServerVLAN:        0,
		ClientVLAN:        0,
		EnableFlowControl: false,
		ProvisioningVLAN:  100,
		ProductionVLAN:    200,
		QuarantineVLAN:    300,
	}
}

// NewOVSIsolatedNetwork creates a new OVS-based isolated network
func NewOVSIsolatedNetwork(cfg *NetworkConfig, opts *OVSNetworkOptions) (*OVSIsolatedNetwork, error) {
	if cfg == nil {
		cfg = DefaultNetworkConfig()
	}
	if opts == nil {
		opts = DefaultOVSNetworkOptions()
	}

	// Check if OVS is available
	if _, err := os.Stat(opts.SocketPath); err != nil {
		return nil, fmt.Errorf("OVS socket not found at %s: %w", opts.SocketPath, err)
	}

	// Create OVS client
	ovsClient, err := ovs.NewClient(opts.SocketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create OVS client: %w", err)
	}

	network := &OVSIsolatedNetwork{
		config:     cfg,
		ovsClient:  ovsClient,
		nlManager:  netlink.NewManager(),
		portPhases: make(map[string]*PortPhaseInfo),
		opts:       opts,
	}

	// Initialize phase tracking
	network.initPhaseTracking()

	return network, nil
}

// Setup creates the OVS-based isolated network
func (n *OVSIsolatedNetwork) Setup() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := n.config.Validate(); err != nil {
		return fmt.Errorf("invalid network config: %w", err)
	}

	// Connect to OVSDB
	if err := n.ovsClient.Connect(ctx); err != nil {
		return fmt.Errorf("failed to connect to OVSDB: %w", err)
	}

	// Create OVS bridge
	if err := n.createOVSBridge(ctx); err != nil {
		n.Cleanup()
		return fmt.Errorf("failed to create OVS bridge: %w", err)
	}

	// Create and attach server TAP
	if err := n.createOVSTap(ctx, n.config.ServerTapName, &n.serverTap); err != nil {
		n.Cleanup()
		return fmt.Errorf("failed to create server TAP: %w", err)
	}

	// Create and attach client TAP
	if err := n.createOVSTap(ctx, n.config.ClientTapName, &n.clientTap); err != nil {
		n.Cleanup()
		return fmt.Errorf("failed to create client TAP: %w", err)
	}

	// Assign IP to bridge for gateway
	if err := n.assignBridgeIP(); err != nil {
		n.Cleanup()
		return fmt.Errorf("failed to assign bridge IP: %w", err)
	}

	// Enable IP forwarding
	if err := n.enableIPForwarding(); err != nil {
		n.Cleanup()
		return fmt.Errorf("failed to enable IP forwarding: %w", err)
	}

	// Setup NAT rules
	if err := n.setupNAT(); err != nil {
		n.Cleanup()
		return fmt.Errorf("failed to setup NAT: %w", err)
	}

	return nil
}

// createOVSBridge creates an OVS bridge
func (n *OVSIsolatedNetwork) createOVSBridge(ctx context.Context) error {
	// Check if bridge already exists
	existing, _ := n.ovsClient.GetBridge(ctx, n.config.BridgeName)
	if existing != nil {
		// Delete existing bridge
		if err := n.ovsClient.DeleteBridge(ctx, n.config.BridgeName); err != nil {
			return fmt.Errorf("failed to delete existing bridge: %w", err)
		}
	}

	// Create new bridge
	bridge, err := n.ovsClient.CreateBridge(ctx, n.config.BridgeName)
	if err != nil {
		return fmt.Errorf("failed to create bridge: %w", err)
	}
	n.bridge = bridge

	return nil
}

// createOVSTap creates a TAP device and attaches it to the OVS bridge
func (n *OVSIsolatedNetwork) createOVSTap(ctx context.Context, tapName string, tapRef *string) error {
	// Create TAP device using netlink manager
	tapConfig := &netlink.TAPConfig{
		Name:       tapName,
		Owner:      0, // root
		Group:      0, // root
		MultiQueue: false,
		Persist:    true,
		MTU:        1500,
	}

	if err := n.nlManager.CreateTAP(tapConfig); err != nil {
		return fmt.Errorf("failed to create TAP device: %w", err)
	}

	// Bring up the TAP device
	if err := n.nlManager.SetTAPUp(tapName); err != nil {
		n.nlManager.DeleteTAP(tapName)
		return fmt.Errorf("failed to bring up TAP: %w", err)
	}

	// Add TAP as OVS port
	_, err := n.ovsClient.AddPort(ctx, n.config.BridgeName, tapName)
	if err != nil {
		n.nlManager.DeleteTAP(tapName)
		return fmt.Errorf("failed to add TAP to OVS bridge: %w", err)
	}

	*tapRef = tapName

	// Disable checksum offloading for NAT compatibility
	n.disableTapOffload(tapName)

	return nil
}

// assignBridgeIP assigns the gateway IP to the OVS bridge interface
func (n *OVSIsolatedNetwork) assignBridgeIP() error {
	// Wait for the OVS bridge interface to be created by ovs-vswitchd
	// The bridge is created in OVSDB but the kernel interface takes a moment
	fmt.Printf("[OVS] Waiting for bridge interface %s...\n", n.config.BridgeName)
	if err := n.waitForBridgeInterface(); err != nil {
		return fmt.Errorf("bridge interface not ready: %w", err)
	}
	fmt.Printf("[OVS] Bridge interface %s is ready\n", n.config.BridgeName)

	// Flush any existing IP addresses on the bridge to ensure clean state
	fmt.Printf("[OVS] Flushing existing IP addresses on %s\n", n.config.BridgeName)
	flushCmd := exec.Command("ip", "addr", "flush", "dev", n.config.BridgeName)
	flushCmd.Run() // Ignore errors - interface might not have any addresses

	// Use ip command to assign IP to the OVS bridge
	// OVS bridges appear as regular interfaces but need special handling
	addr := fmt.Sprintf("%s/%d", n.config.GatewayIP.String(), maskSize(n.config.Subnet.Mask))
	fmt.Printf("[OVS] Assigning IP %s to bridge %s\n", addr, n.config.BridgeName)
	cmd := exec.Command("ip", "addr", "add", addr, "dev", n.config.BridgeName)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to add address: %w: %s", err, string(output))
	}
	fmt.Printf("[OVS] IP address assigned successfully\n")

	// Bring up the bridge interface
	fmt.Printf("[OVS] Bringing up bridge %s\n", n.config.BridgeName)
	cmd = exec.Command("ip", "link", "set", n.config.BridgeName, "up")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to bring up bridge: %w: %s", err, string(output))
	}
	fmt.Printf("[OVS] Bridge %s is now UP\n", n.config.BridgeName)

	// Small delay to ensure kernel state is stable
	time.Sleep(100 * time.Millisecond)

	// Verify the bridge is actually up with the correct IP
	verifyCmd := exec.Command("ip", "addr", "show", n.config.BridgeName)
	if output, err := verifyCmd.CombinedOutput(); err == nil {
		fmt.Printf("[OVS] Bridge status:\n%s\n", string(output))
	}

	return nil
}

// waitForBridgeInterface waits for the OVS bridge kernel interface to appear
func (n *OVSIsolatedNetwork) waitForBridgeInterface() error {
	// Wait up to 5 seconds for the interface to appear
	for i := 0; i < 50; i++ {
		// Check if interface exists using ip link
		cmd := exec.Command("ip", "link", "show", n.config.BridgeName)
		if err := cmd.Run(); err == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for bridge interface %s", n.config.BridgeName)
}

// enableIPForwarding enables IPv4 forwarding
func (n *OVSIsolatedNetwork) enableIPForwarding() error {
	return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644)
}

// setupNAT configures iptables rules for NAT using direct command execution
// NOTE: We use exec.Command instead of go-iptables library because the library
// has compatibility issues with iptables-nft on some systems where InsertUnique
// silently fails to add rules.
// IMPORTANT: We use iptables-legacy because Docker uses legacy tables and we need
// our rules to be in the same chain for proper NAT/forwarding. The iptables-nft
// backend uses different internal tables that don't interact with legacy rules.
func (n *OVSIsolatedNetwork) setupNAT() error {
	subnet := n.config.Subnet.String()
	bridge := n.config.BridgeName

	// Detect which iptables to use - prefer legacy if available since Docker uses it
	iptablesCmd := "iptables-legacy"
	if _, err := exec.LookPath("iptables-legacy"); err != nil {
		iptablesCmd = "iptables"
	}

	fmt.Printf("[OVS] Setting up NAT rules for subnet %s, bridge %s (using %s)\n", subnet, bridge, iptablesCmd)

	// Show current FORWARD chain policy and rules for debugging
	fmt.Printf("[OVS] Current FORWARD chain:\n")
	debugCmd := exec.Command(iptablesCmd, "-L", "FORWARD", "-n", "-v", "--line-numbers")
	if output, err := debugCmd.CombinedOutput(); err == nil {
		fmt.Printf("%s\n", string(output))
	}

	// Show current routing table for debugging
	fmt.Printf("[OVS] Current routing table:\n")
	if routeOutput, err := exec.Command("ip", "route").CombinedOutput(); err == nil {
		fmt.Printf("%s\n", string(routeOutput))
	}

	// Helper function to run iptables commands
	runIptables := func(args ...string) error {
		cmd := exec.Command(iptablesCmd, args...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s %v failed: %w: %s", iptablesCmd, args, err, string(output))
		}
		return nil
	}

	// Check if rule exists before adding
	ruleExists := func(args ...string) bool {
		checkArgs := append([]string{"-C"}, args[1:]...)
		cmd := exec.Command(iptablesCmd, checkArgs...)
		return cmd.Run() == nil
	}

	// Allow forwarding within bridge
	forwardArgs := []string{"-I", "FORWARD", "1", "-i", bridge, "-o", bridge, "-j", "ACCEPT"}
	if !ruleExists(forwardArgs...) {
		fmt.Printf("[OVS] Adding FORWARD rule: -i %s -o %s -j ACCEPT\n", bridge, bridge)
		if err := runIptables(forwardArgs...); err != nil {
			return fmt.Errorf("failed to add bridge-to-bridge forward rule: %w", err)
		}
	}

	// Allow forwarding from bridge to outside
	forwardArgs = []string{"-I", "FORWARD", "1", "-i", bridge, "!", "-o", bridge, "-j", "ACCEPT"}
	if !ruleExists(forwardArgs...) {
		fmt.Printf("[OVS] Adding FORWARD rule: -i %s ! -o %s -j ACCEPT\n", bridge, bridge)
		if err := runIptables(forwardArgs...); err != nil {
			return fmt.Errorf("failed to add bridge-to-outside forward rule: %w", err)
		}
	}

	// Allow return traffic
	forwardArgs = []string{"-I", "FORWARD", "1", "-o", bridge, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"}
	if !ruleExists(forwardArgs...) {
		fmt.Printf("[OVS] Adding FORWARD rule: -o %s -m state --state RELATED,ESTABLISHED -j ACCEPT\n", bridge)
		if err := runIptables(forwardArgs...); err != nil {
			return fmt.Errorf("failed to add return traffic forward rule: %w", err)
		}
	}

	// NAT rule (MASQUERADE)
	natArgs := []string{"-t", "nat", "-I", "POSTROUTING", "1", "-s", subnet, "!", "-o", bridge, "-j", "MASQUERADE"}
	checkNatArgs := []string{"-t", "nat", "-C", "POSTROUTING", "-s", subnet, "!", "-o", bridge, "-j", "MASQUERADE"}
	checkCmd := exec.Command(iptablesCmd, checkNatArgs...)
	if checkCmd.Run() != nil {
		fmt.Printf("[OVS] Adding NAT POSTROUTING rule: -s %s ! -o %s -j MASQUERADE\n", subnet, bridge)
		if err := runIptables(natArgs...); err != nil {
			return fmt.Errorf("failed to add MASQUERADE rule: %w", err)
		}
	}

	// Also try nftables if available (some systems use nft even when iptables-legacy is present)
	if _, err := exec.LookPath("nft"); err == nil {
		fmt.Printf("[OVS] Adding nftables rules as fallback...\n")
		n.setupNFTablesNAT(subnet, bridge)
	}

	// Verify the rules were added
	fmt.Printf("[OVS] Verifying FORWARD rules after setup:\n")
	verifyFwdCmd := exec.Command(iptablesCmd, "-L", "FORWARD", "-n", "-v", "--line-numbers")
	if output, _ := verifyFwdCmd.CombinedOutput(); len(output) > 0 {
		fmt.Printf("%s\n", string(output))
	}

	fmt.Printf("[OVS] Verifying NAT rules:\n")
	verifyCmd := exec.Command(iptablesCmd, "-t", "nat", "-L", "POSTROUTING", "-n", "-v")
	output, _ := verifyCmd.CombinedOutput()
	fmt.Printf("%s\n", string(output))

	fmt.Printf("[OVS] NAT rules setup complete\n")
	return nil
}

// setupNFTablesNAT adds nftables rules as a fallback for systems where iptables-legacy
// doesn't work properly (e.g., systems with nftables as the primary firewall)
func (n *OVSIsolatedNetwork) setupNFTablesNAT(subnet, bridge string) {
	// Create the nat table and chains if they don't exist
	nftCmds := [][]string{
		{"add", "table", "ip", "nat"},
		{"add", "chain", "ip", "nat", "postrouting", "{", "type", "nat", "hook", "postrouting", "priority", "100", ";", "}"},
		{"add", "table", "ip", "filter"},
		{"add", "chain", "ip", "filter", "forward", "{", "type", "filter", "hook", "forward", "priority", "0", ";", "}"},
	}

	for _, args := range nftCmds {
		cmd := exec.Command("nft", args...)
		cmd.Run() // Ignore errors - tables/chains may already exist
	}

	// Add MASQUERADE rule
	masqRule := fmt.Sprintf("add rule ip nat postrouting ip saddr %s oifname != \"%s\" masquerade", subnet, bridge)
	cmd := exec.Command("nft", masqRule)
	if output, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("[OVS] nft masquerade rule (may already exist): %v: %s\n", err, string(output))
	}

	// Add forward rules
	fwdRules := []string{
		fmt.Sprintf("add rule ip filter forward iifname \"%s\" accept", bridge),
		fmt.Sprintf("add rule ip filter forward oifname \"%s\" ct state related,established accept", bridge),
	}

	for _, rule := range fwdRules {
		cmd := exec.Command("nft", rule)
		if output, err := cmd.CombinedOutput(); err != nil {
			fmt.Printf("[OVS] nft forward rule (may already exist): %v: %s\n", err, string(output))
		}
	}

	// Show nftables rules for verification
	fmt.Printf("[OVS] nftables nat rules:\n")
	if output, err := exec.Command("nft", "list", "table", "ip", "nat").CombinedOutput(); err == nil {
		fmt.Printf("%s\n", string(output))
	}
}

// disableTapOffload disables checksum offloading on a TAP device
func (n *OVSIsolatedNetwork) disableTapOffload(tapName string) {
	offloads := []string{"tx", "rx", "sg", "tso", "gso", "gro"}
	for _, offload := range offloads {
		cmd := exec.Command("ethtool", "-K", tapName, offload, "off")
		cmd.Run() // Ignore errors - some features may not be supported
	}
}

// Cleanup removes all OVS network resources
func (n *OVSIsolatedNetwork) Cleanup() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var lastErr error

	// Detect which iptables to use - must match setupNAT
	iptablesCmd := "iptables-legacy"
	if _, err := exec.LookPath("iptables-legacy"); err != nil {
		iptablesCmd = "iptables"
	}

	// Remove NAT rules using exec.Command for consistency with setupNAT
	subnet := n.config.Subnet.String()
	bridge := n.config.BridgeName

	// Remove MASQUERADE rule
	exec.Command(iptablesCmd, "-t", "nat", "-D", "POSTROUTING",
		"-s", subnet, "!", "-o", bridge, "-j", "MASQUERADE").Run()
	// Remove FORWARD rules
	exec.Command(iptablesCmd, "-D", "FORWARD",
		"-i", bridge, "-o", bridge, "-j", "ACCEPT").Run()
	exec.Command(iptablesCmd, "-D", "FORWARD",
		"-i", bridge, "!", "-o", bridge, "-j", "ACCEPT").Run()
	exec.Command(iptablesCmd, "-D", "FORWARD",
		"-o", bridge, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT").Run()

	// Remove server TAP from OVS and delete
	if n.serverTap != "" {
		n.ovsClient.DeletePort(ctx, n.config.BridgeName, n.serverTap)
		n.nlManager.DeleteTAP(n.serverTap)
	}

	// Remove client TAP from OVS and delete
	if n.clientTap != "" {
		n.ovsClient.DeletePort(ctx, n.config.BridgeName, n.clientTap)
		n.nlManager.DeleteTAP(n.clientTap)
	}

	// Delete OVS bridge
	if err := n.ovsClient.DeleteBridge(ctx, n.config.BridgeName); err != nil {
		lastErr = fmt.Errorf("failed to delete OVS bridge: %w", err)
	}

	// Disconnect from OVSDB
	n.ovsClient.Disconnect()

	return lastErr
}

// Config returns the network configuration
func (n *OVSIsolatedNetwork) Config() *NetworkConfig {
	return n.config
}

// ServerTapName returns the server TAP device name
func (n *OVSIsolatedNetwork) ServerTapName() string {
	return n.config.ServerTapName
}

// ClientTapName returns the client TAP device name
func (n *OVSIsolatedNetwork) ClientTapName() string {
	return n.config.ClientTapName
}

// EnsureRules verifies and re-applies NAT/forwarding rules if needed.
// This is used when reusing an existing network (e.g., --client-only mode)
// to ensure internet access works properly.
func (n *OVSIsolatedNetwork) EnsureRules() error {
	// Enable IP forwarding (idempotent)
	if err := n.enableIPForwarding(); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %w", err)
	}

	// Re-apply NAT rules (InsertUnique is idempotent)
	if err := n.setupNAT(); err != nil {
		return fmt.Errorf("failed to setup NAT rules: %w", err)
	}

	return nil
}

// OVSClient returns the OVS client for advanced operations
func (n *OVSIsolatedNetwork) OVSClient() *ovs.Client {
	return n.ovsClient
}

// SetServerVLAN sets the VLAN tag for the server port
func (n *OVSIsolatedNetwork) SetServerVLAN(ctx context.Context, vlan uint16) error {
	if n.serverTap == "" {
		return fmt.Errorf("server TAP not created")
	}
	return n.ovsClient.SetPortVLAN(ctx, n.serverTap, int64(vlan))
}

// SetClientVLAN sets the VLAN tag for the client port
func (n *OVSIsolatedNetwork) SetClientVLAN(ctx context.Context, vlan uint16) error {
	if n.clientTap == "" {
		return fmt.Errorf("client TAP not created")
	}
	return n.ovsClient.SetPortVLAN(ctx, n.clientTap, int64(vlan))
}

// AddFlow adds an OpenFlow rule to the bridge
func (n *OVSIsolatedNetwork) AddFlow(ctx context.Context, flow *ovs.FlowMod) error {
	return n.ovsClient.AddFlow(ctx, n.config.BridgeName, flow)
}

// DeleteFlow removes an OpenFlow rule from the bridge
// The match string should specify which flows to delete (e.g., "in_port=1")
func (n *OVSIsolatedNetwork) DeleteFlow(ctx context.Context, match string) error {
	return n.ovsClient.DeleteFlow(ctx, n.config.BridgeName, match)
}

// IsOVSAvailable checks if OVS is installed and running
func IsOVSAvailable() bool {
	// Check if OVSDB socket exists
	if _, err := os.Stat(DefaultOVSSocketPath); err != nil {
		return false
	}

	// Check if ovs-vsctl command is available
	if _, err := exec.LookPath("ovs-vsctl"); err != nil {
		return false
	}

	return true
}

// maskSize returns the prefix length from a net.IPMask
func maskSize(mask net.IPMask) int {
	ones, _ := mask.Size()
	return ones
}

// Phase Management Methods

// initPhaseTracking initializes the port phase tracking
func (n *OVSIsolatedNetwork) initPhaseTracking() {
	n.mu.Lock()
	defer n.mu.Unlock()

	// Initialize flow generators with default configs
	n.provFlowGen = policy.NewProvisioningFlowGenerator(&policy.ProvisioningFlowConfig{
		ProvisioningVLAN: n.opts.ProvisioningVLAN,
		Gateway:          n.config.GatewayIP,
		AllowICMP:        true,
	})

	n.quarFlowGen = policy.NewQuarantineFlowGenerator(&policy.QuarantineFlowConfig{
		QuarantineVLAN: n.opts.QuarantineVLAN,
		Gateway:        n.config.GatewayIP,
	})

	// Initialize policy engine if provided
	n.policyEngine = n.opts.PolicyEngine
}

// SetPhase transitions a port to a specific network phase
func (n *OVSIsolatedNetwork) SetPhase(portID string, phase NetworkPhase) error {
	if portID == "" {
		return fmt.Errorf("port ID cannot be empty")
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	// Get or create port phase info
	info, exists := n.portPhases[portID]
	if !exists {
		info = &PortPhaseInfo{
			Phase:      NetworkPhaseUnconnected,
			LastChange: time.Now(),
		}
		n.portPhases[portID] = info
	}

	// Update phase info
	oldPhase := info.Phase
	info.Phase = phase
	info.LastChange = time.Now()

	// Set VLAN based on phase
	switch phase {
	case NetworkPhaseProvisioning:
		info.VLAN = n.opts.ProvisioningVLAN
	case NetworkPhaseProduction:
		info.VLAN = n.opts.ProductionVLAN
	case NetworkPhaseQuarantine:
		info.VLAN = n.opts.QuarantineVLAN
	case NetworkPhaseBlocked, NetworkPhaseUnconnected:
		info.VLAN = 0
	}

	// Install appropriate flows based on phase
	if err := n.installPhaseFlows(portID, phase); err != nil {
		// Rollback phase change on error
		info.Phase = oldPhase
		return fmt.Errorf("failed to install phase flows: %w", err)
	}

	// Set VLAN on the port
	if info.VLAN > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := n.ovsClient.SetPortVLAN(ctx, portID, int64(info.VLAN)); err != nil {
			// Rollback on error
			info.Phase = oldPhase
			return fmt.Errorf("failed to set VLAN: %w", err)
		}
	}

	return nil
}

// GetPhase returns the current phase for a port
func (n *OVSIsolatedNetwork) GetPhase(portID string) NetworkPhase {
	n.mu.RLock()
	defer n.mu.RUnlock()

	if info, exists := n.portPhases[portID]; exists {
		return info.Phase
	}

	return NetworkPhaseUnconnected
}

// GetPhaseInfo returns detailed phase information for a port
func (n *OVSIsolatedNetwork) GetPhaseInfo(portID string) (*PortPhaseInfo, error) {
	n.mu.RLock()
	defer n.mu.RUnlock()

	info, exists := n.portPhases[portID]
	if !exists {
		return nil, fmt.Errorf("port %s not found", portID)
	}

	// Return a copy to prevent external modifications
	infoCopy := *info
	return &infoCopy, nil
}

// TransitionToProduction moves a port from provisioning to production
func (n *OVSIsolatedNetwork) TransitionToProduction(portID string, cert *x509.Certificate) error {
	if portID == "" {
		return fmt.Errorf("port ID cannot be empty")
	}

	if cert == nil {
		return fmt.Errorf("certificate cannot be nil")
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	// Validate current phase is Provisioning
	info, exists := n.portPhases[portID]
	if !exists {
		return fmt.Errorf("port %s not found", portID)
	}

	if info.Phase != NetworkPhaseProvisioning {
		return fmt.Errorf("port %s is not in provisioning phase (current: %s)", portID, info.Phase)
	}

	// Store certificate
	info.Certificate = cert

	// Use policy engine if available
	if n.policyEngine != nil {
		if err := n.policyEngine.AuthenticatePort(portID, cert); err != nil {
			return fmt.Errorf("policy engine authentication failed: %w", err)
		}
	}

	// Update phase to production
	info.Phase = NetworkPhaseProduction
	info.VLAN = n.opts.ProductionVLAN
	info.LastChange = time.Now()

	// Apply production flows and VLAN
	if err := n.installPhaseFlows(portID, NetworkPhaseProduction); err != nil {
		// Rollback on error
		info.Phase = NetworkPhaseProvisioning
		info.VLAN = n.opts.ProvisioningVLAN
		return fmt.Errorf("failed to install production flows: %w", err)
	}

	// Set production VLAN
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := n.ovsClient.SetPortVLAN(ctx, portID, int64(info.VLAN)); err != nil {
		// Rollback on error
		info.Phase = NetworkPhaseProvisioning
		info.VLAN = n.opts.ProvisioningVLAN
		return fmt.Errorf("failed to set production VLAN: %w", err)
	}

	return nil
}

// QuarantinePort moves a port to quarantine VLAN
func (n *OVSIsolatedNetwork) QuarantinePort(portID string, reason string) error {
	if portID == "" {
		return fmt.Errorf("port ID cannot be empty")
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	// Get or create port phase info
	info, exists := n.portPhases[portID]
	if !exists {
		info = &PortPhaseInfo{
			Phase:      NetworkPhaseUnconnected,
			LastChange: time.Now(),
		}
		n.portPhases[portID] = info
	}

	// Update phase to quarantine
	oldPhase := info.Phase
	info.Phase = NetworkPhaseQuarantine
	info.VLAN = n.opts.QuarantineVLAN
	info.Reason = reason
	info.LastChange = time.Now()

	// Use policy engine if available
	if n.policyEngine != nil {
		if err := n.policyEngine.SetPortState(portID, policy.PortStateQuarantined); err != nil {
			info.Phase = oldPhase
			return fmt.Errorf("policy engine failed to quarantine port: %w", err)
		}
	}

	// Install quarantine flows
	if err := n.installPhaseFlows(portID, NetworkPhaseQuarantine); err != nil {
		info.Phase = oldPhase
		return fmt.Errorf("failed to install quarantine flows: %w", err)
	}

	// Set quarantine VLAN
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := n.ovsClient.SetPortVLAN(ctx, portID, int64(info.VLAN)); err != nil {
		info.Phase = oldPhase
		return fmt.Errorf("failed to set quarantine VLAN: %w", err)
	}

	return nil
}

// UnquarantinePort moves a port back to production
func (n *OVSIsolatedNetwork) UnquarantinePort(portID string) error {
	if portID == "" {
		return fmt.Errorf("port ID cannot be empty")
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	info, exists := n.portPhases[portID]
	if !exists {
		return fmt.Errorf("port %s not found", portID)
	}

	if info.Phase != NetworkPhaseQuarantine {
		return fmt.Errorf("port %s is not quarantined (current: %s)", portID, info.Phase)
	}

	// Validate certificate still exists
	if info.Certificate == nil {
		return fmt.Errorf("cannot unquarantine port %s: no certificate available", portID)
	}

	// Update phase to production
	info.Phase = NetworkPhaseProduction
	info.VLAN = n.opts.ProductionVLAN
	info.Reason = ""
	info.LastChange = time.Now()

	// Use policy engine if available
	if n.policyEngine != nil {
		if err := n.policyEngine.AuthenticatePort(portID, info.Certificate); err != nil {
			info.Phase = NetworkPhaseQuarantine
			info.VLAN = n.opts.QuarantineVLAN
			return fmt.Errorf("policy engine authentication failed: %w", err)
		}
	}

	// Install production flows
	if err := n.installPhaseFlows(portID, NetworkPhaseProduction); err != nil {
		info.Phase = NetworkPhaseQuarantine
		info.VLAN = n.opts.QuarantineVLAN
		return fmt.Errorf("failed to install production flows: %w", err)
	}

	// Set production VLAN
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := n.ovsClient.SetPortVLAN(ctx, portID, int64(info.VLAN)); err != nil {
		info.Phase = NetworkPhaseQuarantine
		info.VLAN = n.opts.QuarantineVLAN
		return fmt.Errorf("failed to set production VLAN: %w", err)
	}

	return nil
}

// BlockPort completely blocks a port
func (n *OVSIsolatedNetwork) BlockPort(portID string, reason string) error {
	if portID == "" {
		return fmt.Errorf("port ID cannot be empty")
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	// Get or create port phase info
	info, exists := n.portPhases[portID]
	if !exists {
		info = &PortPhaseInfo{
			Phase:      NetworkPhaseUnconnected,
			LastChange: time.Now(),
		}
		n.portPhases[portID] = info
	}

	// Update phase to blocked
	info.Phase = NetworkPhaseBlocked
	info.VLAN = 0
	info.Reason = reason
	info.LastChange = time.Now()

	// Use policy engine if available
	if n.policyEngine != nil {
		if err := n.policyEngine.SetPortState(portID, policy.PortStateBlocked); err != nil {
			return fmt.Errorf("policy engine failed to block port: %w", err)
		}
	}

	// Install block flows
	if err := n.installPhaseFlows(portID, NetworkPhaseBlocked); err != nil {
		return fmt.Errorf("failed to install block flows: %w", err)
	}

	return nil
}

// UnblockPort unblocks a port and returns it to provisioning
func (n *OVSIsolatedNetwork) UnblockPort(portID string) error {
	if portID == "" {
		return fmt.Errorf("port ID cannot be empty")
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	info, exists := n.portPhases[portID]
	if !exists {
		return fmt.Errorf("port %s not found", portID)
	}

	if info.Phase != NetworkPhaseBlocked {
		return fmt.Errorf("port %s is not blocked (current: %s)", portID, info.Phase)
	}

	// Update phase to provisioning
	info.Phase = NetworkPhaseProvisioning
	info.VLAN = n.opts.ProvisioningVLAN
	info.Reason = ""
	info.Certificate = nil // Clear any old certificate
	info.LastChange = time.Now()

	// Use policy engine if available
	if n.policyEngine != nil {
		if err := n.policyEngine.SetPortState(portID, policy.PortStateProvisioning); err != nil {
			info.Phase = NetworkPhaseBlocked
			info.VLAN = 0
			return fmt.Errorf("policy engine failed to unblock port: %w", err)
		}
	}

	// Install provisioning flows
	if err := n.installPhaseFlows(portID, NetworkPhaseProvisioning); err != nil {
		info.Phase = NetworkPhaseBlocked
		info.VLAN = 0
		return fmt.Errorf("failed to install provisioning flows: %w", err)
	}

	// Set provisioning VLAN
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := n.ovsClient.SetPortVLAN(ctx, portID, int64(info.VLAN)); err != nil {
		info.Phase = NetworkPhaseBlocked
		info.VLAN = 0
		return fmt.Errorf("failed to set provisioning VLAN: %w", err)
	}

	return nil
}

// installPhaseFlows installs OpenFlow rules for a phase
func (n *OVSIsolatedNetwork) installPhaseFlows(portID string, phase NetworkPhase) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// First, delete any existing flows for this port
	if err := n.ovsClient.DeleteFlow(ctx, n.config.BridgeName, fmt.Sprintf("in_port=%s", portID)); err != nil {
		// Log but don't fail if no flows exist
		fmt.Printf("[OVS] Warning: failed to delete existing flows for port %s: %v\n", portID, err)
	}

	switch phase {
	case NetworkPhaseProvisioning:
		// Generate provisioning flows
		flows := n.provFlowGen.GenerateFlows(portID, "")
		for _, flow := range flows {
			if err := n.installFlow(ctx, &flow); err != nil {
				return fmt.Errorf("failed to install provisioning flow: %w", err)
			}
		}

	case NetworkPhaseProduction:
		// For production, use policy engine if available, otherwise allow all
		if n.policyEngine != nil {
			// Policy engine will handle production flows
			// This is typically done during TransitionToProduction when
			// the certificate is authenticated
			return nil
		}
		// Default production: allow all traffic on production VLAN
		flow := &policy.FlowRule{
			Table:    0,
			Priority: 1000,
			Match:    fmt.Sprintf("in_port=%s", portID),
			Actions:  "normal",
		}
		if err := n.installFlow(ctx, flow); err != nil {
			return fmt.Errorf("failed to install production flow: %w", err)
		}

	case NetworkPhaseQuarantine:
		// Generate quarantine flows
		flows := n.quarFlowGen.GenerateFlows(portID, "")
		for _, flow := range flows {
			if err := n.installFlow(ctx, &flow); err != nil {
				return fmt.Errorf("failed to install quarantine flow: %w", err)
			}
		}

	case NetworkPhaseBlocked:
		// Block all traffic
		flow := &policy.FlowRule{
			Table:    0,
			Priority: 2000, // High priority to override other rules
			Match:    fmt.Sprintf("in_port=%s", portID),
			Actions:  "drop",
		}
		if err := n.installFlow(ctx, flow); err != nil {
			return fmt.Errorf("failed to install block flow: %w", err)
		}

	case NetworkPhaseUnconnected:
		// No flows needed for unconnected state
		return nil

	default:
		return fmt.Errorf("unknown phase: %v", phase)
	}

	return nil
}

// installFlow is a helper to install a single flow rule
func (n *OVSIsolatedNetwork) installFlow(ctx context.Context, flow *policy.FlowRule) error {
	// Convert policy.FlowRule to OVS flow command
	// For now, we'll use ovs-ofctl directly since we have the match/actions strings
	cmd := exec.CommandContext(ctx, "ovs-ofctl", "add-flow", n.config.BridgeName,
		fmt.Sprintf("table=%d,priority=%d,%s,actions=%s",
			flow.Table, flow.Priority, flow.Match, flow.Actions))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ovs-ofctl add-flow failed: %w: %s", err, string(output))
	}

	return nil
}
