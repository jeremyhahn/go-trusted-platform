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
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"os/exec"
	"time"

	"github.com/vishvananda/netlink"
)

// LinuxIsolatedNetwork implements IsolatedNetwork using Linux netlink and iptables
type LinuxIsolatedNetwork struct {
	config    *NetworkConfig
	bridge    netlink.Link
	serverTap netlink.Link
	clientTap netlink.Link
}

// NewIsolatedNetwork creates a new isolated network for testing
func NewIsolatedNetwork(cfg *NetworkConfig) *LinuxIsolatedNetwork {
	if cfg == nil {
		cfg = DefaultNetworkConfig()
	}
	return &LinuxIsolatedNetwork{config: cfg}
}

// Setup creates the isolated network (bridge, TAPs, NAT)
func (n *LinuxIsolatedNetwork) Setup() error {
	if err := n.config.Validate(); err != nil {
		return fmt.Errorf("invalid network config: %w", err)
	}

	// Create bridge
	if err := n.createBridge(); err != nil {
		return fmt.Errorf("failed to create bridge: %w", err)
	}

	// Create server TAP device
	if err := n.createTap(n.config.ServerTapName, &n.serverTap); err != nil {
		n.Cleanup()
		return fmt.Errorf("failed to create server TAP: %w", err)
	}

	// Create client TAP device
	if err := n.createTap(n.config.ClientTapName, &n.clientTap); err != nil {
		n.Cleanup()
		return fmt.Errorf("failed to create client TAP: %w", err)
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

	// Apply network tuning for reliable NAT traversal
	if err := n.tuneNetworkForNAT(); err != nil {
		n.Cleanup()
		return fmt.Errorf("failed to tune network for NAT: %w", err)
	}

	return nil
}

// createBridge creates the network bridge with gateway IP
func (n *LinuxIsolatedNetwork) createBridge() error {
	// Check if bridge already exists and remove it
	existing, _ := netlink.LinkByName(n.config.BridgeName)
	if existing != nil {
		if err := netlink.LinkDel(existing); err != nil {
			return fmt.Errorf("failed to delete existing bridge: %w", err)
		}
	}

	// Create new bridge
	bridge := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{
			Name: n.config.BridgeName,
		},
	}

	if err := netlink.LinkAdd(bridge); err != nil {
		return fmt.Errorf("failed to add bridge: %w", err)
	}

	// Get the bridge link
	link, err := netlink.LinkByName(n.config.BridgeName)
	if err != nil {
		return fmt.Errorf("failed to get bridge: %w", err)
	}
	n.bridge = link

	// Assign gateway IP address to bridge
	addr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   n.config.GatewayIP,
			Mask: n.config.Subnet.Mask,
		},
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("failed to add address to bridge: %w", err)
	}

	// Bring up the bridge
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to bring up bridge: %w", err)
	}

	return nil
}

// createTap creates a TAP device and attaches it to the bridge
func (n *LinuxIsolatedNetwork) createTap(tapName string, tapLink *netlink.Link) error {
	// Check if TAP already exists and remove it
	existing, _ := netlink.LinkByName(tapName)
	if existing != nil {
		if err := netlink.LinkDel(existing); err != nil {
			return fmt.Errorf("failed to delete existing TAP: %w", err)
		}
	}

	// Create TAP device with VNET_HDR for virtio checksum offload support
	tap := &netlink.Tuntap{
		LinkAttrs: netlink.LinkAttrs{
			Name: tapName,
		},
		Mode:  netlink.TUNTAP_MODE_TAP,
		Flags: netlink.TUNTAP_DEFAULTS | netlink.TUNTAP_NO_PI | netlink.TUNTAP_VNET_HDR,
	}

	if err := netlink.LinkAdd(tap); err != nil {
		return fmt.Errorf("failed to add TAP: %w", err)
	}

	// Get the TAP link
	link, err := netlink.LinkByName(tapName)
	if err != nil {
		return fmt.Errorf("failed to get TAP: %w", err)
	}
	*tapLink = link

	// Attach to bridge
	bridgeLink, ok := n.bridge.(*netlink.Bridge)
	if !ok {
		return fmt.Errorf("bridge is not a netlink.Bridge type")
	}
	if err := netlink.LinkSetMaster(link, bridgeLink); err != nil {
		return fmt.Errorf("failed to attach TAP to bridge: %w", err)
	}

	// Bring up the TAP
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to bring up TAP: %w", err)
	}

	// Disable hardware checksum offloading on the TAP device.
	// This is critical for NAT environments where virtio-net uses software checksums.
	// Without this, outbound packets can have invalid checksums after NAT translation,
	// causing remote servers to RST the connection.
	if err := n.disableTapOffload(tapName); err != nil {
		// Log warning but continue - some systems may not support this
		fmt.Printf("Warning: failed to disable offload on %s: %v\n", tapName, err)
	}

	return nil
}

// disableTapOffload disables checksum offloading on a TAP device using ethtool.
// This fixes "connection reset by peer" issues when using virtio-net through NAT.
func (n *LinuxIsolatedNetwork) disableTapOffload(tapName string) error {
	// Use ethtool to disable TX/RX checksum offload
	// This ensures packets going through NAT have correct checksums
	offloads := []string{
		"tx",  // TX checksum offload
		"rx",  // RX checksum offload
		"sg",  // Scatter-gather (depends on TX offload)
		"tso", // TCP segmentation offload
		"gso", // Generic segmentation offload
		"gro", // Generic receive offload
	}

	for _, offload := range offloads {
		// Try to disable each offload feature
		// ethtool -K <device> <feature> off
		cmd := exec.Command("ethtool", "-K", tapName, offload, "off")
		if err := cmd.Run(); err != nil {
			// Some features may not be supported - that's OK
			continue
		}
	}

	return nil
}

// enableIPForwarding enables IPv4 forwarding in the kernel
func (n *LinuxIsolatedNetwork) enableIPForwarding() error {
	return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644)
}

// tuneNetworkForNAT applies kernel tuning for reliable NAT traversal
func (n *LinuxIsolatedNetwork) tuneNetworkForNAT() error {
	// Enable liberal TCP connection tracking to avoid RST on out-of-window packets
	// This is important for NAT environments where packet reordering can occur
	if err := os.WriteFile("/proc/sys/net/netfilter/nf_conntrack_tcp_be_liberal", []byte("1"), 0644); err != nil {
		// Non-fatal - some systems may not have this sysctl
		fmt.Printf("Warning: failed to set nf_conntrack_tcp_be_liberal: %v\n", err)
	}

	// Disable reverse path filtering on the bridge interface
	// This can cause issues with NAT'd traffic
	rpFilterPath := fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/rp_filter", n.config.BridgeName)
	if err := os.WriteFile(rpFilterPath, []byte("0"), 0644); err != nil {
		// Non-fatal
		fmt.Printf("Warning: failed to disable rp_filter for %s: %v\n", n.config.BridgeName, err)
	}

	return nil
}

// setupNAT configures iptables rules for NAT and forwarding
// Uses iptables-legacy directly to avoid conflicts with iptables-nft
func (n *LinuxIsolatedNetwork) setupNAT() error {
	subnet := n.config.Subnet.String()
	bridge := n.config.BridgeName

	// Detect which iptables to use - prefer legacy if available since Docker uses it
	iptablesCmd := "iptables-legacy"
	if _, err := exec.LookPath("iptables-legacy"); err != nil {
		iptablesCmd = "iptables"
	}

	fmt.Printf("[Network] Setting up NAT rules for subnet %s, bridge %s (using %s)\n", subnet, bridge, iptablesCmd)

	// Show current FORWARD chain policy and rules for debugging
	fmt.Printf("[Network] Current FORWARD chain:\n")
	debugCmd := exec.Command(iptablesCmd, "-L", "FORWARD", "-n", "-v", "--line-numbers")
	if output, err := debugCmd.CombinedOutput(); err == nil {
		fmt.Printf("%s\n", string(output))
	}

	// Show current routing table for debugging
	fmt.Printf("[Network] Current routing table:\n")
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

	// Allow forwarding within bridge (VM to VM communication)
	forwardArgs := []string{"-I", "FORWARD", "1", "-i", bridge, "-o", bridge, "-j", "ACCEPT"}
	if !ruleExists(forwardArgs...) {
		fmt.Printf("[Network] Adding FORWARD rule: -i %s -o %s -j ACCEPT\n", bridge, bridge)
		if err := runIptables(forwardArgs...); err != nil {
			return fmt.Errorf("failed to add bridge-to-bridge forward rule: %w", err)
		}
	}

	// Allow forwarding from bridge to outside (internet access)
	forwardArgs = []string{"-I", "FORWARD", "1", "-i", bridge, "!", "-o", bridge, "-j", "ACCEPT"}
	if !ruleExists(forwardArgs...) {
		fmt.Printf("[Network] Adding FORWARD rule: -i %s ! -o %s -j ACCEPT\n", bridge, bridge)
		if err := runIptables(forwardArgs...); err != nil {
			return fmt.Errorf("failed to add bridge-to-outside forward rule: %w", err)
		}
	}

	// Allow return traffic (responses from internet)
	forwardArgs = []string{"-I", "FORWARD", "1", "-o", bridge, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"}
	if !ruleExists(forwardArgs...) {
		fmt.Printf("[Network] Adding FORWARD rule: -o %s -m state --state RELATED,ESTABLISHED -j ACCEPT\n", bridge)
		if err := runIptables(forwardArgs...); err != nil {
			return fmt.Errorf("failed to add return traffic forward rule: %w", err)
		}
	}

	// NAT rule (MASQUERADE) - translates VM IPs to host IP for outbound traffic
	natArgs := []string{"-t", "nat", "-I", "POSTROUTING", "1", "-s", subnet, "!", "-o", bridge, "-j", "MASQUERADE"}
	checkNatArgs := []string{"-t", "nat", "-C", "POSTROUTING", "-s", subnet, "!", "-o", bridge, "-j", "MASQUERADE"}
	checkCmd := exec.Command(iptablesCmd, checkNatArgs...)
	if checkCmd.Run() != nil {
		fmt.Printf("[Network] Adding NAT POSTROUTING rule: -s %s ! -o %s -j MASQUERADE\n", subnet, bridge)
		if err := runIptables(natArgs...); err != nil {
			return fmt.Errorf("failed to add MASQUERADE rule: %w", err)
		}
	}

	// Add MSS clamping to prevent MTU issues with NAT (non-fatal if fails)
	exec.Command(iptablesCmd, "-t", "mangle", "-A", "FORWARD",
		"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
		"-i", bridge, "-j", "TCPMSS", "--clamp-mss-to-pmtu").Run()
	exec.Command(iptablesCmd, "-t", "mangle", "-A", "FORWARD",
		"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
		"-o", bridge, "-j", "TCPMSS", "--clamp-mss-to-pmtu").Run()

	// Also try nftables if available (some systems use nft even when iptables-legacy is present)
	if _, err := exec.LookPath("nft"); err == nil {
		fmt.Printf("[Network] Adding nftables rules as fallback...\n")
		n.setupNFTablesNAT(subnet, bridge)
	}

	// Verify the rules were added
	fmt.Printf("[Network] Verifying FORWARD rules after setup:\n")
	verifyFwdCmd := exec.Command(iptablesCmd, "-L", "FORWARD", "-n", "-v", "--line-numbers")
	if output, _ := verifyFwdCmd.CombinedOutput(); len(output) > 0 {
		fmt.Printf("%s\n", string(output))
	}

	fmt.Printf("[Network] Verifying NAT rules:\n")
	verifyCmd := exec.Command(iptablesCmd, "-t", "nat", "-L", "POSTROUTING", "-n", "-v")
	output, _ := verifyCmd.CombinedOutput()
	fmt.Printf("%s\n", string(output))

	fmt.Printf("[Network] NAT rules setup complete\n")
	return nil
}

// setupNFTablesNAT adds nftables rules as a fallback for systems where iptables-legacy
// doesn't work properly (e.g., systems with nftables as the primary firewall)
func (n *LinuxIsolatedNetwork) setupNFTablesNAT(subnet, bridge string) {
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
		fmt.Printf("[Network] nft masquerade rule (may already exist): %v: %s\n", err, string(output))
	}

	// Add forward rules
	fwdRules := []string{
		fmt.Sprintf("add rule ip filter forward iifname \"%s\" accept", bridge),
		fmt.Sprintf("add rule ip filter forward oifname \"%s\" ct state related,established accept", bridge),
	}

	for _, rule := range fwdRules {
		cmd := exec.Command("nft", rule)
		if output, err := cmd.CombinedOutput(); err != nil {
			fmt.Printf("[Network] nft forward rule (may already exist): %v: %s\n", err, string(output))
		}
	}

	// Show nftables rules for verification
	fmt.Printf("[Network] nftables nat rules:\n")
	if output, err := exec.Command("nft", "list", "table", "ip", "nat").CombinedOutput(); err == nil {
		fmt.Printf("%s\n", string(output))
	}
}

// Cleanup removes all network resources
func (n *LinuxIsolatedNetwork) Cleanup() error {
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
	// Remove forward rules
	exec.Command(iptablesCmd, "-D", "FORWARD",
		"-i", bridge, "-o", bridge, "-j", "ACCEPT").Run()
	exec.Command(iptablesCmd, "-D", "FORWARD",
		"-i", bridge, "!", "-o", bridge, "-j", "ACCEPT").Run()
	exec.Command(iptablesCmd, "-D", "FORWARD",
		"-o", bridge, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT").Run()
	// Remove MSS clamping rules
	exec.Command(iptablesCmd, "-t", "mangle", "-D", "FORWARD",
		"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
		"-i", bridge, "-j", "TCPMSS", "--clamp-mss-to-pmtu").Run()
	exec.Command(iptablesCmd, "-t", "mangle", "-D", "FORWARD",
		"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
		"-o", bridge, "-j", "TCPMSS", "--clamp-mss-to-pmtu").Run()

	// Delete server TAP device
	if n.serverTap != nil {
		if err := netlink.LinkDel(n.serverTap); err != nil {
			lastErr = fmt.Errorf("failed to delete server TAP: %w", err)
		}
	} else {
		if link, err := netlink.LinkByName(n.config.ServerTapName); err == nil {
			netlink.LinkDel(link)
		}
	}

	// Delete client TAP device
	if n.clientTap != nil {
		if err := netlink.LinkDel(n.clientTap); err != nil {
			lastErr = fmt.Errorf("failed to delete client TAP: %w", err)
		}
	} else {
		if link, err := netlink.LinkByName(n.config.ClientTapName); err == nil {
			netlink.LinkDel(link)
		}
	}

	// Delete bridge
	if n.bridge != nil {
		if err := netlink.LinkDel(n.bridge); err != nil {
			lastErr = fmt.Errorf("failed to delete bridge: %w", err)
		}
	} else {
		if link, err := netlink.LinkByName(n.config.BridgeName); err == nil {
			netlink.LinkDel(link)
		}
	}

	return lastErr
}

// Config returns the network configuration
func (n *LinuxIsolatedNetwork) Config() *NetworkConfig {
	return n.config
}

// ServerTapName returns the TAP device name for the server VM
func (n *LinuxIsolatedNetwork) ServerTapName() string {
	return n.config.ServerTapName
}

// ClientTapName returns the TAP device name for the client VM
func (n *LinuxIsolatedNetwork) ClientTapName() string {
	return n.config.ClientTapName
}

// EnsureRules verifies and re-applies NAT/forwarding rules if needed.
// This is used when reusing an existing network (e.g., --client-only mode)
// to ensure internet access works properly.
func (n *LinuxIsolatedNetwork) EnsureRules() error {
	// Enable IP forwarding (idempotent)
	if err := n.enableIPForwarding(); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %w", err)
	}

	// Re-apply NAT rules (InsertUnique is idempotent)
	if err := n.setupNAT(); err != nil {
		return fmt.Errorf("failed to setup NAT rules: %w", err)
	}

	// Re-apply network tuning
	if err := n.tuneNetworkForNAT(); err != nil {
		return fmt.Errorf("failed to tune network for NAT: %w", err)
	}

	return nil
}

// SetPhase transitions a port to a specific network phase
// Note: This is a stub implementation for Linux bridge. Full implementation requires OVS.
func (n *LinuxIsolatedNetwork) SetPhase(portID string, phase NetworkPhase) error {
	return fmt.Errorf("SetPhase not implemented for LinuxIsolatedNetwork (requires OVS)")
}

// GetPhase returns the current phase for a port
// Note: This is a stub implementation for Linux bridge. Full implementation requires OVS.
func (n *LinuxIsolatedNetwork) GetPhase(portID string) NetworkPhase {
	return NetworkPhaseUnconnected
}

// TransitionToTrusted moves a port from provisioning to the trusted zone
// Note: This is a stub implementation for Linux bridge. Full implementation requires OVS.
func (n *LinuxIsolatedNetwork) TransitionToTrusted(portID string, cert *x509.Certificate) error {
	return fmt.Errorf("TransitionToTrusted not implemented for LinuxIsolatedNetwork (requires OVS)")
}

// QuarantinePort moves a port to quarantine VLAN
// Note: This is a stub implementation for Linux bridge. Full implementation requires OVS.
func (n *LinuxIsolatedNetwork) QuarantinePort(portID string, reason string) error {
	return fmt.Errorf("QuarantinePort not implemented for LinuxIsolatedNetwork (requires OVS)")
}

// UnquarantinePort moves a port back to the trusted zone
// Note: This is a stub implementation for Linux bridge. Full implementation requires OVS.
func (n *LinuxIsolatedNetwork) UnquarantinePort(portID string) error {
	return fmt.Errorf("UnquarantinePort not implemented for LinuxIsolatedNetwork (requires OVS)")
}

// BlockPort completely blocks a port (DROP all traffic)
// Note: This is a stub implementation for Linux bridge. Full implementation requires OVS.
func (n *LinuxIsolatedNetwork) BlockPort(portID string, reason string) error {
	return fmt.Errorf("BlockPort not implemented for LinuxIsolatedNetwork (requires OVS)")
}

// UnblockPort unblocks a port and returns it to provisioning
// Note: This is a stub implementation for Linux bridge. Full implementation requires OVS.
func (n *LinuxIsolatedNetwork) UnblockPort(portID string) error {
	return fmt.Errorf("UnblockPort not implemented for LinuxIsolatedNetwork (requires OVS)")
}

// CleanupStaleResources cleans up any stale network resources from previous runs.
// This should be called before Setup() to ensure a clean state.
func CleanupStaleResources(cfg *NetworkConfig) {
	if cfg == nil {
		cfg = DefaultNetworkConfig()
	}

	// Detect which iptables to use - prefer legacy if available since Docker uses it
	iptablesCmd := "iptables-legacy"
	if _, err := exec.LookPath("iptables-legacy"); err != nil {
		iptablesCmd = "iptables"
	}

	// Clean up iptables rules using direct commands for consistency
	// This ensures we clean up rules in the same tables we add them to
	subnet := cfg.Subnet.String()
	bridge := cfg.BridgeName

	// Remove NAT rule
	exec.Command(iptablesCmd, "-t", "nat", "-D", "POSTROUTING",
		"-s", subnet, "!", "-o", bridge, "-j", "MASQUERADE").Run()
	// Remove FORWARD rules
	exec.Command(iptablesCmd, "-D", "FORWARD",
		"-i", bridge, "-o", bridge, "-j", "ACCEPT").Run()
	exec.Command(iptablesCmd, "-D", "FORWARD",
		"-i", bridge, "!", "-o", bridge, "-j", "ACCEPT").Run()
	exec.Command(iptablesCmd, "-D", "FORWARD",
		"-o", bridge, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT").Run()
	// Remove MSS clamping rules
	exec.Command(iptablesCmd, "-t", "mangle", "-D", "FORWARD",
		"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
		"-i", bridge, "-j", "TCPMSS", "--clamp-mss-to-pmtu").Run()
	exec.Command(iptablesCmd, "-t", "mangle", "-D", "FORWARD",
		"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
		"-o", bridge, "-j", "TCPMSS", "--clamp-mss-to-pmtu").Run()

	// Clean up OVS resources if OVS is available
	// This must be done BEFORE deleting TAP devices via netlink, as OVS manages them
	cleanupOVSResources(cfg)

	// Clean up server TAP device
	if link, err := netlink.LinkByName(cfg.ServerTapName); err == nil {
		netlink.LinkDel(link)
	}

	// Clean up client TAP device
	if link, err := netlink.LinkByName(cfg.ClientTapName); err == nil {
		netlink.LinkDel(link)
	}

	// Clean up bridge (for Linux bridge, not OVS - OVS is cleaned above)
	if link, err := netlink.LinkByName(cfg.BridgeName); err == nil {
		netlink.LinkDel(link)
	}
}

// cleanupOVSResources cleans up OVS bridge and ports if OVS is available
func cleanupOVSResources(cfg *NetworkConfig) {
	// Check if ovs-vsctl is available
	ovsctl, err := exec.LookPath("ovs-vsctl")
	if err != nil {
		return // OVS not installed
	}

	bridge := cfg.BridgeName

	// Check if the bridge exists in OVS
	checkCmd := exec.Command(ovsctl, "br-exists", bridge)
	if err := checkCmd.Run(); err != nil {
		return // Bridge doesn't exist in OVS
	}

	// Delete ports from the bridge first
	for _, portName := range []string{cfg.ServerTapName, cfg.ClientTapName} {
		delPortCmd := exec.Command(ovsctl, "--if-exists", "del-port", bridge, portName)
		delPortCmd.Run() // Ignore errors
	}

	// Delete the bridge from OVS
	delBrCmd := exec.Command(ovsctl, "--if-exists", "del-br", bridge)
	delBrCmd.Run() // Ignore errors

	// Wait a moment for ovs-vswitchd to clean up the kernel interface
	time.Sleep(200 * time.Millisecond)
}

// CheckRootPrivileges checks if the current process has root privileges
// required for network operations
func CheckRootPrivileges() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("root privileges required for network setup (run with sudo)")
	}
	return nil
}

// NetworkExists checks if the network infrastructure already exists.
// This is used by --client-only mode to detect if --server-only has already set up the network.
func NetworkExists(cfg *NetworkConfig) bool {
	if cfg == nil {
		cfg = DefaultNetworkConfig()
	}

	// Check if bridge exists
	if _, err := netlink.LinkByName(cfg.BridgeName); err != nil {
		return false
	}

	// Check if server TAP exists
	if _, err := netlink.LinkByName(cfg.ServerTapName); err != nil {
		return false
	}

	// Check if client TAP exists
	if _, err := netlink.LinkByName(cfg.ClientTapName); err != nil {
		return false
	}

	return true
}
