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

package ipxe

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testenv"
)

// TestEnv provides an isolated network environment for PXE boot testing.
// It integrates with the testenv package to create a dedicated bridge network
// for running PXE servers in an isolated environment suitable for VM testing.
type TestEnv struct {
	config     *TestEnvConfig
	logger     *logging.Logger
	network    testenv.IsolatedNetwork
	httpServer *HTTPServer
	tftpServer *TFTPServer
	dhcpServer *DHCPServer
	serverCfg  *ServerConfig
}

// TestEnvConfig holds test environment configuration for PXE boot testing.
type TestEnvConfig struct {
	// BridgeName is the name of the bridge interface (e.g., "pxe-br").
	BridgeName string

	// TapName is the TAP device name for the PXE client VM.
	TapName string

	// ServerIP is the PXE server IP address (also serves as gateway).
	ServerIP net.IP

	// Subnet is the network subnet (e.g., 10.99.99.0/24).
	Subnet *net.IPNet

	// DHCPStart is the start of the DHCP IP range.
	DHCPStart net.IP

	// DHCPEnd is the end of the DHCP IP range.
	DHCPEnd net.IP

	// Gateway is the default gateway (typically same as ServerIP).
	Gateway net.IP

	// DNS is the DNS server IP address (optional).
	DNS string

	// HTTPPort is the HTTP server port (default: 8080).
	HTTPPort int

	// TFTPPort is the TFTP server port (default: 69).
	TFTPPort int

	// BootEntries are the boot menu entries.
	BootEntries []BootEntry

	// LocalFilesDir is the directory to serve local files from.
	LocalFilesDir string
}

// DefaultTestEnvConfig returns a TestEnvConfig with sensible defaults for testing.
// It uses the 10.99.99.0/24 subnet for PXE boot testing.
func DefaultTestEnvConfig() *TestEnvConfig {
	_, subnet, _ := net.ParseCIDR("10.99.99.0/24")
	return &TestEnvConfig{
		BridgeName:    "pxe-br",
		TapName:       "tap-pxe-client",
		ServerIP:      net.ParseIP("10.99.99.1"),
		Subnet:        subnet,
		DHCPStart:     net.ParseIP("10.99.99.100"),
		DHCPEnd:       net.ParseIP("10.99.99.200"),
		Gateway:       net.ParseIP("10.99.99.1"),
		DNS:           "8.8.8.8",
		HTTPPort:      DefaultHTTPPort,
		TFTPPort:      DefaultTFTPPort,
		BootEntries:   []BootEntry{},
		LocalFilesDir: "/var/lib/ipxe",
	}
}

// Validate validates the test environment configuration.
func (c *TestEnvConfig) Validate() error {
	if c.BridgeName == "" {
		return &SentinelCauseError{Sentinel: ErrInvalidConfig, Cause: &MessageError{Msg: "bridge name is required"}}
	}
	if c.TapName == "" {
		return &SentinelCauseError{Sentinel: ErrInvalidConfig, Cause: &MessageError{Msg: "TAP name is required"}}
	}
	if c.ServerIP == nil {
		return &SentinelCauseError{Sentinel: ErrNoServerIP, Cause: &MessageError{Msg: "server IP is required"}}
	}
	if c.Subnet == nil {
		return &SentinelCauseError{Sentinel: ErrInvalidConfig, Cause: &MessageError{Msg: "subnet is required"}}
	}
	if c.DHCPStart == nil || c.DHCPEnd == nil {
		return &SentinelCauseError{Sentinel: ErrInvalidIPRange, Cause: &MessageError{Msg: "DHCP range is required"}}
	}

	// Validate IPs are within subnet
	if !c.Subnet.Contains(c.ServerIP) {
		return &SentinelCauseError{Sentinel: ErrInvalidConfig, Cause: &MessageError{Msg: fmt.Sprintf("server IP %s is not within subnet %s", c.ServerIP, c.Subnet)}}
	}
	if !c.Subnet.Contains(c.DHCPStart) {
		return &SentinelCauseError{Sentinel: ErrInvalidConfig, Cause: &MessageError{Msg: fmt.Sprintf("DHCP start IP %s is not within subnet %s", c.DHCPStart, c.Subnet)}}
	}
	if !c.Subnet.Contains(c.DHCPEnd) {
		return &SentinelCauseError{Sentinel: ErrInvalidConfig, Cause: &MessageError{Msg: fmt.Sprintf("DHCP end IP %s is not within subnet %s", c.DHCPEnd, c.Subnet)}}
	}

	// Validate ports
	if c.HTTPPort <= 0 || c.HTTPPort > 65535 {
		return &SentinelCauseError{Sentinel: ErrInvalidPort, Cause: &MessageError{Msg: "HTTP port must be between 1 and 65535"}}
	}
	if c.TFTPPort <= 0 || c.TFTPPort > 65535 {
		return &SentinelCauseError{Sentinel: ErrInvalidPort, Cause: &MessageError{Msg: "TFTP port must be between 1 and 65535"}}
	}

	return nil
}

// NewTestEnv creates a new test environment for PXE boot testing.
func NewTestEnv(cfg *TestEnvConfig, logger *logging.Logger) (*TestEnv, error) {
	if cfg == nil {
		cfg = DefaultTestEnvConfig()
	}

	if err := cfg.Validate(); err != nil {
		return nil, &WrappedError{Msg: "invalid test environment config", Err: err}
	}

	if logger == nil {
		logger = logging.DefaultLogger()
	}

	// Create network configuration for testenv
	netCfg := &testenv.NetworkConfig{
		BridgeName:     cfg.BridgeName,
		ServerTapName:  cfg.TapName,
		ClientTapName:  cfg.TapName + "-unused", // We only need one TAP for PXE testing
		GatewayIP:      cfg.ServerIP,
		ServerIP:       cfg.ServerIP,
		ServerPublicIP: net.ParseIP("192.0.2.2"), // TEST-NET-1 for public DNS zone
		ClientIP:       cfg.DHCPStart,
		ClientPublicIP: net.ParseIP("192.0.2.3"),
		Subnet:         cfg.Subnet,
		Domain:         "pxe.test",
		ServerMAC:      "52:54:00:99:00:01",
		ClientMAC:      "52:54:00:99:00:02",
	}

	// Create isolated network
	network := testenv.NewIsolatedNetwork(netCfg)

	// Create PXE server configuration
	serverCfg := &ServerConfig{
		Interface:      cfg.BridgeName,
		HTTPPort:       cfg.HTTPPort,
		TFTPPort:       cfg.TFTPPort,
		ExternalURL:    fmt.Sprintf("http://%s:%d", cfg.ServerIP.String(), cfg.HTTPPort),
		LocalFilesDir:  cfg.LocalFilesDir,
		EnableDHCP:     true,
		DHCPInterface:  cfg.BridgeName,
		DHCPRangeStart: cfg.DHCPStart.String(),
		DHCPRangeEnd:   cfg.DHCPEnd.String(),
		DHCPSubnetMask: net.IP(cfg.Subnet.Mask).String(),
		DHCPGateway:    cfg.Gateway.String(),
		DHCPDNS:        cfg.DNS,
		DHCPLeaseTime:  DefaultLeaseTime,
		DHCPServerIP:   cfg.ServerIP.String(),
		TFTPServerName: "",
		BootFilename:   "ipxe.efi",
		IPXEScript:     fmt.Sprintf("http://%s:%d/boot.ipxe", cfg.ServerIP.String(), cfg.HTTPPort),
		BootEntries:    cfg.BootEntries,
	}

	return &TestEnv{
		config:    cfg,
		logger:    logger,
		network:   network,
		serverCfg: serverCfg,
	}, nil
}

// Setup creates the isolated network infrastructure (bridge, TAP, NAT).
func (t *TestEnv) Setup() error {
	t.logger.Info("Setting up PXE test environment",
		"bridge", t.config.BridgeName,
		"tap", t.config.TapName,
		"server_ip", t.config.ServerIP.String(),
		"subnet", t.config.Subnet.String())

	if err := t.network.Setup(); err != nil {
		return &WrappedError{Msg: "failed to setup isolated network", Err: err}
	}

	t.logger.Info("PXE test environment setup complete")
	return nil
}

// Start starts the PXE server components (HTTP, TFTP, DHCP) on the isolated network.
func (t *TestEnv) Start(ctx context.Context) error {
	// Create DHCP configuration
	dhcpCfg := &DHCPConfig{
		Interface:      t.config.BridgeName,
		ServerIP:       t.config.ServerIP,
		BroadcastIP:    calculateBroadcastIP(t.config.ServerIP, net.IP(t.config.Subnet.Mask)),
		SubnetMask:     net.IP(t.config.Subnet.Mask).To4(),
		RangeStart:     t.config.DHCPStart.To4(),
		RangeEnd:       t.config.DHCPEnd.To4(),
		LeaseTime:      DefaultLeaseTime,
		Router:         t.config.Gateway.To4(),
		DNSServers:     nil,
		TFTPServerName: "",
		TFTPServerIP:   t.config.ServerIP,
		BootFilename:   t.serverCfg.BootFilename,
		IPXEScript:     t.serverCfg.IPXEScript,
		UseRawSocket:   true, // Use raw socket for bridged network
	}

	if t.config.DNS != "" {
		dhcpCfg.DNSServers = []net.IP{net.ParseIP(t.config.DNS).To4()}
	}

	// Create server components
	t.httpServer = NewHTTPServer(t.serverCfg, t.logger)
	t.tftpServer = NewTFTPServer(t.serverCfg, t.config.ServerIP, t.logger)

	var err error
	t.dhcpServer, err = NewDHCPServer(dhcpCfg, t.logger)
	if err != nil {
		return &WrappedError{Msg: "failed to create DHCP server", Err: err}
	}

	// Start servers in separate goroutines
	errChan := make(chan error, 3)

	// Start HTTP server
	go func() {
		t.logger.Info("Starting HTTP server")
		if err := t.httpServer.Start(ctx); err != nil && ctx.Err() == nil {
			errChan <- &WrappedError{Msg: "HTTP server failed", Err: err}
		}
	}()

	// Give HTTP server time to start
	time.Sleep(100 * time.Millisecond)

	// Start TFTP server
	go func() {
		t.logger.Info("Starting TFTP server")
		if err := t.tftpServer.Start(ctx); err != nil && ctx.Err() == nil {
			errChan <- &WrappedError{Msg: "TFTP server failed", Err: err}
		}
	}()

	// Give TFTP server time to start
	time.Sleep(100 * time.Millisecond)

	// Start DHCP server
	go func() {
		t.logger.Info("Starting DHCP server")
		if err := t.dhcpServer.Start(ctx); err != nil && ctx.Err() == nil {
			errChan <- &WrappedError{Msg: "DHCP server failed", Err: err}
		}
	}()

	// Wait for context cancellation or error
	select {
	case <-ctx.Done():
		t.logger.Info("PXE test environment shutting down")
		return nil
	case err := <-errChan:
		return err
	}
}

// Stop stops all PXE server components.
func (t *TestEnv) Stop() error {
	// Servers will be stopped when their context is cancelled
	t.logger.Info("PXE servers stopped")
	return nil
}

// Cleanup removes all network resources.
func (t *TestEnv) Cleanup() error {
	t.logger.Info("Cleaning up PXE test environment")
	if err := t.network.Cleanup(); err != nil {
		return &WrappedError{Msg: "failed to cleanup network", Err: err}
	}
	t.logger.Info("PXE test environment cleanup complete")
	return nil
}

// TapName returns the TAP device name for the PXE client VM.
func (t *TestEnv) TapName() string {
	return t.config.TapName
}

// ServerIP returns the PXE server IP address.
func (t *TestEnv) ServerIP() net.IP {
	return t.config.ServerIP
}

// ServerConfig returns the PXE server configuration.
func (t *TestEnv) ServerConfig() *ServerConfig {
	return t.serverCfg
}

// Network returns the underlying isolated network.
func (t *TestEnv) Network() testenv.IsolatedNetwork {
	return t.network
}
