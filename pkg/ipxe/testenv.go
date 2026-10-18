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
	"strings"
	"sync"

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

	// readyCh closes once all three listeners have bound. Each of them has
	// always accepted a bind signal; Start used to pass nil and sleep 100ms
	// between launches instead, which is the same defect this package's
	// tests carried and is why they mirrored it (#260).
	readyCh   chan struct{}
	readyOnce sync.Once
}

// Ready returns a channel closed once every listener has bound. It is the
// synchronisation point a caller should wait on instead of guessing a
// startup duration.
func (t *TestEnv) Ready() <-chan struct{} { return t.readyCh }

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

	// FirmwareSigner, when set, Authenticode-signs the EFI binaries the
	// TFTP server hands out, for a client whose firmware verifies what it
	// loads (ServerConfig.FirmwareSigner).
	FirmwareSigner EFISigner

	// FirmwareOverrides serves local builds in place of the upstream
	// binaries (ServerConfig.FirmwareOverrides).
	FirmwareOverrides map[string]string

	// TFTPDir is the directory tree served over TFTP beside the iPXE
	// firmware (ServerConfig.TFTPDir): the Raspberry Pi boot files.
	TFTPDir string

	// DataDir is the directory the HTTP server serves under /data/
	// (ServerConfig.DataDir): the netboot media a container serves, the
	// Raspberry Pi's HTTP boot files among them.
	DataDir string

	// ProxyDHCP runs the DHCP server as a proxy (DHCPConfig.ProxyOnly):
	// boot options only, no leases, as on a segment that already has a
	// DHCP server.
	ProxyDHCP bool
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

// maxInterfaceNameLen is IFNAMSIZ-1, the longest interface name Linux
// accepts.
const maxInterfaceNameLen = 15

// unusedTapName names the second TAP the isolated network insists on
// creating, which PXE testing never attaches: the client TAP's name with
// an "-unused" suffix, shortened so the kernel accepts it.
func unusedTapName(tap string) string {
	const suffix = "-unused"
	if len(tap)+len(suffix) > maxInterfaceNameLen {
		tap = strings.TrimRight(tap[:maxInterfaceNameLen-len(suffix)], "-")
	}
	return tap + suffix
}

// Validate validates the test environment configuration.
func (c *TestEnvConfig) Validate() error {
	if c.BridgeName == "" {
		return &SentinelCauseError{Sentinel: ErrInvalidConfig, Cause: &MessageError{Msg: "bridge name is required"}}
	}
	if c.TapName == "" {
		return &SentinelCauseError{Sentinel: ErrInvalidConfig, Cause: &MessageError{Msg: "TAP name is required"}}
	}
	// The kernel refuses an interface name over IFNAMSIZ-1 bytes; the
	// failure would surface later as "Link not found" from the TAP the
	// kernel silently did not create.
	for _, name := range []string{c.BridgeName, c.TapName} {
		if len(name) > maxInterfaceNameLen {
			return &SentinelCauseError{Sentinel: ErrInvalidConfig, Cause: &MessageError{Msg: fmt.Sprintf("interface name %q exceeds %d characters", name, maxInterfaceNameLen)}}
		}
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
		ClientTapName:  unusedTapName(cfg.TapName), // We only need one TAP for PXE testing
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
		Interface:         cfg.BridgeName,
		HTTPPort:          cfg.HTTPPort,
		TFTPPort:          cfg.TFTPPort,
		ExternalURL:       fmt.Sprintf("http://%s:%d", cfg.ServerIP.String(), cfg.HTTPPort),
		LocalFilesDir:     cfg.LocalFilesDir,
		EnableDHCP:        true,
		DHCPInterface:     cfg.BridgeName,
		DHCPRangeStart:    cfg.DHCPStart.String(),
		DHCPRangeEnd:      cfg.DHCPEnd.String(),
		DHCPSubnetMask:    net.IP(cfg.Subnet.Mask).String(),
		DHCPGateway:       cfg.Gateway.String(),
		DHCPDNS:           testEnvDNS(cfg.DNS),
		DHCPLeaseTime:     DefaultLeaseTime,
		DHCPServerIP:      cfg.ServerIP.String(),
		TFTPServerName:    "",
		BootFilename:      "ipxe.efi",
		IPXEScript:        fmt.Sprintf("http://%s:%d/boot.ipxe", cfg.ServerIP.String(), cfg.HTTPPort),
		BootEntries:       cfg.BootEntries,
		FirmwareSigner:    cfg.FirmwareSigner,
		FirmwareOverrides: cfg.FirmwareOverrides,
		TFTPDir:           cfg.TFTPDir,
		DataDir:           cfg.DataDir,
		DHCPProxyOnly:     cfg.ProxyDHCP,
	}

	return &TestEnv{
		config:    cfg,
		logger:    logger,
		network:   network,
		serverCfg: serverCfg,
		readyCh:   make(chan struct{}),
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

// dhcpConfig is the DHCP server's configuration for the environment: the
// same choices Server makes from a ServerConfig, including the
// per-architecture bootfile map (nil in the ServerConfig means the
// default map; an explicit empty map disables the selection), which is
// what hands an AArch64 client its own iPXE instead of the x86 one.
func (t *TestEnv) dhcpConfig() *DHCPConfig {
	archMap := t.serverCfg.BootFilenameByArch
	if archMap == nil {
		archMap = DefaultBootFilenameByArch()
	}
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
		// The same socket Server uses: a UDP socket with SO_BROADCAST bound
		// to the bridge (#649), which reaches a client that has no address
		// yet through the limited broadcast. Measured on the PXE test
		// bridge with U-Boot and iPXE clients (2026-09-22).
		UseRawSocket:       false,
		BootFilenameByArch: archMap,
		ProxyOnly:          t.serverCfg.DHCPProxyOnly,
		// The environment is an isolated bridge on which this is the only
		// DHCP server, so it answers every client — the booted OS's own
		// DHCP client (udhcpc in an Alpine initramfs) included — exactly
		// as the bootstrap container does on a provisioning segment.
		RespondToAll: true,
	}
	if t.config.DNS != "" {
		dhcpCfg.DNSServers = []net.IP{net.ParseIP(t.config.DNS).To4()}
	}
	return dhcpCfg
}

// testEnvDNS is the server's DNS list for the environment's one DNS server.
func testEnvDNS(dns string) []string {
	if dns == "" {
		return nil
	}
	return []string{dns}
}

// Start starts the PXE server components (HTTP, TFTP, DHCP) on the isolated network.
func (t *TestEnv) Start(ctx context.Context) error {
	dhcpCfg := t.dhcpConfig()
	// Create server components
	t.httpServer = NewHTTPServer(t.serverCfg, t.logger)
	t.tftpServer = NewTFTPServer(t.serverCfg, t.config.ServerIP, t.logger)

	var err error
	t.dhcpServer, err = NewDHCPServer(dhcpCfg, t.logger)
	if err != nil {
		return &WrappedError{Msg: "failed to create DHCP server", Err: err}
	}

	// Start servers in separate goroutines. Each reports the instant its
	// listener is bound; the 100ms sleeps that used to separate these
	// launches were guessing at that and could be wrong in either
	// direction — too short on a loaded host, and pure delay otherwise.
	errChan := make(chan error, 3)
	bounds := make(chan struct{}, 3)

	// Start HTTP server
	go func() {
		t.logger.Info("Starting HTTP server")
		if err := t.httpServer.Start(ctx, bounds); err != nil && ctx.Err() == nil {
			errChan <- &WrappedError{Msg: "HTTP server failed", Err: err}
		}
	}()

	// Start TFTP server
	go func() {
		t.logger.Info("Starting TFTP server")
		if err := t.tftpServer.Start(ctx, bounds); err != nil && ctx.Err() == nil {
			errChan <- &WrappedError{Msg: "TFTP server failed", Err: err}
		}
	}()

	// Start DHCP server
	go func() {
		t.logger.Info("Starting DHCP server")
		if err := t.dhcpServer.Start(ctx, bounds); err != nil && ctx.Err() == nil {
			errChan <- &WrappedError{Msg: "DHCP server failed", Err: err}
		}
	}()

	// Signal readiness once all three listeners are up. A listener that
	// fails to bind sends on errChan instead, which the select below
	// surfaces rather than waiting out a timeout.
	go func() {
		for i := 0; i < 3; i++ {
			select {
			case <-bounds:
			case <-ctx.Done():
				return
			}
		}
		t.readyOnce.Do(func() { close(t.readyCh) })
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
