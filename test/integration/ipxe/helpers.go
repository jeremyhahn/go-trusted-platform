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

//go:build integration

package ipxe

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

// =============================================================================
// Error Types
// =============================================================================

// ErrTFTPClientNotInitialized indicates the TFTP client is not initialized.
var ErrTFTPClientNotInitialized = errors.New("TFTP client not initialized")

// ErrServerNotReady indicates the suite's iPXE server did not bind every
// listener before the setup deadline.
var ErrServerNotReady = errors.New("iPXE server not ready")

// SuiteSetupError reports which step of TestMain's suite setup failed.
type SuiteSetupError struct {
	// Step names the failed step, e.g. "start iPXE server".
	Step string
	// Err is the underlying cause.
	Err error
}

// Error implements the error interface.
func (e *SuiteSetupError) Error() string {
	return e.Step + ": " + e.Err.Error()
}

// Unwrap returns the underlying cause.
func (e *SuiteSetupError) Unwrap() error {
	return e.Err
}

// ErrServerUnhealthy indicates the iPXE HTTP server's /health endpoint did
// not answer 200.
var ErrServerUnhealthy = errors.New("iPXE HTTP server unhealthy")

// AdapterSetupError reports which protocol adapter failed to set up.
type AdapterSetupError struct {
	// Protocol names the adapter, e.g. "HTTP".
	Protocol string
	// Err is the underlying cause.
	Err error
}

// Error implements the error interface.
func (e *AdapterSetupError) Error() string {
	return e.Protocol + " adapter setup: " + e.Err.Error()
}

// Unwrap returns the underlying cause.
func (e *AdapterSetupError) Unwrap() error {
	return e.Err
}

// ErrDHCPNak indicates the DHCP server answered a REQUEST with a NAK.
var ErrDHCPNak = errors.New("DHCP server sent NAK")

// DHCPExchangeError reports which step of a DHCP client exchange failed.
type DHCPExchangeError struct {
	// Step names the failed step, e.g. "send DISCOVER".
	Step string
	// Err is the underlying cause.
	Err error
}

// Error implements the error interface.
func (e *DHCPExchangeError) Error() string {
	return "DHCP " + e.Step + ": " + e.Err.Error()
}

// Unwrap returns the underlying cause.
func (e *DHCPExchangeError) Unwrap() error {
	return e.Err
}

// =============================================================================
// Environment Variable Constants
// =============================================================================

const (
	// EnvIPXEServerIP is the environment variable for the iPXE server IP.
	EnvIPXEServerIP = "IPXE_SERVER_IP"

	// EnvIPXEHTTPPort is the environment variable for the HTTP port.
	EnvIPXEHTTPPort = "IPXE_HTTP_PORT"

	// EnvIPXETFTPPort is the environment variable for the TFTP port.
	EnvIPXETFTPPort = "IPXE_TFTP_PORT"

	// EnvIPXEDHCPEnabled starts the suite's DHCP server when set to "1".
	// The DHCP tests fail, never skip, without it.
	EnvIPXEDHCPEnabled = "IPXE_DHCP_ENABLED"

	// EnvIPXEDHCPPort is the UDP port the suite's DHCP server listens on.
	// TestMain sets it; the server and the client both read it.
	EnvIPXEDHCPPort = "IPXE_DHCP_PORT"
)

// =============================================================================
// Default Configuration
// =============================================================================

const (
	// DefaultServerIP is the default iPXE server IP for testing.
	DefaultServerIP = "10.99.99.1"

	// DefaultHTTPPort is the default HTTP server port.
	DefaultHTTPPort = 8080

	// DefaultTFTPPort is the default TFTP server port.
	DefaultTFTPPort = 69

	// DefaultDHCPRangeStart is the default DHCP range start.
	DefaultDHCPRangeStart = "10.99.99.100"

	// DefaultDHCPRangeEnd is the default DHCP range end.
	DefaultDHCPRangeEnd = "10.99.99.200"

	// DefaultSubnetMask is the default subnet mask.
	DefaultSubnetMask = "255.255.255.0"

	// DefaultTestTimeout is the default timeout for test operations.
	DefaultTestTimeout = 30 * time.Second

	// DefaultDHCPTimeout is the default timeout for DHCP operations.
	DefaultDHCPTimeout = 5 * time.Second

	// DefaultTFTPTimeout is the default timeout for TFTP operations.
	DefaultTFTPTimeout = 30 * time.Second

	// DefaultHTTPTimeout is the default timeout for HTTP operations.
	DefaultHTTPTimeout = 10 * time.Second

	// DHCPTestInterface is the interface the suite's DHCP server and client
	// both bind. It is loopback because only loopback hands a host's own
	// broadcast OFFER back to it: the server and the client share one
	// process, and the server's replies go to 255.255.255.255:68.
	DHCPTestInterface = "lo"

	// DHCPClientPort is the port DHCP servers send replies to (RFC 2131).
	// Binding it needs root or CAP_NET_BIND_SERVICE.
	DHCPClientPort = 68
)

// =============================================================================
// PXE Client Architecture Constants
// =============================================================================

// ArchEFIx64 is the EFI x64 client architecture (DHCP option 93).
const ArchEFIx64 = uint16(0x0007)

// =============================================================================
// Server Helpers
// =============================================================================

// RequireDHCPServer fails the test unless TestMain started the suite's DHCP
// server. A DHCP test that reaches here without it was selected by mistake:
// the runner sets IPXE_DHCP_ENABLED=1 for every target that runs one.
func RequireDHCPServer(t *testing.T, cfg TestServerConfig) {
	t.Helper()
	if !cfg.DHCPEnabled || cfg.DHCPPort == 0 {
		t.Fatalf("DHCP server not running: set %s=1 so TestMain starts it", EnvIPXEDHCPEnabled)
	}
}

// =============================================================================
// Configuration Helpers
// =============================================================================

// GetTestServerConfig returns the test server configuration from environment
// variables with sensible defaults. This reads the dynamically assigned ports
// from TestMain.
func GetTestServerConfig() TestServerConfig {
	serverIP := net.ParseIP(getEnvOrDefault(EnvIPXEServerIP, DefaultServerIP))
	httpPort := getEnvIntOrDefault(EnvIPXEHTTPPort, DefaultHTTPPort)
	tftpPort := getEnvIntOrDefault(EnvIPXETFTPPort, DefaultTFTPPort)

	return TestServerConfig{
		ServerIP:       serverIP,
		HTTPPort:       httpPort,
		TFTPPort:       tftpPort,
		DHCPEnabled:    os.Getenv(EnvIPXEDHCPEnabled) == "1",
		DHCPPort:       getEnvIntOrDefault(EnvIPXEDHCPPort, 0),
		DHCPRangeStart: net.ParseIP(DefaultDHCPRangeStart),
		DHCPRangeEnd:   net.ParseIP(DefaultDHCPRangeEnd),
		SubnetMask:     net.IPv4Mask(255, 255, 255, 0),
		Gateway:        serverIP,
		BootEntries: []BootEntryConfig{
			{
				Name:        "alpine-test",
				Description: "Alpine Linux Test Entry",
				ISOURL:      "https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-standard-3.20.0-x86_64.iso",
			},
			{
				Name:        "test-kernel",
				Description: "Test Kernel Boot",
				Kernel:      "http://example.com/vmlinuz",
				Initrd:      "http://example.com/initrd.img",
				Args:        "console=ttyS0",
			},
		},
	}
}

// getEnvOrDefault returns the environment variable value or the default if not set.
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvIntOrDefault returns the environment variable value as an int or the default.
func getEnvIntOrDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		var result int
		if _, err := fmt.Sscanf(value, "%d", &result); err == nil {
			return result
		}
	}
	return defaultValue
}

// =============================================================================
// Test Context Helpers
// =============================================================================

// DefaultTestContext returns a context with a reasonable timeout for integration tests.
func DefaultTestContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), DefaultTestTimeout)
}

// DHCPTestContext returns a context with timeout suitable for DHCP operations.
func DHCPTestContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), DefaultDHCPTimeout)
}

// TFTPTestContext returns a context with timeout suitable for TFTP operations.
func TFTPTestContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), DefaultTFTPTimeout)
}

// HTTPTestContext returns a context with timeout suitable for HTTP operations.
func HTTPTestContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), DefaultHTTPTimeout)
}

// LongRunningTestContext returns a context with a longer timeout for tests
// that may take more time (e.g., full boot flow tests).
func LongRunningTestContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 5*time.Minute)
}

// =============================================================================
// MAC Address Generation
// =============================================================================

// GenerateRandomMAC generates a random MAC address for testing.
// The MAC address uses the locally administered bit to avoid conflicts.
func GenerateRandomMAC() net.HardwareAddr {
	mac := make([]byte, 6)
	_, _ = rand.Read(mac)

	// Set the locally administered bit (second least significant bit of first byte)
	mac[0] = (mac[0] | 0x02) & 0xFE

	return net.HardwareAddr(mac)
}

// GenerateTestMAC generates a deterministic MAC address for testing based on index.
func GenerateTestMAC(index int) net.HardwareAddr {
	return net.HardwareAddr{
		0x52, 0x54, 0x00, // QEMU OUI
		byte(index >> 16),
		byte(index >> 8),
		byte(index),
	}
}

// =============================================================================
// Assertion Helpers
// =============================================================================

// AssertValidIP checks if the IP address is valid and not nil.
func AssertValidIP(t *testing.T, ip net.IP, description string) {
	t.Helper()
	if ip == nil || ip.IsUnspecified() {
		t.Errorf("%s: expected valid IP address, got %v", description, ip)
	}
}

// AssertIPInRange checks if the IP address is within the expected range.
func AssertIPInRange(t *testing.T, ip, rangeStart, rangeEnd net.IP, description string) {
	t.Helper()
	if ip == nil {
		t.Errorf("%s: IP is nil", description)
		return
	}

	ip4 := ip.To4()
	start4 := rangeStart.To4()
	end4 := rangeEnd.To4()

	if ip4 == nil || start4 == nil || end4 == nil {
		t.Errorf("%s: invalid IPv4 addresses", description)
		return
	}

	ipVal := ipToUint32(ip4)
	startVal := ipToUint32(start4)
	endVal := ipToUint32(end4)

	if ipVal < startVal || ipVal > endVal {
		t.Errorf("%s: IP %v not in range [%v, %v]", description, ip, rangeStart, rangeEnd)
	}
}

// ipToUint32 converts an IPv4 address to a uint32 for comparison.
func ipToUint32(ip net.IP) uint32 {
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}
