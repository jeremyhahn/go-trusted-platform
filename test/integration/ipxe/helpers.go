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

// ErrHTTPClientNotInitialized indicates the HTTP client is not initialized.
var ErrHTTPClientNotInitialized = errors.New("HTTP client not initialized")

// ErrDHCPClientNotInitialized indicates the DHCP client is not initialized.
var ErrDHCPClientNotInitialized = errors.New("DHCP client not initialized")

// ErrNoNetworkPrivileges reports that a DHCP test runs without the root
// privileges it needs to bind the DHCP port.
type ErrNoNetworkPrivileges struct {
	EUID int
}

func (e ErrNoNetworkPrivileges) Error() string {
	return fmt.Sprintf("DHCP tests need root or CAP_NET_ADMIN, running as euid %d: "+
		"run them in the devcontainer (make integration-test-ipxe), which runs as root", e.EUID)
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

	// EnvIPXEDHCPEnabled is the environment variable for DHCP enablement.
	EnvIPXEDHCPEnabled = "IPXE_DHCP_ENABLED"

	// EnvIPXENetworkInterface is the environment variable for the network interface.
	EnvIPXENetworkInterface = "IPXE_NETWORK_INTERFACE"

	// EnvIPXETestNetwork is the environment variable for the test network CIDR.
	EnvIPXETestNetwork = "IPXE_TEST_NETWORK"
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
)

// =============================================================================
// PXE Client Architecture Constants
// =============================================================================

const (
	// ArchBIOSx86 is the BIOS x86 client architecture (legacy).
	ArchBIOSx86 = uint16(0x0000)

	// ArchEFIx64 is the EFI x64 client architecture.
	ArchEFIx64 = uint16(0x0007)

	// ArchEFIx86 is the EFI x86 client architecture.
	ArchEFIx86 = uint16(0x0006)

	// ArchEFIBC is the EFI byte code architecture.
	ArchEFIBC = uint16(0x0009)
)

// =============================================================================
// Skip Helpers
// =============================================================================

// SkipIfNoDHCP skips the test if DHCP testing is not enabled.
func SkipIfNoDHCP(t *testing.T) {
	t.Helper()
	if os.Getenv(EnvIPXEDHCPEnabled) != "1" {
		t.Skip("Skipping DHCP test. Set IPXE_DHCP_ENABLED=1 to run.")
	}
}

// CheckNetworkPrivileges returns ErrNoNetworkPrivileges when the process
// cannot bind the privileged DHCP port.
func CheckNetworkPrivileges() error {
	if euid := os.Geteuid(); euid != 0 {
		return ErrNoNetworkPrivileges{EUID: euid}
	}
	return nil
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
// Network Helpers
// =============================================================================

// WaitForPort waits for a TCP port to become available.
func WaitForPort(ctx context.Context, host string, port int) error {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
			if err == nil {
				conn.Close()
				return nil
			}
		}
	}
}

// WaitForUDP waits for a UDP port to become available.
func WaitForUDP(ctx context.Context, host string, port int) error {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			conn, err := net.Dial("udp", addr)
			if err == nil {
				conn.Close()
				return nil
			}
		}
	}
}

// IsPortAvailable checks if a TCP port is available for binding.
func IsPortAvailable(host string, port int) bool {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return false
	}
	ln.Close()
	return true
}

// =============================================================================
// Test Data Helpers
// =============================================================================

// GenerateTestBootEntries generates test boot entries for integration testing.
func GenerateTestBootEntries() []BootEntryConfig {
	return []BootEntryConfig{
		{
			Name:        "alpine-standard",
			Description: "Alpine Linux Standard",
			ISOURL:      "https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-standard-3.20.0-x86_64.iso",
		},
		{
			Name:        "test-kernel",
			Description: "Test Kernel Boot",
			Kernel:      "/files/vmlinuz",
			Initrd:      "/files/initrd.img",
			Args:        "console=ttyS0",
		},
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

// AssertContains checks if a string contains a substring.
func AssertContains(t *testing.T, haystack, needle, description string) {
	t.Helper()
	if haystack == "" {
		t.Errorf("%s: string is empty", description)
		return
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		if haystack[i:i+len(needle)] == needle {
			return
		}
	}
	t.Errorf("%s: expected to contain %q, got %q", description, needle, haystack)
}

// =============================================================================
// Retry Helpers
// =============================================================================

// RetryConfig configures retry behavior for operations.
type RetryConfig struct {
	MaxAttempts int
	InitialWait time.Duration
	MaxWait     time.Duration
	Multiplier  float64
}

// DefaultRetryConfig returns sensible defaults for retry operations.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts: 5,
		InitialWait: 500 * time.Millisecond,
		MaxWait:     5 * time.Second,
		Multiplier:  1.5,
	}
}

// Retry executes an operation with exponential backoff retry.
func Retry(ctx context.Context, cfg RetryConfig, operation func() error) error {
	var lastErr error
	wait := cfg.InitialWait

	for attempt := 1; attempt <= cfg.MaxAttempts; attempt++ {
		lastErr = operation()
		if lastErr == nil {
			return nil
		}

		// Check context cancellation
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Do not wait after last attempt
		if attempt < cfg.MaxAttempts {
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return ctx.Err()
			}

			// Exponential backoff
			wait = time.Duration(float64(wait) * cfg.Multiplier)
			if wait > cfg.MaxWait {
				wait = cfg.MaxWait
			}
		}
	}

	return fmt.Errorf("operation failed after %d attempts: %w", cfg.MaxAttempts, lastErr)
}
