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

package ipxe

import (
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	// DefaultHTTPPort is the default HTTP server port.
	DefaultHTTPPort = 8080

	// DefaultTFTPPort is the default TFTP server port.
	DefaultTFTPPort = 69

	// DefaultLeaseTime is the default DHCP lease time (1 hour).
	DefaultLeaseTime = 1 * time.Hour

	// DefaultSubnetMask is the default subnet mask.
	DefaultSubnetMask = "255.255.255.0"
)

// ServerConfig holds all configuration for the PXE server.
type ServerConfig struct {
	// Interface is the network interface to bind to.
	Interface string

	// HTTPPort is the HTTP server port (default: 8080).
	HTTPPort int

	// TFTPPort is the TFTP server port (default: 69).
	TFTPPort int

	// ExternalURL is the external URL for HTTP server (auto-detected if empty).
	ExternalURL string

	// LocalFilesDir is the directory to serve local files from.
	LocalFilesDir string

	// InstallsDir is the host directory under which install-log uploads are
	// written. PUT /installs/{hostname}/{filename} → InstallsDir/{hostname}/
	// {filename}. Defaults to /data/installs (alongside the SMB share root)
	// so the same volume mount that backs the SMB share also persists
	// install postmortems. Files are size-capped (16 MiB) and written via
	// .partial + atomic rename so half-uploaded logs never appear.
	InstallsDir string

	// EnableDHCP indicates whether the DHCP server should be enabled.
	EnableDHCP bool

	// DHCPInterface is the network interface for DHCP (defaults to Interface if empty).
	DHCPInterface string

	// DHCPRangeStart is the start of the IP range (e.g., "192.168.1.100").
	DHCPRangeStart string

	// DHCPRangeEnd is the end of the IP range (e.g., "192.168.1.200").
	DHCPRangeEnd string

	// DHCPSubnetMask is the subnet mask (e.g., "255.255.255.0").
	DHCPSubnetMask string

	// DHCPGateway is the default gateway (optional).
	DHCPGateway string

	// DHCPDNS is the DNS server (optional).
	DHCPDNS string

	// DHCPLeaseTime is the lease duration (default: 1 hour).
	DHCPLeaseTime time.Duration

	// DHCPServerIP is the DHCP server IP (auto-detected if empty).
	DHCPServerIP string

	// TFTPServerName is the TFTP server hostname (optional).
	TFTPServerName string

	// DataDir is the on-disk directory whose contents are exposed
	// to iPXE clients under the HTTP /data/ URL prefix. Lets the
	// generated bootstrap.ipxe script reference files by path
	// (e.g. `kernel /data/vmlinuz`, `initrd /data/initramfs`) and
	// have them served by the same pxeboot HTTP server. Without
	// this, the iPXE chainload that reaches the /boot/<name>.ipxe
	// script succeeds but the subsequent kernel/initrd fetches
	// return 404 because no handler exists for /data/. Defaults
	// to InstallsDir's parent when unset (typically "/data").
	// Set to "" to disable the /data/ endpoint entirely.
	DataDir string

	// BootFilename is the legacy single-arch boot filename for
	// non-iPXE clients. When BootFilenameByArch is populated, that
	// map takes precedence and BootFilename is used only for
	// architectures not present in the map.
	BootFilename string

	// BootFilenameByArch overrides the boot filename per DHCP
	// option-93 client architecture so legacy BIOS and UEFI PXE
	// clients each receive a firmware-appropriate image. Unset
	// (nil) falls back to DefaultBootFilenameByArch at server
	// startup; an explicit empty map disables arch-aware selection
	// and forces every client to BootFilename.
	BootFilenameByArch map[uint16]string

	// IPXEScript is the iPXE script URL for iPXE clients.
	IPXEScript string

	// DHCPRespondToAll responds to all DHCP clients, not just PXE-tagged ones.
	// Use in bootstrap mode when this is the only DHCP server on the network.
	DHCPRespondToAll bool

	// BootEntries are the boot menu entries.
	BootEntries []BootEntry

	// ProxyCACertPool is the CA certificate pool used for verifying upstream
	// HTTPS connections when proxying resources for iPXE clients. If nil,
	// the system certificate pool is used.
	ProxyCACertPool *x509.CertPool
}

// Config is an alias for ServerConfig for backward compatibility.
type Config = ServerConfig

// BootEntry represents a bootable ISO/image entry.
type BootEntry struct {
	// Name is the identifier for the entry.
	Name string

	// Description is the human-readable description.
	Description string

	// ISOURL is the URL to the ISO file.
	ISOURL string

	// Kernel is the path or URL to the kernel.
	Kernel string

	// Initrd is the path or URL to the initrd.
	Initrd string

	// Args are the kernel arguments.
	Args string

	// AutoInstall is the path to the autoinstall config.
	AutoInstall string
}

// DefaultServerConfig returns a ServerConfig with sensible defaults.
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		Interface:      "",
		HTTPPort:       DefaultHTTPPort,
		TFTPPort:       DefaultTFTPPort,
		ExternalURL:    "",
		LocalFilesDir:  "/var/lib/ipxe",
		InstallsDir:    "/data/installs",
		EnableDHCP:     false,
		DHCPInterface:  "",
		DHCPRangeStart: "",
		DHCPRangeEnd:   "",
		DHCPSubnetMask: DefaultSubnetMask,
		DHCPGateway:    "",
		DHCPDNS:        "",
		DHCPLeaseTime:  DefaultLeaseTime,
		DHCPServerIP:   "",
		TFTPServerName:     "",
		BootFilename:       "ipxe.efi",
		BootFilenameByArch: nil,
		IPXEScript:         "",
		BootEntries:        []BootEntry{},
	}
}

// DefaultConfig is an alias for DefaultServerConfig for backward compatibility.
func DefaultConfig() *Config {
	return DefaultServerConfig()
}

// Validate validates the configuration and returns an error if invalid.
func (c *ServerConfig) Validate() error {
	// Validate HTTP port
	if c.HTTPPort <= 0 || c.HTTPPort > 65535 {
		return fmt.Errorf("%w: HTTP port must be between 1 and 65535", ErrInvalidPort)
	}

	// Validate TFTP port
	if c.TFTPPort <= 0 || c.TFTPPort > 65535 {
		return fmt.Errorf("%w: TFTP port must be between 1 and 65535", ErrInvalidPort)
	}

	// Validate interface if specified
	if c.Interface != "" {
		if _, err := net.InterfaceByName(c.Interface); err != nil {
			return fmt.Errorf("%w: %s", ErrInvalidInterface, c.Interface)
		}
	}

	// Validate DHCP configuration if enabled
	if c.EnableDHCP {
		if err := c.validateDHCP(); err != nil {
			return err
		}
	}

	// Validate boot entries
	if len(c.BootEntries) == 0 {
		return ErrNoBootEntries
	}

	for i, entry := range c.BootEntries {
		if err := entry.Validate(); err != nil {
			return fmt.Errorf("boot entry %d: %w", i, err)
		}
	}

	return nil
}

// validateDHCP validates the DHCP configuration.
func (c *ServerConfig) validateDHCP() error {
	// Validate interface
	dhcpInterface := c.DHCPInterface
	if dhcpInterface == "" {
		dhcpInterface = c.Interface
	}

	if dhcpInterface == "" {
		return fmt.Errorf("%w: DHCP interface must be specified", ErrInvalidConfig)
	}

	if _, err := net.InterfaceByName(dhcpInterface); err != nil {
		return fmt.Errorf("%w: DHCP interface %s", ErrInvalidInterface, dhcpInterface)
	}

	// Validate IP range
	if c.DHCPRangeStart == "" || c.DHCPRangeEnd == "" {
		return fmt.Errorf("%w: DHCP range start and end must be specified", ErrInvalidConfig)
	}

	startIP := net.ParseIP(c.DHCPRangeStart)
	if startIP == nil {
		return fmt.Errorf("%w: invalid range start IP %s", ErrInvalidIPRange, c.DHCPRangeStart)
	}

	endIP := net.ParseIP(c.DHCPRangeEnd)
	if endIP == nil {
		return fmt.Errorf("%w: invalid range end IP %s", ErrInvalidIPRange, c.DHCPRangeEnd)
	}

	// Validate subnet mask
	if c.DHCPSubnetMask != "" {
		mask := net.ParseIP(c.DHCPSubnetMask)
		if mask == nil {
			return fmt.Errorf("%w: invalid subnet mask %s", ErrInvalidConfig, c.DHCPSubnetMask)
		}
	}

	// Validate gateway if specified
	if c.DHCPGateway != "" {
		gw := net.ParseIP(c.DHCPGateway)
		if gw == nil {
			return fmt.Errorf("%w: invalid gateway IP %s", ErrInvalidConfig, c.DHCPGateway)
		}
	}

	// Validate DNS if specified
	if c.DHCPDNS != "" {
		dns := net.ParseIP(c.DHCPDNS)
		if dns == nil {
			return fmt.Errorf("%w: invalid DNS IP %s", ErrInvalidConfig, c.DHCPDNS)
		}
	}

	// Validate lease time
	if c.DHCPLeaseTime <= 0 {
		return fmt.Errorf("%w: DHCP lease time must be positive", ErrInvalidConfig)
	}

	return nil
}

// ToDHCPConfig converts the ServerConfig to a DHCPConfig for the DHCP server.
//
//	func (c *ServerConfig) ToDHCPConfig() (*DHCPConfig, error) {
//		if !c.EnableDHCP {
//			return nil, nil
//		}
//
//		// Determine interface
//		dhcpInterface := c.DHCPInterface
//		if dhcpInterface == "" {
//			dhcpInterface = c.Interface
//		}
//
//		// Parse IPs
//		rangeStart := net.ParseIP(c.DHCPRangeStart)
//		if rangeStart == nil {
//			return nil, fmt.Errorf("%w: invalid range start IP %s", ErrInvalidIPRange, c.DHCPRangeStart)
//		}
//
//		rangeEnd := net.ParseIP(c.DHCPRangeEnd)
//		if rangeEnd == nil {
//			return nil, fmt.Errorf("%w: invalid range end IP %s", ErrInvalidIPRange, c.DHCPRangeEnd)
//		}
//
//		subnetMask := net.ParseIP(c.DHCPSubnetMask)
//		if subnetMask == nil {
//			return nil, fmt.Errorf("%w: invalid subnet mask %s", ErrInvalidConfig, c.DHCPSubnetMask)
//		}
//
//		// Determine server IP
//		var serverIP net.IP
//		if c.DHCPServerIP != "" {
//			serverIP = net.ParseIP(c.DHCPServerIP)
//			if serverIP == nil {
//				return nil, fmt.Errorf("%w: invalid server IP %s", ErrInvalidConfig, c.DHCPServerIP)
//			}
//		} else {
//			// Auto-detect server IP from interface
//			ipStr, err := getInterfaceIP(dhcpInterface)
//			if err != nil {
//				return nil, fmt.Errorf("failed to auto-detect server IP: %w", err)
//			}
//			serverIP = net.ParseIP(ipStr)
//		}
//
//		// Calculate broadcast IP
//		broadcastIP := calculateBroadcastIP(serverIP, subnetMask)
//
//		dhcpConfig := &DHCPConfig{
//			Interface:      dhcpInterface,
//			ServerIP:       serverIP,
//			BroadcastIP:    broadcastIP,
//			SubnetMask:     subnetMask.To4(),
//			RangeStart:     rangeStart.To4(),
//			RangeEnd:       rangeEnd.To4(),
//			LeaseTime:      c.DHCPLeaseTime,
//			TFTPServerName: c.TFTPServerName,
//			TFTPServerIP:   serverIP, // Use same IP for TFTP
//			BootFilename:   c.BootFilename,
//			IPXEScript:     c.IPXEScript,
//			UseRawSocket:   false,
//		}
//
//		// Optional fields
//		if c.DHCPGateway != "" {
//			dhcpConfig.Router = net.ParseIP(c.DHCPGateway).To4()
//		}
//
//		if c.DHCPDNS != "" {
//			dhcpConfig.DNSServers = []net.IP{net.ParseIP(c.DHCPDNS).To4()}
//		}
//
//		return dhcpConfig, nil
//	}
//
// // GetServerIP returns the server IP address, auto-detecting if necessary.
func (c *ServerConfig) GetServerIP() (string, error) {
	// If external URL is set, try to extract IP
	if c.ExternalURL != "" {
		if ip := extractIPFromURL(c.ExternalURL); ip != "" {
			return ip, nil
		}
	}

	// If DHCP server IP is set, use that
	if c.DHCPServerIP != "" {
		return c.DHCPServerIP, nil
	}

	// Auto-detect from interface
	if c.Interface != "" {
		ip, err := getInterfaceIP(c.Interface)
		if err != nil {
			return "", err
		}
		return ip, nil
	}

	// Fall back to default IP detection
	ip, err := getDefaultIP()
	if err != nil {
		return "", err
	}

	return ip, nil
}

// Validate validates the boot entry.
func (b *BootEntry) Validate() error {
	if b.Name == "" {
		return fmt.Errorf("%w: boot entry name is required", ErrInvalidBootEntry)
	}

	if b.Description == "" {
		return fmt.Errorf("%w: boot entry description is required", ErrInvalidBootEntry)
	}

	// At least one of ISO, Kernel, or Initrd must be specified
	if b.ISOURL == "" && b.Kernel == "" && b.Initrd == "" {
		return fmt.Errorf("%w: boot entry must specify at least one of ISOURL, Kernel, or Initrd", ErrInvalidBootEntry)
	}

	return nil
}

// getInterfaceIP returns the IPv4 address of the specified network interface.
func getInterfaceIP(ifaceName string) (string, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrInvalidInterface, ifaceName)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return "", fmt.Errorf("failed to get addresses for interface %s: %w", ifaceName, err)
	}

	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}

		// Return the first non-loopback IPv4 address
		if ip != nil && ip.To4() != nil && !ip.IsLoopback() {
			return ip.String(), nil
		}
	}

	return "", fmt.Errorf("%w: no IPv4 address found on interface %s", ErrNoServerIP, ifaceName)
}

// getDefaultIP returns the first non-loopback IPv4 address found on any interface.
func getDefaultIP() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("failed to get network interfaces: %w", err)
	}

	for _, iface := range ifaces {
		// Skip down interfaces and loopback
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			// Return the first non-loopback IPv4 address
			if ip != nil && ip.To4() != nil && !ip.IsLoopback() {
				return ip.String(), nil
			}
		}
	}

	return "", ErrNoServerIP
}

// extractIPFromURL extracts an IP address from a URL string.
func extractIPFromURL(urlStr string) string {
	// Remove scheme if present
	urlStr = strings.TrimPrefix(urlStr, "http://")
	urlStr = strings.TrimPrefix(urlStr, "https://")

	// Split on colon to remove port
	host := strings.Split(urlStr, ":")[0]

	// Split on slash to remove path
	host = strings.Split(host, "/")[0]

	// Check if it's a valid IP
	if ip := net.ParseIP(host); ip != nil {
		return host
	}

	return ""
}

// calculateBroadcastIP calculates the broadcast IP address given an IP and subnet mask.
func calculateBroadcastIP(ip, mask net.IP) net.IP {
	ip4 := ip.To4()
	mask4 := mask.To4()

	if ip4 == nil || mask4 == nil {
		return nil
	}

	broadcast := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		broadcast[i] = ip4[i] | ^mask4[i]
	}

	return broadcast
}
