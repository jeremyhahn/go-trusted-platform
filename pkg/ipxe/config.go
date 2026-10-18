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
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultHTTPPort is the default HTTP server port.
	DefaultHTTPPort = 8080

	// DefaultTFTPPort is the default TFTP server port.
	DefaultTFTPPort = 69

	// DefaultDHCPPort is the default DHCP server port. It is privileged and
	// globally unique on a host, which is why it is configurable: a test that
	// binds the real 67 depends on host state it does not control.
	DefaultDHCPPort = 67

	// DefaultBindHost is the address the HTTP and TFTP servers bind: empty
	// is the unspecified address, every interface (#93).
	DefaultBindHost = ""

	// DefaultLeaseTime is the default DHCP lease time (1 hour).
	DefaultLeaseTime = 1 * time.Hour

	// DefaultSubnetMask is the default subnet mask.
	DefaultSubnetMask = "255.255.255.0"
)

// ServerConfig holds all configuration for the PXE server.
type ServerConfig struct {
	// Interface is the network interface to bind to.
	Interface string

	// BindHost is the IP address the HTTP and TFTP servers bind (#93).
	// Empty, the default, is the unspecified address: every interface.
	//
	// The DHCP server does not bind it. A UDP socket bound to a unicast
	// address never receives a datagram sent to 255.255.255.255, and a
	// PXE client with no address can only broadcast, so the DHCP socket
	// keeps the unspecified address and is scoped to its segment by
	// SO_BINDTODEVICE on DHCPInterface (or Interface) instead.
	BindHost string

	// HTTPPort is the HTTP server port (default: 8080).
	HTTPPort int

	// TFTPPort is the TFTP server port (default: 69).
	TFTPPort int

	// FirmwareDir is the directory the TFTP server loads iPXE firmware
	// (ipxe.efi, ipxe32.efi, undionly.kpxe) from and caches downloads
	// into. Empty selects the per-user or system cache directory. A
	// deployment that ships the firmware on disk points here and sets
	// FirmwareOffline so nothing is ever fetched at start (#590).
	FirmwareDir string

	// FirmwareUpstream is the base URL firmware is downloaded from when it
	// is not in FirmwareDir (default: DefaultFirmwareUpstream). An
	// infrastructure decision, so it is configuration, not a literal (#93).
	FirmwareUpstream string

	// FirmwareSigner, when set, Authenticode-signs every EFI firmware
	// binary the TFTP server serves (the iPXE images) as it is loaded.
	// Required when clients enforce Secure Boot: the platform's U-Boot
	// builds verify the EFI application they netboot against the
	// preseeded db, and UEFI clients with the keys enrolled do the same.
	FirmwareSigner EFISigner

	// FirmwareOffline forbids downloads: firmware missing from FirmwareDir
	// is an error for the required file and a warning for optional ones.
	FirmwareOffline bool

	// TFTPDir is a directory tree the TFTP server serves for any request
	// the iPXE firmware set does not answer, root-relative and with no
	// escape above it. It carries what a Raspberry Pi bootloader fetches by
	// name (start4.elf, config.txt, the device trees and overlays,
	// kernel8.img), optionally under per-device directories (the
	// bootloader's TFTP_PREFIX: "<serial>/", "<mac-with-dashes>/"), which
	// the bootloader tries before the root. Empty serves only the iPXE
	// firmware.
	TFTPDir string

	// FirmwareOverrides serves the platform's own builds in place of the
	// upstream binaries: served filename → local file. An override is
	// loaded before the cache is consulted, is signed like any other EFI
	// binary, and is an error when unreadable — an operator who named a
	// file meant it. The arm64 iPXE is one: upstream's naps in WFI, which
	// U-Boot's EFI never wakes (build/docker/ipxe-builder).
	FirmwareOverrides map[string]string

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

	// DHCPDNS lists the DNS servers advertised in option 6, in order
	// (optional). Each is an IPv4 address.
	DHCPDNS []string

	// DHCPLeaseTime is the lease duration (default: 1 hour).
	DHCPLeaseTime time.Duration

	// DHCPPort is the UDP port the DHCP server listens on (default: 67).
	// Real deployments must leave this at 67 — PXE clients broadcast to it
	// and cannot be told otherwise. It exists so tests can bind an
	// unprivileged port instead of the host's single real one.
	DHCPPort int

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

	// DHCPProxyOnly runs the DHCP server as a proxy (DHCPConfig.ProxyOnly):
	// boot options only, no leases, on a segment that already has DHCP.
	DHCPProxyOnly bool

	// RaspberryPiOption43 overrides the string a Raspberry Pi bootloader
	// is given in option 43 (DHCPConfig.RaspberryPiOption43).
	RaspberryPiOption43 string

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

	// Architecture restricts the entry to clients of one iPXE build
	// architecture ("x86_64", "arm64", "i386"; iPXE's ${buildarch}).
	// Empty means every client. The menu offers only the entries a
	// client can run, because a kernel for the other architecture fails
	// after the download with no useful message.
	Architecture string

	// AutoInstall is the path to the autoinstall config.
	AutoInstall string
}

// DefaultServerConfig returns a ServerConfig with sensible defaults.
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		Interface:          "",
		BindHost:           DefaultBindHost,
		HTTPPort:           DefaultHTTPPort,
		TFTPPort:           DefaultTFTPPort,
		DHCPPort:           DefaultDHCPPort,
		ExternalURL:        "",
		LocalFilesDir:      "/var/lib/ipxe",
		InstallsDir:        "/data/installs",
		EnableDHCP:         false,
		DHCPInterface:      "",
		DHCPRangeStart:     "",
		DHCPRangeEnd:       "",
		DHCPSubnetMask:     DefaultSubnetMask,
		DHCPGateway:        "",
		DHCPDNS:            nil,
		DHCPLeaseTime:      DefaultLeaseTime,
		DHCPServerIP:       "",
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
		return &SentinelCauseError{Sentinel: ErrInvalidPort, Cause: &MessageError{Msg: "HTTP port must be between 1 and 65535"}}
	}

	// Validate TFTP port
	if c.TFTPPort <= 0 || c.TFTPPort > 65535 {
		return &SentinelCauseError{Sentinel: ErrInvalidPort, Cause: &MessageError{Msg: "TFTP port must be between 1 and 65535"}}
	}

	// Validate DHCP port. Zero means unset and resolves to DefaultDHCPPort at
	// the point of use, so only an out-of-range explicit value is rejected —
	// every ServerConfig literal predating this field keeps working.
	if c.DHCPPort < 0 || c.DHCPPort > 65535 {
		return &SentinelCauseError{Sentinel: ErrInvalidPort, Cause: &MessageError{Msg: "DHCP port must be between 1 and 65535"}}
	}

	// Validate bind host: an IP literal, so a typo fails here rather than
	// at bind time, and a hostname never binds whatever it resolves to.
	if c.BindHost != "" && net.ParseIP(c.BindHost) == nil {
		return &SentinelCauseError{Sentinel: ErrInvalidBindHost, Cause: &MessageError{Msg: c.BindHost + " is not an IP address"}}
	}

	// Validate interface if specified
	if c.Interface != "" {
		if _, err := net.InterfaceByName(c.Interface); err != nil {
			return &SentinelCauseError{Sentinel: ErrInvalidInterface, Cause: &MessageError{Msg: c.Interface}}
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
			return &WrappedError{Msg: fmt.Sprintf("boot entry %d", i), Err: err}
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
		return &SentinelCauseError{Sentinel: ErrInvalidConfig, Cause: &MessageError{Msg: "DHCP interface must be specified"}}
	}

	if _, err := net.InterfaceByName(dhcpInterface); err != nil {
		return &SentinelCauseError{Sentinel: ErrInvalidInterface, Cause: &MessageError{Msg: fmt.Sprintf("DHCP interface %s", dhcpInterface)}}
	}

	// Validate IP range
	if c.DHCPRangeStart == "" || c.DHCPRangeEnd == "" {
		return &SentinelCauseError{Sentinel: ErrInvalidConfig, Cause: &MessageError{Msg: "DHCP range start and end must be specified"}}
	}

	startIP := net.ParseIP(c.DHCPRangeStart)
	if startIP == nil {
		return &SentinelCauseError{Sentinel: ErrInvalidIPRange, Cause: &MessageError{Msg: fmt.Sprintf("invalid range start IP %s", c.DHCPRangeStart)}}
	}

	endIP := net.ParseIP(c.DHCPRangeEnd)
	if endIP == nil {
		return &SentinelCauseError{Sentinel: ErrInvalidIPRange, Cause: &MessageError{Msg: fmt.Sprintf("invalid range end IP %s", c.DHCPRangeEnd)}}
	}

	// Validate subnet mask
	if c.DHCPSubnetMask != "" {
		mask := net.ParseIP(c.DHCPSubnetMask)
		if mask == nil {
			return &SentinelCauseError{Sentinel: ErrInvalidConfig, Cause: &MessageError{Msg: fmt.Sprintf("invalid subnet mask %s", c.DHCPSubnetMask)}}
		}
	}

	if _, _, err := c.dhcpRouterAndDNS(); err != nil {
		return err
	}

	// Validate lease time
	if c.DHCPLeaseTime <= 0 {
		return &SentinelCauseError{Sentinel: ErrInvalidConfig, Cause: &MessageError{Msg: "DHCP lease time must be positive"}}
	}

	return nil
}

// ParseDHCPv4 parses value as the address a DHCPv4 option carries. Options
// 3 (router) and 6 (DNS) hold four-byte addresses only, so anything that is
// not IPv4 is refused here rather than dropped from the offer.
func ParseDHCPv4(option, value string) (net.IP, error) {
	ip := net.ParseIP(value).To4()
	if ip == nil {
		return nil, &DHCPAddressError{Option: option, Value: value}
	}
	return ip, nil
}

// dhcpRouterAndDNS parses the optional gateway and DNS servers. No gateway
// is a nil router: the server then sends no option 3.
func (c *ServerConfig) dhcpRouterAndDNS() (net.IP, []net.IP, error) {
	var router net.IP
	if c.DHCPGateway != "" {
		ip, err := ParseDHCPv4("gateway", c.DHCPGateway)
		if err != nil {
			return nil, nil, err
		}
		router = ip
	}
	var dns []net.IP
	for _, server := range c.DHCPDNS {
		ip, err := ParseDHCPv4("dns", server)
		if err != nil {
			return nil, nil, err
		}
		dns = append(dns, ip)
	}
	return router, dns, nil
}

// GetServerIP returns the server IP address, auto-detecting if necessary.
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

	// Servers bound to one address are reachable only there
	if ip := net.ParseIP(c.BindHost); ip != nil && !ip.IsUnspecified() {
		return c.BindHost, nil
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

// listenAddr returns the address a server listening on port binds: the
// configured BindHost, or every interface when it is empty.
func (c *ServerConfig) listenAddr(port int) string {
	return net.JoinHostPort(c.BindHost, strconv.Itoa(port))
}

// Validate validates the boot entry.
func (b *BootEntry) Validate() error {
	if b.Name == "" {
		return &SentinelCauseError{Sentinel: ErrInvalidBootEntry, Cause: &MessageError{Msg: "boot entry name is required"}}
	}

	if b.Description == "" {
		return &SentinelCauseError{Sentinel: ErrInvalidBootEntry, Cause: &MessageError{Msg: "boot entry description is required"}}
	}

	// At least one of ISO, Kernel, or Initrd must be specified
	if b.ISOURL == "" && b.Kernel == "" && b.Initrd == "" {
		return &SentinelCauseError{Sentinel: ErrInvalidBootEntry, Cause: &MessageError{Msg: "boot entry must specify at least one of ISOURL, Kernel, or Initrd"}}
	}

	return nil
}

// getInterfaceIP returns the IPv4 address of the specified network interface.
func getInterfaceIP(ifaceName string) (string, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return "", &SentinelCauseError{Sentinel: ErrInvalidInterface, Cause: &MessageError{Msg: ifaceName}}
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return "", &WrappedError{Msg: fmt.Sprintf("failed to get addresses for interface %s", ifaceName), Err: err}
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

	return "", &SentinelCauseError{Sentinel: ErrNoServerIP, Cause: &MessageError{Msg: fmt.Sprintf("no IPv4 address found on interface %s", ifaceName)}}
}

// getDefaultIP returns the first non-loopback IPv4 address found on any interface.
func getDefaultIP() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", &WrappedError{Msg: "failed to get network interfaces", Err: err}
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

// EFISigner signs a PE/COFF EFI binary (Authenticode). pkg/authenticode's
// Signer satisfies it; tests use a recorder.
type EFISigner interface {
	Sign(input io.Reader, output io.Writer) error
}

// Architecture names as iPXE reports them in ${buildarch}, used by
// BootEntry.Architecture and the per-architecture menu.
const (
	ArchitectureX86_64 = "x86_64"
	ArchitectureARM64  = "arm64"
	ArchitectureI386   = "i386"
)

// EntriesForArchitecture returns the boot entries a client of the given
// architecture may run: those with a matching Architecture and those with
// none. An empty architecture (a client that did not say) gets them all.
func EntriesForArchitecture(entries []BootEntry, arch string) []BootEntry {
	if arch == "" {
		return entries
	}
	out := make([]BootEntry, 0, len(entries))
	for _, e := range entries {
		if e.Architecture == "" || slices.Contains(ClientArchitectures(e.Architecture), arch) {
			out = append(out, e)
		}
	}
	return out
}

// ClientArchitectures lists the iPXE ${buildarch} values of the clients an
// entry for architecture serves. An x86_64 entry also serves i386 clients:
// legacy-BIOS machines chain undionly.kpxe, a 32-bit iPXE whose buildarch
// is i386, yet boot the 64-bit kernel it fetches. Every other
// architecture serves only itself.
func ClientArchitectures(architecture string) []string {
	if architecture == ArchitectureX86_64 {
		return []string{ArchitectureX86_64, ArchitectureI386}
	}
	return []string{architecture}
}
