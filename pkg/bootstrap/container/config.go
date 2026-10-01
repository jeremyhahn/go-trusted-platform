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

package container

import (
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

const (
	// DefaultHTTPPort is the default HTTP server port.
	DefaultHTTPPort = 8080

	// DefaultTFTPPort is the default TFTP server port.
	DefaultTFTPPort = 69

	// DeviceScriptPortOffset is added to HTTPPort to derive the
	// device-script server's port when ServerConfig.DeviceScriptPort is
	// left unset. With the default HTTP port this is 8081.
	DeviceScriptPortOffset = 1

	// DefaultDHCPLeaseTime is the default DHCP lease duration.
	DefaultDHCPLeaseTime = 1 * time.Hour

	// DefaultAlpineVersion is the Alpine version assumed when the operator
	// does not override it. It must match the version baked into the staged
	// vmlinuz/initramfs so the derived repository branch (vMAJOR.MINOR) is
	// correct for the live-system apk add and the autoinstall repos.
	DefaultAlpineVersion = "3.22.2"

	// DefaultAPKMirror is the install-time APK repository base used when no
	// mirror is configured. It points at the public Alpine mirror so a PXE
	// node on an internet-connected network still resolves packages: PXE
	// nodes have no /media/cdrom, so an empty repo would otherwise leave the
	// live-system apk add with 0 packages and no /sbin/init.
	DefaultAPKMirror = "https://dl-cdn.alpinelinux.org/alpine"
)

// DefaultDataDir is the container's bind-mounted data directory.
const DefaultDataDir = "/data"

// DataURLPath is where the HTTP server serves DataDir.
const DataURLPath = "/data"

// ServerConfig holds all configuration for the bootstrap container server.
type ServerConfig struct {
	// Interface is the network interface to bind to.
	Interface string

	// HTTPPort is the HTTP server port (default: 8080).
	HTTPPort int

	// DeviceScriptPort is the port for the per-device boot script server
	// (/boot/device/{mac}.ipxe), which listens separately from the main
	// HTTP server. Zero derives HTTPPort+1, which is what this listener
	// used before the port was configurable.
	//
	// It is configurable because the deployer is routinely a shared
	// jumpbox, where an unrelated service owning the derived port kills
	// pxeboot on bind with no way to move it short of moving HTTPPort
	// too.
	DeviceScriptPort int

	// TFTPPort is the TFTP server port (default: 69).
	TFTPPort int

	// FirmwareDir is where the iPXE firmware (ipxe.efi, ipxe32.efi,
	// undionly.kpxe) is loaded from and cached into; empty selects the
	// user or system cache directory. FirmwareUpstream is the download
	// base URL when a file is missing (default boot.ipxe.org) and
	// FirmwareOffline forbids downloading at all (#590). All three pass
	// through to ipxe.ServerConfig unchanged.
	FirmwareDir      string
	FirmwareUpstream string
	FirmwareOffline  bool

	// DHCPConfig holds DHCP server settings.
	DHCPConfig DHCPConfig

	// ManifestPath is the path to the YAML manifest file.
	ManifestPath string

	// ConfigDir is the directory containing per-device config files.
	ConfigDir string

	// AlpineVersion is the Alpine release (e.g. "3.22.2") of the staged
	// kernel/initramfs. It drives the repository branch (vMAJOR.MINOR)
	// appended to the PXE kernel cmdline as alpine_repo=.
	AlpineVersion string

	// DataDir is the directory the HTTP server serves at /data/ (default
	// /data, the container's bind mount). MediaDir must be inside it:
	// nodes fetch their media sets from there.
	DataDir string

	// MediaDir holds the media sets the container serves, one directory
	// each with a media-set.yaml (see MediaSet) — the netboot media build's
	// media/ staged under DataDir. Required.
	MediaDir string

	// TFTPDir is the Raspberry Pi boot tree (start4.elf, config.txt,
	// kernel8.img = U-Boot, device trees, overlays, per-device directories)
	// served over TFTP beside the iPXE firmware. Empty serves no Pi.
	TFTPDir string

	// FirmwareOverrides serves prebuilt firmware in place of the upstream
	// downloads: served filename -> file (the db-signed arm64 iPXE a Pi's
	// U-Boot loads, as snponly-aarch64.efi). See ipxe.ServerConfig.
	FirmwareOverrides map[string]string

	// DHCPProxyOnly answers PXE clients with boot options and no lease, for
	// a provisioning segment whose own DHCP server leases addresses.
	DHCPProxyOnly bool

	// APKMirror is the install-time APK repository base (e.g.
	// "http://10.4.6.11:8080"). It is appended to the PXE kernel
	// cmdline both as alpine_repo=<mirror>/<branch>/main (so the Alpine
	// init can build the diskless live root — PXE has no /media/cdrom, so
	// without it the live-system apk add installs 0 packages and there is
	// no /sbin/init) and as platform_apk_mirror=<mirror> (so the
	// post-switch-root autoinstall repo setup resolves packages too).
	APKMirror string
}

// DHCPConfig holds DHCP server settings for the bootstrap container.
type DHCPConfig struct {
	ServerIP   string        `yaml:"server_ip" json:"server_ip"`
	RangeStart string        `yaml:"range_start" json:"range_start"`
	RangeEnd   string        `yaml:"range_end" json:"range_end"`
	SubnetMask string        `yaml:"subnet_mask" json:"subnet_mask"`
	Gateway    string        `yaml:"gateway" json:"gateway"`
	DNS        []string      `yaml:"dns" json:"dns"`
	LeaseTime  time.Duration `yaml:"lease_time" json:"lease_time"`
	// Port is the UDP port the DHCP server listens on. Zero means 67, the
	// only value a real deployment can use — PXE clients broadcast to it.
	// It is settable so tests need not bind the host's single privileged
	// DHCP port.
	Port int `yaml:"port" json:"port"`
}

// Validate checks the server configuration for required fields and valid values.
func (c *ServerConfig) Validate() error {
	if c.ManifestPath == "" {
		return ErrInvalidServerConfig{Field: "manifest_path", Reason: "must not be empty"}
	}
	if c.MediaDir == "" {
		return ErrInvalidServerConfig{Field: "media_dir", Reason: "must not be empty: the container serves the netboot media build's sets"}
	}
	if c.DHCPConfig.ServerIP == "" {
		return ErrInvalidServerConfig{Field: "dhcp_config.server_ip", Reason: "must not be empty"}
	}
	if c.DHCPConfig.RangeStart == "" {
		return ErrInvalidServerConfig{Field: "dhcp_config.range_start", Reason: "must not be empty"}
	}
	if c.DHCPConfig.RangeEnd == "" {
		return ErrInvalidServerConfig{Field: "dhcp_config.range_end", Reason: "must not be empty"}
	}
	if c.DHCPConfig.SubnetMask == "" {
		return ErrInvalidServerConfig{Field: "dhcp_config.subnet_mask", Reason: "must not be empty"}
	}
	if c.HTTPPort < 0 || c.HTTPPort > 65535 {
		return ErrInvalidServerConfig{Field: "http_port", Reason: "must be between 0 and 65535"}
	}
	if c.TFTPPort < 0 || c.TFTPPort > 65535 {
		return ErrInvalidServerConfig{Field: "tftp_port", Reason: "must be between 0 and 65535"}
	}
	if c.DeviceScriptPort < 0 || c.DeviceScriptPort > 65535 {
		return ErrInvalidServerConfig{Field: "device_script_port", Reason: "must be between 0 and 65535"}
	}
	// Caught here rather than at bind time: the two listeners start in
	// separate goroutines, so a collision surfaces as whichever of them
	// loses the race reporting "address already in use" against the
	// server's own other half — a confusing way to learn the ports are
	// the same value.
	if _, err := c.dataURLPath(c.MediaDir); err != nil {
		return ErrInvalidServerConfig{Field: "media_dir", Reason: "must be under the data directory, which the HTTP server serves"}
	}
	if c.TFTPDir != "" {
		if info, err := os.Stat(c.TFTPDir); err != nil || !info.IsDir() {
			return ErrInvalidServerConfig{Field: "tftp_dir", Reason: "must be an existing directory"}
		}
	}
	for name, file := range c.FirmwareOverrides {
		if name == "" || file == "" {
			return ErrInvalidServerConfig{Field: "firmware_overrides", Reason: "entries are name=file with neither empty"}
		}
	}
	if c.DeviceScriptPort != 0 && c.DeviceScriptPort == c.HTTPPort {
		return ErrInvalidServerConfig{
			Field:  "device_script_port",
			Reason: "must differ from http_port; the device-script server is a second listener",
		}
	}
	return nil
}

// ApplyDefaults fills in zero-valued fields with sensible defaults.
func (c *ServerConfig) ApplyDefaults() {
	if c.DataDir == "" {
		c.DataDir = DefaultDataDir
	}
	if c.HTTPPort == 0 {
		c.HTTPPort = DefaultHTTPPort
	}
	if c.TFTPPort == 0 {
		c.TFTPPort = DefaultTFTPPort
	}
	// Derived from HTTPPort rather than a flat constant so that moving
	// the HTTP port keeps carrying the device-script server with it, as
	// it did when the offset was hardcoded at the bind.
	if c.DeviceScriptPort == 0 {
		c.DeviceScriptPort = c.HTTPPort + DeviceScriptPortOffset
	}
	if c.DHCPConfig.LeaseTime == 0 {
		c.DHCPConfig.LeaseTime = DefaultDHCPLeaseTime
	}
	if c.DHCPConfig.SubnetMask == "" {
		c.DHCPConfig.SubnetMask = "255.255.255.0"
	}
	if c.AlpineVersion == "" {
		c.AlpineVersion = DefaultAlpineVersion
	}
	if c.APKMirror == "" {
		c.APKMirror = DefaultAPKMirror
	}
}

// dataURLPath is the HTTP path of p, a file or directory inside DataDir.
func (c *ServerConfig) dataURLPath(p string) (string, error) {
	dataDir := c.DataDir
	if dataDir == "" {
		dataDir = DefaultDataDir
	}
	rel, err := filepath.Rel(filepath.Clean(dataDir), filepath.Clean(p))
	if err != nil {
		return "", err
	}
	if rel == "." {
		return DataURLPath, nil
	}
	if strings.HasPrefix(rel, "..") {
		return "", ErrInvalidServerConfig{Field: "data_dir", Reason: p + " is outside " + dataDir}
	}
	return path.Join(DataURLPath, filepath.ToSlash(rel)), nil
}
