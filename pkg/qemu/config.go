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

package qemu

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Config holds the configuration for a QEMU VM
type Config struct {
	// QEMUBinary is the path to the QEMU binary (default: qemu-system-x86_64)
	// Use this to specify a custom QEMU build with CanoKey support
	QEMUBinary string `yaml:"qemu_binary" json:"qemu_binary" mapstructure:"qemu_binary"`

	// ISO file path for installation
	ISO string `yaml:"iso" json:"iso" mapstructure:"iso"`

	// DiskPath is the path to the VM disk image
	DiskPath string `yaml:"disk_path" json:"disk_path" mapstructure:"disk_path"`

	// DiskSize is the size of the disk (e.g., "10G", "20G")
	DiskSize string `yaml:"disk_size" json:"disk_size" mapstructure:"disk_size"`

	// Memory is the amount of RAM in MB
	Memory int `yaml:"memory" json:"memory" mapstructure:"memory"`

	// CPUs is the number of CPU cores
	CPUs int `yaml:"cpus" json:"cpus" mapstructure:"cpus"`

	// WorkDir is the working directory for VM artifacts
	WorkDir string `yaml:"work_dir" json:"work_dir" mapstructure:"work_dir"`

	// SecureBoot enables UEFI Secure Boot
	SecureBoot bool `yaml:"secure_boot" json:"secure_boot" mapstructure:"secure_boot"`

	// Debug enables debug output
	Debug bool `yaml:"debug" json:"debug" mapstructure:"debug"`

	// OVMFCode is the path to OVMF firmware code
	OVMFCode string `yaml:"ovmf_code" json:"ovmf_code" mapstructure:"ovmf_code"`

	// OVMFCodeSecure is the path to OVMF firmware code with Secure Boot
	OVMFCodeSecure string `yaml:"ovmf_code_secure" json:"ovmf_code_secure" mapstructure:"ovmf_code_secure"`

	// OVMFVars is the path to OVMF NVRAM template
	OVMFVars string `yaml:"ovmf_vars" json:"ovmf_vars" mapstructure:"ovmf_vars"`

	// TPMSocket is the path to the TPM socket
	TPMSocket string `yaml:"tpm_socket" json:"tpm_socket" mapstructure:"tpm_socket"`

	// QMPSocketPath is the path to the QMP (QEMU Machine Protocol) socket.
	// This socket enables runtime control of the VM via QMP commands for
	// graceful shutdown, pause/resume, status queries, and other operations.
	// If empty, defaults to $WorkDir/qmp.sock
	QMPSocketPath string `yaml:"qmp_socket_path" json:"qmp_socket_path" mapstructure:"qmp_socket_path"`

	// EnableKVM enables KVM acceleration
	EnableKVM bool `yaml:"enable_kvm" json:"enable_kvm" mapstructure:"enable_kvm"`

	// SerialConsole enables serial console output to stdio (interactive mode)
	SerialConsole bool `yaml:"serial_console" json:"serial_console" mapstructure:"serial_console"`

	// SerialLogFile specifies a file path to capture serial output (non-interactive mode)
	// When set, serial output goes to this file instead of stdio.
	// This is useful for background processes or when TTY is not available.
	// Takes precedence over SerialConsole when set.
	SerialLogFile string `yaml:"serial_log_file" json:"serial_log_file" mapstructure:"serial_log_file"`

	// NoGraphic runs QEMU without graphical output
	NoGraphic bool `yaml:"no_graphic" json:"no_graphic" mapstructure:"no_graphic"`

	// BootOrder specifies the boot order (e.g., "d" for CD-ROM first)
	BootOrder string `yaml:"boot_order" json:"boot_order" mapstructure:"boot_order"`

	// NetworkMode specifies the network configuration ("user", "bridge", or "none")
	// "user" - QEMU's built-in user-mode networking (NAT)
	// "bridge" - Bridge networking using a host bridge interface
	// "none" - No network
	NetworkMode string `yaml:"network_mode" json:"network_mode" mapstructure:"network_mode"`

	// BridgeName specifies the bridge interface to attach to when NetworkMode is "bridge"
	// Default: "trusted0"
	BridgeName string `yaml:"bridge_name" json:"bridge_name" mapstructure:"bridge_name"`

	// MACAddress specifies the MAC address for the VM's network interface
	// If empty, QEMU will generate a random MAC address
	MACAddress string `yaml:"mac_address" json:"mac_address" mapstructure:"mac_address"`

	// TapDevice specifies a pre-created TAP device name for networking.
	// When set, uses direct TAP attachment instead of bridge helper.
	// The TAP device must already exist and be attached to a bridge.
	// This is used for isolated test networks created with testenv.IsolatedNetwork.
	// Takes precedence over NetworkMode when set.
	TapDevice string `yaml:"tap_device" json:"tap_device" mapstructure:"tap_device"`

	// PortForwards specifies port forwarding rules for user-mode networking.
	// Each entry maps a host port to a guest port.
	// Format: []PortForward{{HostPort: 8443, GuestPort: 8443, Protocol: "tcp"}}
	// Only used when NetworkMode is "user" and TapDevice is not set.
	PortForwards []PortForward `yaml:"port_forwards" json:"port_forwards" mapstructure:"port_forwards"`

	// GuestIP specifies the guest IP address for user-mode networking.
	// Default: 10.0.2.15 (QEMU's default guest IP in user-mode NAT)
	GuestIP string `yaml:"guest_ip" json:"guest_ip" mapstructure:"guest_ip"`

	// OVS holds OVS-specific network configuration when using OVS bridges.
	// When enabled, OVS networking takes precedence over bridge mode.
	OVS *OVSConfig `yaml:"ovs" json:"ovs" mapstructure:"ovs"`

	// VNCDisplay specifies the VNC display number (0 = disabled)
	VNCDisplay int `yaml:"vnc_display" json:"vnc_display" mapstructure:"vnc_display"`

	// FIDO2Config holds FIDO2/CanoKey device configuration
	FIDO2 *FIDO2Config `yaml:"fido2" json:"fido2" mapstructure:"fido2"`

	// PXEEnabled enables PXE network boot
	// When true, boot mode "pxe" will configure the VM to boot from network
	PXEEnabled bool `yaml:"pxe_enabled" json:"pxe_enabled" mapstructure:"pxe_enabled"`

	// PXEServerIP is the TFTP/PXE server IP address (for informational purposes)
	// This field is not used in QEMU command generation, but can be used by
	// higher-level orchestration to track which PXE server the VM boots from
	PXEServerIP string `yaml:"pxe_server_ip" json:"pxe_server_ip" mapstructure:"pxe_server_ip"`
}

// PortForward defines a port forwarding rule for user-mode networking
type PortForward struct {
	// HostPort is the port on the host to forward from
	HostPort int `yaml:"host_port" json:"host_port" mapstructure:"host_port"`

	// GuestPort is the port on the guest to forward to
	GuestPort int `yaml:"guest_port" json:"guest_port" mapstructure:"guest_port"`

	// Protocol is either "tcp" or "udp" (default: "tcp")
	Protocol string `yaml:"protocol" json:"protocol" mapstructure:"protocol"`

	// HostAddr is the optional host address to bind to (default: all interfaces)
	HostAddr string `yaml:"host_addr" json:"host_addr" mapstructure:"host_addr"`
}

// String returns the QEMU hostfwd format string for this port forward
func (pf PortForward) String() string {
	protocol := pf.Protocol
	if protocol == "" {
		protocol = "tcp"
	}
	hostAddr := pf.HostAddr
	// Format: hostfwd=[tcp|udp]:[hostaddr]:hostport-[guestaddr]:guestport
	return fmt.Sprintf("hostfwd=%s:%s:%d-:%d", protocol, hostAddr, pf.HostPort, pf.GuestPort)
}

// DefaultPortForwards returns the standard port forwarding rules for go-trusted-platform
// This includes all ports used by the server and client web services and DNS
func DefaultPortForwards() []PortForward {
	return []PortForward{
		// Server public web service (8xxx range)
		{HostPort: 8080, GuestPort: 8080, Protocol: "tcp"}, // HTTP
		{HostPort: 8443, GuestPort: 8443, Protocol: "tcp"}, // HTTPS
		// Server internal web service (9xxx range)
		{HostPort: 9080, GuestPort: 9080, Protocol: "tcp"}, // HTTP
		{HostPort: 9443, GuestPort: 9443, Protocol: "tcp"}, // HTTPS
		// DNS services
		{HostPort: 8053, GuestPort: 8053, Protocol: "udp"}, // Public DNS
		{HostPort: 8053, GuestPort: 8053, Protocol: "tcp"}, // Public DNS (TCP)
		{HostPort: 9053, GuestPort: 9053, Protocol: "udp"}, // Internal DNS
		{HostPort: 9053, GuestPort: 9053, Protocol: "tcp"}, // Internal DNS (TCP)
	}
}

// FIDO2Config holds FIDO2 security key configuration for QEMU
type FIDO2Config struct {
	// Enable enables FIDO2 device emulation
	Enable bool `yaml:"enable" json:"enable" mapstructure:"enable"`

	// Mode specifies the FIDO2 device mode: "canokey", "u2f-emulated", or "u2f-passthru"
	// "canokey" - Full FIDO2 with HMAC-secret support (recommended for LUKS)
	// "u2f-emulated" - Software U2F emulation (U2F only, no FIDO2)
	// "u2f-passthru" - Pass through physical U2F/FIDO2 key from host
	Mode string `yaml:"mode" json:"mode" mapstructure:"mode"`

	// CanoKeyFile is the path to the CanoKey state file (for "canokey" mode)
	// If empty, defaults to $WorkDir/canokey/canokey.state
	// This file stores the key's credentials and is created on first use
	CanoKeyFile string `yaml:"canokey_file" json:"canokey_file" mapstructure:"canokey_file"`

	// CanoKeyPcap is the optional path to capture USB packets (for debugging)
	CanoKeyPcap string `yaml:"canokey_pcap" json:"canokey_pcap" mapstructure:"canokey_pcap"`

	// PassthruDevice is the host hidraw device path (for "u2f-passthru" mode)
	// e.g., "/dev/hidraw0"
	// If empty, QEMU will auto-detect the first U2F device
	PassthruDevice string `yaml:"passthru_device" json:"passthru_device" mapstructure:"passthru_device"`

	// U2FDir is the directory containing U2F emulation files (for "u2f-emulated" mode)
	// Should contain: certificate.pem, private-key.pem, counter, entropy
	// If empty, uses ephemeral mode (auto-generated credentials)
	U2FDir string `yaml:"u2f_dir" json:"u2f_dir" mapstructure:"u2f_dir"`
}

// OVSConfig holds Open vSwitch (OVS) network configuration
type OVSConfig struct {
	// Enable enables OVS networking mode.
	// When enabled, OVS takes precedence over standard bridge mode.
	Enable bool `yaml:"enable" json:"enable" mapstructure:"enable"`

	// BridgeName is the OVS bridge to attach VMs to.
	// Default: "trusted0"
	BridgeName string `yaml:"bridge_name" json:"bridge_name" mapstructure:"bridge_name"`

	// SocketPath is the path to the OVSDB Unix socket.
	// Default: "/var/run/openvswitch/db.sock"
	SocketPath string `yaml:"socket_path" json:"socket_path" mapstructure:"socket_path"`

	// PortName is the optional specific port name for this VM.
	// If empty, a unique port name will be generated based on VM identity.
	PortName string `yaml:"port_name" json:"port_name" mapstructure:"port_name"`

	// VLAN specifies the VLAN ID for the VM's port (1-4094).
	// 0 means no VLAN tag (access port with native VLAN).
	VLAN uint16 `yaml:"vlan" json:"vlan" mapstructure:"vlan"`

	// Trunks specifies allowed VLAN IDs for trunk ports.
	// Only used when VLANMode is "trunk".
	Trunks []uint16 `yaml:"trunks" json:"trunks" mapstructure:"trunks"`

	// VLANMode specifies the VLAN mode: "access", "trunk", or "native-tagged".
	// Default: "access" (single VLAN assignment)
	VLANMode string `yaml:"vlan_mode" json:"vlan_mode" mapstructure:"vlan_mode"`

	// QoS enables Quality of Service configuration.
	QoS *OVSQoSConfig `yaml:"qos" json:"qos" mapstructure:"qos"`

	// ExternalIDs are key-value pairs attached to the OVS port.
	// Useful for identifying VM ports and policy association.
	ExternalIDs map[string]string `yaml:"external_ids" json:"external_ids" mapstructure:"external_ids"`
}

// OVSQoSConfig holds QoS configuration for OVS ports
type OVSQoSConfig struct {
	// MaxRate is the maximum bandwidth in bits per second (e.g., 1000000000 for 1 Gbps)
	MaxRate int64 `yaml:"max_rate" json:"max_rate" mapstructure:"max_rate"`

	// MinRate is the minimum guaranteed bandwidth in bits per second
	MinRate int64 `yaml:"min_rate" json:"min_rate" mapstructure:"min_rate"`

	// Burst is the burst size in bytes
	Burst int64 `yaml:"burst" json:"burst" mapstructure:"burst"`

	// Priority is the QoS queue priority (0-7, higher = more priority)
	Priority int `yaml:"priority" json:"priority" mapstructure:"priority"`
}

// DefaultOVSSocketPath is the default OVSDB socket path
const DefaultOVSSocketPath = "/var/run/openvswitch/db.sock"

// OVSEnabled returns true if OVS networking is configured and enabled
func (c *Config) OVSEnabled() bool {
	return c.OVS != nil && c.OVS.Enable
}

// GetOVSBridgeName returns the OVS bridge name to use
func (c *Config) GetOVSBridgeName() string {
	if c.OVS != nil && c.OVS.BridgeName != "" {
		return c.OVS.BridgeName
	}
	return DefaultBridgeName
}

// GetOVSSocketPath returns the OVSDB socket path
func (c *Config) GetOVSSocketPath() string {
	if c.OVS != nil && c.OVS.SocketPath != "" {
		return c.OVS.SocketPath
	}
	return DefaultOVSSocketPath
}

// DefaultBridgeName is the default bridge name to look for
const DefaultBridgeName = "trusted0"

// DefaultConfig returns a Config with sensible defaults
func DefaultConfig() *Config {
	cfg := &Config{
		QEMUBinary:     "qemu-system-x86_64",
		Memory:         4096,
		CPUs:           runtime.NumCPU(),
		WorkDir:        "work",
		SecureBoot:     false,
		Debug:          false,
		DiskSize:       "10G",
		EnableKVM:      true,
		SerialConsole:  true,
		NoGraphic:      true,
		BootOrder:      "d",
		NetworkMode:    "user",
		BridgeName:     DefaultBridgeName,
		VNCDisplay:     0,
		OVMFCode:       "/usr/share/OVMF/OVMF_CODE_4M.fd",
		OVMFCodeSecure: "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd",
		OVMFVars:       "/usr/share/OVMF/OVMF_VARS_4M.fd",
		PXEEnabled:     false,
	}

	// Auto-detect network mode: use bridge if trusted0 exists, otherwise use NAT
	if BridgeExists(DefaultBridgeName) {
		cfg.NetworkMode = "bridge"
	}

	return cfg
}

// BridgeExists checks if a network bridge with the given name exists on the system
func BridgeExists(bridgeName string) bool {
	// Check if the bridge interface exists in /sys/class/net/<bridge>/bridge
	bridgePath := filepath.Join("/sys/class/net", bridgeName, "bridge")
	if _, err := os.Stat(bridgePath); err == nil {
		return true
	}
	return false
}

// OVSBridgeExists checks if an OVS bridge with the given name exists.
// This is different from standard Linux bridges - OVS bridges are managed
// through OVSDB and may not appear in /sys/class/net/<bridge>/bridge.
// This function checks both the network interface existence and
// verifies it's managed by Open vSwitch.
func OVSBridgeExists(bridgeName string) bool {
	// First check if the interface exists at all
	interfacePath := filepath.Join("/sys/class/net", bridgeName)
	if _, err := os.Stat(interfacePath); err != nil {
		return false
	}

	// OVS bridges have an "openvswitch" driver
	// Check if this is an OVS-managed interface
	driverPath := filepath.Join(interfacePath, "device", "driver")
	if target, err := os.Readlink(driverPath); err == nil {
		if filepath.Base(target) == "openvswitch" {
			return true
		}
	}

	// Alternative: Check for OVS-specific attributes
	// OVS interfaces have different characteristics than standard bridges
	// The bridge subdirectory won't exist for OVS bridges
	bridgePath := filepath.Join(interfacePath, "bridge")
	if _, err := os.Stat(bridgePath); err != nil {
		// No bridge subdirectory - could be OVS
		// Check if interface exists and is up
		operstatePath := filepath.Join(interfacePath, "operstate")
		if _, err := os.Stat(operstatePath); err == nil {
			// Interface exists but isn't a standard bridge
			// Could be OVS - return true to allow further OVSDB validation
			return true
		}
	}

	return false
}

// findBridgeHelper locates the QEMU bridge helper binary on the system.
// Different QEMU distributions install the bridge helper in different locations.
// The bridge helper requires CAP_NET_ADMIN capability or setuid root to work.
func findBridgeHelper() string {
	// Search paths in order of preference
	helperPaths := []string{
		"/usr/lib/qemu/qemu-bridge-helper",      // Debian/Ubuntu
		"/usr/libexec/qemu-bridge-helper",       // RHEL/CentOS/Fedora
		"/usr/local/libexec/qemu-bridge-helper", // Custom builds
	}

	for _, path := range helperPaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return ""
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.DiskPath == "" {
		return fmt.Errorf("disk path is required")
	}

	if c.Memory <= 0 {
		return fmt.Errorf("memory must be greater than 0")
	}

	if c.CPUs <= 0 {
		return fmt.Errorf("CPUs must be greater than 0")
	}

	if c.DiskSize == "" {
		return fmt.Errorf("disk size is required")
	}

	if c.WorkDir == "" {
		return fmt.Errorf("work directory is required")
	}

	// Check OVMF firmware files exist
	ovmfCode := c.OVMFCode
	if c.SecureBoot && c.OVMFCodeSecure != "" {
		ovmfCode = c.OVMFCodeSecure
	}

	if _, err := os.Stat(ovmfCode); err != nil {
		return fmt.Errorf("%w: %s", ErrOVMFNotFound, ovmfCode)
	}

	if _, err := os.Stat(c.OVMFVars); err != nil {
		return fmt.Errorf("%w: %s", ErrOVMFNotFound, c.OVMFVars)
	}

	return nil
}

// GetNVRAMPath returns the path to the NVRAM file
func (c *Config) GetNVRAMPath() string {
	nvramDir := filepath.Join(c.WorkDir, "nvram")
	return filepath.Join(nvramDir, "OVMF_VARS.fd")
}

// GetOVMFCodePath returns the appropriate OVMF code path based on Secure Boot setting
func (c *Config) GetOVMFCodePath() string {
	if c.SecureBoot && c.OVMFCodeSecure != "" {
		return c.OVMFCodeSecure
	}
	return c.OVMFCode
}

// GetTPMSocketPath returns the TPM socket path
func (c *Config) GetTPMSocketPath() string {
	if c.TPMSocket != "" {
		return c.TPMSocket
	}
	tpmDir := filepath.Join(c.WorkDir, "tpm")
	return filepath.Join(tpmDir, "swtpm.sock")
}

// GetQMPSocketPath returns the QMP socket path.
// If QMPSocketPath is not set, returns a default path in the work directory.
func (c *Config) GetQMPSocketPath() string {
	if c.QMPSocketPath != "" {
		return c.QMPSocketPath
	}
	return filepath.Join(c.WorkDir, "qmp.sock")
}
