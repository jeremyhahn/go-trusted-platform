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

package bootstrap

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Node role constants define the valid roles a node can have.
const (
	RoleControlPlane = "control-plane"
	RoleGateway      = "gateway"
	RoleWorker       = "worker"
)

// validRoles is a map-based lookup for valid node roles.
var validRoles = map[string]struct{}{
	RoleControlPlane: {},
	RoleGateway:      {},
	RoleWorker:       {},
}

// BootstrapConfig is the top-level configuration for PXE network bootstrap.
type BootstrapConfig struct {
	Deployer            DeployerConfig       `yaml:"deployer"`
	Switch              *SwitchConfig        `yaml:"switch,omitempty"`
	ProvisioningNetwork ProvisioningNetwork  `yaml:"provisioning_network"`
	Platform            PlatformGlobalConfig `yaml:"platform"`
	Templates           map[string]string    `yaml:"templates"`
	Nodes               []NodeConfig         `yaml:"nodes"`

	// ISOPath is the local filesystem path to the platform ISO that will be
	// staged on the bootstrap container host for virtual-media boot. Required
	// when any node uses boot_method: virtual-media. The file is copied to
	// the container's /data host directory and exposed via the container's
	// SMB share at smb://<deployer.host>/boot/<filename>.
	ISOPath string `yaml:"iso_path,omitempty"`
}

// Boot method values for NodeConfig.BootMethod.
const (
	BootMethodPXE          = "pxe"
	BootMethodVirtualMedia = "virtual-media"
)

// validBootMethods enumerates the legal values for NodeConfig.BootMethod.
// Empty defaults to BootMethodPXE.
var validBootMethods = map[string]struct{}{
	BootMethodPXE:          {},
	BootMethodVirtualMedia: {},
}

// PlatformGlobalConfig holds network-level values shared across the deployment.
// Device-specific config (CA, TPM, security) belongs in device templates.
type PlatformGlobalConfig struct {
	Domain            string                `yaml:"domain"`
	InternalDomain    string                `yaml:"internal_domain"`
	Hostmaster        string                `yaml:"hostmaster"`
	TenantID          string                `yaml:"tenant_id"`
	Environment       string                `yaml:"environment"`
	UpstreamDNS       []string              `yaml:"upstream_dns"`
	Networks          map[string]NetworkDef `yaml:"networks"`
	BootstrapStrategy string                `yaml:"bootstrap_strategy"`
}

// NetworkDef defines a network with VLAN and subnet.
type NetworkDef struct {
	VLAN   int    `yaml:"vlan"`
	Subnet string `yaml:"subnet"`
}

// DeployerConfig specifies the deployment host and runtime.
type DeployerConfig struct {
	Target             string `yaml:"target"`
	Host               string `yaml:"host"`
	User               string `yaml:"user"`
	SSHKey             string `yaml:"ssh_key"`
	ContainerRuntime   string `yaml:"container_runtime"`
	TransferProtocol   string `yaml:"transfer_protocol,omitempty"`
	TransferServer     string `yaml:"transfer_server,omitempty"`
	ContainerImagePath string `yaml:"container_image_path,omitempty"`
	ConfigFile         string `yaml:"config_file,omitempty"`
	AppID              string `yaml:"app_id,omitempty"`
	ImageFile          string `yaml:"image_file,omitempty"`

	// SMBHost is the address the BMC should use to mount the bootstrap
	// container's SMB share for virtual-media boot. Defaults to Host when
	// unset. Override when the orchestrator and the BMC reach the deployer
	// on different interfaces — e.g. orchestrator SSHes via mgmt
	// (198.51.100.91) but the BMC's L3 path lands on the bootstrap-net
	// interface (198.18.1.91). The SMB URL becomes
	// smb://<smb_host>/boot/<iso>.
	SMBHost string `yaml:"smb_host,omitempty"`
}

// EffectiveSMBHost returns SMBHost when set, otherwise Host. Centralises the
// default so callers don't sprinkle "" checks.
func (d *DeployerConfig) EffectiveSMBHost() string {
	if d.SMBHost != "" {
		return d.SMBHost
	}
	return d.Host
}

// SwitchConfig specifies optional network switch configuration.
type SwitchConfig struct {
	Vendor          string                `yaml:"vendor"`
	Host            string                `yaml:"host"`
	User            string                `yaml:"user"`
	SSHKey          string                `yaml:"ssh_key"`
	VLANs           map[string]NetworkDef `yaml:"vlans"`
	PortAssignments []PortAssignment      `yaml:"port_assignments"`
}

// PortAssignment maps a physical switch port to VLAN configuration.
type PortAssignment struct {
	Port        string `yaml:"port"`
	Mode        string `yaml:"mode"`
	VLANs       []int  `yaml:"vlans"`
	Description string `yaml:"description"`
}

// ProvisioningNetwork defines the PXE provisioning network.
type ProvisioningNetwork struct {
	Subnet         string   `yaml:"subnet"`
	Gateway        string   `yaml:"gateway"`
	DHCPRangeStart string   `yaml:"dhcp_range_start"`
	DHCPRangeEnd   string   `yaml:"dhcp_range_end"`
	DNS            []string `yaml:"dns"`
}

// NodeConfig defines a node to be provisioned via PXE bootstrap.
// A node must have either BMCAddress (for automatic MAC discovery) or MAC
// (for manual specification). Both cannot be empty.
type NodeConfig struct {
	BMCAddress       string                 `yaml:"bmc_address,omitempty"`
	BMCUser          string                 `yaml:"bmc_user,omitempty"`
	BMCPassword      string                 `yaml:"bmc_password,omitempty" secret:"true"`
	BMCProtocol      string                 `yaml:"bmc_protocol,omitempty"`
	BMCEncryptionKey string                 `yaml:"bmc_encryption_key,omitempty" secret:"true"`
	BMCSkipTLSVerify bool                   `yaml:"bmc_skip_tls_verify,omitempty"`
	// MACs lists every NIC MAC the BIOS may PXE-boot from. A node may have
	// multiple onboard NICs and the BIOS picks one at boot time, so all of
	// them must be registered with the PXE server. Legacy bootstrap.yaml files
	// may use the singular `mac:` key, which is migrated automatically by the
	// custom YAML unmarshaller below.
	MACs             []string               `yaml:"macs,omitempty"`
	Role             string                 `yaml:"role"`
	Hostname         string                 `yaml:"hostname"`
	Overrides        map[string]interface{} `yaml:"overrides,omitempty"`

	// BootMethod selects how this node boots the platform ISO during
	// provisioning. Valid values:
	//   - "pxe"           (default) — node PXE-boots from the bootstrap
	//                                  container via DHCP/TFTP/HTTP. Requires
	//                                  data-plane NIC reachable on the
	//                                  bootstrap L2.
	//   - "virtual-media" — bootstrap container's BMC client mounts the ISO
	//                       via SMB on the BMC. Use when PXE isn't viable
	//                       (NIC not cabled, wrong VLAN, license-restricted
	//                       Redfish, etc.). Requires bmc_address.
	BootMethod string `yaml:"boot_method,omitempty" json:"boot_method,omitempty"`
}

// EffectiveBootMethod returns the BootMethod with empty normalised to "pxe".
// Centralises the default so callers don't sprinkle "" checks everywhere.
func (n *NodeConfig) EffectiveBootMethod() string {
	if n.BootMethod == "" {
		return BootMethodPXE
	}
	return n.BootMethod
}

// IsBMCManaged returns true if the node uses BMC for management and MAC discovery.
func (n *NodeConfig) IsBMCManaged() bool {
	return n.BMCAddress != ""
}

// IsManual returns true if the node has at least one manually specified MAC
// and no BMC address (so MAC discovery cannot run).
func (n *NodeConfig) IsManual() bool {
	return n.BMCAddress == "" && len(n.MACs) > 0
}

// PrimaryMAC returns the first configured MAC, or empty string if none.
func (n *NodeConfig) PrimaryMAC() string {
	if len(n.MACs) == 0 {
		return ""
	}
	return n.MACs[0]
}

// nodeConfigYAML is the on-disk shadow type used to migrate the legacy
// singular `mac:` key into the new `macs:` slice. Operators upgrading from a
// previous bootstrap.yaml that listed only one MAC keep working unmodified.
type nodeConfigYAML struct {
	BMCAddress       string                 `yaml:"bmc_address,omitempty"`
	BMCUser          string                 `yaml:"bmc_user,omitempty"`
	BMCPassword      string                 `yaml:"bmc_password,omitempty" secret:"true"`
	BMCProtocol      string                 `yaml:"bmc_protocol,omitempty"`
	BMCEncryptionKey string                 `yaml:"bmc_encryption_key,omitempty" secret:"true"`
	BMCSkipTLSVerify bool                   `yaml:"bmc_skip_tls_verify,omitempty"`
	MAC              string                 `yaml:"mac,omitempty"`
	MACs             []string               `yaml:"macs,omitempty"`
	Role             string                 `yaml:"role"`
	Hostname         string                 `yaml:"hostname"`
	Overrides        map[string]interface{} `yaml:"overrides,omitempty"`
	BootMethod       string                 `yaml:"boot_method,omitempty"`
}

// UnmarshalYAML accepts both the new `macs:` slice and the legacy `mac:`
// scalar form. When both are present the slice wins and the legacy value is
// merged in if not already listed.
func (n *NodeConfig) UnmarshalYAML(value *yaml.Node) error {
	var shadow nodeConfigYAML
	if err := value.Decode(&shadow); err != nil {
		return err
	}
	n.BMCAddress = shadow.BMCAddress
	n.BMCUser = shadow.BMCUser
	n.BMCPassword = shadow.BMCPassword
	n.BMCProtocol = shadow.BMCProtocol
	n.BMCEncryptionKey = shadow.BMCEncryptionKey
	n.BMCSkipTLSVerify = shadow.BMCSkipTLSVerify
	n.Role = shadow.Role
	n.Hostname = shadow.Hostname
	n.Overrides = shadow.Overrides
	n.BootMethod = shadow.BootMethod
	n.MACs = append([]string(nil), shadow.MACs...)
	if shadow.MAC != "" {
		found := false
		for _, m := range n.MACs {
			if m == shadow.MAC {
				found = true
				break
			}
		}
		if !found {
			n.MACs = append(n.MACs, shadow.MAC)
		}
	}
	return nil
}

// LoadBootstrapConfig reads and parses a PXE bootstrap YAML configuration file.
func LoadBootstrapConfig(path string) (*BootstrapConfig, error) {
	if path == "" {
		return nil, ErrMissingRequiredField{Field: "config path"}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrConfigFileNotFound{Path: path}
		}
		return nil, ErrParseYAML{Path: path, Err: err}
	}

	var config BootstrapConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, ErrParseYAML{Path: path, Err: err}
	}

	return &config, nil
}

// Validate checks the BootstrapConfig for correctness and returns the first
// validation error encountered.
func (c *BootstrapConfig) Validate() error {
	// Required top-level fields.
	if c.Deployer.Host == "" {
		return ErrMissingRequiredField{Field: "deployer.host"}
	}
	if c.ProvisioningNetwork.Subnet == "" {
		return ErrMissingRequiredField{Field: "provisioning_network.subnet"}
	}
	if c.Platform.Domain == "" {
		return ErrMissingRequiredField{Field: "platform.domain"}
	}

	if len(c.Nodes) == 0 {
		return ErrInvalidBootstrapConfig{Reason: "at least one node is required"}
	}

	// Validate each node.
	controlPlaneCount := 0
	virtualMediaCount := 0
	macSeen := make(map[string][]string) // MAC -> list of hostnames
	bmcSeen := make(map[string]string)   // BMC address -> hostname

	for i := range c.Nodes {
		node := &c.Nodes[i]

		if node.Hostname == "" {
			return ErrMissingRequiredField{Field: "nodes[].hostname"}
		}

		// Validate identity: must have either BMC address or MAC.
		if !node.IsBMCManaged() && !node.IsManual() {
			return ErrNodeMissingIdentity{Hostname: node.Hostname}
		}

		// Validate role.
		if _, ok := validRoles[node.Role]; !ok {
			return ErrInvalidNodeRole{Hostname: node.Hostname, Role: node.Role}
		}

		// Validate boot method (default empty -> "pxe").
		if node.BootMethod != "" {
			if _, ok := validBootMethods[node.BootMethod]; !ok {
				return ErrInvalidBootMethod{Hostname: node.Hostname, Value: node.BootMethod}
			}
		}
		if node.EffectiveBootMethod() == BootMethodVirtualMedia {
			if node.BMCAddress == "" {
				return ErrVirtualMediaRequiresBMC{Hostname: node.Hostname}
			}
			virtualMediaCount++
		}

		if node.Role == RoleControlPlane {
			controlPlaneCount++
		}

		// Track MAC duplicates (only for manual nodes that already have MACs).
		for _, m := range node.MACs {
			if m != "" {
				macSeen[m] = append(macSeen[m], node.Hostname)
			}
		}

		// Track BMC address duplicates.
		if node.BMCAddress != "" {
			if existing, ok := bmcSeen[node.BMCAddress]; ok {
				return ErrInvalidBootstrapConfig{
					Reason: "duplicate bmc_address " + node.BMCAddress +
						" on nodes " + existing + " and " + node.Hostname,
				}
			}
			bmcSeen[node.BMCAddress] = node.Hostname
		}
	}

	// Check for duplicate MACs.
	for mac, hostnames := range macSeen {
		if len(hostnames) > 1 {
			return ErrDuplicateMAC{MAC: mac, Hostnames: hostnames}
		}
	}

	// Control-plane count validation.
	if controlPlaneCount == 0 {
		return ErrInvalidControlPlaneCount{Count: 0}
	}
	if controlPlaneCount != 1 && (controlPlaneCount < 3 || controlPlaneCount%2 == 0) {
		return ErrInvalidControlPlaneCount{Count: controlPlaneCount}
	}

	// If any node uses virtual-media boot, the bootstrap must know where the
	// platform ISO lives so it can stage it on the deployer host for the BMC
	// SMB share. ISOPath is purely a virtual-media concern; PXE-only configs
	// may leave it unset.
	if virtualMediaCount > 0 && c.ISOPath == "" {
		return ErrMissingRequiredField{Field: "iso_path (required when any node uses boot_method: virtual-media)"}
	}

	return nil
}
