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
	"path/filepath"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/deployer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
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

// validBMCTrustStrategies is the ClassBMC allowlist: the set of trust
// strategies a node's bmc_trust chain may contain. This mirrors the
// allowedStrategies[ClassBMC] map in pkg/trust/config.go and is kept
// here so validation does not require constructing a full Resolver.
var validBMCTrustStrategies = map[trust.Strategy]struct{}{
	trust.StrategyDANE:   {},
	trust.StrategySPKI:   {},
	trust.StrategyCAFile: {},
	trust.StrategyTOFU:   {},
}

// BootstrapConfig is the top-level configuration for PXE network bootstrap.
type BootstrapConfig struct {
	Deployer  DeployerConfig           `yaml:"deployer"`
	Switch    *SwitchConfig            `yaml:"switch,omitempty"`
	Fabric    *FabricConfig            `yaml:"fabric,omitempty"`
	Subnets   []installer.SubnetConfig `yaml:"subnets,omitempty"`
	Platform  PlatformGlobalConfig     `yaml:"platform"`
	Templates map[string]string        `yaml:"templates"`
	Nodes     []NodeConfig             `yaml:"nodes"`

	// ISOPath is the local filesystem path to the platform ISO that will be
	// staged on the bootstrap container host for virtual-media boot. Required
	// when any node uses boot_method: virtual-media. The file is copied to
	// the container's /data host directory and exposed via the container's
	// SMB share at smb://<deployer.host>/boot/<filename>.
	ISOPath string `yaml:"iso_path,omitempty"`

	// BackupsDir is the client-side directory where factory-cert backups
	// are stored during the BMC enrollment ceremony. The orchestrator writes
	// one PEM file per BMC after a successful bmc_enroll run. Empty defaults
	// to defaultBackupsDir ("~/sources/automatethethings/infra/backups");
	// "~" is expanded to the operator's home directory at load time.
	// BackupsDir is used by the next-wave BMC enrollment flow; parsing and
	// exposing it here lets operators configure the path in bootstrap.yaml
	// today.
	BackupsDir string `yaml:"backups_dir,omitempty"`
}

// defaultBackupsDir is the backups directory used when BackupsDir is empty.
// "~" is expanded to os.UserHomeDir() at load time.
const defaultBackupsDir = "~/sources/automatethethings/infra/backups"

// EffectiveBackupsDir returns the BackupsDir with ~ expanded and the
// defaultBackupsDir applied when BackupsDir is empty.
func (c *BootstrapConfig) EffectiveBackupsDir() (string, error) {
	dir := c.BackupsDir
	if dir == "" {
		dir = defaultBackupsDir
	}
	if len(dir) >= 2 && dir[:2] == "~/" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, dir[2:])
	}
	return dir, nil
}

// FabricConfig describes the network fabric topology for the bootstrap
// deployment. This is an informational record that the orchestrator uses
// to configure switch ports post-enrollment or to validate node placement.
type FabricConfig struct {
	Mode     string          `yaml:"mode"`
	Switches []FabricSwitch  `yaml:"switches,omitempty"`
	Peers    []FabricPeer    `yaml:"peers,omitempty"`
	Segments []FabricSegment `yaml:"segments,omitempty"`
}

// FabricSwitch identifies a physical switch in the fabric.
type FabricSwitch struct {
	ID             string `yaml:"id"`
	Vendor         string `yaml:"vendor"`
	Model          string `yaml:"model,omitempty"`
	MgmtIP         string `yaml:"mgmt-ip"`
	CredentialsRef string `yaml:"credentials-ref,omitempty" secret:"true"`
}

// FabricPeer describes a vPC/MLAG peer-link between two fabric switches.
type FabricPeer struct {
	SwitchA            string   `yaml:"switch-a"`
	SwitchB            string   `yaml:"switch-b"`
	PeerLinkInterfaces []string `yaml:"peer-link-interfaces,omitempty"`
}

// FabricSegment defines a named VLAN segment within the fabric.
type FabricSegment struct {
	Name string `yaml:"name"`
	VLAN int    `yaml:"vlan"`
	Role string `yaml:"role,omitempty"`
}

// PostEnrollmentConfig defines actions the orchestrator takes after a
// node successfully installs and passes its initial health check.
type PostEnrollmentConfig struct {
	// SwitchVLAN is the production VLAN the node's switch port should be
	// moved to after enrollment completes (e.g., "production").
	SwitchVLAN string `yaml:"switch_vlan,omitempty" json:"switch_vlan,omitempty"`

	// RunHealthCheck controls whether the orchestrator polls the node's
	// health endpoint after enrollment. Defaults to true when nil.
	RunHealthCheck *bool `yaml:"run_health_check,omitempty" json:"run_health_check,omitempty"`
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
	Target string `yaml:"target"`
	Host   string `yaml:"host"`
	User   string `yaml:"user"`
	SSHKey string `yaml:"ssh_key"`
	// KnownHostsPath is the directory of pinned SSH host-key envelopes the
	// deployer uses to verify the deployer host key. Deployer SSH is
	// fail-closed: without provisioned pins the deploy/stage phase errors
	// rather than trusting the key on first use.
	KnownHostsPath     string `yaml:"known_hosts_path"`
	ContainerRuntime   string `yaml:"container_runtime"`
	ContainerImage     string `yaml:"container_image"`
	TransferProtocol   string `yaml:"transfer_protocol,omitempty"`
	TransferServer     string `yaml:"transfer_server,omitempty"`
	ContainerImagePath string `yaml:"container_image_path,omitempty"`
	ConfigFile         string `yaml:"config_file,omitempty"`
	AppID              string `yaml:"app_id,omitempty"`
	ImageFile          string `yaml:"image_file,omitempty"`

	// SMBHost is the address the BMC should use to mount the bootstrap
	// container's SMB share for virtual-media boot. Defaults to Host when
	// unset. Override when the orchestrator and the BMC reach the deployer
	// on different interfaces -- e.g. orchestrator SSHes via mgmt
	// (198.51.100.91) but the BMC's L3 path lands on the bootstrap-net
	// interface (198.18.1.91). The SMB URL becomes
	// smb://<smb_host>/boot/<iso>.
	SMBHost string `yaml:"smb_host,omitempty"`

	// DataDir is the host-side directory the deployer SSHes into and
	// bind-mounts into the bootstrap container as /data. The orchestrator
	// stages manifest.yaml + image-extracted PXE assets (vmlinuz,
	// initramfs, autoinstall.sh) here, and the iso-stager uploads each
	// node's ISO into the same path so the smbd inside the container
	// serves it. Defaults to deployer.DefaultRemoteDataDir
	// ("/tmp/bootstrap"). Override when /tmp is too small or when an
	// operator wants persistent staging across reboots.
	DataDir string `yaml:"data_dir,omitempty"`

	// RedeployMode controls how Phase 2 (deploy bootstrap container)
	// behaves when a container of the same name is already present on
	// the deployer host:
	//
	//   "always"    — always tear down and re-deploy. Destructive.
	//                 Use this when the operator iterated on container
	//                 image versions or when /data was wiped externally.
	//   "if-stale"  — verify image + bind mount + /data assets match
	//                 expectations; redeploy only on mismatch. (Default)
	//   "never"     — fail Phase 2 with ErrContainerStateMismatch when
	//                 an unexpected container is present. Safe default
	//                 for production runbooks where Phase 2 should never
	//                 surprise an operator with a destructive teardown.
	//
	// Empty defaults to "if-stale".
	RedeployMode string `yaml:"redeploy_mode,omitempty"`

	// BootstrapInterface is the host network interface the bootstrap
	// container's pxeboot daemon binds to. Defaults to "eth0" inside
	// the container. Override on jumpboxes where the
	// bootstrap-network NIC has a non-standard name (systemd
	// predictable names like enp1s0/eno1, USB dongles like
	// enxc8a362b837de). Sets the BOOTSTRAP_INTERFACE env var on the
	// docker run command so the supervisord-managed pxeboot picks
	// up the right NIC for DHCP/TFTP listening.
	BootstrapInterface string `yaml:"bootstrap_interface,omitempty"`

	// BootstrapServerIP is the IP the bootstrap container's
	// DHCP/TFTP/HTTP services bind to. Default in the entrypoint is
	// 172.16.201.1, suitable for a deployment that already has the
	// provisioning subnet configured. For first bootstrap on a
	// fresh deploy (no provisioning subnet yet) this MUST point at
	// an IP the deployer host already holds, typically the same
	// value as smb_host.
	BootstrapServerIP string `yaml:"bootstrap_server_ip,omitempty"`

	// BootstrapDHCPStart and BootstrapDHCPEnd bound the lease pool
	// the bootstrap container offers. Empty falls through to the
	// entrypoint defaults (172.16.201.100 / .200).
	BootstrapDHCPStart string `yaml:"bootstrap_dhcp_start,omitempty"`
	BootstrapDHCPEnd   string `yaml:"bootstrap_dhcp_end,omitempty"`

	// BootstrapGateway is the default gateway advertised in DHCP
	// offers. Empty falls through to entrypoint default (172.16.201.1).
	BootstrapGateway string `yaml:"bootstrap_gateway,omitempty"`

	// BootstrapDNS is the DNS server advertised in DHCP offers.
	// Empty falls through to entrypoint default (172.16.201.1).
	BootstrapDNS string `yaml:"bootstrap_dns,omitempty"`

	// BootstrapAPKMirror is the install-time APK repository base URL
	// advertised to PXE clients (e.g. http://198.51.100.11:8080). It is
	// threaded to the bootstrap container as BOOTSTRAP_APK_MIRROR, which the
	// PXE boot cmdline turns into alpine_repo=<url>/vX.Y/main (diskless live
	// root) and platform_apk_mirror=<url> (post-switch-root install repo).
	// Empty falls through to the container default (public dl-cdn), which
	// only works when the install network has outbound internet.
	BootstrapAPKMirror string `yaml:"bootstrap_apk_mirror,omitempty"`

	// PXEServiceHost names the platform node that should host the
	// persistent PXE/DHCP service after Phase 5 hand-off. Empty means
	// "the gateway role" (current default behaviour). Set to a hostname
	// (e.g. "lab-node-2") to run PXE on the control-plane, or to a custom
	// node hostname for dedicated PXE deployments. The orchestrator
	// passes this value to platformd's pxe-service init at hand-off
	// time. Phase 2 (transient bootstrap container) still runs on the
	// deployer.host jumpbox regardless — it provisions the very first
	// node, then tears down once the destination platform node takes
	// over.
	PXEServiceHost string `yaml:"pxe_service_host,omitempty"`
}

// EffectiveDataDir returns the configured DataDir or the package default.
// Centralises the "" fallback so callers don't sprinkle defaults.
func (d *DeployerConfig) EffectiveDataDir() string {
	if d.DataDir != "" {
		return d.DataDir
	}
	return DefaultDeployerDataDir
}

// EffectiveRedeployMode normalises the YAML field, defaulting to
// RedeployIfStale.
func (d *DeployerConfig) EffectiveRedeployMode() RedeployMode {
	switch d.RedeployMode {
	case string(RedeployAlways):
		return RedeployAlways
	case string(RedeployNever):
		return RedeployNever
	case "", string(RedeployIfStale):
		return RedeployIfStale
	default:
		return RedeployIfStale
	}
}

// DefaultDeployerDataDir is the host-side staging directory used when
// DeployerConfig.DataDir is unset. Re-exported from
// pkg/bootstrap/deployer so callers in this package don't have to import
// the deployer subpackage just to spell the default.
const DefaultDeployerDataDir = deployer.DefaultRemoteDataDir

// RedeployMode is the parsed form of DeployerConfig.RedeployMode. See
// the YAML field doc on DeployerConfig for semantics.
type RedeployMode string

const (
	// RedeployAlways tears down and re-deploys on every Phase 2 run.
	RedeployAlways RedeployMode = "always"
	// RedeployIfStale (default) inspects the running container and
	// re-deploys only when image/bind-mount/data state does not match
	// expectations.
	RedeployIfStale RedeployMode = "if-stale"
	// RedeployNever fails Phase 2 with ErrContainerStateMismatch when an
	// unexpected container is present. Conservative production default.
	RedeployNever RedeployMode = "never"
)

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
	Vendor string `yaml:"vendor"`
	Host   string `yaml:"host"`
	User   string `yaml:"user"`
	SSHKey string `yaml:"ssh_key"`
	// KnownHostsPath is the directory of pinned SSH host-key envelopes the
	// orchestrator uses to verify the switch host key. Switch SSH is
	// fail-closed: without provisioned pins the switch phase errors rather
	// than trusting the key on first use.
	KnownHostsPath  string                `yaml:"known_hosts_path"`
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

// NodeConfig defines a node to be provisioned via PXE bootstrap.
// A node must have either BMCAddress (for automatic MAC discovery) or MAC
// (for manual specification). Both cannot be empty unless SkipInstall is true.
type NodeConfig struct {
	BMCAddress       string `yaml:"bmc_address,omitempty"`
	BMCUser          string `yaml:"bmc_user,omitempty"`
	BMCPassword      string `yaml:"bmc_password,omitempty" secret:"true"`
	BMCProtocol      string `yaml:"bmc_protocol,omitempty"`
	BMCEncryptionKey string `yaml:"bmc_encryption_key,omitempty" secret:"true"`

	// BMCTrust is the ordered strategy chain the orchestrator uses when
	// establishing TLS connections to this node's BMC during bootstrap.
	// Valid strategies: dane, spki, ca-file, tofu.
	// Empty/omitted → use the platform trust config's ClassBMC default.
	// Only strategies in the ClassBMC allowlist are accepted; the
	// orchestrator rejects any unknown value at validation time.
	BMCTrust []trust.Strategy `yaml:"bmc_trust,omitempty"`

	// BMCSPKIPin is the hex-encoded SHA-256 SubjectPublicKeyInfo pin for
	// this node's BMC certificate. Required when bmc_trust contains "spki".
	// The pin is fed into the spki strategy of the per-run trust resolver
	// as a per-endpoint override.
	BMCSPKIPin string `yaml:"bmc_spki_pin,omitempty"`

	// BMCEnroll signals operator intent to run the BMC enrollment ceremony
	// after the node successfully installs. The actual enrollment is
	// orchestrated by the next-wave `platformctl bmc enroll` flow; this
	// flag is parsed and exposed so the orchestrator can plan enrollment
	// alongside installation without requiring a separate operator step.
	BMCEnroll bool `yaml:"bmc_enroll,omitempty"`

	// MACs lists every NIC MAC the BIOS may PXE-boot from. A node may have
	// multiple onboard NICs and the BIOS picks one at boot time, so all of
	// them must be registered with the PXE server. Legacy bootstrap.yaml files
	// may use the singular `mac:` key, which is migrated automatically by the
	// custom YAML unmarshaller below.
	MACs     []string `yaml:"macs,omitempty"`
	Role     string   `yaml:"role"`
	Hostname string   `yaml:"hostname"`
	// Overrides is an inline per-node YAML override map that is deep-merged
	// on top of the role template at install time. Intended for small,
	// deployment-specific tweaks (hostname, static IPs, BMC credentials).
	Overrides map[string]interface{} `yaml:"overrides,omitempty"`
	// OverridesFile points at an external per-node override YAML file,
	// relative to the bootstrap.yaml's directory. Loaded and deep-merged
	// on top of the role template BEFORE the inline Overrides map is
	// applied, so inline entries win on conflict. Keeping per-node
	// overrides in separate files (under e.g.
	// `deployments/dedicated/overrides/<hostname>.<role>.yaml`) keeps
	// bootstrap.yaml small and lets each deployment profile maintain
	// its own override set without duplicating them inline.
	OverridesFile string `yaml:"overrides_file,omitempty"`

	// BootMethod selects how this node boots the platform ISO during
	// provisioning. Valid values:
	//   - "pxe"           (default) -- node PXE-boots from the bootstrap
	//                                  container via DHCP/TFTP/HTTP. Requires
	//                                  data-plane NIC reachable on the
	//                                  bootstrap L2.
	//   - "virtual-media" -- bootstrap container's BMC client mounts the ISO
	//                       via SMB on the BMC. Use when PXE isn't viable
	//                       (NIC not cabled, wrong VLAN, license-restricted
	//                       Redfish, etc.). Requires bmc_address.
	BootMethod string `yaml:"boot_method,omitempty" json:"boot_method,omitempty"`

	// SkipInstall marks this node as already deployed. The orchestrator
	// skips virtual media mount, ISO staging, power cycling, and install
	// log polling for this node, marking it "installed" immediately.
	// The node is still included in validation (e.g. control-plane count),
	// health checks, and the seed phase. Use this when referencing an
	// existing control-plane node in a config that provisions new workers.
	SkipInstall bool `yaml:"skip_install,omitempty" json:"skip_install,omitempty"`

	// SwitchPort is the physical switch port this node is connected to
	// (e.g., "Ethernet1/36"). Used by the orchestrator for post-enrollment
	// VLAN assignment and by the dry-run report for operator verification.
	SwitchPort string `yaml:"switch_port,omitempty" json:"switch_port,omitempty"`

	// PostEnrollment defines actions the orchestrator takes after the node
	// successfully installs and passes its initial health check.
	PostEnrollment *PostEnrollmentConfig `yaml:"post_enrollment,omitempty" json:"post_enrollment,omitempty"`
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

// HasBoardManagement reports whether the node declares an out-of-band board
// management endpoint the orchestrator can drive (power, boot device, virtual
// media). Today that is a BMC block; the predicate is the single place to
// extend as new controller types are added. When false, the node is
// provisioned with NO hardware operations and the ISO self-boots via its
// after-install action. See BoardController.
func (n *NodeConfig) HasBoardManagement() bool {
	return hasBoardManagement(n)
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
	BMCTrust         []trust.Strategy       `yaml:"bmc_trust,omitempty"`
	BMCSPKIPin       string                 `yaml:"bmc_spki_pin,omitempty"`
	BMCEnroll        bool                   `yaml:"bmc_enroll,omitempty"`
	MAC              string                 `yaml:"mac,omitempty"`
	MACs             []string               `yaml:"macs,omitempty"`
	Role             string                 `yaml:"role"`
	Hostname         string                 `yaml:"hostname"`
	Overrides        map[string]interface{} `yaml:"overrides,omitempty"`
	OverridesFile    string                 `yaml:"overrides_file,omitempty"`
	BootMethod       string                 `yaml:"boot_method,omitempty"`
	SkipInstall      bool                   `yaml:"skip_install,omitempty"`
	SwitchPort       string                 `yaml:"switch_port,omitempty"`
	PostEnrollment   *PostEnrollmentConfig  `yaml:"post_enrollment,omitempty"`
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
	n.BMCTrust = append([]trust.Strategy(nil), shadow.BMCTrust...)
	n.BMCSPKIPin = shadow.BMCSPKIPin
	n.BMCEnroll = shadow.BMCEnroll
	n.Role = shadow.Role
	n.Hostname = shadow.Hostname
	n.Overrides = shadow.Overrides
	n.OverridesFile = shadow.OverridesFile
	n.BootMethod = shadow.BootMethod
	n.SkipInstall = shadow.SkipInstall
	n.SwitchPort = shadow.SwitchPort
	n.PostEnrollment = shadow.PostEnrollment
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

// ProvisioningSubnet returns the first subnet with role "provisioning", or nil.
func (c *BootstrapConfig) ProvisioningSubnet() *installer.SubnetConfig {
	for i := range c.Subnets {
		if c.Subnets[i].Role == installer.SubnetRoleProvisioning {
			return &c.Subnets[i]
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

	// Expand ~ in BackupsDir at load time so callers always see an
	// absolute path and don't need to know the expansion logic.
	if config.BackupsDir != "" {
		if len(config.BackupsDir) >= 2 && config.BackupsDir[:2] == "~/" {
			home, homeErr := os.UserHomeDir()
			if homeErr != nil {
				return nil, ErrParseYAML{Path: path, Err: homeErr}
			}
			config.BackupsDir = filepath.Join(home, config.BackupsDir[2:])
		}
	}

	// Resolve per-node OverridesFile references. Each NodeConfig may
	// carry `overrides_file: <relative-path>` pointing at an external
	// YAML file whose contents are deep-merged onto the role template
	// BEFORE the inline `overrides:` map is applied. File paths are
	// resolved relative to bootstrap.yaml's directory so every
	// deployment bundle stays self-contained.
	bootstrapDir := filepath.Dir(path)
	for i := range config.Nodes {
		node := &config.Nodes[i]
		if node.OverridesFile == "" {
			continue
		}
		overrideFile := node.OverridesFile
		if !filepath.IsAbs(overrideFile) {
			overrideFile = filepath.Join(bootstrapDir, overrideFile)
		}
		raw, err := os.ReadFile(overrideFile)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, ErrConfigFileNotFound{Path: overrideFile}
			}
			return nil, ErrParseYAML{Path: overrideFile, Err: err}
		}
		var fileMap map[string]interface{}
		if err := yaml.Unmarshal(raw, &fileMap); err != nil {
			return nil, ErrParseYAML{Path: overrideFile, Err: err}
		}
		// Deep-merge: start with the file map as the base, then overlay
		// any inline Overrides on top so inline entries win on conflict.
		merged := fileMap
		if len(node.Overrides) > 0 {
			merged = deepMergeOverrides(merged, node.Overrides)
		}
		node.Overrides = merged
	}

	return &config, nil
}

// deepMergeOverrides recursively merges src into dst, with src taking
// precedence. Maps are merged; all other types overwrite.
func deepMergeOverrides(dst, src map[string]interface{}) map[string]interface{} {
	if dst == nil {
		dst = make(map[string]interface{})
	}
	out := make(map[string]interface{}, len(dst))
	for k, v := range dst {
		out[k] = v
	}
	for k, v := range src {
		if existing, ok := out[k]; ok {
			if em, emOK := existing.(map[string]interface{}); emOK {
				if sm, smOK := v.(map[string]interface{}); smOK {
					out[k] = deepMergeOverrides(em, sm)
					continue
				}
			}
		}
		out[k] = v
	}
	return out
}

// Validate checks the BootstrapConfig for correctness and returns the first
// validation error encountered.
func (c *BootstrapConfig) Validate() error {
	// Required top-level fields.
	if c.Deployer.Host == "" {
		return ErrMissingRequiredField{Field: "deployer.host"}
	}
	if provSubnet := c.ProvisioningSubnet(); provSubnet == nil {
		return ErrMissingRequiredField{Field: "subnets (no subnet with role: provisioning)"}
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
		// SkipInstall nodes are already deployed, so they don't need
		// BMC or MAC identity for provisioning.
		if !node.SkipInstall && !node.IsBMCManaged() && !node.IsManual() {
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
		// Only count virtual-media nodes that will actually be installed.
		// SkipInstall nodes don't need ISO staging.
		if !node.SkipInstall && node.EffectiveBootMethod() == BootMethodVirtualMedia {
			if node.BMCAddress == "" {
				return ErrVirtualMediaRequiresBMC{Hostname: node.Hostname}
			}
			virtualMediaCount++
		}

		// Validate bmc_trust strategy chain.
		for _, strategy := range node.BMCTrust {
			if _, ok := validBMCTrustStrategies[strategy]; !ok {
				return ErrInvalidBMCTrust{Hostname: node.Hostname, Strategy: string(strategy)}
			}
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
