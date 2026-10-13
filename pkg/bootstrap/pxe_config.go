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
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/container"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/deployer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
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

// forbiddenOverridePath describes an override key path that duplicates an
// authoritative first-class NodeConfig field. Presence of the path in any
// override map (inline, overrides file, or merged) is a validation error
// regardless of value — the bootstrap injects the value from the node's
// first-class field via ApplyNodeIdentity.
type forbiddenOverridePath struct {
	path     []string
	useField string
}

// forbiddenOverridePaths is the Class A table: override keys that are
// structurally forbidden because a first-class NodeConfig field owns them.
var forbiddenOverridePaths = []forbiddenOverridePath{
	{path: []string{"os", "hostname"}, useField: "nodes[].hostname"},
	{path: []string{"network", "interfaces"}, useField: "nodes[].interfaces"},
	{path: []string{"bmc", "address"}, useField: "nodes[].bmc_address"},
	{path: []string{"bmc", "username"}, useField: "nodes[].bmc_user"},
	{path: []string{"bmc", "password"}, useField: "nodes[].bmc_password"},
	{path: []string{"bmc", "protocol"}, useField: "nodes[].bmc_protocol"},
}

// forbiddenGlobalOverrideKey describes a top-level override key that is
// forbidden only when its value equals the corresponding platform global
// (Class B): equal values are pointless duplication; differing values remain
// legal per-node overrides.
type forbiddenGlobalOverrideKey struct {
	key      string
	useField string
	value    func(*PlatformGlobalConfig) string
}

// forbiddenGlobalOverrideKeys is the Class B table.
var forbiddenGlobalOverrideKeys = []forbiddenGlobalOverrideKey{
	{key: "domain", useField: "platform.domain", value: func(p *PlatformGlobalConfig) string { return p.Domain }},
	{key: "hostmaster", useField: "platform.hostmaster", value: func(p *PlatformGlobalConfig) string { return p.Hostmaster }},
	{key: "tenant-id", useField: "platform.tenant_id", value: func(p *PlatformGlobalConfig) string { return p.TenantID }},
	{key: "tenant_id", useField: "platform.tenant_id", value: func(p *PlatformGlobalConfig) string { return p.TenantID }},
	{key: "environment", useField: "platform.environment", value: func(p *PlatformGlobalConfig) string { return p.Environment }},
}

// BootstrapConfig is the top-level configuration for PXE network bootstrap.
type BootstrapConfig struct {
	Deployer DeployerConfig `yaml:"deployer"`
	// Environment is the reference-network environment the deployment
	// is numbered from (docs/architecture/reference-network.md). Every
	// VLAN, subnet and switch port VLAN list is derived from it; it is
	// required.
	Environment *netplan.Environment `yaml:"environment,omitempty"`
	// Zones tunes built-in zone policy and declares owner-defined zones
	// (offsets 9-99), exactly as sdn.zones does in a platform config.
	Zones     []zone.ZoneConfig    `yaml:"zones,omitempty"`
	Switch    *SwitchConfig        `yaml:"switch,omitempty"`
	Platform  PlatformGlobalConfig `yaml:"platform"`
	Templates map[string]string    `yaml:"templates"`
	Nodes     []NodeConfig         `yaml:"nodes"`

	// ISOPath is the local filesystem path to the platform ISO that will be
	// staged on the bootstrap container host for virtual-media boot. Required
	// when any node uses boot_method: virtual-media. The file is copied to
	// the container's /data host directory and exposed via the container's
	// SMB share at smb://<deployer.host>/boot/<filename>.
	ISOPath string `yaml:"iso_path,omitempty"`

	// BackupsDir is the client-side directory where factory-cert backups
	// are stored during the BMC enrollment ceremony. The orchestrator writes
	// one PEM file per BMC after a successful bmc_enroll run. Like the rest
	// of what a deployment needs, it belongs with the deployment's
	// configuration: empty defaults to defaultBackupsDir beside
	// bootstrap.yaml, a relative path is resolved against bootstrap.yaml's
	// directory, and "~" is expanded to the operator's home directory, all
	// at load time.
	// BackupsDir is used by the next-wave BMC enrollment flow; parsing and
	// exposing it here lets operators configure the path in bootstrap.yaml
	// today.
	BackupsDir string `yaml:"backups_dir,omitempty"`
}

// TemplatePath returns the filesystem path of the template configured for
// role, resolved against configDir when the configured path is relative.
// The second return value reports whether a template is configured at all.
//
// Every reader of Templates goes through this method so that one bootstrap
// config names exactly one file per role, no matter which code path reads it
// or which working directory the process happens to run in. Resolving
// against the bootstrap YAML's own directory rather than the process CWD is
// what makes a bootstrap config relocatable: the operator can invoke
// platformctl from anywhere and the same template is read. An absolute path
// is returned unchanged, and an empty configDir (a config that was not
// loaded from a file) leaves the configured path as written.
func (c *BootstrapConfig) TemplatePath(role, configDir string) (string, bool) {
	path, ok := c.Templates[role]
	if !ok {
		return "", false
	}
	if !filepath.IsAbs(path) && configDir != "" {
		path = filepath.Join(configDir, path)
	}
	return path, true
}

// defaultBackupsDir is the backups directory used when BackupsDir is empty,
// relative to bootstrap.yaml's directory.
const defaultBackupsDir = "backups"

// EffectiveBackupsDir returns the BackupsDir with ~ expanded and the
// defaultBackupsDir applied when BackupsDir is empty. A config loaded by
// LoadBootstrapConfig has both already applied, relative to its file; one
// built in memory resolves them against the working directory.
func (c *BootstrapConfig) EffectiveBackupsDir() (string, error) {
	dir := c.BackupsDir
	if dir == "" {
		dir = defaultBackupsDir
	}
	return expandHome(dir)
}

// expandHome expands a leading "~/" to the operator's home directory.
func expandHome(p string) (string, error) {
	if !strings.HasPrefix(p, "~/") {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, p[2:]), nil
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
	Domain            string   `yaml:"domain"`
	InternalDomain    string   `yaml:"internal_domain"`
	Hostmaster        string   `yaml:"hostmaster"`
	TenantID          string   `yaml:"tenant_id"`
	Environment       string   `yaml:"environment"`
	UpstreamDNS       []string `yaml:"upstream_dns"`
	BootstrapStrategy string   `yaml:"bootstrap_strategy"`

	// HealthTimeout overrides how long the post-install health wait allows a
	// node to complete install-reboot -> firstboot seal -> platformd
	// auto-provision -> ACME enrollment -> service restart before the run
	// gives up on it. Zero uses defaultPostInstallHealthTimeout.
	//
	// Exposed because the right value is hardware- and role-dependent and the
	// cost of guessing low is severe: #134 failed a node that was healthy
	// minutes later, and that failure cancelled the whole remaining-nodes
	// phase. An operator on slower chassis can raise it without a rebuild.
	HealthTimeout time.Duration `yaml:"health_timeout,omitempty"`

	// ControlPlanePort is the TLS port of the control plane's webservice,
	// the webservices[].tls-port its role template declares. The
	// orchestrator dials it to capture the CA bundle and SPKI pin, to seed
	// templates and to probe health, and picks the certificate identity
	// it verifies from the webservice entry on this port. Zero uses
	// DefaultControlPlanePort; set it when the control-plane template
	// moves the webservice.
	ControlPlanePort int `yaml:"control_plane_port,omitempty"`
}

// DefaultControlPlanePort is the control plane's webservice TLS port when
// platform.control_plane_port is unset: the tls-port the shipped
// control-plane template declares.
const DefaultControlPlanePort = 8443

// EffectiveControlPlanePort returns the configured control-plane webservice
// port, or DefaultControlPlanePort when unset. Config validation has already
// bounded an explicit value.
func (c *BootstrapConfig) EffectiveControlPlanePort() int {
	if c == nil || c.Platform.ControlPlanePort == 0 {
		return DefaultControlPlanePort
	}
	return c.Platform.ControlPlanePort
}

// HealthProbePorts returns the HTTPS ports a node health probe tries, in
// order: the control plane's webservice port, then the gateway and worker
// listener (nodeWebserviceTLSPort) and the gateway's 443. A node's port
// depends on its role, which a probe by address cannot see, so the probe
// tries each; a control-plane port equal to one of the others is tried once.
func (c *BootstrapConfig) HealthProbePorts() []int {
	ports := []int{c.EffectiveControlPlanePort()}
	for _, port := range []int{nodeWebserviceTLSPort, gatewayWebserviceTLSPort} {
		if !slices.Contains(ports, port) {
			ports = append(ports, port)
		}
	}
	return ports
}

// EffectivePostInstallHealthTimeout returns the configured post-install health
// timeout, or defaultPostInstallHealthTimeout when unset or non-positive. A
// non-positive value is treated as unset rather than as "no wait": a zero here
// almost always means the key was omitted, and honouring it literally would
// fail every node instantly.
func (c *BootstrapConfig) EffectivePostInstallHealthTimeout() time.Duration {
	if c == nil || c.Platform.HealthTimeout <= 0 {
		return defaultPostInstallHealthTimeout
	}
	return c.Platform.HealthTimeout
}

// DeployerConfig specifies the Linux host that runs the bootstrap container
// and its container runtime.
type DeployerConfig struct {
	Host   string `yaml:"host"`
	User   string `yaml:"user"`
	SSHKey string `yaml:"ssh_key"`
	// KnownHostsPath is the directory of pinned SSH host-key envelopes the
	// deployer uses to verify the deployer host key. Deployer SSH is
	// fail-closed: without provisioned pins the deploy/stage phase errors
	// rather than trusting the key on first use.
	KnownHostsPath   string `yaml:"known_hosts_path"`
	ContainerRuntime string `yaml:"container_runtime"`
	ContainerImage   string `yaml:"container_image"`

	// SMBHost is the address the BMC should use to mount the bootstrap
	// container's SMB share for virtual-media boot. Defaults to Host when
	// unset. Override when the orchestrator and the BMC reach the deployer
	// on different interfaces -- e.g. orchestrator SSHes via mgmt
	// (10.4.6.91) but the BMC's L3 path lands on the bootstrap-net
	// interface (10.4.2.91). The SMB URL becomes
	// smb://<smb_host>/boot/<iso>.
	SMBHost string `yaml:"smb_host,omitempty"`

	// DataDir is the host-side directory the deployer SSHes into and
	// bind-mounts into the bootstrap container as /data. The orchestrator
	// stages manifest.yaml and the netboot media build here, and the
	// iso-stager uploads each node's ISO into the same path so the smbd
	// inside the container serves it. Defaults to deployer.DefaultRemoteDataDir
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

	// BootstrapBindHost is the address the bootstrap container's HTTP
	// and TFTP servers bind. Empty, the default, binds every interface.
	// DHCP never binds it: PXE clients broadcast, and Linux delivers a
	// broadcast only to a socket on the unspecified address, so DHCP
	// stays there, scoped to bootstrap_interface (#93).
	BootstrapBindHost string `yaml:"bootstrap_bind_host,omitempty"`

	// BootstrapServerIP is the IP the bootstrap container advertises as
	// the DHCP server and next server; the per-device boot script server
	// binds it. Default in the entrypoint is
	// 192.0.2.1, suitable for a deployment that already has the
	// provisioning subnet configured. For first bootstrap on a
	// fresh deploy (no provisioning subnet yet) this MUST point at
	// an IP the deployer host already holds, typically the same
	// value as smb_host.
	BootstrapServerIP string `yaml:"bootstrap_server_ip,omitempty"`

	// BootstrapHTTPPort is the port the bootstrap container's HTTP
	// service binds to: the per-MAC config endpoint, the install-log
	// sink and /health all live here. Empty falls through to the
	// entrypoint default (8080).
	//
	// The orchestrator reaches this port too (installLogBaseURL), so
	// setting it moves both the server and every URL pointed at it.
	BootstrapHTTPPort int `yaml:"bootstrap_http_port,omitempty"`

	// BootstrapDeviceScriptPort is the port for the container's second
	// listener, the per-device boot script server
	// (/boot/device/{mac}.ipxe). Empty derives bootstrap_http_port+1.
	//
	// It is configurable because the documented `target: linux`
	// deployer is an ordinary shared jumpbox, where an unrelated
	// service owning the derived port kills pxeboot on bind — the
	// container stays up and supervisord retires the program, so the
	// only symptom is that nothing serves boot scripts.
	BootstrapDeviceScriptPort int `yaml:"bootstrap_device_script_port,omitempty"`

	// BootstrapDHCPStart and BootstrapDHCPEnd bound the lease pool
	// the bootstrap container offers. Empty falls through to the
	// entrypoint defaults (192.0.2.100 / .200).
	BootstrapDHCPStart string `yaml:"bootstrap_dhcp_start,omitempty"`
	BootstrapDHCPEnd   string `yaml:"bootstrap_dhcp_end,omitempty"`

	// BootstrapGateway is the default gateway advertised in DHCP
	// offers. Empty falls through to entrypoint default (192.0.2.1).
	BootstrapGateway string `yaml:"bootstrap_gateway,omitempty"`

	// BootstrapDNS is the DNS server advertised in DHCP offers.
	// Empty falls through to entrypoint default (192.0.2.1).
	BootstrapDNS string `yaml:"bootstrap_dns,omitempty"`

	// BootstrapAPKMirror is the install-time APK repository base URL
	// advertised to PXE clients (e.g. http://10.4.6.11:8080). It is
	// threaded to the bootstrap container as BOOTSTRAP_APK_MIRROR, which the
	// PXE boot cmdline turns into alpine_repo=<url>/vX.Y/main (diskless live
	// root) and platform_apk_mirror=<url> (post-switch-root install repo).
	// Empty falls through to the container default (public dl-cdn), which
	// only works when the install network has outbound internet.
	BootstrapAPKMirror string `yaml:"bootstrap_apk_mirror,omitempty"`

	// NetbootMediaDir is the netboot media build on this machine
	// (container.NetbootMedia: every media set, the Raspberry Pi TFTP tree
	// and the db-signed arm64 iPXE), staged into the container's data
	// directory. Required for a Linux deployer: the container image carries
	// no installer media. A relative path is resolved against
	// bootstrap.yaml's directory at load time.
	NetbootMediaDir string `yaml:"netboot_media_dir,omitempty"`

	// ProxyDHCP runs the container's DHCP server as a proxy: PXE clients
	// get boot options and no lease, for a provisioning segment whose own
	// DHCP server leases addresses.
	ProxyDHCP bool `yaml:"proxy_dhcp,omitempty"`

	// PXEServiceHost names the platform node that should host the
	// persistent PXE/DHCP service after Phase 5 hand-off. Empty means
	// "the gateway role" (current default behaviour). Set to a hostname
	// (e.g. "node-02") to run PXE on the control-plane, or to a custom
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

// DefaultBootstrapHTTPPort is the port the bootstrap container's HTTP
// service uses when bootstrap_http_port is unset. It matches the
// entrypoint default and pxeboot's own --http-port default.
const DefaultBootstrapHTTPPort = 8080

// DeviceScriptPortOffset is added to the HTTP port to derive the
// device-script server's port when bootstrap_device_script_port is
// unset. Re-exported from pkg/bootstrap/container so the two defaults
// cannot drift apart.
const DeviceScriptPortOffset = container.DeviceScriptPortOffset

// maxPort is the highest usable TCP port.
const maxPort = 65535

// validatePorts rejects container ports that cannot work, at config-load
// time rather than after the container has been deployed.
//
// The derived case is the one worth spelling out: bootstrap_http_port
// 65535 with the device-script port unset derives 65536, which is not a
// port at all. Left unchecked that reaches the bind as a silent
// failure, which is exactly the class of problem this whole change is
// about.
func (d *DeployerConfig) validatePorts() error {
	if err := validateExplicitPort("deployer.bootstrap_http_port", d.BootstrapHTTPPort); err != nil {
		return err
	}
	if err := validateExplicitPort("deployer.bootstrap_device_script_port", d.BootstrapDeviceScriptPort); err != nil {
		return err
	}

	// Only the derived value can overflow; an explicit one is already
	// bounded above.
	if d.BootstrapDeviceScriptPort == 0 {
		if derived := d.EffectiveBootstrapHTTPPort() + DeviceScriptPortOffset; derived > maxPort {
			return ErrInvalidPort{
				Field:  "deployer.bootstrap_http_port",
				Port:   d.EffectiveBootstrapHTTPPort(),
				Reason: "derives a device-script port above " + strconv.Itoa(maxPort) + "; set deployer.bootstrap_device_script_port explicitly",
			}
		}
	}

	if d.EffectiveBootstrapHTTPPort() == d.EffectiveBootstrapDeviceScriptPort() {
		return ErrInvalidPort{
			Field:  "deployer.bootstrap_device_script_port",
			Port:   d.EffectiveBootstrapDeviceScriptPort(),
			Reason: "must differ from deployer.bootstrap_http_port; the device-script server is a second listener",
		}
	}
	return nil
}

// validateBindHost rejects a bootstrap_bind_host that is not an IP
// address. Empty is valid: every interface.
func (d *DeployerConfig) validateBindHost() error {
	if d.BootstrapBindHost == "" || net.ParseIP(d.BootstrapBindHost) != nil {
		return nil
	}
	return ErrInvalidConfig{
		Field:  "deployer.bootstrap_bind_host",
		Reason: d.BootstrapBindHost + " is not an IP address",
	}
}

// validateExplicitPort bounds a port an operator actually set. Zero is
// not an error — it means "derive it".
func validateExplicitPort(field string, port int) error {
	if port == 0 {
		return nil
	}
	if port < 1 || port > maxPort {
		return ErrInvalidPort{Field: field, Port: port, Reason: "must be between 1 and " + strconv.Itoa(maxPort)}
	}
	return nil
}

// EffectiveBootstrapHTTPPort returns the configured container HTTP port
// or the default. Centralises the fallback so callers building URLs
// against the container agree with the container's own binding.
func (d *DeployerConfig) EffectiveBootstrapHTTPPort() int {
	if d.BootstrapHTTPPort != 0 {
		return d.BootstrapHTTPPort
	}
	return DefaultBootstrapHTTPPort
}

// EffectiveBootstrapDeviceScriptPort returns the configured
// device-script port, or the HTTP port plus the offset. Derived rather
// than a flat constant so moving the HTTP port carries this listener
// with it, exactly as the hardcoded offset used to.
func (d *DeployerConfig) EffectiveBootstrapDeviceScriptPort() int {
	if d.BootstrapDeviceScriptPort != 0 {
		return d.BootstrapDeviceScriptPort
	}
	return d.EffectiveBootstrapHTTPPort() + DeviceScriptPortOffset
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
	Vendor string `yaml:"vendor"`
	Host   string `yaml:"host"`
	User   string `yaml:"user"`
	SSHKey string `yaml:"ssh_key"`
	// KnownHostsPath is the directory of pinned SSH host-key envelopes the
	// orchestrator uses to verify the switch host key. Switch SSH is
	// fail-closed: without provisioned pins the switch phase errors rather
	// than trusting the key on first use.
	KnownHostsPath string `yaml:"known_hosts_path"`
	// PortAssignments gives each platform switch port its port class. The
	// switch's VLANs (one per zone of the environment) and each port's
	// mode, allowed VLANs, native VLAN and MTU are derived from the
	// environment's network plan.
	PortAssignments []PortAssignment `yaml:"port_assignments"`
}

// PortAssignment gives one physical switch port (or port range such as
// "Eth1/25-27") its port class.
type PortAssignment struct {
	Port        string         `yaml:"port"`
	Class       zone.PortClass `yaml:"class"`
	Description string         `yaml:"description,omitempty"`
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

	// Interfaces lists the node's static network interfaces. Authoritative
	// source for the merged device config's network.interfaces; declaring
	// network.interfaces in overrides is a validation error.
	Interfaces []installer.InterfaceConfig `yaml:"interfaces,omitempty" json:"interfaces,omitempty"`
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

	// Platform, Model, Architecture, Serial and BootModel describe hardware
	// that boots differently from a generic x86 server. Empty means a
	// generic server; see node_platform.go for the values and rules.
	Platform     string `yaml:"platform,omitempty" json:"platform,omitempty"`
	Model        string `yaml:"model,omitempty" json:"model,omitempty"`
	Architecture string `yaml:"architecture,omitempty" json:"architecture,omitempty"`
	Serial       string `yaml:"serial,omitempty" json:"serial,omitempty"`
	BootModel    string `yaml:"boot_model,omitempty" json:"boot_model,omitempty"`

	// SwitchPort is the physical switch port this node is connected to
	// (e.g., "Ethernet1/36"), recorded for operator verification. The port
	// carries its class from the switch phase onward: a hypervisor trunk's
	// native VLAN is provisioning, so no post-enrollment move is needed.
	SwitchPort string `yaml:"switch_port,omitempty" json:"switch_port,omitempty"`
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

// StaticIPv4s returns the dotted-quad IPv4 addresses of the node's
// static interfaces, CIDR suffix stripped. Empty when none. The
// interface type is not consulted — a declared ipv4-address is treated
// as authoritative regardless of type, matching the historical
// override-walk semantics this method replaced.
func (n *NodeConfig) StaticIPv4s() []string {
	var out []string
	for i := range n.Interfaces {
		addr := n.Interfaces[i].IPv4Address
		if addr == "" {
			continue
		}
		// Strip CIDR suffix if present ("10.4.2.140/24" -> "10.4.2.140").
		if slash := strings.Index(addr, "/"); slash > 0 {
			addr = addr[:slash]
		}
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		out = append(out, addr)
	}
	return out
}

// nodeConfigYAML is the on-disk shadow type used to migrate the legacy
// singular `mac:` key into the new `macs:` slice. Operators upgrading from a
// previous bootstrap.yaml that listed only one MAC keep working unmodified.
type nodeConfigYAML struct {
	BMCAddress       string                      `yaml:"bmc_address,omitempty"`
	BMCUser          string                      `yaml:"bmc_user,omitempty"`
	BMCPassword      string                      `yaml:"bmc_password,omitempty" secret:"true"`
	BMCProtocol      string                      `yaml:"bmc_protocol,omitempty"`
	BMCEncryptionKey string                      `yaml:"bmc_encryption_key,omitempty" secret:"true"`
	BMCTrust         []trust.Strategy            `yaml:"bmc_trust,omitempty"`
	BMCSPKIPin       string                      `yaml:"bmc_spki_pin,omitempty"`
	BMCEnroll        bool                        `yaml:"bmc_enroll,omitempty"`
	MAC              string                      `yaml:"mac,omitempty"`
	MACs             []string                    `yaml:"macs,omitempty"`
	Role             string                      `yaml:"role"`
	Hostname         string                      `yaml:"hostname"`
	Interfaces       []installer.InterfaceConfig `yaml:"interfaces,omitempty"`
	Overrides        map[string]interface{}      `yaml:"overrides,omitempty"`
	OverridesFile    string                      `yaml:"overrides_file,omitempty"`
	BootMethod       string                      `yaml:"boot_method,omitempty"`
	SkipInstall      bool                        `yaml:"skip_install,omitempty"`
	Platform         string                      `yaml:"platform,omitempty"`
	Model            string                      `yaml:"model,omitempty"`
	Architecture     string                      `yaml:"architecture,omitempty"`
	Serial           string                      `yaml:"serial,omitempty"`
	BootModel        string                      `yaml:"boot_model,omitempty"`
	SwitchPort       string                      `yaml:"switch_port,omitempty"`
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
	n.Interfaces = append([]installer.InterfaceConfig(nil), shadow.Interfaces...)
	n.Overrides = shadow.Overrides
	n.OverridesFile = shadow.OverridesFile
	n.BootMethod = shadow.BootMethod
	n.SkipInstall = shadow.SkipInstall
	n.SwitchPort = shadow.SwitchPort
	n.Platform = shadow.Platform
	n.Model = shadow.Model
	n.Architecture = shadow.Architecture
	n.Serial = shadow.Serial
	n.BootModel = shadow.BootModel
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

// validateOverrideMap rejects override maps that carry a forbidden key:
// Class A paths (forbiddenOverridePaths) are rejected on presence, Class B
// top-level keys (forbiddenGlobalOverrideKeys) only when the override value
// equals the non-empty platform global. source names the file the map came
// from ("" = unknown, e.g. the merged backstop in Validate); root is the
// override map's own YAML node when available so the error can carry a real
// line number, or nil.
func validateOverrideMap(m map[string]interface{}, source, hostname string, platform *PlatformGlobalConfig, root *yaml.Node) error {
	if len(m) == 0 {
		return nil
	}
	for _, fp := range forbiddenOverridePaths {
		if !overrideMapHasPath(m, fp.path) {
			continue
		}
		return ErrForbiddenOverrideKey{
			Source:   source,
			Line:     findKeyPathLine(root, fp.path...),
			Hostname: hostname,
			KeyPath:  strings.Join(fp.path, "."),
			UseField: fp.useField,
		}
	}
	if platform == nil {
		return nil
	}
	for _, gk := range forbiddenGlobalOverrideKeys {
		globalValue := gk.value(platform)
		if globalValue == "" {
			continue
		}
		v, ok := m[gk.key]
		if !ok {
			continue
		}
		str, isStr := v.(string)
		if !isStr || str != globalValue {
			continue
		}
		return ErrForbiddenOverrideKey{
			Source:   source,
			Line:     findKeyPathLine(root, gk.key),
			Hostname: hostname,
			KeyPath:  gk.key,
			UseField: gk.useField,
		}
	}
	return nil
}

// overrideMapHasPath reports whether the nested key path exists in m. Only
// the final segment is a presence check; intermediate segments must be maps.
func overrideMapHasPath(m map[string]interface{}, path []string) bool {
	cur := m
	for i, key := range path {
		v, ok := cur[key]
		if !ok {
			return false
		}
		if i == len(path)-1 {
			return true
		}
		next, isMap := v.(map[string]interface{})
		if !isMap {
			return false
		}
		cur = next
	}
	return false
}

// findKeyPathLine walks mapping YAML nodes from root following path and
// returns the 1-based line of the final key. Returns 0 when root is nil or
// any path segment is missing, so callers can pass nil when no source
// document is available.
func findKeyPathLine(root *yaml.Node, path ...string) int {
	cur := resolveYAMLNode(root)
	for i, key := range path {
		keyNode, valNode := yamlMappingEntry(cur, key)
		if keyNode == nil {
			return 0
		}
		if i == len(path)-1 {
			return keyNode.Line
		}
		cur = resolveYAMLNode(valNode)
	}
	return 0
}

// resolveYAMLNode unwraps document and alias indirection so callers always
// operate on the underlying mapping/sequence/scalar node.
func resolveYAMLNode(n *yaml.Node) *yaml.Node {
	for n != nil {
		switch {
		case n.Kind == yaml.DocumentNode && len(n.Content) > 0:
			n = n.Content[0]
		case n.Kind == yaml.AliasNode && n.Alias != nil:
			n = n.Alias
		default:
			return n
		}
	}
	return nil
}

// yamlMappingEntry returns the key and value nodes for key inside mapping
// node m, or nil when m is not a mapping or the key is absent.
func yamlMappingEntry(m *yaml.Node, key string) (keyNode, valueNode *yaml.Node) {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil, nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i], m.Content[i+1]
		}
	}
	return nil, nil
}

// inlineOverridesNode locates the `overrides:` mapping of nodes[index]
// inside a parsed bootstrap.yaml document, or nil when absent, so inline
// forbidden-key errors carry the real bootstrap.yaml line number.
func inlineOverridesNode(doc *yaml.Node, index int) *yaml.Node {
	root := resolveYAMLNode(doc)
	_, nodesVal := yamlMappingEntry(root, "nodes")
	nodesVal = resolveYAMLNode(nodesVal)
	if nodesVal == nil || nodesVal.Kind != yaml.SequenceNode || index < 0 || index >= len(nodesVal.Content) {
		return nil
	}
	_, overridesVal := yamlMappingEntry(resolveYAMLNode(nodesVal.Content[index]), "overrides")
	return resolveYAMLNode(overridesVal)
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

	// What a deployment needs beside its config — the netboot media build,
	// the BMC cert backups — is named relative to bootstrap.yaml, like an
	// overrides file, so callers always see an absolute path.
	if config.BackupsDir == "" {
		config.BackupsDir = defaultBackupsDir
	}
	for _, p := range []*string{&config.BackupsDir, &config.Deployer.NetbootMediaDir} {
		if *p == "" {
			continue
		}
		expanded, homeErr := expandHome(*p)
		if homeErr != nil {
			return nil, ErrParseYAML{Path: path, Err: homeErr}
		}
		if !filepath.IsAbs(expanded) {
			expanded = filepath.Join(filepath.Dir(path), expanded)
		}
		*p = expanded
	}

	// Resolve per-node OverridesFile references. Each NodeConfig may
	// carry `overrides_file: <relative-path>` pointing at an external
	// YAML file whose contents are deep-merged onto the role template
	// BEFORE the inline `overrides:` map is applied. File paths are
	// resolved relative to bootstrap.yaml's directory so every
	// deployment bundle stays self-contained.
	// Re-parse the raw document into a yaml.Node tree so forbidden-key
	// validation can report the real bootstrap.yaml line for inline
	// overrides. Each override source (inline map, overrides file) is
	// validated BEFORE the merge so the error names the file to fix.
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, ErrParseYAML{Path: path, Err: err}
	}
	if err := checkRetiredKeys(&doc, path); err != nil {
		return nil, err
	}

	bootstrapDir := filepath.Dir(path)
	for i := range config.Nodes {
		node := &config.Nodes[i]

		// Validate the PRE-MERGE inline overrides against bootstrap.yaml.
		if err := validateOverrideMap(node.Overrides, path, node.Hostname,
			&config.Platform, inlineOverridesNode(&doc, i)); err != nil {
			return nil, err
		}

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

		// Validate the overrides file BEFORE merging so the error carries
		// the override file's own path and line number.
		var fileDoc yaml.Node
		if err := yaml.Unmarshal(raw, &fileDoc); err != nil {
			return nil, ErrParseYAML{Path: overrideFile, Err: err}
		}
		if err := validateOverrideMap(fileMap, overrideFile, node.Hostname,
			&config.Platform, &fileDoc); err != nil {
			return nil, err
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

// Validate checks the BootstrapConfig for correctness, including the
// deployer's netboot media build on disk, and returns the first validation
// error encountered.
func (c *BootstrapConfig) Validate() error {
	if err := c.ValidateDefinition(); err != nil {
		return err
	}
	return c.validateNetbootMedia()
}

// ValidateDefinition checks everything Validate does except the netboot
// media build. It is the check for work that only reads the config, such
// as resolving each node's platform config, and so needs no media on disk.
func (c *BootstrapConfig) ValidateDefinition() error {
	// Required top-level fields.
	if c.Deployer.Host == "" {
		return ErrMissingRequiredField{Field: "deployer.host"}
	}
	if _, err := c.NetworkPlan(); err != nil {
		return err
	}
	if c.Platform.Domain == "" {
		return ErrMissingRequiredField{Field: "platform.domain"}
	}

	if err := c.Deployer.validatePorts(); err != nil {
		return err
	}
	if err := c.Deployer.validateBindHost(); err != nil {
		return err
	}
	if err := validateExplicitPort("platform.control_plane_port", c.Platform.ControlPlanePort); err != nil {
		return err
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

		if err := node.validatePlatform(); err != nil {
			return err
		}

		// Validate bmc_trust strategy chain.
		for _, strategy := range node.BMCTrust {
			// Queried from pkg/trust rather than mirrored here. A local
			// copy is what let #83 happen: two allowlists that agreed
			// until one of them changed.
			if !trust.StrategyAllowedForClass(trust.ClassBMC, strategy) {
				return ErrInvalidBMCTrust{Hostname: node.Hostname, Strategy: string(strategy)}
			}
		}

		// Backstop forbidden-key validation on the merged overrides for
		// programmatically constructed configs. Load-time validation
		// (LoadBootstrapConfig) already reported file:line for YAML
		// sources; here no source document is available.
		if err := validateOverrideMap(node.Overrides, "", node.Hostname, &c.Platform, nil); err != nil {
			return err
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
