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

package deployer

import (
	"context"
	"path/filepath"
	"strings"
)

const (
	// DefaultSSHPort is the default SSH port.
	DefaultSSHPort = 22

	// DefaultContainerRuntime is the default container runtime.
	DefaultContainerRuntime = "docker"

	// DefaultRemoteDataDir is the default remote directory for bootstrap data.
	DefaultRemoteDataDir = "/tmp/bootstrap"

	// DefaultContainerName is the default container name.
	DefaultContainerName = "bootstrap-pxe"

	// ContainerFirmwareCacheDir is where pxeboot caches the iPXE firmware
	// it downloads inside the container. In boot-node mode it is a host
	// volume, so a replaced container does not download it again.
	ContainerFirmwareCacheDir = "/var/cache/go-trusted-platform/firmware"

	// firmwareCacheDirSuffix names the boot-node firmware cache beside
	// DataDir when FirmwareCacheDir is unset: /srv/pxeboot caches into
	// /srv/pxeboot-firmware.
	firmwareCacheDirSuffix = "-firmware"

	// bootNodeRestartPolicy restarts a boot node's container after a crash
	// or a host reboot, until it is removed or stopped by hand.
	bootNodeRestartPolicy = "unless-stopped"
)

// volatileDirs are host directories emptied on reboot (tmpfs or cleaned at
// boot). A boot node's volumes must outlive a reboot, so neither may sit
// under one.
var volatileDirs = []string{"/tmp", "/run", "/dev/shm"}

// DeployConfig holds deployment configuration.
type DeployConfig struct {
	// Host is the SSH hostname or IP address.
	Host string

	// Port is the SSH port (default: 22).
	Port int

	// User is the SSH username.
	User string

	// SSHKeyPath is the path to the SSH private key.
	SSHKeyPath string

	// KnownHostsPath is the directory of pinned SSH host-key envelopes the
	// deployer uses to verify the deployer host's key. Deployer SSH is
	// fail-closed: without provisioned pins the SSH client errors rather
	// than trusting the key on first use.
	KnownHostsPath string

	// ContainerRuntime is docker or podman.
	ContainerRuntime string

	// ContainerImage is the Docker image name for the bootstrap container.
	ContainerImage string

	// ManifestPath is the local path to manifest.yaml to copy.
	ManifestPath string

	// ConfigDir is the local config directory to copy.
	ConfigDir string

	// DataDir is the host-side directory the deployer SSHes into and
	// bind-mounts into the bootstrap container as /data. Empty means
	// DefaultRemoteDataDir. The deployer stages the manifest and the
	// netboot media build here before starting the container; the image
	// itself carries nothing under /data.
	DataDir string

	// ContainerName overrides DefaultContainerName for the bootstrap
	// container. Empty means DefaultContainerName.
	ContainerName string

	// RedeployMode controls Verify-then-Deploy idempotency. See the
	// pkg/bootstrap.RedeployMode constants for semantics; the Deployer
	// treats unrecognised values as RedeployIfStale.
	RedeployMode string

	// BootstrapInterface is the host network interface name the
	// bootstrap container's pxeboot daemon binds to (BOOTSTRAP_INTERFACE
	// env var). The image's entrypoint defaults this to "eth0", which
	// is correct for typical jumpbox configurations. Override only on
	// hosts where the bootstrap-network NIC has a non-standard name —
	// e.g. systemd predictable names like "enp1s0", "eno1", or USB
	// dongles like "enxc8a362b837de". When empty the entrypoint's
	// "eth0" default takes effect.
	BootstrapInterface string

	// BootstrapBindHost is the address the bootstrap container's HTTP
	// and TFTP servers bind (BOOTSTRAP_BIND_HOST env var, pxeboot
	// --bind-host). Empty binds every interface. DHCP never binds it: it
	// must receive broadcasts, so it stays on the unspecified address
	// scoped to BootstrapInterface (#93).
	BootstrapBindHost string

	// BootstrapServerIP is the IP address the bootstrap container
	// advertises as the DHCP server and next server, and the address
	// the per-device boot script server binds (BOOTSTRAP_SERVER_IP env
	// var). The HTTP and TFTP servers bind BootstrapBindHost instead.
	// The image's entrypoint defaults this to 192.0.2.1, which
	// matches a typical post-bootstrap provisioning subnet. For the
	// FIRST bootstrap on a fresh deploy (when no provisioning subnet
	// exists yet) this must be set to an IP the deployer host already
	// holds — typically the SMBHost from the orchestrator config.
	// Empty falls through to the entrypoint default.
	BootstrapServerIP string

	// BootstrapHTTPPort is the container's HTTP service port (config
	// endpoint, install-log sink, /health). Zero leaves the entrypoint
	// default (8080) in effect.
	BootstrapHTTPPort int

	// BootstrapDeviceScriptPort is the container's per-device boot
	// script listener port. Zero leaves the entrypoint's derived
	// default (HTTP port + 1) in effect.
	BootstrapDeviceScriptPort int

	// BootstrapDHCPStart and BootstrapDHCPEnd bound the DHCP lease
	// pool the bootstrap container offers to PXE-booting clients
	// (BOOTSTRAP_DHCP_START / BOOTSTRAP_DHCP_END env vars). Defaults
	// in the image entrypoint are 192.0.2.100 / 192.0.2.200.
	// When empty the entrypoint defaults take effect.
	BootstrapDHCPStart string
	BootstrapDHCPEnd   string

	// BootstrapGateway is the default gateway advertised in the DHCP
	// offer (BOOTSTRAP_GATEWAY env var). Empty falls through to the
	// entrypoint default (192.0.2.1).
	BootstrapGateway string

	// BootstrapNoRouter advertises no gateway at all: the DHCP offer and
	// ack carry no router option (3), for an isolated provisioning VLAN
	// whose boot server does not route (BOOTSTRAP_NO_ROUTER). It excludes
	// BootstrapGateway.
	BootstrapNoRouter bool

	// BootstrapDNS is the DNS server advertised in the DHCP offer
	// (BOOTSTRAP_DNS env var). Empty falls through to the entrypoint
	// default (192.0.2.1).
	BootstrapDNS string

	// BootstrapAPKMirror is the install-time APK repository base advertised
	// to PXE clients (BOOTSTRAP_APK_MIRROR env var). The bootstrap server
	// bakes it into the PXE kernel cmdline (alpine_repo= + platform_apk_mirror=)
	// so PXE nodes — which have no /media/cdrom — can resolve packages.
	// Empty falls through to the entrypoint default (the public Alpine
	// mirror), keeping internet-connected installs working.
	BootstrapAPKMirror string

	// NetbootMediaDir is the netboot media build on this machine
	// (container.NetbootMedia), staged into DataDir as it is laid out;
	// required: the container serves every media set from it. Its TFTP tree and arm64 iPXE configure the container
	// (BOOTSTRAP_TFTP_DIR, BOOTSTRAP_ARM64_IPXE).
	NetbootMediaDir string

	// BootstrapProxyDHCP runs the container's DHCP server as a proxy
	// (BOOTSTRAP_PROXY_DHCP).
	BootstrapProxyDHCP bool

	// BootNode keeps the container serving for good: it runs with a
	// restart policy, and the firmware cache is a host volume at
	// FirmwareCacheDir so it outlives the container. DataDir must then be
	// a persistent path.
	BootNode bool

	// FirmwareCacheDir is the host directory mounted at
	// ContainerFirmwareCacheDir in boot-node mode. Empty means DataDir
	// with "-firmware" appended, beside it rather than inside it, so a
	// teardown that deletes DataDir keeps the cache. Only valid with
	// BootNode.
	FirmwareCacheDir string

	// netboot holds the container paths of the staged build's TFTP tree
	// and arm64 iPXE, set by Deploy once the build is staged.
	netboot netbootMediaPaths
}

// DeployResult holds the deployment result.
type DeployResult struct {
	ContainerID string
	Host        string
	Running     bool
}

// Deployer deploys and manages the bootstrap container on a target host.
type Deployer interface {
	// Deploy deploys the bootstrap container to the target host.
	Deploy(ctx context.Context, config *DeployConfig) (*DeployResult, error)

	// Verify checks that the container is running and healthy.
	Verify(ctx context.Context, config *DeployConfig) error

	// Teardown stops and removes the container and data from the target host.
	Teardown(ctx context.Context, config *DeployConfig) error
}

// ApplyDefaults fills in zero-valued fields with sensible defaults.
func (c *DeployConfig) ApplyDefaults() {
	if c.Port == 0 {
		c.Port = DefaultSSHPort
	}
	if c.ContainerRuntime == "" {
		c.ContainerRuntime = DefaultContainerRuntime
	}
	if c.DataDir == "" {
		c.DataDir = DefaultRemoteDataDir
	}
	if c.ContainerName == "" {
		c.ContainerName = DefaultContainerName
	}
	if c.BootNode && c.FirmwareCacheDir == "" {
		c.FirmwareCacheDir = filepath.Clean(c.DataDir) + firmwareCacheDirSuffix
	}
}

// Validate checks the deploy configuration for required fields.
func (c *DeployConfig) Validate() error {
	if err := c.ValidateTeardown(); err != nil {
		return err
	}

	if c.ContainerImage == "" {
		return ErrInvalidDeployConfig{Field: "container_image", Reason: "must not be empty"}
	}
	if c.ManifestPath == "" {
		return ErrInvalidDeployConfig{Field: "manifest_path", Reason: "must not be empty"}
	}
	if c.NetbootMediaDir == "" {
		return ErrInvalidDeployConfig{Field: "netboot_media_dir", Reason: "must not be empty: the container serves the netboot media build's sets (make netboot-media)"}
	}
	if err := c.ValidateRouter(); err != nil {
		return err
	}
	return c.ValidateBootNode()
}

// ValidateRouter refuses a gateway together with BootstrapNoRouter: the
// two say opposite things about the DHCP router option.
func (c *DeployConfig) ValidateRouter() error {
	if c.BootstrapNoRouter && strings.TrimSpace(c.BootstrapGateway) != "" {
		return ErrNoRouterWithGateway{Gateway: c.BootstrapGateway}
	}
	return nil
}

// ValidateBootNode checks the boot-node settings, after ApplyDefaults: a
// boot node's data_dir and firmware cache must be absolute, persistent and
// apart from each other, and a firmware cache without boot-node mode would
// be silently ignored.
func (c *DeployConfig) ValidateBootNode() error {
	if !c.BootNode {
		if c.FirmwareCacheDir != "" {
			return ErrInvalidBootNodeConfig{Field: "firmware_cache_dir", Value: c.FirmwareCacheDir, Reason: "is mounted only in boot-node mode (boot_node: true)"}
		}
		return nil
	}
	if err := checkPersistentDir("data_dir", c.DataDir); err != nil {
		return err
	}
	if err := checkPersistentDir("firmware_cache_dir", c.FirmwareCacheDir); err != nil {
		return err
	}
	if isWithin(c.FirmwareCacheDir, c.DataDir) || isWithin(c.DataDir, c.FirmwareCacheDir) {
		return ErrInvalidBootNodeConfig{Field: "firmware_cache_dir", Value: c.FirmwareCacheDir, Reason: "must not overlap data_dir " + c.DataDir + ": teardown deletes data_dir and must keep the cache"}
	}
	return nil
}

// checkPersistentDir rejects a boot-node host directory that is relative,
// the filesystem root, or under a directory emptied on reboot.
func checkPersistentDir(field, dir string) error {
	if !filepath.IsAbs(dir) {
		return ErrInvalidBootNodeConfig{Field: field, Value: dir, Reason: "must be an absolute host path"}
	}
	if filepath.Clean(dir) == "/" {
		return ErrInvalidBootNodeConfig{Field: field, Value: dir, Reason: "must not be the filesystem root"}
	}
	for _, volatile := range volatileDirs {
		if isWithin(dir, volatile) {
			return ErrInvalidBootNodeConfig{Field: field, Value: dir, Reason: "is under " + volatile + ", which does not survive a reboot"}
		}
	}
	return nil
}

// isWithin reports whether dir is root or a path inside it.
func isWithin(dir, root string) bool {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(dir))
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, "../")
}

// ValidateTeardown checks the subset of fields required to tear down an
// already-running bootstrap container. Teardown only needs the SSH
// connection details and (implicitly) ContainerName/Runtime which both
// fall back to defaults via ApplyDefaults — manifest_path and
// container_image are deploy-time concerns and would (incorrectly)
// reject a valid teardown when only ssh_key_path/host/user are set.
func (c *DeployConfig) ValidateTeardown() error {
	if c.Host == "" {
		return ErrInvalidDeployConfig{Field: "host", Reason: "must not be empty"}
	}
	if c.User == "" {
		return ErrInvalidDeployConfig{Field: "user", Reason: "must not be empty"}
	}
	if c.SSHKeyPath == "" {
		return ErrInvalidDeployConfig{Field: "ssh_key_path", Reason: "must not be empty"}
	}
	return nil
}
