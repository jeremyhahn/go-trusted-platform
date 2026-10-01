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
)

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

	// BootstrapServerIP is the IP address the bootstrap container
	// binds DHCP/TFTP/HTTP services to (BOOTSTRAP_SERVER_IP env var).
	// The image's entrypoint defaults this to 172.16.201.1, which
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
	// in the image entrypoint are 172.16.201.100 / 172.16.201.200.
	// When empty the entrypoint defaults take effect.
	BootstrapDHCPStart string
	BootstrapDHCPEnd   string

	// BootstrapGateway is the default gateway advertised in the DHCP
	// offer (BOOTSTRAP_GATEWAY env var). Empty falls through to the
	// entrypoint default (172.16.201.1).
	BootstrapGateway string

	// BootstrapDNS is the DNS server advertised in the DHCP offer
	// (BOOTSTRAP_DNS env var). Empty falls through to the entrypoint
	// default (172.16.201.1).
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
	return nil
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
