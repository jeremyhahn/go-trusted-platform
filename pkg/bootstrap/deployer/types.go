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

import "context"

// DeployTarget identifies the target platform type.
type DeployTarget string

const (
	// TargetLinux deploys to a standard Linux host with Docker or Podman.
	TargetLinux DeployTarget = "linux"

	// TargetCisco deploys to a Cisco IOS-XE guestshell.
	TargetCisco DeployTarget = "cisco"
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
	// Target is the target platform type (linux or cisco).
	Target DeployTarget

	// Host is the SSH hostname or IP address.
	Host string

	// Port is the SSH port (default: 22).
	Port int

	// User is the SSH username.
	User string

	// SSHKeyPath is the path to the SSH private key.
	SSHKeyPath string

	// ContainerRuntime is docker or podman.
	ContainerRuntime string

	// ContainerImage is the Docker image name for the bootstrap container.
	ContainerImage string

	// ManifestPath is the local path to manifest.yaml to copy.
	ManifestPath string

	// ConfigDir is the local config directory to copy.
	ConfigDir string

	// ProvisioningNetwork configures the provisioning network.
	ProvisioningNetwork ProvisioningNetworkConfig

	// TransferProtocol is the protocol for image transfer (tftp, scp, http).
	// Used by the Cisco deployer.
	TransferProtocol string

	// TransferServer is the IP address of the server hosting the container image.
	// Used by the Cisco deployer.
	TransferServer string

	// CiscoConfigFile is the path to a Cisco IOS-XE configuration file (.cfg).
	// When set, the deployer applies these commands instead of template-rendered config.
	CiscoConfigFile string

	// CiscoAppID is the IOS-XE app-hosting application identifier.
	// Defaults to DefaultCiscoAppID if empty.
	CiscoAppID string

	// CiscoImageFile is the container image filename on router flash.
	// Defaults to DefaultCiscoImageFile if empty.
	CiscoImageFile string
}

// ProvisioningNetworkConfig defines the provisioning network parameters.
type ProvisioningNetworkConfig struct {
	Subnet     string   `yaml:"subnet" json:"subnet"`
	Gateway    string   `yaml:"gateway" json:"gateway"`
	RangeStart string   `yaml:"range_start" json:"range_start"`
	RangeEnd   string   `yaml:"range_end" json:"range_end"`
	DNS        []string `yaml:"dns" json:"dns"`
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
}

// Validate checks the deploy configuration for required fields.
func (c *DeployConfig) Validate() error {
	if c.Host == "" {
		return ErrInvalidDeployConfig{Field: "host", Reason: "must not be empty"}
	}
	if c.User == "" {
		return ErrInvalidDeployConfig{Field: "user", Reason: "must not be empty"}
	}
	if c.SSHKeyPath == "" {
		return ErrInvalidDeployConfig{Field: "ssh_key_path", Reason: "must not be empty"}
	}

	// For Cisco targets, container_image and manifest_path are not required
	// since the image is transferred via TFTP/SCP/HTTP and config comes from
	// a .cfg file or templates.
	if c.Target != TargetCisco {
		if c.ContainerImage == "" {
			return ErrInvalidDeployConfig{Field: "container_image", Reason: "must not be empty"}
		}
		if c.ManifestPath == "" {
			return ErrInvalidDeployConfig{Field: "manifest_path", Reason: "must not be empty"}
		}
	}
	return nil
}
