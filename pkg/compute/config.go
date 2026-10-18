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

package compute

import (
	"fmt"
	"runtime"

	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
)

// OrchestratorConfig holds configuration for the compute orchestrator
type OrchestratorConfig struct {
	// Type is the orchestrator type (vm, container)
	Type ComputeType `json:"type" yaml:"type"`

	// WorkDir is the base working directory for all instances
	WorkDir string `json:"work_dir" yaml:"work_dir"`

	// DefaultMemory is the default memory allocation in MB
	DefaultMemory int `json:"default_memory" yaml:"default_memory"`

	// DefaultCPUs is the default number of CPU cores
	DefaultCPUs int `json:"default_cpus" yaml:"default_cpus"`

	// DefaultDiskSize is the default disk size
	DefaultDiskSize string `json:"default_disk_size" yaml:"default_disk_size"`

	// MaxInstances is the maximum number of instances allowed
	MaxInstances int `json:"max_instances" yaml:"max_instances"`

	// EnableKVM enables KVM acceleration by default (VMs only)
	EnableKVM bool `json:"enable_kvm" yaml:"enable_kvm"`

	// NetworkBridge is the default network bridge name
	NetworkBridge string `json:"network_bridge" yaml:"network_bridge"`

	// OVSSocketPath is the path to the OVSDB socket
	OVSSocketPath string `json:"ovs_socket_path" yaml:"ovs_socket_path"`

	// Arch is the guest architecture of local QEMU VMs: x86_64 or aarch64
	// (VMs only). Empty follows the host: amd64 runs x86_64 guests, arm64 runs
	// aarch64 guests. It also selects the QEMU binary and firmware defaults.
	Arch qemu.Arch `json:"arch,omitempty" yaml:"arch,omitempty"`

	// QEMUBinary is the path to the QEMU binary (VMs only)
	QEMUBinary string `json:"qemu_binary,omitempty" yaml:"qemu_binary,omitempty"`

	// OVMFCode is the path to the UEFI firmware code: OVMF on x86_64, AAVMF
	// on aarch64
	OVMFCode string `json:"ovmf_code,omitempty" yaml:"ovmf_code,omitempty"`

	// OVMFCodeSecure is the path to the UEFI firmware code with Secure Boot
	OVMFCodeSecure string `json:"ovmf_code_secure,omitempty" yaml:"ovmf_code_secure,omitempty"`

	// OVMFVars is the path to the UEFI NVRAM template
	OVMFVars string `json:"ovmf_vars,omitempty" yaml:"ovmf_vars,omitempty"`

	// AutoCleanup enables automatic cleanup of stopped instances
	AutoCleanup bool `json:"auto_cleanup" yaml:"auto_cleanup"`

	// Debug enables debug logging
	Debug bool `json:"debug" yaml:"debug"`

	// PolicyEngine enables 802.1X port authentication on network attachment
	// When nil, network ports are attached without authentication (default behavior)
	// When set, ports are placed in provisioning state until activated
	PolicyEngine policy.PolicyEngine `json:"-" yaml:"-"`

	// PortAuthEnabled enables port authentication on network attachment
	// This flag controls whether the PolicyEngine is used during AttachNetwork
	PortAuthEnabled bool `json:"port_auth_enabled" yaml:"port_auth_enabled"`

	// SharedStorage declares that VM backing storage is reachable from every
	// compute node (e.g. a clustered filesystem or shared NFS/Ceph mount).
	// Live VM migration is gated on this being enabled: with shared storage the
	// destination reaches the same disks so only guest RAM is streamed. When
	// nil or disabled only cold migration (which transfers disks too) is
	// available. See pkg/compute/vm_migrate.go.
	SharedStorage *SharedStorageConfig `json:"shared_storage,omitempty" yaml:"shared_storage,omitempty" mapstructure:"shared_storage"`

	// MigrationCoordinator is the runtime seam that drives the destination
	// daemon side of a VM migration (prepare-incoming / finalize) over mTLS.
	// When nil the orchestrator cannot address a migration destination and
	// MigrateVM fails with ErrMigrationNotConfigured. Wired by the daemon; not
	// serialized.
	MigrationCoordinator MigrationCoordinator `json:"-" yaml:"-"`

	// MigrationTLS supplies the QEMU migration TLS credentials from platform CA
	// material. When nil MigrateVM fails with ErrMigrationTLSNotConfigured —
	// migration is never attempted in plaintext. Wired by the daemon; not
	// serialized.
	MigrationTLS MigrationTLSProvider `json:"-" yaml:"-"`

	// MigrationListenAddress is the IP:port a receiving QEMU binds for an
	// inbound migration stream. Port 0 allocates an ephemeral port per
	// receiver, returned to the source in the PrepareMigration reply; a fixed
	// port admits one receiver at a time. The VM defaults are
	// DefaultMigrationListenAddress; set the migration network's address to
	// keep the stream off every other interface. A receiver is refused, never
	// guessed, when this is empty or unparsable.
	MigrationListenAddress string `json:"migration_listen_address,omitempty" yaml:"migration_listen_address,omitempty" mapstructure:"migration_listen_address"`

	// Provider selects the compute orchestrator backend that the factory
	// (NewOrchestratorForConfig) resolves. An empty value defaults to
	// ProviderLocalContainer to preserve historical behavior. Cloud
	// providers are only resolvable when their build tag is compiled in;
	// naming an uncompiled provider fails closed with a typed
	// ErrComputeProviderNotCompiled.
	Provider ProviderKind `json:"provider,omitempty" yaml:"provider,omitempty" mapstructure:"provider"`

	// AWS holds AWS EC2 (NitroTPM) provider configuration. It is consumed
	// only when Provider is ProviderAWS and the awscompute tag is built.
	AWS *AWSProviderConfig `json:"aws,omitempty" yaml:"aws,omitempty" mapstructure:"aws"`

	// GCP holds Google Compute Engine (vTPM) provider configuration. It is
	// consumed only when Provider is ProviderGCP and the gcpcompute tag is
	// built. Reserved for the GCP orchestrator implemented against the same
	// factory contract.
	GCP *GCPProviderConfig `json:"gcp,omitempty" yaml:"gcp,omitempty" mapstructure:"gcp"`

	// Azure holds Azure Virtual Machine (vTPM) provider configuration. It is
	// consumed only when Provider is ProviderAzure and the azurecompute tag
	// is built. Reserved for the Azure orchestrator implemented against the
	// same factory contract.
	Azure *AzureProviderConfig `json:"azure,omitempty" yaml:"azure,omitempty" mapstructure:"azure"`
}

// SharedStorageConfig declares shared VM backing storage that enables live
// migration. It is intentionally minimal: its presence with Enabled=true is the
// gate live migration checks; the optional fields document the arrangement for
// operators and future validators.
type SharedStorageConfig struct {
	// Enabled turns on live migration. When false the section is inert and only
	// cold migration is available.
	Enabled bool `json:"enabled" yaml:"enabled" mapstructure:"enabled"`

	// Backend names the shared-storage technology (e.g. "nfs", "ceph",
	// "gfs2"). Informational.
	Backend string `json:"backend,omitempty" yaml:"backend,omitempty" mapstructure:"backend"`

	// MountPath is the shared mount every compute node exposes VM images under.
	// Informational; a future validator may assert instance disks live here.
	MountPath string `json:"mount_path,omitempty" yaml:"mount_path,omitempty" mapstructure:"mount_path"`
}

// SharedStorageEnabled reports whether the config declares shared storage. It
// is nil-safe so callers can gate live migration without a preliminary check.
func (c *OrchestratorConfig) SharedStorageEnabled() bool {
	return c != nil && c.SharedStorage != nil && c.SharedStorage.Enabled
}

// AWSProviderConfig holds AWS EC2 provider configuration for launching and
// managing NitroTPM 2.0-enabled instances. Credentials are optional; when
// AccessKeyID/SecretAccessKey are empty the AWS default credential chain
// (IAM role, environment, shared config) is used, matching the go-xkms
// awskms backend convention.
type AWSProviderConfig struct {
	// Region is the AWS region instances are launched in (required).
	Region string `json:"region" yaml:"region" mapstructure:"region"`

	// AccessKeyID is an optional static access key ID. Empty uses the
	// default credential chain.
	AccessKeyID string `json:"access_key_id,omitempty" yaml:"access_key_id,omitempty" mapstructure:"access_key_id"`

	// SecretAccessKey is an optional static secret access key.
	SecretAccessKey string `json:"secret_access_key,omitempty" yaml:"secret_access_key,omitempty" mapstructure:"secret_access_key" secret:"true"`

	// SessionToken is an optional STS session token for temporary
	// credentials.
	SessionToken string `json:"session_token,omitempty" yaml:"session_token,omitempty" mapstructure:"session_token" secret:"true"`

	// Endpoint overrides the EC2 API endpoint. Empty uses the region default.
	// Set this to point the orchestrator at a local AWS emulator for
	// lifecycle testing — Floci (https://floci.io, an MIT-licensed
	// endpoint-URL drop-in on :4566) is the supported emulator and the
	// successor to LocalStack, whose OSS community edition was sunset in
	// 2026-03. See docs/compute/cloud-providers.md. May also point at a
	// private/VPC EC2 endpoint.
	Endpoint string `json:"endpoint,omitempty" yaml:"endpoint,omitempty" mapstructure:"endpoint"`

	// AMIID is the base AMI used for instance launch. The AMI MUST be
	// registered with TpmSupport=v2.0 and boot in UEFI mode for NitroTPM to
	// be available in the guest (required).
	AMIID string `json:"ami_id" yaml:"ami_id" mapstructure:"ami_id"`

	// InstanceType is a Nitro instance type that supports NitroTPM 2.0
	// (e.g. m5.large, c6i.large). Required.
	InstanceType string `json:"instance_type" yaml:"instance_type" mapstructure:"instance_type"`

	// SubnetID is the VPC subnet instances are launched into (optional;
	// falls back to the default subnet for the account/region).
	SubnetID string `json:"subnet_id,omitempty" yaml:"subnet_id,omitempty" mapstructure:"subnet_id"`

	// SecurityGroupIDs are the security groups applied at launch.
	SecurityGroupIDs []string `json:"security_group_ids,omitempty" yaml:"security_group_ids,omitempty" mapstructure:"security_group_ids"`

	// KeyName is the EC2 key pair name for SSH access (optional).
	KeyName string `json:"key_name,omitempty" yaml:"key_name,omitempty" mapstructure:"key_name"`

	// IAMInstanceProfile is the instance profile ARN or name attached at
	// launch (optional).
	IAMInstanceProfile string `json:"iam_instance_profile,omitempty" yaml:"iam_instance_profile,omitempty" mapstructure:"iam_instance_profile"`

	// RootVolumeSizeGiB overrides the root EBS volume size. Zero uses the
	// AMI default.
	RootVolumeSizeGiB int32 `json:"root_volume_size_gib,omitempty" yaml:"root_volume_size_gib,omitempty" mapstructure:"root_volume_size_gib"`

	// SkipNitroTPMAssertion disables the pre-launch AMI NitroTPM 2.0
	// capability check (DescribeImages TpmSupport=v2.0) performed by Create.
	// It defaults false so production launches fail closed unless the AMI is
	// registered TpmSupport=v2.0 — the guarantee that the guest is handed a
	// NitroTPM device. Set true ONLY for non-attesting deployments or local
	// AWS emulators (e.g. Floci) whose DescribeImages does not populate
	// TpmSupport. When true the launched guest is NOT guaranteed a NitroTPM
	// device and VMAttester attestation MUST NOT be relied upon. See
	// docs/compute/cloud-providers.md.
	SkipNitroTPMAssertion bool `json:"skip_nitro_tpm_assertion,omitempty" yaml:"skip_nitro_tpm_assertion,omitempty" mapstructure:"skip_nitro_tpm_assertion"`
}

// GCPProviderConfig holds Google Compute Engine provider configuration.
// Reserved for the GCP orchestrator; the GCP agent implements the
// Orchestrator + capability interfaces against the shared factory using
// these fields.
type GCPProviderConfig struct {
	// ProjectID is the GCP project instances are created in (required).
	ProjectID string `json:"project_id" yaml:"project_id" mapstructure:"project_id"`

	// Zone is the compute zone (e.g. us-central1-a) (required).
	Zone string `json:"zone" yaml:"zone" mapstructure:"zone"`

	// MachineType is the machine type (e.g. n2-standard-2). Confidential
	// VM / Shielded VM machine types provide the vTPM.
	MachineType string `json:"machine_type" yaml:"machine_type" mapstructure:"machine_type"`

	// SourceImage is the boot image (Shielded VM image with vTPM enabled).
	SourceImage string `json:"source_image" yaml:"source_image" mapstructure:"source_image"`

	// Network is the VPC network self-link (optional).
	Network string `json:"network,omitempty" yaml:"network,omitempty" mapstructure:"network"`

	// Subnetwork is the subnet self-link (optional).
	Subnetwork string `json:"subnetwork,omitempty" yaml:"subnetwork,omitempty" mapstructure:"subnetwork"`

	// CredentialsFile is the path to a service-account JSON key (optional;
	// falls back to application default credentials).
	CredentialsFile string `json:"credentials_file,omitempty" yaml:"credentials_file,omitempty" mapstructure:"credentials_file"`
}

// AzureProviderConfig holds Azure Virtual Machine provider configuration.
// Reserved for the Azure orchestrator; the Azure agent implements the
// Orchestrator + capability interfaces against the shared factory using
// these fields.
type AzureProviderConfig struct {
	// SubscriptionID is the Azure subscription (required).
	SubscriptionID string `json:"subscription_id" yaml:"subscription_id" mapstructure:"subscription_id"`

	// ResourceGroup is the resource group VMs are created in (required).
	ResourceGroup string `json:"resource_group" yaml:"resource_group" mapstructure:"resource_group"`

	// Location is the Azure region (e.g. eastus) (required).
	Location string `json:"location" yaml:"location" mapstructure:"location"`

	// VMSize is the VM size (e.g. Standard_D2s_v5). Trusted Launch sizes
	// provide the vTPM.
	VMSize string `json:"vm_size" yaml:"vm_size" mapstructure:"vm_size"`

	// ImageReference is the source image (Trusted Launch capable) (required).
	ImageReference string `json:"image_reference" yaml:"image_reference" mapstructure:"image_reference"`

	// TenantID is the Azure AD tenant for service-principal auth (optional;
	// falls back to the default credential chain).
	TenantID string `json:"tenant_id,omitempty" yaml:"tenant_id,omitempty" mapstructure:"tenant_id"`
}

// DefaultMigrationListenAddress is the defaults-layer value of
// compute.migration_listen_address: every address, an ephemeral port per
// receiver. The stream is mutually authenticated TLS whichever interface
// carries it.
const DefaultMigrationListenAddress = "0.0.0.0:0"

// DefaultOrchestratorConfig returns a configuration with sensible defaults for
// the architecture of the host it runs on
func DefaultOrchestratorConfig(computeType ComputeType) *OrchestratorConfig {
	return defaultOrchestratorConfig(computeType, runtime.GOARCH)
}

// vmFirmware is the QEMU binary and UEFI firmware a guest architecture boots
// with.
type vmFirmware struct {
	qemuBinary string
	code       string
	codeSecure string
	vars       string
}

// hostGuestArch maps a Go host architecture to the guest architecture local
// QEMU VMs run there, the one KVM can accelerate.
var hostGuestArch = map[string]qemu.Arch{
	"amd64": qemu.ArchX86_64,
	"arm64": qemu.ArchAArch64,
}

// vmFirmwareDefaults holds the default QEMU binary and UEFI firmware per guest
// architecture: OVMF on x86_64, AAVMF on aarch64. AAVMF has a single code
// image, so it is also the Secure Boot code default.
var vmFirmwareDefaults = map[qemu.Arch]vmFirmware{
	qemu.ArchX86_64: {
		qemuBinary: "qemu-system-x86_64",
		code:       "/usr/share/OVMF/OVMF_CODE_4M.fd",
		codeSecure: "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd",
		vars:       "/usr/share/OVMF/OVMF_VARS_4M.fd",
	},
	qemu.ArchAArch64: {
		qemuBinary: "qemu-system-aarch64",
		code:       "/usr/share/AAVMF/AAVMF_CODE.fd",
		codeSecure: "/usr/share/AAVMF/AAVMF_CODE.fd",
		vars:       "/usr/share/AAVMF/AAVMF_VARS.fd",
	},
}

// defaultOrchestratorConfig returns the defaults for a host of the given Go
// architecture. A VM config gets the guest architecture that host runs and its
// firmware; a host with no guest mapping gets neither, so Validate rejects it
// instead of assuming x86_64.
func defaultOrchestratorConfig(computeType ComputeType, hostArch string) *OrchestratorConfig {
	config := &OrchestratorConfig{
		Type:            computeType,
		WorkDir:         "/var/lib/trusted-platform/compute",
		DefaultMemory:   4096,
		DefaultCPUs:     runtime.NumCPU(),
		DefaultDiskSize: "20G",
		MaxInstances:    100,
		EnableKVM:       true,
		NetworkBridge:   "br-int",
		OVSSocketPath:   "/var/run/openvswitch/db.sock",
		AutoCleanup:     false,
		Debug:           false,
		PortAuthEnabled: false,
	}

	// VM-specific defaults
	if computeType == ComputeTypeVM {
		config.MigrationListenAddress = DefaultMigrationListenAddress
		if arch, ok := hostGuestArch[hostArch]; ok {
			config.Arch = arch
			config.fillVMFirmware(vmFirmwareDefaults[arch])
		}
	}

	return config
}

// fillVMFirmware sets each empty QEMU binary and firmware path from fw,
// keeping every value already configured.
func (c *OrchestratorConfig) fillVMFirmware(fw vmFirmware) {
	if c.QEMUBinary == "" {
		c.QEMUBinary = fw.qemuBinary
	}
	if c.OVMFCode == "" {
		c.OVMFCode = fw.code
	}
	if c.OVMFCodeSecure == "" {
		c.OVMFCodeSecure = fw.codeSecure
	}
	if c.OVMFVars == "" {
		c.OVMFVars = fw.vars
	}
}

// unsupportedVMArchError reports a VM guest architecture with no QEMU binary
// and firmware defaults.
func unsupportedVMArchError(arch qemu.Arch) error {
	return &SentinelCauseError{Sentinel: ErrInvalidConfiguration, Cause: &MessageError{Msg: fmt.Sprintf("unsupported VM arch %q: use %s or %s", arch, qemu.ArchX86_64, qemu.ArchAArch64)}}
}

// Validate validates the orchestrator configuration
func (c *OrchestratorConfig) Validate() error {
	if !c.Type.IsValid() {
		return &SentinelCauseError{Sentinel: ErrInvalidConfiguration, Cause: &MessageError{Msg: fmt.Sprintf("invalid compute type: %s", c.Type)}}
	}

	if c.WorkDir == "" {
		return &SentinelCauseError{Sentinel: ErrInvalidConfiguration, Cause: &MessageError{Msg: "work directory is required"}}
	}

	if c.DefaultMemory <= 0 {
		return &SentinelCauseError{Sentinel: ErrInvalidConfiguration, Cause: &MessageError{Msg: "default memory must be greater than 0"}}
	}

	if c.DefaultCPUs <= 0 {
		return &SentinelCauseError{Sentinel: ErrInvalidConfiguration, Cause: &MessageError{Msg: "default CPUs must be greater than 0"}}
	}

	if c.DefaultDiskSize == "" {
		return &SentinelCauseError{Sentinel: ErrInvalidConfiguration, Cause: &MessageError{Msg: "default disk size is required"}}
	}

	if c.MaxInstances <= 0 {
		return &SentinelCauseError{Sentinel: ErrInvalidConfiguration, Cause: &MessageError{Msg: "max instances must be greater than 0"}}
	}

	// Validate port authentication configuration
	if c.PortAuthEnabled && c.PolicyEngine == nil {
		return &SentinelCauseError{Sentinel: ErrInvalidConfiguration, Cause: &MessageError{Msg: "policy engine is required when port authentication is enabled"}}
	}

	// QEMU-specific validation. Cloud providers launch VMs through their own
	// SDKs and do not require a local QEMU binary or OVMF firmware, so the
	// firmware checks apply only to the local QEMU provider.
	if c.Type == ComputeTypeVM && !c.Provider.isCloud() {
		if _, ok := vmFirmwareDefaults[c.Arch]; !ok {
			return unsupportedVMArchError(c.Arch)
		}
		if c.QEMUBinary == "" {
			return &SentinelCauseError{Sentinel: ErrInvalidConfiguration, Cause: &MessageError{Msg: "QEMU binary path is required for VM orchestrator"}}
		}
		if c.OVMFCode == "" {
			return &SentinelCauseError{Sentinel: ErrInvalidConfiguration, Cause: &MessageError{Msg: "OVMF code path is required for VM orchestrator"}}
		}
		if c.OVMFVars == "" {
			return &SentinelCauseError{Sentinel: ErrInvalidConfiguration, Cause: &MessageError{Msg: "OVMF vars path is required for VM orchestrator"}}
		}
	}

	return nil
}
