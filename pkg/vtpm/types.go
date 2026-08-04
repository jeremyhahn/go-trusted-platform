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

package vtpm

import (
	"context"
	"crypto/x509"
	"io"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// TPMVersion represents the TPM specification version.
type TPMVersion string

const (
	// TPMVersion20 represents TPM 2.0.
	TPMVersion20 TPMVersion = "2.0"
)

// String returns the string representation of TPMVersion.
func (v TPMVersion) String() string {
	return string(v)
}

// IsValid checks if the TPM version is valid.
func (v TPMVersion) IsValid() bool {
	switch v {
	case TPMVersion20:
		return true
	}
	return false
}

// BundleMode represents the bundle creation mode.
type BundleMode string

const (
	// BundleModeTemplate creates a template without identity (EK cert issued at clone time).
	BundleModeTemplate BundleMode = "template"

	// BundleModePreAssigned creates a complete bundle with identity (EK cert issued at creation time).
	BundleModePreAssigned BundleMode = "pre-assigned"
)

// String returns the string representation of BundleMode.
func (m BundleMode) String() string {
	return string(m)
}

// IsValid checks if the bundle mode is valid.
func (m BundleMode) IsValid() bool {
	switch m {
	case BundleModeTemplate, BundleModePreAssigned:
		return true
	}
	return false
}

// EKAlgorithm represents the EK key algorithm.
type EKAlgorithm string

const (
	// EKAlgorithmRSA uses RSA 2048 for the EK.
	EKAlgorithmRSA EKAlgorithm = "RSA"

	// EKAlgorithmECC uses ECC P-256 for the EK.
	EKAlgorithmECC EKAlgorithm = "ECC"
)

// String returns the string representation of EKAlgorithm.
func (a EKAlgorithm) String() string {
	return string(a)
}

// IsValid checks if the algorithm is valid.
func (a EKAlgorithm) IsValid() bool {
	switch a {
	case EKAlgorithmRSA, EKAlgorithmECC:
		return true
	}
	return false
}

// NVIndex returns the TCG-defined NV index for EK certificates.
func (a EKAlgorithm) NVIndex() uint32 {
	switch a {
	case EKAlgorithmRSA:
		return 0x01C00002 // TCG PC Client Platform spec
	case EKAlgorithmECC:
		return 0x01C0000A // TCG PC Client Platform spec
	default:
		return 0x01C00002
	}
}

// VTPMConfig holds configuration for vTPM generation.
type VTPMConfig struct {
	// Version is the TPM specification version (default: 2.0).
	Version TPMVersion `yaml:"version" json:"version"`

	// StoragePath is the directory where vTPM instances are stored.
	StoragePath string `yaml:"storage-path" json:"storage_path"`

	// EKAlgorithm is the default EK key algorithm (default: RSA).
	EKAlgorithm EKAlgorithm `yaml:"ek-algorithm" json:"ek_algorithm"`

	// PCRBanks specifies the PCR banks for swtpm initialization.
	// Default: ["sha256"]
	PCRBanks []string `yaml:"pcr-banks" json:"pcr_banks"`

	// OVMFCode is the path to OVMF firmware code.
	OVMFCode string `yaml:"ovmf-code" json:"ovmf_code"`

	// OVMFVars is the path to OVMF NVRAM template.
	OVMFVars string `yaml:"ovmf-vars" json:"ovmf_vars"`

	// SecureBootEnabled enables Secure Boot key generation by default.
	SecureBootEnabled bool `yaml:"secure-boot-enabled" json:"secure_boot_enabled"`

	// Debug enables debug output.
	Debug bool `yaml:"debug" json:"debug"`
}

// DefaultVTPMConfig returns a VTPMConfig with sensible defaults.
func DefaultVTPMConfig() *VTPMConfig {
	return &VTPMConfig{
		Version:           TPMVersion20,
		StoragePath:       "/var/lib/trusted-platform/vtpm",
		EKAlgorithm:       EKAlgorithmRSA,
		PCRBanks:          []string{"sha256"},
		OVMFCode:          "/usr/share/OVMF/OVMF_CODE_4M.fd",
		OVMFVars:          "/usr/share/OVMF/OVMF_VARS_4M.fd",
		SecureBootEnabled: false,
		Debug:             false,
	}
}

// Validate validates the VTPMConfig.
func (c *VTPMConfig) Validate() error {
	if c.StoragePath == "" {
		return ErrInvalidConfig{Field: "StoragePath", Reason: "cannot be empty"}
	}
	if c.Version != "" && !c.Version.IsValid() {
		return ErrInvalidConfig{Field: "Version", Reason: "invalid TPM version"}
	}
	if c.EKAlgorithm != "" && !c.EKAlgorithm.IsValid() {
		return ErrInvalidConfig{Field: "EKAlgorithm", Reason: "invalid EK algorithm"}
	}
	return nil
}

// ApplyDefaults applies default values to empty fields.
func (c *VTPMConfig) ApplyDefaults() {
	defaults := DefaultVTPMConfig()
	if c.Version == "" {
		c.Version = defaults.Version
	}
	if c.StoragePath == "" {
		c.StoragePath = defaults.StoragePath
	}
	if c.EKAlgorithm == "" {
		c.EKAlgorithm = defaults.EKAlgorithm
	}
	if len(c.PCRBanks) == 0 {
		c.PCRBanks = defaults.PCRBanks
	}
	if c.OVMFCode == "" {
		c.OVMFCode = defaults.OVMFCode
	}
	if c.OVMFVars == "" {
		c.OVMFVars = defaults.OVMFVars
	}
}

// VTPMInstance represents a generated virtual TPM instance.
type VTPMInstance struct {
	// ID is the unique identifier for this vTPM instance.
	ID string `json:"id"`

	// Version is the TPM specification version.
	Version TPMVersion `json:"version"`

	// StoragePath is the directory containing this vTPM's state files.
	StoragePath string `json:"storage_path"`

	// EKFingerprint is the SHA-256 fingerprint of the EK certificate.
	EKFingerprint string `json:"ek_fingerprint"`

	// EKCertificate is the EK certificate (DER encoded).
	EKCertificate *x509.Certificate `json:"-"`

	// SRKHandle is the TPM handle for the Storage Root Key.
	SRKHandle uint32 `json:"srk_handle"`

	// DeviceProfileID is the associated device profile ID (optional).
	DeviceProfileID uint64 `json:"device_profile_id,omitempty"`

	// DeviceProfile is the associated device profile (optional).
	DeviceProfile *entities.DeviceProfile `json:"-"`

	// SocketPath is the Unix socket path for TPM communication.
	SocketPath string `json:"socket_path"`

	// NVRAMPath is the path to the OVMF NVRAM file.
	NVRAMPath string `json:"nvram_path"`

	// CreatedAt is the instance creation timestamp.
	CreatedAt time.Time `json:"created_at"`

	// Running indicates if the vTPM is currently running.
	Running bool `json:"running"`
}

// Generator provides vTPM instance generation operations.
// This interface focuses on the generation and lifecycle of vTPM instances
// with support for device profile association and EK fingerprint extraction.
type Generator interface {
	// Generate creates a new vTPM instance with the specified options.
	// Returns the instance with its unique ID, EK fingerprint, and storage paths.
	Generate(ctx context.Context, opts *GenerateOptions) (*VTPMInstance, error)

	// GenerateForProfile creates a vTPM instance associated with a device profile.
	// The device profile ID is stored with the instance for later retrieval.
	GenerateForProfile(ctx context.Context, profile *entities.DeviceProfile, opts *GenerateOptions) (*VTPMInstance, error)

	// Get retrieves a vTPM instance by ID.
	Get(ctx context.Context, id string) (*VTPMInstance, error)

	// GetByProfile retrieves the vTPM instance associated with a device profile.
	GetByProfile(ctx context.Context, profileID uint64) (*VTPMInstance, error)

	// Delete removes a vTPM instance and all its state files.
	Delete(ctx context.Context, id string) error

	// List returns all vTPM instances.
	List(ctx context.Context) ([]*VTPMInstance, error)

	// Start starts the swtpm daemon for the vTPM instance.
	Start(ctx context.Context, id string) error

	// Stop stops the swtpm daemon for the vTPM instance.
	Stop(ctx context.Context, id string) error

	// IsRunning checks if the vTPM instance is running.
	IsRunning(id string) bool

	// ExportEKCertificate exports the EK certificate for the vTPM instance.
	ExportEKCertificate(ctx context.Context, id string) (*x509.Certificate, error)

	// GetEKFingerprint returns the EK certificate fingerprint.
	GetEKFingerprint(ctx context.Context, id string) (string, error)

	// Close releases resources held by the generator.
	Close() error
}

// GenerateOptions configures vTPM instance generation.
type GenerateOptions struct {
	// Hostname is the hostname for the vTPM (used in EK certificate CN).
	Hostname string

	// EKAlgorithm specifies the EK key algorithm (default: RSA).
	EKAlgorithm EKAlgorithm

	// SecureBootEnabled enables Secure Boot key generation and NVRAM enrollment.
	SecureBootEnabled bool

	// Labels contains custom metadata key-value pairs.
	Labels map[string]string
}

// Bundle represents a complete vTPM bundle.
type Bundle struct {
	// ID is the unique identifier for this bundle.
	ID string `json:"id"`

	// Mode indicates whether this is a template or pre-assigned bundle.
	Mode BundleMode `json:"mode"`

	// Manifest contains bundle metadata.
	Manifest *Manifest `json:"manifest"`

	// TPMState contains swtpm state file paths.
	TPMState *TPMState `json:"tpm_state"`

	// OVMFState contains OVMF NVRAM file paths.
	OVMFState *OVMFState `json:"ovmf_state"`

	// SecureBootKeys contains Secure Boot key file paths.
	SecureBootKeys *SecureBootKeyPaths `json:"secure_boot_keys"`

	// CreatedAt is the bundle creation timestamp.
	CreatedAt time.Time `json:"created_at"`

	// ClonedFrom is the template ID if this bundle was cloned.
	ClonedFrom string `json:"cloned_from,omitempty"`
}

// Manifest contains bundle metadata stored in manifest.json.
type Manifest struct {
	// Version is the manifest format version.
	Version string `json:"version"`

	// ID is the bundle identifier.
	ID string `json:"id"`

	// Description is an optional template description.
	Description string `json:"description,omitempty"`

	// Mode is the bundle creation mode.
	Mode BundleMode `json:"mode"`

	// Hostname is the VM hostname (for pre-assigned mode).
	Hostname string `json:"hostname,omitempty"`

	// CreatedAt is the creation timestamp.
	CreatedAt time.Time `json:"created_at"`

	// EKCertificate contains EK certificate metadata.
	EKCertificate *EKCertInfo `json:"ek_certificate,omitempty"`

	// EKAlgorithm is the EK key algorithm.
	EKAlgorithm EKAlgorithm `json:"ek_algorithm"`

	// EKHandle is the TPM NV index for the EK certificate.
	EKHandle uint32 `json:"ek_handle"`

	// SecureBootEnabled indicates if Secure Boot keys are enrolled.
	SecureBootEnabled bool `json:"secure_boot_enabled"`

	// SecureBootKeys contains Secure Boot key information.
	SecureBootKeys *SecureBootKeyInfo `json:"secure_boot_keys,omitempty"`

	// Checksums contains SHA-256 checksums for bundle files.
	Checksums map[string]string `json:"checksums"`

	// Labels contains custom metadata key-value pairs.
	Labels map[string]string `json:"labels,omitempty"`

	// ClonedFrom is the template ID if this was cloned.
	ClonedFrom string `json:"cloned_from,omitempty"`

	// DeviceProfileID is the associated device profile ID (optional).
	DeviceProfileID uint64 `json:"device_profile_id,omitempty"`
}

// ManifestVersion is the current manifest format version.
const ManifestVersion = "1.0"

// EKCertInfo contains EK certificate metadata.
type EKCertInfo struct {
	// Subject is the certificate subject.
	Subject string `json:"subject"`

	// Issuer is the certificate issuer.
	Issuer string `json:"issuer"`

	// SerialNumber is the certificate serial number.
	SerialNumber string `json:"serial_number"`

	// NotBefore is the certificate validity start.
	NotBefore time.Time `json:"not_before"`

	// NotAfter is the certificate validity end.
	NotAfter time.Time `json:"not_after"`

	// Fingerprint is the SHA-256 fingerprint.
	Fingerprint string `json:"fingerprint"`
}

// SecureBootKeyInfo contains Secure Boot key information.
type SecureBootKeyInfo struct {
	// PKFingerprint is the Platform Key SHA-256 fingerprint.
	PKFingerprint string `json:"pk_fingerprint"`

	// KEKFingerprint is the Key Exchange Key SHA-256 fingerprint.
	KEKFingerprint string `json:"kek_fingerprint"`

	// DBFingerprint is the Signature Database key SHA-256 fingerprint.
	DBFingerprint string `json:"db_fingerprint"`

	// OwnerGUID is the UEFI key owner GUID.
	OwnerGUID string `json:"owner_guid"`
}

// SecureBootKeyPaths contains paths to Secure Boot key files.
type SecureBootKeyPaths struct {
	// Dir is the directory containing the keys.
	Dir string `json:"dir"`

	// PKKey is the path to PK.key.
	PKKey string `json:"pk_key"`

	// PKCert is the path to PK.crt.
	PKCert string `json:"pk_crt"`

	// KEKKey is the path to KEK.key.
	KEKKey string `json:"kek_key"`

	// KEKCert is the path to KEK.crt.
	KEKCert string `json:"kek_crt"`

	// DBKey is the path to DB.key.
	DBKey string `json:"db_key"`

	// DBCert is the path to DB.crt.
	DBCert string `json:"db_crt"`
}

// TPMState represents swtpm state files.
type TPMState struct {
	// StateDir is the directory containing TPM state files.
	StateDir string `json:"state_dir"`

	// PermallFile is the path to tpm2-00.permall.
	PermallFile string `json:"permall_file"`

	// VolatileFile is the path to tpm2-00.volatilestate (optional).
	VolatileFile string `json:"volatile_file,omitempty"`
}

// OVMFState represents OVMF NVRAM state.
type OVMFState struct {
	// NVRAMFile is the path to OVMF_VARS.fd.
	NVRAMFile string `json:"nvram_file"`
}

// Template represents a reusable vTPM template (no identity).
type Template struct {
	// ID is the template identifier.
	ID string `json:"id"`

	// Description is an optional description.
	Description string `json:"description,omitempty"`

	// TPMStateDir is the directory containing TPM state.
	TPMStateDir string `json:"tpm_state_dir"`

	// NVRAMPath is the path to OVMF NVRAM.
	NVRAMPath string `json:"nvram_path"`

	// SecureBootKeysDir is the directory containing Secure Boot keys.
	SecureBootKeysDir string `json:"secure_boot_keys_dir"`

	// EKAlgorithm is the EK key algorithm.
	EKAlgorithm EKAlgorithm `json:"ek_algorithm"`

	// SecureBootEnabled indicates if Secure Boot keys are enrolled.
	SecureBootEnabled bool `json:"secure_boot_enabled"`

	// CreatedAt is the template creation timestamp.
	CreatedAt time.Time `json:"created_at"`
}

// CreateBundleOptions configures bundle creation.
type CreateBundleOptions struct {
	// Mode specifies template or pre-assigned mode.
	Mode BundleMode

	// Hostname is required for pre-assigned mode.
	Hostname string

	// EKAlgorithm specifies the EK key algorithm (default: RSA).
	EKAlgorithm EKAlgorithm

	// SecureBootEnabled enables Secure Boot key generation and enrollment.
	SecureBootEnabled bool

	// Labels contains custom metadata.
	Labels map[string]string

	// TemplateID specifies a template to clone from (optional).
	TemplateID string

	// DeviceProfileID is the associated device profile ID (optional).
	DeviceProfileID uint64
}

// CreateTemplateOptions configures template creation.
type CreateTemplateOptions struct {
	// ID is the template identifier.
	ID string

	// Description is an optional description.
	Description string

	// EKAlgorithm specifies the EK key algorithm (default: RSA).
	EKAlgorithm EKAlgorithm

	// SecureBootEnabled enables Secure Boot key generation and enrollment.
	SecureBootEnabled bool
}

// CloneOptions configures template cloning.
type CloneOptions struct {
	// TemplateID is the template to clone.
	TemplateID string

	// Hostname is the hostname for the new bundle.
	Hostname string

	// Labels contains custom metadata.
	Labels map[string]string
}

// ListOptions for filtering bundle lists.
type ListOptions struct {
	// Mode filters by bundle mode.
	Mode BundleMode

	// Labels filters by label key-value pairs.
	Labels map[string]string

	// Limit limits the number of results.
	Limit int

	// Offset skips the first N results.
	Offset int

	// DeviceProfileID filters bundles bound to the given device profile.
	// A zero value disables the filter.
	DeviceProfileID uint64
}

// QuoteResult represents the result of a TPM quote operation.
type QuoteResult struct {
	// Quote is the TPM2B_ATTEST structure containing the quote.
	Quote []byte `json:"quote"`

	// Signature is the signature over the quote.
	Signature []byte `json:"signature"`

	// PCRValues contains the PCR values that were quoted.
	PCRValues map[int][]byte `json:"pcr_values"`

	// HashAlgorithm is the hash algorithm used for the quote.
	HashAlgorithm string `json:"hash_algorithm"`
}

// SealOptions configures the seal operation.
type SealOptions struct {
	// PCRs specifies which PCR values to bind the sealed data to.
	// If empty, data is sealed without PCR binding.
	PCRs []int

	// AuthValue is an optional password/auth value for the sealed data.
	AuthValue string
}

// VTPMService provides vTPM bundle management operations.
type VTPMService interface {
	// CreateBundle creates a new vTPM bundle.
	CreateBundle(ctx context.Context, opts *CreateBundleOptions) (*Bundle, error)

	// GetBundle retrieves a bundle by ID.
	GetBundle(ctx context.Context, id string) (*Bundle, error)

	// DeleteBundle deletes a bundle.
	DeleteBundle(ctx context.Context, id string) error

	// ListBundles lists bundles matching the filter options.
	ListBundles(ctx context.Context, opts *ListOptions) ([]*Bundle, error)

	// CreateTemplate creates a new vTPM template.
	CreateTemplate(ctx context.Context, opts *CreateTemplateOptions) (*Template, error)

	// CloneTemplate clones a template to create a new bundle with identity.
	CloneTemplate(ctx context.Context, opts *CloneOptions) (*Bundle, error)

	// GetTemplate retrieves a template by ID.
	GetTemplate(ctx context.Context, id string) (*Template, error)

	// DeleteTemplate deletes a template.
	DeleteTemplate(ctx context.Context, id string) error

	// ListTemplates lists all templates.
	ListTemplates(ctx context.Context) ([]*Template, error)

	// ExportBundle exports a bundle to a tar.gz archive.
	ExportBundle(ctx context.Context, id string, w io.Writer) error

	// ImportBundle imports a bundle from a tar.gz archive.
	ImportBundle(ctx context.Context, r io.Reader) (*Bundle, error)

	// ValidateBundle validates bundle integrity.
	ValidateBundle(ctx context.Context, id string) error

	// GetBundlePath returns the filesystem path to a bundle.
	GetBundlePath(id string) string

	// GetTPMSocketPath returns the TPM socket path for a bundle.
	GetTPMSocketPath(id string) string

	// GetNVRAMPath returns the OVMF NVRAM path for a bundle.
	GetNVRAMPath(id string) string

	// ==========================================================================
	// Runtime TPM Operations
	// ==========================================================================

	// Start starts the swtpm daemon for the specified bundle.
	// The vTPM must be started before any TPM operations can be performed.
	Start(ctx context.Context, bundleID string) error

	// Stop stops the swtpm daemon for the specified bundle.
	// This persists the TPM state and releases resources.
	Stop(ctx context.Context, bundleID string) error

	// IsRunning checks if the vTPM for the specified bundle is running.
	IsRunning(bundleID string) bool

	// Quote generates a TPM quote over the specified PCRs.
	// The nonce provides freshness and prevents replay attacks.
	// The vTPM must be running before calling this method.
	Quote(ctx context.Context, bundleID string, nonce []byte, pcrs []int) (*QuoteResult, error)

	// Seal encrypts data to the TPM, optionally binding to PCR values.
	// The sealed data can only be unsealed when PCR values match.
	// The vTPM must be running before calling this method.
	Seal(ctx context.Context, bundleID string, data []byte, opts *SealOptions) ([]byte, error)

	// Unseal decrypts data that was previously sealed to the TPM.
	// This will fail if PCR values have changed since sealing.
	// The vTPM must be running before calling this method.
	Unseal(ctx context.Context, bundleID string, sealedData []byte, authValue string) ([]byte, error)

	// ExtendPCR extends a PCR with the provided data.
	// PCR extension is a one-way operation: PCR = Hash(PCR || data).
	// The vTPM must be running before calling this method.
	ExtendPCR(ctx context.Context, bundleID string, pcrIndex int, data []byte) error

	// ReadPCR reads the current value of a PCR.
	// The vTPM must be running before calling this method.
	ReadPCR(ctx context.Context, bundleID string, pcrIndex int) ([]byte, error)

	// Close releases resources.
	Close() error
}
