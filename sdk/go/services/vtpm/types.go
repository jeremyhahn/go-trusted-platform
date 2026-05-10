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

import "time"

// BundleMode represents the mode of a vTPM bundle.
type BundleMode string

const (
	// BundleModeUnspecified indicates no mode is set.
	BundleModeUnspecified BundleMode = "UNSPECIFIED"
	// BundleModeTemplate indicates a template bundle.
	BundleModeTemplate BundleMode = "BUNDLE_MODE_TEMPLATE"
	// BundleModePreAssigned indicates a pre-assigned bundle.
	BundleModePreAssigned BundleMode = "BUNDLE_MODE_PRE_ASSIGNED"
)

// EKAlgorithm represents an EK algorithm for vTPM bundles.
type EKAlgorithm string

const (
	// EKAlgorithmUnspecified indicates no algorithm is set.
	EKAlgorithmUnspecified EKAlgorithm = "UNSPECIFIED"
	// EKAlgorithmRSA indicates RSA EK algorithm.
	EKAlgorithmRSA EKAlgorithm = "RSA"
	// EKAlgorithmECC indicates ECC EK algorithm.
	EKAlgorithmECC EKAlgorithm = "ECC"
)

// Status holds the result of a vTPM operation.
type Status struct {
	// Success indicates whether the operation succeeded.
	Success bool `json:"success"`
	// Message provides additional status details.
	Message string `json:"message,omitempty"`
}

// EKCertificateInfo holds EK certificate information.
type EKCertificateInfo struct {
	// Fingerprint is the certificate fingerprint.
	Fingerprint string `json:"fingerprint,omitempty"`
}

// BundleManifest holds manifest information for a bundle.
type BundleManifest struct {
	// Hostname is the VM hostname.
	Hostname string `json:"hostname,omitempty"`
	// EKAlgorithm is the EK algorithm.
	EKAlgorithm EKAlgorithm `json:"ek_algorithm"`
	// SecureBootEnabled indicates if Secure Boot is enabled.
	SecureBootEnabled bool `json:"secure_boot_enabled"`
	// ClonedFrom is the source template ID.
	ClonedFrom string `json:"cloned_from,omitempty"`
	// CreatedAt is the manifest creation time.
	CreatedAt *time.Time `json:"created_at,omitempty"`
	// Labels are key-value metadata.
	Labels map[string]string `json:"labels,omitempty"`
	// Checksums maps filenames to checksums.
	Checksums map[string]string `json:"checksums,omitempty"`
	// EKCertificate holds EK certificate info.
	EKCertificate *EKCertificateInfo `json:"ek_certificate,omitempty"`
}

// TPMState holds TPM state paths.
type TPMState struct {
	// StateDir is the state directory.
	StateDir string `json:"state_dir,omitempty"`
	// PermallFile is the permanent state file.
	PermallFile string `json:"permall_file,omitempty"`
	// VolatileFile is the volatile state file.
	VolatileFile string `json:"volatile_file,omitempty"`
}

// OVMFState holds OVMF state paths.
type OVMFState struct {
	// NVRAMFile is the NVRAM file path.
	NVRAMFile string `json:"nvram_file,omitempty"`
}

// SecureBootKeys holds Secure Boot key paths.
type SecureBootKeys struct {
	// Dir is the keys directory.
	Dir string `json:"dir,omitempty"`
	// PKKey is the PK key path.
	PKKey string `json:"pk_key,omitempty"`
	// PKCert is the PK certificate path.
	PKCert string `json:"pk_crt,omitempty"`
	// KEKKey is the KEK key path.
	KEKKey string `json:"kek_key,omitempty"`
	// KEKCert is the KEK certificate path.
	KEKCert string `json:"kek_crt,omitempty"`
	// DBKey is the DB key path.
	DBKey string `json:"db_key,omitempty"`
	// DBCert is the DB certificate path.
	DBCert string `json:"db_crt,omitempty"`
}

// Bundle holds complete vTPM bundle information.
type Bundle struct {
	// ID is the bundle identifier.
	ID string `json:"id"`
	// Mode is the bundle mode.
	Mode BundleMode `json:"mode"`
	// CreatedAt is the creation time.
	CreatedAt *time.Time `json:"created_at,omitempty"`
	// ClonedFrom is the source template ID.
	ClonedFrom string `json:"cloned_from,omitempty"`
	// Manifest holds manifest details.
	Manifest *BundleManifest `json:"manifest,omitempty"`
	// TPMState holds TPM state paths.
	TPMState *TPMState `json:"tpm_state,omitempty"`
	// OVMFState holds OVMF state paths.
	OVMFState *OVMFState `json:"ovmf_state,omitempty"`
	// SecureBootKeys holds Secure Boot key paths.
	SecureBootKeys *SecureBootKeys `json:"secure_boot_keys,omitempty"`
}

// Template holds vTPM template information.
type Template struct {
	// ID is the template identifier.
	ID string `json:"id"`
	// Description is the template description.
	Description string `json:"description,omitempty"`
	// EKAlgorithm is the EK algorithm.
	EKAlgorithm EKAlgorithm `json:"ek_algorithm"`
	// SecureBootEnabled indicates if Secure Boot is enabled.
	SecureBootEnabled bool `json:"secure_boot_enabled"`
	// TPMStateDir is the TPM state directory.
	TPMStateDir string `json:"tpm_state_dir,omitempty"`
	// NVRAMPath is the NVRAM file path.
	NVRAMPath string `json:"nvram_path,omitempty"`
	// SecureBootKeysDir is the Secure Boot keys directory.
	SecureBootKeysDir string `json:"secure_boot_keys_dir,omitempty"`
	// CreatedAt is the creation time.
	CreatedAt *time.Time `json:"created_at,omitempty"`
}

// CreateBundleOptions holds options for creating a bundle.
type CreateBundleOptions struct {
	// Mode is the bundle mode.
	Mode BundleMode `json:"mode"`
	// Hostname is the VM hostname.
	Hostname string `json:"hostname"`
	// EKAlgorithm is the EK algorithm.
	EKAlgorithm EKAlgorithm `json:"ek_algorithm"`
	// SecureBootEnabled indicates if Secure Boot is enabled.
	SecureBootEnabled bool `json:"secure_boot_enabled"`
	// TemplateID is the source template ID.
	TemplateID string `json:"template_id,omitempty"`
	// Labels are key-value metadata.
	Labels map[string]string `json:"labels,omitempty"`
}

// CreateBundleResponse holds the result of creating a bundle.
type CreateBundleResponse struct {
	// Status is the operation status.
	Status *Status `json:"status,omitempty"`
	// Bundle is the created bundle.
	Bundle *Bundle `json:"bundle,omitempty"`
}

// CloneOptions holds options for cloning a template.
type CloneOptions struct {
	// TemplateID is the source template ID.
	TemplateID string `json:"template_id"`
	// Hostname is the VM hostname.
	Hostname string `json:"hostname"`
	// Labels are key-value metadata.
	Labels map[string]string `json:"labels,omitempty"`
}

// CloneResponse holds the result of cloning a template.
type CloneResponse struct {
	// Status is the operation status.
	Status *Status `json:"status,omitempty"`
	// Bundle is the cloned bundle.
	Bundle *Bundle `json:"bundle,omitempty"`
}

// DeleteResponse holds the result of deleting a bundle or template.
type DeleteResponse struct {
	// Status is the operation status.
	Status *Status `json:"status"`
}

// GetBundleResponse holds the result of getting a bundle.
type GetBundleResponse struct {
	// Bundle is the requested bundle.
	Bundle *Bundle `json:"bundle,omitempty"`
}

// ListBundleOptions holds options for listing bundles.
type ListBundleOptions struct {
	// Mode filters by bundle mode.
	Mode BundleMode `json:"mode,omitempty"`
	// Limit is the maximum number of bundles to return.
	Limit int32 `json:"limit,omitempty"`
	// Offset is the number of bundles to skip.
	Offset int32 `json:"offset,omitempty"`
}

// ListBundlesResponse holds the result of listing bundles.
type ListBundlesResponse struct {
	// Bundles is the list of bundles.
	Bundles []*Bundle `json:"bundles"`
	// Total is the total number of bundles.
	Total int32 `json:"total"`
}

// ImportBundleResponse holds the result of importing a bundle.
type ImportBundleResponse struct {
	// Status is the operation status.
	Status *Status `json:"status,omitempty"`
	// Bundle is the imported bundle.
	Bundle *Bundle `json:"bundle,omitempty"`
}

// CreateTemplateOptions holds options for creating a template.
type CreateTemplateOptions struct {
	// ID is the template identifier.
	ID string `json:"id"`
	// Description is the template description.
	Description string `json:"description,omitempty"`
	// EKAlgorithm is the EK algorithm.
	EKAlgorithm EKAlgorithm `json:"ek_algorithm"`
	// SecureBootEnabled indicates if Secure Boot is enabled.
	SecureBootEnabled bool `json:"secure_boot_enabled"`
}

// CreateTemplateResponse holds the result of creating a template.
type CreateTemplateResponse struct {
	// Status is the operation status.
	Status *Status `json:"status,omitempty"`
	// Template is the created template.
	Template *Template `json:"template,omitempty"`
}

// ListTemplatesResponse holds the result of listing templates.
type ListTemplatesResponse struct {
	// Templates is the list of templates.
	Templates []*Template `json:"templates"`
}

// StartResponse holds the result of starting a vTPM.
type StartResponse struct {
	// BundleID is the bundle identifier.
	BundleID string `json:"bundle_id"`
	// Running indicates if the vTPM is running.
	Running bool `json:"running"`
	// SocketPath is the TPM socket path.
	SocketPath string `json:"socket_path,omitempty"`
}

// StopResponse holds the result of stopping a vTPM.
type StopResponse struct {
	// BundleID is the bundle identifier.
	BundleID string `json:"bundle_id"`
	// Stopped indicates if the vTPM was stopped.
	Stopped bool `json:"stopped"`
}

// IsRunningResponse holds the running status of a vTPM.
type IsRunningResponse struct {
	// BundleID is the bundle identifier.
	BundleID string `json:"bundle_id"`
	// Running indicates if the vTPM is running.
	Running bool `json:"running"`
}

// QuoteResponse holds a vTPM quote result.
type QuoteResponse struct {
	// BundleID is the bundle identifier.
	BundleID string `json:"bundle_id"`
	// HashAlgorithm is the hash algorithm used.
	HashAlgorithm string `json:"hash_algorithm"`
	// Quote is the quote data.
	Quote []byte `json:"quote"`
	// Signature is the quote signature.
	Signature []byte `json:"signature"`
	// PCRValues maps PCR indices to their values.
	PCRValues map[int32][]byte `json:"pcr_values,omitempty"`
}

// SealResponse holds the result of sealing data.
type SealResponse struct {
	// BundleID is the bundle identifier.
	BundleID string `json:"bundle_id"`
	// SealedData is the sealed data.
	SealedData []byte `json:"sealed_data"`
}

// UnsealResponse holds the result of unsealing data.
type UnsealResponse struct {
	// BundleID is the bundle identifier.
	BundleID string `json:"bundle_id"`
	// Data is the unsealed data.
	Data []byte `json:"data"`
}

// ExtendPCRResponse holds the result of extending a PCR.
type ExtendPCRResponse struct {
	// BundleID is the bundle identifier.
	BundleID string `json:"bundle_id"`
	// PCRIndex is the PCR index.
	PCRIndex int32 `json:"pcr_index"`
	// Extended indicates if the PCR was extended.
	Extended bool `json:"extended"`
}

// ReadPCRResponse holds the result of reading a PCR.
type ReadPCRResponse struct {
	// BundleID is the bundle identifier.
	BundleID string `json:"bundle_id"`
	// PCRIndex is the PCR index.
	PCRIndex int32 `json:"pcr_index"`
	// Value is the PCR value.
	Value []byte `json:"value"`
}
