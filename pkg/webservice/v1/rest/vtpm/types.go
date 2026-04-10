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
	"time"
)

// CreateBundleRequest is the request body for creating a bundle.
type CreateBundleRequest struct {
	Mode              string            `json:"mode"`
	Hostname          string            `json:"hostname,omitempty"`
	EKAlgorithm       string            `json:"ek_algorithm,omitempty"`
	SecureBootEnabled bool              `json:"secure_boot_enabled"`
	Labels            map[string]string `json:"labels,omitempty"`
	TemplateID        string            `json:"template_id,omitempty"`
}

// CreateTemplateRequest is the request body for creating a template.
type CreateTemplateRequest struct {
	ID                string `json:"id"`
	Description       string `json:"description,omitempty"`
	EKAlgorithm       string `json:"ek_algorithm,omitempty"`
	SecureBootEnabled bool   `json:"secure_boot_enabled"`
}

// CloneTemplateRequest is the request body for cloning a template.
type CloneTemplateRequest struct {
	TemplateID string            `json:"template_id"`
	Hostname   string            `json:"hostname"`
	Labels     map[string]string `json:"labels,omitempty"`
}

// ListBundlesRequest contains query parameters for listing bundles.
type ListBundlesRequest struct {
	Mode   string `json:"mode,omitempty"`
	Limit  int    `json:"limit,omitempty"`
	Offset int    `json:"offset,omitempty"`
}

// EKCertInfoResponse contains EK certificate metadata.
type EKCertInfoResponse struct {
	Subject      string     `json:"subject"`
	Issuer       string     `json:"issuer"`
	SerialNumber string     `json:"serial_number"`
	NotBefore    *time.Time `json:"not_before,omitempty"`
	NotAfter     *time.Time `json:"not_after,omitempty"`
	Fingerprint  string     `json:"fingerprint"`
}

// SecureBootKeyInfoResponse contains Secure Boot key information.
type SecureBootKeyInfoResponse struct {
	PKFingerprint  string `json:"pk_fingerprint"`
	KEKFingerprint string `json:"kek_fingerprint"`
	DBFingerprint  string `json:"db_fingerprint"`
	OwnerGUID      string `json:"owner_guid"`
}

// SecureBootKeyPathsResponse contains paths to Secure Boot key files.
type SecureBootKeyPathsResponse struct {
	Dir     string `json:"dir"`
	PKKey   string `json:"pk_key"`
	PKCert  string `json:"pk_crt"`
	KEKKey  string `json:"kek_key"`
	KEKCert string `json:"kek_crt"`
	DBKey   string `json:"db_key"`
	DBCert  string `json:"db_crt"`
}

// TPMStateResponse represents swtpm state files.
type TPMStateResponse struct {
	StateDir     string `json:"state_dir"`
	PermallFile  string `json:"permall_file"`
	VolatileFile string `json:"volatile_file,omitempty"`
}

// OVMFStateResponse represents OVMF NVRAM state.
type OVMFStateResponse struct {
	NVRAMFile string `json:"nvram_file"`
}

// ManifestResponse contains bundle metadata.
type ManifestResponse struct {
	Version           string                     `json:"version"`
	ID                string                     `json:"id"`
	Mode              string                     `json:"mode"`
	Hostname          string                     `json:"hostname,omitempty"`
	CreatedAt         *time.Time                 `json:"created_at,omitempty"`
	EKCertificate     *EKCertInfoResponse        `json:"ek_certificate,omitempty"`
	EKAlgorithm       string                     `json:"ek_algorithm"`
	EKHandle          uint32                     `json:"ek_handle"`
	SecureBootEnabled bool                       `json:"secure_boot_enabled"`
	SecureBootKeys    *SecureBootKeyInfoResponse `json:"secure_boot_keys,omitempty"`
	Checksums         map[string]string          `json:"checksums,omitempty"`
	Labels            map[string]string          `json:"labels,omitempty"`
	ClonedFrom        string                     `json:"cloned_from,omitempty"`
}

// BundleResponse is the response for bundle operations.
type BundleResponse struct {
	ID             string                      `json:"id"`
	Mode           string                      `json:"mode"`
	Manifest       *ManifestResponse           `json:"manifest,omitempty"`
	TPMState       *TPMStateResponse           `json:"tpm_state,omitempty"`
	OVMFState      *OVMFStateResponse          `json:"ovmf_state,omitempty"`
	SecureBootKeys *SecureBootKeyPathsResponse `json:"secure_boot_keys,omitempty"`
	CreatedAt      *time.Time                  `json:"created_at,omitempty"`
	ClonedFrom     string                      `json:"cloned_from,omitempty"`
}

// ListBundlesResponse is the response for listing bundles.
type ListBundlesResponse struct {
	Bundles []BundleResponse `json:"bundles"`
	Total   int              `json:"total"`
}

// TemplateResponse is the response for template operations.
type TemplateResponse struct {
	ID                string     `json:"id"`
	Description       string     `json:"description,omitempty"`
	TPMStateDir       string     `json:"tpm_state_dir"`
	NVRAMPath         string     `json:"nvram_path"`
	SecureBootKeysDir string     `json:"secure_boot_keys_dir,omitempty"`
	EKAlgorithm       string     `json:"ek_algorithm"`
	SecureBootEnabled bool       `json:"secure_boot_enabled"`
	CreatedAt         *time.Time `json:"created_at,omitempty"`
}

// ListTemplatesResponse is the response for listing templates.
type ListTemplatesResponse struct {
	Templates []TemplateResponse `json:"templates"`
}

// ValidateBundleResponse is the response for bundle validation.
type ValidateBundleResponse struct {
	Valid  bool     `json:"valid"`
	Errors []string `json:"errors,omitempty"`
}

// PathResponse is the response for path getter operations.
type PathResponse struct {
	Path string `json:"path"`
}

// SuccessResponse is a generic success response.
type SuccessResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}
