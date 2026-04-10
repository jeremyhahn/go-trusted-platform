//go:build integration

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

	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
)

// VTPMCommands defines the interface for vTPM operations across all protocols
type VTPMCommands interface {
	// Setup prepares the adapter for testing
	Setup(ctx context.Context) error

	// Teardown cleans up after testing
	Teardown(ctx context.Context) error

	// Name returns the adapter name
	Name() string

	// Bundle CRUD Operations

	// CreateBundle creates a new vTPM bundle
	CreateBundle(ctx context.Context, opts CreateBundleOptions) (*CreateBundleResult, error)

	// GetBundle retrieves a bundle by its ID
	GetBundle(ctx context.Context, opts GetBundleOptions) (*GetBundleResult, error)

	// DeleteBundle removes a bundle
	DeleteBundle(ctx context.Context, opts DeleteBundleOptions) (*DeleteBundleResult, error)

	// ListBundles lists bundles with optional filtering
	ListBundles(ctx context.Context, opts ListBundlesOptions) (*ListBundlesResult, error)

	// Template CRUD Operations

	// CreateTemplate creates a new vTPM template
	CreateTemplate(ctx context.Context, opts CreateTemplateOptions) (*CreateTemplateResult, error)

	// GetTemplate retrieves a template by its ID
	GetTemplate(ctx context.Context, opts GetTemplateOptions) (*GetTemplateResult, error)

	// DeleteTemplate removes a template
	DeleteTemplate(ctx context.Context, opts DeleteTemplateOptions) (*DeleteTemplateResult, error)

	// ListTemplates lists all templates
	ListTemplates(ctx context.Context, opts ListTemplatesOptions) (*ListTemplatesResult, error)

	// CloneTemplate clones a template to create a new bundle with identity
	CloneTemplate(ctx context.Context, opts CloneTemplateOptions) (*CloneTemplateResult, error)

	// Export/Import Operations

	// ExportBundle exports a bundle to a tar.gz archive
	ExportBundle(ctx context.Context, opts ExportBundleOptions) (*ExportBundleResult, error)

	// ImportBundle imports a bundle from a tar.gz archive
	ImportBundle(ctx context.Context, opts ImportBundleOptions) (*ImportBundleResult, error)

	// Validation Operations

	// ValidateBundle validates bundle integrity
	ValidateBundle(ctx context.Context, opts ValidateBundleOptions) (*ValidateBundleResult, error)

	// Path Helper Operations

	// GetBundlePath returns the filesystem path to a bundle
	GetBundlePath(ctx context.Context, opts GetBundlePathOptions) (*GetBundlePathResult, error)

	// GetTPMSocketPath returns the TPM socket path for a bundle
	GetTPMSocketPath(ctx context.Context, opts GetTPMSocketPathOptions) (*GetTPMSocketPathResult, error)

	// GetNVRAMPath returns the OVMF NVRAM path for a bundle
	GetNVRAMPath(ctx context.Context, opts GetNVRAMPathOptions) (*GetNVRAMPathResult, error)

	// Runtime TPM Operations

	// Start starts the swtpm daemon for a bundle
	Start(ctx context.Context, opts StartOptions) (*StartResult, error)

	// Stop stops the swtpm daemon for a bundle
	Stop(ctx context.Context, opts StopOptions) (*StopResult, error)

	// IsRunning checks if the vTPM for a bundle is running
	IsRunning(ctx context.Context, opts IsRunningOptions) (*IsRunningResult, error)

	// Quote generates a TPM quote over specified PCRs
	Quote(ctx context.Context, opts QuoteOptions) (*QuoteResult, error)

	// Seal encrypts data to the TPM, optionally binding to PCR values
	Seal(ctx context.Context, opts SealOptions) (*SealResult, error)

	// Unseal decrypts data that was previously sealed to the TPM
	Unseal(ctx context.Context, opts UnsealOptions) (*UnsealResult, error)

	// ExtendPCR extends a PCR with the provided data
	ExtendPCR(ctx context.Context, opts ExtendPCROptions) (*ExtendPCRResult, error)

	// ReadPCR reads the current value of a PCR
	ReadPCR(ctx context.Context, opts ReadPCROptions) (*ReadPCRResult, error)
}

// ============================================================================
// Bundle CRUD Options and Results
// ============================================================================

// CreateBundleOptions contains options for creating a bundle
type CreateBundleOptions struct {
	Mode              vtpm.BundleMode   `json:"mode"`
	Hostname          string            `json:"hostname,omitempty"`
	EKAlgorithm       vtpm.EKAlgorithm  `json:"ek_algorithm,omitempty"`
	SecureBootEnabled bool              `json:"secure_boot_enabled,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
	TemplateID        string            `json:"template_id,omitempty"`
}

// CreateBundleResult contains the result of bundle creation
type CreateBundleResult struct {
	Bundle *vtpm.Bundle `json:"bundle"`
}

// GetBundleOptions contains options for getting a bundle
type GetBundleOptions struct {
	ID string `json:"id"`
}

// GetBundleResult contains the result of getting a bundle
type GetBundleResult struct {
	Bundle *vtpm.Bundle `json:"bundle"`
}

// DeleteBundleOptions contains options for deleting a bundle
type DeleteBundleOptions struct {
	ID string `json:"id"`
}

// DeleteBundleResult contains the result of deleting a bundle
type DeleteBundleResult struct {
	Success bool `json:"success"`
}

// ListBundlesOptions contains options for listing bundles
type ListBundlesOptions struct {
	Mode   vtpm.BundleMode   `json:"mode,omitempty"`
	Labels map[string]string `json:"labels,omitempty"`
	Limit  int               `json:"limit,omitempty"`
	Offset int               `json:"offset,omitempty"`
}

// ListBundlesResult contains the result of listing bundles
type ListBundlesResult struct {
	Bundles []*vtpm.Bundle `json:"bundles"`
	Total   int            `json:"total"`
}

// ============================================================================
// Template CRUD Options and Results
// ============================================================================

// CreateTemplateOptions contains options for creating a template
type CreateTemplateOptions struct {
	ID                string           `json:"id"`
	Description       string           `json:"description,omitempty"`
	EKAlgorithm       vtpm.EKAlgorithm `json:"ek_algorithm,omitempty"`
	SecureBootEnabled bool             `json:"secure_boot_enabled,omitempty"`
}

// CreateTemplateResult contains the result of template creation
type CreateTemplateResult struct {
	Template *vtpm.Template `json:"template"`
}

// GetTemplateOptions contains options for getting a template
type GetTemplateOptions struct {
	ID string `json:"id"`
}

// GetTemplateResult contains the result of getting a template
type GetTemplateResult struct {
	Template *vtpm.Template `json:"template"`
}

// DeleteTemplateOptions contains options for deleting a template
type DeleteTemplateOptions struct {
	ID string `json:"id"`
}

// DeleteTemplateResult contains the result of deleting a template
type DeleteTemplateResult struct {
	Success bool `json:"success"`
}

// ListTemplatesOptions contains options for listing templates
type ListTemplatesOptions struct {
	Limit  int `json:"limit,omitempty"`
	Offset int `json:"offset,omitempty"`
}

// ListTemplatesResult contains the result of listing templates
type ListTemplatesResult struct {
	Templates []*vtpm.Template `json:"templates"`
	Total     int              `json:"total"`
}

// CloneTemplateOptions contains options for cloning a template
type CloneTemplateOptions struct {
	TemplateID string            `json:"template_id"`
	Hostname   string            `json:"hostname"`
	Labels     map[string]string `json:"labels,omitempty"`
}

// CloneTemplateResult contains the result of cloning a template
type CloneTemplateResult struct {
	Bundle *vtpm.Bundle `json:"bundle"`
}

// ============================================================================
// Export/Import Options and Results
// ============================================================================

// ExportBundleOptions contains options for exporting a bundle
type ExportBundleOptions struct {
	ID         string `json:"id"`
	OutputPath string `json:"output_path,omitempty"`
}

// ExportBundleResult contains the result of exporting a bundle
type ExportBundleResult struct {
	ArchivePath string `json:"archive_path"`
	Size        int64  `json:"size"`
	Checksum    string `json:"checksum"`
}

// ImportBundleOptions contains options for importing a bundle
type ImportBundleOptions struct {
	ArchivePath string `json:"archive_path,omitempty"`
	ArchiveData []byte `json:"archive_data,omitempty"`
}

// ImportBundleResult contains the result of importing a bundle
type ImportBundleResult struct {
	Bundle *vtpm.Bundle `json:"bundle"`
}

// ============================================================================
// Validation Options and Results
// ============================================================================

// ValidateBundleOptions contains options for validating a bundle
type ValidateBundleOptions struct {
	ID string `json:"id"`
}

// ValidateBundleResult contains the result of validating a bundle
type ValidateBundleResult struct {
	Valid            bool              `json:"valid"`
	Errors           []string          `json:"errors,omitempty"`
	Warnings         []string          `json:"warnings,omitempty"`
	ChecksumVerified bool              `json:"checksum_verified"`
	FilesChecked     map[string]string `json:"files_checked,omitempty"`
}

// ============================================================================
// Path Helper Options and Results
// ============================================================================

// GetBundlePathOptions contains options for getting a bundle path
type GetBundlePathOptions struct {
	ID string `json:"id"`
}

// GetBundlePathResult contains the result of getting a bundle path
type GetBundlePathResult struct {
	Path string `json:"path"`
}

// GetTPMSocketPathOptions contains options for getting a TPM socket path
type GetTPMSocketPathOptions struct {
	ID string `json:"id"`
}

// GetTPMSocketPathResult contains the result of getting a TPM socket path
type GetTPMSocketPathResult struct {
	Path string `json:"path"`
}

// GetNVRAMPathOptions contains options for getting an NVRAM path
type GetNVRAMPathOptions struct {
	ID string `json:"id"`
}

// GetNVRAMPathResult contains the result of getting an NVRAM path
type GetNVRAMPathResult struct {
	Path string `json:"path"`
}

// ============================================================================
// Runtime TPM Options and Results
// ============================================================================

// StartOptions contains options for starting a vTPM
type StartOptions struct {
	BundleID string `json:"bundle_id"`
}

// StartResult contains the result of starting a vTPM
type StartResult struct {
	BundleID   string `json:"bundle_id"`
	Running    bool   `json:"running"`
	SocketPath string `json:"socket_path"`
}

// StopOptions contains options for stopping a vTPM
type StopOptions struct {
	BundleID string `json:"bundle_id"`
}

// StopResult contains the result of stopping a vTPM
type StopResult struct {
	BundleID string `json:"bundle_id"`
	Stopped  bool   `json:"stopped"`
}

// IsRunningOptions contains options for checking if a vTPM is running
type IsRunningOptions struct {
	BundleID string `json:"bundle_id"`
}

// IsRunningResult contains the result of checking if a vTPM is running
type IsRunningResult struct {
	BundleID string `json:"bundle_id"`
	Running  bool   `json:"running"`
}

// QuoteOptions contains options for generating a TPM quote
type QuoteOptions struct {
	BundleID string `json:"bundle_id"`
	Nonce    []byte `json:"nonce"`
	PCRs     []int  `json:"pcrs"`
}

// QuoteResult contains the result of generating a TPM quote
type QuoteResult struct {
	BundleID      string         `json:"bundle_id"`
	Quote         []byte         `json:"quote"`
	Signature     []byte         `json:"signature"`
	PCRValues     map[int][]byte `json:"pcr_values"`
	HashAlgorithm string         `json:"hash_algorithm"`
}

// SealOptions contains options for sealing data to the TPM
type SealOptions struct {
	BundleID  string `json:"bundle_id"`
	Data      []byte `json:"data"`
	PCRs      []int  `json:"pcrs,omitempty"`
	AuthValue string `json:"auth_value,omitempty"`
}

// SealResult contains the result of sealing data
type SealResult struct {
	BundleID   string `json:"bundle_id"`
	SealedData []byte `json:"sealed_data"`
}

// UnsealOptions contains options for unsealing data from the TPM
type UnsealOptions struct {
	BundleID   string `json:"bundle_id"`
	SealedData []byte `json:"sealed_data"`
	AuthValue  string `json:"auth_value,omitempty"`
}

// UnsealResult contains the result of unsealing data
type UnsealResult struct {
	BundleID string `json:"bundle_id"`
	Data     []byte `json:"data"`
}

// ExtendPCROptions contains options for extending a PCR
type ExtendPCROptions struct {
	BundleID string `json:"bundle_id"`
	PCRIndex int    `json:"pcr_index"`
	Data     []byte `json:"data"`
}

// ExtendPCRResult contains the result of extending a PCR
type ExtendPCRResult struct {
	BundleID string `json:"bundle_id"`
	PCRIndex int    `json:"pcr_index"`
	Extended bool   `json:"extended"`
}

// ReadPCROptions contains options for reading a PCR
type ReadPCROptions struct {
	BundleID string `json:"bundle_id"`
	PCRIndex int    `json:"pcr_index"`
}

// ReadPCRResult contains the result of reading a PCR
type ReadPCRResult struct {
	BundleID string `json:"bundle_id"`
	PCRIndex int    `json:"pcr_index"`
	Value    []byte `json:"value"`
}
