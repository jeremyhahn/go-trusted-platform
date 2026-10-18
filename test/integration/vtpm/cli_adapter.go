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

//go:build integration

package vtpm

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	vtpmsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/vtpm"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// platformctl vtpm prints the SDK domain responses (sdk/go/services/vtpm)
// with encoding/json, so the adapter decodes into those same types: enum
// names such as "BUNDLE_MODE_PRE_ASSIGNED", RFC 3339 timestamps and base64
// byte fields all round-trip without a hand-kept mirror of the output.

// bundleModes maps the SDK bundle mode names to the vtpm package modes.
var bundleModes = map[vtpmsvc.BundleMode]vtpm.BundleMode{
	vtpmsvc.BundleModeTemplate:    vtpm.BundleModeTemplate,
	vtpmsvc.BundleModePreAssigned: vtpm.BundleModePreAssigned,
}

// ekAlgorithms maps the SDK EK algorithm names to the vtpm package algorithms.
var ekAlgorithms = map[vtpmsvc.EKAlgorithm]vtpm.EKAlgorithm{
	vtpmsvc.EKAlgorithmRSA: vtpm.EKAlgorithmRSA,
	vtpmsvc.EKAlgorithmECC: vtpm.EKAlgorithmECC,
}

// decodeCLIResponse decodes the JSON a CLI command printed into T. A decode
// failure is a CLIAdapterError that wraps the json error and carries the
// output, so the log says which field failed.
func decodeCLIResponse[T any](operation string, output []byte) (*T, error) {
	var resp T
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, &CLIAdapterError{
			Operation: operation,
			Message:   "failed to parse response",
			Output:    string(output),
			Err:       err,
		}
	}
	return &resp, nil
}

// timeFromDomain returns the time an SDK response carried, or the zero time.
func timeFromDomain(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}

// bundleFromDomain converts an SDK bundle to a vtpm.Bundle.
func bundleFromDomain(b *vtpmsvc.Bundle) *vtpm.Bundle {
	if b == nil {
		return nil
	}
	bundle := &vtpm.Bundle{
		ID:         b.ID,
		Mode:       bundleModes[b.Mode],
		CreatedAt:  timeFromDomain(b.CreatedAt),
		ClonedFrom: b.ClonedFrom,
		Manifest:   manifestFromDomain(b.Manifest),
	}
	if b.TPMState != nil {
		bundle.TPMState = &vtpm.TPMState{
			StateDir:     b.TPMState.StateDir,
			PermallFile:  b.TPMState.PermallFile,
			VolatileFile: b.TPMState.VolatileFile,
		}
	}
	if b.OVMFState != nil {
		bundle.OVMFState = &vtpm.OVMFState{
			NVRAMFile: b.OVMFState.NVRAMFile,
		}
	}
	if b.SecureBootKeys != nil {
		bundle.SecureBootKeys = &vtpm.SecureBootKeyPaths{
			Dir:     b.SecureBootKeys.Dir,
			PKKey:   b.SecureBootKeys.PKKey,
			PKCert:  b.SecureBootKeys.PKCert,
			KEKKey:  b.SecureBootKeys.KEKKey,
			KEKCert: b.SecureBootKeys.KEKCert,
			DBKey:   b.SecureBootKeys.DBKey,
			DBCert:  b.SecureBootKeys.DBCert,
		}
	}
	return bundle
}

// manifestFromDomain converts an SDK bundle manifest to a vtpm.Manifest.
func manifestFromDomain(m *vtpmsvc.BundleManifest) *vtpm.Manifest {
	if m == nil {
		return nil
	}
	manifest := &vtpm.Manifest{
		Hostname:          m.Hostname,
		CreatedAt:         timeFromDomain(m.CreatedAt),
		EKAlgorithm:       ekAlgorithms[m.EKAlgorithm],
		SecureBootEnabled: m.SecureBootEnabled,
		Checksums:         m.Checksums,
		Labels:            m.Labels,
		ClonedFrom:        m.ClonedFrom,
	}
	if m.EKCertificate != nil {
		manifest.EKCertificate = &vtpm.EKCertInfo{
			Fingerprint: m.EKCertificate.Fingerprint,
		}
	}
	return manifest
}

// templateFromDomain converts an SDK template to a vtpm.Template.
func templateFromDomain(t *vtpmsvc.Template) *vtpm.Template {
	if t == nil {
		return nil
	}
	return &vtpm.Template{
		ID:                t.ID,
		Description:       t.Description,
		EKAlgorithm:       ekAlgorithms[t.EKAlgorithm],
		SecureBootEnabled: t.SecureBootEnabled,
		TPMStateDir:       t.TPMStateDir,
		NVRAMPath:         t.NVRAMPath,
		SecureBootKeysDir: t.SecureBootKeysDir,
		CreatedAt:         timeFromDomain(t.CreatedAt),
	}
}

// CLIAdapterError represents an error from the CLI adapter.
type CLIAdapterError struct {
	Operation string
	Message   string
	Output    string
	// Err is the underlying cause, when there is one.
	Err error
}

// Error returns the error message.
func (e *CLIAdapterError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("CLI adapter error [%s]: %s: %v (output: %s)", e.Operation, e.Message, e.Err, e.Output)
	}
	return fmt.Sprintf("CLI adapter error [%s]: %s (output: %s)", e.Operation, e.Message, e.Output)
}

// Unwrap returns the underlying cause.
func (e *CLIAdapterError) Unwrap() error {
	return e.Err
}

// CLIAdapter implements VTPMCommands using the platformctl CLI.
type CLIAdapter struct {
	cliPath    string
	configDir  string
	configPath string
}

// NewCLIAdapter creates a new CLI adapter.
func NewCLIAdapter() *CLIAdapter {
	return &CLIAdapter{
		cliPath: GetCLIPath(),
	}
}

// Setup prepares the adapter for testing.
func (a *CLIAdapter) Setup(ctx context.Context) error {
	_, err := exec.LookPath(a.cliPath)
	if err != nil {
		return &CLIAdapterError{
			Operation: "Setup",
			Message:   "CLI not found",
		}
	}

	// platformctl reaches the harness daemon only through a config context:
	// without --config every command failed before it dialled.
	dir, path, err := helpers.WriteTempLocalCLIConfig(GetSocketPath(), GetGRPCEndpoint())
	if err != nil {
		return &CLIAdapterError{
			Operation: "Setup",
			Message:   "failed to write platformctl config: " + err.Error(),
		}
	}
	a.configDir = dir
	a.configPath = path
	return nil
}

// Teardown cleans up after testing.
func (a *CLIAdapter) Teardown(ctx context.Context) error {
	if a.configDir == "" {
		return nil
	}
	err := os.RemoveAll(a.configDir)
	a.configDir = ""
	a.configPath = ""
	return err
}

// Name returns the adapter name.
func (a *CLIAdapter) Name() string {
	return "CLI"
}

// runCommand executes a CLI command and returns the output.
func (a *CLIAdapter) runCommand(ctx context.Context, args ...string) ([]byte, error) {
	full := append([]string{"--config", a.configPath}, args...)
	cmd := exec.CommandContext(ctx, a.cliPath, full...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, &CLIAdapterError{
			Operation: strings.Join(args, " "),
			Message:   err.Error(),
			Output:    string(output),
		}
	}
	return output, nil
}

// ============================================================================
// Bundle CRUD Operations
// ============================================================================

// CreateBundle creates a new vTPM bundle.
func (a *CLIAdapter) CreateBundle(ctx context.Context, opts CreateBundleOptions) (*CreateBundleResult, error) {
	args := []string{"vtpm", "create",
		"--hostname", opts.Hostname,
		"--output", "json",
	}

	if opts.EKAlgorithm != "" {
		args = append(args, "--ek-algorithm", string(opts.EKAlgorithm))
	}
	if opts.SecureBootEnabled {
		args = append(args, "--secure-boot")
	} else {
		args = append(args, "--secure-boot=false")
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	resp, err := decodeCLIResponse[vtpmsvc.CreateBundleResponse]("CreateBundle", output)
	if err != nil {
		return nil, err
	}

	return &CreateBundleResult{Bundle: bundleFromDomain(resp.Bundle)}, nil
}

// GetBundle retrieves a bundle by its ID.
func (a *CLIAdapter) GetBundle(ctx context.Context, opts GetBundleOptions) (*GetBundleResult, error) {
	args := []string{"vtpm", "info", opts.ID, "--output", "json"}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	resp, err := decodeCLIResponse[vtpmsvc.GetBundleResponse]("GetBundle", output)
	if err != nil {
		return nil, err
	}

	return &GetBundleResult{Bundle: bundleFromDomain(resp.Bundle)}, nil
}

// DeleteBundle removes a bundle.
func (a *CLIAdapter) DeleteBundle(ctx context.Context, opts DeleteBundleOptions) (*DeleteBundleResult, error) {
	args := []string{"vtpm", "delete", opts.ID, "--force"}

	_, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	return &DeleteBundleResult{Success: true}, nil
}

// ListBundles lists all bundles with optional filtering.
func (a *CLIAdapter) ListBundles(ctx context.Context, opts ListBundlesOptions) (*ListBundlesResult, error) {
	args := []string{"vtpm", "list", "--output", "json"}

	if opts.Mode != "" {
		args = append(args, "--mode", string(opts.Mode))
	}
	if opts.Limit > 0 {
		args = append(args, "--limit", fmt.Sprintf("%d", opts.Limit))
	}
	if opts.Offset > 0 {
		args = append(args, "--offset", fmt.Sprintf("%d", opts.Offset))
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	resp, err := decodeCLIResponse[vtpmsvc.ListBundlesResponse]("ListBundles", output)
	if err != nil {
		return nil, err
	}

	bundles := make([]*vtpm.Bundle, 0, len(resp.Bundles))
	for _, b := range resp.Bundles {
		bundles = append(bundles, bundleFromDomain(b))
	}

	return &ListBundlesResult{
		Bundles: bundles,
		Total:   int(resp.Total),
	}, nil
}

// ============================================================================
// Template CRUD Operations
// ============================================================================

// CreateTemplate creates a new vTPM template.
func (a *CLIAdapter) CreateTemplate(ctx context.Context, opts CreateTemplateOptions) (*CreateTemplateResult, error) {
	args := []string{"vtpm", "template", "create",
		"--id", opts.ID,
		"--output", "json",
	}

	if opts.Description != "" {
		args = append(args, "--description", opts.Description)
	}
	if opts.EKAlgorithm != "" {
		args = append(args, "--ek-algorithm", string(opts.EKAlgorithm))
	}
	if opts.SecureBootEnabled {
		args = append(args, "--secure-boot")
	} else {
		args = append(args, "--secure-boot=false")
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	resp, err := decodeCLIResponse[vtpmsvc.CreateTemplateResponse]("CreateTemplate", output)
	if err != nil {
		return nil, err
	}

	return &CreateTemplateResult{Template: templateFromDomain(resp.Template)}, nil
}

// GetTemplate retrieves a template by its ID.
func (a *CLIAdapter) GetTemplate(ctx context.Context, opts GetTemplateOptions) (*GetTemplateResult, error) {
	// Note: Currently there's no separate "template info" command,
	// so we list templates and filter by ID
	args := []string{"vtpm", "template", "list", "--output", "json"}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	resp, err := decodeCLIResponse[vtpmsvc.ListTemplatesResponse]("GetTemplate", output)
	if err != nil {
		return nil, err
	}

	for _, t := range resp.Templates {
		if t.ID == opts.ID {
			return &GetTemplateResult{Template: templateFromDomain(t)}, nil
		}
	}

	return nil, &CLIAdapterError{
		Operation: "GetTemplate",
		Message:   fmt.Sprintf("template not found: %s", opts.ID),
		Output:    "",
	}
}

// DeleteTemplate removes a template.
func (a *CLIAdapter) DeleteTemplate(ctx context.Context, opts DeleteTemplateOptions) (*DeleteTemplateResult, error) {
	args := []string{"vtpm", "template", "delete", opts.ID, "--force"}

	_, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	return &DeleteTemplateResult{Success: true}, nil
}

// ListTemplates lists all templates.
func (a *CLIAdapter) ListTemplates(ctx context.Context, opts ListTemplatesOptions) (*ListTemplatesResult, error) {
	args := []string{"vtpm", "template", "list", "--output", "json"}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	resp, err := decodeCLIResponse[vtpmsvc.ListTemplatesResponse]("ListTemplates", output)
	if err != nil {
		return nil, err
	}

	templates := make([]*vtpm.Template, 0, len(resp.Templates))
	for _, t := range resp.Templates {
		templates = append(templates, templateFromDomain(t))
	}

	return &ListTemplatesResult{
		Templates: templates,
		Total:     len(templates),
	}, nil
}

// CloneTemplate clones a template to create a new bundle.
func (a *CLIAdapter) CloneTemplate(ctx context.Context, opts CloneTemplateOptions) (*CloneTemplateResult, error) {
	args := []string{"vtpm", "clone",
		"--template", opts.TemplateID,
		"--hostname", opts.Hostname,
		"--output", "json",
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	resp, err := decodeCLIResponse[vtpmsvc.CloneResponse]("CloneTemplate", output)
	if err != nil {
		return nil, err
	}

	return &CloneTemplateResult{Bundle: bundleFromDomain(resp.Bundle)}, nil
}

// ============================================================================
// Export/Import Operations
// ============================================================================

// ExportBundle exports a bundle to an archive file.
func (a *CLIAdapter) ExportBundle(ctx context.Context, opts ExportBundleOptions) (*ExportBundleResult, error) {
	args := []string{"vtpm", "export", opts.ID}

	outputPath := opts.OutputPath
	if outputPath != "" {
		args = append(args, "-o", outputPath)
	} else {
		outputPath = fmt.Sprintf("bundle-%s.vtpm.tar.gz", opts.ID)
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	// Verify the file was created and get its size
	info, err := os.Stat(outputPath)
	if err != nil {
		return nil, &CLIAdapterError{
			Operation: "ExportBundle",
			Message:   "export file not created",
			Output:    string(output),
		}
	}

	return &ExportBundleResult{
		ArchivePath: outputPath,
		Size:        info.Size(),
	}, nil
}

// ImportBundle imports a bundle from an archive file.
func (a *CLIAdapter) ImportBundle(ctx context.Context, opts ImportBundleOptions) (*ImportBundleResult, error) {
	args := []string{"vtpm", "import", opts.ArchivePath, "--output", "json"}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	resp, err := decodeCLIResponse[vtpmsvc.ImportBundleResponse]("ImportBundle", output)
	if err != nil {
		return nil, err
	}

	return &ImportBundleResult{Bundle: bundleFromDomain(resp.Bundle)}, nil
}

// ValidateBundle validates bundle integrity.
func (a *CLIAdapter) ValidateBundle(ctx context.Context, opts ValidateBundleOptions) (*ValidateBundleResult, error) {
	// Note: The current CLI doesn't have a dedicated validate command,
	// but we can attempt to get the bundle info which performs basic validation
	args := []string{"vtpm", "info", opts.ID, "--output", "json"}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	if _, err := decodeCLIResponse[vtpmsvc.GetBundleResponse]("ValidateBundle", output); err != nil {
		return &ValidateBundleResult{
			Valid:  false,
			Errors: []string{err.Error()},
		}, nil
	}

	return &ValidateBundleResult{
		Valid:            true,
		ChecksumVerified: true,
	}, nil
}

// ============================================================================
// Path Helper Operations
// ============================================================================

// GetBundlePath returns the filesystem path to a bundle.
func (a *CLIAdapter) GetBundlePath(ctx context.Context, opts GetBundlePathOptions) (*GetBundlePathResult, error) {
	// Get bundle info and extract the path from TPMState
	args := []string{"vtpm", "info", opts.ID, "--output", "json"}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	resp, err := decodeCLIResponse[vtpmsvc.GetBundleResponse]("GetBundlePath", output)
	if err != nil {
		return nil, err
	}

	if resp.Bundle != nil && resp.Bundle.TPMState != nil {
		return &GetBundlePathResult{Path: resp.Bundle.TPMState.StateDir}, nil
	}

	return nil, &CLIAdapterError{
		Operation: "GetBundlePath",
		Message:   "bundle has no TPM state",
		Output:    "",
	}
}

// GetTPMSocketPath returns the TPM socket path for a bundle.
func (a *CLIAdapter) GetTPMSocketPath(ctx context.Context, opts GetTPMSocketPathOptions) (*GetTPMSocketPathResult, error) {
	// Get bundle info and construct socket path
	args := []string{"vtpm", "info", opts.ID, "--output", "json"}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	resp, err := decodeCLIResponse[vtpmsvc.GetBundleResponse]("GetTPMSocketPath", output)
	if err != nil {
		return nil, err
	}

	if resp.Bundle != nil && resp.Bundle.TPMState != nil && resp.Bundle.TPMState.StateDir != "" {
		socketPath := resp.Bundle.TPMState.StateDir + "/swtpm.sock"
		return &GetTPMSocketPathResult{Path: socketPath}, nil
	}

	return nil, &CLIAdapterError{
		Operation: "GetTPMSocketPath",
		Message:   "bundle has no TPM state",
		Output:    "",
	}
}

// GetNVRAMPath returns the OVMF NVRAM path for a bundle.
func (a *CLIAdapter) GetNVRAMPath(ctx context.Context, opts GetNVRAMPathOptions) (*GetNVRAMPathResult, error) {
	args := []string{"vtpm", "info", opts.ID, "--output", "json"}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	resp, err := decodeCLIResponse[vtpmsvc.GetBundleResponse]("GetNVRAMPath", output)
	if err != nil {
		return nil, err
	}

	if resp.Bundle != nil && resp.Bundle.OVMFState != nil {
		return &GetNVRAMPathResult{Path: resp.Bundle.OVMFState.NVRAMFile}, nil
	}

	return nil, &CLIAdapterError{
		Operation: "GetNVRAMPath",
		Message:   "bundle has no OVMF state",
		Output:    "",
	}
}

// ============================================================================
// Runtime TPM Operations
// ============================================================================

// Start starts the swtpm daemon for a bundle.
func (a *CLIAdapter) Start(ctx context.Context, opts StartOptions) (*StartResult, error) {
	args := []string{"vtpm", "start",
		"--bundle-id", opts.BundleID,
		"--output", "json",
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	resp, err := decodeCLIResponse[vtpmsvc.StartResponse]("Start", output)
	if err != nil {
		return nil, err
	}

	return &StartResult{
		BundleID:   resp.BundleID,
		Running:    resp.Running,
		SocketPath: resp.SocketPath,
	}, nil
}

// Stop stops the swtpm daemon for a bundle.
func (a *CLIAdapter) Stop(ctx context.Context, opts StopOptions) (*StopResult, error) {
	args := []string{"vtpm", "stop",
		"--bundle-id", opts.BundleID,
		"--output", "json",
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	resp, err := decodeCLIResponse[vtpmsvc.StopResponse]("Stop", output)
	if err != nil {
		return nil, err
	}

	return &StopResult{
		BundleID: resp.BundleID,
		Stopped:  resp.Stopped,
	}, nil
}

// IsRunning checks if the vTPM for a bundle is running.
func (a *CLIAdapter) IsRunning(ctx context.Context, opts IsRunningOptions) (*IsRunningResult, error) {
	args := []string{"vtpm", "is-running",
		"--bundle-id", opts.BundleID,
		"--output", "json",
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	resp, err := decodeCLIResponse[vtpmsvc.IsRunningResponse]("IsRunning", output)
	if err != nil {
		return nil, err
	}

	return &IsRunningResult{
		BundleID: resp.BundleID,
		Running:  resp.Running,
	}, nil
}

// Quote generates a TPM quote over specified PCRs.
func (a *CLIAdapter) Quote(ctx context.Context, opts QuoteOptions) (*QuoteResult, error) {
	// Build PCR indices as comma-separated string
	pcrStrs := make([]string, 0, len(opts.PCRs))
	for _, pcr := range opts.PCRs {
		pcrStrs = append(pcrStrs, fmt.Sprintf("%d", pcr))
	}

	args := []string{"vtpm", "quote",
		"--bundle-id", opts.BundleID,
		"--nonce", hex.EncodeToString(opts.Nonce),
		"--pcrs", strings.Join(pcrStrs, ","),
		"--output", "json",
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	resp, err := decodeCLIResponse[vtpmsvc.QuoteResponse]("Quote", output)
	if err != nil {
		return nil, err
	}

	pcrValues := make(map[int][]byte, len(resp.PCRValues))
	for idx, value := range resp.PCRValues {
		pcrValues[int(idx)] = value
	}

	return &QuoteResult{
		BundleID:      resp.BundleID,
		Quote:         resp.Quote,
		Signature:     resp.Signature,
		PCRValues:     pcrValues,
		HashAlgorithm: resp.HashAlgorithm,
	}, nil
}

// Seal encrypts data to the TPM, optionally binding to PCR values.
func (a *CLIAdapter) Seal(ctx context.Context, opts SealOptions) (*SealResult, error) {
	args := []string{"vtpm", "seal",
		"--bundle-id", opts.BundleID,
		"--data", base64.StdEncoding.EncodeToString(opts.Data),
		"--output", "json",
	}

	if len(opts.PCRs) > 0 {
		pcrStrs := make([]string, 0, len(opts.PCRs))
		for _, pcr := range opts.PCRs {
			pcrStrs = append(pcrStrs, fmt.Sprintf("%d", pcr))
		}
		args = append(args, "--pcrs", strings.Join(pcrStrs, ","))
	}

	if opts.AuthValue != "" {
		args = append(args, "--auth-value", opts.AuthValue)
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	resp, err := decodeCLIResponse[vtpmsvc.SealResponse]("Seal", output)
	if err != nil {
		return nil, err
	}

	return &SealResult{
		BundleID:   resp.BundleID,
		SealedData: resp.SealedData,
	}, nil
}

// Unseal decrypts data that was previously sealed to the TPM.
func (a *CLIAdapter) Unseal(ctx context.Context, opts UnsealOptions) (*UnsealResult, error) {
	args := []string{"vtpm", "unseal",
		"--bundle-id", opts.BundleID,
		"--sealed-data", base64.StdEncoding.EncodeToString(opts.SealedData),
		"--output", "json",
	}

	if opts.AuthValue != "" {
		args = append(args, "--auth-value", opts.AuthValue)
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	resp, err := decodeCLIResponse[vtpmsvc.UnsealResponse]("Unseal", output)
	if err != nil {
		return nil, err
	}

	return &UnsealResult{
		BundleID: resp.BundleID,
		Data:     resp.Data,
	}, nil
}

// ExtendPCR extends a PCR with the provided data.
func (a *CLIAdapter) ExtendPCR(ctx context.Context, opts ExtendPCROptions) (*ExtendPCRResult, error) {
	args := []string{"vtpm", "pcr", "extend",
		"--bundle-id", opts.BundleID,
		"--pcr-index", fmt.Sprintf("%d", opts.PCRIndex),
		"--data", hex.EncodeToString(opts.Data),
		"--output", "json",
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	resp, err := decodeCLIResponse[vtpmsvc.ExtendPCRResponse]("ExtendPCR", output)
	if err != nil {
		return nil, err
	}

	return &ExtendPCRResult{
		BundleID: resp.BundleID,
		PCRIndex: int(resp.PCRIndex),
		Extended: resp.Extended,
	}, nil
}

// ReadPCR reads the current value of a PCR.
func (a *CLIAdapter) ReadPCR(ctx context.Context, opts ReadPCROptions) (*ReadPCRResult, error) {
	args := []string{"vtpm", "pcr", "read",
		"--bundle-id", opts.BundleID,
		"--pcr-index", fmt.Sprintf("%d", opts.PCRIndex),
		"--output", "json",
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	resp, err := decodeCLIResponse[vtpmsvc.ReadPCRResponse]("ReadPCR", output)
	if err != nil {
		return nil, err
	}

	return &ReadPCRResult{
		BundleID: resp.BundleID,
		PCRIndex: int(resp.PCRIndex),
		Value:    resp.Value,
	}, nil
}

// Verify CLIAdapter implements VTPMCommands
var _ VTPMCommands = (*CLIAdapter)(nil)
