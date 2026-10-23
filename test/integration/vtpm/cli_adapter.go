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

// The vtpm CLI prints the SDK domain types of sdk/go/services/vtpm with
// --output json: enums are strings and times are RFC 3339. The adapter decodes
// that document as-is and converts it to the pkg/vtpm types the suite asserts.

// bundleModeFromCLI converts an SDK domain bundle mode to vtpm.BundleMode.
func bundleModeFromCLI(mode vtpmsvc.BundleMode) vtpm.BundleMode {
	switch mode {
	case vtpmsvc.BundleModeTemplate:
		return vtpm.BundleModeTemplate
	case vtpmsvc.BundleModePreAssigned:
		return vtpm.BundleModePreAssigned
	default:
		return vtpm.BundleMode("")
	}
}

// timeFromCLI returns the time a CLI document carries, or the zero time.
func timeFromCLI(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}

// bundleFromCLI converts an SDK domain bundle to vtpm.Bundle.
func bundleFromCLI(b *vtpmsvc.Bundle) *vtpm.Bundle {
	if b == nil {
		return nil
	}
	bundle := &vtpm.Bundle{
		ID:         b.ID,
		Mode:       bundleModeFromCLI(b.Mode),
		ClonedFrom: b.ClonedFrom,
		CreatedAt:  timeFromCLI(b.CreatedAt),
	}
	if b.Manifest != nil {
		bundle.Manifest = &vtpm.Manifest{
			ID:                b.ID,
			Mode:              bundle.Mode,
			Hostname:          b.Manifest.Hostname,
			EKAlgorithm:       vtpm.EKAlgorithm(b.Manifest.EKAlgorithm),
			SecureBootEnabled: b.Manifest.SecureBootEnabled,
			ClonedFrom:        b.Manifest.ClonedFrom,
			Labels:            b.Manifest.Labels,
			Checksums:         b.Manifest.Checksums,
			CreatedAt:         timeFromCLI(b.Manifest.CreatedAt),
		}
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

// templateFromCLI converts an SDK domain template to vtpm.Template.
func templateFromCLI(t *vtpmsvc.Template) *vtpm.Template {
	if t == nil {
		return nil
	}
	return &vtpm.Template{
		ID:                t.ID,
		Description:       t.Description,
		EKAlgorithm:       vtpm.EKAlgorithm(t.EKAlgorithm),
		SecureBootEnabled: t.SecureBootEnabled,
		TPMStateDir:       t.TPMStateDir,
		NVRAMPath:         t.NVRAMPath,
		SecureBootKeysDir: t.SecureBootKeysDir,
		CreatedAt:         timeFromCLI(t.CreatedAt),
	}
}

// CLI response wrappers for runtime TPM operations
type cliStartVTPMResponse struct {
	BundleID   string `json:"bundle_id"`
	Running    bool   `json:"running"`
	SocketPath string `json:"socket_path"`
}

type cliStopVTPMResponse struct {
	BundleID string `json:"bundle_id"`
	Stopped  bool   `json:"stopped"`
}

type cliIsVTPMRunningResponse struct {
	BundleID string `json:"bundle_id"`
	Running  bool   `json:"running"`
}

type cliQuoteVTPMResponse struct {
	BundleID      string            `json:"bundle_id"`
	Quote         string            `json:"quote"`      // base64-encoded by protobuf JSON
	Signature     string            `json:"signature"`  // base64-encoded by protobuf JSON
	PcrValues     map[string]string `json:"pcr_values"` // protobuf maps int32 keys as strings in JSON
	HashAlgorithm string            `json:"hash_algorithm"`
}

type cliSealVTPMResponse struct {
	BundleID   string `json:"bundle_id"`
	SealedData string `json:"sealed_data"` // base64-encoded by protobuf JSON
}

type cliUnsealVTPMResponse struct {
	BundleID string `json:"bundle_id"`
	Data     string `json:"data"` // base64-encoded by protobuf JSON
}

type cliExtendVTPMPCRResponse struct {
	BundleID string `json:"bundle_id"`
	PcrIndex int    `json:"pcr_index"`
	Extended bool   `json:"extended"`
}

type cliReadVTPMPCRResponse struct {
	BundleID string `json:"bundle_id"`
	PcrIndex int    `json:"pcr_index"`
	Value    string `json:"value"` // base64-encoded by protobuf JSON
}

// CLIAdapterError represents an error from the CLI adapter.
type CLIAdapterError struct {
	Operation string
	Message   string
	Output    string
}

// Error returns the error message.
func (e *CLIAdapterError) Error() string {
	return fmt.Sprintf("CLI adapter error [%s]: %s (output: %s)", e.Operation, e.Message, e.Output)
}

// CLIAdapter implements VTPMCommands using the platformctl CLI.
type CLIAdapter struct {
	cliPath string
	// configDir and configPath hold the platformctl config Setup writes: its
	// context dials the harness daemon socket. platformctl reads its daemon
	// connection only from a context (docs/vtpm/cli.md §1, global flags);
	// without one every verb answers "daemon connection required".
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

	dir, path, err := helpers.WriteTempLocalCLIConfig(GetSocketPath(), GetGRPCEndpoint())
	if err != nil {
		return &CLIAdapterError{
			Operation: "Setup",
			Message:   "writing the platformctl config: " + err.Error(),
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
	if a.configPath != "" {
		args = append([]string{"--config", a.configPath, "--context", helpers.CLIContextName}, args...)
	}
	cmd := exec.CommandContext(ctx, a.cliPath, args...)
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

	var resp vtpmsvc.CreateBundleResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, &CLIAdapterError{
			Operation: "CreateBundle",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &CreateBundleResult{Bundle: bundleFromCLI(resp.Bundle)}, nil
}

// GetBundle retrieves a bundle by its ID.
func (a *CLIAdapter) GetBundle(ctx context.Context, opts GetBundleOptions) (*GetBundleResult, error) {
	args := []string{"vtpm", "info", opts.ID, "--output", "json"}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var resp vtpmsvc.GetBundleResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, &CLIAdapterError{
			Operation: "GetBundle",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &GetBundleResult{Bundle: bundleFromCLI(resp.Bundle)}, nil
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

	var resp vtpmsvc.ListBundlesResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, &CLIAdapterError{
			Operation: "ListBundles",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	bundles := make([]*vtpm.Bundle, 0, len(resp.Bundles))
	for _, b := range resp.Bundles {
		bundles = append(bundles, bundleFromCLI(b))
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

	var resp vtpmsvc.CreateTemplateResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, &CLIAdapterError{
			Operation: "CreateTemplate",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &CreateTemplateResult{Template: templateFromCLI(resp.Template)}, nil
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

	var resp vtpmsvc.ListTemplatesResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, &CLIAdapterError{
			Operation: "GetTemplate",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	for _, t := range resp.Templates {
		if t.ID == opts.ID {
			return &GetTemplateResult{Template: templateFromCLI(t)}, nil
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

	var resp vtpmsvc.ListTemplatesResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, &CLIAdapterError{
			Operation: "ListTemplates",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	templates := make([]*vtpm.Template, 0, len(resp.Templates))
	for _, t := range resp.Templates {
		templates = append(templates, templateFromCLI(t))
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

	var resp vtpmsvc.CloneResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, &CLIAdapterError{
			Operation: "CloneTemplate",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &CloneTemplateResult{Bundle: bundleFromCLI(resp.Bundle)}, nil
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

	// Import response uses same structure as create
	var resp vtpmsvc.ImportBundleResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, &CLIAdapterError{
			Operation: "ImportBundle",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &ImportBundleResult{Bundle: bundleFromCLI(resp.Bundle)}, nil
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

	var resp vtpmsvc.GetBundleResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return &ValidateBundleResult{
			Valid:  false,
			Errors: []string{"failed to parse bundle: " + err.Error()},
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

	var resp vtpmsvc.GetBundleResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, &CLIAdapterError{
			Operation: "GetBundlePath",
			Message:   "failed to parse response",
			Output:    string(output),
		}
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

	var resp vtpmsvc.GetBundleResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, &CLIAdapterError{
			Operation: "GetTPMSocketPath",
			Message:   "failed to parse response",
			Output:    string(output),
		}
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

	var resp vtpmsvc.GetBundleResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, &CLIAdapterError{
			Operation: "GetNVRAMPath",
			Message:   "failed to parse response",
			Output:    string(output),
		}
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

	var resp cliStartVTPMResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, &CLIAdapterError{
			Operation: "Start",
			Message:   "failed to parse response",
			Output:    string(output),
		}
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

	var resp cliStopVTPMResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, &CLIAdapterError{
			Operation: "Stop",
			Message:   "failed to parse response",
			Output:    string(output),
		}
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

	var resp cliIsVTPMRunningResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, &CLIAdapterError{
			Operation: "IsRunning",
			Message:   "failed to parse response",
			Output:    string(output),
		}
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

	var resp cliQuoteVTPMResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, &CLIAdapterError{
			Operation: "Quote",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	// Decode base64-encoded byte fields from protobuf JSON
	quoteBytes, err := base64.StdEncoding.DecodeString(resp.Quote)
	if err != nil {
		return nil, &CLIAdapterError{
			Operation: "Quote",
			Message:   "failed to decode quote: " + err.Error(),
			Output:    string(output),
		}
	}

	sigBytes, err := base64.StdEncoding.DecodeString(resp.Signature)
	if err != nil {
		return nil, &CLIAdapterError{
			Operation: "Quote",
			Message:   "failed to decode signature: " + err.Error(),
			Output:    string(output),
		}
	}

	// Convert PCR values from protobuf JSON format (string keys, base64 values)
	pcrValues := make(map[int][]byte, len(resp.PcrValues))
	for keyStr, valStr := range resp.PcrValues {
		var idx int
		if _, scanErr := fmt.Sscanf(keyStr, "%d", &idx); scanErr != nil {
			return nil, &CLIAdapterError{
				Operation: "Quote",
				Message:   "failed to parse PCR index: " + scanErr.Error(),
				Output:    string(output),
			}
		}
		valBytes, decErr := base64.StdEncoding.DecodeString(valStr)
		if decErr != nil {
			return nil, &CLIAdapterError{
				Operation: "Quote",
				Message:   "failed to decode PCR value: " + decErr.Error(),
				Output:    string(output),
			}
		}
		pcrValues[idx] = valBytes
	}

	return &QuoteResult{
		BundleID:      resp.BundleID,
		Quote:         quoteBytes,
		Signature:     sigBytes,
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

	var resp cliSealVTPMResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, &CLIAdapterError{
			Operation: "Seal",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	sealedBytes, err := base64.StdEncoding.DecodeString(resp.SealedData)
	if err != nil {
		return nil, &CLIAdapterError{
			Operation: "Seal",
			Message:   "failed to decode sealed data: " + err.Error(),
			Output:    string(output),
		}
	}

	return &SealResult{
		BundleID:   resp.BundleID,
		SealedData: sealedBytes,
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

	var resp cliUnsealVTPMResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, &CLIAdapterError{
			Operation: "Unseal",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	dataBytes, err := base64.StdEncoding.DecodeString(resp.Data)
	if err != nil {
		return nil, &CLIAdapterError{
			Operation: "Unseal",
			Message:   "failed to decode data: " + err.Error(),
			Output:    string(output),
		}
	}

	return &UnsealResult{
		BundleID: resp.BundleID,
		Data:     dataBytes,
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

	var resp cliExtendVTPMPCRResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, &CLIAdapterError{
			Operation: "ExtendPCR",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &ExtendPCRResult{
		BundleID: resp.BundleID,
		PCRIndex: resp.PcrIndex,
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

	var resp cliReadVTPMPCRResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, &CLIAdapterError{
			Operation: "ReadPCR",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	valueBytes, err := base64.StdEncoding.DecodeString(resp.Value)
	if err != nil {
		return nil, &CLIAdapterError{
			Operation: "ReadPCR",
			Message:   "failed to decode PCR value: " + err.Error(),
			Output:    string(output),
		}
	}

	return &ReadPCRResult{
		BundleID: resp.BundleID,
		PCRIndex: resp.PcrIndex,
		Value:    valueBytes,
	}, nil
}

// Verify CLIAdapter implements VTPMCommands
var _ VTPMCommands = (*CLIAdapter)(nil)
