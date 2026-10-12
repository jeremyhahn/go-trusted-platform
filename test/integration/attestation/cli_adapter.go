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

package attestation

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/calleradmission"
)

// CLIAdapterError represents an error from the CLI adapter
type CLIAdapterError struct {
	Operation string
	Message   string
	Output    string
}

func (e *CLIAdapterError) Error() string {
	return fmt.Sprintf("CLI adapter error [%s]: %s (output: %s)", e.Operation, e.Message, e.Output)
}

// CLIAdapter implements AttestationCommands using the platformctl CLI
type CLIAdapter struct {
	cliPath string
	// configDir holds the platformctl config whose local context reaches
	// the daemon's Unix socket; Setup writes it, Teardown removes it.
	configDir  string
	configPath string
}

// NewCLIAdapter creates a new CLI adapter
func NewCLIAdapter() *CLIAdapter {
	return &CLIAdapter{
		cliPath: GetCLIPath(),
	}
}

// Setup prepares the adapter for testing
func (a *CLIAdapter) Setup(ctx context.Context) error {
	_, err := exec.LookPath(a.cliPath)
	if err != nil {
		return &CLIAdapterError{
			Operation: "Setup",
			Message:   "CLI not found",
		}
	}

	configDir, err := os.MkdirTemp("", "platformctl-attestation-test-*")
	if err != nil {
		return &CLIAdapterError{Operation: "Setup", Message: "failed to create config dir: " + err.Error()}
	}
	a.configDir = configDir
	a.configPath = filepath.Join(configDir, "config.yaml")
	config := fmt.Sprintf(`current_context: %s
contexts:
  - name: %s
    type: local
    local:
      socket_path: %s
      grpc_addr: %s
`, cliContextName, cliContextName, GetSocketPath(), GetGRPCEndpoint())
	if err := os.WriteFile(a.configPath, []byte(config), 0o600); err != nil {
		return &CLIAdapterError{Operation: "Setup", Message: "failed to write config: " + err.Error()}
	}
	return nil
}

// Teardown cleans up after testing
func (a *CLIAdapter) Teardown(ctx context.Context) error {
	if a.configDir == "" {
		return nil
	}
	err := os.RemoveAll(a.configDir)
	a.configDir = ""
	a.configPath = ""
	return err
}

// Name returns the adapter name
func (a *CLIAdapter) Name() string {
	return "CLI"
}

// runCommand executes a CLI command and returns the output
func (a *CLIAdapter) runCommand(ctx context.Context, args ...string) ([]byte, error) {
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

// cliContextName is the context Setup writes into the adapter's config.
const cliContextName = "integration-test"

// runJSON runs platformctl against the adapter's local context with JSON
// output. Stdout and stderr are kept apart so a warning on stderr never
// corrupts the JSON document.
func (a *CLIAdapter) runJSON(ctx context.Context, args ...string) ([]byte, error) {
	full := append([]string{"--config", a.configPath, "--context", cliContextName}, args...)
	full = append(full, "--output", "json")

	cmd := exec.CommandContext(ctx, a.cliPath, full...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, &CLIAdapterError{
			Operation: strings.Join(args, " "),
			Message:   err.Error(),
			Output:    stdout.String() + stderr.String(),
		}
	}
	return stdout.Bytes(), nil
}

// cliNeverCollected is platformctl's phrase for a device with no report.
const cliNeverCollected = "has never been collected"

// reportingCommand runs one reporting verb and decodes its JSON into out.
// deviceID is the verb's argument and, when set, lets a never-collected
// failure be told apart.
func (a *CLIAdapter) reportingCommand(ctx context.Context, operation, deviceID string, out any, args ...string) error {
	output, err := a.runJSON(ctx, args...)
	if err != nil {
		return classifyReportingText(a.Name(), operation, deviceID, cliNeverCollected, err)
	}
	if err := json.Unmarshal(output, out); err != nil {
		return &CLIAdapterError{Operation: operation, Message: "failed to parse output: " + err.Error(), Output: string(output)}
	}
	return nil
}

// =============================================================================
// VM Attestation Operations
// =============================================================================

// GenerateVMQuote generates a TPM quote for a VM
func (a *CLIAdapter) GenerateVMQuote(ctx context.Context, opts GenerateVMQuoteOptions) (*GenerateVMQuoteResult, error) {
	args := []string{"attestation", "vm", "quote",
		"--vm-id", opts.VMID,
		"--nonce", base64.StdEncoding.EncodeToString(opts.Nonce),
		"--output", "json",
	}

	if len(opts.PCRIndices) > 0 {
		pcrList := make([]string, len(opts.PCRIndices))
		for i, idx := range opts.PCRIndices {
			pcrList[i] = fmt.Sprintf("%d", idx)
		}
		args = append(args, "--pcrs", strings.Join(pcrList, ","))
	}

	if opts.HashAlgorithm != "" {
		args = append(args, "--hash-algorithm", opts.HashAlgorithm)
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result GenerateVMQuoteResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, &CLIAdapterError{
			Operation: "GenerateVMQuote",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &result, nil
}

// GetVMIdentity retrieves VM identity from vTPM EK certificate
func (a *CLIAdapter) GetVMIdentity(ctx context.Context, opts GetVMIdentityOptions) (*GetVMIdentityResult, error) {
	args := []string{"attestation", "vm", "identity",
		"--vm-id", opts.VMID,
		"--output", "json",
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result GetVMIdentityResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, &CLIAdapterError{
			Operation: "GetVMIdentity",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &result, nil
}

// GetVMAttestation generates a full VM attestation
func (a *CLIAdapter) GetVMAttestation(ctx context.Context, opts GetVMAttestationOptions) (*GetVMAttestationResult, error) {
	args := []string{"attestation", "vm", "attest",
		"--vm-id", opts.VMID,
		"--nonce", base64.StdEncoding.EncodeToString(opts.Nonce),
		"--output", "json",
	}

	if len(opts.PCRIndices) > 0 {
		pcrList := make([]string, len(opts.PCRIndices))
		for i, idx := range opts.PCRIndices {
			pcrList[i] = fmt.Sprintf("%d", idx)
		}
		args = append(args, "--pcrs", strings.Join(pcrList, ","))
	}

	if opts.HashAlgorithm != "" {
		args = append(args, "--hash-algorithm", opts.HashAlgorithm)
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result GetVMAttestationResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, &CLIAdapterError{
			Operation: "GetVMAttestation",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &result, nil
}

// VerifyVMAttestation verifies a VM attestation
func (a *CLIAdapter) VerifyVMAttestation(ctx context.Context, opts VerifyVMAttestationOptions) (*VerifyVMAttestationResult, error) {
	args := []string{"attestation", "vm", "verify",
		"--attestation-id", opts.AttestationID,
		"--nonce", base64.StdEncoding.EncodeToString(opts.ExpectedNonce),
		"--output", "json",
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result VerifyVMAttestationResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, &CLIAdapterError{
			Operation: "VerifyVMAttestation",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &result, nil
}

// =============================================================================
// Manifest Operations
// =============================================================================

// BuildManifest builds a host manifest with attestations
func (a *CLIAdapter) BuildManifest(ctx context.Context, opts BuildManifestOptions) (*BuildManifestResult, error) {
	args := []string{"attestation", "manifest", "build",
		"--host-id", opts.HostID,
		"--output", "json",
	}

	if opts.HashAlgorithm != "" {
		args = append(args, "--hash-algorithm", opts.HashAlgorithm)
	}

	if opts.Version != "" {
		args = append(args, "--version", opts.Version)
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result BuildManifestResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, &CLIAdapterError{
			Operation: "BuildManifest",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &result, nil
}

// SignManifest signs a manifest with the host TPM
func (a *CLIAdapter) SignManifest(ctx context.Context, opts SignManifestOptions) (*SignManifestResult, error) {
	args := []string{"attestation", "manifest", "sign",
		"--manifest-id", opts.ManifestID,
		"--output", "json",
	}

	if opts.HashAlgorithm != "" {
		args = append(args, "--hash-algorithm", opts.HashAlgorithm)
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result SignManifestResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, &CLIAdapterError{
			Operation: "SignManifest",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &result, nil
}

// VerifyManifest verifies a signed manifest
func (a *CLIAdapter) VerifyManifest(ctx context.Context, opts VerifyManifestOptions) (*VerifyManifestResult, error) {
	args := []string{"attestation", "manifest", "verify",
		"--manifest-id", opts.ManifestID,
		"--output", "json",
	}

	if opts.ExpectedHostID != "" {
		args = append(args, "--host-id", opts.ExpectedHostID)
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result VerifyManifestResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, &CLIAdapterError{
			Operation: "VerifyManifest",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &result, nil
}

// GetManifest retrieves a manifest by ID
func (a *CLIAdapter) GetManifest(ctx context.Context, opts GetManifestOptions) (*GetManifestResult, error) {
	args := []string{"attestation", "manifest", "get",
		"--manifest-id", opts.ManifestID,
		"--output", "json",
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result GetManifestResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, &CLIAdapterError{
			Operation: "GetManifest",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &result, nil
}

// =============================================================================
// Push Operations
// =============================================================================

// PushAttestation pushes an attestation to a target
func (a *CLIAdapter) PushAttestation(ctx context.Context, opts PushAttestationOptions) (*PushAttestationResult, error) {
	args := []string{"attestation", "push",
		"--manifest-id", opts.ManifestID,
		"--target-id", opts.TargetID,
		"--endpoint", opts.Endpoint,
		"--transport", opts.Transport,
		"--output", "json",
	}

	if opts.ContentType != "" {
		args = append(args, "--content-type", opts.ContentType)
	}

	if opts.Timeout > 0 {
		args = append(args, "--timeout", opts.Timeout.String())
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result PushAttestationResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, &CLIAdapterError{
			Operation: "PushAttestation",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &result, nil
}

// PushAttestationBatch pushes to multiple targets concurrently
func (a *CLIAdapter) PushAttestationBatch(ctx context.Context, opts PushAttestationBatchOptions) (*PushAttestationBatchResult, error) {
	args := []string{"attestation", "push", "batch",
		"--manifest-id", opts.ManifestID,
		"--output", "json",
	}

	// For batch, we might need to pass targets via file or inline JSON
	// This is a simplified implementation
	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result PushAttestationBatchResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, &CLIAdapterError{
			Operation: "PushAttestationBatch",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &result, nil
}

// GetPushStatus retrieves the status of a push operation
func (a *CLIAdapter) GetPushStatus(ctx context.Context, opts GetPushStatusOptions) (*GetPushStatusResult, error) {
	args := []string{"attestation", "push", "status",
		"--push-id", opts.PushID,
		"--output", "json",
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result GetPushStatusResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, &CLIAdapterError{
			Operation: "GetPushStatus",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &result, nil
}

// =============================================================================
// Workload Chain Operations
// =============================================================================

// ExtendWorkloadChain extends the workload PCR with a measurement
func (a *CLIAdapter) ExtendWorkloadChain(ctx context.Context, opts ExtendWorkloadChainOptions) (*ExtendWorkloadChainResult, error) {
	args := []string{"attestation", "workload", "extend",
		"--workload-type", opts.WorkloadType,
		"--workload-id", opts.WorkloadID,
		"--image-digest", opts.ImageDigest,
		"--output", "json",
	}

	if len(opts.ConfigHash) > 0 {
		args = append(args, "--config-hash", base64.StdEncoding.EncodeToString(opts.ConfigHash))
	}

	if len(opts.RuntimeHash) > 0 {
		args = append(args, "--runtime-hash", base64.StdEncoding.EncodeToString(opts.RuntimeHash))
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result ExtendWorkloadChainResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, &CLIAdapterError{
			Operation: "ExtendWorkloadChain",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &result, nil
}

// GetWorkloadChainHistory retrieves the chain history
func (a *CLIAdapter) GetWorkloadChainHistory(ctx context.Context, opts GetWorkloadChainHistoryOptions) (*GetWorkloadChainHistoryResult, error) {
	args := []string{"attestation", "workload", "history",
		"--output", "json",
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

	var result GetWorkloadChainHistoryResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, &CLIAdapterError{
			Operation: "GetWorkloadChainHistory",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &result, nil
}

// VerifyWorkloadChain verifies the chain against expected PCR
func (a *CLIAdapter) VerifyWorkloadChain(ctx context.Context, opts VerifyWorkloadChainOptions) (*VerifyWorkloadChainResult, error) {
	args := []string{"attestation", "workload", "verify",
		"--expected-pcr", base64.StdEncoding.EncodeToString(opts.ExpectedPCRValue),
		"--output", "json",
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result VerifyWorkloadChainResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, &CLIAdapterError{
			Operation: "VerifyWorkloadChain",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &result, nil
}

// GetWorkloadChainStats retrieves chain statistics
func (a *CLIAdapter) GetWorkloadChainStats(ctx context.Context, opts GetWorkloadChainStatsOptions) (*GetWorkloadChainStatsResult, error) {
	args := []string{"attestation", "workload", "stats",
		"--output", "json",
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result GetWorkloadChainStatsResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, &CLIAdapterError{
			Operation: "GetWorkloadChainStats",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &result, nil
}

// ListDeviceReports runs `platformctl attestation reports list`.
func (a *CLIAdapter) ListDeviceReports(ctx context.Context) (*DeviceReportsResult, error) {
	var result DeviceReportsResult
	if err := a.reportingCommand(ctx, "ListDeviceReports", "", &result, "attestation", "reports", "list"); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetDeviceReport runs `platformctl attestation reports get <device-id>`.
func (a *CLIAdapter) GetDeviceReport(ctx context.Context, opts DeviceReportOptions) (*DeviceReport, error) {
	var result DeviceReport
	if err := a.reportingCommand(ctx, "GetDeviceReport", opts.DeviceID, &result, "attestation", "reports", "get", opts.DeviceID); err != nil {
		return nil, err
	}
	return &result, nil
}

// RefreshDeviceReport runs `platformctl attestation reports refresh <device-id>`.
func (a *CLIAdapter) RefreshDeviceReport(ctx context.Context, opts DeviceReportOptions) (*RefreshDeviceReportResult, error) {
	var result RefreshDeviceReportResult
	if err := a.reportingCommand(ctx, "RefreshDeviceReport", "", &result, "attestation", "reports", "refresh", opts.DeviceID); err != nil {
		return nil, err
	}
	return &result, nil
}

// DescribeCallerPolicy runs `platformctl attestation callers`.
func (a *CLIAdapter) DescribeCallerPolicy(ctx context.Context) (*calleradmission.Description, error) {
	var result calleradmission.Description
	if err := a.reportingCommand(ctx, "DescribeCallerPolicy", "", &result, "attestation", "callers"); err != nil {
		return nil, err
	}
	return &result, nil
}

// Verify CLIAdapter implements AttestationCommands
var _ AttestationCommands = (*CLIAdapter)(nil)
