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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/calleradmission"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers/surface"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
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

// runProto runs platformctl with JSON output and decodes the document into
// out. The attestation verbs print the wire message with proto field names,
// so the CLI result maps onto the adapter types exactly as gRPC does.
func (a *CLIAdapter) runProto(ctx context.Context, out proto.Message, args ...string) error {
	output, err := a.runJSON(ctx, args...)
	if err != nil {
		return err
	}
	if err := protojson.Unmarshal(output, out); err != nil {
		return &CLIAdapterError{Operation: strings.Join(args, " "), Message: "failed to parse response: " + err.Error(), Output: string(output)}
	}
	return nil
}

// collectVMAttestation runs `platformctl attestation vm collect <vm-id>`.
func (a *CLIAdapter) collectVMAttestation(ctx context.Context, vmID string, nonce []byte, pcrIndices []int, hashAlgorithm string) (*platformv1.CollectVMAttestationResponse, error) {
	args := []string{"attestation", "vm", "collect", vmID, "--nonce", hex.EncodeToString(nonce)}
	if len(pcrIndices) > 0 {
		pcrList := make([]string, len(pcrIndices))
		for i, idx := range pcrIndices {
			pcrList[i] = strconv.Itoa(idx)
		}
		args = append(args, "--pcrs", strings.Join(pcrList, ","))
	}
	if hashAlgorithm != "" {
		args = append(args, "--hash-algorithm", hashAlgorithm)
	}

	attest := &platformv1.VMAttestation{}
	if err := a.runProto(ctx, attest, args...); err != nil {
		return nil, err
	}
	return &platformv1.CollectVMAttestationResponse{Attestation: attest}, nil
}

// GenerateVMQuote collects a VM quote via `platformctl attestation vm collect`.
func (a *CLIAdapter) GenerateVMQuote(ctx context.Context, opts GenerateVMQuoteOptions) (*GenerateVMQuoteResult, error) {
	resp, err := a.collectVMAttestation(ctx, opts.VMID, opts.Nonce, opts.PCRIndices, opts.HashAlgorithm)
	if err != nil {
		return nil, err
	}
	result, err := vmQuoteResult(resp)
	if err != nil {
		return nil, &CLIAdapterError{Operation: "GenerateVMQuote", Message: err.Error()}
	}
	return result, nil
}

// GetVMIdentity has no platformctl verb: no transport serves it.
func (a *CLIAdapter) GetVMIdentity(ctx context.Context, opts GetVMIdentityOptions) (*GetVMIdentityResult, error) {
	return nil, surface.ErrNoSurface{Transport: "CLI", Operation: "GetVMIdentity"}
}

// GetVMAttestation collects a full VM attestation via
// `platformctl attestation vm collect`.
func (a *CLIAdapter) GetVMAttestation(ctx context.Context, opts GetVMAttestationOptions) (*GetVMAttestationResult, error) {
	resp, err := a.collectVMAttestation(ctx, opts.VMID, opts.Nonce, opts.PCRIndices, opts.HashAlgorithm)
	if err != nil {
		return nil, err
	}
	result, err := vmAttestationResult(resp)
	if err != nil {
		return nil, &CLIAdapterError{Operation: "GetVMAttestation", Message: err.Error()}
	}
	return result, nil
}

// VerifyVMAttestation verifies a quote via `platformctl attestation quote
// verify -f`, sending the request gRPC sends.
func (a *CLIAdapter) VerifyVMAttestation(ctx context.Context, opts VerifyVMAttestationOptions) (*VerifyVMAttestationResult, error) {
	raw, err := protojson.Marshal(verifyAttestationQuoteRequest(opts))
	if err != nil {
		return nil, &CLIAdapterError{Operation: "VerifyVMAttestation", Message: "failed to encode request: " + err.Error()}
	}
	requestPath := filepath.Join(a.configDir, "verify-quote-request.json")
	if err := os.WriteFile(requestPath, raw, 0o600); err != nil {
		return nil, &CLIAdapterError{Operation: "VerifyVMAttestation", Message: "failed to write request: " + err.Error()}
	}

	resp := &platformv1.VerifyAttestationQuoteResponse{}
	runErr := a.runProto(ctx, resp, "attestation", "quote", "verify", "-f", requestPath)
	if err := os.Remove(requestPath); err != nil && runErr == nil {
		return nil, &CLIAdapterError{Operation: "VerifyVMAttestation", Message: "failed to remove request: " + err.Error()}
	}
	if runErr != nil {
		return nil, runErr
	}
	return verifyVMAttestationResult(opts, resp), nil
}

// =============================================================================
// Manifest Operations
// =============================================================================

// BuildManifest builds and stores a signed host manifest via
// `platformctl attestation manifests build`, with the options gRPC sends.
func (a *CLIAdapter) BuildManifest(ctx context.Context, opts BuildManifestOptions) (*BuildManifestResult, error) {
	args := []string{"attestation", "manifests", "build", "--host-id", opts.HostID}
	if opts.HashAlgorithm != "" {
		args = append(args, "--hash-algorithm", opts.HashAlgorithm)
	}
	if opts.Version != "" {
		args = append(args, "--version", opts.Version)
	}
	if len(opts.VMAttestations) > 0 {
		args = append(args, "--include-vms")
	}
	if len(opts.ContainerAttestations) > 0 {
		args = append(args, "--include-containers")
	}

	manifest := &platformv1.HostManifest{}
	if err := a.runProto(ctx, manifest, args...); err != nil {
		return nil, err
	}
	result, err := buildManifestResult(&platformv1.BuildManifestResponse{Manifest: manifest})
	if err != nil {
		return nil, &CLIAdapterError{Operation: "BuildManifest", Message: err.Error()}
	}
	return result, nil
}

// SignManifest has no platformctl verb: no transport serves it, and
// `manifests build` signs unless --sign=false.
func (a *CLIAdapter) SignManifest(ctx context.Context, opts SignManifestOptions) (*SignManifestResult, error) {
	return nil, surface.ErrNoSurface{Transport: "CLI", Operation: "SignManifest"}
}

// getManifest runs `platformctl attestation manifests get <id>`.
func (a *CLIAdapter) getManifest(ctx context.Context, manifestID string) (*platformv1.GetManifestResponse, error) {
	manifest := &platformv1.HostManifest{}
	if err := a.runProto(ctx, manifest, "attestation", "manifests", "get", manifestID); err != nil {
		return nil, err
	}
	return &platformv1.GetManifestResponse{Manifest: manifest}, nil
}

// VerifyManifest verifies a stored manifest via
// `platformctl attestation manifests verify <id>`. The stored manifest is
// fetched first, as gRPC does, so the host id can be compared.
func (a *CLIAdapter) VerifyManifest(ctx context.Context, opts VerifyManifestOptions) (*VerifyManifestResult, error) {
	getResp, err := a.getManifest(ctx, opts.ManifestID)
	if err != nil {
		return nil, err
	}
	manifest, err := storedManifest(getResp)
	if err != nil {
		return nil, &CLIAdapterError{Operation: "VerifyManifest", Message: err.Error()}
	}

	verification := &platformv1.ManifestVerificationResult{}
	if err := a.runProto(ctx, verification, "attestation", "manifests", "verify", opts.ManifestID); err != nil {
		return nil, err
	}
	result, err := verifyManifestResult(opts, manifest, &platformv1.VerifyManifestResponse{Result: verification})
	if err != nil {
		return nil, &CLIAdapterError{Operation: "VerifyManifest", Message: err.Error()}
	}
	return result, nil
}

// GetManifest retrieves a manifest by id via
// `platformctl attestation manifests get <id>`.
func (a *CLIAdapter) GetManifest(ctx context.Context, opts GetManifestOptions) (*GetManifestResult, error) {
	resp, err := a.getManifest(ctx, opts.ManifestID)
	if err != nil {
		return nil, err
	}
	result, err := getManifestResult(resp)
	if err != nil {
		return nil, &CLIAdapterError{Operation: "GetManifest", Message: err.Error()}
	}
	return result, nil
}

// =============================================================================
// Push Operations
// =============================================================================

// PushAttestation has no platformctl verb: no transport serves it.
func (a *CLIAdapter) PushAttestation(ctx context.Context, opts PushAttestationOptions) (*PushAttestationResult, error) {
	return nil, surface.ErrNoSurface{Transport: "CLI", Operation: "PushAttestation"}
}

// PushAttestationBatch has no platformctl verb: no transport serves it.
func (a *CLIAdapter) PushAttestationBatch(ctx context.Context, opts PushAttestationBatchOptions) (*PushAttestationBatchResult, error) {
	return nil, surface.ErrNoSurface{Transport: "CLI", Operation: "PushAttestationBatch"}
}

// GetPushStatus has no platformctl verb: no transport serves it.
func (a *CLIAdapter) GetPushStatus(ctx context.Context, opts GetPushStatusOptions) (*GetPushStatusResult, error) {
	return nil, surface.ErrNoSurface{Transport: "CLI", Operation: "GetPushStatus"}
}

// =============================================================================
// Workload Chain Operations
// =============================================================================

// ExtendWorkloadChain has no platformctl verb: no transport serves it.
func (a *CLIAdapter) ExtendWorkloadChain(ctx context.Context, opts ExtendWorkloadChainOptions) (*ExtendWorkloadChainResult, error) {
	return nil, surface.ErrNoSurface{Transport: "CLI", Operation: "ExtendWorkloadChain"}
}

// GetWorkloadChainHistory has no platformctl verb: no transport serves it.
func (a *CLIAdapter) GetWorkloadChainHistory(ctx context.Context, opts GetWorkloadChainHistoryOptions) (*GetWorkloadChainHistoryResult, error) {
	return nil, surface.ErrNoSurface{Transport: "CLI", Operation: "GetWorkloadChainHistory"}
}

// VerifyWorkloadChain has no platformctl verb: no transport serves it.
func (a *CLIAdapter) VerifyWorkloadChain(ctx context.Context, opts VerifyWorkloadChainOptions) (*VerifyWorkloadChainResult, error) {
	return nil, surface.ErrNoSurface{Transport: "CLI", Operation: "VerifyWorkloadChain"}
}

// GetWorkloadChainStats has no platformctl verb: no transport serves it.
func (a *CLIAdapter) GetWorkloadChainStats(ctx context.Context, opts GetWorkloadChainStatsOptions) (*GetWorkloadChainStatsResult, error) {
	return nil, surface.ErrNoSurface{Transport: "CLI", Operation: "GetWorkloadChainStats"}
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
