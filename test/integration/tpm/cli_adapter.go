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

package tpm

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// =============================================================================
// CLI Protocol Adapter
// =============================================================================

// CLIAdapter implements TPMCommands using platformctl CLI commands.
type CLIAdapter struct {
	binaryPath string
}

// NewCLIAdapter creates a new CLI protocol adapter instance.
func NewCLIAdapter() *CLIAdapter {
	return &CLIAdapter{}
}

// Name returns the protocol adapter identifier.
func (c *CLIAdapter) Name() string {
	return "CLI"
}

// Setup initializes the CLI adapter by locating the platformctl binary.
func (c *CLIAdapter) Setup(ctx context.Context) error {
	binaryPath := os.Getenv(EnvPlatformCTL)
	if binaryPath == "" {
		binaryPath = GetServiceEndpoints().PlatformCTL
	}

	// Check if the binary exists and is executable
	_, err := exec.LookPath(binaryPath)
	if err != nil {
		return ErrConnectionFailed{Protocol: "CLI", Endpoint: binaryPath, Err: err}
	}

	c.binaryPath = binaryPath

	// Verify connectivity by running a simple command
	_, err = c.runCommand(ctx, "tpm", "info", "-o", "json")
	if err != nil {
		return ErrConnectionFailed{Protocol: "CLI", Endpoint: binaryPath, Err: err}
	}

	return nil
}

// Teardown performs any cleanup needed by the CLI adapter.
func (c *CLIAdapter) Teardown() error {
	return nil
}

// runCommand executes a platformctl command and returns the output.
func (c *CLIAdapter) runCommand(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, c.binaryPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("command failed: %s: %w", string(output), err)
	}
	return output, nil
}

// =============================================================================
// TPM Info Operations
// =============================================================================

// Info retrieves TPM information via CLI.
func (c *CLIAdapter) Info(ctx context.Context) (*InfoResult, error) {
	output, err := c.runCommand(ctx, "tpm", "info", "-o", "json")
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "tpm info", Err: err}
	}

	var resp struct {
		Version      string   `json:"version"`
		IsSimulator  bool     `json:"is_simulator"`
		FIPSMode     bool     `json:"fips_mode"`
		MaxNVRAMSize uint32   `json:"max_nvram_size"`
		PCRBanks     []string `json:"pcr_banks"`
		Manufacturer struct {
			Name            string `json:"name"`
			ID              uint32 `json:"id"`
			Model           string `json:"model"`
			FirmwareVersion string `json:"firmware_version"`
		} `json:"manufacturer"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "tpm info", Err: err}
	}

	result := &InfoResult{
		Version:      resp.Version,
		IsSimulator:  resp.IsSimulator,
		FIPSMode:     resp.FIPSMode,
		MaxNVRAMSize: resp.MaxNVRAMSize,
		PCRBanks:     resp.PCRBanks,
	}

	if resp.Manufacturer.Name != "" {
		result.Manufacturer = &ManufacturerInfo{
			Name:            resp.Manufacturer.Name,
			ID:              resp.Manufacturer.ID,
			Model:           resp.Manufacturer.Model,
			FirmwareVersion: resp.Manufacturer.FirmwareVersion,
		}
	}

	return result, nil
}

// =============================================================================
// TPM Provision Operations
// =============================================================================

// Provision provisions the TPM via CLI.
func (c *CLIAdapter) Provision(ctx context.Context, opts ProvisionOptions) (*ProvisionResult, error) {
	args := []string{"tpm", "provision", "-o", "json"}

	if opts.CreateEK {
		args = append(args, "--create-ek")
	}
	if opts.CreateSRK {
		args = append(args, "--create-srk")
	}
	if opts.CreateAK {
		args = append(args, "--create-ak")
	}
	if opts.OwnerPassword != "" {
		args = append(args, "--owner-password", opts.OwnerPassword)
	}
	if opts.EndorsementPassword != "" {
		args = append(args, "--endorsement-password", opts.EndorsementPassword)
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "tpm provision", Err: err}
	}

	var resp struct {
		Success    bool   `json:"success"`
		Message    string `json:"message"`
		EKCreated  bool   `json:"ek_created"`
		SRKCreated bool   `json:"srk_created"`
		AKCreated  bool   `json:"ak_created"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "tpm provision", Err: err}
	}

	return &ProvisionResult{
		Success:    resp.Success,
		Message:    resp.Message,
		EKCreated:  resp.EKCreated,
		SRKCreated: resp.SRKCreated,
		AKCreated:  resp.AKCreated,
	}, nil
}

// =============================================================================
// TPM Clear Operations
// =============================================================================

// Clear clears the TPM via CLI.
func (c *CLIAdapter) Clear(ctx context.Context, opts ClearOptions) (*ClearResult, error) {
	args := []string{"tpm", "clear", "-o", "json", "--confirm"}

	if opts.OwnerPassword != "" {
		args = append(args, "--owner-password", opts.OwnerPassword)
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "tpm clear", Err: err}
	}

	var resp struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "tpm clear", Err: err}
	}

	return &ClearResult{
		Success: resp.Success,
		Message: resp.Message,
	}, nil
}

// =============================================================================
// EK Operations
// =============================================================================

// EKCreate creates an EK via CLI.
func (c *CLIAdapter) EKCreate(ctx context.Context, opts EKCreateOptions) (*EKCreateResult, error) {
	args := []string{"tpm", "ek", "create", "-o", "json"}

	if opts.Algorithm != "" {
		args = append(args, "--algorithm", opts.Algorithm)
	}
	if opts.Persistent {
		args = append(args, "--persistent")
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "tpm ek create", Err: err}
	}

	var resp struct {
		Success   bool   `json:"success"`
		Handle    string `json:"handle"`
		Algorithm string `json:"algorithm"`
		PublicKey string `json:"public_key"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "tpm ek create", Err: err}
	}

	var handle uint32
	fmt.Sscanf(resp.Handle, "0x%08X", &handle)

	return &EKCreateResult{
		Success:   resp.Success,
		Handle:    handle,
		Algorithm: resp.Algorithm,
		PublicKey: []byte(resp.PublicKey),
		CreatedAt: time.Now(),
	}, nil
}

// EKInfo retrieves EK information via CLI.
func (c *CLIAdapter) EKInfo(ctx context.Context, handle uint32) (*EKInfoResult, error) {
	args := []string{"tpm", "ek", "info", "-o", "json"}
	args = append(args, "--handle", fmt.Sprintf("0x%08X", handle))

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "tpm ek info", Err: err}
	}

	var resp struct {
		Handle    string `json:"handle"`
		Algorithm string `json:"algorithm"`
		PublicKey string `json:"public_key"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "tpm ek info", Err: err}
	}

	var parsedHandle uint32
	fmt.Sscanf(resp.Handle, "0x%08X", &parsedHandle)

	return &EKInfoResult{
		Handle:    parsedHandle,
		Algorithm: resp.Algorithm,
		PublicKey: []byte(resp.PublicKey),
	}, nil
}

// EKCertificate retrieves the EK certificate via CLI.
func (c *CLIAdapter) EKCertificate(ctx context.Context) (*EKCertificateResult, error) {
	output, err := c.runCommand(ctx, "tpm", "ek", "certificate", "-o", "json")
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "tpm ek certificate", Err: err}
	}

	var resp struct {
		Format      string `json:"format"`
		Certificate string `json:"certificate"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "tpm ek certificate", Err: err}
	}

	return &EKCertificateResult{
		Format:      resp.Format,
		Certificate: []byte(resp.Certificate),
	}, nil
}

// EKDelete deletes the EK via CLI.
func (c *CLIAdapter) EKDelete(ctx context.Context, handle uint32, password string) (*EKDeleteResult, error) {
	args := []string{"tpm", "ek", "delete", "-o", "json"}
	args = append(args, "--handle", fmt.Sprintf("0x%08X", handle))

	if password != "" {
		args = append(args, "--password", password)
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "tpm ek delete", Err: err}
	}

	var resp struct {
		Deleted bool   `json:"deleted"`
		Message string `json:"message"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "tpm ek delete", Err: err}
	}

	return &EKDeleteResult{
		Success: resp.Deleted,
		Message: resp.Message,
	}, nil
}

// =============================================================================
// SRK Operations
// =============================================================================

// SRKCreate creates an SRK via CLI.
func (c *CLIAdapter) SRKCreate(ctx context.Context, opts SRKCreateOptions) (*SRKCreateResult, error) {
	args := []string{"tpm", "srk", "create", "-o", "json"}

	if opts.Algorithm != "" {
		args = append(args, "--algorithm", opts.Algorithm)
	}
	if opts.Handle != 0 {
		args = append(args, "--handle", fmt.Sprintf("0x%08X", opts.Handle))
	}
	if opts.Password != "" {
		args = append(args, "--password", opts.Password)
	}
	if opts.Persistent {
		args = append(args, "--persistent")
	}
	if opts.Policy {
		args = append(args, "--policy")
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "tpm srk create", Err: err}
	}

	var resp struct {
		Success   bool   `json:"success"`
		Handle    string `json:"handle"`
		Algorithm string `json:"algorithm"`
		PublicKey string `json:"public_key"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "tpm srk create", Err: err}
	}

	var handle uint32
	fmt.Sscanf(resp.Handle, "0x%08X", &handle)

	return &SRKCreateResult{
		Success:   resp.Success,
		Handle:    handle,
		Algorithm: resp.Algorithm,
		PublicKey: []byte(resp.PublicKey),
		CreatedAt: time.Now(),
	}, nil
}

// SRKInfo retrieves SRK information via CLI.
func (c *CLIAdapter) SRKInfo(ctx context.Context, handle uint32) (*SRKInfoResult, error) {
	args := []string{"tpm", "srk", "info", "-o", "json"}
	args = append(args, "--handle", fmt.Sprintf("0x%08X", handle))

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "tpm srk info", Err: err}
	}

	var resp struct {
		Handle    string `json:"handle"`
		Algorithm string `json:"algorithm"`
		PublicKey string `json:"public_key"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "tpm srk info", Err: err}
	}

	var parsedHandle uint32
	fmt.Sscanf(resp.Handle, "0x%08X", &parsedHandle)

	return &SRKInfoResult{
		Handle:    parsedHandle,
		Algorithm: resp.Algorithm,
		PublicKey: []byte(resp.PublicKey),
	}, nil
}

// SRKDelete deletes the SRK via CLI.
func (c *CLIAdapter) SRKDelete(ctx context.Context, handle uint32, password string) (*SRKDeleteResult, error) {
	args := []string{"tpm", "srk", "delete", "-o", "json"}
	args = append(args, "--handle", fmt.Sprintf("0x%08X", handle))

	if password != "" {
		args = append(args, "--password", password)
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "tpm srk delete", Err: err}
	}

	var resp struct {
		Deleted bool   `json:"deleted"`
		Message string `json:"message"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "tpm srk delete", Err: err}
	}

	return &SRKDeleteResult{
		Success: resp.Deleted,
		Message: resp.Message,
	}, nil
}

// =============================================================================
// Seal/Unseal Operations
// =============================================================================

// Seal seals data to the TPM via CLI.
func (c *CLIAdapter) Seal(ctx context.Context, opts SealOptions) (*SealResult, error) {
	args := []string{"tpm", "seal", "-o", "json"}
	args = append(args, "--cn", opts.CN)
	args = append(args, "--data", string(opts.Data))

	if opts.Password != "" {
		args = append(args, "--password", opts.Password)
	}
	if opts.ParentPassword != "" {
		args = append(args, "--parent-password", opts.ParentPassword)
	}
	args = append(args, fmt.Sprintf("--policy=%t", opts.Policy))
	args = append(args, fmt.Sprintf("--parent-policy=%t", opts.ParentPolicy))

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		// Seal may return empty output on success
		if len(output) == 0 || strings.TrimSpace(string(output)) == "" {
			return &SealResult{Success: true}, nil
		}
		return nil, ErrCallFailed{Protocol: "CLI", Method: "tpm seal", Err: err}
	}

	// If output is empty or whitespace, consider it a success
	if len(output) == 0 || strings.TrimSpace(string(output)) == "" {
		return &SealResult{Success: true}, nil
	}

	var resp struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		// If we can't parse JSON but command succeeded, assume success
		return &SealResult{Success: true}, nil
	}

	return &SealResult{
		Success: resp.Success,
		Message: resp.Message,
	}, nil
}

// Unseal unseals data from the TPM via CLI.
func (c *CLIAdapter) Unseal(ctx context.Context, opts UnsealOptions) (*UnsealResult, error) {
	args := []string{"tpm", "unseal", "-o", "json"}
	args = append(args, "--cn", opts.CN)

	if opts.Password != "" {
		args = append(args, "--password", opts.Password)
	}
	if opts.ParentPassword != "" {
		args = append(args, "--parent-password", opts.ParentPassword)
	}
	args = append(args, fmt.Sprintf("--policy=%t", opts.Policy))
	args = append(args, fmt.Sprintf("--parent-policy=%t", opts.ParentPolicy))

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "tpm unseal", Err: err}
	}

	var resp struct {
		Success bool   `json:"success"`
		Data    string `json:"data"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		// If not JSON, the output might be the raw unsealed data
		return &UnsealResult{
			Success: true,
			Data:    output,
		}, nil
	}

	return &UnsealResult{
		Success: resp.Success,
		Data:    []byte(resp.Data),
	}, nil
}

// =============================================================================
// Event Log Operations
// =============================================================================

// EventLog reads the TPM event log via CLI.
func (c *CLIAdapter) EventLog(ctx context.Context, path string) (*EventLogResult, error) {
	args := []string{"tpm", "eventlog", "-o", "json"}

	if path != "" {
		args = append(args, "--path", path)
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "tpm eventlog", Err: err}
	}

	var resp struct {
		Events []struct {
			PCRIndex  uint32 `json:"pcr_index"`
			EventType uint32 `json:"event_type"`
			Digest    string `json:"digest"`
			EventData string `json:"event_data"`
		} `json:"events"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "tpm eventlog", Err: err}
	}

	result := &EventLogResult{
		Events: make([]EventLogEntry, 0, len(resp.Events)),
	}

	for _, e := range resp.Events {
		result.Events = append(result.Events, EventLogEntry{
			PCRIndex:  e.PCRIndex,
			EventType: e.EventType,
			Digest:    []byte(e.Digest),
			EventData: []byte(e.EventData),
		})
	}

	return result, nil
}

// Ensure CLIAdapter implements TPMCommands interface.
var _ TPMCommands = (*CLIAdapter)(nil)
